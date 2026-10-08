package urltok

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("urltok", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping urltok DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type env struct {
	d       *core.Deps
	srv     *httptest.Server
	called  bool
	gotAuth string
	marked  bool
}

// downstream records what the middleware handed it and emits a txt reply with a next: line.
func (e *env) newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	e.d = d
	down := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.called = true
		e.gotAuth = r.Header.Get("Authorization")
		e.marked = FromContext(r.Context())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Add("Link", `</grammar>; rel="help"`)
		io.WriteString(w, "resume: hello world\nnext: GET /v1/me/log | GET /v1/me/news\n")
	})
	e.srv = httptest.NewServer(Middleware(d, down))
	t.Cleanup(e.srv.Close)
	return e
}

func newEnv(t *testing.T) *env { return (&env{}).newEnv(t) }

// tokens mints a root (full token) and a url-class subkey of it.
func (e *env) tokens(t *testing.T) (full, urlTok string) {
	t.Helper()
	ctx := context.Background()
	var rootTok string
	if err := core.Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		var rootID string
		rootID, rootTok, err = core.CreateRoot(ctx, tx, "root-"+randname(t), "10.9.9.9")
		if err != nil {
			return err
		}
		_ = rootID
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	parent, err := e.d.LookupToken(ctx, rootTok)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		_, urlTok, err = core.CreateSubkeyV2(ctx, tx, parent, core.SubkeyOpts{
			Name: "u", Exp: time.Now().Add(time.Hour), Class: "url"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return rootTok, urlTok
}

// urlTokenScoped mints a url-class subkey carrying exactly the given scopes (which must be a subset
// of the root's, i.e. anything, since a root holds every scope).
func (e *env) urlTokenScoped(t *testing.T, scopes []string) string {
	t.Helper()
	ctx := context.Background()
	var rootTok string
	if err := core.Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		_, rootTok, err = core.CreateRoot(ctx, tx, "root-"+randname(t), "10.9.9.9")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	parent, err := e.d.LookupToken(ctx, rootTok)
	if err != nil {
		t.Fatal(err)
	}
	var tok string
	if err := core.Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		_, tok, err = core.CreateSubkeyV2(ctx, tx, parent, core.SubkeyOpts{
			Name: "u", Exp: time.Now().Add(time.Hour), Class: "url", Scopes: scopes})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return tok
}

func randname(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000)
}

func (e *env) get(t *testing.T, method, path string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func TestQueryTokenOnlyUrlClass(t *testing.T) {
	e := newEnv(t)
	_, urlTok := e.tokens(t)
	resp, body := e.get(t, "GET", "/v1/me/resume?t="+urlTok)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if !e.called {
		t.Fatal("downstream was not called")
	}
	if e.gotAuth != "Bearer "+urlTok {
		t.Fatalf("injected Authorization = %q", e.gotAuth)
	}
	if !e.marked {
		t.Fatal("request context was not marked urltoken")
	}
	if !strings.Contains(body, "hello world") {
		t.Fatalf("body = %q", body)
	}
}

// TestUrlTokenScopeCeiling: a non-default url token carrying a scope outside core.URLReadScopes
// (e.g. hook) is refused on the ?t= path (Finding #7), so it cannot leak private reads through a
// shareable link; downstream must never run.
func TestUrlTokenScopeCeiling(t *testing.T) {
	e := newEnv(t)
	urlTok := e.urlTokenScoped(t, []string{"hook"})
	resp, body := e.get(t, "GET", "/v1/me/resume?t="+urlTok)
	if resp.StatusCode != 403 {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if !strings.Contains(body, "err scope url token exceeds read ceiling") {
		t.Fatalf("body = %q", body)
	}
	if e.called {
		t.Fatal("downstream must not run for an over-scoped url token")
	}
}

// TestUrlTokenWithinCeiling: a url token holding only read-ceiling scopes (a subset of
// core.URLReadScopes) still works on the ?t= path.
func TestUrlTokenWithinCeiling(t *testing.T) {
	e := newEnv(t)
	urlTok := e.urlTokenScoped(t, []string{"me:r"})
	resp, body := e.get(t, "GET", "/v1/me/resume?t="+urlTok)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if !e.called {
		t.Fatal("downstream must run for an in-ceiling url token")
	}
}

func TestFullTokenInQueryRefused(t *testing.T) {
	e := newEnv(t)
	full, _ := e.tokens(t)
	resp, body := e.get(t, "GET", "/v1/me/resume?t="+full)
	if resp.StatusCode != 401 {
		t.Fatalf("status %d body %q", resp.StatusCode, body)
	}
	if !strings.Contains(body, "err auth header required") {
		t.Fatalf("body = %q", body)
	}
	if e.called {
		t.Fatal("downstream must not run for a full token in the URL")
	}
}

func TestOnlyGetHead(t *testing.T) {
	e := newEnv(t)
	_, urlTok := e.tokens(t)
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		e.called = false
		resp, body := e.get(t, m, "/v1/me?t="+urlTok)
		if resp.StatusCode != 405 {
			t.Fatalf("%s status %d body %q", m, resp.StatusCode, body)
		}
		if !strings.Contains(body, "query token is read-only") {
			t.Fatalf("%s body = %q", m, body)
		}
		if e.called {
			t.Fatalf("%s: downstream must not run", m)
		}
	}
	// HEAD is allowed and injects the bearer.
	e.called = false
	resp, _ := e.get(t, "HEAD", "/v1/me/resume?t="+urlTok)
	if resp.StatusCode != 200 || !e.called {
		t.Fatalf("HEAD status %d called %v", resp.StatusCode, e.called)
	}
}

func TestMailBodiesDenied(t *testing.T) {
	e := newEnv(t)
	_, urlTok := e.tokens(t)
	for _, path := range []string{"/v1/mb/m123?t=" + urlTok, "/v1/mb?all=1&t=" + urlTok} {
		e.called = false
		resp, body := e.get(t, "GET", path)
		if resp.StatusCode != 403 {
			t.Fatalf("%s status %d body %q", path, resp.StatusCode, body)
		}
		if !strings.Contains(body, "err scope mb:env") {
			t.Fatalf("%s body = %q", path, body)
		}
		if e.called {
			t.Fatalf("%s: downstream must not run", path)
		}
	}
	// The envelope list itself (no id, no ?all=1) is allowed.
	e.called = false
	resp, _ := e.get(t, "GET", "/v1/mb?t="+urlTok)
	if resp.StatusCode != 200 || !e.called {
		t.Fatalf("/v1/mb list status %d called %v", resp.StatusCode, e.called)
	}
}

func TestNextCarriesToken(t *testing.T) {
	e := newEnv(t)
	_, urlTok := e.tokens(t)
	resp, body := e.get(t, "GET", "/v1/me/resume?t="+urlTok)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "/v1/me/log?t="+urlTok) || !strings.Contains(body, "/v1/me/news?t="+urlTok) {
		t.Fatalf("next: paths do not carry the token: %q", body)
	}
	// The Link target is rewritten too.
	if link := resp.Header.Get("Link"); !strings.Contains(link, "/grammar?t="+urlTok) {
		t.Fatalf("Link header = %q", link)
	}
}

func TestNoStoreNoReferrerNoindex(t *testing.T) {
	e := newEnv(t)
	_, urlTok := e.tokens(t)
	resp, _ := e.get(t, "GET", "/v1/me/resume?t="+urlTok)
	if got := resp.Header.Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q", got)
	}
	if got := resp.Header.Get("X-Robots-Tag"); got != "noindex" {
		t.Fatalf("X-Robots-Tag = %q", got)
	}
}

func TestForceTextStripsHTML(t *testing.T) {
	for in, want := range map[string]string{
		"text/html":                      "text/plain",
		"text/html,text/plain":           "text/plain",
		"application/json":               "application/json",
		"text/html;q=0.9, text/markdown": "text/markdown",
		"":                               "text/plain",
	} {
		if got := forceText(in); got != want {
			t.Errorf("forceText(%q) = %q want %q", in, got, want)
		}
	}
}

func TestNoTokenPassesThrough(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.get(t, "GET", "/v1/me/resume")
	if resp.StatusCode != 200 || !e.called {
		t.Fatalf("no-token request status %d called %v", resp.StatusCode, e.called)
	}
	if resp.Header.Get("X-Robots-Tag") == "noindex" {
		t.Fatal("a non-capability read must not be stamped noindex by this middleware")
	}
}
