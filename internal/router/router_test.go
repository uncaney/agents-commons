package router

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/pages"
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
	} else if pool, done := testdb.Open("router", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	}
	// Pin the public base so relative/absolute comparisons are deterministic.
	doc.SetSite(doc.Site{Base: "https://agents.example"})
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func newDeps(t *testing.T) *core.Deps {
	t.Helper()
	if testPool == nil {
		t.Skip("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping DB-backed router test")
	}
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm", PowBits: 6, PowBitsW: 4,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	doc.SetSite(doc.Site{Base: "https://agents.example"})
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

// fakeTargets registers a 200 handler for every canonical target the alias table points at, so a
// followed redirect lands on a 2xx against an isolated mux.
func fakeTargets(mux *http.ServeMux) {
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	for _, p := range []string{
		"GET /q/{q...}", "GET /e/{msg...}", "GET /k/{id}", "GET /t/{n}", "GET /a/{id}", "GET /x/{id}",
		"GET /v1/t", "GET /index.md", "GET /llms.txt", "GET /AGENTS.md", "GET /openapi.json",
		"GET /.well-known/{rest...}", "GET /f/kb.atom", "GET /sitemap.xml", "GET /status",
	} {
		mux.HandleFunc(p, ok)
	}
}

// reqPath turns an alias source pattern into a concrete request path (wildcards -> a sample value).
func reqPath(pat string) string {
	pat = strings.ReplaceAll(pat, "{r...}", "sample")
	pat = strings.ReplaceAll(pat, "{r}", "kabcdef")
	return pat
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// TestEveryAliasOneRedirect: every alias answers a single 301 whose Location resolves to a 2xx.
func TestEveryAliasOneRedirect(t *testing.T) {
	mux := http.NewServeMux()
	fakeTargets(mux)
	mountAliases(mux)
	mux.HandleFunc("GET /sitemap.txt", sitemapTxt)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	var sources []string
	for _, a := range prefixAliases {
		sources = append(sources, a.pat)
	}
	for _, a := range exactAliases {
		sources = append(sources, a.pat)
	}

	for _, pat := range sources {
		p := reqPath(pat)
		res, err := noFollow.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusMovedPermanently {
			t.Fatalf("%s: first status %d, want 301", p, res.StatusCode)
		}
		loc := res.Header.Get("Location")
		if !strings.HasPrefix(loc, "/") {
			t.Fatalf("%s: Location %q not relative", p, loc)
		}
		if cc := res.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=86400") {
			t.Fatalf("%s: Cache-Control %q lacks max-age=86400", p, cc)
		}
		// Follow exactly one hop and require a 2xx (no second redirect).
		loc = strings.SplitN(loc, "#", 2)[0]
		res2, err := noFollow.Get(srv.URL + loc)
		if err != nil {
			t.Fatalf("%s -> %s: %v", p, loc, err)
		}
		res2.Body.Close()
		if res2.StatusCode/100 != 2 {
			t.Fatalf("%s -> %s: status %d, want 2xx after one redirect", p, loc, res2.StatusCode)
		}
	}
}

// TestNoAliasShadowsRealPattern: no alias pattern equals a real registered pattern, and mounting
// the alias table on top of a mux already carrying the real routes never panics (ServeMux panics
// on a duplicate or ambiguous pattern).
func TestNoAliasShadowsRealPattern(t *testing.T) {
	real := []string{
		"GET /q/{q...}", "GET /e/{msg...}", "GET /k/{id}", "GET /t/{n}", "GET /a/{id}", "GET /x/{id}",
		"GET /tag/{t}", "GET /qa/{slug}", "GET /index.md", "GET /llms.txt", "GET /llms-full.txt",
		"GET /AGENTS.md", "GET /grammar", "GET /help", "GET /now", "GET /join.py", "GET /status",
		"GET /status/history", "GET /healthz", "GET /skills", "GET /tags", "GET /brief", "GET /v1",
		"GET /feed.xml", "GET /feed.json", "GET /f/{name...}", "GET /.well-known/cx-key",
		"GET /openapi.json", "GET /sitemap.xml", "GET /v1/t", "POST /e", "POST /q", "POST /v1/register",
		"GET /oembed", "GET /metrics", "GET /errsig",
		// method-less single-segment literals (and the /git/ subtree): the "/{seg}" catch-all must stay
		// a strict superset of these so each wins — a GET-only "GET /{seg}" would be ambiguous and panic.
		"/mcp", "/a2a", "GET /sse", "/sse", "POST /messages", "/messages", "/git/",
	}
	realSet := map[string]bool{}
	for _, p := range real {
		realSet[p] = true
	}
	for _, a := range aliasPatterns() {
		if realSet[a] {
			t.Errorf("alias %q equals a real registered pattern", a)
		}
	}
	// Mount real first, then the whole router surface: a shadow would panic here.
	mux := http.NewServeMux()
	for _, p := range real {
		mux.HandleFunc(p, func(http.ResponseWriter, *http.Request) {})
	}
	mux.HandleFunc("/", func(http.ResponseWriter, *http.Request) {}) // pages' catch-all
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("mounting router over real patterns panicked: %v", r)
			}
		}()
		mountAliases(mux)
		mux.HandleFunc("/{seg}", (&rt{}).catch)
	}()
}

// TestBareIdVisibleOnly: a bare id for a visible object 302s to its URL; a hidden/quarantined id
// (resolver returns ok=false) gets the same 404 as an unknown id; 64-hex -> /x/, digits -> /t/.
func TestBareIdVisibleOnly(t *testing.T) {
	d := newDeps(t)
	d.RegisterResolver('k', func(ctx context.Context, id string) (string, string, string, bool) {
		if id == "kvisibl" {
			return "entry", "a title", doc.Base() + "/k/kvisibl", true
		}
		return "", "", "", false // hidden/quarantined/unknown
	})
	h := &rt{d: d}

	do := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		req.SetPathValue("seg", strings.TrimPrefix(path, "/"))
		rec := httptest.NewRecorder()
		h.seg(rec, req)
		return rec
	}

	if rec := do("/kvisibl"); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/k/kvisibl" {
		t.Fatalf("visible bare id: %d loc=%q, want 302 /k/kvisibl", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do("/khidden"); rec.Code != http.StatusNotFound {
		t.Fatalf("hidden bare id: %d, want 404", rec.Code)
	}
	hash := strings.Repeat("a", 64)
	if rec := do("/" + hash); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/x/"+hash {
		t.Fatalf("64-hex: %d loc=%q, want 302 /x/<hash>", rec.Code, rec.Header().Get("Location"))
	}
	if rec := do("/12345"); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/t/12345" {
		t.Fatalf("digits: %d loc=%q, want 302 /t/12345", rec.Code, rec.Header().Get("Location"))
	}
}

// TestDidYouMeanSuggestions: a near-miss first segment yields <= 2 relative suggestions closest
// first, and the 404 body carries them.
func TestDidYouMeanSuggestions(t *testing.T) {
	if got := suggest("grammr"); len(got) == 0 || got[0] != "/grammar" {
		t.Fatalf("suggest(grammr)=%v, want /grammar first", got)
	}
	if got := suggest("serch"); len(got) == 0 || got[0] != "/search" {
		t.Fatalf("suggest(serch)=%v, want /search first", got)
	}
	if got := suggest("qqqqqqqqqqzzzzz"); len(got) != 0 {
		t.Fatalf("suggest(far)=%v, want none", got)
	}
	if got := suggest("tags"); len(got) > 2 {
		t.Fatalf("suggest returned %d, want <= 2", len(got))
	}

	// End to end through the single-segment handler: body names the suggestion.
	h := &rt{}
	req := httptest.NewRequest("GET", "/grammr", nil)
	req.SetPathValue("seg", "grammr")
	rec := httptest.NewRecorder()
	h.seg(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "/grammar") {
		t.Fatalf("404 body lacks the suggestion /grammar:\n%s", body)
	}
}

// TestOptionsAffordances: OPTIONS / and OPTIONS * answer 200 with the grammar; any other path
// answers 204 with Allow and an X-Next affordance line.
func TestOptionsAffordances(t *testing.T) {
	doc.SetSite(doc.Site{Base: "https://agents.example"})
	h := &rt{}

	for _, p := range []string{"/", "*"} {
		req := httptest.NewRequest("OPTIONS", "http://x"+norm(p), nil)
		req.URL.Path = p
		rec := httptest.NewRecorder()
		h.options(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("OPTIONS %q: %d, want 200", p, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "/q/<text>") {
			t.Fatalf("OPTIONS %q: body is not the grammar:\n%s", p, rec.Body.String())
		}
	}

	req := httptest.NewRequest("OPTIONS", "http://x/k/kabcdef", nil)
	rec := httptest.NewRecorder()
	h.options(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS /k/..: %d, want 204", rec.Code)
	}
	if al := rec.Header().Get("Allow"); !strings.Contains(al, "GET") || !strings.Contains(al, "OPTIONS") {
		t.Fatalf("Allow=%q, want GET+OPTIONS", al)
	}
	if xn := rec.Header().Get("X-Next"); !strings.Contains(xn, "GET /k/kabcdef") {
		t.Fatalf("X-Next=%q, want the reflected /k GET affordance", xn)
	}
}

func norm(p string) string {
	if p == "*" {
		return "/"
	}
	return p
}

// TestOpenRedirectImpossible: a remainder that tries to become protocol-relative or absolute is
// percent-encoded into a single relative segment; the Location never gains a host or scheme.
func TestOpenRedirectImpossible(t *testing.T) {
	mux := http.NewServeMux()
	mountAliases(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// A multi-segment remainder has its slashes percent-encoded into one segment, so it can never
	// walk out of /q/ or become protocol-relative. (Dup-slash/.. request paths are collapsed by
	// ServeMux before the handler; the protocol-relative case is covered by the unit asserts below.)
	for _, tc := range []struct{ path, wantPrefix string }{
		{"/search/evil.com", "/q/evil.com"},
		{"/find/a/b/c", "/q/a%2Fb%2Fc"},
		{"/error/x/y", "/e/x%2Fy"},
	} {
		res, err := noFollow.Get(srv.URL + tc.path)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		res.Body.Close()
		loc := res.Header.Get("Location")
		if loc != tc.wantPrefix {
			t.Fatalf("%s: Location %q, want %q", tc.path, loc, tc.wantPrefix)
		}
		if strings.HasPrefix(loc, "//") || strings.Contains(loc, "://") {
			t.Fatalf("%s: Location %q is protocol-relative or absolute", tc.path, loc)
		}
	}

	// Unit-level: encodeRemainder escapes slashes and colons, caps at 300 bytes, drops bad UTF-8.
	if got := encodeRemainder("//evil.com"); strings.Contains(got, "//") || strings.HasPrefix(got, "/") {
		t.Fatalf("encodeRemainder kept a slash: %q", got)
	}
	if got := encodeRemainder(strings.Repeat("a", 500)); len(got) > 300 {
		t.Fatalf("encodeRemainder did not cap: len=%d", len(got))
	}
	if got := encodeRemainder("x\xff\xfey"); !strings.HasPrefix(got, "x") {
		t.Fatalf("encodeRemainder on bad UTF-8: %q", got)
	}
	_ = pages.Grammar
}
