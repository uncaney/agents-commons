package demand

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/know"
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
	} else if pool, done := testdb.Open("demand", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping demand DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type env struct {
	d   *core.Deps
	srv *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	for _, sql := range []string{`TRUNCATE demand`, `TRUNCATE rank_weak`, `DELETE FROM egress_outbox WHERE kind IN ('indexnow', 'bing_content')`,
		`TRUNCATE wanted`, `DELETE FROM flags WHERE k IN ('bing:cursor', 'bing:quota')`} {
		if _, err := testPool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", OpsToken: "ops-token", CourierToken: "courier-tok", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(ctx, cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	know.SetWantedSecret(cfg.ServerSecret)
	mux := http.NewServeMux()
	core.Register(mux, d)
	know.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &env{d: d, srv: srv}
}

func (e *env) do(t *testing.T, method, path, token string, body any) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", "10.9.9.9")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b))
}

func TestAdminDemandStrictScrub(t *testing.T) {
	e := newEnv(t)
	// Three rows: two clean, one carrying an AWS access key id -> dropped by scrub.Strict.
	rows := []map[string]any{
		{"q": "pydantic v2 validator error", "impressions": 120, "clicks": 3, "position": 14.2, "page": "https://agents.example/kb/abc"},
		{"q": "rust borrow checker lifetime", "impressions": 88, "clicks": 1, "position": 9.5},
		{"q": "my key is AKIAQ7R2M9XKT4P8ZL3W help", "impressions": 40, "clicks": 0, "position": 20},
	}
	st, body := e.do(t, "POST", "/admin/demand", "ops-token", map[string]any{"src": "gsc", "rows": rows})
	if st != 200 {
		t.Fatalf("admin/demand: %d %s", st, body)
	}
	if !strings.Contains(body, "stored=2") || !strings.Contains(body, "dropped=1") {
		t.Fatalf("expected stored=2 dropped=1, got %q", body)
	}
	// The AKIA row must not be in the table.
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM demand WHERE q LIKE '%AKIA%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("AKIA row stored: %d", n)
	}
	// No token -> 401.
	if st, _ := e.do(t, "POST", "/admin/demand", "", map[string]any{"src": "gsc", "rows": rows}); st != 401 {
		t.Fatalf("admin/demand without ops token: %d", st)
	}
	// Bad src -> 400.
	if st, _ := e.do(t, "POST", "/admin/demand", "ops-token", map[string]any{"src": "yahoo", "rows": rows}); st != 400 {
		t.Fatalf("admin/demand bad src: %d", st)
	}
}

func TestWantedKindQ(t *testing.T) {
	e := newEnv(t)
	rows := []map[string]any{
		{"q": "pydantic v2 validator error", "impressions": 120, "clicks": 3, "position": 14.2},
		{"q": "rust borrow checker lifetime", "impressions": 88, "clicks": 1, "position": 9.5},
		{"q": "sqlalchemy 2 session begin", "impressions": 55, "clicks": 0, "position": 11},
	}
	if st, body := e.do(t, "POST", "/admin/demand", "ops-token", map[string]any{"src": "gsc", "rows": rows}); st != 200 {
		t.Fatalf("admin/demand: %d %s", st, body)
	}
	st, body := e.do(t, "GET", "/wanted", "", nil)
	if st != 200 {
		t.Fatalf("wanted: %d %s", st, body)
	}
	if !strings.Contains(body, "searched (engines)") {
		t.Fatalf("/wanted missing engines block:\n%s", body)
	}
	for _, want := range []string{"pydantic v2 validator error", "rust borrow checker lifetime", "sqlalchemy 2 session begin"} {
		if !strings.Contains(body, want) {
			t.Fatalf("/wanted missing query %q:\n%s", want, body)
		}
	}
}

func TestTransparencyPage(t *testing.T) {
	e := newEnv(t)
	rows := []map[string]any{
		{"q": "pydantic v2 validator error", "impressions": 120, "clicks": 3, "position": 14.2},
		{"q": "rust borrow checker lifetime", "impressions": 88, "clicks": 1, "position": 9.5},
	}
	if st, body := e.do(t, "POST", "/admin/demand", "ops-token", map[string]any{"src": "gsc", "rows": rows}); st != 200 {
		t.Fatalf("admin/demand: %d %s", st, body)
	}
	st, body := e.do(t, "GET", "/transparency", "", nil)
	if st != 200 {
		t.Fatalf("transparency: %d %s", st, body)
	}
	if !strings.Contains(body, "impressions=208") || !strings.Contains(body, "clicks=4") {
		t.Fatalf("transparency totals wrong:\n%s", body)
	}
	if !strings.Contains(body, "pydantic v2 validator error") {
		t.Fatalf("transparency missing top query:\n%s", body)
	}
	// The page is indexable: no noindex header.
	req, _ := http.NewRequest("GET", e.srv.URL+"/transparency", nil)
	req.Header.Set("CF-Connecting-IP", "10.9.9.9")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if strings.Contains(strings.ToLower(res.Header.Get("X-Robots-Tag")), "noindex") {
		t.Fatalf("/transparency must be indexable, got X-Robots-Tag=%q", res.Header.Get("X-Robots-Tag"))
	}
}

func TestRankWeakFreshSitemapRealLastmod(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	created := time.Date(2021, 6, 14, 0, 0, 0, 0, time.UTC)
	confirmed := time.Date(2021, 6, 15, 12, 0, 0, 0, time.UTC)
	kbID := "k" + "weak01"
	if _, err := testPool.Exec(ctx, `INSERT INTO kb (id, kind, title, author, author_root, created, confirmed_at, expires_at)
		VALUES ($1, 'fix', 'pydantic v2 validator migration', 'seed', '', $2, $3, now() + interval '365 days')`,
		kbID, created, confirmed); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM kb WHERE id = $1`, kbID) })
	if _, err := testPool.Exec(ctx, `INSERT INTO demand (src, q, impressions, clicks, position) VALUES ('gsc', 'pydantic v2 validator', 300, 2, 15)`); err != nil {
		t.Fatal(err)
	}
	// Deterministic scoring: the top hit is our entry, scoring above the weak threshold.
	orig := SearchTop
	SearchTop = func(ctx context.Context, q core.Q, query string) (string, float64, bool) { return kbID, 0.7, true }
	t.Cleanup(func() { SearchTop = orig })

	if err := MarkWeak(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM rank_weak WHERE kb_id = $1`, kbID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("rank_weak rows for %s = %d", kbID, n)
	}
	urls, err := freshSitemap(ctx, testPool)
	if err != nil {
		t.Fatal(err)
	}
	var got *core.SitemapURL
	for i := range urls {
		if strings.HasSuffix(urls[i].Loc, "/kb/"+kbID) {
			got = &urls[i]
		}
	}
	if got == nil {
		t.Fatalf("fresh sitemap missing %s: %+v", kbID, urls)
	}
	// Real lastmod: greatest(created, confirmed_at) == confirmed, NOT since (now) and NOT now().
	if !got.LastMod.Equal(confirmed) {
		t.Fatalf("fresh lastmod = %s, want the real modified time %s (no fabricated lastmod)", got.LastMod, confirmed)
	}
	if time.Since(got.LastMod) < 24*time.Hour {
		t.Fatalf("fresh lastmod looks fabricated (near now): %s", got.LastMod)
	}
	// A below-threshold score must not mark an entry weak.
	testPool.Exec(ctx, `TRUNCATE rank_weak`)
	SearchTop = func(ctx context.Context, q core.Q, query string) (string, float64, bool) { return kbID, 0.4, true }
	if err := MarkWeak(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM rank_weak`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("weak threshold leaked: %d rows", n)
	}
}

func TestInternalRenderOnlyPublicURL(t *testing.T) {
	e := newEnv(t)
	h := &handlers{d: e.d, mux: http.NewServeMux()}
	call := func(raw string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/internal/render?url="+raw, nil)
		h.render(rec, req)
		return rec.Code
	}
	// Under PUBLIC_URL -> 200 and a real HTTP/1.1 rendition.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/internal/render?url=https%3A%2F%2Fagents.example%2Ftransparency", nil)
	h.render(rec, req)
	if rec.Code != 200 {
		t.Fatalf("render under public url: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "message/http" {
		t.Fatalf("render content-type = %q", ct)
	}
	if !strings.HasPrefix(rec.Body.String(), "HTTP/") {
		t.Fatalf("render body is not a full HTTP response:\n%.80q", rec.Body.String())
	}
	// Off-origin and relative URLs -> 400.
	if c := call("https%3A%2F%2Fevil.example%2Fx"); c != 400 {
		t.Fatalf("foreign host must be 400, got %d", c)
	}
	if c := call("%2Fkb%2Fabc"); c != 400 {
		t.Fatalf("relative url must be 400, got %d", c)
	}
	if c := call("http%3A%2F%2Fagents.example%2Fx"); c != 400 {
		t.Fatalf("wrong scheme must be 400, got %d", c)
	}
}

func TestOnIndexableEnqueuesBing(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Two indexnow outbox rows carrying three distinct URLs.
	for _, urls := range []string{`["https://agents.example/kb/a","https://agents.example/kb/b"]`, `["https://agents.example/kb/c"]`} {
		if _, err := testPool.Exec(ctx, `INSERT INTO egress_outbox (kind, payload) VALUES ('indexnow', $1)`,
			json.RawMessage(`{"urls":`+urls+`}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := OnIndexable(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM egress_outbox WHERE kind = 'bing_content'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("bing_content enqueued = %d, want 3", n)
	}
	// Idempotent: a second run past the cursor enqueues nothing new.
	if err := OnIndexable(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM egress_outbox WHERE kind = 'bing_content'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("bing_content after second run = %d, want 3 (cursor not advanced)", n)
	}
	// A daily quota of 0 enqueues nothing even with fresh indexnow rows.
	testPool.Exec(ctx, `DELETE FROM egress_outbox WHERE kind = 'bing_content'`)
	testPool.Exec(ctx, `INSERT INTO egress_outbox (kind, payload) VALUES ('indexnow', '{"urls":["https://agents.example/kb/d"]}')`)
	if err := e.d.SetFlag(ctx, "bing:quota", true, "0"); err != nil {
		t.Fatal(err)
	}
	if err := OnIndexable(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM egress_outbox WHERE kind = 'bing_content'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("quota 0 enqueued %d", n)
	}
}
