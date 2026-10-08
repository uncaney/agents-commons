package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// newWire is newEnv with extra routes and config tweaks (the v1 helper is owned by P02).
func newWire(t *testing.T, mod func(*Config), routes func(*http.ServeMux, *Deps)) *tenv {
	t.Helper()
	cfg := Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", LicenseContent: "CC0-1.0"}
	if mod != nil {
		mod(&cfg)
	}
	d, err := NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	Register(mux, d)
	if routes != nil {
		routes(mux, d)
	}
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	var b [2]byte
	rand.Read(b[:])
	return &tenv{d, srv, fmt.Sprintf("10.7.%d.%d", b[0], b[1])}
}

// doH is tenv.do returning the response headers too.
func (e *tenv) doH(t *testing.T, method, path, token string, body string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", e.ip)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

func fakeReq(ip string) *http.Request {
	r := httptest.NewRequest("GET", "/v1/me", nil)
	r.Header.Set("CF-Connecting-IP", ip)
	return r
}

func cleanFlags(t *testing.T, d *Deps, keys ...string) {
	t.Helper()
	t.Cleanup(func() {
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM flags WHERE k = ANY($1)`, keys)
		d.RefreshFlags(ctx)
	})
}

func TestRateBudget(t *testing.T) {
	e := newWire(t, nil, nil)
	l := e.d.Lim
	base := time.Now()
	l.now = func() time.Time { return base }
	root := &Ident{ID: "a1111111", Root: "a1111111", Rep: 10} // factor 3: 30 r/s burst 90
	r := fakeReq("198.51.100.9")
	n := 0
	for e.d.AllowCost(r, root, 1) {
		n++
		if n > 200 {
			t.Fatal("never limited")
		}
	}
	if n != 90 {
		t.Fatalf("rep-scaled burst: %d", n)
	}
	// A subkey lives under the root ceiling: nothing left for it either.
	sub := &Ident{ID: "a2222222", Root: "a1111111", Rep: 10}
	if e.d.AllowCost(r, sub, 1) {
		t.Fatal("subkey escaped the root ceiling")
	}
	l.now = func() time.Time { return base.Add(time.Second) } // +30 tokens
	okSub := 0
	for e.d.AllowCost(r, sub, 1) {
		okSub++
	}
	if okSub != 30 {
		t.Fatalf("subkey after refill: %d", okSub)
	}
	// Fractional costs: five 0.2 polls cost one token.
	l2 := NewLimiter()
	l2.now = func() time.Time { return base }
	for i := 0; i < 5*30; i++ {
		if !l2.AllowCost("k", 10, 30, 0.2) {
			t.Fatalf("poll %d refused", i)
		}
	}
	if l2.AllowCost("k", 10, 30, 0.2) {
		t.Fatal("over burst with fractional cost")
	}
	// Allow is AllowCost(…, 1); Take reports the governing bucket.
	l3 := NewLimiter()
	l3.now = func() time.Time { return base }
	ok, info := l3.Take(1, Spec{"a", 10, 30}, Spec{"b", 5, 20})
	if !ok || info.Limit != 20 || info.Remaining != 19 || info.Window != 4 {
		t.Fatalf("take info: %+v", info)
	}
	for i := 0; i < 19; i++ {
		l3.Take(1, Spec{"a", 10, 30}, Spec{"b", 5, 20})
	}
	ok, info = l3.Take(1, Spec{"a", 10, 30}, Spec{"b", 5, 20})
	if ok || info.RetryAfter != 1 {
		t.Fatalf("refused take: ok=%v %+v", ok, info)
	}
	// All-or-nothing: the refused call charged neither bucket.
	if okA, _ := l3.Take(1, Spec{"a", 10, 30}); !okA {
		t.Fatal("bucket a was charged by a refused multi-take")
	}
}

func TestSuperGroupBucket(t *testing.T) {
	e := newWire(t, nil, nil)
	base := time.Now()
	e.d.Lim.now = func() time.Time { return base }
	total := 0
	perIP := map[string]int{}
	for i := 1; i <= 5; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		for j := 0; j < 20; j++ {
			if e.d.Allow(fakeReq(ip), nil) {
				total++
				perIP[ip]++
			}
		}
	}
	if total != 80 || perIP["203.0.113.1"] != 20 || perIP["203.0.113.5"] != 0 {
		t.Fatalf("super-group /24 ceiling: total=%d perIP=%v", total, perIP)
	}
	// Another /24 is unaffected; IPv6 collapses on /48.
	if !e.d.Allow(fakeReq("203.0.114.1"), nil) {
		t.Fatal("other /24 limited")
	}
	v6 := 0
	for i := 1; i <= 5; i++ {
		for j := 0; j < 20; j++ {
			if e.d.Allow(fakeReq(fmt.Sprintf("2001:db8:7:%x::1", i)), nil) {
				v6++
			}
		}
	}
	if v6 != 80 {
		t.Fatalf("/48 ceiling: %d", v6)
	}
}

func TestRateLimitHeaders(t *testing.T) {
	e := newWire(t, nil, nil)
	st, _, h := e.doH(t, "GET", "/healthz", "", "")
	if st != 200 || h.Get("RateLimit-Policy") != "20;w=4" || !strings.HasPrefix(h.Get("RateLimit"), "limit=20, remaining=19, reset=") {
		t.Fatalf("headers: %d policy=%q rl=%q", st, h.Get("RateLimit-Policy"), h.Get("RateLimit"))
	}
	var last http.Header
	st = 200
	for i := 0; i < 30 && st != 429; i++ {
		st, _, last = e.doH(t, "GET", "/healthz", "", "")
	}
	if st != 429 || last.Get("Retry-After") == "" || !strings.Contains(last.Get("RateLimit"), "remaining=0") {
		t.Fatalf("429 headers: %d %v", st, last)
	}
	st, body, last := e.doH(t, "GET", "/healthz?v=2", "", "")
	if st != 429 || !strings.Contains(body, "next: retry retry_s=") {
		t.Fatalf("v2 429 tail: %d %q", st, body)
	}
	st, body, last = e.doH(t, "GET", "/healthz", "", "", "Accept", "application/json")
	if st != 429 || !strings.Contains(body, `"retry_s":`) || last.Get("Retry-After") == "" {
		t.Fatalf("json 429: %d %s", st, body)
	}
}

func TestWaitersCap(t *testing.T) {
	w := NewWaiters(5, 2, 1)
	rel1, ok1 := w.Acquire("r1", "")
	rel2, ok2 := w.Acquire("r1", "")
	_, ok3 := w.Acquire("r1", "")
	if !ok1 || !ok2 || ok3 || w.Len() != 2 {
		t.Fatalf("per root: %v %v %v len=%d", ok1, ok2, ok3, w.Len())
	}
	relG, okG := w.Acquire("", "g1")
	_, okG2 := w.Acquire("", "g1")
	if !okG || okG2 {
		t.Fatal("per group")
	}
	_, okA := w.Acquire("r2", "")
	_, okB := w.Acquire("r3", "")
	_, okC := w.Acquire("r4", "")
	if !okA || !okB || okC || w.Len() != 5 {
		t.Fatalf("global cap: %v %v %v len=%d", okA, okB, okC, w.Len())
	}
	rel1()
	rel1() // idempotent
	if _, ok := w.Acquire("r4", ""); !ok || w.Len() != 5 {
		t.Fatal("release did not free a slot")
	}
	rel2()
	relG()
	if w.Len() != 3 {
		t.Fatalf("len after releases: %d", w.Len())
	}
	if e := newWire(t, nil, nil); e.d.Waiters == nil || e.d.Waiters.Len() != 0 {
		t.Fatal("deps waiters")
	}
}

func TestIdemReplayAndConflict(t *testing.T) {
	e := newWire(t, nil, nil)
	ctx := context.Background()
	root, _ := e.register(t, "idem")
	id := &Ident{ID: root, Root: root}
	h1 := sha256.Sum256([]byte("body-1"))
	h2 := sha256.Sum256([]byte("body-2"))
	runs := 0
	fn := func() (int, string, error) { runs++; return 201, "ok k1", nil }
	st, body, err := Idem(ctx, e.d, id, "key-1", "POST /v1/kb", h1[:], fn)
	if err != nil || st != 201 || body != "ok k1" || runs != 1 {
		t.Fatalf("first: %d %q %v runs=%d", st, body, err, runs)
	}
	st, body, err = Idem(ctx, e.d, id, "key-1", "POST /v1/kb", h1[:], fn)
	if err != nil || st != 201 || body != "ok k1\nidem=replay" || runs != 1 {
		t.Fatalf("replay: %d %q %v runs=%d", st, body, err, runs)
	}
	if _, _, err = Idem(ctx, e.d, id, "key-1", "POST /v1/kb", h2[:], fn); err != ErrIdem {
		t.Fatalf("different body: %v", err)
	}
	if _, _, err = Idem(ctx, e.d, id, "key-1", "POST /v1/t", h1[:], fn); err != ErrIdem {
		t.Fatalf("different route: %v", err)
	}
	// Placeholder without result (first run still in flight) -> busy.
	testPool.Exec(ctx, `INSERT INTO idem (root, key, route, req_hash) VALUES ($1, 'inflight', 'r', $2)`, root, h1[:])
	if _, _, err = Idem(ctx, e.d, id, "inflight", "r", h1[:], fn); err != ErrIdemBusy {
		t.Fatalf("in flight: %v", err)
	}
	// A failing fn frees the key so the client can retry.
	fails := 0
	_, _, err = Idem(ctx, e.d, id, "key-2", "r", h1[:], func() (int, string, error) { fails++; return 0, "", ErrCredits })
	if err != ErrCredits {
		t.Fatalf("fn error: %v", err)
	}
	if st, body, err = Idem(ctx, e.d, id, "key-2", "r", h1[:], fn); err != nil || body != "ok k1" || fails != 1 {
		t.Fatalf("retry after failure: %d %q %v", st, body, err)
	}
	// Empty key: no idempotency; bad key: 400.
	if _, _, err = Idem(ctx, e.d, id, "", "r", h1[:], fn); err != nil || runs != 3 {
		t.Fatalf("empty key: %v runs=%d", err, runs)
	}
	if _, _, err = Idem(ctx, e.d, id, strings.Repeat("k", 65), "r", h1[:], fn); err == nil || !strings.Contains(err.Error(), "err bad") {
		t.Fatalf("long key: %v", err)
	}
	// L0 cap: 100 keys per root; a large body is not stored for replay.
	for i := 0; i < 100; i++ {
		testPool.Exec(ctx, `INSERT INTO idem (root, key, route, req_hash, status, body) VALUES ($1, $2, 'r', $3, 200, 'x') ON CONFLICT DO NOTHING`, root, fmt.Sprintf("fill-%d", i), h1[:])
	}
	if _, _, err = Idem(ctx, e.d, id, "one-more", "r", h1[:], fn); err == nil || !strings.Contains(err.Error(), "err quota") {
		t.Fatalf("cap: %v", err)
	}
	testPool.Exec(ctx, `DELETE FROM idem WHERE root = $1`, root)
	big := strings.Repeat("b", 2000)
	if _, body, err = Idem(ctx, e.d, id, "big", "r", h1[:], func() (int, string, error) { return 200, big, nil }); err != nil || body != big {
		t.Fatalf("big: %v", err)
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM idem WHERE root = $1 AND key = 'big'`, root).Scan(&n)
	if n != 0 {
		t.Fatal("oversize body kept a placeholder")
	}
	// Janitor TTL 24 h.
	testPool.Exec(ctx, `UPDATE idem SET created = now() - interval '25 hours' WHERE root = $1`, root)
	e.d.Janitor.RunOnce(ctx)
	testPool.QueryRow(ctx, `SELECT count(*) FROM idem WHERE root = $1`, root).Scan(&n)
	if n != 0 {
		t.Fatalf("janitor left %d idem rows", n)
	}
}

func TestHeadersPolicy(t *testing.T) {
	e := newWire(t, nil, func(mux *http.ServeMux, d *Deps) {
		pub := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "public, max-age=60")
			OK(w, r, "page", nil)
		}
		mux.HandleFunc("GET /{$}", pub)
		mux.HandleFunc("GET /k/{id}", pub)
		mux.HandleFunc("GET /kb/{$}", pub)
		mux.HandleFunc("GET /e/{sig}", pub)
		mux.HandleFunc("GET /embed/{id}", pub)
		mux.HandleFunc("GET /v1/kb", func(w http.ResponseWriter, r *http.Request) { OK(w, r, "hits", nil) })
	})
	_, tok := e.register(t, "hdr")
	st, _, h := e.doH(t, "GET", "/v1/kb", tok, "")
	if st != 200 || h.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("token request cache: %d %q", st, h.Get("Cache-Control"))
	}
	if _, _, h = e.doH(t, "GET", "/k/kabc", tok, ""); h.Get("Cache-Control") != "private, max-age=60" {
		t.Fatalf("handler public cache survived a token: %q", h.Get("Cache-Control"))
	}
	if privateCache("public, max-age=31536000, immutable") != "private, max-age=31536000, immutable" || privateCache("") != "private, no-store" || privateCache("s-maxage=5, public") != "private" {
		t.Fatal("privateCache")
	}
	if _, _, h = e.doH(t, "GET", "/k/kabc?t=cx_x", "", ""); h.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("?t= request not private: %q", h.Get("Cache-Control"))
	}
	if _, _, h = e.doH(t, "GET", "/k/kabc", "", ""); h.Get("Cache-Control") != "public, max-age=60" {
		t.Fatalf("anonymous cache overridden: %q", h.Get("Cache-Control"))
	}
	// Robots by prefix.
	for path, want := range map[string]string{"/v1/me": "noindex", "/e/sig": "noindex, follow", "/kb/?q=x": "noindex", "/kb/": "", "/k/kabc": "", "/": ""} {
		_, _, h := e.doH(t, "GET", path, tok, "")
		if got := h.Get("X-Robots-Tag"); got != want {
			t.Errorf("%s: X-Robots-Tag %q want %q", path, got, want)
		}
	}
	// Frame options everywhere but /embed/.
	if _, _, h = e.doH(t, "GET", "/embed/x", "", ""); h.Get("X-Frame-Options") != "" {
		t.Fatal("embed got X-Frame-Options")
	}
	if _, _, h = e.doH(t, "GET", "/k/kabc", "", ""); h.Get("X-Frame-Options") != "DENY" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("security headers")
	}
	// Link headers: trio everywhere on 200, root additions on /.
	_, _, h = e.doH(t, "GET", "/", "", "")
	link := strings.Join(h.Values("Link"), ", ")
	for _, want := range []string{`</openapi.json>; rel="service-desc"`, `</llms.txt>; rel="service-doc"`, `</.well-known/api-catalog>; rel="api-catalog"`, `</grammar>; rel="help"`, `</q/{q}>; rel="search"; templated`} {
		if !strings.Contains(link, want) {
			t.Errorf("root Link missing %s: %s", want, link)
		}
	}
	_, _, h = e.doH(t, "GET", "/v1/me", tok, "")
	if l := h.Get("Link"); !strings.Contains(l, `rel="help"`) || strings.Contains(l, "service-desc") {
		t.Fatalf("/v1/me link: %s", l)
	}
	if _, _, h = e.doH(t, "GET", "/v1/me", "", ""); h.Get("Link") != "" {
		t.Fatalf("401 carried Link: %s", h.Get("Link"))
	}
	// CORS on public GETs.
	_, _, h = e.doH(t, "GET", "/v1/me", tok, "")
	if h.Get("Access-Control-Allow-Origin") != "*" || !strings.Contains(h.Get("Access-Control-Expose-Headers"), "RateLimit") {
		t.Fatalf("cors: %v", h)
	}
	if _, _, h = e.doH(t, "GET", "/embed/x", "", ""); h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("cors on a non-public path")
	}
}

func TestCORSPreflight(t *testing.T) {
	e := newWire(t, nil, nil)
	for _, p := range []string{"/mcp", "/a2a", "/v1/kb", "/v1/me"} {
		st, _, h := e.doH(t, "OPTIONS", p, "", "", "Origin", "https://app.example", "Access-Control-Request-Method", "POST")
		ah := h.Get("Access-Control-Allow-Headers")
		if st != 204 || h.Get("Access-Control-Allow-Origin") != "*" || !strings.Contains(ah, "Idempotency-Key") || !strings.Contains(ah, "X-PoW") ||
			!strings.Contains(ah, "Mcp-Session-Id") || !strings.Contains(h.Get("Access-Control-Allow-Methods"), "DELETE") || h.Get("Access-Control-Max-Age") != "86400" {
			t.Fatalf("%s preflight: %d %v", p, st, h)
		}
	}
	// Plain OPTIONS (curl -X OPTIONS /mcp) answers the same way; other paths fall through to the mux.
	if st, _, _ := e.doH(t, "OPTIONS", "/mcp", "", ""); st != 204 {
		t.Fatalf("bare OPTIONS /mcp: %d", st)
	}
	if st, _, _ := e.doH(t, "OPTIONS", "/healthz", "", ""); st == 204 {
		t.Fatal("preflight on a non-API path")
	}
}

func TestFlagsAnyKey(t *testing.T) {
	e := newWire(t, nil, nil)
	ctx := context.Background()
	keys := []string{"freeze:blobs", "shed:anon-search", "maintenance_until", "edgekv:/robots.txt", "freeze:kb", "freeze:write", "freeze:all"}
	cleanFlags(t, e.d, keys...)
	for _, bad := range []string{"Bogus", "a b", strings.Repeat("a", 90), "", "9x", "k;drop"} {
		if err := e.d.SetFlag(ctx, bad, true, ""); err == nil {
			t.Fatalf("accepted key %q", bad)
		}
	}
	if err := e.d.SetFreeze(ctx, "bogus", true); err == nil {
		t.Fatal("v1 SetFreeze accepted a bare unknown kind")
	}
	if err := e.d.SetFreeze(ctx, "freeze:kb", true); err != nil || !e.d.Frozen("kb") || !e.d.Frozen("freeze:kb") {
		t.Fatalf("freeze:kb: %v", err)
	}
	if err := e.d.SetFlag(ctx, "freeze:blobs", true, ""); err != nil || !e.d.Frozen("blobs") || e.d.Frozen("write") {
		t.Fatalf("freeze:blobs: %v", err)
	}
	if err := e.d.SetFlag(ctx, "shed:anon-search", true, ""); err != nil || !e.d.Flag("shed:anon-search") || !e.d.Shed(fakeReq("1.1.1.1"), "anon-search") || e.d.Shed(nil, "feeds") {
		t.Fatalf("shed flag: %v", err)
	}
	if err := e.d.SetFlag(ctx, "edgekv:/robots.txt", true, "sha256:abc"); err != nil || e.d.FlagStr("edgekv:/robots.txt") != "sha256:abc" {
		t.Fatalf("string flag: %v %q", err, e.d.FlagStr("edgekv:/robots.txt"))
	}
	until := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	if err := e.d.SetFlag(ctx, "maintenance_until", true, until); err != nil {
		t.Fatal(err)
	}
	if tm, ok := MaintenanceUntil(); !ok || tm.UTC().Format(time.RFC3339) != until {
		t.Fatal("maintenance_until not mirrored")
	}
	e.d.SetFlag(ctx, "maintenance_until", false, until)
	if _, ok := MaintenanceUntil(); ok {
		t.Fatal("maintenance_until still active after off")
	}
	// freeze:write is the governor's write freeze; freeze:all freezes everything; AuthWrite refuses.
	e.d.SetFlag(ctx, "freeze:write", true, "")
	if !e.d.Frozen("write") || e.d.Frozen("reg") {
		t.Fatal("freeze:write")
	}
	e.d.SetFlag(ctx, "freeze:all", true, "")
	if !e.d.Frozen("reg") || !e.d.Frozen("compute") || !e.d.Frozen("anything") {
		t.Fatal("freeze:all")
	}
	// A fresh Deps sees the same cache contents (DB-backed).
	d2, err := NewDeps(ctx, e.d.Cfg, testPool, e.d.Log)
	if err != nil || !d2.Frozen("kb") || d2.FlagStr("edgekv:/robots.txt") != "sha256:abc" {
		t.Fatal("flags not persisted")
	}
	d2.Close()
}

func TestStorageGovernorFreeze(t *testing.T) {
	e := newWire(t, nil, nil)
	ctx := context.Background()
	cleanFlags(t, e.d, "freeze:tcls", "freeze:tcls2", "freeze:pg", "freeze:write", "freeze:reg")
	e.d.StorageClass("tcls", 100, `SELECT 95::bigint`)
	e.d.StorageClass("tcls2", 100, `SELECT 10::bigint`)
	if err := e.d.RunGovernor(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.d.Frozen("tcls") || e.d.Frozen("tcls2") {
		t.Fatal("90% class not frozen or 10% class frozen")
	}
	if err := e.d.CheckFrozen(httptest.NewRecorder(), fakeReq("1.1.1.1"), "tcls"); err {
		t.Fatal("CheckFrozen should refuse")
	}
	e.d.StorageClass("tcls", 100, `SELECT 85::bigint`) // hysteresis: stays frozen above 80 %
	e.d.RunGovernor(ctx)
	if !e.d.Frozen("tcls") {
		t.Fatal("lifted above 80%")
	}
	e.d.StorageClass("tcls", 100, `SELECT 70::bigint`)
	e.d.RunGovernor(ctx)
	if e.d.Frozen("tcls") {
		t.Fatal("not lifted at 70%")
	}
	// An operator freeze on a healthy class is never lifted by the governor.
	e.d.SetFreeze(ctx, "freeze:tcls2", true)
	e.d.RunGovernor(ctx)
	if !e.d.Frozen("tcls2") {
		t.Fatal("governor lifted an operator flag")
	}
	// Usage is reported; a broken usedSQL is an error but the others still run.
	e.d.StorageClass("broken", 10, `SELECT no_such_column FROM flags`)
	if err := e.d.RunGovernor(ctx); err == nil {
		t.Fatal("broken class should error")
	}
	var used int64
	for _, c := range e.d.StorageClasses() {
		if c.Name == "tcls" {
			used = c.Used
		}
	}
	if used != 70 {
		t.Fatalf("usage reported %d", used)
	}
	if free, err := DiskFree(e.d.Cfg.DataDir); err != nil || free == 0 {
		t.Fatalf("statfs: %d %v", free, err)
	}
}

func TestPGClassFreeze(t *testing.T) {
	e := newWire(t, func(c *Config) { c.PGMaxBytes = 1 }, nil)
	ctx := context.Background()
	cleanFlags(t, e.d, "freeze:pg", "freeze:write")
	_, tok := e.register(t, "pgf")
	if err := e.d.RunGovernor(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.d.Frozen("pg") || !e.d.Frozen("write") {
		t.Fatal("pg at 100% of cap did not freeze writes")
	}
	if st, body := e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 1}); st != 503 || body != "err frozen write" {
		t.Fatalf("frozen write: %d %s", st, body)
	}
	if st, _ := e.do(t, "GET", "/v1/me", tok, nil); st != 200 {
		t.Fatal("reads must still work")
	}
	e.d.Cfg.PGMaxBytes = 1 << 50
	e.d.RunGovernor(ctx)
	if e.d.Frozen("pg") || e.d.Frozen("write") {
		t.Fatal("pg freeze not lifted")
	}
	if st, _ := e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 1}); st != 201 {
		t.Fatal("write after lift")
	}
}

func TestNotifierPGBridge(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), PGNotify: true}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d1, err := NewDeps(ctx, cfg, testPool, log)
	if err != nil {
		t.Fatal(err)
	}
	defer d1.Close()
	d2, err := NewDeps(ctx, cfg, testPool, log)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	woken := make(chan bool, 1)
	go func() { woken <- d2.Notify.Wait(ctx, "bridge:x", 5*time.Second) }()
	// The listener connects asynchronously: keep waking until the remote waiter is released.
	deadline := time.Now().Add(5 * time.Second)
	for {
		d1.Notify.Wake("bridge:x")
		select {
		case ok := <-woken:
			if !ok {
				t.Fatal("remote waiter timed out")
			}
			goto second
		case <-time.After(100 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("bridge never delivered")
		}
	}
second:
	// Coalescing: many wakes in a burst become one notification each; a different topic is not woken.
	go func() { woken <- d2.Notify.Wait(ctx, "bridge:other", 400*time.Millisecond) }()
	for i := 0; i < 50; i++ {
		d1.Notify.Wake("bridge:x")
	}
	if <-woken {
		t.Fatal("unrelated topic woken")
	}
}

func TestEgressOutboxPerKindCaps(t *testing.T) {
	ctx := context.Background()
	testPool.Exec(ctx, `DELETE FROM egress_outbox`)
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM egress_outbox`) })
	for i := 0; i < 50; i++ {
		if err := Egress(ctx, testPool, "anchor", map[string]any{"day": i}); err != nil {
			t.Fatalf("anchor %d: %v", i, err)
		}
	}
	if err := Egress(ctx, testPool, "anchor", map[string]any{"day": 51}); err != ErrOutboxFull {
		t.Fatalf("anchor cap: %v", err)
	}
	// Done rows do not count as live.
	testPool.Exec(ctx, `UPDATE egress_outbox SET done_at = now() WHERE kind = 'anchor'`)
	if err := Egress(ctx, testPool, "anchor", map[string]any{"day": 52}); err != nil {
		t.Fatalf("after done: %v", err)
	}
	// libmeta: 500/day counts done rows too.
	testPool.Exec(ctx, `INSERT INTO egress_outbox (kind, payload, done_at) SELECT 'libmeta', '{}'::jsonb, now() FROM generate_series(1, 500)`)
	if err := Egress(ctx, testPool, "libmeta", map[string]any{"lib": "x"}); err != ErrOutboxFull {
		t.Fatalf("libmeta daily: %v", err)
	}
	testPool.Exec(ctx, `UPDATE egress_outbox SET created = now() - interval '2 days' WHERE kind = 'libmeta'`)
	if err := Egress(ctx, testPool, "libmeta", map[string]any{"lib": "x"}); err != nil {
		t.Fatalf("libmeta after a day: %v", err)
	}
	// Shared pool exhausted (10k - 3x500 reserved): ordinary kinds refused, reserved kinds still accepted.
	testPool.Exec(ctx, `INSERT INTO egress_outbox (kind, payload) SELECT 'bulk', '{}'::jsonb FROM generate_series(1, 8500)`)
	if err := Egress(ctx, testPool, "hf", map[string]any{"f": 1}); err != ErrOutboxFull {
		t.Fatalf("shared cap: %v", err)
	}
	for _, k := range []string{"backup_ship", "mirror_rewrite", "cf_purge"} {
		if err := Egress(ctx, testPool, k, map[string]any{"f": 1}); err != nil {
			t.Fatalf("reserved %s: %v", k, err)
		}
	}
	testPool.Exec(ctx, `INSERT INTO egress_outbox (kind, payload) SELECT 'bulk', '{}'::jsonb FROM generate_series(1, 1500)`)
	if err := Egress(ctx, testPool, "cf_purge", map[string]any{"f": 2}); err != ErrOutboxFull {
		t.Fatalf("global 10k: %v", err)
	}
	// Payload and kind validation.
	if err := Egress(ctx, testPool, "indexnow", strings.Repeat("x", EgressMaxPayload+1)); err != ErrSize {
		t.Fatalf("payload cap: %v", err)
	}
	if err := Egress(ctx, testPool, "Bad Kind", map[string]any{}); err == nil {
		t.Fatal("bad kind accepted")
	}
	if err := Egress(ctx, testPool, "indexnow", json.RawMessage(`{not json`)); err == nil {
		t.Fatal("invalid raw payload accepted")
	}
	if EgressCap("indexnow") != 4000 || EgressCap("cf_purge") != EgressMaxLive || EgressCap("other") != egressDefaultCap {
		t.Fatal("EgressCap")
	}
}

func TestEventAuditOriginHelpers(t *testing.T) {
	e := newWire(t, nil, nil)
	ctx := context.Background()
	root, rtok := e.register(t, "evt")
	_, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"credits": 1})
	sub := kv(body)["id"]
	woken := make(chan bool, 1)
	go func() { woken <- e.d.Notify.Wait(ctx, "ev", 2*time.Second) }()
	time.Sleep(20 * time.Millisecond)
	long := strings.Repeat("t", 200) + "\nnext: GET /evil"
	if err := Event(ctx, testPool, "kb", "kabcdef", "", long); err != nil {
		t.Fatal(err)
	}
	if !<-woken {
		t.Fatal("Event did not wake ev")
	}
	var title string
	var scope *string
	testPool.QueryRow(ctx, `SELECT title, root_scope FROM events WHERE ref = 'kabcdef' ORDER BY seq DESC LIMIT 1`).Scan(&title, &scope)
	if len([]rune(title)) != 160 || strings.ContainsAny(title, "\n\r") || scope != nil {
		t.Fatalf("event row: %q scope=%v", title, scope)
	}
	if err := Event(ctx, testPool, "j", "jxyz", root, "done"); err != nil {
		t.Fatal(err)
	}
	testPool.QueryRow(ctx, `SELECT root_scope FROM events WHERE ref = 'jxyz'`).Scan(&scope)
	if scope == nil || *scope != root {
		t.Fatal("root scope not stored")
	}
	if err := Audit(ctx, testPool, sub, "kb", "k1", 2); err != nil {
		t.Fatal(err)
	}
	var aroot, aid string
	var n int
	if err := testPool.QueryRow(ctx, `SELECT root, id, n FROM audit WHERE id = $1`, sub).Scan(&aroot, &aid, &n); err != nil || aroot != root || n != 2 {
		t.Fatalf("audit row: %s %s %d %v", aroot, aid, n, err)
	}
	if err := Audit(ctx, testPool, "a0000000", "kb", "k1", 1); err != nil {
		t.Fatal("audit for unknown id should be a silent no-op")
	}
	if err := Origin(ctx, testPool, "kb", "k1", root, sub, "203.0.113.5"); err != nil {
		t.Fatal(err)
	}
	var ip string
	testPool.QueryRow(ctx, `SELECT ip FROM content_origin WHERE kind = 'kb' AND ref = 'k1'`).Scan(&ip)
	if ip != "203.0.113.5" {
		t.Fatalf("origin ip %q", ip)
	}
	// Inside a tx: rolled back rows never appear.
	tx, _ := testPool.Begin(ctx)
	Event(ctx, tx, "kb", "rolled", "", "x")
	tx.Rollback(ctx)
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE ref = 'rolled'`).Scan(&n)
	if n != 0 {
		t.Fatal("tx-aware helper leaked a row")
	}
	if cleanLine("a\tb\x00c", 0) != "a b c" || cleanLine("  x  ", 0) != "x" || cleanLine("héllo", 2) != "hé" {
		t.Fatal("cleanLine")
	}
}

func TestSecondPoolTimeouts(t *testing.T) {
	ctx := context.Background()
	pool, err := OpenDB(ctx, testPool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	d, err := NewDeps(ctx, Config{DataDir: t.TempDir()}, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	show := func(p *pgxpool.Pool, k string) string {
		var v string
		if err := p.QueryRow(ctx, `SHOW `+k).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if show(d.DB, "statement_timeout") != "8s" || show(d.DB, "lock_timeout") != "2s" || show(d.DB, "idle_in_transaction_session_timeout") != "10s" {
		t.Fatalf("request pool timeouts: %s %s %s", show(d.DB, "statement_timeout"), show(d.DB, "lock_timeout"), show(d.DB, "idle_in_transaction_session_timeout"))
	}
	if show(d.Ops, "statement_timeout") != "25s" || show(d.Ops, "lock_timeout") != "25s" {
		t.Fatalf("ops pool timeouts: %s", show(d.Ops, "statement_timeout"))
	}
	if d.Ops.Config().MaxConns != 2 || d.DB.Config().MaxConns != 16 {
		t.Fatalf("pool sizes: ops=%d db=%d", d.Ops.Config().MaxConns, d.DB.Config().MaxConns)
	}
	if d.Ops == d.DB {
		t.Fatal("ops pool must be distinct")
	}
}

func TestMigrateDedicatedConn(t *testing.T) {
	ctx := context.Background()
	cfg := testPool.Config()
	cfg.AfterConnect = connTimeouts(100*time.Millisecond, 100*time.Millisecond, 10*time.Second)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// Hold an exclusive lock on schema_migrations: a pooled connection (100 ms lock_timeout) would
	// fail; the dedicated migration connection (lock_timeout 30 s) waits for it.
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Migrate(ctx, pool) }()
	select {
	case err := <-done:
		t.Fatalf("migrate did not wait for the lock: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	tx.Rollback(ctx)
	if err := <-done; err != nil {
		t.Fatalf("migrate on a dedicated connection: %v", err)
	}
	// The pool itself still carries the short timeouts (the migration never touched it).
	var v string
	pool.QueryRow(ctx, `SHOW lock_timeout`).Scan(&v)
	if v != "100ms" {
		t.Fatalf("pool lock_timeout changed: %s", v)
	}
}

func TestJanitorAdvisoryLock(t *testing.T) {
	e := newWire(t, nil, nil)
	ctx := context.Background()
	j := &Janitor{log: e.d.Log, ops: e.d.Ops}
	ran := 0
	j.Add("tlock", func(context.Context) error { ran++; return nil })
	holder, err := testPool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holder.Exec(ctx, `SELECT pg_advisory_lock(hashtext('janitor:tlock'))`); err != nil {
		t.Fatal(err)
	}
	j.RunOnce(ctx)
	if ran != 0 {
		t.Fatal("task ran while another instance held its lock")
	}
	holder.Exec(ctx, `SELECT pg_advisory_unlock(hashtext('janitor:tlock'))`)
	holder.Release()
	j.RunOnce(ctx)
	j.RunOnce(ctx)
	if ran != 2 {
		t.Fatalf("task runs after unlock: %d", ran)
	}
	// The lock is released after each run (another session can take it).
	var free bool
	testPool.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext('janitor:tlock'))`).Scan(&free)
	if !free {
		t.Fatal("janitor left its advisory lock held")
	}
	testPool.Exec(ctx, `SELECT pg_advisory_unlock_all()`)
	// Without an ops pool (bare Janitor in tests) tasks run directly.
	j2 := &Janitor{log: e.d.Log}
	j2.Add("direct", func(context.Context) error { ran++; return nil })
	j2.RunOnce(ctx)
	if ran != 3 {
		t.Fatal("bare janitor")
	}
}

func TestFormTokenAndOrigin(t *testing.T) {
	e := newWire(t, nil, func(mux *http.ServeMux, d *Deps) {
		mux.HandleFunc("POST /w/form", func(w http.ResponseWriter, r *http.Request) {
			MaxBytes(w, r, 4<<10)
			if err := d.CheckForm(r); err != nil {
				Fail(w, r, err)
				return
			}
			OK(w, r, "ok", nil)
		})
	})
	secret := e.d.Cfg.ServerSecret
	now := time.Now()
	tok := FormToken(secret, "/w/form", e.ip, now)
	if len(tok) != 32 || tok != FormToken(secret, "/w/form", e.ip, now) || tok == FormToken(secret, "/w/other", e.ip, now) || tok == FormToken(secret, "/w/form", "9.9.9.9", now) {
		t.Fatalf("token derivation: %s", tok)
	}
	form := func(ft string) string { return url.Values{"ft": {ft}, "title": {"x"}}.Encode() }
	ct := []string{"Content-Type", "application/x-www-form-urlencoded"}
	st, body, _ := e.doH(t, "POST", "/w/form", "", form(tok), append(ct, "Origin", "https://agents.example")...)
	if st != 200 || body != "ok" {
		t.Fatalf("valid form: %d %s", st, body)
	}
	st, body, _ = e.doH(t, "POST", "/w/form", "", form(FormToken(secret, "/w/form", e.ip, now.Add(-24*time.Hour))), append(ct, "Referer", "https://agents.example/w/kb")...)
	if st != 200 {
		t.Fatalf("yesterday + referer: %d %s", st, body)
	}
	for name, c := range map[string]struct{ body, origin string }{
		"no ft":          {url.Values{"title": {"x"}}.Encode(), "https://agents.example"},
		"stale":          {form(FormToken(secret, "/w/form", e.ip, now.Add(-48*time.Hour))), "https://agents.example"},
		"foreign origin": {form(tok), "https://evil.example"},
		"no origin":      {form(tok), ""},
		"other path":     {form(FormToken(secret, "/w/kb", e.ip, now)), "https://agents.example"},
	} {
		hdr := append([]string{}, ct...)
		if c.origin != "" {
			hdr = append(hdr, "Origin", c.origin)
		}
		if st, body, _ := e.doH(t, "POST", "/w/form", "", c.body, hdr...); st != 403 || body != "err bad form token" {
			t.Fatalf("%s: %d %s", name, st, body)
		}
	}
	// Unit: CheckForm on a JSON body (no form) refuses.
	r := httptest.NewRequest("POST", "/w/form", strings.NewReader(`{"ft":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://agents.example")
	if err := e.d.CheckForm(r); err != ErrBadForm {
		t.Fatalf("json body: %v", err)
	}
}

func TestByteLRUBound(t *testing.T) {
	l := NewByteLRU(1000)
	base := time.Now()
	l.now = func() time.Time { return base }
	for i := 0; i < 50; i++ {
		l.Put(fmt.Sprintf("k%02d", i), make([]byte, 100), 0)
		if l.Bytes() > 1000 {
			t.Fatalf("over budget: %d", l.Bytes())
		}
	}
	if l.Len() != 5 || l.Bytes() != 835 { // (3 + 100 + 64) = 167 bytes each: five fit in 1000
		t.Fatalf("len=%d bytes=%d", l.Len(), l.Bytes())
	}
	if _, ok := l.Get("k00"); ok {
		t.Fatal("oldest survived")
	}
	if _, ok := l.Get("k49"); !ok {
		t.Fatal("newest evicted")
	}
	l.Put("huge", make([]byte, 2000), 0)
	if _, ok := l.Get("huge"); ok {
		t.Fatal("oversize entry stored")
	}
	// Recently read entries survive; TTL expiry.
	l.Get("k45") // oldest survivor becomes most recent
	l.Put("new", make([]byte, 100), time.Second)
	_, has45 := l.Get("k45")
	_, has46 := l.Get("k46")
	if !has45 || has46 {
		t.Fatalf("LRU order ignores Get: k45=%v k46=%v", has45, has46)
	}
	l.now = func() time.Time { return base.Add(2 * time.Second) }
	if _, ok := l.Get("new"); ok {
		t.Fatal("expired entry served")
	}
	l.Put("k49", []byte("v2"), 0)
	if v, _ := l.Get("k49"); string(v) != "v2" {
		t.Fatal("overwrite")
	}
	l.Delete("k49")
	if _, ok := l.Get("k49"); ok {
		t.Fatal("delete")
	}
}

func TestReservedNames(t *testing.T) {
	for _, n := range []string{"admin", "Admin", "a.d.m.i.n", "ad_min", "admn", "admins", "sytem", "ekaii", "Ekaii-", "root", "roots", "api2", "tpl-foo", "cx-bar", "/q something", "/help", "mcp", "claude", "gpt"} {
		if !Reserved(n) {
			t.Errorf("Reserved(%q) = false", n)
		}
	}
	for _, n := range []string{"alice", "bob42", "my-agent", "research-bot", "", "zz", "q", "x7", "adminstration-of-things", "/queue"} {
		if Reserved(n) {
			t.Errorf("Reserved(%q) = true", n)
		}
	}
	if !within1("abc", "abd") || !within1("abc", "ab") || !within1("abc", "xabc") || within1("abc", "xyz") || within1("abc", "abcde") {
		t.Fatal("within1")
	}
}

func TestSystemRootRow(t *testing.T) {
	ctx := context.Background()
	var name, root string
	var parent *string
	var credits int64
	var hlen int
	if err := testPool.QueryRow(ctx, `SELECT name, root, parent, credits, length(token_hash) FROM identities WHERE id = $1`, SystemID).
		Scan(&name, &root, &parent, &credits, &hlen); err != nil {
		t.Fatalf("system row: %v", err)
	}
	if name != "system" || root != SystemID || parent != nil || credits != 0 || hlen != 32 || !ValidID(SystemID) {
		t.Fatalf("system row: %s %s %v %d %d", name, root, parent, credits, hlen)
	}
	e := newWire(t, nil, nil)
	for _, tok := range []string{"cx_" + strings.Repeat("A", 43), "system-" + SystemID} {
		if _, err := e.d.LookupToken(ctx, tok); err != ErrBadToken {
			t.Fatalf("token %q matched the system root: %v", tok, err)
		}
	}
	// Re-running the migration keeps a single row (ON CONFLICT DO NOTHING).
	if err := Migrate(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM identities WHERE name = 'system'`).Scan(&n)
	if n != 1 {
		t.Fatalf("system rows: %d", n)
	}
}

func TestIPSuper(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.77":         "203.0.113.0/24",
		"::ffff:203.0.113.7":   "203.0.113.0/24",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1::/48",
		"2001:db8:1:ffff::1":   "2001:db8:1::/48",
		"2001:db8:2::1":        "2001:db8:2::/48",
		"2001:db8:1:2::/64":    "2001:db8:1::/48", // an IPGroup string is accepted too
		"garbage":              "garbage",
	} {
		if got := IPSuper(in); got != want {
			t.Errorf("IPSuper(%q)=%q want %q", in, got, want)
		}
	}
	e := newWire(t, nil, nil)
	r := fakeReq("2001:db8:9:8::1")
	if e.d.IPSuper(r) != "2001:db8:9::/48" || e.d.IPGroup(r) != "2001:db8:9:8::/64" {
		t.Fatal("deps keys")
	}
	ip, grp, sup := ClientFrom(WithClient(context.Background(), "1.2.3.4", "1.2.3.4", "1.2.3.0/24"))
	if ip != "1.2.3.4" || grp != "1.2.3.4" || sup != "1.2.3.0/24" {
		t.Fatal("WithClient/ClientFrom")
	}
	if a, b, c := ClientFrom(context.Background()); a != "" || b != "" || c != "" {
		t.Fatal("ClientFrom on an empty ctx")
	}
	// Handler stashes the keys for handlers and ops.
	var got string
	e2 := newWire(t, nil, func(mux *http.ServeMux, d *Deps) {
		mux.HandleFunc("GET /probe", func(w http.ResponseWriter, r *http.Request) {
			_, _, got = ClientFrom(r.Context())
			OK(w, r, "ok", nil)
		})
	})
	e2.do(t, "GET", "/probe", "", nil)
	if got != IPSuper(e2.ip) {
		t.Fatalf("ctx super %q", got)
	}
	// UseNetQuota charges the group at limit and the super-group at 4x.
	ctx := context.Background()
	kind := fmt.Sprintf("tq%d", time.Now().UnixNano())
	for i := 1; i <= 4; i++ {
		if err := UseNetQuota(ctx, testPool, fmt.Sprintf("192.0.2.%d", i), kind, 1); err != nil {
			t.Fatalf("group %d: %v", i, err)
		}
	}
	if err := UseNetQuota(ctx, testPool, "192.0.2.1", kind, 1); err != ErrQuota {
		t.Fatal("group limit")
	}
	if err := UseNetQuota(ctx, testPool, "192.0.2.5", kind, 1); err != ErrQuota {
		t.Fatal("super-group 4x limit")
	}
	if err := UseNetQuota(ctx, testPool, "192.0.3.1", kind, 1); err != nil {
		t.Fatal("other /24")
	}
}

// REV3

func TestDecodeDispatchesBodyParserFn(t *testing.T) {
	defer func() { BodyParserFn = nil }()
	type in struct {
		Title string   `json:"title"`
		Tags  []string `json:"tags"`
		N     int      `json:"n"`
	}
	e := newWire(t, nil, func(mux *http.ServeMux, d *Deps) {
		d.RegisterOpenAPI(json.RawMessage(`{"paths":{"/v1/probe":{"post":{"operationId":"probe","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["title"],"properties":{"title":{"type":"string","maxLength":160},"tags":{"type":"array","maxItems":8},"n":{"type":"integer"}}}}}}}}}}`))
		mux.HandleFunc("POST /v1/probe", func(w http.ResponseWriter, r *http.Request) {
			var v in
			if err := Decode(w, r, 4<<10, &v); err != nil {
				Fail(w, r, err)
				return
			}
			OK(w, r, fmt.Sprintf("title=%s tags=%d n=%d", v.Title, len(v.Tags), v.N), nil)
		})
	})
	// nil parser: JSON works (with or without Content-Type), empty body is zero, text is 415.
	if st, body, _ := e.doH(t, "POST", "/v1/probe", "", `{"title":"a","tags":["x"],"n":2}`); st != 200 || body != "title=a tags=1 n=2" {
		t.Fatalf("json: %d %s", st, body)
	}
	if st, body, _ := e.doH(t, "POST", "/v1/probe", "", ""); st != 200 || body != "title= tags=0 n=0" {
		t.Fatalf("empty: %d %s", st, body)
	}
	st, body, _ := e.doH(t, "POST", "/v1/probe", "", "title: a", "Content-Type", "text/plain")
	if st != 415 || !strings.HasPrefix(body, "err bad content type text/plain") || !strings.Contains(body, "\nexpect: title<=160* tags[]<=8 n (* required)") || !strings.Contains(body, "\nexample: title: …") {
		t.Fatalf("415: %d %q", st, body)
	}
	// JSON syntax errors name the byte and a scrubbed window; unknown fields keep the v1 text; both get expect:.
	st, body, _ = e.doH(t, "POST", "/v1/probe", "", `{"title": cx_SECRETSECRETSECRET}`)
	if st != 400 || !strings.Contains(body, "err bad json at byte") || strings.Contains(body, "SECRET") || !strings.Contains(body, "\nexample: {\"title\":\"…\"}") {
		t.Fatalf("syntax: %d %q", st, body)
	}
	if st, body, _ := e.doH(t, "POST", "/v1/probe", "", `{"nope":1}`); st != 400 || !strings.Contains(body, "unknown field") || !strings.Contains(body, "expect:") {
		t.Fatalf("unknown field: %d %q", st, body)
	}
	// With a parser: text grammar, forms and POST query parameters are dispatched with the route schema.
	var gotSchema json.RawMessage
	BodyParserFn = func(r *http.Request, schema json.RawMessage) (json.RawMessage, error) {
		gotSchema = schema
		m := map[string]any{}
		ct, _, _ := mimeType(r)
		switch {
		case strings.HasPrefix(ct, "text/plain"):
			b, _ := io.ReadAll(r.Body)
			for _, l := range strings.Split(string(b), "\n") {
				if k, v, ok := strings.Cut(l, ": "); ok && k != "next" {
					m[k] = v
				}
			}
		default:
			r.ParseForm()
			for k, v := range r.Form {
				if k == "tags" {
					m[k] = strings.Split(v[0], ",")
				} else {
					m[k] = v[0]
				}
			}
		}
		if m["title"] == "boom" {
			return nil, E(422, "bad", "field title")
		}
		return json.Marshal(m)
	}
	if st, body, _ := e.doH(t, "POST", "/v1/probe", "", "title: hello\nnext: GET /x", "Content-Type", "text/plain"); st != 200 || body != "title=hello tags=0 n=0" {
		t.Fatalf("text: %d %s", st, body)
	}
	if gotSchema == nil || !strings.Contains(string(gotSchema), `"maxLength":160`) {
		t.Fatalf("parser schema: %s", gotSchema)
	}
	if st, body, _ := e.doH(t, "POST", "/v1/probe", "", "title=f&tags=a,b", "Content-Type", "application/x-www-form-urlencoded"); st != 200 || body != "title=f tags=2 n=0" {
		t.Fatalf("form: %d %s", st, body)
	}
	if st, body, _ := e.doH(t, "POST", "/v1/probe?title=q", "", ""); st != 200 || body != "title=q tags=0 n=0" {
		t.Fatalf("query on POST: %d %s", st, body)
	}
	if st, body, _ := e.doH(t, "POST", "/v1/probe", "", "title: boom", "Content-Type", "text/plain"); st != 422 || !strings.HasPrefix(body, "err bad field title\nexpect:") {
		t.Fatalf("parser error + expect: %d %q", st, body)
	}
	// JSON still bypasses the parser; a GET never reads query params as a body.
	gotSchema = nil
	if st, _, _ := e.doH(t, "POST", "/v1/probe", "", `{"title":"j"}`, "Content-Type", "application/json"); st != 200 || gotSchema != nil {
		t.Fatal("json went through the parser")
	}
	r := httptest.NewRequest("GET", "/v1/probe?title=q", nil)
	var v in
	if err := Decode(httptest.NewRecorder(), r, 1<<10, &v); err != nil || v.Title != "" {
		t.Fatalf("GET query decoded: %v %+v", err, v)
	}
	if lines := Expect(nil, ""); lines != nil {
		t.Fatal("Expect(nil)")
	}
}

func mimeType(r *http.Request) (string, string, error) {
	ct := r.Header.Get("Content-Type")
	return ct, "", nil
}

type botKey struct{}

func TestBotLaneKeysAndShedExemption(t *testing.T) {
	BotLaneFn = func(ctx context.Context) (bool, string) {
		cat, ok := ctx.Value(botKey{}).(string)
		return ok, cat
	}
	defer func() { BotLaneFn = nil }()
	e := newWire(t, nil, nil)
	ctx := context.Background()
	cleanFlags(t, e.d, "shed:feeds", "shed:longpoll")
	base := time.Now()
	e.d.Lim.now = func() time.Time { return base }
	bot := func(ip, cat string) *http.Request {
		r := fakeReq(ip)
		return r.WithContext(context.WithValue(r.Context(), botKey{}, cat))
	}
	ok := 0
	for i := 0; i < 120; i++ {
		if e.d.Allow(bot(fmt.Sprintf("66.249.%d.%d", i/50, i%250), "search"), nil) {
			ok++
		}
	}
	if ok != 100 {
		t.Fatalf("bot:search burst: %d", ok)
	}
	if !e.d.Allow(bot("66.249.1.1", "ai"), nil) {
		t.Fatal("another category is a separate bucket")
	}
	if !e.d.Allow(fakeReq("66.249.0.1"), nil) {
		t.Fatal("verified traffic charged the IP group bucket")
	}
	if _, info := e.d.Take(bot("66.249.0.2", "search"), nil, 1); info.Limit != 100 {
		t.Fatalf("bot bucket info: %+v", info)
	}
	// Shed exemptions: feeds and anon-search on reads only; longpoll never.
	e.d.SetFlag(ctx, "shed:feeds", true, "")
	e.d.SetFlag(ctx, "shed:longpoll", true, "")
	if !e.d.Shed(fakeReq("1.1.1.1"), "feeds") || e.d.Shed(bot("1.1.1.1", "search"), "feeds") {
		t.Fatal("feeds exemption")
	}
	post := bot("1.1.1.1", "search")
	post.Method = "POST"
	if !e.d.Shed(post, "feeds") || !e.d.Shed(bot("1.1.1.1", "search"), "longpoll") {
		t.Fatal("exemption too wide")
	}
	if e.d.Shed(fakeReq("1.1.1.1"), "compute") {
		t.Fatal("unset rung")
	}
	if st, body, h := e.doH(t, "GET", "/healthz", "", ""); st != 200 || body != "ok" || h.Get("RateLimit") == "" {
		t.Fatal("plain request through handler")
	}
}

func TestTdmAndLicenseHeaders(t *testing.T) {
	e := newWire(t, func(c *Config) { c.LicenseContent = "CC-BY-4.0" }, func(mux *http.ServeMux, d *Deps) {
		pub := func(w http.ResponseWriter, r *http.Request) { OK(w, r, "page", nil) }
		mux.HandleFunc("GET /{$}", pub)
		mux.HandleFunc("GET /k/{id}", pub)
		mux.HandleFunc("GET /d/{secret}", pub)
		mux.HandleFunc("GET /status", pub)
	})
	_, tok := e.register(t, "tdm")
	for path, want := range map[string]string{"/v1/me": "1", "/d/abc": "1", "/": "0", "/k/kabc": "0", "/status": "0"} {
		_, _, h := e.doH(t, "GET", path, tok, "")
		if h.Get("tdm-reservation") != want {
			t.Errorf("%s: tdm-reservation %q want %q", path, h.Get("tdm-reservation"), want)
		}
		if want == "0" && h.Get("tdm-policy") != "https://agents.example/legal" {
			t.Errorf("%s: tdm-policy %q", path, h.Get("tdm-policy"))
		}
		if want == "1" && h.Get("tdm-policy") != "" {
			t.Errorf("%s: reserved path carries a policy", path)
		}
	}
	lic := `<https://creativecommons.org/licenses/by/4.0/>; rel="license"`
	for path, want := range map[string]bool{"/k/kabc": true, "/": true, "/status": false, "/v1/me": false} {
		_, _, h := e.doH(t, "GET", path, tok, "")
		if got := strings.Contains(strings.Join(h.Values("Link"), ", "), lic); got != want {
			t.Errorf("%s: license link %v want %v (%s)", path, got, want, h.Get("Link"))
		}
	}
	if LicenseURL("CC0-1.0") != "https://creativecommons.org/publicdomain/zero/1.0/" || LicenseURL("MIT") != "https://spdx.org/licenses/MIT.html" {
		t.Fatal("LicenseURL")
	}
}

func TestMaintenanceRetryAfter(t *testing.T) {
	e := newWire(t, nil, nil)
	ctx := context.Background()
	cleanFlags(t, e.d, "maintenance_until", "freeze:write")
	t.Cleanup(func() { maintenanceUntil.Store(nil) })
	_, tok := e.register(t, "maint")
	until := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second)
	e.d.SetFlag(ctx, "freeze:write", true, "")
	e.d.SetFlag(ctx, "maintenance_until", true, until.Format(time.RFC3339))
	st, body, h := e.doH(t, "POST", "/v1/subkey", tok, `{"credits":1}`)
	if st != 503 || body != "err frozen maintenance until="+until.Format(time.RFC3339) {
		t.Fatalf("maintenance reply: %d %q", st, body)
	}
	ra, _ := time.ParseDuration(h.Get("Retry-After") + "s")
	if ra < 9*time.Minute || ra > 11*time.Minute {
		t.Fatalf("Retry-After %q", h.Get("Retry-After"))
	}
	st, body, h = e.doH(t, "POST", "/v1/subkey?v=2", tok, `{"credits":1}`, "Accept", "application/json")
	if st != 503 || !strings.Contains(body, `"retry_s":`) || !strings.Contains(body, `"next":["retry retry_s=`) {
		t.Fatalf("json v2 maintenance: %d %s", st, body)
	}
	// Plain freeze without maintenance: v1 text, Retry-After 120.
	e.d.SetFlag(ctx, "maintenance_until", false, "")
	st, body, h = e.doH(t, "POST", "/v1/subkey", tok, `{"credits":1}`)
	if st != 503 || body != "err frozen write" || h.Get("Retry-After") != "120" {
		t.Fatalf("plain freeze: %d %q retry=%q", st, body, h.Get("Retry-After"))
	}
	// Shed replies are 503 + Retry-After; a handler-set Retry-After is honoured.
	rec := httptest.NewRecorder()
	Fail(rec, fakeReq("1.1.1.1"), ErrBusy("feeds"))
	if rec.Code != 503 || rec.Header().Get("Retry-After") != "120" || !strings.HasPrefix(rec.Body.String(), "err busy retry shed:feeds") {
		t.Fatalf("shed reply: %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	rec = httptest.NewRecorder()
	rec.Header().Set("Retry-After", "7")
	r := fakeReq("1.1.1.1")
	r.Header.Set("X-CX-V", "2")
	Fail(rec, r, ErrRate)
	if rec.Header().Get("Retry-After") != "7" || !strings.Contains(rec.Body.String(), "next: retry retry_s=7 | GET /status") {
		t.Fatalf("429 v2: %s", rec.Body.String())
	}
	// WWW-Authenticate on 401 when set.
	WWWAuthenticate = `Bearer realm="cx"`
	defer func() { WWWAuthenticate = "" }()
	if _, _, h := e.doH(t, "GET", "/v1/me", "", ""); h.Get("WWW-Authenticate") != `Bearer realm="cx"` {
		t.Fatalf("WWW-Authenticate: %q", h.Get("WWW-Authenticate"))
	}
}

func TestStorageClassesListing(t *testing.T) {
	e := newWire(t, func(c *Config) { c.PGMaxBytes = 10 << 30 }, nil)
	ctx := context.Background()
	cleanFlags(t, e.d, "freeze:zeta")
	e.d.StorageClass("zeta", 1000, `SELECT 950::bigint`)
	e.d.StorageClass("alpha", 5000, `SELECT 12::bigint`)
	if err := e.d.RunGovernor(ctx); err != nil {
		t.Fatal(err)
	}
	cls := e.d.StorageClasses()
	if len(cls) != 3 || cls[0].Name != "alpha" || cls[1].Name != "pg" || cls[2].Name != "zeta" {
		t.Fatalf("listing: %+v", cls)
	}
	if cls[0].Used != 12 || cls[0].Cap != 5000 || cls[0].Frozen || cls[2].Used != 950 || !cls[2].Frozen || cls[1].Cap != 10<<30 || cls[1].Used == 0 {
		t.Fatalf("listing values: %+v", cls)
	}
	if err := CheckBudget(cls, 0); err != nil {
		t.Fatal("unset budget must pass")
	}
	if err := CheckBudget(cls, 20<<30); err != nil {
		t.Fatalf("budget ok: %v", err)
	}
	if err := CheckBudget(cls, 5<<30); err == nil || !strings.Contains(err.Error(), "DISK_BUDGET") {
		t.Fatalf("budget exceeded: %v", err)
	}
	// Config v2: sizes, FORGEJO_URL empty allowed, PGNotify default on.
	for in, want := range map[string]int64{"0": 0, "64M": 64 << 20, "20GiB": 20 << 30, "1k": 1024, "12345": 12345} {
		if got, err := ParseBytes(in); err != nil || got != want {
			t.Errorf("ParseBytes(%q)=%d %v", in, got, err)
		}
	}
	if _, err := ParseBytes("-1"); err == nil {
		t.Fatal("negative size")
	}
	t.Setenv("DATABASE_URL", "postgres://x")
	t.Setenv("SERVER_SECRET", "0123456789abcdef0123")
	t.Setenv("FORGEJO_URL", "")
	t.Setenv("PG_MAX_BYTES", "2G")
	t.Setenv("POW_BITS_W", "18")
	cfg, err := LoadConfig()
	if err != nil || cfg.ForgejoURL != "" || cfg.PGMaxBytes != 2<<30 || cfg.PowBitsW != 18 || !cfg.PGNotify || cfg.InternalListen != ":8081" || cfg.LicenseContent != "CC0-1.0" || cfg.ExportDir != "data/export" || cfg.AdminBlobMax != 64<<20 || cfg.SignKID != 1 {
		t.Fatalf("LoadConfig: %+v %v", cfg, err)
	}
}

// Keep the hook registries honest: registration order, lookups and observers.
func TestHookRegistries(t *testing.T) {
	e := newWire(t, nil, nil)
	ctx := context.Background()
	d := e.d
	d.OnResume(func(context.Context, string) []string { return []string{"a"} })
	d.OnResume(func(context.Context, string) []string { return []string{"b"} })
	if got := d.ResumeLines(ctx, "r"); strings.Join(got, ",") != "a,b" {
		t.Fatal("resume hooks")
	}
	d.MeExtra(func(context.Context, *Ident) []string { return []string{"saved=1"} })
	if got := d.MeLines(ctx, &Ident{}); len(got) != 1 {
		t.Fatal("me hooks")
	}
	d.RegisterTarget("kb", Target{Exists: func(context.Context, Q, string) error { return nil }})
	if _, ok := d.Target("kb"); !ok {
		t.Fatal("target")
	}
	var sb strings.Builder
	d.OnExport("b", func(_ context.Context, root string, w io.Writer) error { io.WriteString(w, "b"); return nil })
	d.OnExport("a", func(_ context.Context, root string, w io.Writer) error { io.WriteString(w, "a"); return nil })
	if d.Export(ctx, "r", &sb); sb.String() != "ba" {
		t.Fatalf("export order %q", sb.String())
	}
	if s, ok := d.ScopeOf("GET /v1/me"); !ok || s != "me:r" {
		t.Fatal("scope registry")
	}
	d.RegisterCost("GET /v1/kb", 2)
	if d.CostOf("GET /v1/kb") != 2 || d.CostOf("GET /nope") != 1 {
		t.Fatal("cost registry")
	}
	d.RegisterFeed("kb", func(context.Context, string, int) ([]FeedItem, error) { return nil, nil })
	d.RegisterSitemap("kb", func(context.Context) ([]SitemapURL, error) { return nil, nil })
	d.RegisterLLMSFull("b", func(context.Context) string { return "" })
	d.RegisterLLMSFull("a", func(context.Context) string { return "" })
	d.RegisterResolver('k', func(_ context.Context, id string) (string, string, string, bool) { return "kb", id, "/k/" + id, true })
	d.OnEscrow(`SELECT 0`)
	names, _ := d.LLMSFull()
	if len(d.Feeds()) != 1 || len(d.Sitemaps()) != 1 || strings.Join(names, ",") != "a,b" || len(d.EscrowSQL()) != 1 || len(d.OpenAPIFragments()) != 0 {
		t.Fatal("registries")
	}
	if typ, _, u, ok := d.Resolve(ctx, "kabc"); !ok || typ != "kb" || u != "/k/kabc" {
		t.Fatal("resolver")
	}
	if _, _, _, ok := d.Resolve(ctx, "zzz"); ok {
		t.Fatal("unknown prefix resolved")
	}
	var mu sync.Mutex
	var seen []string
	d.Observe(func(route string, status int, _ time.Duration) {
		mu.Lock()
		seen = append(seen, fmt.Sprintf("%s=%d", route, status))
		mu.Unlock()
	})
	e.do(t, "GET", "/healthz", "", nil)
	e.do(t, "GET", "/v1/me", "", nil)
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, " ") != "GET /healthz=200 GET /v1/me=401" {
		t.Fatalf("observed %v", seen)
	}
	// Nil-safe seams fail closed / neutral.
	if _, _, err := d.XPoW(ctx, fakeReq("1.1.1.1")); err == nil || err.Error() != "err pow X-PoW required" {
		t.Fatalf("XPoW default: %v", err)
	}
	if Level(ctx, testPool, "x") != 0 || d.AnonBits(ctx, "s") != DefaultPowBitsW || ChallengeID(ctx, "c") != "" {
		t.Fatal("seam defaults")
	}
	if a, err := LeakedToken(ctx, testPool, "t"); a != "" || err != nil {
		t.Fatal("LeakedToken default")
	}
	if err := RegisterBundle(ctx, testPool, "a", json.RawMessage(`{}`)); err != nil {
		t.Fatal("RegisterBundle default")
	}
	ExportRemove(ctx, "kb", "k")
	if ok, _ := BotLane(ctx); ok {
		t.Fatal("BotLane default")
	}
	if logPath(fakeReq("1.1.1.1")) != "/v1/me" {
		t.Fatal("logPath default")
	}
	LogPathFn = func(p string) string { return "masked" }
	defer func() { LogPathFn = nil }()
	if logPath(fakeReq("1.1.1.1")) != "masked" {
		t.Fatal("LogPathFn")
	}
}
