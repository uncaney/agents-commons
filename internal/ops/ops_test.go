package ops

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
)

var (
	testPool *pgxpool.Pool
	testDSN  string
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			panic(err)
		}
		// A dedicated builder database: start from an empty schema so migration edits apply.
		if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, testDSN, cleanup = pool, dsn, pool.Close
	} else if pool, done := testdb.Open("ops", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
		testDSN, _ = testdb.URL("ops")
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping ops DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	o   *Ops
	mux *http.ServeMux
	srv *httptest.Server
}

// newEnv builds a Deps on the shared pool; withCore mounts core's routes first (so GET /healthz
// belongs to core, as in the gateway) and the server wraps d.Handler with o.Middleware.
func newEnv(t *testing.T, withCore bool) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 4, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if withCore {
		core.Register(mux, d)
	}
	o := Register(mux, d)
	srv := httptest.NewServer(o.Middleware(d.Handler(mux)))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	e := &tenv{d: d, o: o, mux: mux, srv: srv}
	e.clearFlags(t)
	t.Cleanup(func() { e.clearFlags(t) })
	return e
}

func (e *tenv) clearFlags(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, l := range Levels {
		if err := e.d.SetFlag(ctx, "shed:"+l, false, ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []string{"maintenance_until", "write", "freeze:write"} {
		if err := e.d.SetFlag(ctx, k, false, ""); err != nil {
			t.Fatal(err)
		}
	}
}

func (e *tenv) get(t *testing.T, path string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
			continue
		}
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func scrape(t *testing.T, h http.Handler, accept string) (*http.Response, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Result(), rr.Body.String()
}

func mustContain(t *testing.T, body string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(body, s) {
			t.Fatalf("missing %q in:\n%s", s, body)
		}
	}
}

func count(t *testing.T, sql string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := testPool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// --- metrics ----------------------------------------------------------------------------------

func TestMetricsExposition(t *testing.T) {
	e := newEnv(t, true)
	if resp, _ := e.get(t, "/healthz"); resp.StatusCode != 200 {
		t.Fatalf("healthz %d", resp.StatusCode)
	}
	if resp, _ := e.get(t, "/nope"); resp.StatusCode != 404 {
		t.Fatalf("nope %d", resp.StatusCode)
	}
	SetGauge("wal_last_archived_age_s", 42)
	SetGauge("quarantine_occ", 0.25)
	SetGauge("bad name!", 1) // refused
	e.d.Janitor.RunOnce(context.Background())
	resp, body := scrape(t, e.o.MetricsHandler(), "")
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	mustContain(t, body,
		"# TYPE cx_requests_total counter",
		`cx_requests_total{class="health",route="GET /healthz",status="200"} 1`,
		`cx_requests_total{class="page",route="unmatched",status="404"} 1`,
		`cx_request_seconds_bucket{class="health",le="+Inf"} 1`,
		`cx_request_seconds_count{class="health"} 1`,
		"# TYPE cx_shed_level gauge", "\ncx_shed_level 0\n",
		`cx_shed_rung{level="feeds"} 0`,
		"cx_wal_last_archived_age_s 42", "cx_quarantine_occ 0.25",
		`cx_pool_conns{pool="request",state="acquired"}`, `cx_pool_max_conns{pool="request"} `,
		"cx_waiters 0", "cx_waiters_max 2000", "cx_limiter_keys", "cx_notifier_topics", "cx_go_goroutines", "cx_process_start_time_seconds",
		`cx_replicas{state="queued"} 0`, "cx_replica_oldest_queued_seconds 0", `cx_storage_cap_bytes{class="pg"}`,
		`cx_table_rows_estimate{table="events"}`, `cx_frozen{what="write"} 0`,
		`cx_janitor_runs_total{task="ops_gauges",result="ok"} 1`)
	if strings.Contains(body, "bad name") || strings.Contains(body, "# EOF") {
		t.Fatalf("unexpected content:\n%s", body)
	}
	resp, body = scrape(t, e.o.MetricsHandler(), "application/openmetrics-text; version=1.0.0")
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/openmetrics-text") {
		t.Fatalf("openmetrics content type %q", ct)
	}
	mustContain(t, body, "# TYPE cx_requests counter", "\ncx_requests_total{")
	if !strings.HasSuffix(body, "# EOF\n") {
		t.Fatalf("openmetrics body must end with # EOF")
	}
}

func TestMetricsLabelBounds(t *testing.T) {
	r := NewRegistry()
	r.Declare("cx_x_total", "x", counter, "route")
	for i := 0; i < maxRoutes+50; i++ {
		r.Add("cx_x_total", 1, r.route(fmt.Sprintf("GET /r%d", i)))
	}
	r.mu.Lock()
	n := len(r.fams["cx_x_total"].samples)
	other := r.fams["cx_x_total"].samples["other"]
	r.mu.Unlock()
	if n != maxRoutes+1 || other == nil || other.v != 50 {
		t.Fatalf("routes=%d other=%v", n, other)
	}
	if got := escapeLabel("a\"b\\c\nd\re"); got != `a\"b\\c\nde` {
		t.Fatalf("escape %q", got)
	}
	for in, want := range map[string]string{"GET /healthz": "health", "GET /status.json": "health", "GET /admin/stats": "admin", "/mcp": "mcp",
		"POST /a2a": "a2a", "GET /f/kb.atom": "feed", "GET /q/{q}": "search", "GET /v1/kb": "search", "GET /v1/me": "api",
		"GET /robots.txt": "static", "GET /.well-known/agent.json": "static", "GET /k/{id}": "page", "GET /nope": "page"} {
		if got := classOf(in); got != want {
			t.Fatalf("classOf(%q)=%q want %q", in, got, want)
		}
	}
}

func TestMetricsNeverOnPublicMux(t *testing.T) {
	e := newEnv(t, true)
	for _, host := range []string{"agents.ekaii.fr", "127.0.0.1:9100", "localhost", "gateway:8080"} {
		for _, p := range []string{"/metrics", "/metrics/", "/metrics.txt"} {
			if resp, _ := e.get(t, p, "Host", host); resp.StatusCode != 404 {
				t.Fatalf("public %s %s -> %d, want 404", host, p, resp.StatusCode)
			}
		}
	}
	mh := e.o.MetricsHandler()
	for _, p := range []string{"/status", "/healthz", "/", "/v1/me", "/admin/stats"} {
		rr := httptest.NewRecorder()
		mh.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, p, nil))
		if rr.Code != 404 {
			t.Fatalf("metrics server %s -> %d, want 404", p, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rr.Code != 405 {
		t.Fatalf("POST /metrics -> %d, want 405", rr.Code)
	}
	// ServeMetrics is its own listener (METRICS_LISTEN), stopped by ctx.
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.o.ServeMetrics(ctx, addr) }()
	var body string
	for i := 0; i < 100; i++ {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body = string(b)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mustContain(t, body, "cx_requests_total", "cx_shed_level")
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("ServeMetrics: %v", err)
	}
	if err := e.o.ServeMetrics(ctx, ""); err != nil {
		t.Fatalf("empty addr must be a no-op: %v", err)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.NotFoundHandler())
	u, _ := url.Parse(srv.URL)
	srv.Close()
	return u.Host
}

// --- shed ladder ------------------------------------------------------------------------------

func TestShedLadderHysteresis(t *testing.T) {
	l := NewLadder()
	steps := func(p float64, n int) (lvl int) {
		for i := 0; i < n; i++ {
			lvl, _ = l.Step(p)
		}
		return lvl
	}
	if lvl, ch := l.Step(0.72); lvl != 0 || ch {
		t.Fatalf("one sample must not climb: %d %v", lvl, ch)
	}
	if lvl, ch := l.Step(0.72); lvl != 1 || !ch {
		t.Fatalf("second sample climbs: %d %v", lvl, ch)
	}
	if lvl := steps(0.60, 20); lvl != 1 { // between clear (0.55) and the next set (0.80): hold
		t.Fatalf("dip inside the band must hold rung 1, got %d", lvl)
	}
	if lvl := steps(0.99, 2); lvl != 2 {
		t.Fatalf("one rung per two samples, got %d", lvl)
	}
	if lvl := steps(0.99, 6); lvl != 5 {
		t.Fatalf("full ladder, got %d", lvl)
	}
	if lvl := steps(0.99, 4); lvl != 5 {
		t.Fatalf("capped at %d rungs, got %d", len(Levels), lvl)
	}
	if lvl := steps(0.80, 5); lvl != 5 { // <= ClearAt[4] but only 5 samples
		t.Fatalf("descent needs %d samples, got %d", l.ClearAfter, lvl)
	}
	if lvl := steps(0.80, 1); lvl != 4 {
		t.Fatalf("sixth calm sample descends, got %d", lvl)
	}
	if lvl := steps(0.80, 30); lvl != 4 { // 0.80 > ClearAt[3] (0.79): hysteresis holds rung 4
		t.Fatalf("hysteresis must hold rung 4 at 0.80, got %d", lvl)
	}
	steps(0.5, 5)
	steps(0.85, 1) // a sample inside rung 4's band (0.79, 0.94) resets the descent counter
	if lvl := steps(0.5, 5); lvl != 4 {
		t.Fatalf("descent counter must reset, got %d", lvl)
	}
	if lvl := steps(0.5, 1); lvl != 3 {
		t.Fatalf("got %d", lvl)
	}
	if lvl := steps(0.1, 18); lvl != 0 {
		t.Fatalf("back to 0, got %d (level %d)", lvl, l.Level())
	}

	// Flags: rungs are set with this instance's stamp, lifted in reverse, operator flags untouched,
	// stale stamps of dead instances lifted, live stamps of other instances respected.
	e := newEnv(t, false)
	ctx := context.Background()
	e.o.applyLevel(ctx, 2, 0.85)
	lvl, names := e.o.Level()
	if lvl != 2 || strings.Join(names, ",") != "feeds,anon-search" {
		t.Fatalf("level %d %v", lvl, names)
	}
	if s := e.d.FlagStr("shed:feeds"); !strings.HasPrefix(s, "auto "+e.o.inst+" ") {
		t.Fatalf("stamp %q", s)
	}
	if n := count(t, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'shed:feeds' AND title LIKE 'shed on feeds pressure=0.85%'`); n != 1 {
		t.Fatalf("shed on event rows %d", n)
	}
	e.o.applyLevel(ctx, 1, 0.60)
	if e.d.Flag("shed:anon-search") || !e.d.Flag("shed:feeds") {
		t.Fatal("rung 2 must be lifted, rung 1 kept")
	}
	if n := count(t, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'shed:anon-search' AND title LIKE 'shed off anon-search%'`); n != 1 {
		t.Fatalf("shed off event rows %d", n)
	}
	if err := e.d.SetFreeze(ctx, "shed:compute", true); err != nil { // operator rung: s = ""
		t.Fatal(err)
	}
	stale := fmt.Sprintf("auto deadbeef %d", time.Now().Add(-StaleAfter-time.Minute).Unix())
	if err := e.d.SetFlag(ctx, "shed:longpoll", true, stale); err != nil {
		t.Fatal(err)
	}
	live := fmt.Sprintf("auto deadbeef %d", time.Now().Unix())
	if err := e.d.SetFlag(ctx, "shed:anon-write", true, live); err != nil {
		t.Fatal(err)
	}
	e.o.applyLevel(ctx, 0, 0.1)
	if e.d.Flag("shed:feeds") || e.d.Flag("shed:longpoll") {
		t.Fatal("own and stale auto rungs must be lifted")
	}
	if !e.d.Flag("shed:compute") || !e.d.Flag("shed:anon-write") {
		t.Fatal("operator rung and another live instance's rung must stay")
	}
	lvl, names = e.o.Level()
	if lvl != 5 || strings.Join(names, ",") != "anon-write,compute" {
		t.Fatalf("level from flags %d %v", lvl, names)
	}
	// A live own stamp older than a minute is refreshed while the rung stays wanted.
	old := fmt.Sprintf("auto %s %d", e.o.inst, time.Now().Add(-2*time.Minute).Unix())
	if err := e.d.SetFlag(ctx, "shed:feeds", true, old); err != nil {
		t.Fatal(err)
	}
	e.o.applyLevel(ctx, 1, 0.75)
	if s := e.d.FlagStr("shed:feeds"); s == old || !strings.HasPrefix(s, "auto "+e.o.inst) {
		t.Fatalf("stamp not refreshed: %q", s)
	}
	// tick: real signals are calm, the pressure gauge is set and shed seconds accrue while any
	// rung is on (operator or auto), landing in status_daily through the flush.
	e.o.tick(ctx, time.Now())
	if _, body := scrape(t, e.o.MetricsHandler(), ""); !strings.Contains(body, "\ncx_pressure ") || !strings.Contains(body, "\ncx_shed_level 5\n") {
		t.Fatalf("gauges after tick:\n%s", body)
	}
	before := count(t, `SELECT coalesce(sum(shed_s), 0) FROM status_daily WHERE day = current_date`)
	if err := e.o.flushDaily(ctx); err != nil {
		t.Fatal(err)
	}
	if after := count(t, `SELECT coalesce(sum(shed_s), 0) FROM status_daily WHERE day = current_date`); after < before+int64(SampleEvery/time.Second) {
		t.Fatalf("shed seconds not accounted: %d -> %d", before, after)
	}
	if auto, own, _ := parseStamp("operator note", e.o.inst, time.Now()); auto || own {
		t.Fatal("operator value parsed as auto")
	}
}

// --- status, healthz, history -------------------------------------------------------------------

func TestStatusPageCoarse(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	resp, body := e.get(t, "/status")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Cache-Control"), "max-age=300") {
		t.Fatalf("status %d cc=%q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	mustContain(t, body, "status ok\n", "state: ok\n", "shed: -\n", "level: 0/5\n", "frozen: -\n", "storage: ", "as_of: ", "next: GET /status/history")
	for _, leak := range []string{"identities", "credits", "jobs", "ip", "root="} {
		if strings.Contains(body, leak) {
			t.Fatalf("coarse page leaks %q:\n%s", leak, body)
		}
	}
	if resp, body := e.get(t, "/status.json"); resp.StatusCode != 200 || !strings.Contains(body, `"state":"ok"`) || !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		t.Fatalf("json twin %d %q %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	if resp, _ := e.get(t, "/status.md"); resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Type"), "markdown") {
		t.Fatalf("md twin %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if resp, body := e.get(t, "/status", "Accept", "text/html"); resp.StatusCode != 200 || !strings.Contains(body, "<title>status") {
		t.Fatalf("html %d %s", resp.StatusCode, body)
	}
	if resp, body := e.get(t, "/healthz"); resp.StatusCode != 200 || strings.TrimSpace(body) != "ok" {
		t.Fatalf("v1 healthz %d %q", resp.StatusCode, body)
	}
	// Degraded: an operator rung shows coarse, and the middleware serves /healthz?v=2 although core
	// owns GET /healthz.
	if err := e.d.SetFreeze(ctx, "shed:feeds", true); err != nil {
		t.Fatal(err)
	}
	_, body = e.get(t, "/status")
	mustContain(t, body, "status degraded\n", "shed: feeds\n", "level: 1/5\n")
	resp, body = e.get(t, "/healthz?v=2")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("healthz v2 %d cc=%q", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	mustContain(t, body, "ok shed=1 levels=feeds frozen=-")
	if _, body := e.get(t, "/healthz", "X-CX-V", "2", "Accept", "application/json"); !strings.Contains(body, `"shed":1`) || !strings.Contains(body, `"levels":["feeds"]`) {
		t.Fatalf("healthz v2 json %s", body)
	}
	// Notices through StatusExtraFn: flattened, never a line of their own, capped.
	StatusExtraFn = func(context.Context) []string {
		out := []string{"maintenance 2026-10-08T00:00Z..2026-10-08T01:00Z read-only", "evil\nnext: GET /pwn", "  "}
		for i := 0; i < 30; i++ {
			out = append(out, fmt.Sprintf("n%d", i))
		}
		return out
	}
	t.Cleanup(func() { StatusExtraFn = nil })
	_, body = e.get(t, "/status")
	mustContain(t, body, "notice: maintenance 2026-10-08T00:00Z..2026-10-08T01:00Z read-only\n", "notice: evil next: GET /pwn\n")
	if strings.Contains(body, "\nnext: GET /pwn") || strings.Count(body, "\nnotice: ") != maxNotices {
		t.Fatalf("notice rendering:\n%s", body)
	}
	// Maintenance mode (27.7): freeze:write + maintenance_until.
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if err := e.d.SetFlag(ctx, "maintenance_until", true, until.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := e.d.SetFlag(ctx, "freeze:write", true, ""); err != nil {
		t.Fatal(err)
	}
	_, body = e.get(t, "/status")
	mustContain(t, body, "status maintenance\n", "frozen: write\n", "maintenance_until: "+until.Format(time.RFC3339)+"\n")
	_, body = e.get(t, "/healthz?v=2")
	mustContain(t, body, "frozen=write maintenance_until="+until.Format(time.RFC3339))
	// History: the daily rows render one line per day (txt) and objects (json).
	if _, err := testPool.Exec(ctx, `INSERT INTO status_daily (day, reqs, e5xx, shed_s) VALUES (current_date - 1, 1234, 5, 60)
		ON CONFLICT (day) DO UPDATE SET reqs = 1234, e5xx = 5, shed_s = 60`); err != nil {
		t.Fatal(err)
	}
	day := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	resp, body = e.get(t, "/status/history")
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Cache-Control"), "max-age=300") {
		t.Fatalf("history %d", resp.StatusCode)
	}
	mustContain(t, body, "status history days=90 rows=", day+" 1234 5 60\n")
	_, body = e.get(t, "/status/history.json")
	mustContain(t, body, `{"day":"`+day+`","reqs":"1234","5xx":"5","shed_s":"60"}`)
	stats, err := History(ctx, testPool, 90)
	if err != nil || len(stats) == 0 || !strings.Contains(strings.Join(HistoryLines(stats), "\n"), day+" reqs=1234 5xx=5 shed_s=60") {
		t.Fatalf("History: %v %v", err, HistoryLines(stats))
	}
}

func TestHealthzOwnedByOpsWhenFree(t *testing.T) {
	e := newEnv(t, false)
	if resp, body := e.get(t, "/healthz"); resp.StatusCode != 200 || strings.TrimSpace(body) != "ok" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	if _, body := e.get(t, "/healthz?v=2"); !strings.HasPrefix(body, "ok shed=0 levels=- frozen=-") {
		t.Fatalf("%q", body)
	}
	// A route another package already owns is left alone (P115 renders /status/history).
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status/history", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "theirs") })
	Register(mux, e.d)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/status/history", nil))
	if rr.Body.String() != "theirs" {
		t.Fatalf("history route overridden: %q", rr.Body.String())
	}
}

// --- digest -------------------------------------------------------------------------------------

func TestDigestRow(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	week := WeekStart(time.Now()).AddDate(0, 0, -7)
	if WeekStart(week.Add(50*time.Hour)) != week || week.Weekday() != time.Monday {
		t.Fatalf("WeekStart: %v", week)
	}
	wk := week.Format("2006-01-02")
	for _, s := range []struct {
		sql string
		arg any
	}{{`DELETE FROM ops_digest WHERE week = $1`, week}, {`DELETE FROM status_daily WHERE day >= $1 AND day < $1::date + 7`, week},
		{`DELETE FROM events WHERE kind = 'ops' AND (ref = 'digest:' || $1::text OR at < now() - interval '6 days')`, wk}} {
		if _, err := testPool.Exec(ctx, s.sql, s.arg); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO status_daily (day, reqs, e5xx, shed_s) VALUES ($1::date + 1, 1000, 5, 30), ($1::date + 2, 1000, 5, 0)`, week); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO events (kind, ref, title, at) VALUES ('ops', 'shed:feeds', 'shed on feeds pressure=0.80', $1::date + interval '1 day'),
		('ops', 'shed:feeds', 'shed off feeds pressure=0.40', $1::date + interval '1 day 1 hour'), ('ops', 'disk', 'low disk', $1::date + interval '2 days')`, week); err != nil {
		t.Fatal(err)
	}
	created, err := e.o.WriteDigest(ctx, week.Add(36*time.Hour))
	if err != nil || !created {
		t.Fatalf("WriteDigest: %v created=%v", err, created)
	}
	var body, reqs string
	if err := testPool.QueryRow(ctx, `SELECT body, stats->>'reqs' FROM ops_digest WHERE week = $1`, week).Scan(&body, &reqs); err != nil {
		t.Fatal(err)
	}
	mustContain(t, body, "digest week="+wk+"..", "traffic: reqs=2000 5xx=10 (0.50%) shed_s=30\n", "shed: events=1\n", "moderation: reports=", "storage: pg ", "notices: ops_events=1\n", "audit: failures=0\n")
	if reqs != "2000" {
		t.Fatalf("stats reqs %q", reqs)
	}
	if n := count(t, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = $1 AND title LIKE 'weekly digest %'`, "digest:"+wk); n != 1 {
		t.Fatalf("digest event rows %d", n)
	}
	if created, err := e.o.WriteDigest(ctx, week); err != nil || created {
		t.Fatalf("second write: %v created=%v", err, created)
	}
	if n := count(t, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = $1`, "digest:"+wk); n != 1 {
		t.Fatalf("duplicate digest event: %d", n)
	}
	if got, err := Digest(ctx, testPool, week); err != nil || got != body {
		t.Fatalf("Digest: %v", err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM ops_digest WHERE week = $1`, week); err != nil {
		t.Fatal(err)
	}
	if err := e.o.digestTask(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, `SELECT count(*) FROM ops_digest WHERE week = $1`, week); n != 1 {
		t.Fatalf("janitor did not write last week's digest: %d", n)
	}
	if got, err := Digest(ctx, testPool, week.AddDate(0, 0, -700)); err != nil || got != "" {
		t.Fatalf("missing digest must be empty: %q %v", got, err)
	}
}

// --- retention ----------------------------------------------------------------------------------

func TestRetentionJanitors(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	stmts := []string{
		`INSERT INTO events (kind, ref, title, at) VALUES ('kb', 'ret-old', 'old', now() - interval '8 days'), ('kb', 'ret-new', 'new', now() - interval '1 hour')`,
		`INSERT INTO audit (root, id, ts, op) VALUES ('aretention', 'aretention', now() - interval '31 days', 'old'), ('aretention', 'aretention', now() - interval '31 days', 'old'),
			('aretention', 'aretention', now() - interval '31 days', 'old'), ('aretention', 'aretention', now() - interval '1 day', 'new')`,
		`INSERT INTO content_origin (kind, ref, at) VALUES ('kb', 'ret-old', now() - interval '400 days'), ('kb', 'ret-new', now() - interval '1 day')`,
		`INSERT INTO status_daily (day, reqs) VALUES (current_date - 401, 1), (current_date - 2, 1) ON CONFLICT (day) DO NOTHING`,
		`INSERT INTO ops_digest (week, body) VALUES ('2020-01-06', 'ancient') ON CONFLICT (week) DO NOTHING`,
	}
	for _, s := range stmts {
		if _, err := testPool.Exec(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	old := RetentionBatch
	RetentionBatch = 1 // several rounds per table
	t.Cleanup(func() { RetentionBatch = old })
	if err := e.o.retention(ctx); err != nil {
		t.Fatal(err)
	}
	checks := map[string]int64{
		`SELECT count(*) FROM events WHERE ref = 'ret-old'`:                         0,
		`SELECT count(*) FROM events WHERE ref = 'ret-new'`:                         1,
		`SELECT count(*) FROM audit WHERE root = 'aretention' AND op = 'old'`:       0,
		`SELECT count(*) FROM audit WHERE root = 'aretention' AND op = 'new'`:       1,
		`SELECT count(*) FROM content_origin WHERE ref = 'ret-old'`:                 0,
		`SELECT count(*) FROM content_origin WHERE ref = 'ret-new'`:                 1,
		`SELECT count(*) FROM status_daily WHERE day = current_date - 401`:          0,
		`SELECT count(*) FROM status_daily WHERE day = current_date - 2`:            1,
		`SELECT count(*) FROM ops_digest WHERE week = '2020-01-06'`:                 0,
		`SELECT count(*) FROM events WHERE kind = 'ops' AND title LIKE 'shed on %'`: count(t, `SELECT count(*) FROM events WHERE kind = 'ops' AND title LIKE 'shed on %'`),
	}
	for sql, want := range checks {
		if got := count(t, sql); got != want {
			t.Fatalf("%s = %d, want %d", sql, got, want)
		}
	}
	_, body := scrape(t, e.o.MetricsHandler(), "")
	mustContain(t, body, `cx_retention_deleted_total{table="audit"} 3`, `cx_retention_deleted_total{table="events"} `, `cx_janitor_runs_total{task="ops_retention",result="ok"} 1`)
	// The daily flush accumulates per day and is read back by History.
	e.o.daily.add(time.Now(), 10, 2, 0)
	if err := e.o.flushDaily(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(t, `SELECT reqs FROM status_daily WHERE day = current_date`); n < 10 {
		t.Fatalf("today's reqs %d", n)
	}
}
