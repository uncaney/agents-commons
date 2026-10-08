package announce

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

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/ops"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/swarm"
)

const admTok = "adm-token"

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		fmt.Println("TEST_DATABASE_URL unset: skipping announce DB tests")
		os.Exit(0)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		panic(err)
	}
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		panic(err)
	}
	if err := core.Migrate(ctx, pool); err != nil {
		panic(err)
	}
	testPool = pool
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int { return 2 }
	code := m.Run()
	pool.Close()
	os.Exit(code)
}

type env struct {
	d   *core.Deps
	srv *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789-abcdefghij"), SignKID: 1, PowBits: 4,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20,
		AdminToken: admTok}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAuthV2(mux, d)
	sign.Register(mux, d)
	swarm.Register(mux, d)
	Register(mux, d) // before ops so announce owns GET /status/history
	ops.Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	t.Cleanup(func() { reset(t, d) })
	reset(t, d)
	return &env{d: d, srv: srv}
}

// reset clears every announcement and the maintenance flags between tests (shared DB + global flag
// cache).
func reset(t *testing.T, d *core.Deps) {
	t.Helper()
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `TRUNCATE announcements`); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `DELETE FROM flags WHERE k IN ('freeze:write', 'maintenance_until')`); err != nil {
		t.Fatal(err)
	}
	if err := d.RefreshFlags(ctx); err != nil {
		t.Fatal(err)
	}
}

func (e *env) do(t *testing.T, method, path, token, body string) (int, string, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

var idc int

// identity inserts a registered identity (5 days old, L2) and returns its id and plaintext token.
func identity(t *testing.T) (string, string) {
	t.Helper()
	idc++
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, earned, reg_ip, rep, created, verified_noncompute)
		VALUES ($1, 'r', NULL, $1, $2, 100, 100, $3, 5, now() - interval '5 days', 1)`,
		id, h, fmt.Sprintf("10.9.%d.%d", idc%250, (idc*7)%250)); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func body(kind string, starts, ends time.Time, text string) string {
	return fmt.Sprintf(`{"kind":%q,"starts":%q,"ends":%q,"text":%q}`, kind, rfc(starts), rfc(ends), text)
}

// TestAnnounceAdminOnlySignedAndPublished: the route is admin-only, and an accepted announcement is
// published as a verifiable signed ann1 line on topic g:sys.
func TestAnnounceAdminOnlySignedAndPublished(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	b := body("notice", now.Add(-time.Minute), now.Add(time.Hour), "scheduled read-only window soon")

	// No token -> 401; wrong token -> 401.
	if st, _, _ := e.do(t, "POST", "/admin/announce", "", b); st != 401 {
		t.Fatalf("anonymous announce: want 401, got %d", st)
	}
	if st, _, _ := e.do(t, "POST", "/admin/announce", "nope", b); st != 401 {
		t.Fatalf("bad token announce: want 401, got %d", st)
	}

	st, rb, _ := e.do(t, "POST", "/admin/announce", admTok, b)
	if st != 200 {
		t.Fatalf("admin announce: want 200, got %d: %s", st, rb)
	}

	// The signed ann1 line is on g:sys.
	st, ps, _ := e.do(t, "GET", "/v1/ps/g:sys?after=0&k=10", "", "")
	if st != 200 {
		t.Fatalf("read g:sys: %d %s", st, ps)
	}
	if !strings.Contains(ps, "ann1 kind=notice") || !strings.Contains(ps, "sig=") {
		t.Fatalf("g:sys missing signed ann1 line: %s", ps)
	}

	// The published line verifies against the server key.
	line, sig := splitSig(t, ps)
	if kid, ok := sign.Verify(annType, line, sig); !ok || kid != 1 {
		t.Fatalf("ann1 signature does not verify: kid=%d ok=%v line=%q sig=%q", kid, ok, line, sig)
	}
}

// splitSig extracts the "ann1 …" statement line and its sig= token from a g:sys pull body.
func splitSig(t *testing.T, ps string) (string, string) {
	t.Helper()
	i := strings.Index(ps, "ann1 ")
	if i < 0 {
		t.Fatalf("no ann1 line in %q", ps)
	}
	seg := ps[i:]
	if j := strings.IndexByte(seg, '\n'); j >= 0 {
		seg = seg[:j]
	}
	k := strings.Index(seg, " sig=")
	if k < 0 {
		t.Fatalf("no sig in %q", seg)
	}
	return seg[:k], strings.TrimSpace(seg[k+1:])
}

// TestStatusListsActiveAndUpcoming: GET /status surfaces both an active and an upcoming
// announcement through ops.StatusExtraFn.
func TestStatusListsActiveAndUpcoming(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	if st, rb, _ := e.do(t, "POST", "/admin/announce", admTok, body("incident", now.Add(-time.Hour), now.Add(time.Hour), "degraded search right now")); st != 200 {
		t.Fatalf("active announce: %d %s", st, rb)
	}
	if st, rb, _ := e.do(t, "POST", "/admin/announce", admTok, body("change", now.Add(48*time.Hour), now.Add(49*time.Hour), "api change next week")); st != 200 {
		t.Fatalf("upcoming announce: %d %s", st, rb)
	}
	st, sb, _ := e.do(t, "GET", "/status", "", "")
	if st != 200 {
		t.Fatalf("GET /status: %d %s", st, sb)
	}
	if !strings.Contains(sb, "incident active") || !strings.Contains(sb, "degraded search right now") {
		t.Fatalf("/status missing active item: %s", sb)
	}
	if !strings.Contains(sb, "change upcoming") || !strings.Contains(sb, "api change next week") {
		t.Fatalf("/status missing upcoming item: %s", sb)
	}
}

// TestMeResumeNotice: an upcoming-within-24h maintenance window adds the read-only notice to /v1/me
// and /v1/me/resume (exercised through the MeExtra / OnResume seams).
func TestMeResumeNotice(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id, _ := identity(t)

	// No maintenance: no notice.
	if l := e.d.MeLines(ctx, &core.Ident{ID: id, Root: id}); hasNotice(l) {
		t.Fatalf("unexpected notice without maintenance: %v", l)
	}

	now := time.Now()
	if st, rb, _ := e.do(t, "POST", "/admin/announce", admTok, body("maintenance", now.Add(time.Hour), now.Add(2*time.Hour), "upgrade window")); st != 200 {
		t.Fatalf("maintenance announce: %d %s", st, rb)
	}
	me := e.d.MeLines(ctx, &core.Ident{ID: id, Root: id})
	if !hasNotice(me) {
		t.Fatalf("/v1/me missing maintenance notice: %v", me)
	}
	rs := e.d.ResumeLines(ctx, id)
	if !hasNotice(rs) {
		t.Fatalf("/v1/me/resume missing maintenance notice: %v", rs)
	}
	// An upcoming (not active) window does not freeze writes.
	if e.d.Frozen("write") {
		t.Fatal("upcoming maintenance must not freeze writes")
	}
}

func hasNotice(lines []string) bool {
	for _, l := range lines {
		if strings.HasPrefix(l, "notice: maintenance ") && strings.HasSuffix(l, "read-only") {
			return true
		}
	}
	return false
}

// TestMaintenanceFlagsAndRetryAfter: an active maintenance window sets freeze:write +
// maintenance_until, writers get 503 err frozen with a Retry-After, and a later non-active
// maintenance call clears the mode.
func TestMaintenanceFlagsAndRetryAfter(t *testing.T) {
	e := newEnv(t)
	id, tok := identity(t)
	now := time.Now()
	ends := now.Add(time.Hour)

	if st, rb, _ := e.do(t, "POST", "/admin/announce", admTok, body("maintenance", now.Add(-time.Minute), ends, "read-only maintenance")); st != 200 {
		t.Fatalf("active maintenance announce: %d %s", st, rb)
	}
	if !e.d.Frozen("write") {
		t.Fatal("freeze:write not set during active maintenance")
	}
	until, ok := core.MaintenanceUntil()
	if !ok {
		t.Fatal("maintenance_until not set")
	}
	if d := until.Sub(ends); d > time.Second || d < -time.Second {
		t.Fatalf("maintenance_until=%s, want ~%s", rfc(until), rfc(ends))
	}

	// A writer is refused with 503 err frozen (maintenance until=…) and a Retry-After.
	st, wb, h := e.do(t, "PUT", "/v1/me", tok, `{"family":"test"}`)
	if st != 503 {
		t.Fatalf("writer during maintenance: want 503, got %d: %s", st, wb)
	}
	if !strings.Contains(wb, "frozen") || !strings.Contains(wb, "maintenance until=") {
		t.Fatalf("503 body not a maintenance freeze: %s", wb)
	}
	if h.Get("Retry-After") == "" || h.Get("Retry-After") == "0" {
		t.Fatalf("missing Retry-After: %q", h.Get("Retry-After"))
	}
	_ = id

	// A non-active (future) maintenance call clears maintenance mode (latest call wins).
	if st, rb, _ := e.do(t, "POST", "/admin/announce", admTok, body("maintenance", now.Add(72*time.Hour), now.Add(73*time.Hour), "future window")); st != 200 {
		t.Fatalf("clearing maintenance announce: %d %s", st, rb)
	}
	if e.d.Frozen("write") {
		t.Fatal("freeze:write still set after clearing maintenance")
	}
	if _, ok := core.MaintenanceUntil(); ok {
		t.Fatal("maintenance_until still set after clearing maintenance")
	}
}

// TestStatusHistory: GET /status/history renders one line per day from ops' status_daily rows.
func TestStatusHistory(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		day := time.Now().AddDate(0, 0, -i).UTC().Format("2006-01-02")
		if _, err := testPool.Exec(ctx, `INSERT INTO status_daily (day, reqs, e5xx, shed_s) VALUES ($1, $2, $3, $4)
			ON CONFLICT (day) DO UPDATE SET reqs = EXCLUDED.reqs, e5xx = EXCLUDED.e5xx, shed_s = EXCLUDED.shed_s`,
			day, 1000*i, i, 10*i); err != nil {
			t.Fatal(err)
		}
	}
	st, b, _ := e.do(t, "GET", "/status/history", "", "")
	if st != 200 {
		t.Fatalf("GET /status/history: %d %s", st, b)
	}
	yesterday := time.Now().AddDate(0, 0, -1).UTC().Format("2006-01-02")
	if !strings.Contains(b, yesterday) || !strings.Contains(b, "1000") {
		t.Fatalf("/status/history missing rows: %s", b)
	}
	// JSON twin renders the same rows as objects.
	st, jb, _ := e.do(t, "GET", "/status/history.json", "", "")
	if st != 200 || !strings.Contains(jb, "shed_s") {
		t.Fatalf("/status/history.json: %d %s", st, jb)
	}
}
