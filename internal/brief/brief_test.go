package brief

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/cache"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/know"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/testdb"
)

var pool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		p, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, p); err != nil {
			panic(err)
		}
		pool, cleanup = p, p.Close
	} else if p, done := testdb.Open("brief", core.Migrate); p != nil {
		pool, cleanup = p, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping brief DB tests")
		os.Exit(0)
	}
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int { return 2 }
	know.SetWantedSecret([]byte("brief-test-secret"))
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	Register(mux, d)
	return &tenv{d: d, srv: httptest.NewServer(mux)}
}

func (e *tenv) close() { e.srv.Close() }

// ctx returns a client context (super-group set) the way the middleware would.
func bgCtx() context.Context {
	return core.WithClient(context.Background(), "10.1.2.3", "grp1", "super1")
}

func rid(prefix byte) string {
	var b [6]byte
	rand.Read(b[:])
	return string(prefix) + hex.EncodeToString(b[:])
}

func mustExec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func seedKB(t *testing.T, title string) string {
	t.Helper()
	id := rid('k')
	mustExec(t, `INSERT INTO kb (id, kind, title, symptom, author, author_root, expires_at)
		VALUES ($1, 'fix', $2, $3, 'a', 'aroot', now() + interval '365 days')`, id, title, title)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM kb WHERE id = $1`, id) })
	return id
}

func seedAlias(t *testing.T, alias, key string) {
	t.Helper()
	mustExec(t, `INSERT INTO lib_alias (alias, key, confirms, seeded) VALUES ($1, $2, 1, true)
		ON CONFLICT (alias) DO UPDATE SET key = EXCLUDED.key, seeded = true`, alias, key)
}

func seedClaim(t *testing.T, lib, kind, vFrom, vTo, title string) string {
	t.Helper()
	id := rid('v')
	mustExec(t, `INSERT INTO claims (id, lib, kind, v_from, v_to, vkey_to, title, author, author_root, status, conf_w, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'a', 'aroot', 'verified', 2, now() + interval '365 days')`,
		id, lib, kind, vFrom, vTo, know.VKey(vTo), title)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM claims WHERE id = $1`, id) })
	return id
}

func seedDigest(t *testing.T, lib, topic, body string) string {
	t.Helper()
	id := rid('d')
	h := sha256.Sum256([]byte(id + topic))
	mustExec(t, `INSERT INTO digests (id, lib, topic, body, hash, author, author_root, status, ok_w, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'a', 'aroot', 'live', 3, now() + interval '365 days')`, id, lib, topic, body, h[:])
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM digests WHERE id = $1`, id) })
	return id
}

func seedCache(t *testing.T, key string, cost int) {
	t.Helper()
	mustExec(t, `INSERT INTO cache (key, attest, producer_lvl, cost_tokens, expires_at)
		VALUES ($1, 'claim', 2, $2, now() + interval '30 days')
		ON CONFLICT (key) DO UPDATE SET cost_tokens = EXCLUDED.cost_tokens, expires_at = EXCLUDED.expires_at`, key, cost)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM cache WHERE key = $1`, key) })
}

// --- TestSectionBudgetsAndFlow -------------------------------------------------------------------

func TestSectionBudgetsAndFlow(t *testing.T) {
	e := newEnv(t)
	defer e.close()
	ctx := bgCtx()

	q := "zzqbudget econnreset undici pool " + rid('q')
	for i := 0; i < 5; i++ {
		seedKB(t, fmt.Sprintf("%s hit %d handling", q, i))
	}
	seedAlias(t, "undici", "npm:undici")
	seedClaim(t, "npm:undici", "breaking", "5", "6", "undici 6 breaking pool change")
	seedClaim(t, "npm:undici", "security", "5", "6", "undici 6 security advisory")
	seedDigest(t, "npm:undici", "econnreset", q+" retry guidance for econnreset with undici pool")

	// Full budget: every populated section present, in the fixed order, head counts right.
	m, err := build(ctx, e.d, Req{Q: "undici@5 econnreset " + q, Env: "", B: 2000}, false)
	if err != nil {
		t.Fatal(err)
	}
	order := sectionNames(m)
	wantOrder := []string{"kb", "changes", "digests"}
	if !isSubsequence(order, wantOrder) {
		t.Fatalf("sections %v not in fixed order %v", order, wantOrder)
	}
	if m.Hits != 5 {
		t.Fatalf("hits = %d, want 5", m.Hits)
	}
	if m.Changes != 2 {
		t.Fatalf("changes = %d, want 2", m.Changes)
	}
	head := m.head()
	if !strings.Contains(head, "hits=5") || !strings.Contains(head, "changes=2") || !strings.Contains(head, "b=") {
		t.Fatalf("head missing counts: %q", head)
	}

	// Flow-on: with NO kb hits, a change line longer than the changes base share still renders
	// because the (empty) kb section's 45 % share flows on to changes.
	longTitle := "flowtest " + strings.Repeat("breakbreak ", 12) // ~141 bytes, under the 160 title cap
	seedAlias(t, "flowlib", "npm:flowlib")
	seedClaim(t, "npm:flowlib", "breaking", "1", "2", longTitle)
	fm, err := build(ctx, e.d, Req{Q: "flowlib@1 nomatchqueryxyzonly", B: 200}, false)
	if err != nil {
		t.Fatal(err)
	}
	if fm.Hits != 0 {
		t.Fatalf("flow case expected 0 kb hits, got %d", fm.Hits)
	}
	ch := sectionVal(fm, "changes")
	if !strings.Contains(ch, "flowtest") {
		t.Fatalf("flowed change line dropped: changes=%q (sections %v)", ch, sectionNames(fm))
	}
	base := int(float64(200*4-260) * 0.25) // the changes section's own base share
	if len(longTitle) <= base {
		t.Fatalf("flow test not meaningful: title %d fits base share %d", len(longTitle), base)
	}
}

// --- TestLibsParsedFromQAndEnv -------------------------------------------------------------------

func TestLibsParsedFromQAndEnv(t *testing.T) {
	e := newEnv(t)
	defer e.close()
	ctx := bgCtx()

	seedAlias(t, "undici", "npm:undici")
	seedAlias(t, "node", "npm:node")
	seedClaim(t, "npm:undici", "breaking", "5", "7", "undici 7 removes compat")
	seedClaim(t, "npm:node", "security", "20", "24", "node 24 security fix")

	// undici@6 parsed from q (6.1 grammar), node@22.9 parsed from env.
	m, err := build(ctx, e.d, Req{Q: "undici@6 econnreset handling", Env: "linux/arm64,node@22.9", B: 1500}, false)
	if err != nil {
		t.Fatal(err)
	}
	if m.Libs != 2 {
		t.Fatalf("libs = %d, want 2 (undici from q, node from env)", m.Libs)
	}
	ch := sectionVal(m, "changes")
	if !strings.Contains(ch, "undici") || !strings.Contains(ch, "node") {
		t.Fatalf("changes missing a lib: %q", ch)
	}
	// breaking/security first: the first change line is a breaking or security claim.
	first := strings.SplitN(strings.TrimSpace(ch), "\n", 2)[0]
	if !strings.Contains(first, "breaking") && !strings.Contains(first, "security") {
		t.Fatalf("first change not breaking/security: %q", first)
	}
}

// --- TestCacheSectionHitLineOnly -----------------------------------------------------------------

func TestCacheSectionHitLineOnly(t *testing.T) {
	e := newEnv(t)
	defer e.close()
	ctx := bgCtx()

	q := "cache section query " + rid('q')
	key, _, _ := cache.Derive("sum", q)
	seedCache(t, key, 4242)

	m, err := build(ctx, e.d, Req{Q: q, NS: "sum", B: 1000}, false)
	if err != nil {
		t.Fatal(err)
	}
	if m.Cached != 1 {
		t.Fatalf("cached = %d, want 1", m.Cached)
	}
	cv := sectionVal(m, "cache")
	if !strings.HasPrefix(cv, "hit ") {
		t.Fatalf("cache section not a hit line: %q", cv)
	}
	if strings.Contains(cv, "\n") {
		t.Fatalf("cache section must be the hit line only (no body): %q", cv)
	}
	if !strings.Contains(cv, "tok=4242") {
		t.Fatalf("cache hit line missing cost: %q", cv)
	}
	// next: offers GET /c/<key> (the body behind the hit line).
	var found bool
	for _, a := range m.Next {
		if a.Path == "/c/"+key {
			found = true
		}
	}
	if !found {
		t.Fatalf("next: missing GET /c/%s; next=%v", key, m.Next)
	}
}

// --- TestWantedGapRecordsMissOnce ----------------------------------------------------------------

func TestWantedGapRecordsMissOnce(t *testing.T) {
	e := newEnv(t)
	defer e.close()
	ctx := bgCtx()

	q := "totally absent query " + rid('q')
	h := wantedHash(q)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM wanted WHERE kind = 'q' AND h = $1`, h) })

	m, err := e.lookupH(ctx, nil, Req{Q: q, B: 600})
	if err != nil {
		t.Fatal(err)
	}
	if m.Hits != 0 || m.Changes != 0 {
		t.Fatalf("expected an empty pack, got hits=%d changes=%d", m.Hits, m.Changes)
	}
	if w := sectionVal(m, "wanted"); !strings.Contains(w, "gap") {
		t.Fatalf("wanted section missing gap: %q", w)
	}
	// Exactly one miss recorded for this brief.
	if n := countWanted(t, h); n != 1 {
		t.Fatalf("wanted n = %d after one brief, want 1", n)
	}

	// A kb hit means no miss is recorded.
	q2 := "answered query " + rid('q')
	seedKB(t, q2+" has a fix")
	h2 := wantedHash(q2)
	if _, err := e.lookupH(ctx, nil, Req{Q: q2, B: 600}); err != nil {
		t.Fatal(err)
	}
	if n := countWanted(t, h2); n != 0 {
		t.Fatalf("wanted recorded despite a kb hit: n=%d", n)
	}
}

// --- TestAnonymousCapAndLRU ----------------------------------------------------------------------

func TestAnonymousCapAndLRU(t *testing.T) {
	e := newEnv(t)
	defer e.close()
	ctx := bgCtx()

	q := "anon cap query " + rid('q')
	id := seedKB(t, q+" one fix here")

	// Anonymous caller asking for b=2000 is capped to AnonBudget (400).
	m, err := e.lookupH(ctx, nil, Req{Q: q, B: 2000})
	if err != nil {
		t.Fatal(err)
	}
	if m.B != AnonBudget {
		t.Fatalf("anon budget = %d, want cap %d", m.B, AnonBudget)
	}
	if !strings.Contains(m.head(), "/"+fmt.Sprint(AnonBudget)) {
		t.Fatalf("head does not show the capped total: %q", m.head())
	}
	if m.Hits != 1 {
		t.Fatalf("hits = %d, want 1", m.Hits)
	}

	// Serve the same (q, env, b) again from the ByteLRU: delete the row, the cached pack stands.
	mustExec(t, `DELETE FROM kb WHERE id = $1`, id)
	m2, err := e.lookupH(ctx, nil, Req{Q: q, B: 2000})
	if err != nil {
		t.Fatal(err)
	}
	if m2.Hits != 1 {
		t.Fatalf("LRU miss: hits = %d after deletion, want 1 (cached)", m2.Hits)
	}

	// A token caller never reads the LRU: it recomputes and now sees 0 hits.
	tok := e.mkToken(t)
	tid, err := e.d.LookupToken(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	m3, err := e.lookupH(ctx, tid, Req{Q: q, B: 2000})
	if err != nil {
		t.Fatal(err)
	}
	if m3.Hits != 0 {
		t.Fatalf("token caller read the anon LRU: hits=%d, want 0", m3.Hits)
	}
	if m3.B != MaxBudget {
		t.Fatalf("token budget capped: %d, want %d (no anon cap)", m3.B, MaxBudget)
	}
}

// --- TestSemaphoreAndTimeout ---------------------------------------------------------------------

func TestSemaphoreAndTimeout(t *testing.T) {
	e := newEnv(t)
	defer e.close()

	// A healthy brief sets the read tx up and returns; prove the statement timeout is in force by
	// a successful run (the SET LOCAL executes inside build's tx or the call errors).
	if _, err := build(bgCtx(), e.d, Req{Q: "warm query " + rid('q'), B: 600}, false); err != nil {
		t.Fatalf("baseline brief: %v", err)
	}

	// Saturate the shared trigram semaphore; a brief with a done context must come back busy (503)
	// rather than block or run.
	n := cap(kb.SearchSem)
	for i := 0; i < n; i++ {
		kb.SearchSem <- struct{}{}
	}
	defer func() {
		for i := 0; i < n; i++ {
			<-kb.SearchSem
		}
	}()
	cctx, cancel := context.WithCancel(bgCtx())
	cancel()
	_, err := build(cctx, e.d, Req{Q: "busy query " + rid('q'), B: 600}, false)
	if err == nil {
		t.Fatal("expected busy error under a saturated semaphore")
	}
	if ae, ok := err.(*core.APIError); !ok || ae.Status != 503 {
		t.Fatalf("want 503 busy, got %v", err)
	}
}

// --- end-to-end acceptance (curl) ----------------------------------------------------------------

func TestHTTPKBSectionAndNext(t *testing.T) {
	e := newEnv(t)
	defer e.close()

	q := "ECONNRESET undici fetch " + rid('q')
	seedKB(t, q+" retry the request")
	resp, err := http.Get(e.srv.URL + "/brief?q=" + urlEscape(q) + "&env=node@22.9&b=400")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "max-age=60") {
		t.Fatalf("anonymous reply not public-cached: %q", cc)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "kb:") {
		t.Fatalf("no kb section:\n%s", s)
	}
	if !strings.Contains(s, "next:") {
		t.Fatalf("no next line:\n%s", s)
	}
	if !strings.HasPrefix(s, "brief q=") {
		t.Fatalf("head not a brief head:\n%s", s)
	}
}

// --- helpers -------------------------------------------------------------------------------------

// lookupH drives the same path the handler uses (LRU for anon, side effects once).
func (e *tenv) lookupH(ctx context.Context, id *core.Ident, req Req) (*model, error) {
	h := &handlers{e.d}
	return h.lookup(ctx, id, req, id == nil)
}

func (e *tenv) mkToken(t *testing.T) string {
	t.Helper()
	_, tok, err := core.CreateRoot(context.Background(), pool, "brief-test", "10.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func sectionNames(m *model) []string {
	out := make([]string, 0, len(m.Sections))
	for _, f := range m.Sections {
		out = append(out, f.Name)
	}
	return out
}

func sectionVal(m *model, name string) string {
	for _, f := range m.Sections {
		if f.Name == name {
			return f.Val
		}
	}
	return ""
}

func isSubsequence(all, want []string) bool {
	i := 0
	for _, a := range all {
		if i < len(want) && a == want[i] {
			i++
		}
	}
	return i == len(want)
}

func wantedHash(q string) []byte {
	h := sha256.Sum256([]byte(scrub.Normalize(q)))
	return h[:]
}

func urlEscape(s string) string { return url.QueryEscape(s) }

func countWanted(t *testing.T, h []byte) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT coalesce(sum(n), 0) FROM wanted WHERE kind = 'q' AND h = $1`, h).Scan(&n); err != nil {
		t.Fatalf("count wanted: %v", err)
	}
	return n
}
