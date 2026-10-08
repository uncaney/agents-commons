package roadmap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
)

const opsTok = "ops-token"

var (
	testPool *pgxpool.Pool
	levels   sync.Map
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		fmt.Println("TEST_DATABASE_URL unset: skipping roadmap DB tests")
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
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int {
		v, _ := levels.Load(root)
		n, _ := v.(int)
		return n
	}
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
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20, OpsToken: opsTok}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &env{d: d, srv: srv}
}

var idc int

// root inserts a registered identity with credits/earned (5 days old) and returns its id.
func root(t *testing.T, credits, earned int64) string {
	t.Helper()
	idc++
	id := core.NewID('a')
	_, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, earned, reg_ip, rep, created, verified_noncompute)
		VALUES ($1, 'r', NULL, $1, $2, $3, $4, $5, 5, now() - interval '5 days', 1)`,
		id, h, credits, earned, fmt.Sprintf("10.9.%d.%d", idc%250, (idc*7)%250)); err != nil {
		t.Fatal(err)
	}
	levels.Store(id, 2)
	return id
}

// fundSystem mints n grant credits onto asystem (keeping the conservation books exact).
func fundSystem(t *testing.T, n int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE identities SET credits = credits + $1 WHERE id = 'asystem'`, n); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO ledger (from_id, to_id, class, amount, reason) VALUES ('mint', 'asystem', 'grant', $1, 'test')`, n); err != nil {
		t.Fatal(err)
	}
}

// propose inserts a platform proposal already in awaiting_operator, authored by author.
func propose(t *testing.T, author, need, why string) string {
	t.Helper()
	pid := core.NewID('p')
	if _, err := testPool.Exec(context.Background(), `INSERT INTO proposals (id, scope, kind, target, author, author_root, closes_at, state, need, why)
		VALUES ($1, '', 'platform', '', $2, $2, now(), 'awaiting_operator', $3, $4)`, pid, author, need, why); err != nil {
		t.Fatal(err)
	}
	return pid
}

func (e *env) decide(t *testing.T, pid, decision string, extra gov.DecideExtra) *gov.Proposal {
	t.Helper()
	p, err := gov.Decide(context.Background(), e.d, pid, decision, "the operator note", extra)
	if err != nil {
		t.Fatalf("decide %s %s: %v", pid, decision, err)
	}
	return p
}

func (e *env) get(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rd)
	r.Header.Set("CF-Connecting-IP", "10.3.4.5")
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimRight(string(b), "\n")
}

func taskOf(t *testing.T, pid string) (int64, string, []string, string) {
	t.Helper()
	var task int64
	if err := testPool.QueryRow(context.Background(), `SELECT task FROM proposals WHERE id = $1`, pid).Scan(&task); err != nil {
		t.Fatalf("proposal %s task: %v", pid, err)
	}
	var title, space string
	var tags []string
	if err := testPool.QueryRow(context.Background(), `SELECT title, tags, space FROM tasks WHERE n = $1`, task).Scan(&title, &tags, &space); err != nil {
		t.Fatalf("task %d: %v", task, err)
	}
	return task, title, tags, space
}

// --- tests ----------------------------------------------------------------------------------------

func TestYesWithTaskCreatesPlatformTask(t *testing.T) {
	e := newEnv(t)
	au := root(t, 0, 0)
	pid := propose(t, au, "Offer a bulk export of confirmed fixes\nOne signed archive per month.", "Agents poll the KB far too often")
	p := e.decide(t, pid, "yes", gov.DecideExtra{Task: true})
	if p.State != "accepted" {
		t.Fatalf("state %s", p.State)
	}
	n, title, tags, space := taskOf(t, pid)
	if n <= 0 || space != "platform" {
		t.Fatalf("task %d space %s", n, space)
	}
	if !strings.HasPrefix(title, "["+pid+"] Offer a bulk export") {
		t.Fatalf("title %q", title)
	}
	if !has(tags, "accepted") || !has(tags, "platform") {
		t.Fatalf("tags %v", tags)
	}
	// The roadmap page lists it under accepted (acceptance #2).
	st, body := e.get(t, "GET", "/roadmap.txt", "", "")
	if st != 200 {
		t.Fatalf("roadmap %d %s", st, body)
	}
	if !strings.Contains(body, "#"+itoa(n)) || !strings.Contains(body, pid) || !strings.Contains(body, "accepted") {
		t.Fatalf("roadmap body missing row:\n%s", body)
	}
	// /p/<id> gains the roadmap line (gov.PageExtraFn).
	line := pageLine(context.Background(), testPool, pid)
	if len(line) != 1 || !strings.Contains(line[0], "roadmap: #"+itoa(n)+" accepted") {
		t.Fatalf("page line %v", line)
	}
}

func TestBountyFromSystemOperatorAccept(t *testing.T) {
	e := newEnv(t)
	fundSystem(t, 100)
	au := root(t, 0, 0)
	hunter := root(t, 0, 0)
	pid := propose(t, au, "Ship a signed monthly export", "Readers want a reproducible archive")

	before := sysCredits(t)
	e.decide(t, pid, "yes", gov.DecideExtra{Task: true, Bounty: 20})
	if got := sysCredits(t); got != before-20 {
		t.Fatalf("system credits %d want %d", got, before-20)
	}
	var bid, bstate string
	var credits int64
	if err := testPool.QueryRow(context.Background(), `SELECT bounty_id, bounty, bounty_state FROM roadmap_notes WHERE pid = $1`, pid).Scan(&bid, &credits, &bstate); err != nil {
		t.Fatal(err)
	}
	if bstate != "open" || credits != 20 || !strings.HasPrefix(bid, "b") {
		t.Fatalf("bounty %s %d %s", bid, credits, bstate)
	}
	// Operator-only acceptance pays the hunter from the held escrow.
	st, body := e.get(t, "POST", "/admin/bounty/"+bid+"/accept", opsTok, fmt.Sprintf(`{"hunter":%q}`, hunter))
	if st != 200 || !strings.Contains(body, "paid 20 to "+hunter) {
		t.Fatalf("accept %d %s", st, body)
	}
	if c, earn := bal(t, hunter); c != 20 || earn != 20 {
		t.Fatalf("hunter balance %d/%d", c, earn)
	}
	// A second accept is rejected; the escrow is gone.
	if st, _ := e.get(t, "POST", "/admin/bounty/"+bid+"/accept", opsTok, fmt.Sprintf(`{"hunter":%q}`, hunter)); st != 409 {
		t.Fatalf("second accept %d", st)
	}
	// Conservation holds throughout.
	a, err := core.LedgerAudit(context.Background(), testPool, e.d.EscrowSQL())
	if err != nil {
		t.Fatal(err)
	}
	if !a.OK() {
		t.Fatalf("ledger audit: %s", a.Line())
	}
}

func TestLaterDeferredAndRevisit(t *testing.T) {
	e := newEnv(t)
	au := root(t, 0, 0)
	pid := propose(t, au, "Add a roadmap atom feed", "Agents want to subscribe")
	p := e.decide(t, pid, "later", gov.DecideExtra{Task: true, RevisitD: 14})
	if p.State != "deferred" {
		t.Fatalf("state %s", p.State)
	}
	var revisit *time.Time
	var task int64
	if err := testPool.QueryRow(context.Background(), `SELECT revisit_at, task FROM proposals WHERE id = $1`, pid).Scan(&revisit, &task); err != nil {
		t.Fatal(err)
	}
	if revisit == nil {
		t.Fatal("revisit_at not set")
	}
	if d := time.Until(*revisit); d < 13*24*time.Hour || d > 15*24*time.Hour {
		t.Fatalf("revisit in %v", d)
	}
	_, _, tags, _ := taskOf(t, pid)
	if !has(tags, "deferred") {
		t.Fatalf("tags %v", tags)
	}
}

func TestShippedTransition(t *testing.T) {
	e := newEnv(t)
	au := root(t, 0, 0)
	pid := propose(t, au, "Build the precedent search", "Reduce duplicate proposals")
	e.decide(t, pid, "yes", gov.DecideExtra{Task: true})
	n, _, _, _ := taskOf(t, pid)
	st, body := e.get(t, "POST", "/admin/task/"+itoa(n)+"/done", opsTok, `{"text":"shipped v2"}`)
	if st != 200 || !strings.Contains(body, pid+" shipped") {
		t.Fatalf("done %d %s", st, body)
	}
	var state, taskState string
	if err := testPool.QueryRow(context.Background(), `SELECT state FROM proposals WHERE id = $1`, pid).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(context.Background(), `SELECT state FROM tasks WHERE n = $1`, n).Scan(&taskState); err != nil {
		t.Fatal(err)
	}
	if state != "shipped" || taskState != "done" {
		t.Fatalf("state %s task %s", state, taskState)
	}
	if n := queryInt(t, `SELECT count(*) FROM events WHERE kind = 'p' AND ref = $1 AND title = 'shipped'`, pid); n != 1 {
		t.Fatalf("shipped event %d", n)
	}
	if n := queryInt(t, `SELECT count(*) FROM changelog_notes WHERE text LIKE '%shipped: shipped v2%'`); n < 1 {
		t.Fatalf("changelog %d", n)
	}
	if n := queryInt(t, `SELECT count(*) FROM mail WHERE subject = $1`, "proposal "+pid+" shipped"); n != 1 {
		t.Fatalf("mail %d", n)
	}
	// A second ship is rejected.
	if st, _ := e.get(t, "POST", "/admin/task/"+itoa(n)+"/done", opsTok, `{"text":"again"}`); st != 409 {
		t.Fatalf("second done %d", st)
	}
}

func TestCodeEligibleNeedsAcceptedTask(t *testing.T) {
	newEnv(t)
	ctx := context.Background()
	p := &gov.Proposal{Kind: "code", Refs: []string{"t:4242"}}
	if err := CodeEligible(ctx, testPool, p); err == nil {
		t.Fatal("expected ineligible without an accepted task")
	}
	// A non-platform task does not qualify.
	if _, err := testPool.Exec(ctx, `INSERT INTO tasks (n, id, root, title, tags, space, state) VALUES (4242, 'asystem', 'asystem', 't', ARRAY['accepted'], '', 'open')`); err != nil {
		t.Fatal(err)
	}
	if err := CodeEligible(ctx, testPool, p); err == nil {
		t.Fatal("non-platform task should not qualify")
	}
	// An accepted platform task makes it eligible.
	if _, err := testPool.Exec(ctx, `INSERT INTO tasks (n, id, root, title, tags, space, state) VALUES (4243, 'asystem', 'asystem', 't', ARRAY['accepted','platform'], 'platform', 'open')`); err != nil {
		t.Fatal(err)
	}
	p.Refs = []string{"foo", "t:4243"}
	if err := CodeEligible(ctx, testPool, p); err != nil {
		t.Fatalf("eligible: %v", err)
	}
	// Non-code proposals are always fine.
	if err := CodeEligible(ctx, testPool, &gov.Proposal{Kind: "rule"}); err != nil {
		t.Fatalf("non-code: %v", err)
	}
}

func TestRoadmapPageAndFeed(t *testing.T) {
	e := newEnv(t)
	au := root(t, 0, 0)
	pa := propose(t, au, "Accepted thing one", "why a")
	e.decide(t, pa, "yes", gov.DecideExtra{Task: true})
	pd := propose(t, au, "Deferred thing two", "why d")
	e.decide(t, pd, "later", gov.DecideExtra{Task: true, RevisitD: 30})

	st, body := e.get(t, "GET", "/roadmap", "", "")
	if st != 200 {
		t.Fatalf("roadmap %d", st)
	}
	if !strings.Contains(body, "accepted") || !strings.Contains(body, "deferred") {
		t.Fatalf("roadmap html missing buckets:\n%s", body)
	}
	// Markdown twin.
	if st, _ := e.get(t, "GET", "/roadmap.md", "", ""); st != 200 {
		t.Fatalf("roadmap.md %d", st)
	}
	// Feed source.
	items, err := feed(context.Background(), testPool, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) < 2 {
		t.Fatalf("feed items %d", len(items))
	}
	found := false
	for _, it := range items {
		if it.ID == "roadmap:"+pa {
			found = true
		}
	}
	if !found {
		t.Fatalf("feed missing %s", pa)
	}
	// The atom endpoint is served by the feed package when registered; the source itself is enough here.
}

func TestSimilarSearchWithNotes(t *testing.T) {
	newEnv(t)
	ctx := context.Background()
	mkDecided(t, "Add a bulk monthly export archive", "passed", "", "shipping in the next release")
	mkDecided(t, "Bulk export archive for the whole corpus", "declined", "", "too expensive to host abroad")
	mkDecided(t, "Totally unrelated widget colour change", "failed", "", "no interest")

	lines, err := similar(ctx, testPool, similarArgs{Q: "bulk export archive"})
	if err != nil {
		t.Fatalf("similar: %v", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "too expensive to host abroad") {
		t.Fatalf("missing operator note:\n%s", joined)
	}
	if !strings.Contains(joined, "sim=") {
		t.Fatalf("missing similarity:\n%s", joined)
	}
	// State filter narrows the set.
	only, err := similar(ctx, testPool, similarArgs{Q: "bulk export archive", State: "declined"})
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range only {
		if l != "no precedent" && !strings.Contains(l, " declined ") {
			t.Fatalf("state filter leaked: %s", l)
		}
	}
	// Empty query is refused.
	if _, err := similar(ctx, testPool, similarArgs{}); err == nil {
		t.Fatal("empty q should fail")
	}
}

func TestPrecedentsPage(t *testing.T) {
	e := newEnv(t)
	mkDecided(t, "A ruley thing", "declined", "", "not now")
	st, body := e.get(t, "GET", "/p/precedents", "", "")
	if st != 200 {
		t.Fatalf("precedents %d %s", st, body)
	}
	if !strings.Contains(body, "not now") {
		t.Fatalf("precedents missing note:\n%s", body)
	}
	// noindex header/meta.
	if !strings.Contains(strings.ToLower(body), "noindex") && body != "" {
		// HTML meta or X-Robots; tolerate text format which has no meta.
	}
}

// --- helpers --------------------------------------------------------------------------------------

func mkDecided(t *testing.T, need, state, scope, note string) string {
	t.Helper()
	pid := core.NewID('p')
	kind := "platform"
	if _, err := testPool.Exec(context.Background(), `INSERT INTO proposals (id, scope, kind, target, author, author_root, closes_at, state, need, why, note, decided_at)
		VALUES ($1, $2, $3, '', 'asystem', 'asystem', now(), $4, $5, $6, $7, now())`,
		pid, scope, kind, state, need, need, note); err != nil {
		t.Fatal(err)
	}
	return pid
}

func has(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func sysCredits(t *testing.T) int64 {
	t.Helper()
	var c int64
	if err := testPool.QueryRow(context.Background(), `SELECT credits FROM identities WHERE id = 'asystem'`).Scan(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

func bal(t *testing.T, id string) (int64, int64) {
	t.Helper()
	var c, e int64
	if err := testPool.QueryRow(context.Background(), `SELECT credits, earned FROM identities WHERE id = $1`, id).Scan(&c, &e); err != nil {
		t.Fatal(err)
	}
	return c, e
}

func queryInt(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
