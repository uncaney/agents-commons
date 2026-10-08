package auction

import (
	"context"
	"crypto/rand"
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

	"ekaii.fr/commons/internal/bounty"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/testdb"
)

var (
	testPool *pgxpool.Pool
	levels   sync.Map // root -> level (core.LevelFn stub)
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	var cleanup func()
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
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
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("auction", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping auction DB tests")
		os.Exit(0)
	}
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int {
		v, _ := levels.Load(root)
		n, _ := v.(int)
		return n
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	s   *svc
	srv *httptest.Server
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	forge.Register(mux, d)
	bounty.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, s: svcFor(d), srv: srv}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

func (e *tenv) do(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	return e.doIP(t, method, path, token, body, randIP())
}

func (e *tenv) doIP(t *testing.T, method, path, token, body, ip string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rd)
	r.Header.Set("CF-Connecting-IP", ip)
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

// mkRoot inserts a root registered from ip (5 days old) with credits/earned and rep.
func mkRoot(t *testing.T, ip string, credits, earned int64, rep int) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, earned, reg_ip, rep, created, verified_noncompute)
		VALUES ($1, 'r', NULL, $1, $2, $3, $4, $5, $6, now() - interval '5 days', 1)`, id, h, credits, earned, ip, rep); err != nil {
		t.Fatal(err)
	}
	lvl := 0
	switch {
	case rep >= 5:
		lvl = 2
	case rep >= 1:
		lvl = 1
	}
	levels.Store(id, lvl)
	return id, tok
}

func (e *tenv) ident(t *testing.T, tok string) *core.Ident {
	t.Helper()
	id, err := e.d.LookupToken(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *tenv) task(t *testing.T, tok, title string) int64 {
	t.Helper()
	n, err := forge.CreateTask(context.Background(), e.d, e.ident(t, tok), forge.TaskInput{Title: title})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// mkAuction posts an auction on task n from the creator token; extra goes inside the JSON object.
func (e *tenv) mkAuction(t *testing.T, tok string, n, budget int64, extra, ip string) string {
	t.Helper()
	st, body := e.doIP(t, "POST", "/v1/au", tok, fmt.Sprintf(`{"task":%d,"budget":%d%s}`, n, budget, extra), ip)
	if st != 201 || !strings.HasPrefix(body, "ok n") {
		t.Fatalf("create auction: %d %s", st, body)
	}
	return strings.Fields(body)[1]
}

// bid places a bid from a bidder (its own ip) and asserts the status.
func (e *tenv) bidOK(t *testing.T, tok, id string, amount int64, ip string) {
	t.Helper()
	st, body := e.doIP(t, "POST", "/v1/au/"+id+"/bid", tok, fmt.Sprintf(`{"amount":%d}`, amount), ip)
	if st != 200 {
		t.Fatalf("bid: %d %s", st, body)
	}
}

func (e *tenv) row(t *testing.T, id string) *auction {
	t.Helper()
	a, err := load(context.Background(), testPool, id, false)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func bal(t *testing.T, id string) (credits, earned int64) {
	t.Helper()
	if err := testPool.QueryRow(context.Background(), `SELECT credits, earned FROM identities WHERE id = $1`, id).Scan(&credits, &earned); err != nil {
		t.Fatal(err)
	}
	return
}

func (e *tenv) closeNow(t *testing.T, id string) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE auctions SET closes_at = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := e.s.janitor(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func bountyRow(t *testing.T, id string) (escrow, held int64, state, hunterRoot string, deadline time.Time) {
	t.Helper()
	if err := testPool.QueryRow(context.Background(), `SELECT escrow, held, state, hunter_root, deadline FROM bounties WHERE id = $1`, id).Scan(&escrow, &held, &state, &hunterRoot, &deadline); err != nil {
		t.Fatal(err)
	}
	return
}

func bondState(t *testing.T, ref, root string) string {
	t.Helper()
	var s string
	if err := testPool.QueryRow(context.Background(), `SELECT state FROM bonds WHERE ref = $1 AND root = $2`, ref, root).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func conserved(t *testing.T, e *tenv, step string) {
	t.Helper()
	a, err := core.LedgerAudit(context.Background(), testPool, e.d.EscrowSQL())
	if err != nil {
		t.Fatal(err)
	}
	if !a.OK() {
		t.Fatalf("%s: %s", step, a.Line())
	}
}

func holder(t *testing.T, n int64) string {
	t.Helper()
	_, root, err := forge.ClaimFence(context.Background(), testPool, n)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// --- tests ---

func TestCreateEscrowAndRender(t *testing.T) {
	e := newEnv(t)
	cip := "10.1.1.1"
	cid, ctok := mkRoot(t, cip, 100, 100, 2)
	n := e.task(t, ctok, "ship it")
	conserved(t, e, "start")
	id := e.mkAuction(t, ctok, n, 40, `,"closes_m":30,"min_bidders":2`, cip)
	// Escrow reserved: earned down by 40.
	c, ear := bal(t, cid)
	if c != 60 || ear != 60 {
		t.Fatalf("creator balance = %d/%d want 60/60", c, ear)
	}
	conserved(t, e, "escrowed")
	// Task detail renders the sealed auction line (through the TaskExtra chain).
	_, tk := e.do(t, "GET", "/v1/t/"+fmt.Sprint(n), ctok, "")
	if !strings.Contains(tk, "auction: "+id) || !strings.Contains(tk, "budget<=40cr") || !strings.Contains(tk, "bids=0") {
		t.Fatalf("task detail missing auction line:\n%s", tk)
	}
	if lines := TaskExtra(context.Background(), testPool, n); len(lines) != 1 || !strings.Contains(lines[0], "auction: "+id) {
		t.Fatalf("hook: %q", lines)
	}
	// Detail is sealed before close.
	st, body := e.do(t, "GET", "/v1/au/"+id, ctok, "")
	if st != 200 || !strings.Contains(body, "sealed until close") {
		t.Fatalf("detail: %d %s", st, body)
	}
}

func TestBidsSealedUntilClose(t *testing.T) {
	e := newEnv(t)
	cip := "10.1.1.1"
	_, ctok := mkRoot(t, cip, 100, 100, 2)
	n := e.task(t, ctok, "task")
	id := e.mkAuction(t, ctok, n, 40, `,"min_bidders":2`, cip)
	_, b1 := mkRoot(t, "10.2.2.1", 10, 0, 1)
	e.bidOK(t, b1, id, 7, "10.2.2.1")
	// Before close: amounts hidden.
	st, body := e.do(t, "GET", "/v1/au/"+id, ctok, "")
	if st != 200 || strings.Contains(body, "7cr") || !strings.Contains(body, "bids: 1 (sealed until close)") {
		t.Fatalf("pre-close leaked amount:\n%s", body)
	}
	conserved(t, e, "bid")
	// After close (nobid, 1<2): amounts now listed.
	e.closeNow(t, id)
	st, body = e.do(t, "GET", "/v1/au/"+id, ctok, "")
	if st != 200 || !strings.Contains(body, "7cr") {
		t.Fatalf("post-close should list amounts:\n%s", body)
	}
	if a := e.row(t, id); a.State != "nobid" {
		t.Fatalf("state = %s want nobid", a.State)
	}
	conserved(t, e, "nobid")
}

func TestDistinctAndExcludedBidders(t *testing.T) {
	e := newEnv(t)
	cip := "10.1.1.1"
	_, ctok := mkRoot(t, cip, 100, 100, 2)
	n := e.task(t, ctok, "task")
	id := e.mkAuction(t, ctok, n, 40, `,"min_bidders":2`, cip)
	// Same super-group as the creator -> refused.
	_, same := mkRoot(t, "10.1.1.9", 10, 0, 1)
	if st, body := e.doIP(t, "POST", "/v1/au/"+id+"/bid", same, `{"amount":10}`, "10.1.1.9"); st != 409 || !strings.Contains(body, "distinct") {
		t.Fatalf("same-super bid: %d %s want 409 distinct", st, body)
	}
	// L0 bidder -> refused.
	_, l0 := mkRoot(t, "10.9.9.9", 10, 0, 0)
	if st, _ := e.doIP(t, "POST", "/v1/au/"+id+"/bid", l0, `{"amount":10}`, "10.9.9.9"); st != 403 {
		t.Fatalf("L0 bid status = %d want 403", st)
	}
	// Excluded (collusion pair) -> refused.
	bidderRoot, ex := mkRoot(t, "10.2.2.1", 10, 0, 1)
	ExcludeFn = func(ctx context.Context, q core.Q, a, b string) (bool, error) {
		return b == bidderRoot || a == bidderRoot, nil
	}
	t.Cleanup(func() { ExcludeFn = nil })
	if st, body := e.doIP(t, "POST", "/v1/au/"+id+"/bid", ex, `{"amount":10}`, "10.2.2.1"); st != 409 || !strings.Contains(body, "collusion") {
		t.Fatalf("excluded bid: %d %s want 409 collusion", st, body)
	}
	ExcludeFn = nil
	// Now the same bidder is allowed.
	e.bidOK(t, ex, id, 10, "10.2.2.1")
	conserved(t, e, "excluded")
}

func TestSuperGroupCollapseAndSecondPrice(t *testing.T) {
	e := newEnv(t)
	cip := "10.1.1.1"
	ccid, ctok := mkRoot(t, cip, 100, 100, 2)
	n := e.task(t, ctok, "task")
	id := e.mkAuction(t, ctok, n, 40, `,"min_bidders":2`, cip)
	// Two bidders share super 10.2.2.0/24 (amounts 20 and 15); one in 10.3.3.0/24 (25).
	aRoot, aTok := mkRoot(t, "10.2.2.1", 10, 0, 1)
	bRoot, bTok := mkRoot(t, "10.2.2.2", 10, 0, 1)
	cRoot, cTok := mkRoot(t, "10.3.3.1", 10, 0, 1)
	e.bidOK(t, aTok, id, 20, "10.2.2.1")
	e.bidOK(t, bTok, id, 15, "10.2.2.2")
	e.bidOK(t, cTok, id, 25, "10.3.3.1")
	conserved(t, e, "bids")
	e.closeNow(t, id)
	a := e.row(t, id)
	if a.State != "awarded" {
		t.Fatalf("state = %s want awarded", a.State)
	}
	// Collapse keeps b (15) for super 10.2.2.0/24; winner is the lowest collapsed (b), price is
	// the second-lowest collapsed amount (c = 25).
	if a.WinnerRoot != bRoot {
		t.Fatalf("winner = %s want %s", a.WinnerRoot, bRoot)
	}
	if a.Price != 25 {
		t.Fatalf("price = %d want 25", a.Price)
	}
	esc, _, state, hunter, _ := bountyRow(t, a.Bounty)
	if esc != 25 || state != "open" || hunter != bRoot {
		t.Fatalf("bounty = esc %d state %s hunter %s want 25/open/%s", esc, state, hunter, bRoot)
	}
	// Creator refunded budget-price = 15 (earned back to 60+15=75).
	if _, ear := bal(t, ccid); ear != 75 {
		t.Fatalf("creator earned = %d want 75", ear)
	}
	// Winner bond held, losers returned.
	if s := bondState(t, id, bRoot); s != "held" {
		t.Fatalf("winner bond = %s want held", s)
	}
	if s := bondState(t, id, aRoot); s != "returned" {
		t.Fatalf("a bond = %s want returned", s)
	}
	if s := bondState(t, id, cRoot); s != "returned" {
		t.Fatalf("c bond = %s want returned", s)
	}
	conserved(t, e, "awarded")
}

func TestNobidFallbackBounty(t *testing.T) {
	e := newEnv(t)
	cip := "10.1.1.1"
	_, ctok := mkRoot(t, cip, 100, 100, 2)
	n := e.task(t, ctok, "task")
	id := e.mkAuction(t, ctok, n, 30, `,"min_bidders":3,"fallback":"bounty"`, cip)
	_, t1 := mkRoot(t, "10.2.2.1", 10, 0, 1)
	_, t2 := mkRoot(t, "10.3.3.1", 10, 0, 1)
	e.bidOK(t, t1, id, 10, "10.2.2.1")
	e.bidOK(t, t2, id, 12, "10.3.3.1")
	e.closeNow(t, id)
	a := e.row(t, id)
	if a.State != "nobid" || a.Bounty == "" {
		t.Fatalf("state=%s bounty=%s want nobid + fallback bounty", a.State, a.Bounty)
	}
	esc, _, state, hunter, _ := bountyRow(t, a.Bounty)
	if esc != 30 || state != "open" || hunter != "" {
		t.Fatalf("fallback bounty = esc %d state %s hunter %q want 30/open/''", esc, state, hunter)
	}
	conserved(t, e, "nobid fallback")
}

func TestNobidRefund(t *testing.T) {
	e := newEnv(t)
	cip := "10.1.1.1"
	cid, ctok := mkRoot(t, cip, 100, 100, 2)
	n := e.task(t, ctok, "task")
	id := e.mkAuction(t, ctok, n, 30, `,"min_bidders":3`, cip)
	_, t1 := mkRoot(t, "10.2.2.1", 10, 0, 1)
	e.bidOK(t, t1, id, 10, "10.2.2.1")
	e.closeNow(t, id)
	if a := e.row(t, id); a.State != "nobid" || a.Bounty != "" {
		t.Fatalf("state=%s bounty=%s want nobid no bounty", a.State, a.Bounty)
	}
	// Creator fully refunded.
	if _, ear := bal(t, cid); ear != 100 {
		t.Fatalf("creator earned = %d want 100 (refunded)", ear)
	}
	conserved(t, e, "nobid refund")
}

func TestAwardCreatesBountyAndClaim(t *testing.T) {
	e := newEnv(t)
	cip := "10.1.1.1"
	cid, ctok := mkRoot(t, cip, 100, 100, 2)
	n := e.task(t, ctok, "acceptance")
	id := e.mkAuction(t, ctok, n, 40, `,"min_bidders":2`, cip)
	// Three distinct-super bidders at 10, 12 and 15.
	winRoot, winTok := mkRoot(t, "10.2.2.1", 10, 0, 1)
	_, t12 := mkRoot(t, "10.3.3.1", 10, 0, 1)
	_, t15 := mkRoot(t, "10.4.4.1", 10, 0, 1)
	e.bidOK(t, winTok, id, 10, "10.2.2.1")
	e.bidOK(t, t12, id, 12, "10.3.3.1")
	e.bidOK(t, t15, id, 15, "10.4.4.1")
	e.closeNow(t, id)
	a := e.row(t, id)
	if a.State != "awarded" || a.WinnerRoot != winRoot || a.Price != 12 {
		t.Fatalf("award = state %s winner %s price %d want awarded/%s/12", a.State, a.WinnerRoot, a.Price, winRoot)
	}
	// Winner holds the claim.
	if h := holder(t, n); h != winRoot {
		t.Fatalf("claim holder = %s want %s", h, winRoot)
	}
	// A bounty b… escrow=12 exists.
	esc, held, state, hunter, _ := bountyRow(t, a.Bounty)
	if !strings.HasPrefix(a.Bounty, "b") || esc != 12 || held != 12 || state != "open" || hunter != winRoot {
		t.Fatalf("bounty %s = esc %d held %d state %s hunter %s want b…/12/12/open/%s", a.Bounty, esc, held, state, hunter, winRoot)
	}
	// The creator is refunded budget-12 = 28 (earned 60 -> 88).
	if _, ear := bal(t, cid); ear != 88 {
		t.Fatalf("creator earned = %d want 88 (refunded budget-12)", ear)
	}
	conserved(t, e, "award acceptance")
}

func TestWinnerBondForfeitWithoutSubmission(t *testing.T) {
	e := newEnv(t)
	cip := "10.1.1.1"
	_, ctok := mkRoot(t, cip, 100, 100, 2)
	n := e.task(t, ctok, "task")
	id := e.mkAuction(t, ctok, n, 40, `,"min_bidders":2`, cip)
	winRoot, winTok := mkRoot(t, "10.2.2.1", 10, 0, 1)
	_, t2 := mkRoot(t, "10.3.3.1", 10, 0, 1)
	e.bidOK(t, winTok, id, 10, "10.2.2.1")
	e.bidOK(t, t2, id, 12, "10.3.3.1")
	e.closeNow(t, id)
	a := e.row(t, id)
	if a.State != "awarded" {
		t.Fatalf("state = %s want awarded", a.State)
	}
	if s := bondState(t, id, winRoot); s != "held" {
		t.Fatalf("winner bond before deadline = %s want held", s)
	}
	// Force the bounty deadline into the past with no submission, then run the janitor.
	if _, err := testPool.Exec(context.Background(), `UPDATE bounties SET deadline = now() - interval '1 hour' WHERE id = $1`, a.Bounty); err != nil {
		t.Fatal(err)
	}
	if err := e.s.janitor(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := bondState(t, id, winRoot); s != "forfeited" {
		t.Fatalf("winner bond after deadline = %s want forfeited", s)
	}
	conserved(t, e, "forfeit")
}

func TestCancelRefunds(t *testing.T) {
	e := newEnv(t)
	cip := "10.1.1.1"
	cid, ctok := mkRoot(t, cip, 100, 100, 2)
	n := e.task(t, ctok, "task")
	id := e.mkAuction(t, ctok, n, 40, `,"min_bidders":2`, cip)
	bRoot, bTok := mkRoot(t, "10.2.2.1", 10, 0, 1)
	e.bidOK(t, bTok, id, 10, "10.2.2.1")
	// Bidder down 1 credit for the bond.
	if c, _ := bal(t, bRoot); c != 9 {
		t.Fatalf("bidder credits = %d want 9", c)
	}
	st, body := e.do(t, "POST", "/v1/au/"+id+"/cancel", ctok, "")
	if st != 200 || !strings.Contains(body, "cancelled") {
		t.Fatalf("cancel: %d %s", st, body)
	}
	if a := e.row(t, id); a.State != "cancelled" {
		t.Fatalf("state = %s want cancelled", a.State)
	}
	// Creator budget back, bidder bond back.
	if _, ear := bal(t, cid); ear != 100 {
		t.Fatalf("creator earned = %d want 100", ear)
	}
	if c, _ := bal(t, bRoot); c != 10 {
		t.Fatalf("bidder credits = %d want 10 (bond returned)", c)
	}
	if s := bondState(t, id, bRoot); s != "returned" {
		t.Fatalf("bond = %s want returned", s)
	}
	conserved(t, e, "cancelled")
}

func TestLedgerConservation(t *testing.T) {
	e := newEnv(t)
	cip := "10.1.1.1"
	_, ctok := mkRoot(t, cip, 200, 200, 2)
	n := e.task(t, ctok, "task")
	conserved(t, e, "start")
	id := e.mkAuction(t, ctok, n, 50, `,"min_bidders":2`, cip)
	conserved(t, e, "created")
	_, w := mkRoot(t, "10.2.2.1", 10, 0, 1)
	_, x := mkRoot(t, "10.3.3.1", 10, 0, 1)
	_, y := mkRoot(t, "10.4.4.1", 10, 0, 1)
	e.bidOK(t, w, id, 20, "10.2.2.1")
	e.bidOK(t, x, id, 30, "10.3.3.1")
	e.bidOK(t, y, id, 40, "10.4.4.1")
	conserved(t, e, "bids held")
	// Re-bid replaces (no extra bond).
	e.bidOK(t, w, id, 18, "10.2.2.1")
	conserved(t, e, "rebid")
	e.closeNow(t, id)
	if a := e.row(t, id); a.State != "awarded" || a.Price != 30 {
		t.Fatalf("award = %s price %d want awarded/30", a.State, a.Price)
	}
	conserved(t, e, "awarded")
}
