package treasury

import (
	"context"
	"crypto/rand"
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

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/spaces"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
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
	} else if pool, done := testdb.Open("treasury", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping treasury DB tests")
		os.Exit(0)
	}
	core.LevelFn = trust.LevelOf // so fund caps read real levels
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
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	spaces.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, srv: srv}
}

func ctx() context.Context { return context.Background() }

func exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := testPool.Exec(ctx(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func randIP() string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.7", b[0], b[1])
}

func slug(prefix string) string {
	var b [4]byte
	rand.Read(b[:])
	return fmt.Sprintf("%s-%x", prefix, b[:])
}

// member creates a fresh root, grants it `earned` transferable credits (with a matching mint row so
// the audit stays balanced) and lifts it to the given level.
func member(t *testing.T, earned int64, level int) (id, token, ip string) {
	t.Helper()
	ip = randIP()
	id, token, err := core.CreateRoot(ctx(), testPool, "tr-test", ip)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case level >= 2:
		exec(t, `UPDATE identities SET rep = 6, created = now() - interval '8 days', verified_noncompute = 1, last_verified_at = now() WHERE id = $1`, id)
	case level == 1:
		exec(t, `UPDATE identities SET rep = 1, created = now() - interval '2 days' WHERE id = $1`, id)
	}
	if earned > 0 {
		exec(t, `UPDATE identities SET credits = credits + $2, earned = earned + $2 WHERE id = $1`, id, earned)
		if err := core.Ledger(ctx(), testPool, core.LedgerMint, id, "earned", earned, "test-grant", ""); err != nil {
			t.Fatal(err)
		}
	}
	return id, token, ip
}

func makeSpace(t *testing.T, members ...string) string {
	t.Helper()
	sl := slug("tr")
	rules := `{"join":"open","write":"members","topics":["x"],"quota":{"t":30,"kb":10,"n":100,"inbox":100},"pins":[],"templates":{"task":true,"kb":false},"docs":"stewards","pins_by":"stewards","inbox":"members","vote":{"window_h":48,"threshold":66,"min_member_h":24}}`
	exec(t, `INSERT INTO spaces (slug, name, about, creator_root, rules, members) VALUES ($1, 'Tr', '', $2, $3::jsonb, $4)`,
		sl, "asystem", rules, len(members))
	for _, r := range members {
		exec(t, `INSERT INTO space_members (space, root, role) VALUES ($1, $2, 'member')`, sl, r)
	}
	return sl
}

func (e *tenv) do(t *testing.T, method, path, token, body, ip string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", ip)
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
	return resp.StatusCode, string(b)
}

func audit(t *testing.T) core.AuditReport {
	t.Helper()
	a, err := core.LedgerAudit(ctx(), testPool, []string{"SELECT coalesce(sum(balance), 0) FROM space_treasury"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func treasuryBalance(t *testing.T, sl string) int64 {
	t.Helper()
	var b int64
	if err := testPool.QueryRow(ctx(), `SELECT balance FROM space_treasury WHERE space = $1`, sl).Scan(&b); err != nil {
		if err == pgx.ErrNoRows {
			return 0
		}
		t.Fatal(err)
	}
	return b
}

// --- tests ----------------------------------------------------------------------------------------

func TestFundEarnedOnlyAndCaps(t *testing.T) {
	newEnv(t)
	s := &svc{d: depsFor(t)}

	// earned-only: a member with grant credits but no earned is refused.
	gid, _, _ := member(t, 0, 1)
	exec(t, `UPDATE identities SET credits = credits + 100 WHERE id = $1`, gid) // grant, not earned
	if err := core.Ledger(ctx(), testPool, core.LedgerMint, gid, "grant", 100, "test", ""); err != nil {
		t.Fatal(err)
	}
	sl := makeSpace(t, gid)
	if _, err := s.Fund(ctx(), identOf(t, gid), sl, 10); err == nil || !strings.Contains(err.Error(), "earned") {
		t.Fatalf("want earned-only error, got %v", err)
	}

	// L1 cap 50/day: 50 ok, a further 1 over the line.
	eid, _, _ := member(t, 1000, 1)
	sl2 := makeSpace(t, eid)
	if _, err := s.Fund(ctx(), identOf(t, eid), sl2, 50); err != nil {
		t.Fatalf("fund 50: %v", err)
	}
	_, err := s.Fund(ctx(), identOf(t, eid), sl2, 1)
	if err == nil || !strings.Contains(err.Error(), "over 50/day") {
		t.Fatalf("want cap error, got %v", err)
	}
	if b := treasuryBalance(t, sl2); b != 50 {
		t.Fatalf("balance %d want 50", b)
	}
	if !audit(t).OK() {
		t.Fatalf("audit: %s", audit(t).Line())
	}
}

func TestConservationIncludesTreasury(t *testing.T) {
	e := newEnv(t)
	before := audit(t)
	if !before.OK() {
		t.Fatalf("precondition unbalanced: %s", before.Line())
	}
	a, _, _ := member(t, 100, 2)
	b, _, _ := member(t, 100, 2)
	sl := makeSpace(t, a, b)
	s := &svc{d: e.d}
	if _, err := s.Fund(ctx(), identOf(t, a), sl, 20); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fund(ctx(), identOf(t, b), sl, 20); err != nil {
		t.Fatal(err)
	}
	if bal := treasuryBalance(t, sl); bal != 40 {
		t.Fatalf("balance %d want 40", bal)
	}
	if got := audit(t); !got.OK() || got.Escrow < 40 {
		t.Fatalf("audit after fund: %s (escrow %d)", got.Line(), got.Escrow)
	}
}

func TestDebitGuarded(t *testing.T) {
	e := newEnv(t)
	a, _, _ := member(t, 100, 2)
	sl := makeSpace(t, a)
	s := &svc{d: e.d}
	if _, err := s.Fund(ctx(), identOf(t, a), sl, 30); err != nil {
		t.Fatal(err)
	}
	// Over-balance debit pays nothing.
	ok, err := Debit(ctx(), testPool, sl, 31, "job1")
	if err != nil || ok {
		t.Fatalf("over-balance debit: ok=%v err=%v", ok, err)
	}
	if b := treasuryBalance(t, sl); b != 30 {
		t.Fatalf("balance %d want 30 after refused debit", b)
	}
	// In-balance debit succeeds and moves credits to the system root.
	ok, err = Debit(ctx(), testPool, sl, 20, "job2")
	if err != nil || !ok {
		t.Fatalf("debit 20: ok=%v err=%v", ok, err)
	}
	if b := treasuryBalance(t, sl); b != 10 {
		t.Fatalf("balance %d want 10", b)
	}
	if !audit(t).OK() {
		t.Fatalf("audit: %s", audit(t).Line())
	}
	// Unknown space debits nothing.
	if ok, err := Debit(ctx(), testPool, "no-such-space", 5, "x"); err != nil || ok {
		t.Fatalf("unknown space debit: ok=%v err=%v", ok, err)
	}
}

func TestSpendProposalValidatorAndApplier(t *testing.T) {
	e := newEnv(t)
	s := &svc{d: e.d}
	a, _, _ := member(t, 1000, 2)
	payee, _, _ := member(t, 0, 1)
	sl := makeSpace(t, a)
	if _, err := s.Fund(ctx(), identOf(t, a), sl, 100); err != nil {
		t.Fatal(err)
	}

	// validator: platform scope refused.
	if err := s.validateSpend("", json.RawMessage(`{"to":"burn","credits":10}`)); err == nil {
		t.Fatal("want space-scope error")
	}
	// validator: over 20% of a 100cr balance (20 is the ceiling).
	if err := s.validateSpend(sl, json.RawMessage(fmt.Sprintf(`{"to":%q,"credits":21}`, payee))); err == nil {
		t.Fatal("want 20%% error")
	}
	if err := s.validateSpend(sl, json.RawMessage(fmt.Sprintf(`{"to":%q,"credits":20}`, payee))); err != nil {
		t.Fatalf("valid spend rejected: %v", err)
	}
	// validator: bad recipient.
	if err := s.validateSpend(sl, json.RawMessage(`{"to":"nope","credits":5}`)); err == nil {
		t.Fatal("want recipient error")
	}

	// applier: Earn to the identity.
	p := &gov.Proposal{ID: core.NewID('p'), Scope: sl, Kind: "spend", Patch: json.RawMessage(fmt.Sprintf(`{"to":%q,"credits":20,"why":"grant"}`, payee))}
	before, _ := creditsOf(t, payee)
	if err := core.Tx(ctx(), testPool, func(tx pgx.Tx) error { _, e := s.applySpend(ctx(), tx, p); return e }); err != nil {
		t.Fatalf("apply earn: %v", err)
	}
	after, afterEarned := creditsOf(t, payee)
	if after != before+20 || afterEarned < 20 {
		t.Fatalf("payee credits %d->%d earned=%d", before, after, afterEarned)
	}
	if b := treasuryBalance(t, sl); b != 80 {
		t.Fatalf("balance %d want 80", b)
	}

	// applier: burn.
	pb := &gov.Proposal{ID: core.NewID('p'), Scope: sl, Kind: "spend", Patch: json.RawMessage(`{"to":"burn","credits":10}`)}
	if err := core.Tx(ctx(), testPool, func(tx pgx.Tx) error { _, e := s.applySpend(ctx(), tx, pb); return e }); err != nil {
		t.Fatalf("apply burn: %v", err)
	}
	if b := treasuryBalance(t, sl); b != 70 {
		t.Fatalf("balance %d want 70 after burn", b)
	}
	if !audit(t).OK() {
		t.Fatalf("audit: %s", audit(t).Line())
	}
}

func TestArchiveRefundsProRata(t *testing.T) {
	e := newEnv(t)
	s := &svc{d: e.d}
	a, _, _ := member(t, 1000, 2)
	b, _, _ := member(t, 1000, 2)
	sl := makeSpace(t, a, b)
	// a funds 75, b funds 25 -> 100cr pool, shares 3:1.
	if _, err := s.Fund(ctx(), identOf(t, a), sl, 75); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fund(ctx(), identOf(t, b), sl, 25); err != nil {
		t.Fatal(err)
	}
	aBefore, _ := creditsOf(t, a)
	bBefore, _ := creditsOf(t, b)
	exec(t, `UPDATE spaces SET archived = true, archived_at = now() WHERE slug = $1`, sl)
	if err := s.RunArchiveRefunds(ctx()); err != nil {
		t.Fatal(err)
	}
	aAfter, _ := creditsOf(t, a)
	bAfter, _ := creditsOf(t, b)
	if aAfter-aBefore != 75 || bAfter-bBefore != 25 {
		t.Fatalf("refund a=%d b=%d want 75/25", aAfter-aBefore, bAfter-bBefore)
	}
	if treasuryBalance(t, sl) != 0 {
		t.Fatalf("balance not drained")
	}
	if !audit(t).OK() {
		t.Fatalf("audit: %s", audit(t).Line())
	}
	// Idempotent: a second pass does nothing.
	if err := s.RunArchiveRefunds(ctx()); err != nil {
		t.Fatal(err)
	}
	if a2, _ := creditsOf(t, a); a2 != aAfter {
		t.Fatalf("second refund paid again")
	}
}

func TestLedgerRouteAndHeaderLine(t *testing.T) {
	e := newEnv(t)
	s := &svc{d: e.d}
	a, tokA, ipA := member(t, 1000, 2)
	b, _, _ := member(t, 1000, 2)
	sl := makeSpace(t, a, b)
	if _, err := s.Fund(ctx(), identOf(t, a), sl, 20); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Fund(ctx(), identOf(t, b), sl, 20); err != nil {
		t.Fatal(err)
	}
	// sg header line.
	st, body := e.do(t, "GET", "/v1/s/"+sl, tokA, "", ipA)
	if st != 200 || !strings.Contains(body, "treasury: 40cr") {
		t.Fatalf("sg header %d missing treasury line: %s", st, body)
	}
	// ledger route.
	st, body = e.do(t, "GET", "/v1/s/"+sl+"/ledger?k=10", tokA, "", ipA)
	if st != 200 || !strings.Contains(body, "balance=40cr") || !strings.Contains(body, "fund") {
		t.Fatalf("ledger route %d: %s", st, body)
	}
	// fund over HTTP.
	st, body = e.do(t, "POST", "/v1/s/"+sl+"/fund", tokA, `{"credits":5}`, ipA)
	if st != 201 || !strings.Contains(body, "treasury=45cr") {
		t.Fatalf("fund route %d: %s", st, body)
	}
}

func TestGovWeightUnchangedByFunding(t *testing.T) {
	e := newEnv(t)
	s := &svc{d: e.d}
	a, _, _ := member(t, 1000, 2)
	sl := makeSpace(t, a)
	since := time.Now().Add(-48 * time.Hour)
	st0, err := trust.Load(ctx(), testPool, a)
	if err != nil {
		t.Fatal(err)
	}
	w0 := trust.GovWeight(st0, since, 24)
	if w0 <= 0 {
		t.Fatalf("precondition: funder has no gov weight (%v)", w0)
	}
	if _, err := s.Fund(ctx(), identOf(t, a), sl, 200); err != nil {
		t.Fatal(err)
	}
	st1, err := trust.Load(ctx(), testPool, a)
	if err != nil {
		t.Fatal(err)
	}
	if w1 := trust.GovWeight(st1, since, 24); w1 != w0 {
		t.Fatalf("gov weight changed by funding: %v -> %v", w0, w1)
	}
}

// --- small helpers requiring the pool -------------------------------------------------------------

func depsFor(t *testing.T) *core.Deps {
	t.Helper()
	return newEnv(t).d
}

func identOf(t *testing.T, root string) *core.Ident {
	t.Helper()
	var id core.Ident
	var earned int64
	if err := testPool.QueryRow(ctx(), `SELECT id, root, credits, earned FROM identities WHERE id = $1`, root).
		Scan(&id.ID, &id.Root, &id.Credits, &earned); err != nil {
		t.Fatal(err)
	}
	id.Earned = earned
	return &id
}

func creditsOf(t *testing.T, id string) (credits, earned int64) {
	t.Helper()
	if err := testPool.QueryRow(ctx(), `SELECT credits, earned FROM identities WHERE id = $1`, id).Scan(&credits, &earned); err != nil {
		t.Fatal(err)
	}
	return
}
