package graph

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
)

var pool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	// rep_log rows are written through core.RepLogger; wire trust's recorder so clawback is logged.
	core.RepLogger = trust.RecordRep
	// A default signer for the rel1 statements.
	sg, err := sign.New(core.Config{ServerSecret: []byte("test-secret-0123456789-abcdefghij"), SignKID: 1})
	if err != nil {
		panic(err)
	}
	sign.Use(sg)

	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		p, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if _, err := p.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, p); err != nil {
			panic(err)
		}
		pool = p
		code := m.Run()
		p.Close()
		os.Exit(code)
	}
	p, cleanup := testdb.Open("graph", core.Migrate)
	if p == nil {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping graph DB tests")
		os.Exit(0)
	}
	pool = p
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// --- helpers --------------------------------------------------------------------------------

func bg() context.Context { return context.Background() }

func wipe(t *testing.T) {
	t.Helper()
	for _, tbl := range []string{"pair_log", "vote_edges", "pair_damp", "collusion_pairs",
		"ledger_flags", "rel_counters", "graph_state", "kb_votes", "kb", "task_votes", "tasks",
		"ledger", "reviews", "review_slots", "review_excl", "bounties", "vouches", "rep_log",
		"identities", "events"} {
		pool.Exec(bg(), "DELETE FROM "+tbl)
	}
}

func mkRoot(t *testing.T, ip string, rep int) string {
	t.Helper()
	id := core.NewID('a')
	_, h := core.NewToken()
	if ip == "" {
		ip = fmt.Sprintf("10.%d.%d.1", int(id[1])%250, int(id[2])%250)
	}
	_, err := pool.Exec(bg(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, reg_ip, rep, created)
		VALUES ($1, 'r', NULL, $1, $2, 1000, $3, $4, now() - interval '40 days')`, id, h, ip, rep)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// mkKB inserts an entry authored by root and returns its id.
func mkKB(t *testing.T, root string) string {
	t.Helper()
	id := core.NewID('k')
	_, err := pool.Exec(bg(), `INSERT INTO kb (id, kind, title, author, author_root, expires_at)
		VALUES ($1, 'note', 't', $2, $2, now() + interval '30 days')`, id, root)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// voteKB casts an up/down vote on kbID by voter at a given age.
func voteKB(t *testing.T, kbID, voter string, up bool, ageDays int) {
	t.Helper()
	_, err := pool.Exec(bg(), `INSERT INTO kb_votes (kb_id, root, up, w, created)
		VALUES ($1, $2, $3, 1, now() - make_interval(days => $4))
		ON CONFLICT (kb_id, root) DO NOTHING`, kbID, voter, up, ageDays)
	if err != nil {
		t.Fatal(err)
	}
}

func scalarInt(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(bg(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func repOf(t *testing.T, root string) int {
	t.Helper()
	r, err := core.Rep(bg(), pool, root)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// --- tests ----------------------------------------------------------------------------------

func TestPairLogFromVotes(t *testing.T) {
	if pool == nil {
		t.Skip()
	}
	wipe(t)
	a := mkRoot(t, "10.1.0.1", 0)
	b := mkRoot(t, "10.2.0.1", 0)
	voteKB(t, mkKB(t, a), b, true, 1) // b confirms a
	voteKB(t, mkKB(t, b), a, true, 1) // a confirms b
	if err := VoteGraph(bg(), pool); err != nil {
		t.Fatal(err)
	}
	if n := scalarInt(t, `SELECT count(*) FROM pair_log WHERE NOT super AND kind = 'kb'`); n == 0 {
		t.Fatal("no root-keyed pair_log rows")
	}
	if n := scalarInt(t, `SELECT count(*) FROM vote_edges`); n != 2 {
		t.Fatalf("vote_edges = %d, want 2", n)
	}
	if n := scalarInt(t, `SELECT count(*) FROM pair_log WHERE super`); n == 0 {
		t.Fatal("no super-keyed pair_log twin")
	}
}

func TestRepClawbackPerCounterparty(t *testing.T) {
	if pool == nil {
		t.Skip()
	}
	wipe(t)
	a := mkRoot(t, "10.3.0.1", 7) // rep 7 = the 7 nominal confirmations each earned
	b := mkRoot(t, "10.4.0.1", 7)
	// Each authors 7 entries, one per day; the other up-confirms all 7 over the week.
	for d := 0; d < 7; d++ {
		voteKB(t, mkKB(t, a), b, true, d)
		voteKB(t, mkKB(t, b), a, true, d)
	}
	if err := VoteGraph(bg(), pool); err != nil {
		t.Fatal(err)
	}
	// Rule 1: keep +1 per 7 d per counterparty, claw back the other 6.
	if got := repOf(t, a); got != 1 {
		t.Fatalf("a rep = %d, want 1 (7 - 6 clawed)", got)
	}
	if got := repOf(t, b); got != 1 {
		t.Fatalf("b rep = %d, want 1", got)
	}
	if n := scalarInt(t, `SELECT count(*) FROM rep_log WHERE kind = 'rep:pairdup' AND delta < 0`); n < 2 {
		t.Fatalf("rep:pairdup rows = %d, want >= 2", n)
	}
	// Idempotent: a second run claws nothing more.
	if err := VoteGraph(bg(), pool); err != nil {
		t.Fatal(err)
	}
	if got := repOf(t, a); got != 1 {
		t.Fatalf("a rep after rerun = %d, want 1", got)
	}
}

func TestAffinityCreditFlag(t *testing.T) {
	if pool == nil {
		t.Skip()
	}
	wipe(t)
	p := mkRoot(t, "10.5.0.1", 0)
	r := mkRoot(t, "10.6.0.1", 0)
	pool.Exec(bg(), `UPDATE identities SET verified_contrib = 5 WHERE id = $1`, r)
	for i := 0; i < 4; i++ { // 4 x 100 = 400 earned over 30 d: 300 cap -> the 4th crosses it
		if _, err := pool.Exec(bg(), `INSERT INTO ledger (from_id, to_id, class, amount, reason)
			VALUES ($1, $2, 'earned', 100, 'bounty')`, p, r); err != nil {
			t.Fatal(err)
		}
	}
	if err := VoteGraph(bg(), pool); err != nil {
		t.Fatal(err)
	}
	if n := scalarInt(t, `SELECT count(*) FROM ledger_flags WHERE flag = 'affinity'`); n != 1 {
		t.Fatalf("affinity-flagged rows = %d, want 1 (the over-cap payout)", n)
	}
	if vc := scalarInt(t, `SELECT verified_contrib FROM identities WHERE id = $1`, r); vc != 4 {
		t.Fatalf("verified_contrib = %d, want 4 (trimmed by 1)", vc)
	}
	if n := scalarInt(t, `SELECT count(*) FROM rep_log WHERE kind = 'vc:affinity'`); n != 1 {
		t.Fatalf("vc:affinity notes = %d, want 1", n)
	}
	// Idempotent.
	if err := VoteGraph(bg(), pool); err != nil {
		t.Fatal(err)
	}
	if vc := scalarInt(t, `SELECT verified_contrib FROM identities WHERE id = $1`, r); vc != 4 {
		t.Fatalf("verified_contrib after rerun = %d, want 4", vc)
	}
}

func TestReciprocalPairDamp(t *testing.T) {
	if pool == nil {
		t.Skip()
	}
	wipe(t)
	a := mkRoot(t, "10.7.0.1", 0)
	b := mkRoot(t, "10.8.0.1", 0)
	for i := 0; i < 3; i++ { // n_ab = n_ba = 3, each confirms only the other (share 1.0)
		voteKB(t, mkKB(t, a), b, true, i)
		voteKB(t, mkKB(t, b), a, true, i)
	}
	if err := VoteGraph(bg(), pool); err != nil {
		t.Fatal(err)
	}
	lo, hi := order(a, b)
	var damp float64
	var reason string
	if err := pool.QueryRow(bg(), `SELECT damp, reason FROM pair_damp WHERE a = $1 AND b = $2`, lo, hi).Scan(&damp, &reason); err != nil {
		t.Fatalf("no pair_damp row: %v", err)
	}
	if damp != 0 || reason != "reciprocal" {
		t.Fatalf("damp = %v reason = %q, want 0 reciprocal", damp, reason)
	}
	if d := PairDamp(bg(), pool, a, b); d != 0 {
		t.Fatalf("PairDamp = %v, want 0", d)
	}
}

func TestCliqueDetection(t *testing.T) {
	if pool == nil {
		t.Skip()
	}
	wipe(t)
	a := mkRoot(t, "10.9.0.1", 0)
	b := mkRoot(t, "10.10.0.1", 0)
	c := mkRoot(t, "10.11.0.1", 0)
	ka, kb, kc := mkKB(t, a), mkKB(t, b), mkKB(t, c)
	// Fully reciprocal ring, no outside confirmations -> 100 % inbound from inside.
	voteKB(t, kb, a, true, 1)
	voteKB(t, kc, a, true, 1)
	voteKB(t, ka, b, true, 1)
	voteKB(t, kc, b, true, 1)
	voteKB(t, ka, c, true, 1)
	voteKB(t, kb, c, true, 1)
	if err := VoteGraph(bg(), pool); err != nil {
		t.Fatal(err)
	}
	if n := scalarInt(t, `SELECT count(*) FROM pair_damp WHERE reason LIKE 'clique:%' AND damp = 0`); n != 3 {
		t.Fatalf("clique-damped pairs = %d, want 3", n)
	}
}

func TestExcludedPairs(t *testing.T) {
	if pool == nil {
		t.Skip()
	}
	wipe(t)
	a := mkRoot(t, "10.12.0.1", 0)
	b := mkRoot(t, "10.13.0.1", 0)
	for i := 0; i < 3; i++ {
		voteKB(t, mkKB(t, a), b, true, i)
		voteKB(t, mkKB(t, b), a, true, i)
	}
	if err := VoteGraph(bg(), pool); err != nil {
		t.Fatal(err)
	}
	lo, hi := order(a, b)
	var score float64
	if err := pool.QueryRow(bg(), `SELECT score FROM collusion_pairs WHERE a = $1 AND b = $2`, lo, hi).Scan(&score); err != nil {
		t.Fatalf("no collusion_pairs row: %v", err)
	}
	if score < 50 {
		t.Fatalf("score = %v, want >= 50", score)
	}
	if !Excluded(bg(), pool, a, b) {
		t.Fatal("Excluded = false, want true")
	}
	// An unrelated pair is not excluded.
	x := mkRoot(t, "10.14.0.1", 0)
	if Excluded(bg(), pool, a, x) {
		t.Fatal("unrelated pair excluded")
	}
}

func TestConfirmerEntropyAndLastVerified(t *testing.T) {
	if pool == nil {
		t.Skip()
	}
	wipe(t)
	v := mkRoot(t, "10.15.0.1", 0)
	a1 := mkRoot(t, "10.16.0.1", 0)
	a2 := mkRoot(t, "10.17.0.1", 0)
	a3 := mkRoot(t, "10.18.0.1", 0)
	voteKB(t, mkKB(t, a1), v, true, 1)
	voteKB(t, mkKB(t, a2), v, true, 1)
	ok, err := ConfirmerEntropy(bg(), pool, v)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("entropy true with 2 distinct authors, want false")
	}
	voteKB(t, mkKB(t, a3), v, true, 1)
	ok, err = ConfirmerEntropy(bg(), pool, v)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("entropy false with 3 distinct authors, want true")
	}
	// A qualifying confirmation marks the author verified (last_verified_at set via trust.Verified).
	if err := trust.Verified(bg(), pool, a3, true); err != nil {
		t.Fatal(err)
	}
	var set bool
	pool.QueryRow(bg(), `SELECT last_verified_at IS NOT NULL FROM identities WHERE id = $1`, a3).Scan(&set)
	if !set {
		t.Fatal("last_verified_at not set")
	}
}

func TestReliabilityDerivation(t *testing.T) {
	if pool == nil {
		t.Skip()
	}
	wipe(t)
	// 80 % drop rule (pure).
	if !claimOK(10*time.Minute, 5*time.Minute) {
		t.Fatal("claim dropped at 50 % TTL should be ok")
	}
	if claimOK(10*time.Minute, 9*time.Minute) {
		t.Fatal("claim held to 90 % TTL should be bad")
	}
	req := mkRoot(t, "10.19.0.1", 0)
	w := mkRoot(t, "10.20.0.1", 0)
	// A review owned by req; w answers one slot (ok); w's lease expires on another (bad); req
	// reviewing its own request is self-owned and excluded.
	if _, err := pool.Exec(bg(), `INSERT INTO reviews (id, req_id, req_root, kind, n, pay_each, deadline)
		VALUES ('rv1', 'q1', $1, 'code', 1, 1, now() + interval '1 day')`, req); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(bg(), `INSERT INTO review_slots (review, slot, state, pay, worker_root, answered_at)
		VALUES ('rv1', 1, 'answered', 1, $1, now()), ('rv1', 2, 'answered', 1, $2, now())`, w, req); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(bg(), `INSERT INTO review_excl (review, slot, root, why) VALUES ('rv1', 3, $1, 'expired')`, w); err != nil {
		t.Fatal(err)
	}
	if err := Reliability(bg(), pool); err != nil {
		t.Fatal(err)
	}
	ok := scalarInt(t, `SELECT coalesce(sum(ok), 0) FROM rel_counters WHERE root = $1 AND kind = 'review'`, w)
	bad := scalarInt(t, `SELECT coalesce(sum(bad), 0) FROM rel_counters WHERE root = $1 AND kind = 'review'`, w)
	if ok != 1 || bad != 1 {
		t.Fatalf("worker review ok/bad = %d/%d, want 1/1", ok, bad)
	}
	if n := scalarInt(t, `SELECT count(*) FROM rel_counters WHERE root = $1`, req); n != 0 {
		t.Fatalf("self-owned requester has %d rel rows, want 0", n)
	}
}

func TestRel1LineVerifies(t *testing.T) {
	if pool == nil {
		t.Skip()
	}
	wipe(t)
	r := mkRoot(t, "10.21.0.1", 0)
	line, sig := RelLine(bg(), pool, r)
	if !strings.HasPrefix(line, "rel1 root="+r+" ") {
		t.Fatalf("line = %q", line)
	}
	if _, ok := sign.Verify("rel1", line, sig); !ok {
		t.Fatal("rel1 signature does not verify")
	}
}

func TestShownOnlyAfterTen(t *testing.T) {
	if pool == nil {
		t.Skip()
	}
	wipe(t)
	r := mkRoot(t, "10.22.0.1", 0)
	month := time.Now().UTC().Format("2006-01")
	// 9 interactions: hidden (rel=0.50 n=0).
	if _, err := pool.Exec(bg(), `INSERT INTO rel_counters (root, month, kind, ok, bad) VALUES ($1, $2, 'claim', 9, 0)`, r, month); err != nil {
		t.Fatal(err)
	}
	if rel, n := Rel(bg(), pool, r); rel != 0.5 || n != 0 {
		t.Fatalf("at 9 interactions Rel = %v/%d, want 0.5/0", rel, n)
	}
	line, _ := RelLine(bg(), pool, r)
	if !strings.Contains(line, "rel=0.50 n=0") {
		t.Fatalf("hidden line = %q, want rel=0.50 n=0", line)
	}
	// 10th interaction: shown.
	if _, err := pool.Exec(bg(), `UPDATE rel_counters SET ok = 10 WHERE root = $1`, r); err != nil {
		t.Fatal(err)
	}
	if rel, n := Rel(bg(), pool, r); n != 10 || rel < 0.8 {
		t.Fatalf("at 10 interactions Rel = %v/%d, want ~0.857/10", rel, n)
	}
}
