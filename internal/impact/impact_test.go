package impact

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/spaces"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
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
	} else if p, done := testdb.Open("impact", core.Migrate); p != nil {
		pool, cleanup = p, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping impact DB tests")
		os.Exit(0)
	}
	core.LevelFn = trust.LevelOf
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func newDeps(t *testing.T) *core.Deps {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20, AbuseContact: "abuse@example.test"}
	d, err := core.NewDeps(context.Background(), cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

var taskN atomic.Int64

func init() { taskN.Store(time.Now().UnixNano() % 1_000_000_000) }

// mkRoot inserts a root identity with the given rep, age and since-verification freshness.
func mkRoot(t *testing.T, rep int, age time.Duration, verified bool) string {
	t.Helper()
	id := core.NewID('a')
	var tok [32]byte
	rand.Read(tok[:])
	var lv *time.Time
	if verified {
		now := time.Now()
		lv = &now
	}
	_, err := pool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, rep, reg_ip, created, seed, last_verified_at)
		VALUES ($1, 'm', NULL, $1, $2, $3, '203.0.113.7', $4, false, $5)`,
		id, tok[:], rep, time.Now().Add(-age), lv)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// mkSpace inserts a live space with the given rules and returns its unique slug.
func mkSpace(t *testing.T, rules spaces.Rules) string {
	t.Helper()
	slug := "imp-" + strings.ToLower(core.NewID('a'))[1:]
	_, err := pool.Exec(context.Background(), `INSERT INTO spaces (slug, name, creator_root, rules, members)
		VALUES ($1, 'test', 'asystem', $2, 0)`, slug, []byte(rules.JSON()))
	if err != nil {
		t.Fatal(err)
	}
	return slug
}

// addMember joins root to slug (role member|steward, member since `sinceAgo`).
func addMember(t *testing.T, slug, root, role string, sinceAgo time.Duration) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `INSERT INTO space_members (space, root, role, since) VALUES ($1, $2, $3, $4)`,
		slug, root, role, time.Now().Add(-sinceAgo))
	if err != nil {
		t.Fatal(err)
	}
	pool.Exec(context.Background(), `UPDATE spaces SET members = members + 1 WHERE slug = $1`, slug)
}

func addTask(t *testing.T, slug, root string, createdAgo time.Duration) int64 {
	t.Helper()
	n := taskN.Add(1)
	_, err := pool.Exec(context.Background(), `INSERT INTO tasks (n, id, root, space, state, created) VALUES ($1, $2, $3, $4, 'open', $5)`,
		n, core.NewID('t'), root, slug, time.Now().Add(-createdAgo))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func patch(s string) json.RawMessage { return json.RawMessage(s) }

// --- tests ----------------------------------------------------------------------------------------

// TestDryRunCountsAggregateOnly: a write:established dry-run in a 40-member space where 12 are below
// L2 prints the aggregate "write lost 12/40" and nothing else leaks (no member ids), and it writes
// nothing (rules and member rows unchanged).
func TestDryRunCountsAggregateOnly(t *testing.T) {
	ctx := context.Background()
	slug := mkSpace(t, spaces.Default()) // write:members
	var belowL2 []string
	for i := 0; i < 40; i++ {
		var root string
		if i < 12 {
			root = mkRoot(t, 0, 10*24*time.Hour, true) // rep 0 -> not established
			belowL2 = append(belowL2, root)
		} else {
			root = mkRoot(t, 10, 10*24*time.Hour, true) // established
		}
		addMember(t, slug, root, "member", 48*time.Hour)
	}
	res, err := Dryrun(ctx, pool, slug, patch(`{"write":"established"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Line, "write lost 12/40") {
		t.Fatalf("want 'write lost 12/40' in %q", res.Line)
	}
	for _, r := range belowL2 {
		if strings.Contains(res.Line, r) {
			t.Fatalf("dry-run leaked a member id %s: %q", r, res.Line)
		}
	}
	// no write happened: rules and membership are unchanged.
	var raw []byte
	pool.QueryRow(ctx, `SELECT rules FROM spaces WHERE slug = $1`, slug).Scan(&raw)
	rr, _ := spaces.Parse(raw)
	if rr.Write != "members" {
		t.Fatalf("dry-run mutated rules: write=%s", rr.Write)
	}
	var members int
	pool.QueryRow(ctx, `SELECT count(*) FROM space_members WHERE space = $1`, slug).Scan(&members)
	if members != 40 {
		t.Fatalf("dry-run changed membership: %d", members)
	}
}

// TestDrasticTagging: a rule patch that drops eligible weight by more than half is drastic, and
// OnPropose tags the proposal.
func TestDrasticTagging(t *testing.T) {
	ctx := context.Background()
	slug := mkSpace(t, spaces.Default()) // vote.min_member_h = 24
	for i := 0; i < 4; i++ {
		root := mkRoot(t, 10, 10*24*time.Hour, true)
		addMember(t, slug, root, "member", 25*time.Hour) // eligible at 24 h, not at 336 h
	}
	// raise the membership-age bar to the max: every member's weight drops to 0.
	res, err := Dryrun(ctx, pool, slug, patch(`{"vote":{"min_member_h":336}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Drastic {
		t.Fatalf("expected drastic, line=%q", res.Line)
	}
	if !strings.Contains(res.Line, "eligible_w") {
		t.Fatalf("want eligible_w segment: %q", res.Line)
	}
	p := &gov.Proposal{ID: core.NewID('p'), Scope: slug, Kind: "rule", Patch: patch(`{"vote":{"min_member_h":336}}`), Flags: []string{}}
	if err := OnPropose(ctx, pool, p); err != nil {
		t.Fatal(err)
	}
	if !hasFlag(p.Flags, "drastic") {
		t.Fatalf("OnPropose did not tag drastic: %v", p.Flags)
	}

	// a benign patch (no eligible/write change) is not drastic.
	p2 := &gov.Proposal{ID: core.NewID('p'), Scope: slug, Kind: "rule", Patch: patch(`{"topics":["go"]}`), Flags: []string{}}
	if err := OnPropose(ctx, pool, p2); err != nil {
		t.Fatal(err)
	}
	if hasFlag(p2.Flags, "drastic") {
		t.Fatalf("benign patch tagged drastic: %v", p2.Flags)
	}
}

// TestImpactStoredOnPropose: OnPropose stores the impact line for a rule proposal; it is readable on
// the /p/<id> page lines.
func TestImpactStoredOnPropose(t *testing.T) {
	ctx := context.Background()
	slug := mkSpace(t, spaces.Default())
	for i := 0; i < 10; i++ {
		rep := 10
		if i < 6 {
			rep = 0
		}
		addMember(t, slug, mkRoot(t, rep, 10*24*time.Hour, true), "member", 48*time.Hour)
	}
	pid := core.NewID('p')
	p := &gov.Proposal{ID: pid, Scope: slug, Kind: "rule", Patch: patch(`{"write":"established"}`), Flags: []string{}}
	if err := OnPropose(ctx, pool, p); err != nil {
		t.Fatal(err)
	}
	var impact string
	if err := pool.QueryRow(ctx, `SELECT impact FROM proposal_impact WHERE pid = $1`, pid).Scan(&impact); err != nil {
		t.Fatalf("no proposal_impact row: %v", err)
	}
	if !strings.Contains(impact, "write lost 6/10") {
		t.Fatalf("stored impact %q", impact)
	}
	lines := pageLines(ctx, pool, pid)
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "impact: ") {
		t.Fatalf("page lines %v", lines)
	}
}

// TestOutcomeAfter30Days: OnApplied snapshots the baseline; after the 30-day window the janitor
// writes the after aggregates, the outcome line and marks written_at.
func TestOutcomeAfter30Days(t *testing.T) {
	ctx := context.Background()
	d := newDeps(t)
	slug := mkSpace(t, spaces.Default())
	author := mkRoot(t, 10, 10*24*time.Hour, true)
	addMember(t, slug, author, "member", 48*time.Hour)
	// baseline: no tasks yet.
	def := spaces.Default()
	pid := core.NewID('p')
	insertProposal(t, pid, slug, "rule", `{"write":"established"}`, string(def.JSON()))
	if err := OnApplied(ctx, pool, &gov.Proposal{ID: pid, Scope: slug, Kind: "rule"}); err != nil {
		t.Fatal(err)
	}
	// activity grows after apply.
	for i := 0; i < 5; i++ {
		addTask(t, slug, author, 2*24*time.Hour)
	}
	// age the outcome past its 30-day window.
	pool.Exec(ctx, `UPDATE proposal_outcomes SET applied_at = now() - interval '31 days' WHERE pid = $1`, pid)

	if err := RunOutcomes(ctx, d); err != nil {
		t.Fatal(err)
	}
	var after []byte
	var written *time.Time
	if err := pool.QueryRow(ctx, `SELECT after, written_at FROM proposal_outcomes WHERE pid = $1`, pid).Scan(&after, &written); err != nil {
		t.Fatal(err)
	}
	if after == nil || written == nil {
		t.Fatalf("outcome not written: after=%v written=%v", after, written)
	}
	lines := pageLines(ctx, pool, pid)
	var got string
	for _, l := range lines {
		if strings.HasPrefix(l, "outcome: ") {
			got = l
		}
	}
	if got == "" || !strings.Contains(got, "members 1->1") || !strings.Contains(got, "reverted:no") {
		t.Fatalf("outcome line %q (lines=%v)", got, lines)
	}
	// changelog carries the line.
	var cn int
	pool.QueryRow(ctx, `SELECT count(*) FROM changelog_notes WHERE pid = $1`, pid).Scan(&cn)
	if cn == 0 {
		t.Fatal("no changelog note for outcome")
	}
}

// TestRevertedDetection: a later applied rule proposal that restores the previous value marks the
// earlier proposal's outcome reverted.
func TestRevertedDetection(t *testing.T) {
	ctx := context.Background()
	d := newDeps(t)
	base := spaces.Default() // write:members
	slug := mkSpace(t, base)
	addMember(t, slug, mkRoot(t, 10, 10*24*time.Hour, true), "member", 48*time.Hour)

	// P applied: members -> established (prev = the members rules).
	pA := core.NewID('p')
	insertProposalApplied(t, pA, slug, "rule", `{"write":"established"}`, string(base.JSON()), time.Now().Add(-40*24*time.Hour))
	if err := OnApplied(ctx, pool, &gov.Proposal{ID: pA, Scope: slug, Kind: "rule"}); err != nil {
		t.Fatal(err)
	}
	pool.Exec(ctx, `UPDATE proposal_outcomes SET applied_at = now() - interval '40 days' WHERE pid = $1`, pA)

	// the space now reads write:established.
	est, _ := spaces.Merge(base, patch(`{"write":"established"}`))
	pool.Exec(ctx, `UPDATE spaces SET rules = $2 WHERE slug = $1`, slug, []byte(est.JSON()))

	// Q applied later: established -> members, restoring P's prev. The space is back to members.
	pB := core.NewID('p')
	insertProposalApplied(t, pB, slug, "rule", `{"write":"members"}`, string(est.JSON()), time.Now().Add(-5*24*time.Hour))
	pool.Exec(ctx, `UPDATE spaces SET rules = $2 WHERE slug = $1`, slug, []byte(base.JSON()))

	if err := RunOutcomes(ctx, d); err != nil {
		t.Fatal(err)
	}
	var reverted bool
	if err := pool.QueryRow(ctx, `SELECT reverted FROM proposal_outcomes WHERE pid = $1`, pA).Scan(&reverted); err != nil {
		t.Fatal(err)
	}
	if !reverted {
		t.Fatal("expected P reverted by the later proposal")
	}

	// control: a space left at established is not reverted.
	slug2 := mkSpace(t, base)
	addMember(t, slug2, mkRoot(t, 10, 10*24*time.Hour, true), "member", 48*time.Hour)
	pC := core.NewID('p')
	insertProposalApplied(t, pC, slug2, "rule", `{"write":"established"}`, string(base.JSON()), time.Now().Add(-40*24*time.Hour))
	OnApplied(ctx, pool, &gov.Proposal{ID: pC, Scope: slug2, Kind: "rule"})
	pool.Exec(ctx, `UPDATE proposal_outcomes SET applied_at = now() - interval '40 days' WHERE pid = $1`, pC)
	est2, _ := spaces.Merge(base, patch(`{"write":"established"}`))
	pool.Exec(ctx, `UPDATE spaces SET rules = $2 WHERE slug = $1`, slug2, []byte(est2.JSON()))
	if err := RunOutcomes(ctx, d); err != nil {
		t.Fatal(err)
	}
	var rev2 bool
	pool.QueryRow(ctx, `SELECT reverted FROM proposal_outcomes WHERE pid = $1`, pC).Scan(&rev2)
	if rev2 {
		t.Fatal("control should not be reverted")
	}
}

// TestMemberOnlyAndRate: the dry run is members-only and capped at 20/day.
func TestMemberOnlyAndRate(t *testing.T) {
	ctx := context.Background()
	d := newDeps(t)
	slug := mkSpace(t, spaces.Default())
	stranger := mkRoot(t, 10, 10*24*time.Hour, true)
	if _, err := runDryrun(ctx, d, stranger, slug, patch(`{"write":"established"}`)); err == nil {
		t.Fatal("non-member allowed")
	} else if ae, ok := err.(*core.APIError); !ok || ae.Status != 403 {
		t.Fatalf("want 403, got %v", err)
	}

	member := mkRoot(t, 10, 10*24*time.Hour, true)
	addMember(t, slug, member, "member", 48*time.Hour)
	for i := 0; i < 20; i++ {
		if _, err := runDryrun(ctx, d, member, slug, patch(`{"topics":["go"]}`)); err != nil {
			t.Fatalf("call %d failed: %v", i+1, err)
		}
	}
	if _, err := runDryrun(ctx, d, member, slug, patch(`{"topics":["go"]}`)); err == nil {
		t.Fatal("21st call not rate-limited")
	} else if ae, ok := err.(*core.APIError); !ok || ae.Status != 429 {
		t.Fatalf("want 429, got %v", err)
	}
}

// --- proposal row helpers -------------------------------------------------------------------------

func insertProposal(t *testing.T, pid, scope, kind, patchJSON, prevJSON string) {
	t.Helper()
	insertProposalApplied(t, pid, scope, kind, patchJSON, prevJSON, time.Now())
}

func insertProposalApplied(t *testing.T, pid, scope, kind, patchJSON, prevJSON string, appliedAt time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `INSERT INTO proposals
		(id, scope, kind, target, patch, why, need, author, author_root, closes_at, state, prev, applied_at)
		VALUES ($1, $2, $3, '', $4, 'why', '', 'asystem', 'asystem', now(), 'applied', $5, $6)`,
		pid, scope, kind, []byte(patchJSON), []byte(prevJSON), appliedAt)
	if err != nil {
		t.Fatal(err)
	}
}
