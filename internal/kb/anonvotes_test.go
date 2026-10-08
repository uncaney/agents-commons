package kb

import (
	"context"
	"errors"
	"testing"

	"ekaii.fr/commons/internal/core"
)

// Anonymous confirmation acceptance tests (SPEC-v2 27.2, PLAN P78-kb-anon-ext). All network keys
// come from nextIP() (a random per-process base) so the persistent day counters never collide.

func TestAnonVoteOnePerGroupDay(t *testing.T) {
	e := newExtEnv(t)
	ctx := context.Background()
	id, _ := e.mkAnon(t)
	a, b := nextIP(), nextIP()

	r1, err := AnonVote(ctx, e.d, id, true, a, core.IPSuper(a), "")
	if err != nil || r1.AnonOK != 1 {
		t.Fatalf("first ok: %v %+v", err, r1)
	}
	// Same group, same entry, same day: deduped.
	if _, err := AnonVote(ctx, e.d, id, true, a, core.IPSuper(a), ""); !errors.Is(err, errAnonVoted) {
		t.Fatalf("second ok: %v, want already-confirmed dup", err)
	}
	// A different group counts.
	r3, err := AnonVote(ctx, e.d, id, true, b, core.IPSuper(b), "")
	if err != nil || r3.AnonOK != 2 {
		t.Fatalf("other group: %v %+v", err, r3)
	}
}

func TestAnonVoteCaps(t *testing.T) {
	e := newExtEnv(t)
	ctx := context.Background()
	voter := nextIP()
	super := core.IPSuper(voter)
	for i := 0; i < anonVotePerGroup; i++ {
		id, _ := e.mkAnon(t)
		if _, err := AnonVote(ctx, e.d, id, true, voter, super, ""); err != nil {
			t.Fatalf("vote %d: %v", i+1, err)
		}
	}
	// The 11th confirmation from the same group in a day is refused.
	id, _ := e.mkAnon(t)
	if _, err := AnonVote(ctx, e.d, id, true, voter, super, ""); !errors.Is(err, core.ErrQuota) {
		t.Fatalf("over-cap vote: %v, want ErrQuota", err)
	}
}

func TestAnonVotesNeverPromoteOrHide(t *testing.T) {
	e := newExtEnv(t)
	ctx := context.Background()
	id, _ := e.mkAnon(t)

	for i := 0; i < 5; i++ {
		g := nextIP()
		if _, err := AnonVote(ctx, e.d, id, true, g, core.IPSuper(g), ""); err != nil {
			t.Fatalf("anon ok %d: %v", i, err)
		}
	}
	for i := 0; i < 5; i++ {
		g := nextIP()
		if _, err := AnonVote(ctx, e.d, id, false, g, core.IPSuper(g), "no good"); err != nil {
			t.Fatalf("anon bad %d: %v", i, err)
		}
	}
	var quar, hidden bool
	var okW, badW float32
	var anonOK, anonBad int
	if err := testPool.QueryRow(ctx, `SELECT quarantine, hidden, ok_w, bad_w, anon_ok, anon_bad FROM kb WHERE id = $1`, id).
		Scan(&quar, &hidden, &okW, &badW, &anonOK, &anonBad); err != nil {
		t.Fatal(err)
	}
	if !quar || hidden {
		t.Fatalf("quarantine=%v hidden=%v, want still quarantined and not hidden", quar, hidden)
	}
	if okW != 0 || badW != 0 {
		t.Fatalf("ok_w=%v bad_w=%v, anon votes must never touch the real weights", okW, badW)
	}
	if anonOK != 5 || anonBad != 5 {
		t.Fatalf("anon_ok=%d anon_bad=%d, want 5/5", anonOK, anonBad)
	}
}

func TestAnonFailsLine(t *testing.T) {
	e := newExtEnv(t)
	ctx := context.Background()
	id, _ := e.mkAnon(t)

	const n = anonFailsCap + 1
	for i := 0; i < n; i++ {
		g := nextIP()
		if _, err := AnonVote(ctx, e.d, id, false, g, core.IPSuper(g), uniq("fails because")); err != nil {
			t.Fatalf("anon bad %d: %v", i, err)
		}
	}
	fails, err := AnonFails(ctx, testPool, id, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(fails) != anonFailsCap {
		t.Fatalf("fails hints = %d, want %d (capped)", len(fails), anonFailsCap)
	}
	for _, f := range fails {
		if f[:7] != "fails: " || f[len(f)-7:] != " (anon)" {
			t.Fatalf("line %q not an anon-marked fails: line", f)
		}
	}
	// The counter matches the number of distinct groups that voted.
	var anonBad int
	if err := testPool.QueryRow(ctx, `SELECT anon_bad FROM kb WHERE id = $1`, id).Scan(&anonBad); err != nil {
		t.Fatal(err)
	}
	if anonBad != n {
		t.Fatalf("anon_bad = %d, want %d", anonBad, n)
	}
}
