package spaces

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// TestStewardConsecutiveTermLimit is the SECURITY-REVIEW-2 #9 regression: SetSteward must refuse a
// grant once a root has served MaxTerms consecutive terms (no intervening recall), and a recall
// must reset the streak.
func TestStewardConsecutiveTermLimit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	slug, _, _ := mkSpace(t, e, nil)
	m := addMemberSQL(t, slug, rootOpts{rep: 1, age: 48 * time.Hour}, time.Hour)

	grant := func() error {
		return core.Tx(ctx, pool, func(tx pgx.Tx) error { return SetSteward(ctx, tx, slug, m, true, 30, "p1aaaa") })
	}
	recall := func() error {
		return core.Tx(ctx, pool, func(tx pgx.Tx) error { return SetSteward(ctx, tx, slug, m, false, 0, "p2aaaa") })
	}

	if err := grant(); err != nil {
		t.Fatalf("term 1: %v", err)
	}
	if err := grant(); err != nil {
		t.Fatalf("term 2: %v", err)
	}
	if err := grant(); err == nil || !strings.Contains(err.Error(), "consecutive terms") {
		t.Fatalf("term 3 must hit the %d-term limit, got %v", MaxTerms, err)
	}
	// A recall breaks the streak, so the root can be elected again.
	if err := recall(); err != nil {
		t.Fatalf("recall: %v", err)
	}
	if err := grant(); err != nil {
		t.Fatalf("term after recall should be allowed: %v", err)
	}
}

// TestPlatformImmutableDocStewardPinsOpen is the SECURITY-REVIEW-2 #3 regression: the platform
// roadmap space is non-amendable through the governance doc path (ApplyDoc refuses slug=="platform",
// defense-in-depth), while the system-root StewardPins -> SetPins route it must NOT break stays open.
func TestPlatformImmutableDocStewardPinsOpen(t *testing.T) {
	newEnv(t)
	ctx := context.Background()

	err := core.Tx(ctx, pool, func(tx pgx.Tx) error {
		_, _, e := ApplyDoc(ctx, tx, "platform", "home", "# hijacked roadmap", "pzzzzzz")
		return e
	})
	if err == nil || !strings.Contains(err.Error(), "not amendable") {
		t.Fatalf("platform ApplyDoc must be refused, got %v", err)
	}

	// StewardPins is the documented system-root pin route on the platform roadmap: still works.
	if _, err := StewardPins(ctx, pool, "platform", core.SystemID, []string{}); err != nil {
		t.Fatalf("system-root StewardPins on platform must still work: %v", err)
	}
}

// TestInfoForGov is the SECURITY-REVIEW-2 #8 regression for the gov.SpaceInfoFn adapter source: it
// resolves existence, membership, ban/freeze state and the rules.vote thresholds the engine clamps.
func TestInfoForGov(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	slug, creator, _ := mkSpace(t, e, map[string]any{"vote": map[string]any{"window_h": 72, "threshold": 60, "min_member_h": 48}})
	m := addMemberSQL(t, slug, rootOpts{rep: 1, age: 48 * time.Hour}, 2*time.Hour)

	gi, err := InfoForGov(ctx, pool, slug, m)
	if err != nil {
		t.Fatal(err)
	}
	if !gi.Exists || !gi.Member || gi.Banned || gi.Frozen {
		t.Fatalf("member info %+v", gi)
	}
	if gi.VoteWindowH != 72 || gi.VoteThreshold != 60 || gi.MinMemberH != 48 {
		t.Fatalf("thresholds not surfaced: %+v", gi)
	}
	if gi.Creator != creator {
		t.Fatalf("creator = %q want %q", gi.Creator, creator)
	}

	nm, _ := mkRoot(t, rootOpts{})
	if gi2, err := InfoForGov(ctx, pool, slug, nm); err != nil || !gi2.Exists || gi2.Member {
		t.Fatalf("non-member: %+v err %v", gi2, err)
	}

	exec(t, `INSERT INTO space_bans (space, root, until) VALUES ($1, $2, now() + interval '1 day')`, slug, m)
	if gi3, _ := InfoForGov(ctx, pool, slug, m); !gi3.Banned {
		t.Fatalf("ban not reflected: %+v", gi3)
	}

	exec(t, `UPDATE spaces SET frozen = true WHERE slug = $1`, slug)
	if gi4, _ := InfoForGov(ctx, pool, slug, m); !gi4.Frozen {
		t.Fatalf("freeze not reflected: %+v", gi4)
	}

	if gi5, err := InfoForGov(ctx, pool, "nosuchspace", core.SystemID); err != nil || gi5.Exists {
		t.Fatalf("unknown space must be Exists=false with no error: %+v err %v", gi5, err)
	}
}
