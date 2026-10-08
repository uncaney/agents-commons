package gov

import (
	"context"
	"testing"
)

// TestScopeCounts is the SECURITY-REVIEW-2 #8 regression for the spaces.ProposalCountsFn source:
// positive terminal states count as passed, negative terminals as failed, in-flight states as
// neither, and hidden proposals are excluded.
func TestScopeCounts(t *testing.T) {
	if testPool == nil {
		t.Skip("no TEST_DATABASE_URL: skipping gov DB test")
	}
	ctx := context.Background()
	const scope = "sc-count"

	rows := []struct{ id, state string }{
		{"pscaaaa", "passed"}, {"pscaaab", "applied"}, {"pscaaac", "awaiting_operator"},
		{"pscaaad", "accepted"}, {"pscaaae", "shipped"}, // 5 passed
		{"pscaaaf", "failed"}, {"pscaaag", "declined"}, {"pscaaah", "vetoed"}, // 3 failed
		{"pscaaai", "open"}, {"pscaaaj", "contested"}, {"pscaaak", "deferred"}, // in flight
	}
	for _, r := range rows {
		if _, err := testPool.Exec(ctx, `INSERT INTO proposals (id, scope, kind, author, author_root, closes_at, state)
			VALUES ($1, $2, 'pin', 'aaaaaaa', 'aaaaaaa', now(), $3)
			ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, scope = EXCLUDED.scope, hidden = false`, r.id, scope, r.state); err != nil {
			t.Fatalf("seed %s: %v", r.id, err)
		}
	}
	// A hidden positive-terminal proposal must not be counted.
	if _, err := testPool.Exec(ctx, `INSERT INTO proposals (id, scope, kind, author, author_root, closes_at, state, hidden)
		VALUES ('pscaaaz', $1, 'pin', 'aaaaaaa', 'aaaaaaa', now(), 'applied', true)
		ON CONFLICT (id) DO UPDATE SET state = 'applied', hidden = true, scope = EXCLUDED.scope`, scope); err != nil {
		t.Fatalf("seed hidden: %v", err)
	}

	passed, failed, err := ScopeCounts(ctx, testPool, scope)
	if err != nil {
		t.Fatal(err)
	}
	if passed != 5 || failed != 3 {
		t.Fatalf("passed=%d failed=%d, want 5/3", passed, failed)
	}
}
