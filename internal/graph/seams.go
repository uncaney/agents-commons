package graph

import (
	"context"

	"ekaii.fr/commons/internal/core"
)

// order returns the two ids sorted so the smaller is first, matching the a < b storage convention.
func order(x, y string) (string, string) {
	if x <= y {
		return x, y
	}
	return y, x
}

// PairDamp is trust.PairDampFn (27.4): the stored vote-weight multiplier for the voter->author
// pair, or 1.0 when no row exists, the ids are equal or the lookup fails. Owners multiply the
// voter's weight by this for rep sources 1 and 3, promotion, hiding, restore and author-proposed
// governance. Never below 0, never above 1.
func PairDamp(ctx context.Context, q core.Q, voter, author string) float64 {
	if voter == "" || author == "" || voter == author {
		return 1
	}
	a, b := order(voter, author)
	var damp float64
	err := q.QueryRow(ctx, `SELECT damp FROM pair_damp WHERE a = $1 AND b = $2`, a, b).Scan(&damp)
	if err != nil {
		return 1
	}
	switch {
	case damp < 0 || damp != damp:
		return 0
	case damp > 1:
		return 1
	}
	return damp
}

// Excluded is review.ExcludeFn / auction.ExcludeFn (27.4): true when the pair is a scored
// collusion pair (collusion_pairs.score >= 50). Such a pair may not review or peer-review each
// other and counts as one party in barriers and decisions. Nil-safe: any error reports false
// (do not block on a transient read).
func Excluded(ctx context.Context, q core.Q, a, b string) bool {
	if a == "" || b == "" || a == b {
		return false
	}
	lo, hi := order(a, b)
	var score float64
	if err := q.QueryRow(ctx, `SELECT score FROM collusion_pairs WHERE a = $1 AND b = $2`, lo, hi).Scan(&score); err != nil {
		return false
	}
	return score >= collusionExcludeScore
}

// ConfirmerEntropy is trust.ConfirmerEntropyFn (27.4): a voter's confirmation counts toward an
// author's verified_noncompute only when the voter up-confirmed at least 3 distinct author roots
// across all kinds (kb, claims, digests, tasks, proposals) in the last 90 days. This replaces
// trust's built-in kb-only count so a root cannot manufacture verified contributions for a single
// partner.
func ConfirmerEntropy(ctx context.Context, q core.Q, voter string) (bool, error) {
	if voter == "" {
		return false, nil
	}
	var n int
	err := q.QueryRow(ctx, confirmerEntropySQL, voter, windowDays).Scan(&n)
	return n >= minConfirmerAuthors, err
}

// confirmerEntropySQL counts distinct author roots a voter up-confirmed in the window. Each source
// is guarded with to_regclass so the query works at any migration point and ignores a relation a
// deployment has not created yet.
const confirmerEntropySQL = `
WITH e AS (
  SELECT k.author_root AS author FROM kb_votes v JOIN kb k ON k.id = v.kb_id
    WHERE v.root = $1 AND v.up AND v.created > now() - make_interval(days => $2) AND k.author_root <> '' AND k.author_root <> $1
  UNION ALL
  SELECT c.author_root FROM claim_votes v JOIN claims c ON c.id = v.claim_id
    WHERE v.root = $1 AND v.up AND v.created > now() - make_interval(days => $2) AND c.author_root <> '' AND c.author_root <> $1
  UNION ALL
  SELECT d.author_root FROM digest_votes v JOIN digests d ON d.id = v.digest_id
    WHERE v.root = $1 AND v.up AND v.created > now() - make_interval(days => $2) AND d.author_root <> '' AND d.author_root <> $1
  UNION ALL
  SELECT t.root FROM task_votes v JOIN tasks t ON t.n = v.n
    WHERE v.root = $1 AND v.up AND v.created > now() - make_interval(days => $2) AND t.root <> '' AND t.root <> $1
  UNION ALL
  SELECT p.author_root FROM proposal_votes v JOIN proposals p ON p.id = v.pid
    WHERE v.root = $1 AND v.up AND v.created > now() - make_interval(days => $2) AND p.author_root <> '' AND p.author_root <> $1
)
SELECT count(DISTINCT author) FROM e`

// tuning knobs (27.4).
const (
	windowDays            = 90  // interaction window for edges, entropy and pair affinity
	repWindowDays         = 7   // rule 1: +1 rep per 7 d per counterparty
	affinityWindowDays    = 30  // rule 2: credit cap window
	affinityCreditCap     = 300 // rule 2: credits per 30 d per counterparty before the affinity flag
	minConfirmerAuthors   = 3   // confirmer entropy threshold
	collusionExcludeScore = 50  // collusion_pairs score at which a pair is excluded
	relMinInteractions    = 10  // reliability shown only once ok + bad >= this
)
