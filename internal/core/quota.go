package core

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Limit scales a base daily quota: established roots (rep >= 5 and 72 h old, or seed) get x5.
func Limit(id *Ident, base int) int {
	if id.Established() {
		return base * 5
	}
	return base
}

// UseQuota consumes one unit of the root's daily counter for kind; ErrQuota when over Limit(id, base).
func UseQuota(ctx context.Context, q Q, id *Ident, kind string, base int) error {
	n, err := bump(ctx, q, id.Root, kind, 1)
	if err != nil {
		return err
	}
	if n > Limit(id, base) {
		return ErrQuota
	}
	return nil
}

// UseIPQuota is the anonymous variant keyed by IP group (pass d.IPGroup(r); e.g. reports 20/day).
func UseIPQuota(ctx context.Context, q Q, ip, kind string, limit int) error {
	n, err := bump(ctx, q, "ip:"+IPGroup(ip), kind, 1)
	if err != nil {
		return err
	}
	if n > limit {
		return ErrQuota
	}
	return nil
}

// bump adds delta to today's counter and returns the new value.
func bump(ctx context.Context, q Q, scope, kind string, delta int) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`,
		scope, kind, delta).Scan(&n)
	return n, err
}

// Credit classes (SPEC-v2 16.1): grant = credits - earned is never transferable; earned (compute
// payouts, bounties, reviews, catalog fees) is. Every movement writes a ledger row in the caller's
// transaction. Pseudo-ids: mint and burn are the only ways credits enter or leave; hold is where a
// reservation or escrow sits while its job, bounty or review is open.
const (
	LedgerMint = "mint"
	LedgerBurn = "burn"
	LedgerHold = "hold"
)

// ErrEarned: fewer transferable credits than asked (bounties, reviews, tips need earned).
var ErrEarned = E(402, "credits", "insufficient earned credits")

// Reserve debits n credits from identity id for its own jobs, subkeys and catalog calls: grant
// first, then earned (the class split is recorded). ErrCredits if insufficient.
func Reserve(ctx context.Context, q Q, id string, n int64) error {
	if n < 0 {
		return Bad("negative credits")
	}
	if n == 0 {
		return nil
	}
	var fromEarned int64
	err := q.QueryRow(ctx, `WITH old AS (SELECT id, earned FROM identities WHERE id = $1 AND credits >= $2 FOR UPDATE),
		u AS (UPDATE identities i SET credits = i.credits - $2, earned = LEAST(i.earned, i.credits - $2)
		      FROM old WHERE i.id = old.id RETURNING old.earned - i.earned)
		SELECT * FROM u`, id, n).Scan(&fromEarned)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCredits
	}
	if err != nil {
		return err
	}
	if g := n - fromEarned; g > 0 {
		if err := Ledger(ctx, q, id, LedgerHold, "grant", g, "reserve", ""); err != nil {
			return err
		}
	}
	if fromEarned > 0 {
		return Ledger(ctx, q, id, LedgerHold, "earned", fromEarned, "reserve", "")
	}
	return nil
}

// ReserveEarned debits n transferable credits (bounty, review and proposal escrows, tips);
// ErrEarned when the identity holds fewer.
func ReserveEarned(ctx context.Context, q Q, id string, n int64) error {
	if n < 0 {
		return Bad("negative credits")
	}
	if n == 0 {
		return nil
	}
	tag, err := q.Exec(ctx, `UPDATE identities SET credits = credits - $2, earned = earned - $2 WHERE id = $1 AND earned >= $2`, id, n)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrEarned
	}
	return Ledger(ctx, q, id, LedgerHold, "earned", n, "reserve", "")
}

// Earn pays n held credits to identity id as earned (compute payouts, bounty and review payments).
func Earn(ctx context.Context, q Q, id string, n int64) error {
	return credit(ctx, q, id, n, "earned", "earn")
}

// Refund returns n held credits to identity id as grant (the class Reserve takes first).
func Refund(ctx context.Context, q Q, id string, n int64) error {
	return credit(ctx, q, id, n, "grant", "refund")
}

// RefundEarned returns n held credits ReserveEarned took, keeping them transferable.
func RefundEarned(ctx context.Context, q Q, id string, n int64) error {
	return credit(ctx, q, id, n, "earned", "refund")
}

// credit moves n credits from hold to a live identity. A revoked or unknown payee cannot receive
// them, so they leave the system through a burn row and the conservation audit stays exact.
func credit(ctx context.Context, q Q, id string, n int64, class, reason string) error {
	if n <= 0 {
		return nil
	}
	sql := `UPDATE identities SET credits = credits + $2 WHERE id = $1 AND revoked_at IS NULL`
	if class == "earned" {
		sql = `UPDATE identities SET credits = credits + $2, earned = earned + $2 WHERE id = $1 AND revoked_at IS NULL`
	}
	tag, err := q.Exec(ctx, sql, id, n)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return Ledger(ctx, q, LedgerHold, LedgerBurn, class, n, "unpayable", id)
	}
	return Ledger(ctx, q, LedgerHold, id, class, n, reason, "")
}

// BurnHeld records n held credits that are neither paid out nor refunded (a compute charge
// remainder, a forfeited bond) so the audit stays exact; ref names the job or bond.
func BurnHeld(ctx context.Context, q Q, n int64, reason, ref string) error {
	if n <= 0 {
		return nil
	}
	return Ledger(ctx, q, LedgerHold, LedgerBurn, "grant", n, reason, ref)
}

// AddRep changes a root's reputation. Positive deltas are subject to a daily cap: at most `cap`
// points per day under counter `capKind` (e.g. "rep:work" cap 20, "rep:kbok:<voterRoot>" cap 1).
// Negative deltas always apply. Every applied change is logged through RepLogger (4.2) when set.
// Returns the delta actually applied.
func AddRep(ctx context.Context, q Q, root string, delta int, capKind string, cap int) (int, error) {
	if delta > 0 && cap > 0 {
		n, err := bump(ctx, q, root, capKind, delta)
		if err != nil {
			return 0, err
		}
		if over := n - cap; over > 0 {
			delta -= over
			if delta <= 0 {
				return 0, nil
			}
		}
	}
	if delta == 0 {
		return 0, nil
	}
	tag, err := q.Exec(ctx, `UPDATE identities SET rep = rep + $2 WHERE id = $1 AND parent IS NULL`, root, delta)
	if err != nil || tag.RowsAffected() == 0 {
		return delta, err
	}
	kind := capKind
	if kind == "" {
		kind = "rep"
	}
	return delta, repLog(ctx, q, root, delta, kind, "")
}

// Rep returns a root's current reputation.
func Rep(ctx context.Context, q Q, root string) (int, error) {
	var r int
	err := q.QueryRow(ctx, `SELECT rep FROM identities WHERE id = $1`, root).Scan(&r)
	return r, err
}

// VoteWeight per SPEC: 1 + min(rep,20)/10.
func VoteWeight(rep int) float64 {
	if rep < 0 {
		rep = 0
	}
	if rep > 20 {
		rep = 20
	}
	return 1 + float64(rep)/10
}
