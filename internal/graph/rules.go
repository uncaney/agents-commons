package graph

import (
	"context"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
)

// itoa64 renders a signed 64-bit int in base 10.
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// clawbackRep enforces rule 1 (27.4): a root may keep at most +1 reputation per 7 days from the
// same counterparty root or super-group across all confirmation kinds. The janitor counts the
// window's confirmations per (beneficiary, counterparty key) -- each nominally worth +1 -- and
// claws back the excess with core.AddRep(..., "rep:pairdup", ...). The pass is idempotent: it
// subtracts what it has already clawed from the beneficiary in the window, so repeated nightly
// runs converge rather than drain a root. Negatives are never dampened (only positive excess is
// removed).
func clawbackRep(ctx context.Context, db *pgxpool.Pool) error {
	rows, err := db.Query(ctx, `
		SELECT e.author AS b,
		       coalesce(nullif(graph_super(ic.reg_ip), ''), e.voter) AS kkey,
		       count(*)::int AS n
		FROM (`+confirmSources+`) e
		JOIN identities ic ON ic.id = e.voter
		GROUP BY e.author, kkey`, repWindowDays)
	if err != nil {
		return err
	}
	desired := map[string]int{}
	for rows.Next() {
		var b, k string
		var n int
		if err := rows.Scan(&b, &k, &n); err != nil {
			rows.Close()
			return err
		}
		if n > 1 {
			desired[b] += n - 1
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for b, want := range desired {
		var already int
		if err := db.QueryRow(ctx, `SELECT coalesce(-sum(delta), 0) FROM rep_log
			WHERE root = $1 AND kind = 'rep:pairdup' AND at > now() - make_interval(days => $2)`,
			b, repWindowDays).Scan(&already); err != nil {
			return err
		}
		if apply := want - already; apply > 0 {
			if err := core.Tx(ctx, db, func(tx pgx.Tx) error {
				_, e := core.AddRep(ctx, tx, b, -apply, "rep:pairdup", 0)
				return e
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// flagAffinity enforces rule 2 (27.4): beyond 300 credits in 30 days from one counterparty, the
// earned-ledger rows that carry the excess are flagged 'affinity' (ledger_flags), excluded from
// verified_contrib, and rendered as the `(p2p <n>)` share. Idempotent: ledger_flags has the row id
// as its primary key, and verified_contrib is only decremented for rows newly flagged this run.
func flagAffinity(ctx context.Context, db *pgxpool.Pool) error {
	return core.Tx(ctx, db, func(tx pgx.Tx) error {
		// Running total per (recipient, payer) ordered by ledger id; rows past the cap are excess.
		rows, err := tx.Query(ctx, `
			WITH earned AS (
				SELECT id, to_id AS recipient, from_id AS payer, amount,
				       sum(amount) OVER (PARTITION BY to_id, from_id ORDER BY id) AS running
				FROM ledger
				WHERE class = 'earned' AND ts > now() - make_interval(days => $1)
				  AND from_id <> 'mint' AND to_id <> from_id
			)
			SELECT id, recipient FROM earned WHERE running > $2 ORDER BY id`,
			affinityWindowDays, affinityCreditCap)
		if err != nil {
			return err
		}
		var ids []int64
		recip := map[int64]string{}
		for rows.Next() {
			var id int64
			var r string
			if err := rows.Scan(&id, &r); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
			recip[id] = r
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			tag, err := tx.Exec(ctx, `INSERT INTO ledger_flags (ledger_id, flag) VALUES ($1, 'affinity')
				ON CONFLICT (ledger_id) DO NOTHING`, id)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 { // newly flagged: trim one verified contribution, logged.
				if _, err := tx.Exec(ctx, `UPDATE identities SET verified_contrib = greatest(0, verified_contrib - 1)
					WHERE id = $1 AND parent IS NULL`, recip[id]); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO rep_log (root, delta, kind, ref)
					VALUES ($1, 0, 'vc:affinity', $2)`, recip[id], "ledger:"+itoa64(id)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
