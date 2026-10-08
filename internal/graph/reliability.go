package graph

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
)

// relKinds is the closed set of reliability kinds (27.4), matching the rel_counters CHECK.
var relKinds = map[string]bool{
	"claim": true, "lock": true, "sem": true, "wq": true,
	"barrier": true, "review": true, "bounty": true, "grp": true,
}

// claimOK applies the claim reliability rule (27.4): a claim dropped or finished before 80 % of its
// TTL counts ok; running past that (toward expiry) counts bad. ttl <= 0 is treated as ok.
func claimOK(ttl, held time.Duration) bool {
	if ttl <= 0 {
		return true
	}
	return held < (ttl*4)/5
}

// Reliability is the daily janitor (27.4): it derives rel_counters from the owning tables (review
// slots and bounties, self-owned objects excluded) and folds the uniform `rel` reliability events
// of the other kinds. Display only -- it never touches rep, caps or ranking. Rebuilding the
// table-derived kinds from scratch each run keeps the pass idempotent; the event fold advances a
// high-water seq.
func Reliability(ctx context.Context, db *pgxpool.Pool) error {
	if err := rebuildReviewRel(ctx, db); err != nil {
		return err
	}
	if err := rebuildBountyRel(ctx, db); err != nil {
		return err
	}
	return foldRelEvents(ctx, db)
}

// rebuildReviewRel rebuilds the review kind: an answered slot is ok, an expired lease (review_excl
// why='expired') is bad, keyed on the worker root and the event month. A worker reviewing their own
// request is self-owned and excluded.
func rebuildReviewRel(ctx context.Context, db *pgxpool.Pool) error {
	return core.Tx(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM rel_counters WHERE kind = 'review'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO rel_counters (root, month, kind, ok, bad)
			SELECT s.worker_root, to_char(s.answered_at, 'YYYY-MM'), 'review', count(*)::int, 0
			FROM review_slots s JOIN reviews r ON r.id = s.review
			WHERE s.answered_at IS NOT NULL AND s.worker_root <> '' AND s.worker_root <> r.req_root
			GROUP BY s.worker_root, to_char(s.answered_at, 'YYYY-MM')
			ON CONFLICT (root, month, kind) DO UPDATE SET ok = rel_counters.ok + excluded.ok`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO rel_counters (root, month, kind, ok, bad)
			SELECT x.root, to_char(x.at, 'YYYY-MM'), 'review', 0, count(*)::int
			FROM review_excl x JOIN reviews r ON r.id = x.review
			WHERE x.why = 'expired' AND x.root <> '' AND x.root <> r.req_root
			GROUP BY x.root, to_char(x.at, 'YYYY-MM')
			ON CONFLICT (root, month, kind) DO UPDATE SET bad = rel_counters.bad + excluded.bad`)
		return err
	})
}

// rebuildBountyRel rebuilds the bounty kind: a submission on or before the deadline is ok, a
// hunter awarded (auction) but never submitting is bad, keyed on the hunter root and month. A
// hunter on their own bounty is self-owned and excluded.
func rebuildBountyRel(ctx context.Context, db *pgxpool.Pool) error {
	return core.Tx(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM rel_counters WHERE kind = 'bounty'`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO rel_counters (root, month, kind, ok, bad)
			SELECT hunter_root,
			       to_char(coalesce(submitted_at, deadline), 'YYYY-MM'), 'bounty',
			       count(*) FILTER (WHERE submitted_at IS NOT NULL AND submitted_at <= deadline)::int,
			       count(*) FILTER (WHERE submitted_at IS NULL AND deadline < now())::int
			FROM bounties
			WHERE hunter_root <> '' AND hunter_root <> creator_root
			GROUP BY hunter_root, to_char(coalesce(submitted_at, deadline), 'YYYY-MM')
			ON CONFLICT (root, month, kind) DO UPDATE
			  SET ok = rel_counters.ok + excluded.ok, bad = rel_counters.bad + excluded.bad`)
		return err
	})
}

// foldRelEvents folds the uniform reliability events into rel_counters: an event of kind 'rel' with
// ref '<kind>:<root>' and title 'ok' or 'bad' adds one to that root's month/kind tally. The owning
// packages (claim, lock, sem, wq, barrier, grp) emit these for outcomes they alone can classify,
// excluding self-owned objects. A high-water seq makes the fold idempotent.
func foldRelEvents(ctx context.Context, db *pgxpool.Pool) error {
	return core.Tx(ctx, db, func(tx pgx.Tx) error {
		var last int64
		tx.QueryRow(ctx, `SELECT v FROM graph_state WHERE k = 'rel_event_seq'`).Scan(&last)
		rows, err := tx.Query(ctx, `SELECT seq, ref, title, to_char(at, 'YYYY-MM') FROM events
			WHERE kind = 'rel' AND seq > $1 ORDER BY seq`, last)
		if err != nil {
			return err
		}
		type row struct {
			seq        int64
			kind, root string
			ok         bool
			month      string
		}
		var batch []row
		var maxSeq int64
		for rows.Next() {
			var seq int64
			var ref, title, month string
			if err := rows.Scan(&seq, &ref, &title, &month); err != nil {
				rows.Close()
				return err
			}
			maxSeq = seq
			kind, root, found := strings.Cut(ref, ":")
			if !found || !relKinds[kind] || root == "" {
				continue
			}
			batch = append(batch, row{seq, kind, root, title == "ok", month})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range batch {
			ok, bad := 0, 0
			if r.ok {
				ok = 1
			} else {
				bad = 1
			}
			if _, err := tx.Exec(ctx, `INSERT INTO rel_counters (root, month, kind, ok, bad)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (root, month, kind) DO UPDATE
				  SET ok = rel_counters.ok + excluded.ok, bad = rel_counters.bad + excluded.bad`,
				r.root, r.month, r.kind, ok, bad); err != nil {
				return err
			}
		}
		if maxSeq > last {
			if _, err := tx.Exec(ctx, `INSERT INTO graph_state (k, v) VALUES ('rel_event_seq', $1)
				ON CONFLICT (k) DO UPDATE SET v = excluded.v`, maxSeq); err != nil {
				return err
			}
		}
		return nil
	})
}
