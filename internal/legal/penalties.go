package legal

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// batchHours are the UTC hours at which penalties and statements of reasons are applied (8.3 D11):
// 00:00, 06:00, 12:00, 18:00 by default, overridable with E2E_BATCH_HOURS (a comma list of hours).
func batchHours() []int {
	v := strings.TrimSpace(os.Getenv("E2E_BATCH_HOURS"))
	if v == "" {
		return []int{0, 6, 12, 18}
	}
	var hs []int
	for _, p := range strings.Split(v, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n >= 0 && n < 24 {
			hs = append(hs, n)
		}
	}
	if len(hs) == 0 {
		return []int{0, 6, 12, 18}
	}
	sort.Ints(hs)
	return hs
}

// latestTick returns the most recent batch boundary at or before now (UTC).
func latestTick(now time.Time) time.Time {
	now = now.UTC()
	hs := batchHours()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	best := time.Time{}
	for _, h := range hs {
		t := day.Add(time.Duration(h) * time.Hour)
		if !t.After(now) && t.After(best) {
			best = t
		}
	}
	if best.IsZero() {
		// Before the first boundary of the day: use the last boundary of yesterday.
		prev := day.AddDate(0, 0, -1)
		best = prev.Add(time.Duration(hs[len(hs)-1]) * time.Hour)
	}
	return best
}

// tick applies every pending penalty created at or before the latest batch boundary exactly once:
// it freezes the sender (identities' frozen_until via x_frozen, so xmail refuses sends), takes the
// reputation hit, and delivers the generic statement of reasons to the sender's inbox with no
// message reference (D11). Idempotent per boundary via the batch_ticks primary key.
func (s *svc) tick(ctx context.Context, now time.Time) error {
	boundary := latestTick(now)
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('e2e-batch-tick'))`); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO batch_ticks (tick) VALUES ($1) ON CONFLICT DO NOTHING`, boundary)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil // this boundary was already processed
		}
		rows, err := tx.Query(ctx, `SELECT id, from_root, until, rep_delta FROM x_penalties
			WHERE applied_at IS NULL AND created <= $1 ORDER BY id`, boundary)
		if err != nil {
			return err
		}
		type pen struct {
			id       int64
			root     string
			until    time.Time
			repDelta int
		}
		var pens []pen
		for rows.Next() {
			var p pen
			if err := rows.Scan(&p.id, &p.root, &p.until, &p.repDelta); err != nil {
				rows.Close()
				return err
			}
			pens = append(pens, p)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		statements := 0
		for _, p := range pens {
			if err := freeze(ctx, tx, p.root, p.until); err != nil {
				return err
			}
			if _, err := core.AddRep(ctx, tx, p.root, p.repDelta, "", 0); err != nil {
				return err
			}
			if err := core.SysMail(ctx, tx, p.root, "mail-frozen", statement(p.until)); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE x_penalties SET applied_at = now() WHERE id = $1`, p.id); err != nil {
				return err
			}
			statements++
		}
		_, err = tx.Exec(ctx, `UPDATE batch_ticks SET penalties = $2, statements = $2 WHERE tick = $1`, boundary, statements)
		return err
	})
}

// statement is the DSA art. 17 generic statement of reasons (8.3 D11): no message reference, time or
// recipient, only the action, the end date, the basis and the appeal route.
func statement(until time.Time) string {
	return "sys action=mail-frozen until=" + until.UTC().Format("2006-01-02") + " basis=reports appeal=/legal#appeal"
}
