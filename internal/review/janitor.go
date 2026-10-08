package review

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
)

// expireLeases requeues leases past lease_until (16.3): the root is excluded from that review, the
// bond is forfeited, rep -1 (cap 5/day); waiting reviewers are woken.
func (s *svc) expireLeases(ctx context.Context, pool *pgxpool.Pool) error {
	type row struct {
		review, worker, root string
		slot                 int
		bond                 int64
	}
	rows, err := pool.Query(ctx, `SELECT review, slot, worker, worker_root, bond FROM review_slots WHERE state = 'leased' AND lease_until < now() LIMIT 200`)
	if err != nil {
		return err
	}
	var exp []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.review, &x.slot, &x.worker, &x.root, &x.bond); err != nil {
			rows.Close()
			return err
		}
		exp = append(exp, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range exp {
		err := core.Tx(ctx, pool, func(tx pgx.Tx) error {
			if err := requeue(ctx, tx, x.review, x.slot, x.root, x.bond, "expired", true); err != nil {
				return err
			}
			if err := repDown(ctx, tx, x.root, "rep:review-forfeit", RepForfeitCap); err != nil {
				return err
			}
			return core.Event(ctx, tx, "review", x.review, x.root, "review lease forfeited")
		})
		if err != nil {
			return err
		}
	}
	if len(exp) > 0 {
		s.wake("pr")
	}
	return nil
}

// deadlines settles reviews past their deadline (16.3): unfilled slots are refunded, the unused
// escalation reserve returned, answers unsealed, the bounty callback told; the review stays open
// for leases still running and closes once every slot is settled.
func (s *svc) deadlines(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `SELECT id FROM reviews r WHERE state <> 'closed' AND deadline < now()
		AND (unsealed_at IS NULL OR reserve > 0 OR EXISTS (SELECT 1 FROM review_slots s WHERE s.review = r.id AND s.state = 'queued')) LIMIT 200`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		var refunded int
		var reqRoot string
		err := core.Tx(ctx, pool, func(tx pgx.Tx) error {
			r, err := load(ctx, tx, id, true)
			if err != nil {
				return err
			}
			if time.Now().Before(r.Deadline) {
				return nil
			}
			reqRoot = r.ReqRoot
			for i := range r.Slots {
				if r.Slots[i].State != "queued" {
					continue
				}
				done, err := refundSlot(ctx, tx, r, &r.Slots[i], []string{"queued"}, "")
				if err != nil {
					return err
				}
				if done {
					refunded++
				}
			}
			if err := releaseReserve(ctx, tx, r); err != nil {
				return err
			}
			if r.UnsealedAt == nil {
				if _, err := tx.Exec(ctx, `UPDATE reviews SET unsealed_at = now(), split = $2 WHERE id = $1`, r.ID, isSplit(r)); err != nil {
					return err
				}
				if r.Debate && r.N == 2 && r.answeredSlots() == len(r.Slots) {
					if _, err := tx.Exec(ctx, `UPDATE review_slots SET rebut_until = now() + $2::interval WHERE review = $1 AND round = 1`,
						r.ID, RebutWindow.String()); err != nil {
						return err
					}
				}
				if r.Task != nil && OnTaskDecidedFn != nil {
					if err := OnTaskDecidedFn(ctx, tx, *r.Task, taskVerdict(r)); err != nil {
						return err
					}
				}
			}
			if r.answeredSlots() > 0 {
				if _, err := tx.Exec(ctx, `UPDATE reviews SET state = 'answered' WHERE id = $1 AND state = 'open'`, r.ID); err != nil {
					return err
				}
			}
			return closeIfDone(ctx, tx, r.ID)
		})
		if err != nil {
			return err
		}
		s.wake("pr:" + id)
		if refunded > 0 {
			s.notify(ctx, reqRoot, sfmt("review %s deadline: %d unfilled slots refunded", id, refunded), "GET /v1/pr/"+id)
		}
	}
	return nil
}

// defaultPay settles answered slots past pay_due (16.3, 27.4): paid when the requester tree has seen
// the answers (bounty reviews count as seen), refunded to the requester when still unseen 72 h later.
func (s *svc) defaultPay(ctx context.Context, pool *pgxpool.Pool) error {
	type row struct {
		review string
		slot   int
	}
	rows, err := pool.Query(ctx, `SELECT review, slot FROM review_slots WHERE state = 'answered' AND pay_due < now() LIMIT 200`)
	if err != nil {
		return err
	}
	var due []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.review, &x.slot); err != nil {
			rows.Close()
			return err
		}
		due = append(due, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range due {
		var refundedTo string
		err := core.Tx(ctx, pool, func(tx pgx.Tx) error {
			r, err := load(ctx, tx, x.review, true)
			if err != nil {
				return err
			}
			var sl *Slot
			for i := range r.Slots {
				if r.Slots[i].Slot == x.slot {
					sl = &r.Slots[i]
				}
			}
			now := time.Now()
			if sl == nil || sl.State != "answered" || sl.PayDue == nil || now.Before(*sl.PayDue) {
				return nil
			}
			switch {
			case r.AnswersSeenAt != nil || r.Task != nil:
				if _, err := paySlot(ctx, tx, r, sl, ""); err != nil {
					return err
				}
			case now.After(sl.PayDue.Add(UnseenGrace)):
				done, err := refundSlot(ctx, tx, r, sl, []string{"answered"}, "")
				if err != nil {
					return err
				}
				if done {
					refundedTo = r.ReqRoot
				}
			default:
				return nil
			}
			return closeIfDone(ctx, tx, r.ID)
		})
		if err != nil {
			return err
		}
		if refundedTo != "" {
			s.notify(ctx, refundedTo, sfmt("review %s: unseen answer refunded", x.review), "GET /v1/pr/"+x.review)
		}
	}
	return nil
}
