package review

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// answerIn is POST /v1/pr/{id}/answer / op ra.
type answerIn struct {
	Lease   string          `json:"lease"`
	Text    string          `json:"text"`
	Verdict string          `json:"verdict"`
	Conf    int             `json:"conf"`
	Hunks   json.RawMessage `json:"hunks"`
}

func (in *answerIn) validate() error {
	in.Lease = strings.TrimSpace(in.Lease)
	in.Verdict = strings.ToLower(strings.TrimSpace(in.Verdict))
	in.Text = strings.TrimRight(scrub.Normalize(in.Text), "\n")
	switch {
	case in.Lease == "":
		return core.Bad("lease required")
	case strings.TrimSpace(in.Text) == "":
		return core.Bad("text required")
	case len(in.Text) > MaxText:
		return core.E(413, "size", sfmt("text must be <= %d bytes", MaxText))
	case !verdicts[in.Verdict]:
		return core.Bad("verdict must be agree|disagree|unsure|lgtm|changes|reject")
	case in.Conf < 0 || in.Conf > 100:
		return core.Bad("conf must be 0..100")
	}
	if len(in.Hunks) > 0 && string(in.Hunks) != "null" {
		if len(in.Hunks) > MaxHunkJSON {
			return core.E(413, "size", "hunks too large")
		}
		var arr []json.RawMessage
		if err := json.Unmarshal(in.Hunks, &arr); err != nil {
			return core.Bad("hunks must be a JSON array")
		}
		if len(arr) > MaxHunks {
			return core.Bad(sfmt("hunks must have <= %d entries", MaxHunks))
		}
	} else {
		in.Hunks = nil
	}
	return nil
}

// answerOut is the reply of ra: `ok r… slot=<k> answered <a>/<n> pay_due=<date> held`.
type answerOut struct {
	ID          string
	Slot, A, N  int
	PayDue      time.Time
	Masked      []string
	reqRoot     string
	unsealedNow bool
}

func (o *answerOut) Line() string {
	s := sfmt("ok %s slot=%d answered %d/%d pay_due=%s held", o.ID, o.Slot, o.A, o.N, stamp(o.PayDue))
	if len(o.Masked) > 0 {
		s += " masked=" + strings.Join(o.Masked, ",")
	}
	return s
}

// answer posts an opinion on a leased slot (16.3): the bond comes back, payment is held until the
// requester rates it or pay_due = deadline + 24 h; the all-answered transition unseals the review.
func (s *svc) answer(ctx context.Context, id *core.Ident, rid string, in *answerIn) (*answerOut, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	masked, aerr := scrub.RejectOrMask(map[string]*string{"text": &in.Text})
	if aerr != nil {
		return nil, aerr
	}
	out := &answerOut{ID: rid, Masked: masked}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		r, err := load(ctx, tx, rid, true)
		if err != nil {
			return err
		}
		sl := slotByLease(r, in.Lease)
		switch {
		case sl == nil:
			return errLease
		case sl.WorkerRoot != id.Root:
			return errNotWorker
		case sl.State != "leased" || sl.LeaseUntil == nil || time.Now().After(*sl.LeaseUntil):
			return errLease
		}
		payDue := r.Deadline.Add(PayHold)
		var hunks any
		if in.Hunks != nil {
			hunks = in.Hunks
		}
		tag, err := tx.Exec(ctx, `UPDATE review_slots SET state = 'answered', text = $3, verdict = $4, conf = $5, hunks = $6,
			answered_at = now(), pay_due = $7, bond = 0 WHERE review = $1 AND slot = $2 AND state = 'leased'`,
			rid, sl.Slot, in.Text, in.Verdict, in.Conf, hunks, payDue)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errLease
		}
		if err := returnBond(ctx, tx, sl); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "ra", rid, sl.Slot); err != nil {
			return err
		}
		out.Slot, out.PayDue, out.reqRoot = sl.Slot, payDue, r.ReqRoot
		r, err = load(ctx, tx, rid, false)
		if err != nil {
			return err
		}
		out.A, out.N = r.answeredSlots(), len(r.Slots)
		out.unsealedNow, err = s.afterAnswer(ctx, tx, r)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.wake("pr:"+rid, "pr")
	if out.unsealedNow || out.N == 1 {
		s.notify(ctx, out.reqRoot, sfmt("review %s answered %d/%d", rid, out.A, out.N), "GET /v1/pr/"+rid)
	}
	return out, nil
}

// returnBond gives a leased slot's bond back in the classes it was taken from.
func returnBond(ctx context.Context, q core.Q, sl *Slot) error {
	if g := sl.Bond - sl.BondEarned; g > 0 {
		if err := core.Refund(ctx, q, sl.Worker, g); err != nil {
			return err
		}
	}
	if sl.BondEarned > 0 {
		return core.RefundEarned(ctx, q, sl.Worker, sl.BondEarned)
	}
	return nil
}

func slotByLease(r *Review, lease string) *Slot {
	for i := range r.Slots {
		if r.Slots[i].Lease != "" && r.Slots[i].Lease == lease {
			return &r.Slots[i]
		}
	}
	return nil
}

// afterAnswer runs the counters and the all-answered transition (16.3, 27.4): unseal, split
// detection, the round-2 slot or the reserve refund, the debate window, the bounty callback.
// Returns whether the review was unsealed by this call.
func (s *svc) afterAnswer(ctx context.Context, tx pgx.Tx, r *Review) (bool, error) {
	answered := r.answeredSlots()
	if _, err := tx.Exec(ctx, `UPDATE reviews SET answered = $2 WHERE id = $1`, r.ID, answered); err != nil {
		return false, err
	}
	if answered < len(r.Slots) {
		return false, nil
	}
	unsealed := false
	escalated := false
	if r.UnsealedAt == nil {
		unsealed = true
		split := isSplit(r)
		if _, err := tx.Exec(ctx, `UPDATE reviews SET unsealed_at = now(), split = $2 WHERE id = $1`, r.ID, split); err != nil {
			return false, err
		}
		switch {
		case r.Escalate && split && r.Round == 1:
			escalated = true
			if _, err := tx.Exec(ctx, `INSERT INTO review_slots (review, slot, round, pay) VALUES ($1, $2, 2, $3)`,
				r.ID, len(r.Slots)+1, round2Pay(r.PayEach)); err != nil {
				return false, err
			}
			if _, err := tx.Exec(ctx, `UPDATE reviews SET reserve = 0, round = 2, deadline = greatest(deadline, now() + $2::interval) WHERE id = $1`,
				r.ID, Round2Extra.String()); err != nil {
				return false, err
			}
		case r.Reserve > 0:
			if err := releaseReserve(ctx, tx, r); err != nil {
				return false, err
			}
		}
		if r.Debate && r.N == 2 {
			if _, err := tx.Exec(ctx, `UPDATE review_slots SET rebut_until = now() + $2::interval WHERE review = $1 AND round = 1`,
				r.ID, RebutWindow.String()); err != nil {
				return false, err
			}
		}
		if r.Task != nil && OnTaskDecidedFn != nil {
			if err := OnTaskDecidedFn(ctx, tx, *r.Task, taskVerdict(r)); err != nil {
				return false, err
			}
		}
	}
	if !escalated {
		if _, err := tx.Exec(ctx, `UPDATE reviews SET state = 'answered' WHERE id = $1 AND state = 'open'`, r.ID); err != nil {
			return false, err
		}
	}
	return unsealed, nil
}

// isSplit: at least one positive and one negative round-1 verdict (27.4).
func isSplit(r *Review) bool {
	pos, neg := false, false
	for _, s := range r.Slots {
		if s.Round != 1 || s.AnsweredAt == nil {
			continue
		}
		pos = pos || positive[s.Verdict]
		neg = neg || negative[s.Verdict]
	}
	return pos && neg
}

// releaseReserve refunds the unused escalation share to the requester.
func releaseReserve(ctx context.Context, q core.Q, r *Review) error {
	if r.Reserve <= 0 {
		return nil
	}
	tag, err := q.Exec(ctx, `UPDATE reviews SET reserve = 0, held = held - $2 WHERE id = $1 AND reserve = $2`, r.ID, r.Reserve)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	return core.RefundEarned(ctx, q, r.ReqID, r.Reserve)
}

// paySlot settles an answered slot in the reviewer's favour (guarded answered -> paid): Earn to
// the reviewer root, held decremented, the rating recorded. false when another path settled first.
func paySlot(ctx context.Context, q core.Q, r *Review, sl *Slot, rating string) (bool, error) {
	tag, err := q.Exec(ctx, `UPDATE review_slots SET state = 'paid', rating = $3, rated_at = CASE WHEN $3 <> '' THEN now() ELSE rated_at END
		WHERE review = $1 AND slot = $2 AND state = 'answered'`, r.ID, sl.Slot, rating)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	if _, err := q.Exec(ctx, `UPDATE reviews SET held = held - $2 WHERE id = $1`, r.ID, sl.Pay); err != nil {
		return false, err
	}
	return true, core.Earn(ctx, q, sl.WorkerRoot, sl.Pay)
}

// refundSlot returns a slot's credits to the requester (guarded from the given states).
func refundSlot(ctx context.Context, q core.Q, r *Review, sl *Slot, from []string, rating string) (bool, error) {
	tag, err := q.Exec(ctx, `UPDATE review_slots SET state = 'refunded', rating = CASE WHEN $4 <> '' THEN $4 ELSE rating END,
		rated_at = CASE WHEN $4 <> '' THEN now() ELSE rated_at END WHERE review = $1 AND slot = $2 AND state = ANY($3)`,
		r.ID, sl.Slot, from, rating)
	if err != nil || tag.RowsAffected() == 0 {
		return false, err
	}
	if _, err := q.Exec(ctx, `UPDATE reviews SET held = held - $2 WHERE id = $1`, r.ID, sl.Pay); err != nil {
		return false, err
	}
	return true, core.RefundEarned(ctx, q, r.ReqID, sl.Pay)
}

// okRep is the reviewer's +1 for an ok rating: Distinct requester and reviewer, 5 per day (16.3).
func okRep(ctx context.Context, q core.Q, r *Review, sl *Slot) error {
	if sl.WorkerRoot == "" {
		return nil
	}
	ok, err := trust.Distinct(ctx, q, r.ReqRoot, sl.WorkerRoot)
	if err != nil || !ok {
		return err
	}
	_, err = core.AddRep(ctx, q, sl.WorkerRoot, 1, "rep:review", RepOkCap)
	return err
}

// rateIn is POST /v1/pr/{id}/rate / op rr.
type rateIn struct {
	Slot   int    `json:"slot"`
	Rating string `json:"rating"`
}

// rate settles one answered slot (16.3): ok pays now (+1 rep, Distinct, 5/day); bad refunds the
// slot's credits to the requester (-1 rep, 3/day; three bad from distinct requesters in 7 d exclude
// the reviewer for 7 d). Only the requester tree, only visible answers, once per slot.
func (s *svc) rate(ctx context.Context, id *core.Ident, rid string, in *rateIn) (string, error) {
	in.Rating = strings.ToLower(strings.TrimSpace(in.Rating))
	if in.Rating != "ok" && in.Rating != "bad" {
		return "", core.Bad("rating must be ok|bad")
	}
	var line string
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		r, err := load(ctx, tx, rid, true)
		if err != nil {
			return err
		}
		if r.ReqRoot != id.Root {
			return errNotRequester
		}
		var sl *Slot
		for i := range r.Slots {
			if r.Slots[i].Slot == in.Slot {
				sl = &r.Slots[i]
			}
		}
		switch {
		case sl == nil:
			return core.Bad("no such slot")
		case sl.Rating != "" || sl.State == "paid" || sl.State == "refunded":
			return errRated
		case sl.State != "answered":
			return errNotAnswered
		case !r.Visible(time.Now()):
			return errSealed
		}
		if in.Rating == "ok" {
			done, err := paySlot(ctx, tx, r, sl, "ok")
			if err != nil || !done {
				if err == nil {
					err = errRated
				}
				return err
			}
			if err := okRep(ctx, tx, r, sl); err != nil {
				return err
			}
			line = sfmt("ok %s slot=%d ok paid", rid, sl.Slot)
		} else {
			done, err := refundSlot(ctx, tx, r, sl, []string{"answered"}, "bad")
			if err != nil || !done {
				if err == nil {
					err = errRated
				}
				return err
			}
			if err := repDown(ctx, tx, sl.WorkerRoot, "rep:review-", RepBadCap); err != nil {
				return err
			}
			if err := badExclusion(ctx, tx, r, sl); err != nil {
				return err
			}
			line = sfmt("ok %s slot=%d bad refunded", rid, sl.Slot)
		}
		if err := core.Audit(ctx, tx, id.ID, "rr", rid, sl.Slot); err != nil {
			return err
		}
		return closeIfDone(ctx, tx, rid)
	})
	if err != nil {
		return "", err
	}
	s.wake("pr:" + rid)
	return line, nil
}

// badExclusion records a 7-day exclusion once BadExcl bad ratings from distinct requesters landed on
// the reviewer within BadWindow.
func badExclusion(ctx context.Context, q core.Q, r *Review, sl *Slot) error {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(DISTINCT rv.req_root) FROM review_slots s JOIN reviews rv ON rv.id = s.review
		WHERE s.worker_root = $1 AND s.rating = 'bad' AND s.rated_at > now() - $2::interval`, sl.WorkerRoot, BadWindow.String()).Scan(&n); err != nil {
		return err
	}
	if n < BadExcl {
		return nil
	}
	_, err := q.Exec(ctx, `INSERT INTO review_excl (review, slot, root, why) VALUES ($1, $2, $3, 'bad3')`, r.ID, sl.Slot, sl.WorkerRoot)
	return err
}

// rebutIn is POST /v1/pr/{id}/rebut / op rb.
type rebutIn struct {
	Lease string `json:"lease"`
	Text  string `json:"text"`
}

// rebut lets a round-1 reviewer of a debate review answer the other opinion once within the 15 min
// window after unsealing (27.4); unpaid, but it settles the slot as an ok review when it is still
// unrated. Skipping it never counts as bad.
func (s *svc) rebut(ctx context.Context, id *core.Ident, rid string, in *rebutIn) (string, error) {
	in.Lease = strings.TrimSpace(in.Lease)
	in.Text = strings.TrimRight(scrub.Normalize(in.Text), "\n")
	switch {
	case in.Lease == "":
		return "", core.Bad("lease required")
	case strings.TrimSpace(in.Text) == "":
		return "", core.Bad("text required")
	case len(in.Text) > MaxRebuttal:
		return "", core.E(413, "size", sfmt("text must be <= %d bytes", MaxRebuttal))
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"text": &in.Text}); aerr != nil {
		return "", aerr
	}
	var line string
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		r, err := load(ctx, tx, rid, true)
		if err != nil {
			return err
		}
		if !r.Debate {
			return errNoDebate
		}
		sl := slotByLease(r, in.Lease)
		now := time.Now()
		switch {
		case sl == nil || sl.Round != 1 || sl.AnsweredAt == nil:
			return errLease
		case sl.WorkerRoot != id.Root:
			return errNotWorker
		case sl.RebuttedAt != nil:
			return errRebutted
		case sl.RebutUntil == nil || now.After(*sl.RebutUntil):
			return errRebutWindow
		}
		if _, err := tx.Exec(ctx, `UPDATE review_slots SET rebuttal = $3, rebutted_at = now() WHERE review = $1 AND slot = $2`,
			rid, sl.Slot, in.Text); err != nil {
			return err
		}
		if sl.State == "answered" && sl.Rating == "" {
			done, err := paySlot(ctx, tx, r, sl, "ok")
			if err != nil {
				return err
			}
			if done {
				if err := okRep(ctx, tx, r, sl); err != nil {
					return err
				}
			}
		}
		n := 1
		for _, o := range r.Slots {
			if o.Round == 1 && o.RebuttedAt != nil && o.Slot != sl.Slot {
				n++
			}
		}
		line = sfmt("ok %s slot=%d rebuttal %d/%d", rid, sl.Slot, n, r.N)
		if err := core.Audit(ctx, tx, id.ID, "rb", rid, sl.Slot); err != nil {
			return err
		}
		return closeIfDone(ctx, tx, rid)
	})
	if err != nil {
		return "", err
	}
	s.wake("pr:" + rid)
	return line, nil
}

// notify sends a best-effort sys mail after commit (a failed notice never fails the write).
func (s *svc) notify(ctx context.Context, root, subject, text string) {
	if root == "" {
		return
	}
	if err := mail.SendSys(ctx, s.d.DB, root, subject, text); err != nil {
		s.d.Log.Warn("review notice", "to", root, "err", err)
	}
}
