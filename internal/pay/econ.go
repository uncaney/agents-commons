package pay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// writeAuth is the shared write guard: authed, unbanned, writes not frozen, economy not frozen.
func (s *svc) writeAuth(id *core.Ident) error {
	if id == nil {
		return core.ErrAuth
	}
	if id.Banned {
		return core.ErrBanned
	}
	if s.d.Frozen("write") {
		return core.Frozen("write")
	}
	if s.d.Frozen("bounties") {
		return core.Frozen("bounties")
	}
	return nil
}

// requireL1 refuses a root below L1 (agreements and tips are L1+).
func requireL1(ctx context.Context, q core.Q, root string) error {
	st, err := trust.Load(ctx, q, root)
	if err != nil {
		return err
	}
	if st.Level() < 1 {
		return core.E(403, "level", "L1 required")
	}
	return nil
}

// liveRoot reports whether id names a live top-level root (a valid payee / tip recipient).
func liveRoot(ctx context.Context, q core.Q, id string) (bool, error) {
	if !core.ValidIDPrefix(id, 'a') {
		return false, nil
	}
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM identities WHERE id = $1 AND parent IS NULL AND revoked_at IS NULL)`, id).Scan(&ok)
	return ok, err
}

func cleanRe(s string) (string, error) {
	s = scrub.Normalize(s)
	if len(s) > maxRe {
		return "", core.Bad(fmt.Sprintf("re <= %d", maxRe))
	}
	return doc.SafeLine(s), nil
}

// --- create ---

type createIn struct {
	To        string `json:"to"`
	Max       int64  `json:"max"`
	PerCharge int64  `json:"per_charge"`
	TTLH      int    `json:"ttl_h"`
	Re        string `json:"re"`
	Key       string `json:"key"`
}

// create escrows a metered agreement (27.4): ReserveEarned of the ceiling, state offered, a sys
// mail to the payee. L1+, <= 10 open agreements per payer, one pending offer per (payer, payee).
func (s *svc) create(ctx context.Context, id *core.Ident, in createIn) (*agreement, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	if in.Max < minMax || in.Max > maxMax {
		return nil, core.Bad(fmt.Sprintf("max %d..%d", minMax, maxMax))
	}
	if in.PerCharge == 0 {
		in.PerCharge = in.Max
		if in.PerCharge > maxPerCharge {
			in.PerCharge = maxPerCharge
		}
	}
	if in.PerCharge < minPerCharge || in.PerCharge > maxPerCharge {
		return nil, core.Bad(fmt.Sprintf("per_charge %d..%d", minPerCharge, maxPerCharge))
	}
	if in.TTLH == 0 {
		in.TTLH = maxTTLH
	}
	if in.TTLH < minTTLH || in.TTLH > maxTTLH {
		return nil, core.Bad(fmt.Sprintf("ttl_h %d..%d", minTTLH, maxTTLH))
	}
	re, err := cleanRe(in.Re)
	if err != nil {
		return nil, err
	}
	if in.To == id.Root {
		return nil, core.Bad("cannot open an agreement with your own tree")
	}
	a := &agreement{ID: core.NewID('y'), Payer: id.ID, PayerRoot: id.Root, PayeeRoot: in.To,
		Max: in.Max, PerCharge: in.PerCharge, Until: time.Now().Add(time.Duration(in.TTLH) * time.Hour), State: "offered", Re: re}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := requireL1(ctx, tx, id.Root); err != nil {
			return err
		}
		ok, err := liveRoot(ctx, tx, in.To)
		if err != nil {
			return err
		}
		if !ok {
			return core.E(404, "notfound", "payee root "+in.To)
		}
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM agreements WHERE payer_root = $1 AND state IN `+liveStates, id.Root).Scan(&open); err != nil {
			return err
		}
		if open >= openPerRoot {
			return core.E(429, "quota", fmt.Sprintf("open agreements %d/%d", open, openPerRoot))
		}
		var pending bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agreements WHERE payer_root = $1 AND payee_root = $2 AND state = 'offered')`, id.Root, in.To).Scan(&pending); err != nil {
			return err
		}
		if pending {
			return core.E(409, "dup", "a pending offer to "+in.To+" already exists")
		}
		if err := core.ReserveEarned(ctx, tx, id.ID, in.Max); err != nil {
			if errors.Is(err, core.ErrEarned) {
				return core.E(402, "credits", fmt.Sprintf("earned required (earned=%d need=%d; agreements escrow transferable credits only)", id.Earned, in.Max))
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agreements (id, payer, payer_root, payee_root, max, per_charge, until, state, re)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'offered', $8)`, a.ID, a.Payer, a.PayerRoot, a.PayeeRoot, a.Max, a.PerCharge, a.Until, a.Re); err != nil {
			return err
		}
		if err := core.SysMail(ctx, tx, a.PayeeRoot, "agreement "+a.ID+" offered", fmt.Sprintf("%s offers a metered agreement: up to %dcr, %dcr per charge, until %s. Accept within 24 h: POST /v1/ag/%s/accept", id.ID, a.Max, a.PerCharge, core.Date(a.Until), a.ID)); err != nil {
			return err
		}
		if err := core.Event(ctx, tx, "ag", a.ID, "", fmt.Sprintf("agreement max=%dcr to %s offered", a.Max, a.PayeeRoot)); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "ag", a.ID, int(a.Max))
	})
	if err != nil {
		return nil, err
	}
	return load(ctx, s.d.DB, a.ID, false)
}

// accept flips an offer open (payee only, within 24 h). A late accept is refused; the janitor then
// auto-closes and refunds it.
func (s *svc) accept(ctx context.Context, id *core.Ident, agID string) (*agreement, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	var a *agreement
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var err error
		if a, err = load(ctx, tx, agID, true); err != nil {
			return err
		}
		if a.PayeeRoot != id.Root {
			return core.E(403, "auth", "payee only")
		}
		if a.State != "offered" {
			return core.E(409, "bad", "agreement "+a.State)
		}
		if !a.Created.Add(acceptWindow).After(time.Now()) {
			return core.E(409, "bad", "offer expired; it will be refunded")
		}
		tag, err := tx.Exec(ctx, `UPDATE agreements SET state = 'open' WHERE id = $1 AND state = 'offered'`, a.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return core.E(409, "bad", "agreement "+a.State)
		}
		a.State = "open"
		if err := core.SysMail(ctx, tx, a.PayerRoot, "agreement "+a.ID+" accepted", fmt.Sprintf("%s accepted; charges may now draw up to %dcr", id.ID, a.Max)); err != nil {
			return err
		}
		return core.Event(ctx, tx, "ag", a.ID, "", "accepted")
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// --- charge ---

type chargeIn struct {
	Amount int64  `json:"amount"`
	Key    string `json:"key"`
	Ref    string `json:"ref"`
}

// charge draws one metered unit (payee tree only). The (agreement, key) PK makes a replay idempotent
// (replay=true, nothing charged twice); the guarded UPDATE enforces open state, the deadline, the
// ceiling and per_charge; the amount is paid from the escrow as an `earned`/`ag` ledger row.
func (s *svc) charge(ctx context.Context, id *core.Ident, agID string, in chargeIn) (a *agreement, replay bool, err error) {
	if err := s.writeAuth(id); err != nil {
		return nil, false, err
	}
	if in.Key == "" || len(in.Key) > maxKey {
		return nil, false, core.Bad(fmt.Sprintf("key 1..%d", maxKey))
	}
	ref := scrub.Normalize(in.Ref)
	if len(ref) > maxChargeRef {
		return nil, false, core.Bad(fmt.Sprintf("ref <= %d", maxChargeRef))
	}
	ref = doc.SafeLine(ref)
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var err error
		if a, err = load(ctx, tx, agID, true); err != nil {
			return err
		}
		if a.PayeeRoot != id.Root {
			return core.E(403, "auth", "payee tree only")
		}
		if a.State != "open" {
			return core.E(409, "bad", "agreement "+a.State)
		}
		if in.Amount < 1 {
			return core.Bad("amount >= 1")
		}
		// Idempotency: the first charge for this key inserts; a replay conflicts and changes nothing.
		tag, err := tx.Exec(ctx, `INSERT INTO charges (agreement, key, amount, ref) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, a.ID, in.Key, in.Amount, ref)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			replay = true
			return nil
		}
		// Guarded draw: open, before the deadline, within the ceiling and per_charge.
		var used int64
		err = tx.QueryRow(ctx, `UPDATE agreements SET used = used + $2 WHERE id = $1 AND state = 'open'
			AND until > now() AND used + $2 <= max AND $2 <= per_charge RETURNING used`, a.ID, in.Amount).Scan(&used)
		if errors.Is(err, pgx.ErrNoRows) {
			return core.E(402, "credits", fmt.Sprintf("agreement used=%d/%d (amount %d, per_charge %d)", a.Used, a.Max, in.Amount, a.PerCharge))
		}
		if err != nil {
			return err
		}
		a.Used = used
		// Pay the payee from the escrow: an earned/ag ledger row, ref y…/<key>.
		if err := payFromEscrow(ctx, tx, a.PayeeRoot, in.Amount, "ag", a.ID+"/"+in.Key); err != nil {
			return err
		}
		return core.Event(ctx, tx, "ag", a.ID, "", fmt.Sprintf("charge %dcr key=%s used=%d/%d", in.Amount, in.Key, used, a.Max))
	})
	if err != nil {
		return nil, false, err
	}
	a, err = load(ctx, s.d.DB, agID, false)
	return a, replay, err
}

// --- close ---

// close settles a live agreement (either party), refunding the remainder to the payer.
func (s *svc) close(ctx context.Context, id *core.Ident, agID string) (*agreement, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	var a *agreement
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var err error
		if a, err = load(ctx, tx, agID, true); err != nil {
			return err
		}
		if !a.party(id.Root) {
			return core.E(403, "auth", "payer or payee only")
		}
		if !a.live() {
			return core.E(409, "bad", "agreement "+a.State)
		}
		who := "payer"
		if id.Root == a.PayeeRoot {
			who = "payee"
		}
		return settleClose(ctx, tx, a, "closed by "+who)
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// settleClose flips a live agreement closed and refunds the remainder (max - used) to the payer.
func settleClose(ctx context.Context, q core.Q, a *agreement, why string) error {
	tag, err := q.Exec(ctx, `UPDATE agreements SET state = 'closed' WHERE id = $1 AND state IN `+liveStates, a.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.E(409, "bad", "agreement "+a.State)
	}
	rem := a.remainder()
	a.State = "closed"
	if rem > 0 {
		if err := core.RefundEarned(ctx, q, a.Payer, rem); err != nil {
			return err
		}
	}
	if err := core.Event(ctx, q, "ag", a.ID, "", fmt.Sprintf("closed: %s (refunded %dcr)", why, rem)); err != nil {
		return err
	}
	return core.SysMail(ctx, q, a.PayerRoot, "agreement "+a.ID+" closed", fmt.Sprintf("%s; %dcr refunded, %dcr spent", why, rem, a.Used))
}

// --- tip ---

type tipIn struct {
	To      string `json:"to"`
	Credits int64  `json:"credits"`
	Re      string `json:"re"`
	Key     string `json:"key"`
}

// tip transfers 1..50 transferable credits in one tx (ReserveEarned + payFromEscrow with reason
// tip), enforcing 20 tips and 200 credits per day per root, then mails the recipient.
func (s *svc) tip(ctx context.Context, id *core.Ident, in tipIn) (int64, error) {
	if err := s.writeAuth(id); err != nil {
		return 0, err
	}
	if in.Credits < minTip || in.Credits > maxTip {
		return 0, core.Bad(fmt.Sprintf("credits %d..%d", minTip, maxTip))
	}
	re, err := cleanRe(in.Re)
	if err != nil {
		return 0, err
	}
	if in.To == id.Root {
		return 0, core.Bad("cannot tip your own tree")
	}
	var remaining int64
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := requireL1(ctx, tx, id.Root); err != nil {
			return err
		}
		ok, err := liveRoot(ctx, tx, in.To)
		if err != nil {
			return err
		}
		if !ok {
			return core.E(404, "notfound", "recipient root "+in.To)
		}
		// Daily caps: count and credits per root per day.
		var n int
		var spent int64
		if err := tx.QueryRow(ctx, `INSERT INTO tips_daily (root, day, n, credits) VALUES ($1, current_date, 1, $2)
			ON CONFLICT (root, day) DO UPDATE SET n = tips_daily.n + 1, credits = tips_daily.credits + $2 RETURNING n, credits`,
			id.Root, in.Credits).Scan(&n, &spent); err != nil {
			return err
		}
		if n > tipsPerDay {
			return core.E(429, "quota", fmt.Sprintf("tips %d/%d today", n, tipsPerDay))
		}
		if spent > tipCreditsPerDay {
			return core.E(429, "quota", fmt.Sprintf("tip credits %d/%d today", spent, tipCreditsPerDay))
		}
		remaining = tipCreditsPerDay - spent
		if err := core.ReserveEarned(ctx, tx, id.ID, in.Credits); err != nil {
			if errors.Is(err, core.ErrEarned) {
				return core.E(402, "credits", fmt.Sprintf("earned required (earned=%d need=%d; tips move transferable credits only)", id.Earned, in.Credits))
			}
			return err
		}
		if err := payFromEscrow(ctx, tx, in.To, in.Credits, "tip", id.ID); err != nil {
			return err
		}
		sub := fmt.Sprintf("tip +%d from %s", in.Credits, id.ID)
		body := sub
		if re != "" {
			body += " (" + re + ")"
		}
		if err := core.SysMail(ctx, tx, in.To, sub, body); err != nil {
			return err
		}
		return core.Event(ctx, tx, "tip", id.ID, "", fmt.Sprintf("tip +%d to %s", in.Credits, in.To))
	})
	if err != nil {
		return 0, err
	}
	return remaining, nil
}

// payFromEscrow moves n held credits to a live root as earned under a custom ledger reason+ref
// (reason ag for charges, tip for tips). A revoked payee burns instead, keeping the audit exact.
func payFromEscrow(ctx context.Context, q core.Q, root string, n int64, reason, ref string) error {
	if n <= 0 {
		return nil
	}
	tag, err := q.Exec(ctx, `UPDATE identities SET credits = credits + $2, earned = earned + $2 WHERE id = $1 AND revoked_at IS NULL`, root, n)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.Ledger(ctx, q, core.LedgerHold, core.LedgerBurn, "earned", n, "unpayable", ref)
	}
	return core.Ledger(ctx, q, core.LedgerHold, root, "earned", n, reason, ref)
}

// --- janitor ---
//

// janitor (periodic) auto-closes agreements whose offer window lapsed without acceptance and open
// agreements past their deadline, refunding the remainder each time.
func (s *svc) janitor(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT id FROM agreements
		WHERE (state = 'offered' AND created + interval '24 hours' < now())
		   OR (state IN ('offered', 'open') AND until < now())
		ORDER BY created LIMIT 200`)
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
		err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			a, err := load(ctx, tx, id, true)
			if err != nil {
				return err
			}
			if !a.live() {
				return nil
			}
			why := "deadline reached"
			if a.State == "offered" {
				why = "offer not accepted within 24 h"
			}
			return settleClose(ctx, tx, a, why)
		})
		if err != nil {
			s.d.Log.Warn("pay janitor", "agreement", id, "err", err)
		}
	}
	return nil
}
