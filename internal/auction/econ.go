package auction

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/bounty"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

type createIn struct {
	Task       json.RawMessage `json:"task"`
	Budget     int64           `json:"budget"`
	ClosesM    int             `json:"closes_m"`
	MinBidders int             `json:"min_bidders"`
	Fallback   string          `json:"fallback"`
	Key        string          `json:"key"`
}

type newTask struct {
	Title string   `json:"title"`
	Body  string   `json:"body"`
	Tags  []string `json:"tags"`
}

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

// create escrows a reverse auction (27.4): ReserveEarned of the budget ceiling, one live
// auction/bounty per task, task creation through forge.CreateTask when a title is given. Auctions
// count in the bounties cap row.
func (s *svc) create(ctx context.Context, id *core.Ident, in createIn) (*auction, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	if in.Budget < minBudget || in.Budget > maxBudget {
		return nil, core.Bad(fmt.Sprintf("budget %d..%d", minBudget, maxBudget))
	}
	if in.ClosesM == 0 {
		in.ClosesM = minClosesM
	}
	if in.ClosesM < minClosesM || in.ClosesM > maxClosesM {
		return nil, core.Bad(fmt.Sprintf("closes_m %d..%d", minClosesM, maxClosesM))
	}
	if in.MinBidders == 0 {
		in.MinBidders = minBidders
	}
	if in.MinBidders < minBidders || in.MinBidders > maxBidders {
		return nil, core.Bad(fmt.Sprintf("min_bidders %d..%d", minBidders, maxBidders))
	}
	switch in.Fallback {
	case "", "bounty":
	default:
		return nil, core.Bad("fallback must be '' or bounty")
	}
	var task int64
	raw := strings.TrimSpace(string(in.Task))
	switch {
	case raw == "" || raw == "null":
		return nil, core.Bad(`task required: a number or {"title","body","tags"}`)
	case raw[0] == '{':
		var nt newTask
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&nt); err != nil {
			return nil, core.Bad("task: title, body, tags")
		}
		n, err := forge.CreateTask(ctx, s.d, id, forge.TaskInput{Title: nt.Title, Body: nt.Body, Tags: nt.Tags})
		if err != nil {
			return nil, err
		}
		task = n
	default:
		if _, err := fmt.Sscanf(raw, "%d", &task); err != nil || task <= 0 || itoa(task) != raw {
			return nil, core.Bad("task must be a task number")
		}
	}
	a := &auction{ID: core.NewID('n'), Task: task, Creator: id.ID, CreatorRoot: id.Root, Budget: in.Budget,
		ClosesAt: time.Now().Add(time.Duration(in.ClosesM) * time.Minute), MinBidders: in.MinBidders, Fallback: in.Fallback, State: "open"}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var state, troot string
		var quarantine bool
		err := tx.QueryRow(ctx, `SELECT state, root, quarantine FROM tasks WHERE n = $1 FOR UPDATE`, task).Scan(&state, &troot, &quarantine)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && state == "hidden") {
			return core.E(404, "notfound", "task #"+itoa(task))
		}
		if err != nil {
			return err
		}
		if state == "done" {
			return core.E(409, "bad", "task closed")
		}
		if troot != id.Root {
			return core.E(403, "auth", "task creator only")
		}
		if quarantine {
			return core.E(409, "quarantine", "task quarantined")
		}
		if err := liveTaskGuard(ctx, tx, task); err != nil {
			return err
		}
		// Auctions count in the bounties cap row (open bounties + live auctions).
		st, err := trust.Load(ctx, tx, id.Root)
		if err != nil {
			return err
		}
		capN := trust.Cap("bounties", st.CapLevel())
		if capN == 0 {
			return core.E(429, "quota", "bounties L1 required")
		}
		var open int
		if err := tx.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM auctions WHERE creator_root = $1 AND state IN `+liveStates+`)
			+ (SELECT count(*) FROM bounties WHERE creator_root = $1 AND state IN ('open', 'submitted', 'rejected'))`, id.Root).Scan(&open); err != nil {
			return err
		}
		if open >= capN {
			return core.E(429, "quota", fmt.Sprintf("bounties open %d/%d", open, capN))
		}
		if err := core.ReserveEarned(ctx, tx, id.ID, in.Budget); err != nil {
			if errors.Is(err, core.ErrEarned) {
				return core.E(402, "credits", fmt.Sprintf("earned required (earned=%d need=%d; auctions escrow transferable credits only)", id.Earned, in.Budget))
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auctions (id, task, creator, creator_root, budget, closes_at, min_bidders, fallback)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, a.ID, a.Task, a.Creator, a.CreatorRoot, a.Budget, a.ClosesAt, a.MinBidders, a.Fallback); err != nil {
			return err
		}
		if err := core.Event(ctx, tx, "au", a.ID, "", fmt.Sprintf("auction budget<=%dcr on #%d", a.Budget, a.Task)); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "au", a.ID, int(a.Budget))
	})
	if err != nil {
		return nil, err
	}
	s.d.Notify.Wake(forge.TaskTopic(task))
	return load(ctx, s.d.DB, a.ID, false)
}

// liveTaskGuard refuses a second live auction or bounty on the same task.
func liveTaskGuard(ctx context.Context, q core.Q, task int64) error {
	var id string
	if err := q.QueryRow(ctx, `SELECT id FROM auctions WHERE task = $1 AND state IN `+liveStates+` LIMIT 1`, task).Scan(&id); err == nil {
		return core.E(409, "dup", "auction "+id+" live on task #"+itoa(task))
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err := q.QueryRow(ctx, `SELECT id FROM bounties WHERE task = $1 AND state IN ('open', 'submitted', 'rejected') LIMIT 1`, task).Scan(&id); err == nil {
		return core.E(409, "dup", "bounty "+id+" live on task #"+itoa(task))
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

type bidIn struct {
	Amount int64  `json:"amount"`
	Note   string `json:"note"`
	Key    string `json:"key"`
}

// bid places (or replaces) a sealed bid: L1+, distinct super-group from the creator, not a flagged
// collusion pair, amount 1..budget, a 1-credit bond, at most 5 open bids per root.
func (s *svc) bid(ctx context.Context, id *core.Ident, auctionID string, in bidIn) (*auction, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	note := strings.TrimSpace(scrub.Normalize(in.Note))
	if len(note) > maxNote {
		return nil, core.Bad(fmt.Sprintf("note <= %d", maxNote))
	}
	note = doc.SafeLine(note)
	var a *auction
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var err error
		if a, err = load(ctx, tx, auctionID, true); err != nil {
			return err
		}
		if a.State != "open" {
			return core.E(409, "bad", "auction "+a.State)
		}
		if !a.ClosesAt.After(time.Now()) {
			return core.E(409, "bad", "auction closing")
		}
		if in.Amount < 1 || in.Amount > a.Budget {
			return core.Bad(fmt.Sprintf("amount 1..%d", a.Budget))
		}
		st, err := trust.Load(ctx, tx, id.Root)
		if err != nil {
			return err
		}
		if st.Level() < 1 {
			return core.E(403, "level", "L1 required to bid")
		}
		distinct, err := trust.Distinct(ctx, tx, a.CreatorRoot, id.Root)
		if err != nil {
			return err
		}
		if !distinct {
			return core.E(409, "bad", "bidder must be distinct from the creator")
		}
		if ExcludeFn != nil {
			excluded, err := ExcludeFn(ctx, tx, a.CreatorRoot, id.Root)
			if err != nil {
				return err
			}
			if excluded {
				return core.E(409, "bad", "flagged collusion pair with the creator")
			}
		}
		// New bid vs re-bid: a re-bid keeps its bond and does not count against the open-bids cap.
		var had bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM bids WHERE auction = $1 AND root = $2)`, a.ID, id.Root).Scan(&had); err != nil {
			return err
		}
		if !had {
			var openBids int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM bids b JOIN auctions au ON au.id = b.auction
				WHERE b.root = $1 AND au.state = 'open'`, id.Root).Scan(&openBids); err != nil {
				return err
			}
			if openBids >= maxOpenBids {
				return core.E(429, "quota", fmt.Sprintf("open bids %d/%d", openBids, maxOpenBids))
			}
			tag, err := tx.Exec(ctx, `INSERT INTO bonds (ref, root, credits) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, a.ID, id.Root, bidBond)
			if err != nil {
				return err
			}
			if tag.RowsAffected() > 0 {
				if err := core.Reserve(ctx, tx, id.ID, bidBond); err != nil {
					if errors.Is(err, core.ErrCredits) {
						return core.E(402, "credits", fmt.Sprintf("bond %d", bidBond))
					}
					return err
				}
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO bids (auction, root, id, amount, note, bond) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (auction, root) DO UPDATE SET id = EXCLUDED.id, amount = EXCLUDED.amount, note = EXCLUDED.note, created = now()`,
			a.ID, id.Root, id.ID, in.Amount, note, bidBond); err != nil {
			return err
		}
		return core.Event(ctx, tx, "au", a.ID, "", "bid")
	})
	if err != nil {
		return nil, err
	}
	return load(ctx, s.d.DB, auctionID, false)
}

// cancel refunds a live auction (creator only, before close): budget and every bond returned.
func (s *svc) cancel(ctx context.Context, id *core.Ident, auctionID string) (*auction, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	var a *auction
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var err error
		if a, err = load(ctx, tx, auctionID, true); err != nil {
			return err
		}
		if a.CreatorRoot != id.Root {
			return core.E(403, "auth", "creator only")
		}
		if !a.live() {
			return core.E(409, "bad", "auction "+a.State)
		}
		return settleCancel(ctx, tx, a, "cancelled by creator")
	})
	if err != nil {
		return nil, err
	}
	return load(ctx, s.d.DB, auctionID, false)
}

// settleCancel refunds the budget to the creator and every bond to its bidder, state -> cancelled.
func settleCancel(ctx context.Context, q core.Q, a *auction, why string) error {
	tag, err := q.Exec(ctx, `UPDATE auctions SET state = 'cancelled' WHERE id = $1 AND state IN `+liveStates, a.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.E(409, "bad", "auction "+a.State)
	}
	if err := core.RefundEarned(ctx, q, a.Creator, a.Budget); err != nil {
		return err
	}
	if err := refundAllBonds(ctx, q, a.ID); err != nil {
		return err
	}
	a.State = "cancelled"
	if err := core.Event(ctx, q, "au", a.ID, "", "cancelled: "+why); err != nil {
		return err
	}
	return core.SysMail(ctx, q, a.CreatorRoot, "auction "+a.ID+" cancelled", why+"; budget refunded")
}

// --- close / award ---

// closeOne settles a past-deadline auction under a row lock: collapse bids to one per super-group
// (lowest), then award at the second-lowest collapsed price or declare nobid.
func closeOne(ctx context.Context, q core.Q, a *auction) error {
	if a.State == "open" {
		tag, err := q.Exec(ctx, `UPDATE auctions SET state = 'closing' WHERE id = $1 AND state = 'open'`, a.ID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return nil
		}
		a.State = "closing"
	}
	if a.State != "closing" {
		return nil
	}
	bids, err := loadBids(ctx, q, a.ID)
	if err != nil {
		return err
	}
	collapsed := collapse(bids)
	if len(collapsed) < a.MinBidders {
		return settleNobid(ctx, q, a)
	}
	// Winner = lowest amount; ties: higher rel, then earlier created.
	winner := collapsed[0]
	price := collapsed[1].Amount
	return award(ctx, q, a, winner, price, collapsed)
}

// collapse keeps the single best bid per super-group and sorts the survivors for the second-price
// rule: ascending amount, then higher reliability, then earlier.
func collapse(bids []bidRow) []bidRow {
	best := map[string]bidRow{}
	for _, b := range bids {
		cur, ok := best[b.super]
		if !ok || less(b, cur) {
			best[b.super] = b
		}
	}
	out := make([]bidRow, 0, len(best))
	for _, b := range best {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}

// less orders bids by ascending amount, then higher rel, then earlier created, then id (stable).
func less(a, b bidRow) bool {
	if a.Amount != b.Amount {
		return a.Amount < b.Amount
	}
	if a.rel != b.rel {
		return a.rel > b.rel
	}
	if !a.Created.Equal(b.Created) {
		return a.Created.Before(b.Created)
	}
	return a.ID < b.ID
}

// settleNobid refunds every bond, refunds the budget to the creator (or opens a fixed bounty at
// the full budget when fallback=bounty), state -> nobid.
func settleNobid(ctx context.Context, q core.Q, a *auction) error {
	tag, err := q.Exec(ctx, `UPDATE auctions SET state = 'nobid' WHERE id = $1 AND state = 'closing'`, a.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	a.State = "nobid"
	if err := refundAllBonds(ctx, q, a.ID); err != nil {
		return err
	}
	if a.Fallback == "bounty" {
		bid, err := openFallbackBounty(ctx, q, a)
		if err == nil {
			if _, err := q.Exec(ctx, `UPDATE auctions SET bounty = $2 WHERE id = $1`, a.ID, bid); err != nil {
				return err
			}
			a.Bounty = bid
			if err := core.Event(ctx, q, "au", a.ID, "", "nobid -> fallback bounty "+bid); err != nil {
				return err
			}
			return core.SysMail(ctx, q, a.CreatorRoot, "auction "+a.ID+" nobid", "too few distinct bidders; opened fallback bounty "+bid+" at the full budget")
		}
		// Fallback could not open (e.g. task closed): fall back to a refund.
	}
	if err := core.RefundEarned(ctx, q, a.Creator, a.Budget); err != nil {
		return err
	}
	if err := core.Event(ctx, q, "au", a.ID, "", "nobid: refunded"); err != nil {
		return err
	}
	return core.SysMail(ctx, q, a.CreatorRoot, "auction "+a.ID+" nobid", "too few distinct bidders; budget refunded")
}

// openFallbackBounty opens an ordinary open bounty on the task carrying the auction's held budget
// (no assignee): the escrow stays in hold under the new bounty row, so the audit is unchanged.
func openFallbackBounty(ctx context.Context, q core.Q, a *auction) (string, error) {
	var state string
	err := q.QueryRow(ctx, `SELECT state FROM tasks WHERE n = $1`, a.Task).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (state == "hidden" || state == "done")) {
		return "", core.E(409, "bad", "task unavailable")
	}
	if err != nil {
		return "", err
	}
	var live string
	if err := q.QueryRow(ctx, `SELECT id FROM bounties WHERE task = $1 AND state IN ('open', 'submitted', 'rejected') LIMIT 1`, a.Task).Scan(&live); err == nil {
		return "", core.E(409, "dup", "bounty live")
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	bid := core.NewID('b')
	deadline := a.ClosesAt.Add(awardDeadlineH * time.Hour)
	if _, err := q.Exec(ctx, `INSERT INTO bounties (id, task, creator, creator_root, escrow, held, review, deadline, state)
		VALUES ($1, $2, $3, $4, $5, $5, 'creator', $6, 'open')`, bid, a.Task, a.Creator, a.CreatorRoot, a.Budget, deadline); err != nil {
		return "", err
	}
	if err := core.Event(ctx, q, "bt", bid, "", fmt.Sprintf("fallback bounty %dcr on #%d (auction %s)", a.Budget, a.Task, a.ID)); err != nil {
		return "", err
	}
	return bid, nil
}

// award assigns the lowest bidder the task and a bounty at the second-lowest collapsed price from
// the same escrow (the remainder refunded), with every losing bond returned and the winner's held.
func award(ctx context.Context, q core.Q, a *auction, winner bidRow, price int64, collapsed []bidRow) error {
	deadline := a.ClosesAt.Add(awardDeadlineH * time.Hour)
	if !deadline.After(time.Now()) {
		deadline = time.Now().Add(awardDeadlineH * time.Hour)
	}
	bid, err := bounty.CreateFromEscrow(ctx, q, a.Task, price, a.Creator, a.CreatorRoot, winner.ID, winner.Root, deadline)
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `UPDATE auctions SET state = 'awarded', winner = $2, winner_root = $3, price = $4, bounty = $5 WHERE id = $1 AND state = 'closing'`,
		a.ID, winner.ID, winner.Root, price, bid)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.E(409, "bad", "auction "+a.State)
	}
	a.State, a.Winner, a.WinnerRoot, a.Price, a.Bounty = "awarded", winner.ID, winner.Root, price, bid
	// The remainder of the ceiling returns to the creator; the price stays held under the bounty.
	if rem := a.Budget - price; rem > 0 {
		if err := core.RefundEarned(ctx, q, a.Creator, rem); err != nil {
			return err
		}
	}
	// Assign the task claim to the winner for 24 h.
	if _, err := forge.ClaimAssign(ctx, q, a.Task, winner.ID, winner.Root, claimTTL); err != nil {
		return err
	}
	// Losing bonds returned now; the winner's bond is held until the first submission.
	for _, b := range collapsedAndLosers(ctx, q, a.ID, winner.Root) {
		if err := returnBond(ctx, q, a.ID, b.ID, b.Root); err != nil {
			return err
		}
	}
	if err := core.Event(ctx, q, "au", a.ID, "", fmt.Sprintf("awarded %s price=%d bounty=%s", winner.ID, price, bid)); err != nil {
		return err
	}
	if err := core.SysMail(ctx, q, winner.Root, fmt.Sprintf("won %s price=%d", a.ID, price), fmt.Sprintf("you won auction %s at %dcr; bounty %s, task #%d claimed for 24 h, submit before %s", a.ID, price, bid, a.Task, core.Date(deadline))); err != nil {
		return err
	}
	// Notify every distinct losing super-group once.
	notified := map[string]bool{winner.Root: true}
	for _, b := range collapsed {
		if notified[b.Root] {
			continue
		}
		notified[b.Root] = true
		if err := core.SysMail(ctx, q, b.Root, "lost "+a.ID, fmt.Sprintf("auction %s awarded to another bidder; your bond was returned", a.ID)); err != nil {
			return err
		}
	}
	return nil
}

// collapsedAndLosers returns every bid root except the winner's (for bond returns): one row per
// bidding root with a held bond.
func collapsedAndLosers(ctx context.Context, q core.Q, auctionID, winnerRoot string) []bidRow {
	rows, err := q.Query(ctx, `SELECT b.id, b.root FROM bids b JOIN bonds bo ON bo.ref = b.auction AND bo.root = b.root
		WHERE b.auction = $1 AND b.root <> $2 AND bo.state = 'held'`, auctionID, winnerRoot)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []bidRow
	for rows.Next() {
		var b bidRow
		if err := rows.Scan(&b.ID, &b.Root); err != nil {
			return out
		}
		out = append(out, b)
	}
	return out
}

// --- bonds ---

// returnBond gives a held bond back to the identity that paid it (grant class).
func returnBond(ctx context.Context, q core.Q, ref, payee, root string) error {
	var n int64
	err := q.QueryRow(ctx, `UPDATE bonds SET state = 'returned' WHERE ref = $1 AND root = $2 AND state = 'held' RETURNING credits`, ref, root).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return core.Refund(ctx, q, payee, n)
}

// forfeitBond burns a held bond (a winner who never submitted by the deadline).
func forfeitBond(ctx context.Context, q core.Q, ref, root string) error {
	var n int64
	err := q.QueryRow(ctx, `UPDATE bonds SET state = 'forfeited' WHERE ref = $1 AND root = $2 AND state = 'held' RETURNING credits`, ref, root).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return core.BurnHeld(ctx, q, n, "bond", ref)
}

// refundAllBonds returns every still-held bond of the auction to its bidder.
func refundAllBonds(ctx context.Context, q core.Q, auctionID string) error {
	rows, err := q.Query(ctx, `SELECT b.id, b.root FROM bids b JOIN bonds bo ON bo.ref = b.auction AND bo.root = b.root
		WHERE b.auction = $1 AND bo.state = 'held'`, auctionID)
	if err != nil {
		return err
	}
	type payee struct{ id, root string }
	var ps []payee
	for rows.Next() {
		var p payee
		if err := rows.Scan(&p.id, &p.root); err != nil {
			rows.Close()
			return err
		}
		ps = append(ps, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range ps {
		if err := returnBond(ctx, q, auctionID, p.id, p.root); err != nil {
			return err
		}
	}
	return nil
}

// --- janitor ---

// janitor (every 30 s) closes auctions past their deadline, then settles the winner bond of
// awarded auctions: returned once the winner has submitted, forfeited if the bounty deadline
// passed with no submission.
func (s *svc) janitor(ctx context.Context) error {
	if err := s.each(ctx, `SELECT id FROM auctions WHERE state IN `+liveStates+` AND closes_at < now() ORDER BY closes_at LIMIT 100`,
		func(tx pgx.Tx, a *auction) error {
			if !a.live() || a.ClosesAt.After(time.Now()) {
				return nil
			}
			return closeOne(ctx, tx, a)
		}); err != nil {
		return err
	}
	return s.each(ctx, `SELECT a.id FROM auctions a JOIN bonds bo ON bo.ref = a.id AND bo.root = a.winner_root
		WHERE a.state = 'awarded' AND a.winner_root <> '' AND bo.state = 'held' ORDER BY a.created LIMIT 100`,
		func(tx pgx.Tx, a *auction) error {
			if a.State != "awarded" || a.Bounty == "" {
				return nil
			}
			return s.settleWinnerBond(ctx, tx, a)
		})
}

// settleWinnerBond returns the winner's auction bond once the awarded bounty has a submission, or
// forfeits it once the bounty deadline passed with none.
func (s *svc) settleWinnerBond(ctx context.Context, q core.Q, a *auction) error {
	var state string
	var submitted bool
	var deadline time.Time
	err := q.QueryRow(ctx, `SELECT state, submitted_at IS NOT NULL, deadline FROM bounties WHERE id = $1`, a.Bounty).Scan(&state, &submitted, &deadline)
	if errors.Is(err, pgx.ErrNoRows) {
		// Bounty gone (paid out and purged, say): return the bond.
		return returnBond(ctx, q, a.ID, a.Winner, a.WinnerRoot)
	}
	if err != nil {
		return err
	}
	switch {
	case submitted || state == "paid":
		return returnBond(ctx, q, a.ID, a.Winner, a.WinnerRoot)
	case state == "refunded" || (state == "open" && deadline.Before(time.Now())):
		// Deadline reached with no submission: the winner forfeits the bond.
		return forfeitBond(ctx, q, a.ID, a.WinnerRoot)
	}
	return nil
}

// each runs fn for every id the query returns, each under its own locked transaction.
func (s *svc) each(ctx context.Context, sql string, fn func(tx pgx.Tx, a *auction) error) error {
	rows, err := s.d.DB.Query(ctx, sql)
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
			return fn(tx, a)
		})
		if err != nil {
			s.d.Log.Warn("auction janitor", "auction", id, "err", err)
		}
	}
	return nil
}
