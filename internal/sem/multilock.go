package sem

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/swarm"
)

const (
	lkmMin     = 2
	lkmMax     = 8
	lkmWaitCap = 85 // seconds
)

type lkmIn struct {
	Names    []string `json:"names"`
	TTL      int      `json:"ttl_s"`
	Wait     int      `json:"wait"`
	OnExpire *struct {
		PS string `json:"ps"`
	} `json:"on_expire"`
}

type lkmLine struct {
	name  string
	fence int64
	until time.Time
}

// multiLock is POST /v1/lkm and op lkm: take (or renew) every named lock in bytewise-sorted order
// inside one transaction so the global order is identical for every caller (no deadlock); any
// failure rolls the whole transaction back and answers 409 taken. With wait it subscribes to every
// lk:<name> and retries the whole transaction on any wake (85 s cap, cost 1 per name per attempt).
func (s *svc) multiLock(ctx context.Context, id *core.Ident, in lkmIn, grp string) (reply, error) {
	if len(in.Names) < lkmMin || len(in.Names) > lkmMax {
		return reply{}, core.Bad(fmt.Sprintf("names must be %d..%d", lkmMin, lkmMax))
	}
	ttl, err := checkRange("ttl_s", in.TTL, semTTLDef, 1, semTTLMax)
	if err != nil {
		return reply{}, err
	}
	if in.Wait < 0 || in.Wait > lkmWaitCap {
		return reply{}, core.Bad("wait must be 0.." + strconv.Itoa(lkmWaitCap))
	}
	if err := s.frozen(); err != nil {
		return reply{}, err
	}
	names := make([]swarm.Name, 0, len(in.Names))
	seen := map[string]bool{}
	for _, raw := range in.Names {
		n, err := swarm.ParseName(raw, id.Root)
		if err != nil {
			return reply{}, err
		}
		if seen[n.Full] {
			return reply{}, core.Bad("duplicate name " + n.Full)
		}
		seen[n.Full] = true
		if err := swarm.Access(ctx, s.d.DB, id, n, true); err != nil {
			return reply{}, err
		}
		names = append(names, n)
	}
	slices.SortFunc(names, func(a, b swarm.Name) int {
		if a.Full < b.Full {
			return -1
		}
		if a.Full > b.Full {
			return 1
		}
		return 0
	})
	onExpire := ""
	if in.OnExpire != nil && in.OnExpire.PS != "" {
		tn, err := swarm.ParseName(in.OnExpire.PS, id.Root)
		if err != nil {
			return reply{}, core.Bad("on_expire.ps: topic name")
		}
		if err := swarm.Access(ctx, s.d.DB, id, tn, true); err != nil {
			return reply{}, err
		}
		onExpire = tn.Full
	}
	lines, taken, err := s.lkmTry(ctx, id, names, ttl, onExpire)
	if err == nil {
		return lkmReply(lines), nil
	}
	if taken == nil || in.Wait == 0 {
		return reply{}, err
	}
	return s.lkmWait(ctx, id, names, ttl, onExpire, in.Wait, grp)
}

// lkmTry runs one all-or-nothing transaction. taken is non-nil (the blocking lock's error) when a
// name was held by someone else, so the caller may long-poll.
func (s *svc) lkmTry(ctx context.Context, id *core.Ident, names []swarm.Name, ttl int, onExpire string) (lines []lkmLine, taken *core.APIError, err error) {
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		lines = lines[:0]
		for _, n := range names {
			// Only a fresh take counts against the live-locks cap; renewals do not.
			var holds bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM locks WHERE name = $1 AND root = $2 AND until > now())`, n.Full, id.Root).Scan(&holds); err != nil {
				return err
			}
			if !holds {
				if err := liveLocksCap(ctx, tx, id.Root); err != nil {
					return err
				}
			}
			f, u, aerr := swarm.AcquireTx(ctx, tx, n.Full, id.ID, id.Root, time.Duration(ttl)*time.Second)
			if ae, ok := aerr.(*core.APIError); ok && ae.Code == "taken" {
				// Name the blocking lock in the all-or-nothing failure (27.4 wire).
				return core.E(409, "taken", n.Full+" "+ae.Msg)
			}
			if aerr != nil {
				return aerr
			}
			if onExpire != "" {
				if _, err := tx.Exec(ctx, `UPDATE locks SET on_expire = $2 WHERE name = $1`, n.Full, onExpire); err != nil {
					return err
				}
			}
			lines = append(lines, lkmLine{n.Full, f, u})
		}
		return nil
	})
	var ae *core.APIError
	if errors.As(err, &ae) && ae.Code == "taken" {
		return nil, ae, err
	}
	if err != nil {
		return nil, nil, err
	}
	for _, l := range lines {
		s.wake("lk:" + l.name)
	}
	return lines, nil, nil
}

// lkmWait retries the whole multi-lock transaction on any wake across every lock until it succeeds
// or the wait ends.
func (s *svc) lkmWait(ctx context.Context, id *core.Ident, names []swarm.Name, ttl int, onExpire string, wait int, grp string) (reply, error) {
	if s.d.Shed(nil, "longpoll") {
		return reply{}, s.lkmNoSlot(ctx, names)
	}
	release, ok := s.d.Waiters.Acquire(id.Root, grp)
	if !ok {
		return reply{}, s.lkmNoSlot(ctx, names)
	}
	defer release()
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		cancels := make([]func(), 0, len(names))
		chans := make([]<-chan struct{}, 0, len(names))
		for _, n := range names {
			c, cancel := s.d.Notify.Subscribe("lk:" + n.Full)
			chans = append(chans, c)
			cancels = append(cancels, cancel)
		}
		lines, taken, err := s.lkmTry(ctx, id, names, ttl, onExpire)
		if err == nil {
			for _, c := range cancels {
				c()
			}
			return lkmReply(lines), nil
		}
		if taken == nil {
			for _, c := range cancels {
				c()
			}
			return reply{}, err
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			for _, c := range cancels {
				c()
			}
			return reply{}, taken
		}
		rem = max(rem, 20*time.Millisecond)
		fired := waitAny(ctx, chans, rem)
		for _, c := range cancels {
			c()
		}
		if !fired {
			// timer or ctx done: one last check at the deadline falls through on the next loop.
			if time.Now().After(deadline) {
				_, taken, _ := s.lkmTry(ctx, id, names, ttl, onExpire)
				if taken != nil {
					return reply{}, taken
				}
			}
		}
		if ctx.Err() != nil {
			return reply{}, s.lkmNoSlot(ctx, names)
		}
	}
}

// waitAny blocks until any channel fires, the timeout elapses or ctx is done; true when a channel
// fired.
func waitAny(ctx context.Context, chans []<-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	// A small fan-in: select over up to 8 channels plus the timer and ctx.
	switch len(chans) {
	case 0:
		select {
		case <-t.C:
		case <-ctx.Done():
		}
		return false
	}
	// Build a reflect-free select by chaining; 2..8 names, so a goroutine fan-in is simplest.
	done := make(chan struct{}, 1)
	stop := make(chan struct{})
	for _, c := range chans {
		go func(c <-chan struct{}) {
			select {
			case <-c:
				select {
				case done <- struct{}{}:
				default:
				}
			case <-stop:
			}
		}(c)
	}
	defer close(stop)
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}

func (s *svc) lkmNoSlot(ctx context.Context, names []swarm.Name) error {
	_, taken, _ := s.lkmTry(ctx, nil, names, 1, "")
	if taken != nil {
		return taken
	}
	return core.E(409, "taken", "retry")
}

func lkmReply(lines []lkmLine) reply {
	text := "ok"
	for _, l := range lines {
		text += fmt.Sprintf("\n%s fence=%d until=%s", l.name, l.fence, unix(l.until))
	}
	return reply{text: text, next: []doc.Action{{Method: "DELETE", Path: "/v1/lkm", Hint: "release"}}}
}

type lkmRelIn struct {
	Locks []struct {
		Name  string `json:"name"`
		Fence int64  `json:"fence"`
	} `json:"locks"`
}

// multiRelease is DELETE /v1/lkm and op lkmd: release each named lock the caller holds at the given
// fence; stale fences are a no-op.
func (s *svc) multiRelease(ctx context.Context, id *core.Ident, in lkmRelIn) (reply, error) {
	if len(in.Locks) == 0 || len(in.Locks) > lkmMax {
		return reply{}, core.Bad(fmt.Sprintf("locks must be 1..%d", lkmMax))
	}
	text := "ok"
	for _, l := range in.Locks {
		n, err := swarm.ParseName(l.Name, id.Root)
		if err != nil {
			return reply{}, err
		}
		if err := swarm.Access(ctx, s.d.DB, id, n, true); err != nil {
			return reply{}, err
		}
		tag, err := s.d.DB.Exec(ctx, `UPDATE locks SET until = now(), notified = true WHERE name = $1 AND root = $2 AND fence = $3 AND until > now()`,
			n.Full, id.Root, l.Fence)
		if err != nil {
			return reply{}, err
		}
		if tag.RowsAffected() > 0 {
			s.wake("lk:" + n.Full)
			text += "\n" + n.Full + " released"
		} else {
			text += "\n" + n.Full + " stale"
		}
	}
	return reply{text: text}, nil
}

// --- handover (locks, permits, claims) ----------------------------------------------------------

type handoverIn struct {
	Fence int64  `json:"fence"`
	To    string `json:"to"`
	TTL   int    `json:"ttl_s"`
	Note  string `json:"note"`
}

// lockHandover is POST /v1/lk/{name}/handover and op lkh: hand a held lock to an eligible recipient
// (swarm.Handover, fence+1) with a sys mail carrying the note. "to":"waiter" is reserved for a FIFO
// waiter and resolves to a bad-request until implemented.
func (s *svc) lockHandover(ctx context.Context, id *core.Ident, raw string, in handoverIn) (reply, error) {
	n, err := swarm.ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if in.Fence <= 0 {
		return reply{}, core.Bad("fence required")
	}
	ttl, err := checkRange("ttl_s", in.TTL, semTTLDef, 1, semTTLMax)
	if err != nil {
		return reply{}, err
	}
	if err := swarm.Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	toID, toRoot, err := s.resolveTo(ctx, id, n, in.To)
	if err != nil {
		return reply{}, err
	}
	note, err := cleanNote(in.Note)
	if err != nil {
		return reply{}, err
	}
	if err := s.eligibleTo(ctx, n, toID, toRoot); err != nil {
		return reply{}, err
	}
	if err := s.foreignHandover(ctx, s.d.DB, id.Root, toRoot); err != nil {
		return reply{}, err
	}
	fence, until, err := swarm.Handover(ctx, s.d.DB, n.Full, in.Fence, id.Root, toID, toRoot, time.Duration(ttl)*time.Second, note)
	if err != nil {
		return reply{}, err
	}
	return reply{text: fmt.Sprintf("ok handover lk %s fence=%d to=%s until=%s", n.Full, fence, toID, unix(until))}, nil
}

// resolveTo validates the "to" recipient. "waiter" is not yet supported.
func (s *svc) resolveTo(ctx context.Context, id *core.Ident, n swarm.Name, to string) (string, string, error) {
	if to == "waiter" {
		return "", "", core.Bad("to: waiter not supported")
	}
	if !core.ValidIDPrefix(to, 'a') {
		return "", "", core.Bad("to: identity id")
	}
	var root string
	err := s.d.DB.QueryRow(ctx, `SELECT root FROM identities WHERE id = $1`, to).Scan(&root)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", core.E(409, "bad", "to not live")
	}
	if err != nil {
		return "", "", err
	}
	return to, root, nil
}

// permitHandover is POST /v1/sm/{name}/{slot}/handover and op smh: hand a held permit to an
// eligible recipient (UPDATE guarded by fence, fence+1) with a sys mail.
func (s *svc) permitHandover(ctx context.Context, id *core.Ident, raw string, slot int, in handoverIn) (reply, error) {
	n, err := swarm.ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if slot <= 0 || in.Fence <= 0 {
		return reply{}, core.Bad("slot and fence required")
	}
	ttl, err := checkRange("ttl_s", in.TTL, semTTLDef, 1, semTTLMax)
	if err != nil {
		return reply{}, err
	}
	if err := swarm.Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	toID, toRoot, err := s.resolveTo(ctx, id, n, in.To)
	if err != nil {
		return reply{}, err
	}
	note, err := cleanNote(in.Note)
	if err != nil {
		return reply{}, err
	}
	if err := s.eligibleTo(ctx, n, toID, toRoot); err != nil {
		return reply{}, err
	}
	var newFence int64
	var until time.Time
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := s.foreignHandover(ctx, tx, id.Root, toRoot); err != nil {
			return err
		}
		// Guard by the caller's root: the fence is public (status leaks it), so without this a
		// stranger could hand over (steal/reassign) a permit they do not hold. Only the current
		// holder's root may hand it over.
		e := tx.QueryRow(ctx, `UPDATE sem_permits SET holder = $4, root = $5, fence = fence + 1,
				until = now() + $6 * interval '1 second',
				since = CASE WHEN root = $5 THEN since ELSE now() END, notified = false
			WHERE name = $1 AND slot = $2 AND fence = $3 AND root = $7 AND until > now()
			RETURNING fence, until`, n.Full, slot, in.Fence, toID, toRoot, ttl, id.Root).Scan(&newFence, &until)
		if errors.Is(e, pgx.ErrNoRows) {
			st, serr := semStateOf(ctx, tx, n.Full)
			if serr != nil {
				return serr
			}
			return core.E(409, "fenced", strconv.FormatInt(st.fence, 10))
		}
		if e != nil {
			return e
		}
		// Bump the shared sem fence so later acquisitions stay monotonic past this permit.
		if _, err := tx.Exec(ctx, `UPDATE sems SET fence = greatest(fence, $2) WHERE name = $1`, n.Full, newFence); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return reply{}, err
	}
	s.wake("sm:" + n.Full)
	if swarm.NotifyExpired != nil {
		text := fmt.Sprintf("handover sm %s slot=%d fence=%d from %s", n.Full, slot, newFence, id.ID)
		if note != "" {
			text += "\nnote: " + doc.Indent(note)
		}
		if err := swarm.NotifyExpired(ctx, s.d.DB, toRoot, "handover sm "+n.Full, text); err != nil {
			return reply{}, err
		}
	}
	return reply{text: fmt.Sprintf("ok handover sm %s slot=%d fence=%d to=%s until=%s", n.Full, slot, newFence, toID, unix(until))}, nil
}

// --- HTTP --------------------------------------------------------------------------------------

func (s *svc) lkmAcquire(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in lkmIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.multiLock(r.Context(), id, in, s.grp(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) lkmRelease(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in lkmRelIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.multiRelease(r.Context(), id, in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) lkHandover(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in handoverIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.lockHandover(r.Context(), id, r.PathValue("name"), in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) smHandover(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in handoverIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	slot, err := strconv.Atoi(r.PathValue("slot"))
	if err != nil {
		doc.Fail(w, r, core.Bad("slot must be an integer"))
		return
	}
	rep, err := s.permitHandover(r.Context(), id, r.PathValue("name"), slot, in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}
