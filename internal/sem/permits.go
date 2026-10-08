package sem

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/swarm"
	"ekaii.fr/commons/internal/trust"
)

// semState is a semaphore's row plus its live permit count.
type semState struct {
	exists     bool
	n, perRoot int
	fence      int64
	free       int
	nextFree   time.Time // the earliest lease deadline when full (for the 409 until= hint)
}

func fullErr(st semState) *core.APIError {
	hint := "0"
	if !st.nextFree.IsZero() {
		hint = unix(st.nextFree)
	}
	return core.E(409, "full", fmt.Sprintf("free=0/%d until=%s", st.n, hint))
}

// semStateOf reads a semaphore and its current free count (held permits are until > now()).
func semStateOf(ctx context.Context, q core.Q, name string) (semState, error) {
	var st semState
	err := q.QueryRow(ctx, `SELECT n, per_root, fence FROM sems WHERE name = $1`, name).Scan(&st.n, &st.perRoot, &st.fence)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.exists = true
	var held int
	var next *time.Time
	if err := q.QueryRow(ctx, `SELECT count(*), min(until) FROM sem_permits WHERE name = $1 AND until > now()`, name).Scan(&held, &next); err != nil {
		return st, err
	}
	st.free = st.n - held
	if next != nil {
		st.nextFree = *next
	}
	return st, nil
}

type smIn struct {
	N        int `json:"n"`
	TTL      int `json:"ttl_s"`
	Wait     int `json:"wait"`
	PerRoot  int `json:"per_root"`
	OnExpire *struct {
		PS string `json:"ps"`
	} `json:"on_expire"`
}

func semNext(name string, slot int) []doc.Action {
	p := "/v1/sm/" + name
	sp := p + "/" + strconv.Itoa(slot)
	return []doc.Action{doc.POST(p+"/renew", "renew"), {Method: "DELETE", Path: sp, Hint: "release"},
		doc.POST(sp+"/handover", "handover"), doc.GET(p, "state")}
}

func semReply(name string, slot int, fence int64, until time.Time, free, n int) reply {
	return reply{
		text: fmt.Sprintf("ok slot=%d fence=%d until=%s free=%d/%d", slot, fence, unix(until), free, n),
		next: semNext(name, slot),
	}
}

// acquire is POST /v1/sm/{name} and op sm: upsert the semaphore (creator fixes n/per_root), bump
// the fence and take the lowest free slot in one transaction, honouring the per-root ceiling and
// the live-locks cap; zero rows -> 409 full or long-poll on sm:<name>.
func (s *svc) acquire(ctx context.Context, id *core.Ident, raw string, in smIn, grp string) (reply, error) {
	n, err := swarm.ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	width, err := checkRange("n", in.N, 1, 1, 64)
	if err != nil {
		return reply{}, err
	}
	ttl, err := checkRange("ttl_s", in.TTL, semTTLDef, 1, semTTLMax)
	if err != nil {
		return reply{}, err
	}
	if err := checkWait(in.Wait); err != nil {
		return reply{}, err
	}
	if in.PerRoot != 0 && (in.PerRoot < 1 || in.PerRoot > 64) {
		return reply{}, core.Bad("per_root must be 1..64")
	}
	if err := swarm.Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if err := s.frozen(); err != nil {
		return reply{}, err
	}
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
	slot, fence, until, free, full, err := s.try(ctx, id, n, width, in.PerRoot, ttl, onExpire)
	if err == nil {
		return semReply(n.Full, slot, fence, until, free, width), nil
	}
	if full == nil || in.Wait == 0 {
		return reply{}, err
	}
	return s.wait(ctx, id, n, width, in.PerRoot, ttl, onExpire, in.Wait, grp, *full)
}

// try runs one acquisition transaction. full is non-nil (with the current state) when the attempt
// failed because no slot was free for this caller, so the caller may long-poll.
func (s *svc) try(ctx context.Context, id *core.Ident, n swarm.Name, width, perRoot, ttl int, onExpire string) (slot int, fence int64, until time.Time, free int, full *semState, err error) {
	var st semState
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		// Serialise this semaphore's acquisitions (also guards the per-root ceiling and free scan).
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('sm:' || $1))`, n.Full); err != nil {
			return err
		}
		pr := perRoot
		if pr == 0 {
			pr = (width + 1) / 2 // ceil(n/2)
		}
		var effFence int64
		var effN, effPR int
		err := tx.QueryRow(ctx, `INSERT INTO sems (name, n, per_root, owner_root, fence, idle_since)
			VALUES ($1, $2, $3, $4, 1, now())
			ON CONFLICT (name) DO UPDATE SET fence = sems.fence + 1, idle_since = now()
			RETURNING fence, n, per_root`, n.Full, width, pr, id.Root).Scan(&effFence, &effN, &effPR)
		if err != nil {
			return err
		}
		if effN != width {
			return core.E(409, "bad", "n="+strconv.Itoa(effN))
		}
		st.exists, st.n, st.perRoot, st.fence = true, effN, effPR, effFence
		// Count this root's live permits for the per-root ceiling.
		var mine, held int
		var next *time.Time
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE root = $2 AND until > now()),
			count(*) FILTER (WHERE until > now()), min(until) FILTER (WHERE until > now())
			FROM sem_permits WHERE name = $1`, n.Full, id.Root).Scan(&mine, &held, &next); err != nil {
			return err
		}
		st.free = effN - held
		if next != nil {
			st.nextFree = *next
		}
		if mine >= effPR {
			full = &st
			return errFull
		}
		// Live-locks cap: locks + permits held by this root (4.3), only for a fresh take.
		if err := liveLocksCap(ctx, tx, id.Root); err != nil {
			return err
		}
		// Lowest free slot (never created, or created and lapsed).
		var free1 *int
		if err := tx.QueryRow(ctx, `SELECT s FROM generate_series(1, $2) AS s
			WHERE NOT EXISTS (SELECT 1 FROM sem_permits p WHERE p.name = $1 AND p.slot = s AND p.until > now())
			ORDER BY s LIMIT 1`, n.Full, effN).Scan(&free1); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				full = &st
				return errFull
			}
			return err
		}
		if free1 == nil {
			full = &st
			return errFull
		}
		slot = *free1
		fence = effFence
		err = tx.QueryRow(ctx, `INSERT INTO sem_permits (name, slot, holder, root, fence, since, until, on_expire, notified)
			VALUES ($1, $2, $3, $4, $5, now(), now() + $6 * interval '1 second', $7, false)
			ON CONFLICT (name, slot) DO UPDATE SET holder = EXCLUDED.holder, root = EXCLUDED.root,
				fence = EXCLUDED.fence, since = now(), until = EXCLUDED.until, on_expire = EXCLUDED.on_expire, notified = false
			WHERE sem_permits.until < now()
			RETURNING until`, n.Full, slot, id.ID, id.Root, effFence, ttl, onExpire).Scan(&until)
		if errors.Is(err, pgx.ErrNoRows) { // lost the slot to a concurrent take
			full = &st
			return errFull
		}
		if err != nil {
			return err
		}
		st.free = effN - held - 1
		return nil
	})
	if errors.Is(err, errFull) {
		return 0, 0, time.Time{}, 0, full, fullErr(st)
	}
	if err != nil {
		return 0, 0, time.Time{}, 0, nil, err
	}
	s.wake("sm:" + n.Full)
	return slot, fence, until, st.free, nil, nil
}

var errFull = errors.New("sem full")

// liveLocksCap refuses a new live object when a root's locks + permits reach the shared cap (4.3).
func liveLocksCap(ctx context.Context, q core.Q, root string) error {
	var n int
	if err := q.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM locks WHERE root = $1 AND until > now())
		+ (SELECT count(*) FROM sem_permits WHERE root = $1 AND until > now())`, root).Scan(&n); err != nil {
		return err
	}
	if capN := trust.Cap("locks", core.Level(ctx, q, root)); n >= capN {
		return quotaErr("locks live", capN)
	}
	return nil
}

// wait queues the caller on sm:<name> and retries the acquisition on every wake until a slot frees
// or the wait ends (3.6: tokens only, a d.Waiters slot, shed:longpoll).
func (s *svc) wait(ctx context.Context, id *core.Ident, n swarm.Name, width, perRoot, ttl int, onExpire string, wait int, grp string, st semState) (reply, error) {
	noSlot := fullErr(st)
	if s.d.Shed(nil, "longpoll") {
		return reply{}, noSlot
	}
	release, ok := s.d.Waiters.Acquire(id.Root, grp)
	if !ok {
		return reply{}, noSlot
	}
	defer release()
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		c, cancel := s.d.Notify.Subscribe("sm:" + n.Full)
		slot, fence, until, free, full, err := s.try(ctx, id, n, width, perRoot, ttl, onExpire)
		if err == nil {
			cancel()
			return semReply(n.Full, slot, fence, until, free, width), nil
		}
		if full == nil {
			cancel()
			return reply{}, err
		}
		st = *full
		rem := time.Until(deadline)
		if rem <= 0 {
			cancel()
			return reply{}, fullErr(st)
		}
		if !st.nextFree.IsZero() {
			rem = min(rem, time.Until(st.nextFree)+50*time.Millisecond)
		}
		rem = max(rem, 20*time.Millisecond)
		t := time.NewTimer(rem)
		select {
		case <-c:
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return reply{}, fullErr(st)
		}
		t.Stop()
		cancel()
	}
}

type smRenewIn struct {
	Slot  int   `json:"slot"`
	Fence int64 `json:"fence"`
	TTL   int   `json:"ttl_s"`
}

// renew is POST /v1/sm/{name}/renew and op smr: ok only when the slot's fence matches and the
// caller's root holds it; the lease extends up to since + 24 h.
func (s *svc) renew(ctx context.Context, id *core.Ident, raw string, in smRenewIn) (reply, error) {
	n, err := swarm.ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	ttl, err := checkRange("ttl_s", in.TTL, semTTLDef, 1, semTTLMax)
	if err != nil {
		return reply{}, err
	}
	if in.Slot <= 0 || in.Fence <= 0 {
		return reply{}, core.Bad("slot and fence required")
	}
	if err := swarm.Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	var until time.Time
	err = s.d.DB.QueryRow(ctx, `UPDATE sem_permits SET until = least(now() + $4 * interval '1 second', since + interval '24 hours')
		WHERE name = $1 AND slot = $2 AND root = $3 AND fence = $5 AND until > now() RETURNING until`,
		n.Full, in.Slot, id.Root, ttl, in.Fence).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		st, serr := semStateOf(ctx, s.d.DB, n.Full)
		if serr != nil {
			return reply{}, serr
		}
		return reply{}, core.E(409, "fenced", strconv.FormatInt(st.fence, 10))
	}
	if err != nil {
		return reply{}, err
	}
	free, width := s.freeCount(ctx, n.Full)
	return semReply(n.Full, in.Slot, in.Fence, until, free, width), nil
}

func (s *svc) freeCount(ctx context.Context, name string) (int, int) {
	st, err := semStateOf(ctx, s.d.DB, name)
	if err != nil {
		return 0, 0
	}
	return st.free, st.n
}

// release is DELETE /v1/sm/{name}/{slot} and op smd: ok, or 200 ok stale for a stale fence.
func (s *svc) release(ctx context.Context, id *core.Ident, raw string, slot int, fence int64) (reply, error) {
	n, err := swarm.ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if slot <= 0 || fence <= 0 {
		return reply{}, core.Bad("slot and fence required")
	}
	if err := swarm.Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	tag, err := s.d.DB.Exec(ctx, `UPDATE sem_permits SET until = now(), notified = true
		WHERE name = $1 AND slot = $2 AND root = $3 AND fence = $4 AND until > now()`, n.Full, slot, id.Root, fence)
	if err != nil {
		return reply{}, err
	}
	next := []doc.Action{doc.POST("/v1/sm/"+n.Full, "acquire"), doc.GET("/v1/sm/"+n.Full, "state")}
	if tag.RowsAffected() == 0 {
		return reply{text: "ok stale", next: next}, nil
	}
	s.wake("sm:" + n.Full)
	return reply{text: "ok", next: next}, nil
}

// semGet is GET /v1/sm/{name} and op smg (anonymous for g:): free/held counts.
func (s *svc) semGet(ctx context.Context, id *core.Ident, raw string) (reply, error) {
	root := ""
	if id != nil {
		root = id.Root
	}
	n, err := swarm.ParseName(raw, root)
	if err != nil {
		return reply{}, err
	}
	if err := swarm.Access(ctx, s.d.DB, id, n, false); err != nil {
		return reply{}, err
	}
	st, err := semStateOf(ctx, s.d.DB, n.Full)
	if err != nil {
		return reply{}, err
	}
	if !st.exists {
		return reply{}, core.ErrNotFound
	}
	text := fmt.Sprintf("sm %s free=%d/%d fence=%d", n.Full, st.free, st.n, st.fence)
	rows, err := s.d.DB.Query(ctx, `SELECT slot, holder, fence, until FROM sem_permits WHERE name = $1 AND until > now() ORDER BY slot`, n.Full)
	if err != nil {
		return reply{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var slot int
		var holder string
		var f int64
		var until time.Time
		if err := rows.Scan(&slot, &holder, &f, &until); err != nil {
			return reply{}, err
		}
		text += fmt.Sprintf("\n- slot=%d %s fence=%d until=%s", slot, holder, f, unix(until))
	}
	return reply{text: text, next: []doc.Action{doc.POST("/v1/sm/"+n.Full, "acquire")}}, nil
}

// CheckFence refuses a fenced write unless fence is the live fence of permit ref "sm:<name>/<slot>"
// (the mem.FenceCheckFn implementation for the sm: prefix, P60a).
func CheckFence(ctx context.Context, q core.Q, ref string, fence int64) error {
	name, slot, ok := splitPermitRef(ref)
	if !ok {
		return core.Bad("fence ref")
	}
	var f int64
	var held bool
	err := q.QueryRow(ctx, `SELECT fence, until > now() FROM sem_permits WHERE name = $1 AND slot = $2`, name, slot).Scan(&f, &held)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.E(409, "fenced", "0")
	}
	if err != nil {
		return err
	}
	if !held || f != fence {
		return core.E(409, "fenced", strconv.FormatInt(f, 10))
	}
	return nil
}

// splitPermitRef parses "sm:<name>/<slot>" into its name and slot.
func splitPermitRef(ref string) (name string, slot int, ok bool) {
	i := len(ref) - 1
	for ; i >= 0; i-- {
		if ref[i] == '/' {
			break
		}
	}
	if i <= 0 {
		return "", 0, false
	}
	s, err := strconv.Atoi(ref[i+1:])
	if err != nil || s <= 0 {
		return "", 0, false
	}
	return ref[:i], s, true
}

// --- HTTP --------------------------------------------------------------------------------------

func (s *svc) smAcquire(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in smIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.acquire(r.Context(), id, r.PathValue("name"), in, s.grp(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) smRenew(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in smRenewIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.renew(r.Context(), id, r.PathValue("name"), in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) smRelease(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		Fence int64 `json:"fence"`
	}
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	slot, err := strconv.Atoi(r.PathValue("slot"))
	if err != nil {
		doc.Fail(w, r, core.Bad("slot must be an integer"))
		return
	}
	rep, err := s.release(r.Context(), id, r.PathValue("name"), slot, in.Fence)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) smGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.semGet(r.Context(), id, r.PathValue("name"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

// --- janitor, purge, report target --------------------------------------------------------------

type expiredPermit struct {
	name, holder, root, onExpire string
	slot                         int
	fence                        int64
}

// janPermits emits the one-shot expiry notice for lapsed permits (publish permit-expired to
// on_expire, else mail the holder root), wakes waiters, charges the lease-expiry rep penalty and
// deletes permits of idle semaphores.
func (s *svc) janPermits(ctx context.Context) error {
	q := s.d.DB
	rows, err := q.Query(ctx, `UPDATE sem_permits SET notified = true
		WHERE (name, slot) IN (SELECT name, slot FROM sem_permits WHERE until <= now() AND NOT notified ORDER BY until LIMIT 200)
		RETURNING name, slot, holder, root, fence, on_expire`)
	if err != nil {
		return err
	}
	var exps []expiredPermit
	for rows.Next() {
		var e expiredPermit
		if err := rows.Scan(&e.name, &e.slot, &e.holder, &e.root, &e.fence, &e.onExpire); err != nil {
			rows.Close()
			return err
		}
		exps = append(exps, e)
	}
	rows.Close()
	for _, e := range exps {
		s.notifyExpired(ctx, q, e)
	}
	// Reap semaphores idle (no live permits) for 7 days.
	_, err = q.Exec(ctx, `DELETE FROM sems WHERE idle_since < now() - interval '7 days'
		AND NOT EXISTS (SELECT 1 FROM sem_permits p WHERE p.name = sems.name AND p.until > now())`)
	return err
}

// notifyExpired wakes the waiters of a lapsed permit, publishes permit-expired to on_expire (else
// mails the holder root) and applies the 4.2 lease-expiry penalty.
func (s *svc) notifyExpired(ctx context.Context, q core.Q, e expiredPermit) {
	s.wake("sm:" + e.name)
	text := fmt.Sprintf("permit-expired %s slot=%d holder=%s", e.name, e.slot, e.holder)
	switch {
	case e.onExpire != "":
		if _, err := swarm.Publish(ctx, q, e.onExpire, core.SystemID, core.SystemID, text, ""); err != nil {
			slog.Warn("sem permit expiry publish", "topic", e.onExpire, "err", err)
		}
	case swarm.NotifyExpired != nil:
		if err := swarm.NotifyExpired(ctx, q, e.root, "permit-expired "+e.name, text); err != nil {
			slog.Warn("sem permit expiry mail", "root", e.root, "err", err)
		}
	}
	s.leaseExpired(ctx, q, e.root, e.name)
}

// leaseExpired applies the 4.2 lease-expiry penalty (-1 rep, at most 5 per day) and logs an event.
func (s *svc) leaseExpired(ctx context.Context, q core.Q, root, name string) {
	if root == "" || root == core.SystemID {
		return
	}
	n, err := bump(ctx, q, root, "rep:lease", 1)
	if err != nil || n > leaseRepCap {
		return
	}
	core.AddRep(ctx, q, root, -1, "rep:lease", 0)
	core.Event(ctx, q, "sm", name, root, "permit expired "+name)
}

// purge releases the root's permits and erases the semaphores it owns (OnPurge).
func (s *svc) purge(ctx context.Context, root string) error {
	q := s.d.DB
	rows, err := q.Query(ctx, `UPDATE sem_permits SET until = now(), notified = true WHERE root = $1 AND until > now() RETURNING name`, root)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	rows.Close()
	for _, n := range names {
		s.wake("sm:" + n)
	}
	own := "a:" + root + ".%"
	if _, err := q.Exec(ctx, `DELETE FROM sem_permits WHERE name LIKE $1`, own); err != nil {
		return err
	}
	_, err = q.Exec(ctx, `DELETE FROM sems WHERE name LIKE $1 OR owner_root = $2`, own, root)
	return err
}

func (s *svc) smExists(ctx context.Context, q core.Q, ref string) error {
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sems WHERE name = $1)`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

// smHide releases every live permit of a reported semaphore (the rows and fence stay).
func (s *svc) smHide(ctx context.Context, q core.Q, ref string) error {
	tag, err := q.Exec(ctx, `UPDATE sem_permits SET until = now(), notified = true WHERE name = $1 AND until > now()`, ref)
	if err == nil && tag.RowsAffected() > 0 {
		s.wake("sm:" + ref)
	}
	return err
}

func (s *svc) smRestore(context.Context, core.Q, string) error { return nil }
