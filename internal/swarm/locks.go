package swarm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Locks and leases (12.1): one row per name that outlives releases so the fence stays monotonic.
const (
	lockTTLDef         = 60
	lockTTLMax         = 3600
	lockWaitersPerName = 64
	lockWaitersPerRoot = 8
	lockRepCap         = 5 // lease expiry costs 1 rep, at most 5 per day (4.2)
)

// fencedErr is the 409 of a missing or stale fence; the detail is the current fence (10.3 wire).
func fencedErr(cur int64) *core.APIError { return core.E(409, "fenced", strconv.FormatInt(cur, 10)) }

func takenErr(holder string, until time.Time) *core.APIError {
	return core.E(409, "taken", holder+" "+unix(until))
}

type lockState struct {
	exists       bool
	holder, root string
	fence        int64
	until        time.Time
}

func (st lockState) held() bool { return st.exists && st.until.After(time.Now()) }

func (st lockState) line() string {
	if !st.held() {
		return fmt.Sprintf("free fence=%d", st.fence)
	}
	return fmt.Sprintf("held %s fence=%d until=%s", st.holder, st.fence, unix(st.until))
}

func lockStateOf(ctx context.Context, q core.Q, name string) (lockState, error) {
	var st lockState
	err := q.QueryRow(ctx, `SELECT holder, root, fence, until FROM locks WHERE name = $1`, name).
		Scan(&st.holder, &st.root, &st.fence, &st.until)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, nil
	}
	st.exists = err == nil
	return st, err
}

// expiredLock is a lease that ended without a release and still owes its expiry notice.
type expiredLock struct {
	name, holder, root, onExpire string
	fence                        int64
}

// notifyExpired wakes the waiters of an expired lease and publishes `lock-expired <name> fence=<n>
// holder=<id>` to its on_expire topic, else mails the holder root (NotifyExpired, nil-safe); the
// 4.2 lease-expiry penalty applies.
func notifyExpired(ctx context.Context, q core.Q, e expiredLock) {
	wake("lk:" + e.name)
	text := fmt.Sprintf("lock-expired %s fence=%d holder=%s", e.name, e.fence, e.holder)
	switch {
	case e.onExpire != "":
		if _, err := Publish(ctx, q, e.onExpire, core.SystemID, core.SystemID, text, ""); err != nil {
			slog.Warn("swarm lock expiry publish", "topic", e.onExpire, "err", err)
		}
	case NotifyExpired != nil:
		if err := NotifyExpired(ctx, q, e.root, "lock-expired "+e.name, text); err != nil {
			slog.Warn("swarm lock expiry mail", "root", e.root, "err", err)
		}
	}
	leaseExpired(ctx, q, e.root, e.name)
}

// leaseExpired applies the 4.2 lease-expiry penalty (-1 rep, at most 5 per day) and logs an event.
func leaseExpired(ctx context.Context, q core.Q, root, name string) {
	if root == "" || root == core.SystemID {
		return
	}
	n, err := bump(ctx, q, root, "rep:lease", 1)
	if err != nil || n > lockRepCap {
		return
	}
	core.AddRep(ctx, q, root, -1, "rep:lease", 0)
	core.Event(ctx, q, "lk", name, root, "lock expired "+name)
}

// AcquireTx takes or renews lock name for holder (an identity of root) inside tx: one statement
// `INSERT … ON CONFLICT DO UPDATE … WHERE until <= now()` (fence + 1), else the renewal path when
// root already holds it (same fence, at most since + 24 h), else `409 taken <holder> <until>`.
// Taking over a lease that expired unnoticed emits its expiry notice in the same transaction.
func AcquireTx(ctx context.Context, tx core.Q, name, holder, root string, ttl time.Duration) (int64, time.Time, error) {
	secs := max(1, int(ttl/time.Second))
	var prev *expiredLock
	var e expiredLock
	err := tx.QueryRow(ctx, `SELECT holder, root, fence, on_expire FROM locks WHERE name = $1 AND until <= now() AND NOT notified FOR UPDATE`, name).
		Scan(&e.holder, &e.root, &e.fence, &e.onExpire)
	switch {
	case err == nil:
		e.name = name
		prev = &e
	case !errors.Is(err, pgx.ErrNoRows):
		return 0, time.Time{}, err
	}
	var fence int64
	var until time.Time
	err = tx.QueryRow(ctx, `INSERT INTO locks (name, holder, root, fence, until, since, on_expire, notified)
		VALUES ($1, $2, $3, 1, now() + $4 * interval '1 second', now(), '', false)
		ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, root = EXCLUDED.root, fence = locks.fence + 1,
			until = EXCLUDED.until, since = now(), on_expire = '', notified = false
		WHERE locks.until <= now()
		RETURNING fence, until`, name, holder, root, secs).Scan(&fence, &until)
	if err == nil {
		if prev != nil {
			notifyExpired(ctx, tx, *prev)
		}
		return fence, until, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, time.Time{}, err
	}
	err = tx.QueryRow(ctx, `UPDATE locks SET until = least(now() + $3 * interval '1 second', since + interval '24 hours')
		WHERE name = $1 AND root = $2 AND until > now() RETURNING fence, until`, name, root, secs).Scan(&fence, &until)
	if err == nil {
		return fence, until, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, time.Time{}, err
	}
	st, err := lockStateOf(ctx, tx, name)
	if err != nil {
		return 0, time.Time{}, err
	}
	return 0, time.Time{}, takenErr(st.holder, st.until)
}

// CheckFence refuses a fenced write (KV g: puts, queue acks, bounty submissions) unless fence is
// the live fence of lock name: `409 fenced <current>`; the mem.FenceCheckFn implementation.
func CheckFence(ctx context.Context, q core.Q, name string, fence int64) error {
	st, err := lockStateOf(ctx, q, name)
	if err != nil {
		return err
	}
	if !st.held() || st.fence != fence {
		return fencedErr(st.fence)
	}
	return nil
}

// Handover passes a held lock to another identity in one guarded update (27.4): only the current
// fence may hand over; the fence increases, waiters are woken and the successor gets a sys mail
// `handover lk <name> fence=<n+1> from <id>` plus the note (through NotifyExpired, nil-safe).
func Handover(ctx context.Context, q core.Q, name string, fence int64, fromRoot, toHolder, toRoot string, ttl time.Duration, note string) (int64, time.Time, error) {
	if !core.ValidIDPrefix(toHolder, 'a') || !core.ValidIDPrefix(toRoot, 'a') {
		return 0, time.Time{}, core.Bad("to: identity id")
	}
	secs := max(1, int(ttl/time.Second))
	st, err := lockStateOf(ctx, q, name)
	if err != nil {
		return 0, time.Time{}, err
	}
	var newFence int64
	var until time.Time
	// AND root = $6 guards by the caller's root: the fence is public, so without this a stranger
	// could hand over (steal) a lock they do not hold.
	err = q.QueryRow(ctx, `UPDATE locks SET holder = $3, root = $4, fence = fence + 1, until = now() + $5 * interval '1 second',
			since = CASE WHEN root = $4 THEN since ELSE now() END, notified = false
		WHERE name = $1 AND fence = $2 AND root = $6 AND until > now() RETURNING fence, until`, name, fence, toHolder, toRoot, secs, fromRoot).Scan(&newFence, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, time.Time{}, fencedErr(st.fence)
	}
	if err != nil {
		return 0, time.Time{}, err
	}
	wake("lk:" + name)
	if NotifyExpired != nil {
		text := fmt.Sprintf("handover lk %s fence=%d from %s", name, newFence, st.holder)
		if note = doc.Indent(note); note != "" {
			text += "\nnote: " + note
		}
		if err := NotifyExpired(ctx, q, toRoot, "handover lk "+name, text); err != nil {
			return newFence, until, err
		}
	}
	return newFence, until, nil
}

// ReleaseByOwner releases lock name when root holds it (any fence), keeping the row so the fence
// stays monotonic, and wakes the waiters. Unknown or foreign locks are a no-op.
func ReleaseByOwner(ctx context.Context, q core.Q, root, name string) error {
	tag, err := q.Exec(ctx, `UPDATE locks SET until = now(), notified = true WHERE name = $1 AND root = $2 AND until > now()`, name, root)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		wake("lk:" + name)
	}
	return nil
}

// --- FIFO waiters (in-process, per name) -----------------------------------------------------

type lockWaiter struct {
	root string
	turn chan struct{} // closed when this waiter is the head of its queue
	head bool
}

type lockQueue struct {
	mu      sync.Mutex
	q       map[string][]*lockWaiter
	perRoot map[string]int
}

func newLockQueue() *lockQueue {
	return &lockQueue{q: map[string][]*lockWaiter{}, perRoot: map[string]int{}}
}

// enqueue appends a waiter (caps 64 per name, 8 per root); the first waiter gets its turn at once.
func (l *lockQueue) enqueue(name, root string) (*lockWaiter, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.q[name]) >= lockWaitersPerName || l.perRoot[root] >= lockWaitersPerRoot {
		return nil, false
	}
	w := &lockWaiter{root: root, turn: make(chan struct{})}
	if len(l.q[name]) == 0 {
		w.head = true
		close(w.turn)
	}
	l.q[name] = append(l.q[name], w)
	l.perRoot[root]++
	return w, true
}

// dequeue removes a waiter; when it was the head the next one gets its turn.
func (l *lockQueue) dequeue(name string, w *lockWaiter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	q := l.q[name]
	i := slices.Index(q, w)
	if i < 0 {
		return
	}
	q = slices.Delete(q, i, i+1)
	if len(q) == 0 {
		delete(l.q, name)
	} else {
		l.q[name] = q
		if w.head && !q[0].head {
			q[0].head = true
			close(q[0].turn)
		}
	}
	if l.perRoot[w.root]--; l.perRoot[w.root] <= 0 {
		delete(l.perRoot, w.root)
	}
}

func (l *lockQueue) isHead(w *lockWaiter) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return w.head
}

// --- service ------------------------------------------------------------------------------------

type lkIn struct {
	TTL      int `json:"ttl_s"`
	Wait     int `json:"wait"`
	OnExpire *struct {
		PS string `json:"ps"`
	} `json:"on_expire"`
}

func lockNext(n Name) []doc.Action {
	p := "/v1/lk/" + n.Full
	return []doc.Action{doc.POST(p+"/renew", "renew"), {Method: "DELETE", Path: p, Hint: "release"}, doc.GET(p, "state")}
}

func lockReply(n Name, fence int64, until time.Time) reply {
	return reply{text: fmt.Sprintf("ok fence=%d until=%s", fence, unix(until)), next: lockNext(n)}
}

// acquire is POST /v1/lk/{name} and op lk.
func (s *svc) acquire(ctx context.Context, id *core.Ident, raw string, in lkIn, grp string) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	ttl, err := checkRange("ttl_s", in.TTL, lockTTLDef, 1, lockTTLMax)
	if err != nil {
		return reply{}, err
	}
	if err := checkWait(in.Wait); err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if err := s.frozen("swarm"); err != nil {
		return reply{}, err
	}
	onExpire := ""
	if in.OnExpire != nil && in.OnExpire.PS != "" {
		tn, err := ParseName(in.OnExpire.PS, id.Root)
		if err != nil {
			return reply{}, core.Bad("on_expire.ps: topic name")
		}
		if err := Access(ctx, s.d.DB, id, tn, true); err != nil {
			return reply{}, err
		}
		onExpire = tn.Full
	}
	fence, until, taken, err := s.tryAcquire(ctx, id, n, ttl, onExpire)
	if err == nil {
		return lockReply(n, fence, until), nil
	}
	if taken == nil || in.Wait == 0 {
		return reply{}, err
	}
	return s.waitAcquire(ctx, id, n, ttl, onExpire, in.Wait, grp, *taken)
}

// tryAcquire runs one acquisition transaction (live-locks cap on a fresh take). When the lock is
// taken it also returns the state so waiters know the current lease deadline.
func (s *svc) tryAcquire(ctx context.Context, id *core.Ident, n Name, ttl int, onExpire string) (fence int64, until time.Time, taken *lockState, err error) {
	var fresh bool
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var holds bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM locks WHERE name = $1 AND root = $2 AND until > now())`, n.Full, id.Root).Scan(&holds); err != nil {
			return err
		}
		if !holds {
			if err := rootLock(ctx, tx, id.Root); err != nil {
				return err
			}
			if err := liveCap(ctx, tx, id.Root, "locks", `SELECT count(*) FROM locks WHERE root = $1 AND until > now()`); err != nil {
				return err
			}
		}
		f, u, err := AcquireTx(ctx, tx, n.Full, id.ID, id.Root, time.Duration(ttl)*time.Second)
		if err != nil {
			return err
		}
		fence, until, fresh = f, u, !holds
		if onExpire != "" {
			if _, err := tx.Exec(ctx, `UPDATE locks SET on_expire = $2 WHERE name = $1`, n.Full, onExpire); err != nil {
				return err
			}
		}
		return nil
	})
	var ae *core.APIError
	if errors.As(err, &ae) && ae.Code == "taken" {
		st, serr := lockStateOf(ctx, s.d.DB, n.Full)
		if serr != nil {
			return 0, time.Time{}, nil, serr
		}
		return 0, time.Time{}, &st, err
	}
	if err == nil && fresh {
		wake("lk:" + n.Full) // followers watching the fence learn the new holder
	}
	return fence, until, nil, err
}

// waitAcquire queues the caller behind the lock's FIFO waiters (64/name, 8/root, plus a d.Waiters
// slot) and retries at the head on every release, handover, expiry or wake until the wait ends.
func (s *svc) waitAcquire(ctx context.Context, id *core.Ident, n Name, ttl int, onExpire string, wait int, grp string, st lockState) (reply, error) {
	noSlot := core.E(409, "taken", st.holder+" "+unix(st.until)+" retry="+strconv.Itoa(retryNoW))
	if s.d.Shed(nil, "longpoll") {
		return reply{}, noSlot
	}
	release, ok := s.d.Waiters.Acquire(id.Root, grp)
	if !ok {
		return reply{}, noSlot
	}
	defer release()
	wt, ok := s.lq.enqueue(n.Full, id.Root)
	if !ok {
		return reply{}, noSlot
	}
	defer s.lq.dequeue(n.Full, wt)
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		c, cancel := s.d.Notify.Subscribe("lk:" + n.Full)
		var turn <-chan struct{}
		if s.lq.isHead(wt) {
			fence, until, taken, err := s.tryAcquire(ctx, id, n, ttl, onExpire)
			if err == nil {
				cancel()
				return lockReply(n, fence, until), nil
			}
			if taken == nil {
				cancel()
				return reply{}, err
			}
			st = *taken
		} else {
			turn = wt.turn
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			cancel()
			return reply{}, takenErr(st.holder, st.until)
		}
		if st.held() {
			rem = min(rem, time.Until(st.until)+50*time.Millisecond) // observe expiry without the janitor
		}
		rem = max(rem, 20*time.Millisecond)
		t := time.NewTimer(rem)
		select {
		case <-c:
		case <-turn:
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return reply{}, takenErr(st.holder, st.until)
		}
		t.Stop()
		cancel()
	}
}

type lkRenewIn struct {
	Fence int64 `json:"fence"`
	TTL   int   `json:"ttl_s"`
}

// renew is POST /v1/lk/{name}/renew and op lkr: ok only when the fence matches and root holds.
func (s *svc) renew(ctx context.Context, id *core.Ident, raw string, in lkRenewIn) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	ttl, err := checkRange("ttl_s", in.TTL, lockTTLDef, 1, lockTTLMax)
	if err != nil {
		return reply{}, err
	}
	if in.Fence <= 0 {
		return reply{}, core.Bad("fence required")
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	var until time.Time
	err = s.d.DB.QueryRow(ctx, `UPDATE locks SET until = least(now() + $3 * interval '1 second', since + interval '24 hours')
		WHERE name = $1 AND root = $2 AND fence = $4 AND until > now() RETURNING until`, n.Full, id.Root, ttl, in.Fence).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		st, serr := lockStateOf(ctx, s.d.DB, n.Full)
		if serr != nil {
			return reply{}, serr
		}
		if st.held() {
			return reply{}, takenErr(st.holder, st.until)
		}
		return reply{}, core.E(409, "taken", "free fence="+strconv.FormatInt(st.fence, 10))
	}
	if err != nil {
		return reply{}, err
	}
	return lockReply(n, in.Fence, until), nil
}

// release is DELETE /v1/lk/{name} and op lkd: `ok`, or `ok stale` for a stale fence.
func (s *svc) release(ctx context.Context, id *core.Ident, raw string, fence int64) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if fence <= 0 {
		return reply{}, core.Bad("fence required")
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	tag, err := s.d.DB.Exec(ctx, `UPDATE locks SET until = now(), notified = true WHERE name = $1 AND root = $2 AND fence = $3 AND until > now()`,
		n.Full, id.Root, fence)
	if err != nil {
		return reply{}, err
	}
	next := []doc.Action{doc.POST("/v1/lk/"+n.Full, "acquire"), doc.GET("/v1/lk/"+n.Full, "state")}
	if tag.RowsAffected() == 0 {
		return reply{text: "ok stale", next: next}, nil
	}
	wake("lk:" + n.Full)
	return reply{text: "ok", next: next}, nil
}

// lockGet is GET /v1/lk/{name} and op lkg; with wait it long-polls until the fence differs from
// ?fence= (or the lock is free), or until any change against the first snapshot.
func (s *svc) lockGet(ctx context.Context, id *core.Ident, raw string, wait int, fence int64, hasFence bool, grp string) (reply, error) {
	n, err := ParseName(raw, rootOf(id))
	if err != nil {
		return reply{}, err
	}
	if err := checkWait(wait); err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, false); err != nil {
		return reply{}, err
	}
	var st, base lockState
	first := true
	retry, err := s.pollHint(ctx, id, grp, wait, "lk:"+n.Full, func(ctx context.Context) (bool, time.Time, error) {
		cur, err := lockStateOf(ctx, s.d.DB, n.Full)
		if err != nil {
			return false, time.Time{}, err
		}
		st = cur
		var hint time.Time
		if cur.held() {
			hint = cur.until // the lease deadline is a state change too
		}
		if hasFence {
			return cur.fence != fence || !cur.held(), hint, nil
		}
		if first {
			first, base = false, cur
			return false, hint, nil
		}
		return cur.fence != base.fence || cur.held() != base.held(), hint, nil
	})
	if err != nil {
		return reply{}, err
	}
	text := st.line()
	if retry > 0 {
		text += " retry=" + strconv.Itoa(retry)
	}
	return reply{text: text, next: []doc.Action{doc.POST("/v1/lk/"+n.Full, "acquire"), doc.GET("/v1/lk/"+n.Full+"?wait=85&fence="+strconv.FormatInt(st.fence, 10), "watch")}}, nil
}

// --- HTTP ---------------------------------------------------------------------------------------

func (s *svc) lkAcquire(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in lkIn
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

func (s *svc) lkRenew(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in lkRenewIn
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

func (s *svc) lkRelease(w http.ResponseWriter, r *http.Request) {
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
	if in.Fence == 0 {
		if f, _, err := queryInt64(r, "fence"); err == nil {
			in.Fence = f
		}
	}
	rep, err := s.release(r.Context(), id, r.PathValue("name"), in.Fence)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) lkGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	wait, err := queryInt(r, "wait")
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	fence, hasFence, err := queryInt64(r, "fence")
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.lockGet(r.Context(), id, r.PathValue("name"), wait, fence, hasFence, s.grp(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

// --- janitor, report target --------------------------------------------------------------------

// janLocks sends expiry notices (on_expire topic or the holder root's mailbox), wakes waiters,
// charges the lease-expiry rep penalty and deletes rows idle for 7 days.
func (s *svc) janLocks(ctx context.Context) error {
	q := s.d.DB
	rows, err := q.Query(ctx, `UPDATE locks SET notified = true
		WHERE name IN (SELECT name FROM locks WHERE until <= now() AND NOT notified ORDER BY until LIMIT 200)
		RETURNING name, fence, holder, root, on_expire`)
	if err != nil {
		return err
	}
	var exps []expiredLock
	for rows.Next() {
		var e expiredLock
		if err := rows.Scan(&e.name, &e.fence, &e.holder, &e.root, &e.onExpire); err != nil {
			rows.Close()
			return err
		}
		exps = append(exps, e)
	}
	rows.Close()
	for _, e := range exps {
		notifyExpired(ctx, q, e)
	}
	_, err = q.Exec(ctx, `DELETE FROM locks WHERE until < now() - interval '7 days'`)
	return err
}

func (s *svc) lkExists(ctx context.Context, q core.Q, ref string) error {
	st, err := lockStateOf(ctx, q, ref)
	if err != nil {
		return err
	}
	if !st.exists {
		return core.ErrNotFound
	}
	return nil
}

// lkHide releases a reported lock (the row and its fence stay).
func (s *svc) lkHide(ctx context.Context, q core.Q, ref string) error {
	tag, err := q.Exec(ctx, `UPDATE locks SET until = now(), notified = true WHERE name = $1 AND until > now()`, ref)
	if err == nil && tag.RowsAffected() > 0 {
		wake("lk:" + ref)
	}
	return err
}

func (s *svc) lkRestore(context.Context, core.Q, string) error { return nil }
