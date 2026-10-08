package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Deps is shared by every package's Register(mux, d).
type Deps struct {
	Cfg     Config
	DB      *pgxpool.Pool // request pool (16 conns, 8 s statement timeout)
	Ops     *pgxpool.Pool // janitor + admin pool (2 conns, 25 s)
	Lim     *Limiter
	Log     *slog.Logger
	Janitor *Janitor
	Notify  *Notifier
	Waiters *Waiters

	flags      atomic.Pointer[map[string]bool]
	flagStrs   atomic.Pointer[map[string]string]
	purgeMu    sync.Mutex
	purgeHooks []func(ctx context.Context, rootID string) error
	hmu        sync.RWMutex
	h          hooks
	govMu      sync.Mutex
	govSet     map[string]bool // flags the storage governor switched on
	govDisk    bool
	usage      atomic.Pointer[map[string]int64]
	inst       string
}

// NewDeps wires a Deps from config + pool, derives the ops pool, loads flags, registers the core
// janitor tasks and (when cfg.PGNotify) bridges the notifier through pg_notify.
func NewDeps(ctx context.Context, cfg Config, db *pgxpool.Pool, log *slog.Logger) (*Deps, error) {
	if log == nil {
		log = slog.Default()
	}
	ops, err := OpsPool(ctx, db)
	if err != nil {
		return nil, err
	}
	var ib [6]byte
	rand.Read(ib[:])
	d := &Deps{Cfg: cfg, DB: db, Ops: ops, Lim: NewLimiter(), Log: log, Notify: NewNotifier(),
		Waiters: NewWaiters(MaxWaiters, MaxWaitersPerRoot, MaxWaitersPerGrp), h: newHooks(),
		govSet: map[string]bool{}, inst: hex.EncodeToString(ib[:])}
	d.Janitor = &Janitor{log: log, ops: ops}
	if err := d.RefreshFlags(ctx); err != nil {
		ops.Close()
		return nil, err
	}
	eventNotify.Store(d.Notify)
	if cfg.PGNotify {
		d.startBridge(ctx)
	}
	d.Janitor.Add("flags", d.RefreshFlags)
	d.Janitor.Add("limiter", func(context.Context) error { d.Lim.Evict(10 * time.Minute); return nil })
	d.Janitor.Add("notifier", func(context.Context) error { d.Notify.Sweep(2 * time.Minute); return nil })
	d.Janitor.Add("challenges", func(ctx context.Context) error {
		_, err := db.Exec(ctx, `DELETE FROM used_challenges WHERE exp < now()`)
		return err
	})
	d.Janitor.Add("reg_ips", func(ctx context.Context) error {
		_, err := db.Exec(ctx, `DELETE FROM reg_ips WHERE at < now() - interval '24 hours'`)
		return err
	})
	d.Janitor.Add("counters", func(ctx context.Context) error {
		_, err := db.Exec(ctx, `DELETE FROM counters WHERE day < current_date - 2`)
		return err
	})
	d.Janitor.Add("expired_identities", func(ctx context.Context) error { _, err := RevokeExpired(ctx, db); return err })
	d.Janitor.Add("revoked_identities", func(ctx context.Context) error {
		// Revoked subkeys are dead weight after 30 days: delete leaves first (children cascade
		// anyway, but only revoked ones can exist below a revoked row). Roots are kept (rep/bans).
		_, err := db.Exec(ctx, `DELETE FROM identities i WHERE i.parent IS NOT NULL
			AND i.revoked_at < now() - interval '30 days'
			AND NOT EXISTS (SELECT 1 FROM identities c WHERE c.parent = i.id)`)
		return err
	})
	d.Janitor.Add("idem", func(ctx context.Context) error {
		_, err := db.Exec(ctx, `DELETE FROM idem WHERE created < now() - interval '24 hours'`)
		return err
	})
	d.Janitor.Add("governor", d.RunGovernor)
	return d, nil
}

// Close releases the ops pool (the request pool belongs to the caller).
func (d *Deps) Close() {
	if d.Ops != nil {
		d.Ops.Close()
	}
}

// OnPurge registers a hook run by Purge before core deletes a root's rows.
func (d *Deps) OnPurge(fn func(ctx context.Context, rootID string) error) {
	d.purgeMu.Lock()
	d.purgeHooks = append(d.purgeHooks, fn)
	d.purgeMu.Unlock()
}

// Janitor is a registry of periodic tasks run sequentially every tick. Each task runs under
// pg_try_advisory_lock(hashtext('janitor:'||name)) on the ops pool so two gateway instances never
// run the same task concurrently (21.3); without a pool (tests) tasks run directly.
type Janitor struct {
	mu    sync.Mutex
	tasks []janitorTask
	log   *slog.Logger
	ops   *pgxpool.Pool
}

type janitorTask struct {
	name string
	fn   func(ctx context.Context) error
}

func (j *Janitor) Add(name string, fn func(ctx context.Context) error) {
	j.mu.Lock()
	j.tasks = append(j.tasks, janitorTask{name, j.locked(name, fn)})
	j.mu.Unlock()
}

func (j *Janitor) locked(name string, fn func(ctx context.Context) error) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		if j.ops == nil {
			return fn(ctx)
		}
		conn, err := j.ops.Acquire(ctx)
		if err != nil {
			return err
		}
		defer conn.Release()
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext($1))`, "janitor:"+name).Scan(&got); err != nil {
			return err
		}
		if !got {
			return nil // another instance holds this task
		}
		err = fn(ctx)
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, uerr := conn.Exec(uctx, `SELECT pg_advisory_unlock(hashtext($1))`, "janitor:"+name); uerr != nil {
			// A session lock we cannot release must not survive in the pool: kill the connection.
			conn.Conn().Close(uctx)
		}
		return err
	}
}

// RunOnce executes every task with a per-task timeout; errors are logged, not returned.
func (j *Janitor) RunOnce(ctx context.Context) {
	j.mu.Lock()
	tasks := append([]janitorTask(nil), j.tasks...)
	j.mu.Unlock()
	for _, t := range tasks {
		tctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		if err := t.fn(tctx); err != nil && ctx.Err() == nil {
			j.log.Warn("janitor", "task", t.name, "err", err)
		}
		cancel()
	}
}

// Run loops RunOnce every interval until ctx is done.
func (j *Janitor) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			j.RunOnce(ctx)
		}
	}
}

// Notifier is an in-process broadcast per topic (e.g. "lease", "job:<id>") for long-polls.
// Entries are refcounted: a topic lives only while it has subscribers (or until Wake). With a
// bridge, Wake also publishes pg_notify('cx', topic) (coalesced 50 ms) so long-polls on another
// gateway instance wake too (21.3).
type Notifier struct {
	mu      sync.Mutex
	ch      map[string]*topicEntry
	pending map[string]struct{}
	publish func(topics []string)
}

type topicEntry struct {
	c    chan struct{}
	refs int
	last time.Time // last legacy Chan() subscription (refs do not cover those)
}

func NewNotifier() *Notifier { return &Notifier{ch: map[string]*topicEntry{}} }

// Wake releases every current waiter on topic (locally and, when bridged, on other instances).
func (n *Notifier) Wake(topic string) {
	n.mu.Lock()
	n.wakeLocked(topic)
	if n.publish != nil {
		if n.pending == nil {
			n.pending = map[string]struct{}{}
		}
		if len(n.pending) < 10_000 {
			n.pending[topic] = struct{}{}
		}
	}
	n.mu.Unlock()
}

func (n *Notifier) wakeLocked(topic string) {
	if e, ok := n.ch[topic]; ok {
		close(e.c)
		delete(n.ch, topic)
	}
}

// wakeLocal releases local waiters only (remote notifications).
func (n *Notifier) wakeLocal(topic string) {
	n.mu.Lock()
	n.wakeLocked(topic)
	n.mu.Unlock()
}

// flushLoop publishes pending topics every 50 ms until ctx is done.
func (n *Notifier) flushLoop(ctx context.Context) {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.mu.Lock()
			p := n.pending
			n.pending = nil
			pub := n.publish
			n.mu.Unlock()
			if len(p) == 0 || pub == nil {
				continue
			}
			topics := make([]string, 0, len(p))
			for k := range p {
				topics = append(topics, k)
			}
			pub(topics)
		}
	}
}

// Subscribe returns a channel closed on the next Wake(topic) and a cancel that MUST be called
// when the waiter returns; the topic entry is dropped when its last subscriber leaves.
func (n *Notifier) Subscribe(topic string) (<-chan struct{}, func()) {
	n.mu.Lock()
	e, ok := n.ch[topic]
	if !ok {
		e = &topicEntry{c: make(chan struct{})}
		n.ch[topic] = e
	}
	e.refs++
	n.mu.Unlock()
	var once sync.Once
	return e.c, func() {
		once.Do(func() {
			n.mu.Lock()
			e.refs--
			if cur, ok := n.ch[topic]; ok && cur == e && e.refs <= 0 && e.last.IsZero() {
				delete(n.ch, topic)
			}
			n.mu.Unlock()
		})
	}
}

// Chan returns a channel closed on the next Wake(topic). Select on it with ctx/timeouts.
// Deprecated: it cannot be released, so idle entries are only reclaimed by Sweep; prefer Subscribe.
func (n *Notifier) Chan(topic string) <-chan struct{} {
	n.mu.Lock()
	defer n.mu.Unlock()
	e, ok := n.ch[topic]
	if !ok {
		e = &topicEntry{c: make(chan struct{})}
		n.ch[topic] = e
	}
	e.last = time.Now()
	return e.c
}

// Sweep drops (and closes, so legacy waiters re-check) topics that have no Subscribe refs and
// whose last Chan() call is older than idle. Run from the janitor.
func (n *Notifier) Sweep(idle time.Duration) {
	cut := time.Now().Add(-idle)
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, e := range n.ch {
		if e.refs <= 0 && !e.last.IsZero() && e.last.Before(cut) {
			close(e.c)
			delete(n.ch, k)
		}
	}
}

// Len is the number of live topics.
func (n *Notifier) Len() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.ch)
}

// Wait blocks until Wake(topic), ctx done or timeout; true when woken. Leak-free.
func (n *Notifier) Wait(ctx context.Context, topic string, max time.Duration) bool {
	c, cancel := n.Subscribe(topic)
	defer cancel()
	t := time.NewTimer(max)
	defer t.Stop()
	select {
	case <-c:
		return true
	case <-ctx.Done():
		return false
	case <-t.C:
		return false
	}
}

// startBridge publishes local wakes through pg_notify and fans remote ones into the notifier.
func (d *Deps) startBridge(ctx context.Context) {
	inst := d.inst
	d.Notify.mu.Lock()
	d.Notify.publish = func(topics []string) {
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if _, err := d.Ops.Exec(pctx, `SELECT pg_notify('cx', $1 || ' ' || t) FROM unnest($2::text[]) AS t`, inst, topics); err != nil && ctx.Err() == nil {
			d.Log.Warn("notify bridge publish", "err", err)
		}
	}
	d.Notify.mu.Unlock()
	go d.Notify.flushLoop(ctx)
	go d.listenBridge(ctx)
}

func (d *Deps) listenBridge(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := d.listenOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			d.Log.Warn("notify bridge listen", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 10*time.Second {
			backoff *= 2
		}
	}
}

func (d *Deps) listenOnce(ctx context.Context) error {
	conn, err := pgx.ConnectConfig(ctx, d.Ops.Config().ConnConfig)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `LISTEN cx`); err != nil {
		return err
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		inst, topic, ok := strings.Cut(n.Payload, " ")
		if !ok || inst == d.inst || topic == "" {
			continue
		}
		d.Notify.wakeLocal(topic)
	}
}

// ClientIP honours CF-Connecting-IP only when TRUST_CF=1.
func (d *Deps) ClientIP(r *http.Request) string {
	if d.Cfg.TrustCF {
		if ip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// IPGroup is the per-client key used by every per-IP limit/quota: the address itself for IPv4
// (/32), the /64 prefix for IPv6 (one tenant usually controls a whole /64).
func (d *Deps) IPGroup(r *http.Request) string { return IPGroup(d.ClientIP(r)) }

// IPSuper is the coarse network key (IPv4 /24, IPv6 /48) used by anti-sybil boundaries (3.2).
func (d *Deps) IPSuper(r *http.Request) string { return IPSuper(d.ClientIP(r)) }

// IPGroup maps an IP string to its limit group (IPv4 → ip, IPv6 → "<prefix>/64").
func IPGroup(ip string) string {
	a := net.ParseIP(ip)
	if a == nil {
		return ip
	}
	if v4 := a.To4(); v4 != nil {
		return v4.String()
	}
	return a.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// IPSuper maps an IP (or an IPGroup string) to its super-group: IPv4 "<a.b.c.0>/24", IPv6 "<prefix>/48".
func IPSuper(ip string) string {
	s := ip
	if i := strings.IndexByte(s, '/'); i > 0 {
		s = s[:i]
	}
	a := net.ParseIP(s)
	if a == nil {
		return ip
	}
	if v4 := a.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return a.Mask(net.CIDRMask(48, 128)).String() + "/48"
}

// Register mounts core routes.
func Register(mux *http.ServeMux, d *Deps) {
	mux.HandleFunc("GET /healthz", d.healthz)
	mux.HandleFunc("POST /v1/challenge", d.hChallenge)
	mux.HandleFunc("POST /v1/register", d.hRegister)
	mux.HandleFunc("POST /v1/subkey", d.hSubkey)
	mux.HandleFunc("DELETE /v1/subkey/{id}", d.hSubkeyRevoke)
	mux.HandleFunc("GET /v1/me", d.hMe)
	mux.HandleFunc("POST /admin/freeze", d.adminOnly(d.hFreeze))
	mux.HandleFunc("GET /admin/stats", d.adminOnly(d.hStats))
	mux.HandleFunc("POST /admin/purge", d.adminOnly(d.hPurge))
	d.RegisterScope("POST /v1/subkey", "sub")
	d.RegisterScope("DELETE /v1/subkey/{id}", "sub")
	d.RegisterScope("GET /v1/me", "me:r")
}

func (d *Deps) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := d.DB.Ping(ctx); err != nil {
		Err(w, r, 503, "db", "unavailable")
		return
	}
	OK(w, r, "ok", map[string]bool{"ok": true})
}
