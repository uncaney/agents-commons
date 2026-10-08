package core

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Admin plane (SPEC-v2 21.4). Four token kinds, each read from its own file (config.go):
// admin (everything), ops (decide, check requests), poll (read-only: inbox, stats, audit,
// notices), check (the check runner's two routes). Every /admin handler compares the presented
// token first, in constant time against every kind, so a valid token always passes whatever
// happened before from that network. Failures are only rate-limited (10 per minute per IP group,
// then a 1 s delay and 429 for the rest of that minute); there is no lockout. Every call lands in
// admin_log(at, ip_group, token_kind, action, arg).

const (
	kindNone = iota
	kindAdmin
	kindOps
	kindPoll
	kindCheck
)

var kindNames = [...]string{"none", "admin", "ops", "poll", "check"}

// kindSet is the set of token kinds a route accepts.
type kindSet uint8

const (
	setAdmin kindSet = 1 << kindAdmin
	setOps   kindSet = setAdmin | 1<<kindOps
	setPoll  kindSet = setOps | 1<<kindPoll
	setCheck kindSet = setAdmin | 1<<kindCheck
)

func (s kindSet) has(kind int) bool { return kind != kindNone && s&(1<<kind) != 0 }

// v1 routes mounted by Register through adminOnly that the poll token may read (21.4).
var adminPollRoutes = map[string]bool{"GET /admin/stats": true}

// Failure limiter: 10 failures per minute per IP group, then 1 s + 429 until the minute ends.
const (
	adminFailPerMin   = 10
	adminFailMaxGroup = 10_000
)

// adminFailDelay is the wait before a 429 (a var so tests can shorten it).
var adminFailDelay = time.Second

type failWindow struct {
	start time.Time
	n     int
}

type failTracker struct {
	mu sync.Mutex
	m  map[string]*failWindow
}

var adminFails = &failTracker{m: map[string]*failWindow{}}

// fail counts one failure for group; over reports the limit was passed in the current minute and
// retry the seconds left in it. Past the map cap, untracked newcomers are treated as over (safe
// side: valid tokens never consult this path).
func (f *failTracker) fail(group string, now time.Time) (over bool, retry int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.m[group]
	if w == nil {
		if len(f.m) >= adminFailMaxGroup {
			f.sweepLocked(now)
			if len(f.m) >= adminFailMaxGroup {
				return true, 60
			}
		}
		w = &failWindow{}
		f.m[group] = w
	}
	if now.Sub(w.start) >= time.Minute {
		w.start, w.n = now, 0
	}
	w.n++
	if w.n > adminFailPerMin {
		return true, int((time.Minute - now.Sub(w.start) + time.Second - 1) / time.Second)
	}
	return false, 0
}

// sweep drops windows older than a minute (janitor).
func (f *failTracker) sweep(now time.Time) {
	f.mu.Lock()
	f.sweepLocked(now)
	f.mu.Unlock()
}

func (f *failTracker) sweepLocked(now time.Time) {
	for k, w := range f.m {
		if now.Sub(w.start) >= time.Minute {
			delete(f.m, k)
		}
	}
}

// tokenKind identifies the presented token: every configured kind is compared in constant time
// over fixed-length digests; an empty configured kind never matches.
func (d *Deps) tokenKind(tok string) int {
	if tok == "" {
		return kindNone
	}
	h := sha256.Sum256([]byte(tok))
	match := kindNone
	for kind, cfg := range [...]string{kindAdmin: d.Cfg.AdminToken, kindOps: d.Cfg.OpsToken, kindPoll: d.Cfg.PollToken, kindCheck: d.Cfg.CheckToken} {
		if cfg == "" {
			continue
		}
		ch := sha256.Sum256([]byte(cfg))
		if subtle.ConstantTimeCompare(h[:], ch[:]) == 1 && match == kindNone {
			match = kind
		}
	}
	return match
}

type adminCallKey struct{}

// adminCall carries the argument a handler wants logged next to its action.
type adminCall struct{ arg string }

// AdminArg records the argument of the current admin call for admin_log (ids, counts; <= 200
// chars, one line). Handlers call it once they have validated their input.
func AdminArg(r *http.Request, arg string) {
	if c, ok := r.Context().Value(adminCallKey{}).(*adminCall); ok {
		c.arg = cleanLine(arg, 200)
	}
}

// adminAction names the route for admin_log: the matched pattern (server vocabulary, never a raw path).
func adminAction(r *http.Request) string {
	if r.Pattern != "" {
		return cleanLine(r.Pattern, 64)
	}
	return cleanLine(r.Method+" "+r.URL.Path, 64)
}

// adminLog writes one admin_log row; it outlives a cancelled request so a disconnect never drops it.
func (d *Deps) adminLog(ctx context.Context, group, kind, action, arg string) {
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := d.DB.Exec(lctx, `INSERT INTO admin_log (ip_group, token_kind, action, arg) VALUES ($1, $2, $3, $4)`,
		cleanLine(group, 64), kind, action, cleanLine(arg, 200)); err != nil {
		d.Log.Warn("admin_log", "err", err)
	}
}

// adminGate is the one gate every /admin handler goes through (see the file comment).
func (d *Deps) adminGate(accept kindSet, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind := d.tokenKind(bearer(r.Header.Get("Authorization")))
		group, action := d.IPGroup(r), adminAction(r)
		if accept.has(kind) {
			call := &adminCall{}
			r = r.WithContext(context.WithValue(r.Context(), adminCallKey{}, call))
			defer func() { d.adminLog(r.Context(), group, kindNames[kind], action, call.arg) }()
			h(w, r)
			return
		}
		if over, retry := adminFails.fail(group, time.Now()); over {
			select {
			case <-time.After(adminFailDelay):
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Retry-After", strconv.Itoa(retry))
			Fail(w, r, E(429, "rate", "admin"))
			return
		}
		arg := "denied"
		if kind != kindNone {
			arg += ":" + kindNames[kind]
		}
		d.adminLog(r.Context(), group, "none", action, arg)
		Fail(w, r, E(401, "auth", "admin"))
	}
}

// AdminOnly admits the admin token only (freeze, purge, pins, blob, trusted, credits, seed-root, asn, origin).
func (d *Deps) AdminOnly(h http.HandlerFunc) http.HandlerFunc { return d.adminGate(setAdmin, h) }

// OpsOnly admits the ops token (and admin): POST /admin/decide, cxa check requests.
func (d *Deps) OpsOnly(h http.HandlerFunc) http.HandlerFunc { return d.adminGate(setOps, h) }

// PollOnly admits the poll token (and ops, admin): inbox, stats, audit, notices.
func (d *Deps) PollOnly(h http.HandlerFunc) http.HandlerFunc { return d.adminGate(setPoll, h) }

// CheckOnly admits the check runner's token (and admin): GET /admin/checkq, proposal checks.
func (d *Deps) CheckOnly(h http.HandlerFunc) http.HandlerFunc { return d.adminGate(setCheck, h) }

// adminOnly keeps the v1 name Register uses: admin token, except the poll-readable v1 routes.
func (d *Deps) adminOnly(h http.HandlerFunc) http.HandlerFunc {
	admin, poll := d.adminGate(setAdmin, h), d.adminGate(setPoll, h)
	return func(w http.ResponseWriter, r *http.Request) {
		if adminPollRoutes[r.Pattern] {
			poll(w, r)
			return
		}
		admin(w, r)
	}
}

func (d *Deps) hFreeze(w http.ResponseWriter, r *http.Request) {
	var in struct {
		What string `json:"what"`
		On   bool   `json:"on"`
	}
	if err := Decode(w, r, 1<<10, &in); err != nil {
		Fail(w, r, err)
		return
	}
	if err := d.SetFreeze(r.Context(), in.What, in.On); err != nil {
		Fail(w, r, err)
		return
	}
	AdminArg(r, fmt.Sprintf("%s=%v", in.What, in.On))
	OK(w, r, fmt.Sprintf("ok %s=%v", in.What, in.On), map[string]any{"ok": true, "what": in.What, "on": in.On})
}

// statTables are the count queries exposed by /admin/stats.
var statTables = map[string]string{
	"identities":      `SELECT count(*) FROM identities WHERE revoked_at IS NULL`,
	"roots":           `SELECT count(*) FROM identities WHERE parent IS NULL AND revoked_at IS NULL`,
	"kb":              `SELECT count(*) FROM kb WHERE NOT hidden AND expires_at > now()`,
	"kb_hidden":       `SELECT count(*) FROM kb WHERE hidden`,
	"kb_votes":        `SELECT count(*) FROM kb_votes`,
	"tasks":           `SELECT count(*) FROM tasks`,
	"task_claims":     `SELECT count(*) FROM task_claims WHERE until > now()`,
	"notes":           `SELECT count(*) FROM notes`,
	"blobs":           `SELECT count(*) FROM blobs`,
	"blob_bytes":      `SELECT coalesce(sum(size),0) FROM blobs`,
	"jobs_active":     `SELECT count(*) FROM jobs WHERE status IN ('queued','running')`,
	"jobs_done":       `SELECT count(*) FROM jobs WHERE status = 'done'`,
	"jobs_failed":     `SELECT count(*) FROM jobs WHERE status = 'failed'`,
	"replicas_queued": `SELECT count(*) FROM replicas WHERE state = 'queued'`,
	"replicas_leased": `SELECT count(*) FROM replicas WHERE state = 'leased'`,
	"forge_outbox":    `SELECT count(*) FROM forge_outbox`,
	"reports":         `SELECT count(*) FROM reports`,
}

// CollusionFn renders the compute collusion graph for /admin/stats (14.5); set by the compute
// audit package, nil = no section.
var CollusionFn func(ctx context.Context, q Q) []string

// hStats: the v1 k=v lines (prefix-stable), then the v2 appendix (21.1): waiters, notifier
// topics, shed levels, ledger totals, egress outbox depth per kind, storage classes, collusion.
func (d *Deps) hStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	keys := make([]string, 0, len(statTables))
	for k := range statTables {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]any{}
	var b strings.Builder
	for _, k := range keys {
		var n int64
		if err := d.DB.QueryRow(ctx, statTables[k]).Scan(&n); err != nil {
			Fail(w, r, err)
			return
		}
		out[k] = n
		fmt.Fprintf(&b, "%s=%d\n", k, n)
	}
	var frozen, shed []string
	if m := d.flags.Load(); m != nil {
		for k, v := range *m {
			switch {
			case !v:
			case strings.HasPrefix(k, "shed:"):
				shed = append(shed, strings.TrimPrefix(k, "shed:"))
			default:
				frozen = append(frozen, k)
			}
		}
	}
	sort.Strings(frozen)
	sort.Strings(shed)
	out["frozen"] = frozen
	out["limiter_keys"] = d.Lim.Len()
	fmt.Fprintf(&b, "frozen=%s\nlimiter_keys=%d", strings.Join(frozen, ","), d.Lim.Len())
	out["waiters"], out["notifier_topics"], out["shed"] = d.Waiters.Len(), d.Notify.Len(), shed
	fmt.Fprintf(&b, "\nwaiters=%d\nnotifier_topics=%d\nshed=%s", d.Waiters.Len(), d.Notify.Len(), strings.Join(shed, ","))
	mint, burn, err := ledgerTotals(ctx, d.DB)
	if err != nil {
		Fail(w, r, err)
		return
	}
	out["ledger_mint"], out["ledger_burn"] = mint, burn
	fmt.Fprintf(&b, "\nledger_mint=%d\nledger_burn=%d", mint, burn)
	rows, err := d.DB.Query(ctx, `SELECT kind, count(*) FROM egress_outbox WHERE done_at IS NULL GROUP BY kind ORDER BY kind`)
	if err != nil {
		Fail(w, r, err)
		return
	}
	outbox := map[string]int64{}
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			Fail(w, r, err)
			return
		}
		outbox[k] = n
		fmt.Fprintf(&b, "\noutbox_%s=%d/%d", cleanLine(k, 32), n, EgressCap(k))
	}
	rows.Close()
	out["outbox"] = outbox
	var classes []map[string]any
	for _, c := range d.StorageClasses() {
		classes = append(classes, map[string]any{"name": c.Name, "used": c.Used, "cap": c.Cap, "frozen": c.Frozen})
		fmt.Fprintf(&b, "\nstorage_%s=%d/%d", c.Name, c.Used, c.Cap)
	}
	out["storage"] = classes
	if CollusionFn != nil {
		lines := CollusionFn(ctx, d.DB)
		out["collusion"] = lines
		for _, l := range lines {
			b.WriteString("\ncollusion: " + cleanLine(l, 200))
		}
	}
	OK(w, r, b.String(), out)
}

func (d *Deps) hPurge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID string `json:"id"`
	}
	if err := Decode(w, r, 1<<10, &in); err != nil {
		Fail(w, r, err)
		return
	}
	if !ValidID(in.ID) {
		Fail(w, r, Bad("bad id"))
		return
	}
	AdminArg(r, "id="+in.ID)
	n, err := d.Purge(r.Context(), in.ID)
	if err != nil {
		Fail(w, r, err)
		return
	}
	OK(w, r, fmt.Sprintf("ok purged=%d", n), map[string]any{"ok": true, "purged": n})
}

// Purge revokes id and all descendants (their remaining credits are burnt in the ledger, 16.1),
// runs OnPurge hooks (with the root id, so packages can clean up their external state while rows
// still exist), then deletes the subtree's rows from core-owned tables. Returns the number of
// identities revoked. The system root is never purged.
func (d *Deps) Purge(ctx context.Context, id string) (int64, error) {
	if id == SystemID {
		return 0, Bad("system root")
	}
	ids, err := Descendants(ctx, d.DB, id)
	if err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, ErrNotFound
	}
	var n int64
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var credits, earned int64
		if err := tx.QueryRow(ctx, `WITH l AS (SELECT credits, earned FROM identities WHERE id = ANY($1) AND revoked_at IS NULL FOR UPDATE)
			SELECT coalesce(sum(credits), 0), coalesce(sum(earned), 0) FROM l`, ids).Scan(&credits, &earned); err != nil {
			return err
		}
		if n, err = RevokeTree(ctx, tx, id, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE identities SET earned = 0 WHERE id = ANY($1) AND earned <> 0`, ids); err != nil {
			return err
		}
		if g := credits - earned; g > 0 {
			if err := Ledger(ctx, tx, id, LedgerBurn, "grant", g, "purge", ""); err != nil {
				return err
			}
		}
		if earned > 0 {
			return Ledger(ctx, tx, id, LedgerBurn, "earned", earned, "purge", "")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	d.purgeMu.Lock()
	hooks := append([]func(context.Context, string) error(nil), d.purgeHooks...)
	d.purgeMu.Unlock()
	for _, h := range hooks {
		if err := h(ctx, id); err != nil {
			d.Log.Warn("purge hook", "id", id, "err", err)
		}
	}
	return n, Tx(ctx, d.DB, func(tx pgx.Tx) error {
		// Active jobs die with their submitter: their reservations leave hold through a burn row.
		var reserved int64
		if err := tx.QueryRow(ctx, `WITH k AS (UPDATE jobs SET status = 'failed', reason = 'purged', finished_at = now()
			WHERE submitter = ANY($1) AND status IN ('queued','running') RETURNING reserved)
			SELECT coalesce(sum(reserved), 0) FROM k`, ids).Scan(&reserved); err != nil {
			return err
		}
		if err := BurnHeld(ctx, tx, reserved, "purge", id); err != nil {
			return err
		}
		stmts := []string{
			`DELETE FROM kb_votes WHERE root = ANY($1)`,
			`DELETE FROM kb WHERE author = ANY($1)`,
			`DELETE FROM notes WHERE owner = ANY($1)`,
			`DELETE FROM task_claims WHERE id = ANY($1)`,
			`DELETE FROM replicas WHERE job IN (SELECT id FROM jobs WHERE submitter = ANY($1))`,
			`DELETE FROM replicas WHERE worker = ANY($1) AND state <> 'reported'`,
			`DELETE FROM blobs WHERE owner_root = ANY($1)`,
			`DELETE FROM reports WHERE reporter = ANY($1)`,
			`DELETE FROM counters WHERE scope = ANY($1)`,
		}
		for _, s := range stmts {
			if _, err := tx.Exec(ctx, s, ids); err != nil {
				return err
			}
		}
		return nil
	})
}
