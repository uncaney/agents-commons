// Package swarm implements the coordination primitives of SPEC-v2 section 12: fenced locks and
// leases (leader election), cyclic rank-giving barriers with gather, rendezvous and presence,
// ordered topics with cursors, work queues with visibility timeouts and receipts, and a shared
// upstream rate limiter. Every name follows one grammar (names.go); every write path is capped
// per 4.3, scrubbed, and renders user text indented so it can never start a line.
package swarm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

const (
	// MaxWait is the long-poll ceiling in seconds (3.6).
	MaxWait  = 85
	bodyMax  = 16 << 10
	pushMax  = 512 << 10
	idle     = 7 * 24 * time.Hour
	retryNoW = 5 // retry=<s> appended when a requested wait could not be honoured
)

// Storage class caps (21.2).
const (
	swarmCapBytes = 128 << 20
	msgsCapBytes  = 256 << 20
)

var settleSteps = []time.Duration{100 * time.Millisecond, 400 * time.Millisecond}

type svc struct {
	d     *core.Deps
	lq    *lockQueue
	rvKey []byte
}

// notifier lets the exported service functions (Handover, ReleaseByOwner, Publish, Push) wake
// long-polls without a Deps; Register installs the gateway's notifier.
var notifier atomic.Pointer[core.Notifier]

func wake(topic string) {
	if n := notifier.Load(); n != nil {
		n.Wake(topic)
	}
}

func newSvc(d *core.Deps) *svc {
	mac := hmac.New(sha256.New, d.Cfg.ServerSecret)
	mac.Write([]byte("cx-rv-v1"))
	return &svc{d: d, lq: newLockQueue(), rvKey: mac.Sum(nil)}
}

// Register mounts the swarm routes and hooks (scopes, costs, storage classes, janitor, purge,
// resume, export, report targets lk/ps, the ps feed, the x resolver, OpenAPI and llms-full).
func Register(mux *http.ServeMux, d *core.Deps) { register(mux, d) }

func register(mux *http.ServeMux, d *core.Deps) *svc {
	s := newSvc(d)
	notifier.Store(d.Notify)
	current.Store(s)
	routes := []struct {
		pat, scope string
		h          http.HandlerFunc
		cost       float64
	}{
		{"POST /v1/lk/{name}", "lk", s.lkAcquire, 1},
		{"POST /v1/lk/{name}/renew", "lk", s.lkRenew, 1},
		{"DELETE /v1/lk/{name}", "lk", s.lkRelease, 1},
		{"GET /v1/lk/{name}", "lk", s.lkGet, 0.2},
		{"POST /v1/br/{name}", "br", s.brArrive, 1},
		{"GET /v1/br/{name}", "br", s.brGet, 0.2},
		{"POST /v1/rv", "rv", s.rvArrive, 1},
		{"GET /v1/rv/{id}", "rv", s.rvGet, 0.2},
		{"POST /v1/ps/{topic}", "ps:w", s.psPub, 1},
		{"GET /v1/ps/{topic}", "ps:r", s.psPull, 0.2},
		{"PUT /v1/pscur/{topic}", "ps:w", s.psCurSet, 0.2},
		{"GET /v1/pscur/{topic}", "ps:r", s.psCurGet, 0.2},
		{"POST /v1/wq/{name}", "*", s.wqPush, 1},
		{"POST /v1/wq/{name}/take", "*", s.wqTake, 1},
		{"POST /v1/wq/{name}/ack", "*", s.wqAck, 0.2},
		{"POST /v1/wq/{name}/nack", "*", s.wqNack, 1},
		{"POST /v1/wq/{name}/extend", "*", s.wqExtend, 1},
		{"GET /v1/wq/{name}", "*", s.wqGet, 0.2},
		{"POST /v1/rl/{key}", "lk", s.rlTake, 0.2},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, rt.scope)
		if rt.cost != 1 {
			d.RegisterCost(rt.pat, rt.cost)
		}
	}
	d.StorageClass("swarm", swarmCapBytes, `SELECT pg_total_relation_size('locks') + pg_total_relation_size('barriers')
		+ pg_total_relation_size('barrier_parties') + pg_total_relation_size('barrier_gens') + pg_total_relation_size('rv')
		+ pg_total_relation_size('rv_peers') + pg_total_relation_size('queues') + pg_total_relation_size('q_items')
		+ pg_total_relation_size('rl_buckets') + pg_total_relation_size('topic_cursors')`)
	d.StorageClass("topic_msgs", msgsCapBytes, `SELECT pg_total_relation_size('topic_msgs') + pg_total_relation_size('topics')`)
	d.Janitor.Add("swarm_locks", s.janLocks)
	d.Janitor.Add("swarm_barriers", s.janBarriers)
	d.Janitor.Add("swarm_rv", s.janRV)
	d.Janitor.Add("swarm_topics", s.janTopics)
	d.Janitor.Add("swarm_queues", s.janQueues)
	d.Janitor.Add("swarm_rl", s.janRL)
	d.OnPurge(s.purge)
	d.OnResume(s.resume)
	d.OnExport("swarm", func(ctx context.Context, root string, w io.Writer) error { return s.export(ctx, root, w) })
	d.RegisterTarget("lk", core.Target{Exists: s.lkExists, Hide: s.lkHide, Restore: s.lkRestore})
	d.RegisterTarget("ps", core.Target{Exists: s.psExists, Hide: s.psHide, Restore: s.psRestore})
	d.RegisterFeed("ps", s.psFeed)
	d.RegisterResolver('x', s.rvResolve)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("swarm", func(context.Context) string { return llmsText })
	return s
}

// reply is a rendered text document: head line + lines, status and next: actions.
type reply struct {
	status int
	text   string
	next   []doc.Action
}

func (s *svc) send(w http.ResponseWriter, r *http.Request, rep reply) {
	if rep.status == 0 {
		rep.status = http.StatusOK
	}
	doc.TailStatus(w, r, rep.status, rep.text, rep.next...)
}

func unix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func quotaErr(what string, capN int) *core.APIError {
	return core.E(429, "quota", what+" "+strconv.Itoa(capN))
}

func checkWait(wait int) error {
	if wait < 0 || wait > MaxWait {
		return core.Bad("wait must be 0.." + strconv.Itoa(MaxWait))
	}
	return nil
}

// checkRange validates an integer option: zero takes the default, otherwise lo..hi.
func checkRange(name string, v, def, lo, hi int) (int, error) {
	if v == 0 {
		v = def
	}
	if v < lo || v > hi {
		return 0, core.Bad(fmt.Sprintf("%s must be %d..%d", name, lo, hi))
	}
	return v, nil
}

// frozen maps a storage-class or write freeze to its 503.
func (s *svc) frozen(classes ...string) error {
	for _, c := range classes {
		if s.d.Frozen(c) {
			return core.Frozen(c)
		}
	}
	return nil
}

// writeOK mirrors core.AuthWrite for ops: token, not banned, no write freeze.
func (s *svc) writeOK(id *core.Ident) error {
	switch {
	case id == nil:
		return core.ErrAuth
	case id.Banned:
		return core.ErrBanned
	case s.d.Frozen("write"):
		return core.Frozen("write")
	}
	return nil
}

// bump adds n to today's counter (scope, kind) and returns the new value (core counters table).
func bump(ctx context.Context, q core.Q, scope, kind string, n int) (int, error) {
	var cur int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, scope, kind, n).Scan(&cur)
	return cur, err
}

// useCap charges n units of a per-root daily cap (4.3): counter (root, kind), limit trust.Cap(capKind,
// level). kind may carry a suffix (ps:<topic>) so one cap row can apply per object.
func useCap(ctx context.Context, q core.Q, root, kind, capKind string, n int) error {
	cur, err := bump(ctx, q, root, kind, n)
	if err != nil {
		return err
	}
	if capN := trust.Cap(capKind, core.Level(ctx, q, root)); cur > capN {
		return quotaErr(capKind, capN)
	}
	return nil
}

// liveCap refuses a new live object when countSQL ($1 = root) already reaches the cap of capKind.
func liveCap(ctx context.Context, q core.Q, root, capKind, countSQL string) error {
	var n int
	if err := q.QueryRow(ctx, countSQL, root).Scan(&n); err != nil {
		return err
	}
	if capN := trust.Cap(capKind, core.Level(ctx, q, root)); n >= capN {
		return quotaErr(capKind+" live", capN)
	}
	return nil
}

// rootLock serialises a root's cap-counted creations inside its transaction.
func rootLock(ctx context.Context, q core.Q, root string) error {
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "swarm:"+root)
	return err
}

// cleanText is the write order for user text (4.6, 5): normalise, drop control characters,
// trim, reject tier-1 secrets, mask tier-2 findings; max is the stored byte cap. Returns the kinds
// masked (for `masked=…`).
func cleanText(field string, text *string, max int) ([]string, error) {
	*text = strings.TrimRight(doc.CleanMulti(scrub.Normalize(*text)), "\n ")
	if len(*text) > max {
		return nil, core.E(413, "size", field+" > "+strconv.Itoa(max)+" bytes")
	}
	if *text == "" {
		return nil, nil
	}
	masked, aerr := scrub.RejectOrMask(map[string]*string{field: text})
	if aerr != nil {
		return nil, aerr
	}
	if len(*text) > max {
		return nil, core.E(413, "size", field+" > "+strconv.Itoa(max)+" bytes")
	}
	return masked, nil
}

func maskedField(kinds []string) string {
	if len(kinds) == 0 {
		return ""
	}
	return " masked=" + strings.Join(kinds, ",")
}

// poll runs check until it reports done, a wake arrives on topic or the wait ends (3.6: tokens
// only, a d.Waiters slot, shed:longpoll). retry is 5 when a wait was asked but not honoured.
// Writers wake before their commit, so an empty re-read after a wake settles briefly first.
func (s *svc) poll(ctx context.Context, id *core.Ident, grp string, wait int, topic string, check func(context.Context) (bool, error)) (int, error) {
	return s.pollHint(ctx, id, grp, wait, topic, func(ctx context.Context) (bool, time.Time, error) {
		done, err := check(ctx)
		return done, time.Time{}, err
	})
}

// pollHint is poll with a deadline hint: a non-zero time returned by check caps the next sleep so a
// state change that happens by itself (a lease deadline) is observed without a wake.
func (s *svc) pollHint(ctx context.Context, id *core.Ident, grp string, wait int, topic string, check func(context.Context) (bool, time.Time, error)) (int, error) {
	done, _, err := check(ctx)
	if err != nil || done || wait == 0 {
		return 0, err
	}
	if id == nil || s.d.Shed(nil, "longpoll") {
		return retryNoW, nil
	}
	release, ok := s.d.Waiters.Acquire(id.Root, grp)
	if !ok {
		return retryNoW, nil
	}
	defer release()
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	settle := len(settleSteps)
	for {
		c, cancel := s.d.Notify.Subscribe(topic)
		done, hint, err := check(ctx)
		if err != nil || done {
			cancel()
			return 0, err
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			cancel()
			return 0, nil
		}
		if settle < len(settleSteps) {
			rem = min(rem, settleSteps[settle])
			settle++
		}
		if !hint.IsZero() {
			rem = min(rem, max(time.Until(hint)+50*time.Millisecond, 20*time.Millisecond))
		}
		t := time.NewTimer(rem)
		select {
		case <-c:
			settle = 0
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return 0, nil
		}
		t.Stop()
		cancel()
	}
}

// arg decodes an MCP op argument object (empty/null = zero value).
func arg(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(a)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

// queryInt parses an optional integer query parameter.
func queryInt(r *http.Request, name string) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, core.Bad(name + " must be an integer")
	}
	return n, nil
}

func queryInt64(r *http.Request, name string) (int64, bool, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false, core.Bad(name + " must be a non-negative integer")
	}
	return n, true, nil
}

// grp returns the request's IP group (anonymous waiter key).
func (s *svc) grp(r *http.Request) string { return s.d.IPGroup(r) }

func grpCtx(ctx context.Context) string {
	_, g, _ := core.ClientFrom(ctx)
	return g
}

// --- hooks -------------------------------------------------------------------------------------

// purge releases the root's locks and erases its swarm rows (OnPurge).
func (s *svc) purge(ctx context.Context, root string) error {
	q := s.d.DB
	rows, err := q.Query(ctx, `UPDATE locks SET until = now(), notified = true WHERE root = $1 AND until > now() RETURNING name`, root)
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
		wake("lk:" + n)
	}
	own := "a:" + root + ".%"
	stmts := []struct{ sql, arg string }{
		{`DELETE FROM locks WHERE name LIKE $1`, own},
		{`DELETE FROM barrier_parties WHERE root = $1`, root},
		{`DELETE FROM barrier_parties WHERE name IN (SELECT name FROM barriers WHERE owner_root = $1)`, root},
		{`DELETE FROM barrier_gens WHERE name IN (SELECT name FROM barriers WHERE owner_root = $1)`, root},
		{`DELETE FROM barriers WHERE owner_root = $1`, root},
		{`DELETE FROM rv_peers WHERE root = $1`, root},
		{`DELETE FROM rv WHERE owner_root = $1`, root},
		{`UPDATE topic_msgs SET text = '', key = '', hidden = true, flags = '{}' WHERE root = $1`, root},
		{`DELETE FROM topic_cursors WHERE root = $1`, root},
		{`DELETE FROM topic_msgs WHERE topic LIKE $1`, own},
		{`DELETE FROM topics WHERE name LIKE $1`, own},
		{`DELETE FROM q_items WHERE queue LIKE $1`, own},
		{`DELETE FROM queues WHERE name LIKE $1`, own},
		{`DELETE FROM rl_buckets WHERE root = $1`, root},
	}
	for _, st := range stmts {
		if _, err := q.Exec(ctx, st.sql, st.arg); err != nil {
			return err
		}
	}
	return nil
}

// resume lists the locks the root holds (OnResume).
func (s *svc) resume(ctx context.Context, root string) []string {
	rows, err := s.d.DB.Query(ctx, `SELECT name, fence, until FROM locks WHERE root = $1 AND until > now() ORDER BY until LIMIT 20`, root)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		var fence int64
		var until time.Time
		if rows.Scan(&name, &fence, &until) == nil {
			out = append(out, fmt.Sprintf("lock %s fence=%d until=%s", name, fence, unix(until)))
		}
	}
	return out
}

// export writes the root's swarm state as JSON lines (OnExport "swarm").
func (s *svc) export(ctx context.Context, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	type row = map[string]any
	emit := func(sql string, scan func(rows interface{ Scan(...any) error }) (row, error)) error {
		rows, err := s.d.DB.Query(ctx, sql, root)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			m, err := scan(rows)
			if err != nil {
				return err
			}
			if err := enc.Encode(m); err != nil {
				return err
			}
		}
		return rows.Err()
	}
	if err := emit(`SELECT name, holder, fence, until, since FROM locks WHERE root = $1 AND until > now() ORDER BY name`, func(r interface{ Scan(...any) error }) (row, error) {
		var name, holder string
		var fence int64
		var until, since time.Time
		err := r.Scan(&name, &holder, &fence, &until, &since)
		return row{"kind": "lock", "name": name, "holder": holder, "fence": fence, "until": until.UTC(), "since": since.UTC()}, err
	}); err != nil {
		return err
	}
	if err := emit(`SELECT name, mode, last_seq, created FROM topics WHERE owner_root = $1 ORDER BY name`, func(r interface{ Scan(...any) error }) (row, error) {
		var name, mode string
		var seq int64
		var created time.Time
		err := r.Scan(&name, &mode, &seq, &created)
		return row{"kind": "topic", "name": name, "mode": mode, "last_seq": seq, "created": created.UTC()}, err
	}); err != nil {
		return err
	}
	if err := emit(`SELECT topic, seq, text, created FROM topic_msgs WHERE root = $1 AND NOT hidden ORDER BY created LIMIT 5000`, func(r interface{ Scan(...any) error }) (row, error) {
		var topic, text string
		var seq int64
		var created time.Time
		err := r.Scan(&topic, &seq, &text, &created)
		return row{"kind": "msg", "topic": topic, "seq": seq, "text": text, "created": created.UTC()}, err
	}); err != nil {
		return err
	}
	if err := emit(`SELECT topic, seq FROM topic_cursors WHERE root = $1 ORDER BY topic`, func(r interface{ Scan(...any) error }) (row, error) {
		var topic string
		var seq int64
		err := r.Scan(&topic, &seq)
		return row{"kind": "cursor", "topic": topic, "seq": seq}, err
	}); err != nil {
		return err
	}
	if err := emit(`SELECT name, mode, created FROM queues WHERE owner_root = $1 ORDER BY name`, func(r interface{ Scan(...any) error }) (row, error) {
		var name, mode string
		var created time.Time
		err := r.Scan(&name, &mode, &created)
		return row{"kind": "queue", "name": name, "mode": mode, "created": created.UTC()}, err
	}); err != nil {
		return err
	}
	return emit(`SELECT id, cap, until FROM rv WHERE owner_root = $1 AND until > now() ORDER BY created`, func(r interface{ Scan(...any) error }) (row, error) {
		var id string
		var capN int
		var until time.Time
		err := r.Scan(&id, &capN, &until)
		return row{"kind": "rv", "id": id, "cap": capN, "until": until.UTC()}, err
	})
}
