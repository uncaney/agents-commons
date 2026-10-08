package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// sessionRow is a session loaded for expiry.
type sessionRow struct {
	id, root, owner, name string
	ttl                   int
	started               time.Time
	plan                  []Step
}

// fireResult is one recorded plan-step outcome, stored in sessions.fired (27.3: failures recorded,
// never retried).
type fireResult struct {
	Op  string `json:"op"`
	Ref string `json:"ref,omitempty"`
	OK  bool   `json:"ok"`
	Err string `json:"err,omitempty"`
}

// Expire ends every lapsed session (last_beat + ttl_s < now()) with cause expired and runs its plan
// as the owner identity. It claims each session with a conditional UPDATE first, so a second janitor
// pass (or instance) never double-fires; steps then run on the ops pool outside any request tx, and
// each outcome is written to fired. Registered as the janitor task "sessions" (advisory-locked).
func Expire(ctx context.Context, d *core.Deps) error {
	rows, err := d.Ops.Query(ctx, `SELECT id, root, owner, name, ttl_s, started, plan FROM sessions
		WHERE ended IS NULL AND last_beat + make_interval(secs => ttl_s) < now()
		ORDER BY last_beat LIMIT $1`, JanitorN)
	if err != nil {
		return err
	}
	var due []*sessionRow
	for rows.Next() {
		var s sessionRow
		var planJSON []byte
		if err := rows.Scan(&s.id, &s.root, &s.owner, &s.name, &s.ttl, &s.started, &planJSON); err != nil {
			rows.Close()
			return err
		}
		if len(planJSON) > 0 {
			_ = json.Unmarshal(planJSON, &s.plan)
		}
		due = append(due, &s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range due {
		if err := expireOne(ctx, d, s); err != nil && ctx.Err() == nil {
			d.Log.Warn("session expire", "id", s.id, "err", err)
		}
	}
	return nil
}

// expireOne claims one session, runs its plan and records the outcome.
func expireOne(ctx context.Context, d *core.Deps, s *sessionRow) error {
	var claimed bool
	if err := d.Ops.QueryRow(ctx, `UPDATE sessions SET ended = now(), cause = 'expired'
		WHERE id = $1 AND ended IS NULL RETURNING true`, s.id).Scan(&claimed); err != nil {
		if err == pgx.ErrNoRows {
			return nil // already ended by a goodbye or another pass
		}
		return err
	}
	ph := resolvePlaceholders(ctx, d.Ops, s.root, s.name)
	results := make([]fireResult, 0, len(s.plan))
	for i := range s.plan {
		st := &s.plan[i]
		ref, err := st.fire(ctx, d.Ops, s, ph)
		res := fireResult{Op: st.Op, Ref: ref, OK: err == nil}
		if err != nil {
			res.Err = errText(err)
		}
		results = append(results, res)
	}
	fired, _ := json.Marshal(results)
	if _, err := d.Ops.Exec(ctx, `UPDATE sessions SET fired = $2 WHERE id = $1`, s.id, fired); err != nil {
		return err
	}
	ok := 0
	for _, r := range results {
		if r.OK {
			ok++
		}
	}
	return core.Tx(ctx, d.Ops, func(tx pgx.Tx) error {
		if err := core.Audit(ctx, tx, s.owner, "hb-fire", s.id, ok); err != nil {
			return err
		}
		return core.Event(ctx, tx, "session", s.id, s.root,
			fmt.Sprintf("%s expired (fired %d/%d)", s.name, ok, len(results)))
	})
}

func errText(err error) string {
	var ae *core.APIError
	if errors.As(err, &ae) {
		return ae.Code + ": " + ae.Msg
	}
	return err.Error()
}

// --- in-memory heartbeat coalescer ---------------------------------------------------------------

// Coalescer batches X-Session heartbeats in memory and flushes them every FlushEach as one UPDATE
// per live session, so a heartbeat never writes inside a request transaction (27.3). A pending
// entry carries the owning root so a flush only refreshes sessions the caller actually owns.
type Coalescer struct {
	d       *core.Deps
	mu      sync.Mutex
	pending map[string]string // session id -> root
	once    sync.Once
}

// coalescerFor returns the single Coalescer for a Deps (both Register and Middleware share it).
var (
	coalMu  sync.Mutex
	coalMap = map[*core.Deps]*Coalescer{}
)

func coalescerFor(d *core.Deps) *Coalescer {
	coalMu.Lock()
	defer coalMu.Unlock()
	c, ok := coalMap[d]
	if !ok {
		c = &Coalescer{d: d, pending: map[string]string{}}
		coalMap[d] = c
	}
	return c
}

// Mark records a pending heartbeat for session id owned by root.
func (c *Coalescer) Mark(id, root string) {
	if !core.ValidIDPrefix(id, 'e') || root == "" {
		return
	}
	c.mu.Lock()
	c.pending[id] = root
	c.mu.Unlock()
}

// Flush drains the pending set and refreshes last_beat for each session (one UPDATE each, scoped to
// the owning root and live sessions only). It runs on the ops pool, never a request connection.
func (c *Coalescer) Flush(ctx context.Context) error {
	c.mu.Lock()
	pend := c.pending
	c.pending = map[string]string{}
	c.mu.Unlock()
	var firstErr error
	for id, root := range pend {
		if _, err := c.d.Ops.Exec(ctx, `UPDATE sessions SET last_beat = now()
			WHERE id = $1 AND root = $2 AND ended IS NULL`, id, root); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// start launches the flush ticker once (production path, via Register); tests drive Flush directly.
func (c *Coalescer) start() {
	c.once.Do(func() {
		go func() {
			t := time.NewTicker(FlushEach)
			defer t.Stop()
			for range t.C {
				ctx, cancel := context.WithTimeout(context.Background(), FlushEach)
				if err := c.Flush(ctx); err != nil {
					c.d.Log.Warn("session heartbeat flush", "err", err)
				}
				cancel()
			}
		}()
	})
}

// Middleware refreshes the X-Session heartbeat of authenticated callers (27.3). It is installed by
// P60a around the mux; it never blocks the request or writes synchronously — the session id is
// marked in the coalescer and flushed in the background. An absent or malformed header is a no-op.
// Ownership is enforced at flush time, so an unauthenticated or foreign header refreshes nothing.
func Middleware(d *core.Deps, next http.Handler) http.Handler {
	c := coalescerFor(d)
	c.start()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sid := r.Header.Get("X-Session"); sid != "" {
			if id, err := d.AuthOpt(r); err == nil && id != nil {
				c.Mark(sid, id.Root)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- resume section ------------------------------------------------------------------------------

// resume reports how the root's most recent session ended (27.3): either
//
//	last session: <name> expired <ts> after 12 min (fired 3/3)
//	last session: <name> goodbye <summary>
//
// Nothing is shown while the root has only live sessions and no ended one.
func resume(ctx context.Context, q core.Q, root string) []string {
	var (
		name, cause, summary string
		started, ended       time.Time
		fired                []byte
	)
	err := q.QueryRow(ctx, `SELECT name, cause, summary, started, ended, fired FROM sessions
		WHERE root = $1 AND ended IS NOT NULL ORDER BY ended DESC LIMIT 1`, root).Scan(
		&name, &cause, &summary, &started, &ended, &fired)
	if err != nil {
		return nil
	}
	switch cause {
	case "goodbye":
		line := "last session: " + name + " goodbye"
		if summary != "" {
			line += " " + summary
		}
		return []string{line}
	case "expired", "revoked":
		mins := int(ended.Sub(started).Minutes())
		ok, total := firedCounts(fired)
		return []string{fmt.Sprintf("last session: %s %s %s after %d min (fired %d/%d)",
			name, cause, ended.UTC().Format(time.RFC3339), mins, ok, total)}
	}
	return nil
}

func firedCounts(fired []byte) (ok, total int) {
	var rs []fireResult
	if len(fired) == 0 || json.Unmarshal(fired, &rs) != nil {
		return 0, 0
	}
	for _, r := range rs {
		if r.OK {
			ok++
		}
	}
	return ok, len(rs)
}
