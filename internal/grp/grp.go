// Package grp implements the membership groups of SPEC-v2 27.4 (P96): consumer-group semantics
// over a fixed shard space. Identities join-or-heartbeat a named group; on every membership change
// the epoch is bumped and the live members are re-ranked densely by (since, id), so each member
// deterministically owns the shards {s : s mod n == rank} (reported compactly as every=<n>
// from=<rank>). The epoch fences dependent writes (grp.CheckFence, composed into mem.FenceCheckFn
// by P60a), so a member that missed a rebalance is told `409 fenced` rather than writing under a
// stale ownership. distinct:true ranks only the oldest member per registration super-group (the
// others stand by at rank -1). Names follow the 12 grammar (g: public read, ~/a:<root>. own tree,
// s:<slug>. space members); g: reads are anonymous.
package grp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

const (
	// MaxWait is the long-poll ceiling in seconds (3.6).
	MaxWait  = 85
	bodyMax  = 16 << 10
	ttlDef   = 30
	ttlMin   = 10
	ttlMax   = 600
	shardMax = 4096
	maxMem   = 64
	dataMax  = 512
	flapMax  = 30 // epoch bumps per root per hour before 429 err rate flapping
	retryNoW = 5
	capBytes = 32 << 20
	fencePfx = "grp:"
)

var settleSteps = []time.Duration{100 * time.Millisecond, 400 * time.Millisecond}

type svc struct{ d *core.Deps }

// Register mounts the group routes, scopes, costs, janitor, purge/resume/export, report target,
// OpenAPI and llms-full.
func Register(mux *http.ServeMux, d *core.Deps) { register(mux, d) }

func register(mux *http.ServeMux, d *core.Deps) *svc {
	s := &svc{d: d}
	mux.HandleFunc("POST /v1/grp/{name}", s.hJoin)
	mux.HandleFunc("GET /v1/grp/{name}", s.hGet)
	mux.HandleFunc("DELETE /v1/grp/{name}", s.hLeave)
	d.RegisterScope("POST /v1/grp/{name}", "lk")
	d.RegisterScope("GET /v1/grp/{name}", "lk")
	d.RegisterScope("DELETE /v1/grp/{name}", "lk")
	d.RegisterCost("GET /v1/grp/{name}", 0.2)
	d.StorageClass("groups", capBytes, `SELECT pg_total_relation_size('groups') + pg_total_relation_size('group_members')`)
	d.Janitor.Add("grp_groups", s.janitor)
	d.OnPurge(s.purge)
	d.OnResume(s.resume)
	d.OnExport("grp", s.export)
	d.RegisterTarget("grp", core.Target{Exists: s.tgtExists, Hide: s.tgtHide, Restore: s.tgtRestore})
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("grp", func(context.Context) string { return llmsText })
	return s
}

type reply struct {
	text string
	next []doc.Action
}

func (s *svc) send(w http.ResponseWriter, r *http.Request, rep reply) {
	doc.Tail(w, r, rep.text, rep.next...)
}

func unix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }
func itoa(n int) string       { return strconv.Itoa(n) }

func checkWait(wait int) error {
	if wait < 0 || wait > MaxWait {
		return core.Bad("wait must be 0.." + itoa(MaxWait))
	}
	return nil
}

func (s *svc) frozen() error {
	if s.d.Frozen("groups") {
		return core.Frozen("groups")
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

// cleanData normalises the member blob (<= 512 bytes): drop control characters, cap size, reject
// tier-1 secrets / mask tier-2 findings, then refuse a high injection-lexicon score. Rendered
// indented to the other members, so it is kept multi-line but never line-injection-capable.
func cleanData(data string) (string, []string, error) {
	data = strings.TrimRight(doc.CleanMulti(scrub.Normalize(data)), "\n ")
	if len(data) > dataMax {
		return "", nil, core.E(413, "size", "data > "+itoa(dataMax)+" bytes")
	}
	fields := map[string]*string{"data": &data}
	masked, err := scrub.RejectOrMask(fields)
	if err != nil {
		return "", nil, err
	}
	if len(data) > dataMax {
		return "", nil, core.E(413, "size", "data > "+itoa(dataMax)+" bytes")
	}
	if score, _, _ := scrub.Flags(data); score >= 2 {
		return "", nil, core.E(400, "bad", "lexicon data")
	}
	return data, masked, nil
}

func maskedField(kinds []string) string {
	if len(kinds) == 0 {
		return ""
	}
	return " masked=" + strings.Join(kinds, ",")
}

// poll runs check until it reports done, a wake arrives on topic or the wait ends (3.6).
func (s *svc) poll(ctx context.Context, id *core.Ident, grp string, wait int, topic string, check func(context.Context) (bool, time.Time, error)) (int, error) {
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

func queryInt64(r *http.Request, field string) (int64, bool, error) {
	v := r.URL.Query().Get(field)
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false, core.Bad(field + " must be a non-negative integer")
	}
	return n, true, nil
}

func grpCtx(ctx context.Context) string {
	_, g, _ := core.ClientFrom(ctx)
	return g
}

// --- report target (4.7): a group name ---------------------------------------------------------

func (s *svc) tgtExists(ctx context.Context, q core.Q, ref string) error {
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM groups WHERE name = $1)`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

// tgtHide hides the group and bumps its epoch so dependent writes fence out; the members stay on
// record until restore or the idle sweep.
func (s *svc) tgtHide(ctx context.Context, q core.Q, ref string) error {
	tag, err := q.Exec(ctx, `UPDATE groups SET hidden = true, epoch = epoch + 1 WHERE name = $1 AND NOT hidden`, ref)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if e := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM groups WHERE name = $1)`, ref).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return core.ErrNotFound
		}
	}
	s.d.Notify.Wake("grp:" + ref)
	return nil
}

func (s *svc) tgtRestore(ctx context.Context, q core.Q, ref string) error {
	tag, err := q.Exec(ctx, `UPDATE groups SET hidden = false, epoch = epoch + 1 WHERE name = $1 AND hidden`, ref)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	s.d.Notify.Wake("grp:" + ref)
	return nil
}

// --- hooks -------------------------------------------------------------------------------------

// purge erases the root's memberships, the groups it owns and its flap ledger (OnPurge).
func (s *svc) purge(ctx context.Context, root string) error {
	for _, st := range []string{
		`DELETE FROM group_members WHERE root = $1`,
		`DELETE FROM group_members WHERE name IN (SELECT name FROM groups WHERE owner_root = $1)`,
		`DELETE FROM group_flaps WHERE root = $1`,
		`DELETE FROM groups WHERE owner_root = $1`,
	} {
		if _, err := s.d.DB.Exec(ctx, st, root); err != nil {
			return err
		}
	}
	return nil
}

// resume lists the root's live memberships (OnResume).
func (s *svc) resume(ctx context.Context, root string) []string {
	rows, err := s.d.DB.Query(ctx, `SELECT m.name, g.epoch, m.rank, m.until FROM group_members m JOIN groups g ON g.name = m.name
		WHERE m.root = $1 AND m.until > now() AND NOT g.hidden ORDER BY m.until LIMIT 10`, root)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		var epoch int64
		var rank int
		var until time.Time
		if rows.Scan(&n, &epoch, &rank, &until) == nil {
			out = append(out, fmt.Sprintf("group %s epoch=%d rank=%d renew-by=%s", n, epoch, rank, unix(until)))
		}
	}
	return out
}

// export writes the root's groups and memberships as JSON lines (OnExport "grp").
func (s *svc) export(ctx context.Context, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	rows, err := s.d.DB.Query(ctx, `SELECT name, epoch, n, shards, ttl_s, "distinct", on_change, created FROM groups WHERE owner_root = $1 ORDER BY name`, root)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n string
		var epoch int64
		var nn, shards, ttl int
		var dist bool
		var onChange string
		var created time.Time
		if err := rows.Scan(&n, &epoch, &nn, &shards, &ttl, &dist, &onChange, &created); err != nil {
			rows.Close()
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "group", "name": n, "epoch": epoch, "n": nn, "shards": shards,
			"ttl_s": ttl, "distinct": dist, "on_change": onChange, "created": created.UTC()}); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	rows, err = s.d.DB.Query(ctx, `SELECT name, id, rank, since, until, data FROM group_members WHERE root = $1 ORDER BY name, id LIMIT 5000`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var n, id, data string
		var rank int
		var since, until time.Time
		if err := rows.Scan(&n, &id, &rank, &since, &until, &data); err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "member", "name": n, "id": id, "rank": rank,
			"since": since.UTC(), "until": until.UTC(), "data": data}); err != nil {
			return err
		}
	}
	return rows.Err()
}
