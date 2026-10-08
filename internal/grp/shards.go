package grp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/swarm"
	"ekaii.fr/commons/internal/trust"
)

var errNoGroup = errors.New("no group")

type joinIn struct {
	TTL      int           `json:"ttl_s"`
	Shards   int           `json:"shards"`
	Data     string        `json:"data"`
	OnChange *onChangeSpec `json:"on_change"`
	Distinct bool          `json:"distinct"`
	Wait     int           `json:"wait"`
}

// onChangeSpec is the notify target of a group: {"ps":"<topic>"}.
type onChangeSpec struct {
	PS string `json:"ps"`
}

type group struct {
	name     string
	epoch    int64
	n        int
	shards   int
	ttl      int
	owner    string
	distinct bool
	onChange string
	hidden   bool
}

// outcome is the caller's post-transaction view plus the change events to publish once committed.
type outcome struct {
	epoch   int64
	rank    int
	n       int
	changed bool
	topic   string
	events  []string
}

func fencedErr(cur int64) *core.APIError { return core.E(409, "fenced", strconv.FormatInt(cur, 10)) }

// CheckFence refuses a fenced write unless epoch is the live epoch of group name (prefixed
// "grp:"): `409 fenced <current>`. P60a composes it into mem.FenceCheckFn by the grp: prefix, so a
// g: KV write or queue ack tied to a shard assignment fences out the moment the group rebalances.
func CheckFence(ctx context.Context, q core.Q, name string, epoch int64) error {
	gname := strings.TrimPrefix(name, fencePfx)
	var cur int64
	var hidden bool
	err := q.QueryRow(ctx, `SELECT epoch, hidden FROM groups WHERE name = $1`, gname).Scan(&cur, &hidden)
	if errors.Is(err, pgx.ErrNoRows) {
		return fencedErr(0)
	}
	if err != nil {
		return err
	}
	if hidden || cur != epoch {
		return fencedErr(cur)
	}
	return nil
}

func (s *svc) loadGroup(ctx context.Context, q core.Q, name string, lock bool) (group, error) {
	g := group{name: name}
	sql := `SELECT epoch, n, shards, ttl_s, owner_root, "distinct", on_change, hidden FROM groups WHERE name = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	err := q.QueryRow(ctx, sql, name).Scan(&g.epoch, &g.n, &g.shards, &g.ttl, &g.owner, &g.distinct, &g.onChange, &g.hidden)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, errNoGroup
	}
	return g, err
}

// superOf is root's registration super-group, or root:<root> when unknown (so unknown roots never
// collapse together under distinct).
func superOf(ctx context.Context, q core.Q, root string) (string, error) {
	st, err := trust.Load(ctx, q, root)
	if err != nil {
		return "", err
	}
	if st.Super == "" {
		return "root:" + root, nil
	}
	return st.Super, nil
}

// groupCap refuses creating a group past the root's live groups cap (4.3 groups row).
func (s *svc) groupCap(ctx context.Context, q core.Q, root string) error {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "grpcap:"+root); err != nil {
		return err
	}
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM groups WHERE owner_root = $1 AND NOT hidden`, root).Scan(&n); err != nil {
		return err
	}
	if capN := trust.Cap("groups", core.Level(ctx, q, root)); n >= capN {
		return core.E(429, "quota", "groups live "+itoa(capN))
	}
	return nil
}

// flap enforces and records one self-caused epoch bump for root (27.4: 30/h -> 429 err rate
// flapping). Reaps of other members are never charged, so a steady heartbeater is never limited.
func (s *svc) flap(ctx context.Context, q core.Q, root string) error {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM group_flaps WHERE root = $1 AND at > now() - interval '1 hour'`, root).Scan(&n); err != nil {
		return err
	}
	if n >= flapMax {
		return core.E(429, "rate", "flapping")
	}
	_, err := q.Exec(ctx, `INSERT INTO group_flaps (root) VALUES ($1)`, root)
	return err
}

// reap deletes members past their heartbeat deadline and returns the leavers (id, root) for the
// change events; the caller re-ranks and bumps the epoch when it reports any.
func (s *svc) reap(ctx context.Context, q core.Q, name string) ([][2]string, error) {
	rows, err := q.Query(ctx, `DELETE FROM group_members WHERE name = $1 AND until < now() RETURNING id, root`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][2]string
	for rows.Next() {
		var id, root string
		if err := rows.Scan(&id, &root); err != nil {
			return nil, err
		}
		out = append(out, [2]string{id, root})
	}
	return out, rows.Err()
}

// rerank recomputes dense ranks by (since, id) and bumps the epoch; distinct groups rank only the
// oldest member per super-group (the rest stand by at rank -1). Returns the new epoch and n.
func (s *svc) rerank(ctx context.Context, q core.Q, g group) (int64, int, error) {
	rows, err := q.Query(ctx, `SELECT id, super, rank FROM group_members WHERE name = $1 ORDER BY since, id`, g.name)
	if err != nil {
		return 0, 0, err
	}
	type mem struct {
		id, super string
		rank      int
	}
	var ms []mem
	for rows.Next() {
		var m mem
		if err := rows.Scan(&m.id, &m.super, &m.rank); err != nil {
			rows.Close()
			return 0, 0, err
		}
		ms = append(ms, m)
	}
	rows.Close()
	seen := map[string]bool{}
	n := 0
	for i := range ms {
		want := n
		if g.distinct {
			if seen[ms[i].super] {
				want = -1
			} else {
				seen[ms[i].super] = true
			}
		}
		if want >= 0 {
			n++
		}
		if ms[i].rank != want {
			if _, err := q.Exec(ctx, `UPDATE group_members SET rank = $3 WHERE name = $1 AND id = $2`, g.name, ms[i].id, want); err != nil {
				return 0, 0, err
			}
		}
	}
	var epoch int64
	err = q.QueryRow(ctx, `UPDATE groups SET n = $2, epoch = epoch + 1, touched = now() WHERE name = $1 RETURNING epoch`, g.name, n).Scan(&epoch)
	return epoch, n, err
}

// myRank reads the caller's rank in the group (-1 when not a member).
func (s *svc) myRank(ctx context.Context, q core.Q, name, id string) (int, error) {
	var rank int
	err := q.QueryRow(ctx, `SELECT rank FROM group_members WHERE name = $1 AND id = $2`, name, id).Scan(&rank)
	if errors.Is(err, pgx.ErrNoRows) {
		return -1, nil
	}
	return rank, err
}

// join is POST /v1/grp/{name} and op grp: join-or-heartbeat in one advisory-locked transaction,
// reaping expired members, re-ranking and bumping the epoch on any membership change.
func (s *svc) join(ctx context.Context, id *core.Ident, raw string, in joinIn, grp string) (reply, error) {
	n, err := parseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if in.TTL != 0 && (in.TTL < ttlMin || in.TTL > ttlMax) {
		return reply{}, core.Bad("ttl_s must be " + itoa(ttlMin) + ".." + itoa(ttlMax))
	}
	if in.Shards != 0 && (in.Shards < 1 || in.Shards > shardMax) {
		return reply{}, core.Bad("shards must be 1.." + itoa(shardMax))
	}
	if err := checkWait(in.Wait); err != nil {
		return reply{}, err
	}
	data, masked, err := cleanData(in.Data)
	if err != nil {
		return reply{}, err
	}
	if err := access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if err := s.frozen(); err != nil {
		return reply{}, err
	}
	out, err := s.joinTx(ctx, id, n, in, data)
	if err != nil {
		return reply{}, err
	}
	s.afterChange(ctx, n.full, out)
	retry := 0
	if in.Wait > 0 {
		joined := out.epoch
		retry, err = s.poll(ctx, id, grp, in.Wait, "grp:"+n.full, func(ctx context.Context) (bool, time.Time, error) {
			g, err := s.loadGroup(ctx, s.d.DB, n.full, false)
			if errors.Is(err, errNoGroup) {
				return true, time.Time{}, nil
			}
			if err != nil {
				return false, time.Time{}, err
			}
			if g.epoch == joined {
				return false, time.Time{}, nil
			}
			rank, err := s.myRank(ctx, s.d.DB, n.full, id.ID)
			if err != nil {
				return false, time.Time{}, err
			}
			out.epoch, out.n, out.rank = g.epoch, g.n, rank
			return true, time.Time{}, nil
		})
		if err != nil {
			return reply{}, err
		}
	}
	text := headJoin(out) + maskedField(masked)
	if retry > 0 {
		text += " retry=" + itoa(retry)
	}
	p := "/v1/grp/" + n.full
	return reply{text: text, next: []doc.Action{
		doc.GET(p+"?epoch="+strconv.FormatInt(out.epoch, 10)+"&wait=85", "watch"),
		doc.POST(p, "heartbeat"),
	}}, nil
}

func (s *svc) joinTx(ctx context.Context, id *core.Ident, n name, in joinIn, data string) (out outcome, err error) {
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "grp:"+n.full); err != nil {
			return err
		}
		g, err := s.loadGroup(ctx, tx, n.full, true)
		creating := false
		if errors.Is(err, errNoGroup) {
			shards := in.Shards
			if shards == 0 {
				shards = 1
			}
			ttl := in.TTL
			if ttl == 0 {
				ttl = ttlDef
			}
			onChange := ""
			if in.OnChange != nil {
				onChange = strings.TrimSpace(in.OnChange.PS)
			}
			if err := s.groupCap(ctx, tx, id.Root); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO groups (name, shards, ttl_s, owner_root, "distinct", on_change)
				VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (name) DO NOTHING`,
				n.full, shards, ttl, id.Root, in.Distinct, onChange); err != nil {
				return err
			}
			g, err = s.loadGroup(ctx, tx, n.full, true)
			creating = true
		}
		if err != nil {
			return err
		}
		if g.hidden {
			return core.ErrNotFound
		}
		out.topic = g.onChange
		// L0 cannot join a g: group it did not create.
		if n.ns == 'g' && !creating && g.owner != id.Root && core.Level(ctx, tx, id.Root) == 0 {
			return core.E(403, "auth", "l0 cannot join g: groups it did not create")
		}
		reaped, err := s.reap(ctx, tx, n.full)
		if err != nil {
			return err
		}
		var wasMember bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM group_members WHERE name = $1 AND id = $2)`, n.full, id.ID).Scan(&wasMember); err != nil {
			return err
		}
		selfJoined := false
		if wasMember {
			if _, err := tx.Exec(ctx, `UPDATE group_members SET until = now() + $3 * interval '1 second', data = $4
				WHERE name = $1 AND id = $2`, n.full, id.ID, g.ttl, data); err != nil {
				return err
			}
		} else {
			var live int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM group_members WHERE name = $1`, n.full).Scan(&live); err != nil {
				return err
			}
			if live >= maxMem {
				return core.E(409, "full", "members "+itoa(maxMem))
			}
			super, err := superOf(ctx, tx, id.Root)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO group_members (name, id, root, super, since, until, data)
				VALUES ($1, $2, $3, $4, now(), now() + $5 * interval '1 second', $6)`,
				n.full, id.ID, id.Root, super, g.ttl, data); err != nil {
				return err
			}
			selfJoined = true
		}
		changed := selfJoined || len(reaped) > 0
		if changed {
			if selfJoined {
				if err := s.flap(ctx, tx, id.Root); err != nil {
					return err
				}
			}
			epoch, nn, err := s.rerank(ctx, tx, g)
			if err != nil {
				return err
			}
			out.epoch, out.n, out.changed = epoch, nn, true
			if selfJoined {
				out.events = append(out.events, "member-joined "+n.full+" "+id.ID+" epoch="+strconv.FormatInt(epoch, 10))
			}
			for _, m := range reaped {
				out.events = append(out.events, "member-left "+n.full+" "+m[0]+" epoch="+strconv.FormatInt(epoch, 10))
			}
		} else {
			out.epoch, out.n = g.epoch, g.n
		}
		out.rank, err = s.myRank(ctx, tx, n.full, id.ID)
		return err
	})
	return out, err
}

// afterChange wakes the group's waiters and publishes the member-joined/left lines to on_change
// once the transaction has committed (a bad on_change topic can never roll back the membership).
func (s *svc) afterChange(ctx context.Context, name string, out outcome) {
	if !out.changed {
		return
	}
	s.d.Notify.Wake("grp:" + name)
	if out.topic == "" {
		return
	}
	for i, line := range out.events {
		key := fmt.Sprintf("grp:%s:%d:%d", name, out.epoch, i)
		_, _ = swarm.Publish(ctx, s.d.DB, out.topic, core.SystemID, core.SystemID, line, key)
	}
}

// headJoin renders the POST reply: `ok epoch=<e> rank=<r> n=<n> every=<n> from=<r>`, or for a
// distinct standby `ok epoch=<e> rank=-1 n=<n> standby`.
func headJoin(o outcome) string {
	if o.rank < 0 {
		return fmt.Sprintf("ok epoch=%d rank=-1 n=%d standby", o.epoch, o.n)
	}
	return fmt.Sprintf("ok epoch=%d rank=%d n=%d every=%d from=%d", o.epoch, o.rank, o.n, o.n, o.rank)
}

// get is GET /v1/grp/{name}?epoch=&wait= and op grpg: immediate when the stored epoch differs from
// the query epoch, else a long-poll until it moves; renders the epoch head and the member lines.
func (s *svc) get(ctx context.Context, id *core.Ident, raw string, epoch int64, hasEpoch bool, wait, grp string, waitS int) (reply, error) {
	n, err := parseName(raw, rootOf(id))
	if err != nil {
		return reply{}, err
	}
	if err := access(ctx, s.d.DB, id, n, false); err != nil {
		return reply{}, err
	}
	g, err := s.loadGroup(ctx, s.d.DB, n.full, false)
	if errors.Is(err, errNoGroup) || (err == nil && g.hidden) {
		return reply{}, core.ErrNotFound
	}
	if err != nil {
		return reply{}, err
	}
	retry := 0
	if hasEpoch && g.epoch == epoch && waitS > 0 {
		retry, err = s.poll(ctx, id, grp, waitS, "grp:"+n.full, func(ctx context.Context) (bool, time.Time, error) {
			cur, err := s.loadGroup(ctx, s.d.DB, n.full, false)
			if errors.Is(err, errNoGroup) {
				return true, time.Time{}, nil
			}
			if err != nil {
				return false, time.Time{}, err
			}
			g = cur
			return cur.hidden || cur.epoch != epoch, time.Time{}, nil
		})
		if err != nil {
			return reply{}, err
		}
		if g.hidden {
			return reply{}, core.ErrNotFound
		}
	}
	rep, err := s.render(ctx, n, g)
	if err != nil {
		return reply{}, err
	}
	if retry > 0 {
		rep.text += " retry=" + itoa(retry)
	}
	return rep, nil
}

func (s *svc) render(ctx context.Context, n name, g group) (reply, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "epoch=%d n=%d shards=%d", g.epoch, g.n, g.shards)
	rows, err := s.d.DB.Query(ctx, `SELECT id, rank, data FROM group_members WHERE name = $1 ORDER BY (rank < 0), rank, since, id`, n.full)
	if err != nil {
		return reply{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var mid, data string
		var rank int
		if err := rows.Scan(&mid, &rank, &data); err != nil {
			return reply{}, err
		}
		if rank < 0 {
			fmt.Fprintf(&b, "\n- %s standby", mid)
		} else {
			fmt.Fprintf(&b, "\n- %s rank=%d", mid, rank)
		}
		if data != "" {
			b.WriteString("\n  " + doc.Indent(data))
		}
	}
	if err := rows.Err(); err != nil {
		return reply{}, err
	}
	p := "/v1/grp/" + n.full
	return reply{text: b.String(), next: []doc.Action{doc.POST(p, "join"), doc.GET(p+"?epoch="+strconv.FormatInt(g.epoch, 10)+"&wait=85", "watch")}}, nil
}

// leave is DELETE /v1/grp/{name} and op grpx: remove the caller, reap, re-rank and bump the epoch.
func (s *svc) leave(ctx context.Context, id *core.Ident, raw string) (reply, error) {
	n, err := parseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if err := access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	out, err := s.leaveTx(ctx, id, n)
	if err != nil {
		return reply{}, err
	}
	s.afterChange(ctx, n.full, out)
	p := "/v1/grp/" + n.full
	return reply{text: fmt.Sprintf("ok left epoch=%d n=%d", out.epoch, out.n), next: []doc.Action{doc.POST(p, "rejoin")}}, nil
}

func (s *svc) leaveTx(ctx context.Context, id *core.Ident, n name) (out outcome, err error) {
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "grp:"+n.full); err != nil {
			return err
		}
		g, err := s.loadGroup(ctx, tx, n.full, true)
		if errors.Is(err, errNoGroup) {
			return core.ErrNotFound
		}
		if err != nil {
			return err
		}
		out.topic = g.onChange
		reaped, err := s.reap(ctx, tx, n.full)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM group_members WHERE name = $1 AND id = $2`, n.full, id.ID)
		if err != nil {
			return err
		}
		selfLeft := tag.RowsAffected() > 0
		changed := selfLeft || len(reaped) > 0
		if !changed {
			out.epoch, out.n = g.epoch, g.n
			return nil
		}
		if selfLeft {
			if err := s.flap(ctx, tx, id.Root); err != nil {
				return err
			}
		}
		epoch, nn, err := s.rerank(ctx, tx, g)
		if err != nil {
			return err
		}
		out.epoch, out.n, out.changed = epoch, nn, true
		if selfLeft {
			out.events = append(out.events, "member-left "+n.full+" "+id.ID+" epoch="+strconv.FormatInt(epoch, 10))
		}
		for _, m := range reaped {
			out.events = append(out.events, "member-left "+n.full+" "+m[0]+" epoch="+strconv.FormatInt(epoch, 10))
		}
		return nil
	})
	return out, err
}

// --- HTTP ---------------------------------------------------------------------------------------

func (s *svc) hJoin(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in joinIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.join(r.Context(), id, r.PathValue("name"), in, s.d.IPGroup(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) hGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	epoch, hasEpoch, err := queryInt64(r, "epoch")
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	waitS := 0
	if v := r.URL.Query().Get("wait"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 0 || n > MaxWait {
			doc.Fail(w, r, core.Bad("wait must be 0.."+itoa(MaxWait)))
			return
		}
		waitS = n
	}
	rep, err := s.get(r.Context(), id, r.PathValue("name"), epoch, hasEpoch, r.URL.Query().Get("wait"), s.d.IPGroup(r), waitS)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) hLeave(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.leave(r.Context(), id, r.PathValue("name"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

// --- janitor ------------------------------------------------------------------------------------

// janitor reaps expired members (bumping the epoch of every group that lost one so the survivors
// learn within ttl_s), deletes groups idle for 7 days, and sweeps the flap ledger.
func (s *svc) janitor(ctx context.Context) error {
	q := s.d.DB
	rows, err := q.Query(ctx, `SELECT DISTINCT name FROM group_members WHERE until < now() LIMIT 500`)
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
	for _, name := range names {
		var out outcome
		err := core.Tx(ctx, q, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "grp:"+name); err != nil {
				return err
			}
			g, err := s.loadGroup(ctx, tx, name, true)
			if err != nil {
				return err
			}
			reaped, err := s.reap(ctx, tx, name)
			if err != nil || len(reaped) == 0 {
				return err
			}
			epoch, nn, err := s.rerank(ctx, tx, g)
			if err != nil {
				return err
			}
			out.epoch, out.n, out.changed, out.topic = epoch, nn, true, g.onChange
			for _, m := range reaped {
				out.events = append(out.events, "member-left "+name+" "+m[0]+" epoch="+strconv.FormatInt(epoch, 10))
			}
			return nil
		})
		if err != nil && !errors.Is(err, errNoGroup) {
			return err
		}
		s.afterChange(ctx, name, out)
	}
	for _, st := range []string{
		`DELETE FROM groups WHERE touched < now() - interval '7 days' AND NOT EXISTS (SELECT 1 FROM group_members m WHERE m.name = groups.name)`,
		`DELETE FROM group_flaps WHERE at < now() - interval '1 hour'`,
	} {
		if _, err := q.Exec(ctx, st); err != nil {
			return err
		}
	}
	return nil
}
