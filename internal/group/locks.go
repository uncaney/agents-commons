package group

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/swarm"
)

// opaque swarm primitives on group-scoped names (5.4): locks and leader election reuse the swarm
// `locks` table through swarm.AcquireTx with the group id as the namespace, so the DS stays content-
// blind (the name k is an opaque hex handle, never inspected) and nothing is duplicated.

func lockName(gid, k string) string { return "g:" + gid + ":" + k }

// opaqueKey validates k: 1..64 lowercase hex chars, an opaque handle the server never interprets.
func opaqueKey(k string) (string, error) {
	if k == "" || len(k) > 64 {
		return "", core.Bad("k must be 1..64 hex chars")
	}
	if _, err := hex.DecodeString(k); err != nil {
		return "", core.Bad("k must be a hex handle")
	}
	return k, nil
}

func (s *svc) lockish(r *http.Request) (*core.Ident, *grpRow, *member, error) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		return nil, nil, nil, err
	}
	gid := r.PathValue("gid")
	if !core.ValidIDPrefix(gid, 'g') {
		return nil, nil, nil, core.Bad("gid must be a group id")
	}
	g, err := loadGroup(r.Context(), s.d.DB, gid)
	if err != nil {
		return nil, nil, nil, err
	}
	m, err := memberOf(r.Context(), s.d.DB, gid, id.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	return id, g, m, nil
}

type lockIn struct {
	K   string `json:"k"`
	TTL int    `json:"ttl"`
	N   int    `json:"n"`
}

func (s *svc) readLockIn(r *http.Request) (lockIn, error) {
	var in lockIn
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<10))
	if err != nil {
		return in, core.Bad("read")
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &in); err != nil {
			return in, core.Bad("body: " + err.Error())
		}
	}
	return in, nil
}

// lock is POST /v1/g/{gid}/lock {"k","ttl"}: take or renew an opaque lock scoped to the group.
func (s *svc) lock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, g, _, err := s.lockish(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	in, err := s.readLockIn(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	k, err := opaqueKey(in.K)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	ttl := in.TTL
	if ttl <= 0 || ttl > LockTTLMax {
		ttl = 300
	}
	var fence int64
	var until time.Time
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		fence, until, err = swarm.AcquireTx(r.Context(), tx, lockName(g.id, k), id.ID, id.Root, time.Duration(ttl)*time.Second)
		return err
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, "ok until="+until.UTC().Format(time.RFC3339)+" fence="+strconv.FormatInt(fence, 10),
		map[string]any{"ok": true, "until": until.Unix(), "fence": fence})
}

// lead is POST /v1/g/{gid}/lead {"k","ttl"}: leader election on an opaque name. The first caller to
// acquire the lock leads; a later caller is told who leads (the current fence).
func (s *svc) lead(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, g, me, err := s.lockish(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	in, err := s.readLockIn(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	k, err := opaqueKey(in.K)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	ttl := in.TTL
	if ttl <= 0 || ttl > LockTTLMax {
		ttl = 300
	}
	var fence int64
	var until time.Time
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		fence, until, err = swarm.AcquireTx(r.Context(), tx, lockName(g.id, k), id.ID, id.Root, time.Duration(ttl)*time.Second)
		return err
	})
	var ae *core.APIError
	if errors.As(err, &ae) && ae.Status == 409 {
		core.Text(w, r, 200, "ok leader=other", map[string]any{"ok": true, "leader": false})
		return
	}
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, "ok leader=self idx="+strconv.Itoa(me.idx)+" fence="+strconv.FormatInt(fence, 10)+" until="+until.UTC().Format(time.RFC3339),
		map[string]any{"ok": true, "leader": true, "idx": me.idx, "fence": fence, "until": until.Unix()})
}

// barrier is POST /v1/g/{gid}/barrier {"k","n"}: content-blind barrier on an opaque name; it trips
// when n distinct members have arrived at k.
func (s *svc) barrier(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, g, me, err := s.lockish(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	in, err := s.readLockIn(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	k, err := opaqueKey(in.K)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if in.N < 1 || in.N > g.maxN {
		core.Fail(w, r, core.Bad("n must be 1..max"))
		return
	}
	var count int
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, "gb:"+g.id+":"+k); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO grp_barrier (gid, k, gen, idx) VALUES ($1, $2, 0, $3) ON CONFLICT DO NOTHING`, g.id, k, me.idx); err != nil {
			return err
		}
		return tx.QueryRow(r.Context(), `SELECT count(*) FROM grp_barrier WHERE gid = $1 AND k = $2 AND gen = 0`, g.id, k).Scan(&count)
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	tripped := count >= in.N
	if tripped {
		s.d.Notify.Wake("gb:" + g.id + ":" + k)
	}
	text := "ok arrived=" + strconv.Itoa(count) + " n=" + strconv.Itoa(in.N)
	if tripped {
		text += " tripped"
	}
	core.Text(w, r, 200, text, map[string]any{"ok": true, "arrived": count, "n": in.N, "tripped": tripped})
}
