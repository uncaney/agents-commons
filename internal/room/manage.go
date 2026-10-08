package room

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// counts are the per-primitive row counts of a room's namespace (r:<id> prefix), read-only over the
// owners' tables. These are the room-wide caps of 27.9 (2000 kv, 10 topics, 5 queues, 16 locks).
type counts struct {
	KV, Topics, Queues, Locks int
}

// overCap reports whether any room-wide cap is exceeded.
func (c counts) overCap() bool {
	return c.KV > MaxKV || c.Topics > MaxTopics || c.Queues > MaxQueues || c.Locks > MaxLocks
}

// countRoom tallies the live primitive rows under r:<id> by prefix (kv ns is the exact r:<id>; the
// swarm primitives are r:<id>.<name>). The room id is base32 only, so it carries no LIKE wildcard.
func countRoom(ctx context.Context, q core.Q, id string) (counts, error) {
	var c counts
	pfx := ns(id) + ".%"
	err := q.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM kv WHERE ns = $1),
		(SELECT count(*) FROM topics WHERE name LIKE $2),
		(SELECT count(*) FROM queues WHERE name LIKE $2),
		(SELECT count(*) FROM locks WHERE name LIKE $2)`, ns(id), pfx).
		Scan(&c.KV, &c.Topics, &c.Queues, &c.Locks)
	return c, err
}

// info serves GET /v1/room/{id} (members): the peers and the per-primitive counts of the room.
func (s *svc) info(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	seg, _ := doc.SplitSuffix(r.PathValue("id"))
	if !core.ValidIDPrefix(seg, 'o') {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	rr, err := s.byID(r.Context(), s.d.DB, seg)
	if errors.Is(err, errMiss) {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	// Members only: the owner, or any joined root. Non-members get the same 404 (nothing is listed).
	if id.Root != rr.OwnerRoot {
		ok, err := IsMember(r.Context(), s.d.DB, seg, id.Root)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		if !ok {
			doc.Fail(w, r, core.ErrNotFound)
			return
		}
	}
	c, err := countRoom(r.Context(), s.d.DB, seg)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{
		Head:    fmt.Sprintf("room %s peers=%d/%d exp=%s", rr.ID, rr.Members, rr.Cap, core.Date(rr.Until)),
		Title:   "room " + rr.ID,
		Desc:    "members, expiry and per-primitive counts of one room",
		NoIndex: true,
		MaxAge:  -1,
		Fields: []doc.F{
			{Name: "closed", Val: boolStr(rr.Closed)},
			{Name: "kv", Val: fmt.Sprintf("%d/%d", c.KV, MaxKV)},
			{Name: "topics", Val: fmt.Sprintf("%d/%d", c.Topics, MaxTopics)},
			{Name: "queues", Val: fmt.Sprintf("%d/%d", c.Queues, MaxQueues)},
			{Name: "locks", Val: fmt.Sprintf("%d/%d", c.Locks, MaxLocks)},
		},
	}
	if rr.Name != "" {
		d.Fields = append([]doc.F{{Name: "name", Val: doc.SafeLine(rr.Name)}}, d.Fields...)
	}
	if id.Root == rr.OwnerRoot {
		d.Fields = append(d.Fields, doc.F{Name: "owner", Val: "you"})
	}
	doc.Reply(w, r, http.StatusOK, d)
}

// kick serves POST /v1/room/{id}/kick {"id"} (owner): removes one member by identity id.
func (s *svc) kick(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") {
		return
	}
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	seg := r.PathValue("id")
	if !core.ValidIDPrefix(seg, 'o') {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if in.ID == "" {
		doc.Fail(w, r, core.Bad("id required (the member identity id to kick)"))
		return
	}
	var members int
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		rr, e := s.ownerRoom(r.Context(), tx, seg, id.Root)
		if e != nil {
			return e
		}
		if _, e := tx.Exec(r.Context(), `DELETE FROM room_members WHERE room = $1 AND id = $2`, rr.ID, in.ID); e != nil {
			return e
		}
		return tx.QueryRow(r.Context(), `UPDATE rooms SET members = (SELECT count(DISTINCT root) FROM room_members WHERE room = $1)
			WHERE id = $1 RETURNING members`, rr.ID).Scan(&members)
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusOK, fmt.Sprintf("ok room=%s peers=%d", seg, members), doc.GET("/v1/room/"+seg, ""))
}

// del serves DELETE /v1/room/{id} (owner): tears the room down now (every r:<id> row and the room).
func (s *svc) del(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") {
		return
	}
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	seg := r.PathValue("id")
	if !core.ValidIDPrefix(seg, 'o') {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		if _, e := s.ownerRoom(r.Context(), tx, seg, id.Root); e != nil {
			return e
		}
		return cleanupRoom(r.Context(), tx, seg)
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusOK, "ok deleted room="+seg, doc.POST("/v1/room", ""))
}

// ownerRoom loads a room and asserts root owns it; ErrNotFound when it does not exist or is not
// owned (nothing is listed, so a non-owner never learns the room exists).
func (s *svc) ownerRoom(ctx context.Context, q core.Q, id, root string) (*roomRow, error) {
	rr, err := s.byID(ctx, q, id)
	if errors.Is(err, errMiss) || (err == nil && rr.OwnerRoot != root) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return rr, nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
