package group

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
)

// srvProp is the cleartext header of a server-originated proposal (5.5): the lawful lever. by is the
// string "server", never a member idx, so clients can tell it apart from a member proposal.
type srvProp struct {
	Rm  []int  `json:"rm"`
	By  string `json:"by"`
	Why string `json:"why"`
}

// serverRemove is the one operation the server may take on the roster (5.5): it inserts a kind-3
// proposal signed with the online key, deletes the member from grp_members immediately (no more
// reads or writes), tombstones it, and raises the pending gate. A member clears it by landing a
// commit whose pp covers the proposal. The server can only ever remove, never inject a member.
func (s *svc) serverRemove(ctx context.Context, tx pgx.Tx, g *grpRow, m *member, basis string) (int64, error) {
	var gen int64
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(gen), 0) + 1 FROM grp_rows WHERE gid = $1 AND idx = 0`, g.id).Scan(&gen); err != nil {
		return 0, err
	}
	js, err := json.Marshal(srvProp{Rm: []int{m.idx}, By: "server", Why: basis})
	if err != nil {
		return 0, err
	}
	hdr := (&e2e.GHdr{Kind: e2e.GKindProposal, GID: g.id, Epoch: uint32(g.epoch), Idx: 0, Gen: uint32(gen), Pol: 0,
		S: make([]byte, 32), C: make([]byte, 32)}).Marshal()
	sig := s.signer.SignBytes(e2e.Labeled(e2e.LabelGSig, hdr, js))
	row := append(append(append([]byte{}, hdr...), e2e.U16(uint16(len(js)))...), js...)
	row = append(row, sig...)
	seq, at, err := bumpSeq(ctx, tx, g.id, len(row))
	if err != nil {
		return 0, err
	}
	rc := s.rcpt(hdr, seq, at)
	exp := at.Add(time.Duration(g.ttlD) * 24 * time.Hour)
	if _, err := tx.Exec(ctx, `INSERT INTO grp_rows (gid, seq, kind, epoch, idx, gen, hdr, body, sig, rcpt, size, at, exp)
		VALUES ($1, $2, 3, $3, 0, $4, $5, $6, $7, $8, $9, $10, $11)`,
		g.id, seq, int64(g.epoch), gen, hdr, row, sig, rc, len(row), at, exp); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO grp_pending (gid, pseq, idx, basis) VALUES ($1, $2, $3, $4)`, g.id, seq, m.idx, basis); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO grp_members_tomb (gid, idx, id, root, left_epoch) VALUES ($1, $2, $3, $4, $5)`,
		g.id, m.idx, m.id, m.root, g.epoch); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM grp_members WHERE gid = $1 AND idx = $2`, g.id, m.idx); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE grp SET pending = pending + 1, idle = now() WHERE id = $1`, g.id); err != nil {
		return 0, err
	}
	return seq, nil
}

// leave is POST /v1/g/{gid}/leave: a member asks to be removed; the server removes it (5.5).
func (s *svc) leave(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	gid := r.PathValue("gid")
	if !core.ValidIDPrefix(gid, 'g') {
		core.Fail(w, r, core.Bad("gid must be a group id"))
		return
	}
	var seq int64
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, "g:"+gid); err != nil {
			return err
		}
		g, err := loadGroup(r.Context(), tx, gid)
		if err != nil {
			return err
		}
		m, err := memberOf(r.Context(), tx, gid, id.ID)
		if err != nil {
			return err
		}
		seq, err = s.serverRemove(r.Context(), tx, g, m, "leave")
		return err
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	s.d.Notify.Wake("g:" + gid)
	core.Text(w, r, 200, fmt.Sprintf("ok removed pending seq=%d", seq), map[string]any{"ok": true, "pending": seq})
}

// remove is POST /v1/g/{gid}/remove {"idx"|"id"}: an admin (role 1) triggers a server-originated
// removal of a member (basis admin). Owner removals of this kind are the lawful lever just like a
// purge; a member-initiated membership change is a commit, not this route.
func (s *svc) remove(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	gid := r.PathValue("gid")
	if !core.ValidIDPrefix(gid, 'g') {
		core.Fail(w, r, core.Bad("gid must be a group id"))
		return
	}
	body, _ := io.ReadAll(r.Body)
	var in struct {
		Idx int    `json:"idx"`
		ID  string `json:"id"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &in); err != nil {
			core.Fail(w, r, core.Bad("body: "+err.Error()))
			return
		}
	}
	var seq int64
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, "g:"+gid); err != nil {
			return err
		}
		g, err := loadGroup(r.Context(), tx, gid)
		if err != nil {
			return err
		}
		caller, err := memberOf(r.Context(), tx, gid, id.ID)
		if err != nil {
			return err
		}
		if caller.role != 1 {
			return core.E(403, "roster", "only an admin may remove a member")
		}
		var target *member
		if in.ID != "" {
			target, err = memberOf(r.Context(), tx, gid, in.ID)
		} else {
			target, err = memberByIdx(r.Context(), tx, gid, in.Idx)
		}
		if err != nil {
			return err
		}
		if target.idx == caller.idx {
			return core.Bad("use leave to remove yourself")
		}
		seq, err = s.serverRemove(r.Context(), tx, g, target, "admin")
		return err
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	s.d.Notify.Wake("g:" + gid)
	core.Text(w, r, 200, fmt.Sprintf("ok removed pending seq=%d", seq), map[string]any{"ok": true, "pending": seq})
}

func memberByIdx(ctx context.Context, q core.Q, gid string, idx int) (*member, error) {
	m := &member{}
	err := q.QueryRow(ctx, `SELECT idx, id, root, leaf, ik, role, since_epoch FROM grp_members WHERE gid = $1 AND idx = $2`, gid, idx).
		Scan(&m.idx, &m.id, &m.root, &m.leaf, &m.ik, &m.role, &m.sinceEpoch)
	if err != nil {
		return nil, errNotMember
	}
	return m, nil
}

// del is DELETE /v1/g/{gid}: the creator deletes the whole group (full deletability, D6). Rows,
// roster, state and snapshots cascade; nothing survives in a backup.
func (s *svc) del(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	gid := r.PathValue("gid")
	if !core.ValidIDPrefix(gid, 'g') {
		core.Fail(w, r, core.Bad("gid must be a group id"))
		return
	}
	g, err := loadGroup(r.Context(), s.d.DB, gid)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if g.creatorRoot != id.Root {
		core.Fail(w, r, core.E(403, "roster", "only the creator may delete the group"))
		return
	}
	if _, err := s.d.DB.Exec(r.Context(), `DELETE FROM grp WHERE id = $1`, gid); err != nil {
		core.Fail(w, r, err)
		return
	}
	s.d.Notify.Wake("g:" + gid)
	core.Text(w, r, 200, "ok deleted", map[string]any{"ok": true})
}

// purge is the OnPurge hook (5.5): a purged root is server-removed from every group it belongs to.
func (s *svc) purge(ctx context.Context, root string) error {
	rows, err := s.d.DB.Query(ctx, `SELECT DISTINCT gid FROM grp_members WHERE root = $1`, root)
	if err != nil {
		return err
	}
	var gids []string
	for rows.Next() {
		var gid string
		if err := rows.Scan(&gid); err != nil {
			rows.Close()
			return err
		}
		gids = append(gids, gid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, gid := range gids {
		err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "g:"+gid); err != nil {
				return err
			}
			g, err := loadGroup(ctx, tx, gid)
			if err != nil {
				return err
			}
			ms, err := roster(ctx, tx, gid)
			if err != nil {
				return err
			}
			for i := range ms {
				if ms[i].root == root {
					if _, err := s.serverRemove(ctx, tx, g, &ms[i], "purge"); err != nil {
						return err
					}
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		s.d.Notify.Wake("g:" + gid)
	}
	return nil
}

// exists/hide/restore back the report target g: (4.7); hide freezes the group, restore thaws it.
func exists(ctx context.Context, q core.Q, ref string) error {
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM grp WHERE id = $1)`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func hide(ctx context.Context, q core.Q, ref string) error {
	_, err := q.Exec(ctx, `UPDATE grp SET frozen = true WHERE id = $1`, ref)
	return err
}

func restore(ctx context.Context, q core.Q, ref string) error {
	_, err := q.Exec(ctx, `UPDATE grp SET frozen = false WHERE id = $1`, ref)
	return err
}

// resumeLines lists the caller's groups on GET /v1/me/resume (10.1).
func resumeLines(ctx context.Context, q core.Q, root string) []string {
	rows, err := q.Query(ctx, `SELECT g.id, g.epoch, g.pending FROM grp g JOIN grp_members m ON m.gid = g.id WHERE m.root = $1 ORDER BY g.idle DESC LIMIT 20`, root)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var gid string
		var epoch int64
		var pending int
		if err := rows.Scan(&gid, &epoch, &pending); err != nil {
			return out
		}
		line := fmt.Sprintf("group %s epoch=%d", gid, epoch)
		if pending > 0 {
			line += " pending=" + strconv.Itoa(pending) + " (commit to clear)"
		}
		out = append(out, line)
	}
	return out
}

// meLines adds the caller's group count to GET /v1/me (3.6).
func meLines(ctx context.Context, q core.Q, id *core.Ident) []string {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM grp_members WHERE root = $1`, id.Root).Scan(&n); err != nil || n == 0 {
		return nil
	}
	return []string{"groups=" + strconv.Itoa(n)}
}
