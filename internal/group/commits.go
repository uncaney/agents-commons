package group

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
)

// insertCommit validates a commit (5.4), advances the epoch under a CAS, stores the row and applies
// the membership change (adds join the roster, removes move to the tomb, covered pending proposals
// clear). All checks are content-blind: the server reads the cleartext header, never the envelopes.
func (s *svc) insertCommit(ctx context.Context, tx pgx.Tx, id *core.Ident, g *grpRow, me *member, body []byte, sig *e2e.ReqSig, out **rowRes) error {
	cs := e2e.Suite(g.cs)
	c, err := e2e.ParseCommit(body, cs)
	if err != nil {
		return errBadRow
	}
	if int(c.Header.By) != me.idx {
		return core.E(403, "roster", "the commit's by must be the committer's idx")
	}
	if !c.VerifySig(me.ik) {
		return core.E(403, "sig", "the commit is not signed by the committer")
	}
	newEpoch := g.epoch + 1
	if int64(c.Hdr.Epoch) != newEpoch || int64(c.Header.E) != newEpoch {
		return errStaleEpoch(g.epoch)
	}
	// Removals must name current members; adds must sit at the exact log leaf they name.
	ms, err := roster(ctx, tx, g.id)
	if err != nil {
		return err
	}
	byIdx := map[int]member{}
	maxIdx := 0
	for _, m := range ms {
		byIdx[m.idx] = m
		if m.idx > maxIdx {
			maxIdx = m.idx
		}
	}
	for _, rm := range c.Header.Rm {
		if _, ok := byIdx[int(rm)]; !ok {
			return core.E(400, "roster", fmt.Sprintf("remove %d: not a member", rm))
		}
	}
	type add struct {
		id, root string
		leaf     int64
		ik       []byte
	}
	var adds []add
	for _, a := range c.Header.Add {
		ab, err := keys.AtLeaf(ctx, tx, a.ID, a.Leaf)
		if err != nil {
			return core.E(400, "roster", fmt.Sprintf("add %s: no bundle at leaf %d", a.ID, a.Leaf))
		}
		adds = append(adds, add{id: a.ID, root: ab.Root, leaf: int64(a.Leaf), ik: ab.IK})
	}
	final := len(ms) - len(c.Header.Rm) + len(adds)
	if final > g.maxN {
		return core.Bad("roster would exceed max")
	}
	// Every open server-originated proposal must be covered by pp.
	if err := coverPending(ctx, tx, g, c.Header.PP); err != nil {
		return err
	}
	// Epoch CAS: exactly one committer wins the race for this epoch.
	tag, err := tx.Exec(ctx, `UPDATE grp SET epoch = epoch + 1 WHERE id = $1 AND epoch = $2`, g.id, g.epoch)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var cur int64
		tx.QueryRow(ctx, `SELECT epoch FROM grp WHERE id = $1`, g.id).Scan(&cur)
		return errStaleEpoch(cur)
	}
	// Apply membership.
	for _, rm := range c.Header.Rm {
		m := byIdx[int(rm)]
		if _, err := tx.Exec(ctx, `INSERT INTO grp_members_tomb (gid, idx, id, root, left_epoch) VALUES ($1, $2, $3, $4, $5)`,
			g.id, m.idx, m.id, m.root, newEpoch); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM grp_members WHERE gid = $1 AND idx = $2`, g.id, m.idx); err != nil {
			return err
		}
	}
	for i, a := range adds {
		if _, err := tx.Exec(ctx, `INSERT INTO grp_members (gid, idx, id, root, leaf, ik, role, since_epoch)
			VALUES ($1, $2, $3, $4, $5, $6, 0, $7)`, g.id, maxIdx+1+i, a.id, a.root, a.leaf, a.ik, newEpoch); err != nil {
			if core.IsUniqueViolation(err) {
				return core.E(409, "roster", "add "+a.id+" is already a member")
			}
			return err
		}
	}
	seq, at, err := bumpSeq(ctx, tx, g.id, len(body))
	if err != nil {
		return err
	}
	rc := s.rcpt(c.Hdr.Marshal(), seq, at)
	exp := at.Add(time.Duration(g.ttlD) * 24 * time.Hour)
	if err := insertRow(ctx, tx, g.id, seq, newEpoch, c.Hdr, body, c.Sig, rc, sig, at, exp); err != nil {
		if core.IsUniqueViolation(err) {
			return core.E(409, "gen", "a row with this (idx, gen) already exists")
		}
		return err
	}
	*out = &rowRes{Seq: seq, At: at, Epoch: newEpoch, Rcpt: rc}
	return core.Audit(ctx, tx, id.ID, "g", g.id+"/commit/"+strconv.FormatInt(newEpoch, 10), len(body))
}

// coverPending refuses a commit that does not cover every open server-originated proposal, then
// clears them (5.5).
func coverPending(ctx context.Context, tx pgx.Tx, g *grpRow, pp []uint64) error {
	if g.pending == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT pseq FROM grp_pending WHERE gid = $1`, g.id)
	if err != nil {
		return err
	}
	var open []int64
	for rows.Next() {
		var ps int64
		if err := rows.Scan(&ps); err != nil {
			rows.Close()
			return err
		}
		open = append(open, ps)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	have := map[int64]bool{}
	for _, p := range pp {
		have[int64(p)] = true
	}
	for _, ps := range open {
		if !have[ps] {
			return core.E(400, "bad", fmt.Sprintf("pp must cover pending proposal %d", ps))
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM grp_pending WHERE gid = $1`, g.id); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE grp SET pending = 0 WHERE id = $1`, g.id)
	return err
}

// insertWelcome stores a kind-4 welcome row (5.3-5.4): accepted only for a To that the roster now
// holds (a prior commit added it, or it is an existing member re-keying).
func (s *svc) insertWelcome(ctx context.Context, tx pgx.Tx, id *core.Ident, g *grpRow, me *member, body []byte, sig *e2e.ReqSig, out **rowRes) error {
	wc, err := e2e.ParseWelcome(body, e2e.Suite(g.cs))
	if err != nil {
		return errBadRow
	}
	if !wc.VerifySig(me.ik) {
		return core.E(403, "sig", "the welcome is not signed by the committer")
	}
	if _, err := memberOf(ctx, tx, g.id, wc.To); err != nil {
		return core.E(409, "roster", "a welcome is accepted only for a current member")
	}
	if err := core.UseQuota(ctx, tx, id, "gwelcome", GWelcomePerDay); err != nil {
		return err
	}
	seq, at, err := bumpSeq(ctx, tx, g.id, len(body))
	if err != nil {
		return err
	}
	rc := s.rcpt(wc.Hdr.Marshal(), seq, at)
	exp := at.Add(time.Duration(g.ttlD) * 24 * time.Hour)
	if _, err := tx.Exec(ctx, `INSERT INTO grp_rows (gid, seq, kind, epoch, idx, gen, to_id, hdr, body, sig, rcpt, size, at, exp)
		VALUES ($1, $2, 4, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		g.id, seq, int64(wc.Hdr.Epoch), int(wc.Hdr.Idx), int64(wc.Hdr.Gen), wc.To, wc.Hdr.Marshal(), body, wc.Sig, rc, len(body), at, exp); err != nil {
		if core.IsUniqueViolation(err) {
			return core.E(409, "gen", "a row with this (idx, gen) already exists")
		}
		return err
	}
	*out = &rowRes{Seq: seq, At: at, Epoch: g.epoch, Rcpt: rc}
	return nil
}

// invites is GET /v1/g/inv: pending welcomes addressed to the caller across all groups.
func (s *svc) invites(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	rows, err := s.d.DB.Query(r.Context(), `SELECT gid, idx, seq, body FROM grp_rows WHERE kind = 4 AND to_id = $1 ORDER BY at DESC LIMIT 100`, id.ID)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	defer rows.Close()
	var b string
	for rows.Next() {
		var gid string
		var idx int
		var seq int64
		var body []byte
		if err := rows.Scan(&gid, &idx, &seq, &body); err != nil {
			core.Fail(w, r, err)
			return
		}
		b += fmt.Sprintf("%s %d %d %s\n", gid, idx, seq, b64(body))
	}
	if err := rows.Err(); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, b, nil)
}
