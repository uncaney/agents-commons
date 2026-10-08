package group

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
)

// randSeq is the random 40-bit sequence offset of a fresh group (5.4): the pull cursor is the
// group's own sequence, never a per-member counter.
func randSeq() int64 {
	var b [8]byte
	rand.Read(b[:])
	return int64(binary.BigEndian.Uint64(b[:])>>24) + 1
}

// rcpt signs the relay receipt (5.3, 4.4) with the online statement key.
func (s *svc) rcpt(hdr []byte, seq int64, at time.Time) []byte {
	return s.signer.SignBytes(e2e.GRcptBytes(hdr, uint64(seq), uint64(at.Unix())))
}

// rowRes is an accepted write.
type rowRes struct {
	Seq   int64
	At    time.Time
	Epoch int64
	Rcpt  []byte
}

func (r *rowRes) appText() string {
	return fmt.Sprintf("ok seq=%d at=%d rcpt=%s", r.Seq, r.At.Unix(), b64(r.Rcpt))
}

// --- create -------------------------------------------------------------------------------------

type createIn struct {
	CS     int    `json:"cs"`
	Max    int    `json:"max"`
	TTLD   int    `json:"ttl_d"`
	Commit string `json:"commit"`
}

// create is POST /v1/g: the creator posts the group's first commit (epoch 1). The gid, suite and
// roster come from the commit itself (the creator chose the gid, which the crypto binds); the server
// records the roster it can see, stores the commit at the group's first sequence and returns it.
func (s *svc) create(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if s.d.Frozen("mail") || s.d.Frozen("write") {
		core.Fail(w, r, errFrozen)
		return
	}
	if !id.Seed && id.Age() < 72*time.Hour {
		core.Fail(w, r, core.E(403, "standing", "group creators must be established (3 d old)"))
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		core.Fail(w, r, core.Bad("read"))
		return
	}
	var in createIn
	if err := json.Unmarshal(body, &in); err != nil {
		core.Fail(w, r, core.Bad("body: "+err.Error()))
		return
	}
	cs := e2e.Suite(in.CS)
	if !cs.Valid() {
		core.Fail(w, r, core.Bad("cs must be 1 or 2"))
		return
	}
	maxN := in.Max
	cap := e2e.MaxMembersCS1
	if cs == e2e.CS2 {
		cap = e2e.MaxMembersCS2
	}
	if maxN <= 0 || maxN > cap {
		core.Fail(w, r, core.Bad(fmt.Sprintf("max must be 1..%d for cs=%d", cap, in.CS)))
		return
	}
	if in.TTLD <= 0 || in.TTLD > 30 {
		core.Fail(w, r, core.Bad("ttl_d must be 1..30"))
		return
	}
	row, err := decodeB64(in.Commit)
	if err != nil {
		core.Fail(w, r, core.Bad("commit must be the base64url commit row"))
		return
	}
	pc, err := e2e.ParseCommit(row, cs)
	if err != nil {
		core.Fail(w, r, errBadRow)
		return
	}
	gid := pc.Hdr.GID
	if !core.ValidIDPrefix(gid, 'g') {
		core.Fail(w, r, core.Bad("the commit's gid must be a group id (g…)"))
		return
	}
	if pc.Hdr.Epoch != 1 || pc.Header.E != 1 || pc.Header.By != 1 || len(pc.Header.Rm) != 0 {
		core.Fail(w, r, core.Bad("a create commit must be epoch 1, by idx 1, no removals"))
		return
	}
	// The committer is the caller, roster idx 1; verify the commit signature under its pinned key.
	cb, found, err := keys.Bundle(r.Context(), s.d.DB, id.ID)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if !found {
		core.Fail(w, r, core.E(403, "sig", "no key published for "+id.ID))
		return
	}
	if !pc.VerifySig(cb.IK) {
		core.Fail(w, r, core.E(403, "sig", "the commit is not signed by the creator"))
		return
	}
	// Build the roster: committer at idx 1, each add at the next idx in order; every added bundle
	// must sit at the exact log leaf the commit names, so members run the DVR on the same bytes.
	ms := []member{{idx: 1, id: id.ID, root: id.Root, leaf: cb.LeafIdx(), ik: cb.IK, role: 1, sinceEpoch: 1}}
	for i, a := range pc.Header.Add {
		ab, err := keys.AtLeaf(r.Context(), s.d.DB, a.ID, a.Leaf)
		if err != nil {
			core.Fail(w, r, core.E(400, "roster", fmt.Sprintf("add %s: no bundle at leaf %d", a.ID, a.Leaf)))
			return
		}
		ms = append(ms, member{idx: i + 2, id: a.ID, root: ab.Root, leaf: int64(a.Leaf), ik: ab.IK, sinceEpoch: 1})
	}
	if len(ms) > maxN {
		core.Fail(w, r, core.Bad("roster exceeds max"))
		return
	}
	base := randSeq()
	at := time.Now().Truncate(time.Second)
	exp := at.Add(time.Duration(in.TTLD) * 24 * time.Hour)
	seq := base + 1
	rc := s.rcpt(pc.Hdr.Marshal(), seq, at)
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		if err := core.UseQuota(r.Context(), tx, id, "gcreate", GCreatePerDay); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO grp (id, cs, max_n, ttl_d, epoch, last_seq, bytes, creator_root, idle)
			VALUES ($1, $2, $3, $4, 1, $5, $6, $7, now())`, gid, int16(cs), maxN, in.TTLD, seq, len(row), id.Root); err != nil {
			if core.IsUniqueViolation(err) {
				return core.E(409, "taken", "a group with this id already exists")
			}
			return err
		}
		for _, m := range ms {
			if _, err := tx.Exec(r.Context(), `INSERT INTO grp_members (gid, idx, id, root, leaf, ik, role, since_epoch)
				VALUES ($1, $2, $3, $4, $5, $6, $7, 1)`, gid, m.idx, m.id, m.root, m.leaf, m.ik, m.role); err != nil {
				return err
			}
		}
		sig, _ := keys.SigFrom(r.Context())
		return insertRow(r.Context(), tx, gid, seq, 1, pc.Hdr, row, pc.Sig, rc, sig, at, exp)
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	s.d.Notify.Wake("g:" + gid)
	core.Text(w, r, 201, fmt.Sprintf("g=%s seq=%d epoch=1", gid, seq),
		map[string]any{"g": gid, "seq": seq, "epoch": 1, "rcpt": b64(rc)})
}

// insertRow stores one opaque row with its cleartext header, the member send-signature and the
// online relay receipt inside the caller's transaction.
func insertRow(ctx context.Context, q core.Q, gid string, seq, epoch int64, h *e2e.GHdr, body, sig, rc []byte, reqSig *e2e.ReqSig, at, exp time.Time) error {
	var ts int64
	var nonce, ssig []byte
	if reqSig != nil {
		ts, nonce, ssig = int64(reqSig.TS), reqSig.Nonce, reqSig.Sig
	}
	var to any
	_, err := q.Exec(ctx, `INSERT INTO grp_rows (gid, seq, kind, epoch, idx, gen, to_id, hdr, body, sig, rcpt, send_ts, send_nonce, send_sig, size, at, exp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		gid, seq, int16(h.Kind), epoch, int(h.Idx), int64(h.Gen), to, h.Marshal(), body, sig, rc, ts, nonce, ssig, len(body), at, exp)
	return err
}

// --- app message (kind 1) -----------------------------------------------------------------------

func (s *svc) postApp(w http.ResponseWriter, r *http.Request) {
	s.postRow(w, r, e2e.GKindApp)
}
func (s *svc) postCommit(w http.ResponseWriter, r *http.Request) {
	s.postRow(w, r, e2e.GKindCommit)
}
func (s *svc) postProposal(w http.ResponseWriter, r *http.Request) {
	s.postRow(w, r, e2e.GKindProposal)
}
func (s *svc) postWelcome(w http.ResponseWriter, r *http.Request) {
	s.postRow(w, r, e2e.GKindWelcome)
}

// postRow is the shared write path for app/commit/proposal/welcome: roster check, content-blind
// validation (5.4), the ordered insert with its receipt. The caller's identity and request
// signature come from keys.RequireSig.
func (s *svc) postRow(w http.ResponseWriter, r *http.Request, kind uint8) {
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
	if s.d.Frozen("mail") || s.d.Frozen("write") {
		core.Fail(w, r, errFrozen)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		core.Fail(w, r, core.Bad("read"))
		return
	}
	h, err := e2e.ParseGHdr(firstN(body, e2e.GHdrLen))
	if err != nil || h.Kind != kind || h.GID != gid {
		core.Fail(w, r, errBadRow)
		return
	}
	expect, hasExpect := int64(0), false
	if v := r.URL.Query().Get("expect"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			expect, hasExpect = n, true
		}
	}
	sig, _ := keys.SigFrom(r.Context())
	res, err := s.relay(r.Context(), id, gid, kind, h, body, sig, expect, hasExpect)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	s.d.Notify.Wake("g:" + gid)
	switch kind {
	case e2e.GKindCommit:
		core.Text(w, r, 200, fmt.Sprintf("ok seq=%d epoch=%d", res.Seq, res.Epoch),
			map[string]any{"ok": true, "seq": res.Seq, "epoch": res.Epoch, "rcpt": b64(res.Rcpt)})
	case e2e.GKindWelcome:
		core.Text(w, r, 200, "ok seq="+strconv.FormatInt(res.Seq, 10), map[string]any{"ok": true, "seq": res.Seq})
	default:
		core.Text(w, r, 200, res.appText(), map[string]any{"ok": true, "seq": res.Seq, "at": res.At.Unix(), "rcpt": b64(res.Rcpt)})
	}
}

func firstN(b []byte, n int) []byte {
	if len(b) < n {
		return b
	}
	return b[:n]
}

// relay runs the content-blind checks of 5.4 and inserts the row in one transaction.
func (s *svc) relay(ctx context.Context, id *core.Ident, gid string, kind uint8, h *e2e.GHdr, body []byte, sig *e2e.ReqSig, expect int64, hasExpect bool) (*rowRes, error) {
	cap := RowCap
	if kind == e2e.GKindCommit {
		cap = CommitRowCap
	}
	if len(body) > cap {
		return nil, core.E(413, "bad", "row exceeds the size cap")
	}
	var res *rowRes
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "g:"+gid); err != nil {
			return err
		}
		g, err := loadGroup(ctx, tx, gid)
		if err != nil {
			return err
		}
		if g.frozen {
			return errFrozen
		}
		me, err := memberOf(ctx, tx, gid, id.ID)
		if err != nil {
			return err
		}
		if int(h.Idx) != me.idx {
			return errBadIdx
		}
		switch kind {
		case e2e.GKindApp:
			return s.insertApp(ctx, tx, id, g, me, h, body, sig, expect, hasExpect, &res)
		case e2e.GKindCommit:
			return s.insertCommit(ctx, tx, id, g, me, body, sig, &res)
		case e2e.GKindProposal:
			return s.insertSimple(ctx, tx, id, g, me, h, body, sig, &res)
		case e2e.GKindWelcome:
			return s.insertWelcome(ctx, tx, id, g, me, body, sig, &res)
		}
		return errBadRow
	})
	return res, err
}

// insertApp validates and stores a kind-1 app message (5.3-5.4).
func (s *svc) insertApp(ctx context.Context, tx pgx.Tx, id *core.Ident, g *grpRow, me *member, h *e2e.GHdr, body []byte, sig *e2e.ReqSig, expect int64, hasExpect bool, out **rowRes) error {
	if g.pending > 0 {
		return core.E(409, "pending", fmt.Sprintf("commit-required %d", g.pending))
	}
	e := int64(h.Epoch)
	if e != g.epoch && e != g.epoch-1 {
		return core.E(409, "stale", fmt.Sprintf("epoch=%d", g.epoch))
	}
	m, err := e2e.ParseApp(body)
	if err != nil {
		return errBadRow
	}
	if !m.VerifySig(me.ik) {
		return core.E(403, "sig", "the row is not signed by the sender's key")
	}
	if err := s.quota(ctx, tx, id, len(body)); err != nil {
		return err
	}
	if err := g.budgetCheck(ctx, tx, len(body)); err != nil {
		return err
	}
	seq, at, err := bumpSeq(ctx, tx, g.id, len(body))
	if err != nil {
		return err
	}
	if hasExpect && seq != expect+1 {
		return core.E(409, "taken", strconv.FormatInt(seq, 10))
	}
	rc := s.rcpt(h.Marshal(), seq, at)
	exp := at.Add(time.Duration(g.ttlD) * 24 * time.Hour)
	if err := insertRow(ctx, tx, g.id, seq, e, h, body, m.Sig, rc, sig, at, exp); err != nil {
		if core.IsUniqueViolation(err) {
			return core.E(409, "gen", "a row with this (idx, gen) already exists")
		}
		return err
	}
	*out = &rowRes{Seq: seq, At: at, Epoch: g.epoch, Rcpt: rc}
	return core.Audit(ctx, tx, id.ID, "g", g.id+"/"+strconv.FormatInt(seq, 10), len(body))
}

// insertSimple stores a proposal row (kind 3) after the signature check.
func (s *svc) insertSimple(ctx context.Context, tx pgx.Tx, id *core.Ident, g *grpRow, me *member, h *e2e.GHdr, body []byte, sig *e2e.ReqSig, out **rowRes) error {
	p, err := e2e.ParseProposal(body)
	if err != nil {
		return errBadRow
	}
	if !p.VerifySig(me.ik) {
		return core.E(403, "sig", "the proposal is not signed by the sender's key")
	}
	if err := s.quota(ctx, tx, id, len(body)); err != nil {
		return err
	}
	seq, at, err := bumpSeq(ctx, tx, g.id, len(body))
	if err != nil {
		return err
	}
	rc := s.rcpt(h.Marshal(), seq, at)
	exp := at.Add(time.Duration(g.ttlD) * 24 * time.Hour)
	if err := insertRow(ctx, tx, g.id, seq, int64(h.Epoch), h, body, p.Sig, rc, sig, at, exp); err != nil {
		if core.IsUniqueViolation(err) {
			return core.E(409, "gen", "a row with this (idx, gen) already exists")
		}
		return err
	}
	*out = &rowRes{Seq: seq, At: at, Epoch: g.epoch, Rcpt: rc}
	return nil
}

// quota consumes the sender's daily message and byte quotas (5.5).
func (s *svc) quota(ctx context.Context, q core.Q, id *core.Ident, size int) error {
	if err := core.UseQuota(ctx, q, id, "gmsg", GMsgPerDay); err != nil {
		return err
	}
	var n int
	if err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, 'gbytes', current_date, $2)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, "root:"+id.Root, size).Scan(&n); err != nil {
		return err
	}
	if n > GBytesPerDay {
		return core.E(429, "quota", "gbytes: 4 MiB per day")
	}
	return nil
}

func (g *grpRow) budgetCheck(ctx context.Context, q core.Q, size int) error {
	if g.bytes+int64(size) > GroupBytes {
		return core.E(429, "quota", "group live bytes: 4 MiB")
	}
	return nil
}

// bumpSeq advances the group's total-order sequence and idle marker, returning the new seq.
func bumpSeq(ctx context.Context, q core.Q, gid string, size int) (int64, time.Time, error) {
	at := time.Now().Truncate(time.Second)
	var seq int64
	err := q.QueryRow(ctx, `UPDATE grp SET last_seq = last_seq + 1, bytes = bytes + $2, idle = now() WHERE id = $1 RETURNING last_seq`, gid, size).Scan(&seq)
	return seq, at, err
}

// --- pull ---------------------------------------------------------------------------------------

// pull is GET /v1/g/{gid}/m?from=<seq>: rows with seq > from, at most 100 (roster-checked).
func (s *svc) pull(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, g, _, err := s.authMember(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	text, err := s.rows(r.Context(), g.id, from)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, text, nil)
}

// wait is GET /v1/g/{gid}/wait?from=<seq>: pull with a server-fixed hold on the group topic.
func (s *svc) wait(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, g, _, err := s.authMember(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	var last int64
	if err := s.d.DB.QueryRow(r.Context(), `SELECT last_seq FROM grp WHERE id = $1`, g.id).Scan(&last); err != nil {
		core.Fail(w, r, err)
		return
	}
	if last <= from {
		ctx, cancel := context.WithTimeout(r.Context(), WaitHold)
		defer cancel()
		s.d.Notify.Wait(ctx, "g:"+g.id, WaitHold)
	}
	text, err := s.rows(r.Context(), g.id, from)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, text, nil)
}

// rows renders the lines `<seq> <at> <kind> <idx> <rcpt> <send_sig> <b64url row>` (5.4).
func (s *svc) rows(ctx context.Context, gid string, from int64) (string, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT seq, at, kind, idx, rcpt, send_sig, body FROM grp_rows
		WHERE gid = $1 AND seq > $2 ORDER BY seq LIMIT $3`, gid, from, PullMax)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var seq int64
		var at time.Time
		var kind, idx int
		var rc, ssig, body []byte
		if err := rows.Scan(&seq, &at, &kind, &idx, &rc, &ssig, &body); err != nil {
			return "", err
		}
		out = append(out, fmt.Sprintf("%d %d %d %d %s %s %s", seq, at.Unix(), kind, idx, b64(rc), b64(ssig), b64(body)))
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	var text string
	for _, l := range out {
		text += l + "\n"
	}
	return text, nil
}
