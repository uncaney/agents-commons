package xmail

import (
	"context"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
)

// klogAppend appends a leaf to the key log (E2EE 3.3) inside the caller's transaction: kind 6 state
// receipts and kind 4 successions are written here, under the same advisory lock and with the same
// leaf and node hashing as the keys package (e2e.KlogLeaf, e2e.NodeHash over the perfect subtrees).
func klogAppend(ctx context.Context, q core.Q, kind uint8, id string, seq int, item []byte) (uint64, error) {
	if len(item) != 32 {
		return 0, errors.New("xmail: item hash must be 32 bytes")
	}
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "klog"); err != nil {
		return 0, err
	}
	n, err := keys.LogSize(ctx, q)
	if err != nil {
		return 0, err
	}
	leaf := e2e.KlogLeaf(kind, id, item, n)
	if _, err := q.Exec(ctx, `INSERT INTO klog (idx, kind, id, seq, item_hash, leaf) VALUES ($1, $2, $3, $4, $5, $6)`,
		int64(n), int16(kind), id, seq, item, leaf); err != nil {
		return 0, err
	}
	h, level, pos := leaf, 0, n
	for {
		if _, err := q.Exec(ctx, `INSERT INTO knodes (level, pos, hash) VALUES ($1, $2, $3) ON CONFLICT (level, pos) DO UPDATE SET hash = EXCLUDED.hash`,
			int16(level), int64(pos), h); err != nil {
			return 0, err
		}
		if pos&1 == 0 {
			break
		}
		var left []byte
		if err := q.QueryRow(ctx, `SELECT hash FROM knodes WHERE level = $1 AND pos = $2`, int16(level), int64(pos-1)).Scan(&left); err != nil {
			return 0, fmt.Errorf("xmail: klog node %d:%d: %w", level, pos-1, err)
		}
		h, level, pos = e2e.NodeHash(left, h), level+1, pos>>1
	}
	return n, nil
}

// --- sealed state (7.2) ---------------------------------------------------------------------------

// statePut is PUT /v1/x/state (raw <= 64 KiB, If-Match: <ver>, X-Cx-Sig): compare-and-swap on ver,
// 60 writes/day, a kind 6 receipt sha256(id || u64(ver) || sha256(blob)) per accepted write.
func (s *svc) statePut(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	blob, err := io.ReadAll(r.Body)
	if err != nil {
		core.Fail(w, r, core.Bad("read"))
		return
	}
	if len(blob) < 1+32+16 || len(blob) > e2e.StateCap || blob[0] != e2e.StateVer {
		core.Fail(w, r, core.Bad("state blob must be 0x01 | s[32] | ciphertext, at most 64 KiB"))
		return
	}
	var want int64
	if m := strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), `"`); m != "" {
		if want, err = strconv.ParseInt(m, 10, 64); err != nil || want < 0 {
			core.Fail(w, r, core.Bad("If-Match must be the current ver (0 for the first write)"))
			return
		}
	}
	ctx := r.Context()
	var ver int64
	var leaf uint64
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := core.UseQuota(ctx, tx, id, "xstate", StatePerDay); err != nil {
			return err
		}
		// Fold the compare-and-swap into the write so the no-row case cannot double-apply: a fresh
		// id inserts ver=want+1 (want must be 0 for the first write), an existing row advances only
		// when its committed ver still equals want. On the 0->1 race the loser's DO UPDATE sees the
		// committed ver=1, its WHERE x_state.ver=want(0) fails, no row comes back and it is a 409.
		err := tx.QueryRow(ctx, `INSERT INTO x_state (id, ver, blob, updated) VALUES ($1, $2, $3, now())
			ON CONFLICT (id) DO UPDATE SET ver = x_state.ver + 1, blob = EXCLUDED.blob, updated = now()
			WHERE x_state.ver = $4 RETURNING ver`, id.ID, want+1, blob, want).Scan(&ver)
		if errors.Is(err, pgx.ErrNoRows) {
			var cur int64
			if e := tx.QueryRow(ctx, `SELECT ver FROM x_state WHERE id = $1`, id.ID).Scan(&cur); e != nil {
				return e
			}
			return core.E(409, "conflict", "ver="+strconv.FormatInt(cur, 10))
		}
		if err != nil {
			return err
		}
		if leaf, err = klogAppend(ctx, tx, keys.KindState, id.ID, int(ver), e2e.StateReceipt(id.ID, uint64(ver), blob)); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "xstate", strconv.FormatInt(ver, 10), len(blob))
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("ETag", `"`+strconv.FormatInt(ver, 10)+`"`)
	core.OK(w, r, fmt.Sprintf("ok ver=%d leaf=%d", ver, leaf), map[string]any{"ok": true, "ver": ver, "leaf": leaf})
}

// stateGet is GET /v1/x/state: the raw blob with ETag: <ver> (If-None-Match -> 304).
func (s *svc) stateGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if id.Class == "url" {
		core.Fail(w, r, errURLToken)
		return
	}
	var ver int64
	var blob []byte
	err = s.d.DB.QueryRow(r.Context(), `SELECT ver, blob FROM x_state WHERE id = $1`, id.ID).Scan(&ver, &blob)
	if errors.Is(err, pgx.ErrNoRows) {
		core.Fail(w, r, errNoState)
		return
	}
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	etag := `"` + strconv.FormatInt(ver, 10) + `"`
	w.Header().Set("ETag", etag)
	if strings.TrimSpace(r.Header.Get("If-None-Match")) == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if core.WantJSON(r) {
		core.JSON(w, 200, map[string]any{"ver": ver, "blob": b64(blob)})
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(blob)))
	w.WriteHeader(200)
	w.Write(blob)
}

// stateDel is DELETE /v1/x/state (X-Cx-Sig).
func (s *svc) stateDel(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if _, err := s.d.DB.Exec(r.Context(), `DELETE FROM x_state WHERE id = $1`, id.ID); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, "ok", map[string]any{"ok": true})
}

// --- revocation, rotation cancel, succession (3.7) -----------------------------------------------

// revoke is POST /v1/x/revoke {"id","r"}: no signature (the seed may be in the thief's hands);
// sha256(r) must equal the current bundle's rev_commit. The token dies, the bundle is tombstoned
// (kind 2), outbound sealed mail is frozen, the inbox stays fetchable (after POST /v1/recover) and is
// marked revoked so peers drop their pins.
func (s *svc) revoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := core.UseIPQuota(ctx, s.d.DB, s.d.ClientIP(r), "xrevoke", RevokePerDay); err != nil {
		core.Fail(w, r, err)
		return
	}
	var in struct {
		ID string `json:"id"`
		R  string `json:"r"`
	}
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	code, err := decodeB64(in.R)
	if !core.ValidIDPrefix(in.ID, 'a') || err != nil || len(code) != 32 {
		core.Fail(w, r, core.Bad("id must be an identity id and r its base64url revoke code"))
		return
	}
	b, found, err := keys.Bundle(ctx, s.d.DB, in.ID)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	commit := sha256.Sum256(code)
	if !found || !hmac.Equal(commit[:], b.RevCommit) {
		core.Fail(w, r, errRevokeCode)
		return
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var dead [32]byte
		rand.Read(dead[:])
		if _, err := tx.Exec(ctx, `UPDATE identities SET token_hash = $2, token_hash_prev = NULL, rotated_at = now() WHERE id = $1`, in.ID, dead[:]); err != nil {
			return err
		}
		if _, err := keys.Tombstone(ctx, tx, in.ID); err != nil {
			return err
		}
		if _, err := loadInbox(ctx, tx, in.ID, b.Root); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE x_inbox SET revoked_at = now(), updated = now() WHERE id = $1 AND revoked_at IS NULL`, in.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO x_frozen (id, until, basis) VALUES ($1, 'infinity', 'revoked')
			ON CONFLICT (id) DO UPDATE SET until = 'infinity', basis = 'revoked'`, in.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM x_lease WHERE id = $1`, in.ID); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, in.ID, "xrevoke", "", 0); err != nil {
			return err
		}
		return core.SysMail(ctx, tx, b.Root, "identity "+in.ID+" revoked", "the revoke code of "+in.ID+" was used: its token and keys are revoked and sealed sends in its name are frozen; POST /v1/recover {\"id\",\"recovery\"} issues a new token to read what is left in the inbox")
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, "ok revoked="+in.ID, map[string]any{"ok": true, "revoked": in.ID})
}

// cancelBytes is the statement the previous ik signs to cancel a pending rotation:
// "cx1/rotate" || 0x00 || "cancel" || id || u32(seq). It cannot collide with a bundle statement, whose
// payload starts with the "cxkb2" magic.
func cancelBytes(id string, seq uint32) []byte {
	return e2e.Labeled(e2e.LabelRotate, []byte("cancel"), []byte(id), e2e.U32(seq))
}

// rotate is POST /v1/x/rotate {"id","seq","sig"} | {"id","r"}: cancels the pending ik rotation of
// id when sig verifies under the CURRENT (previous) ik over cancelBytes, or when r is the revoke
// code of the current bundle (kind 2 leaf through keys.CancelPending).
func (s *svc) rotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := core.UseIPQuota(ctx, s.d.DB, s.d.ClientIP(r), "xrotate", RevokePerDay); err != nil {
		core.Fail(w, r, err)
		return
	}
	var in struct {
		ID  string `json:"id"`
		Seq uint32 `json:"seq"`
		Sig string `json:"sig"`
		R   string `json:"r"`
	}
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	if !core.ValidIDPrefix(in.ID, 'a') {
		core.Fail(w, r, core.Bad("id must be an identity id"))
		return
	}
	curB, found, err := keys.Bundle(ctx, s.d.DB, in.ID)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if !found {
		core.Fail(w, r, keys.ErrNoKeys)
		return
	}
	var pendSeq int
	err = s.d.DB.QueryRow(ctx, `SELECT seq FROM key_bundles WHERE id = $1 AND state = 'pending'`, in.ID).Scan(&pendSeq)
	if errors.Is(err, pgx.ErrNoRows) {
		core.Fail(w, r, core.E(404, "notfound", "no pending rotation"))
		return
	}
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	switch {
	case in.R != "":
		code, err := decodeB64(in.R)
		commit := sha256.Sum256(code)
		if err != nil || len(code) != 32 || !hmac.Equal(commit[:], curB.RevCommit) {
			core.Fail(w, r, errRevokeCode)
			return
		}
	default:
		sig, err := decodeB64(in.Sig)
		if err != nil || len(sig) != 64 || uint32(pendSeq) != in.Seq || !e2e.Verify(curB.IK, cancelBytes(in.ID, in.Seq), sig) {
			core.Fail(w, r, core.E(403, "sig", "cancel must be signed by the previous identity key over seq "+strconv.Itoa(pendSeq)))
			return
		}
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := keys.CancelPending(ctx, tx, in.ID); err != nil {
			return err
		}
		return core.SysMail(ctx, tx, curB.Root, "key rotation cancelled "+in.ID, fmt.Sprintf("the pending identity-key rotation n=%d of %s was cancelled by the previous key", pendSeq, in.ID))
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, fmt.Sprintf("ok cancelled seq=%d", pendSeq), map[string]any{"ok": true, "cancelled": pendSeq})
}

// succeed is POST /v1/x/succeed {"old","new","sig_old","sig_new"} over "cx1/succ" || old || new || ik_new:
// both current identity keys must sign (old-key-signed only: a bearer alone cannot announce a
// successor), logged as a kind 4 leaf, immediate; peers re-pin on the double signature.
func (s *svc) succeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in struct {
		Old    string `json:"old"`
		New    string `json:"new"`
		SigOld string `json:"sig_old"`
		SigNew string `json:"sig_new"`
	}
	if err := core.Decode(w, r, 2<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	if !core.ValidIDPrefix(in.Old, 'a') || !core.ValidIDPrefix(in.New, 'a') || in.Old == in.New {
		core.Fail(w, r, core.Bad("old and new must be two identity ids"))
		return
	}
	if id.ID != in.Old && id.ID != in.New {
		core.Fail(w, r, core.E(403, "auth", "the token must belong to old or new"))
		return
	}
	oldB, found, err := keys.Bundle(ctx, s.d.DB, in.Old)
	if err != nil || !found {
		core.Fail(w, r, core.E(404, "notfound", "old has no current keys"))
		return
	}
	newB, found, err := keys.Bundle(ctx, s.d.DB, in.New)
	if err != nil || !found {
		core.Fail(w, r, core.E(404, "notfound", "new has no current keys"))
		return
	}
	stmt := e2e.SuccBytes(in.Old, in.New, newB.IK)
	sigOld, err1 := decodeB64(in.SigOld)
	sigNew, err2 := decodeB64(in.SigNew)
	if err1 != nil || err2 != nil || !e2e.Verify(oldB.IK, stmt, sigOld) || !e2e.Verify(newB.IK, stmt, sigNew) {
		core.Fail(w, r, core.E(403, "sig", "sig_old and sig_new must both verify over cx1/succ || old || new || ik_new"))
		return
	}
	var leaf uint64
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var err error
		if leaf, err = klogAppend(ctx, tx, keys.KindSuccession, in.Old, 0, e2e.Sum(stmt)); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO x_succ (old_id, new_id, ik_new, sig_old, sig_new, leaf) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING`,
			in.Old, in.New, newB.IK, sigOld, sigNew, int64(leaf))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return core.E(409, "dup", "succession already announced")
		}
		if err := core.Event(ctx, tx, "pk", in.Old, "", fmt.Sprintf("succession %s -> %s fp=%s", in.Old, in.New, e2e.FP16(newB.Fingerprint()))); err != nil {
			return err
		}
		if oldB.Root != newB.Root {
			if err := core.SysMail(ctx, tx, oldB.Root, "succession announced "+in.Old+" -> "+in.New, "both identity keys signed a succession; peers re-pin to "+in.New); err != nil {
				return err
			}
		}
		return core.Audit(ctx, tx, id.ID, "xsucc", in.Old+">"+in.New, 0)
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, fmt.Sprintf("ok leaf=%d", leaf), map[string]any{"ok": true, "leaf": leaf})
}

// succList is GET /v1/x/succ/{id}: the successions announced by an identity, with both signatures
// so a peer can verify them before re-pinning.
func (s *svc) succList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !core.ValidIDPrefix(id, 'a') {
		core.Fail(w, r, core.Bad("id must be an identity id"))
		return
	}
	rows, err := s.d.DB.Query(r.Context(), `SELECT new_id, ik_new, sig_old, sig_new, leaf, at FROM x_succ WHERE old_id = $1 ORDER BY at`, id)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	defer rows.Close()
	var b strings.Builder
	var js []map[string]any
	for rows.Next() {
		var newID string
		var ik, so, sn []byte
		var leaf int64
		var at time.Time
		if err := rows.Scan(&newID, &ik, &so, &sn, &leaf, &at); err != nil {
			core.Fail(w, r, err)
			return
		}
		fmt.Fprintf(&b, "old=%s new=%s ik_new=%s sig_old=%s sig_new=%s leaf=%d at=%d\n", id, newID, b64(ik), b64(so), b64(sn), leaf, at.Unix())
		js = append(js, map[string]any{"old": id, "new": newID, "ik_new": b64(ik), "sig_old": b64(so), "sig_new": b64(sn), "leaf": leaf, "at": at.Unix()})
	}
	if err := rows.Err(); err != nil {
		core.Fail(w, r, err)
		return
	}
	if len(js) == 0 {
		core.Fail(w, r, core.E(404, "notfound", "no succession announced"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	core.OK(w, r, b.String(), map[string]any{"id": id, "succ": js})
}

// --- epoch shares (4.9, mode D+) -------------------------------------------------------------------

// share is GET /v1/keys/share?e=<e> (X-Cx-Sig): mints share_e for epochs e..e+4 of the caller's root
// on demand (32 random bytes each) and returns them sealed under the caller's lk (HPKE, info
// "cx1/share" || id || u32(e)). The server stores the shares, never the derived key.
func (s *svc) share(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	now := time.Now().Unix()
	e0 := e2e.Epoch(now)
	if v := r.URL.Query().Get("e"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || uint32(n) < e0-1 || uint32(n) > e0+e2e.EpochsAhead {
			core.Fail(w, r, core.Bad(fmt.Sprintf("e must be an epoch between %d and %d", e0-1, e0+e2e.EpochsAhead)))
			return
		}
		e0 = uint32(n)
	}
	b, found, err := keys.Bundle(ctx, s.d.DB, id.ID)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if !found {
		core.Fail(w, r, keys.ErrNoKeys)
		return
	}
	cs := e2e.CS1
	pk, err := cs.NewPublicKey(b.LK1)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if err := core.UseQuota(ctx, s.d.DB, id, "xshare", SharePerDay); err != nil {
		core.Fail(w, r, err)
		return
	}
	var text strings.Builder
	var js []map[string]any
	for i := 0; i < e2e.EpochsAhead; i++ {
		e := e0 + uint32(i)
		var share []byte
		fresh := make([]byte, 32)
		rand.Read(fresh)
		// Shares live until the epoch is over plus the mail TTL and the linger; sends extend them.
		if err := s.d.DB.QueryRow(ctx, `INSERT INTO epoch_shares (root, e, b, exp) VALUES ($1, $2, $3, to_timestamp($4) + $5::interval)
			ON CONFLICT (root, e) DO UPDATE SET exp = greatest(epoch_shares.exp, EXCLUDED.exp) RETURNING b`,
			id.Root, int64(e), fresh, e2e.EpochStart(e+1), (TTL + ShareLinger).String()).Scan(&share); err != nil {
			core.Fail(w, r, err)
			return
		}
		enc, sender, err := hpke.NewSender(pk, e2e.KDF(), e2e.AEAD(), e2e.Labeled(e2e.LabelShare, []byte(id.ID), e2e.U32(e)))
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		ct, err := sender.Seal(nil, share)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		sealed := append(enc, ct...)
		fmt.Fprintf(&text, "e=%d share=%s\n", e, b64(sealed))
		js = append(js, map[string]any{"e": e, "share": b64(sealed)})
	}
	w.Header().Set("Cache-Control", "no-store")
	core.OK(w, r, text.String(), map[string]any{"id": id.ID, "cs": int(cs), "shares": js})
}

// OpenShare is the client side of GET /v1/keys/share (cx, tests): lk is LK(seed, CS1).
func OpenShare(lk hpke.PrivateKey, id string, e uint32, sealed []byte) ([]byte, error) {
	n := e2e.CS1.EncSize()
	if len(sealed) != n+32+16 {
		return nil, errors.New("xmail: sealed share length")
	}
	rcpt, err := hpke.NewRecipient(sealed[:n], lk, e2e.KDF(), e2e.AEAD(), e2e.Labeled(e2e.LabelShare, []byte(id), e2e.U32(e)))
	if err != nil {
		return nil, err
	}
	return rcpt.Open(nil, sealed[n:])
}
