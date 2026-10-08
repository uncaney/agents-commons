package keys

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/notary"
)

// Record is a published bundle with the server-side facts the directory serves.
type Record struct {
	*e2e.Bundle
	Raw          []byte // canonical || sigs as published (clients verify these bytes)
	Hash         []byte // sha256(canonical): the leaf's item_hash, the next bundle's prev_hash
	Root         string
	State        string // current | pending | superseded | void | revoked
	Leaf         int64  // kind 1 leaf, -1 while pending
	PendingLeaf  int64  // kind 3 leaf, -1 when the bundle was never pending
	Published    time.Time
	PendingUntil time.Time
}

// LeafIdx is the leaf the directory names for this bundle (the kind 1 leaf, else the pending one).
func (b *Record) LeafIdx() int64 {
	if b.Leaf >= 0 {
		return b.Leaf
	}
	return b.PendingLeaf
}

// PubResult is what a publication reports: `seq=<n> leaf=<idx> bundle=<sha256 hex> head=<hex16>`.
// Contested is the committed outcome of a legacy contest (the caller answers `err keys contested`).
type PubResult struct {
	Seq       uint32
	Leaf      uint64
	RawHash   []byte // sha256 over the bytes as sent (the client compares it with what it sent)
	Pending   bool
	Until     time.Time
	Contested bool
}

type identInfo struct {
	ID, Root string
	Sub      bool
}

const bundleCols = `id, seq, root, bundle, hash, state, coalesce(leaf, -1), coalesce(pending_leaf, -1), published, coalesce(pending_until, 'epoch'::timestamptz)`

func scanBundle(row pgx.Row) (*Record, error) {
	b := &Record{}
	var id string
	var seq int
	var until time.Time
	if err := row.Scan(&id, &seq, &b.Root, &b.Raw, &b.Hash, &b.State, &b.Leaf, &b.PendingLeaf, &b.Published, &until); err != nil {
		return nil, err
	}
	pb, err := e2e.ParseBundle(b.Raw)
	if err != nil {
		return nil, fmt.Errorf("keys: stored bundle %s/%d: %w", id, seq, err)
	}
	b.Bundle = pb
	if until.Unix() > 0 {
		b.PendingUntil = until
	}
	return b, nil
}

func loadState(ctx context.Context, q core.Q, id, state string) (*Record, error) {
	return scanBundle(q.QueryRow(ctx, `SELECT `+bundleCols+` FROM key_bundles WHERE id = $1 AND state = $2`, id, state))
}

// Bundle returns the current bundle of an id (pending bundles never count); found is false when
// the identity published nothing usable.
func Bundle(ctx context.Context, q core.Q, id string) (*Record, bool, error) {
	b, err := loadState(ctx, q, id, "current")
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// Lookup resolves what GET /v1/keys/{id} serves: the current bundle, else a pending one (marked),
// else ErrRevoked, ErrContested or ErrNoKeys.
func Lookup(ctx context.Context, q core.Q, id string) (*Record, error) {
	for _, st := range []string{"current", "pending"} {
		b, err := loadState(ctx, q, id, st)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	var state string
	var at *time.Time
	err := q.QueryRow(ctx, `SELECT state, revoked_at FROM key_bundles WHERE id = $1 AND state IN ('revoked', 'void') ORDER BY state DESC LIMIT 1`, id).Scan(&state, &at)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, ErrNoKeys
	case err != nil:
		return nil, err
	case state == "void":
		return nil, ErrContested
	}
	if at != nil {
		return nil, core.E(410, "revoked", "at="+core.Date(*at))
	}
	return nil, ErrRevoked
}

// AtLeaf returns the id's bundle logged at a leaf (kind 1 or pending leaf).
func AtLeaf(ctx context.Context, q core.Q, id string, leaf uint64) (*Record, error) {
	b, err := scanBundle(q.QueryRow(ctx, `SELECT `+bundleCols+` FROM key_bundles WHERE id = $1 AND (leaf = $2 OR pending_leaf = $2)`, id, int64(leaf)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.E(404, "notfound", "no bundle of "+id+" at this leaf")
	}
	return b, err
}

func identOf(ctx context.Context, q core.Q, id string) (identInfo, error) {
	var in identInfo
	var revoked bool
	err := q.QueryRow(ctx, `SELECT id, root, parent IS NOT NULL, revoked_at IS NOT NULL FROM identities WHERE id = $1`, id).Scan(&in.ID, &in.Root, &in.Sub, &revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return in, core.ErrNotFound
	}
	if err == nil && revoked {
		return in, ErrRevoked
	}
	return in, err
}

func identInfoOf(id *core.Ident) identInfo {
	return identInfo{ID: id.ID, Root: id.Root, Sub: id.Parent != ""}
}

const b32 = "abcdefghijklmnopqrstuvwxyz234567"

// ChallengeID derives the id a registration challenge will mint (E2EE 3.2): "a" + base32 of the
// first 30 bits of HMAC(SERVER_SECRET, "cx1/regid" || 0x00 || challenge). Stateless: the server
// recomputes it from the challenge the client presents. Empty until Register ran.
func ChallengeID(_ context.Context, c string) string {
	s := cur.Load()
	if s == nil || c == "" || len(c) > 128 {
		return ""
	}
	return challengeID(s.d.Cfg.ServerSecret, c)
}

func challengeID(secret []byte, c string) string {
	m := hmac.New(sha256.New, secret)
	m.Write(e2e.Labeled(e2e.LabelRegID, []byte(c)))
	sum := m.Sum(nil)
	v := (uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])) >> 2
	out := []byte("a000000")
	for i := 6; i >= 1; i-- {
		out[i] = b32[v&31]
		v >>= 5
	}
	return string(out)
}

// RegisterBundle implements core.RegisterBundleFn: inside the registration transaction, the seq-1
// bundle (a base64 JSON string of canonical || sigs) is verified against the minted id and
// published as the identity's current bundle, kind 1 leaf included (finding 1: no seq-1 PUT).
func RegisterBundle(ctx context.Context, q core.Q, id string, bundle json.RawMessage) error {
	var enc string
	if err := json.Unmarshal(bundle, &enc); err != nil {
		return core.Bad("bundle must be a base64 string of canonical || sigs")
	}
	if enc == "" { // null or "": no bundle (a plaintext-only registration)
		return nil
	}
	if len(enc) > 4*e2e.BundleCap/3+4 {
		return core.ErrSize
	}
	raw, err := decodeB64(enc)
	if err != nil {
		return core.Bad("bundle is not base64")
	}
	b, err := parseBundle(raw, id, time.Now().Unix())
	if err != nil {
		return err
	}
	if b.Seq != 1 {
		return core.Bad("registration bundle must be seq 1")
	}
	in, err := identOf(ctx, q, id)
	if err != nil {
		return err
	}
	if (b.Flags&e2e.FlagSub != 0) != in.Sub {
		return core.Bad("flags.sub must match the identity kind")
	}
	_, err = publish(ctx, q, in, b, raw, nil, time.Time{})
	return err
}

// parseBundle is the server-side shape check of a bundle addressed to id (3.1, 3.2).
func parseBundle(raw []byte, id string, now int64) (*e2e.Bundle, error) {
	if len(raw) > e2e.BundleCap {
		return nil, core.ErrSize
	}
	b, err := e2e.ParseBundle(raw)
	if err != nil {
		return nil, core.Bad("bundle: " + err.Error())
	}
	switch {
	case b.ID != id:
		return nil, core.Bad("bundle id " + b.ID + " is not " + id)
	case int64(b.IAT) > now+e2e.IATSkew:
		return nil, core.Bad("bundle iat in the future")
	case int64(b.Exp) <= now:
		return nil, core.Bad("bundle expired")
	}
	if err := b.Verify(); err != nil {
		return nil, core.E(400, "sig", "bundle signature invalid")
	}
	return b, nil
}

func policyName(p uint8) string {
	switch p {
	case e2e.PolicyBoth:
		return "both"
	case e2e.PolicyE2EE:
		return "e2ee"
	}
	return "plain"
}

// publish stores a verified bundle (current, or pending until `until`), appends its leaf (kind 1,
// or 3 while pending), stamps the binding into the notary (26.6), writes the public events row and,
// on a key change (ik or rk differs from prev), sets identities.keys_changed_at on the root and mails
// the owner `key changed n=<seq>`. prev is the current bundle being replaced (nil for seq 1).
func publish(ctx context.Context, q core.Q, in identInfo, b *e2e.Bundle, raw []byte, prev *Record, until time.Time) (*PubResult, error) {
	if err := lockLog(ctx, q); err != nil {
		return nil, err
	}
	hash, err := b.CanonicalHash()
	if err != nil {
		return nil, core.Bad("bundle: " + err.Error())
	}
	pending := !until.IsZero()
	kind, state := uint8(KindBundle), "current"
	var untilP *time.Time
	if pending {
		kind, state, untilP = KindPending, "pending", &until
	} else if prev != nil {
		if _, err := q.Exec(ctx, `UPDATE key_bundles SET state = 'superseded' WHERE id = $1 AND state = 'current'`, in.ID); err != nil {
			return nil, err
		}
	}
	if _, err := q.Exec(ctx, `INSERT INTO key_bundles (id, seq, root, bundle, hash, ik, rk, policy, iat, exp, state, pending_until)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, to_timestamp($9), to_timestamp($10), $11, $12)`,
		in.ID, int(b.Seq), in.Root, raw, hash, b.IK, b.RK, policyName(b.MailPolicy), int64(b.IAT), int64(b.Exp), state, untilP); err != nil {
		if core.IsUniqueViolation(err) {
			return nil, core.E(409, "dup", "bundle seq already published")
		}
		return nil, err
	}
	idx, _, err := appendLeaf(ctx, q, kind, in.ID, int(b.Seq), hash)
	if err != nil {
		return nil, err
	}
	col := "leaf"
	if pending {
		col = "pending_leaf"
	}
	if _, err := q.Exec(ctx, `UPDATE key_bundles SET `+col+` = $3 WHERE id = $1 AND seq = $2`, in.ID, int(b.Seq), int64(idx)); err != nil {
		return nil, err
	}
	if _, _, err := notary.Stamp(ctx, q, stampHash(in.ID, hash), "pk", in.Root); err != nil {
		return nil, err
	}
	fp := e2e.FP16(b.Fingerprint())
	title := fmt.Sprintf("key published %s n=%d fp=%s", in.ID, b.Seq, fp)
	if pending {
		title += " pending"
	}
	if err := core.Event(ctx, q, "pk", in.ID, "", title); err != nil {
		return nil, err
	}
	if prev != nil && (!equal(prev.IK, b.IK) || !equal(prev.RK, b.RK)) {
		if _, err := q.Exec(ctx, `UPDATE identities SET keys_changed_at = now() WHERE id = $1`, in.Root); err != nil {
			return nil, err
		}
		text := fmt.Sprintf("identity %s published key bundle n=%d (fp %s)", in.ID, b.Seq, fp)
		if pending {
			text += fmt.Sprintf("; the new identity key becomes current at %s unless the previous key cancels it", until.UTC().Format(time.RFC3339))
		}
		text += "; tree pulls (?all=1) are refused for 24 h; if you did not do this, revoke now"
		if err := core.SysMail(ctx, q, in.Root, fmt.Sprintf("key changed n=%d", b.Seq), text); err != nil {
			return nil, err
		}
	}
	return &PubResult{Seq: b.Seq, Leaf: idx, RawHash: e2e.BundleHash(raw), Pending: pending, Until: until}, nil
}

// stampHash is the notary leaf of a publication: sha256("pk" || 0x00 || id || 0x00 || bundle_hash) (26.6).
func stampHash(id string, bundleHash []byte) []byte {
	return e2e.Sum([]byte("pk\x00"), []byte(id), []byte{0}, bundleHash)
}

// publishNext is PUT /v1/keys for an identity that holds a current bundle (seq >= 2, 3.2, 3.7): the
// request was signed with the current rk; seq, prev_hash and the sub flag must chain; a changed ik
// needs sig_prev under the current ik and becomes a 24 h pending rotation; key changes (ik or rk)
// are limited to one per 24 h per root.
func publishNext(ctx context.Context, q core.Q, id *core.Ident, b *e2e.Bundle, raw []byte, prev *Record) (*PubResult, error) {
	in := identInfoOf(id)
	switch {
	case b.Seq != prev.Seq+1:
		return nil, core.Bad(fmt.Sprintf("seq want=%d", prev.Seq+1))
	case !equal(b.PrevHash, prev.Hash):
		return nil, core.Bad("prev_hash does not match the current bundle (" + hex.EncodeToString(prev.Hash) + ")")
	case (b.Flags&e2e.FlagSub != 0) != in.Sub:
		return nil, core.Bad("flags.sub must match the identity kind")
	}
	if p, err := loadState(ctx, q, id.ID, "pending"); err == nil {
		return nil, core.E(409, "keys", "rotation pending until="+p.PendingUntil.UTC().Format(time.RFC3339))
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var until time.Time
	if equal(b.IK, prev.IK) {
		if b.Rotated() {
			return nil, core.Bad("sig_prev set but ik unchanged")
		}
	} else {
		if err := b.VerifyRotation(prev.IK); err != nil {
			return nil, core.E(400, "sig", "sig_prev does not verify under the current ik")
		}
		until = time.Now().Add(PendingWindow).Truncate(time.Second)
	}
	if !equal(b.IK, prev.IK) || !equal(b.RK, prev.RK) {
		var changed *time.Time
		if err := q.QueryRow(ctx, `SELECT keys_changed_at FROM identities WHERE id = $1`, id.Root).Scan(&changed); err != nil {
			return nil, err
		}
		if changed != nil && time.Since(*changed) < KeyChangeEvery {
			return nil, core.E(429, "quota", "key change: 1 per 24 h")
		}
	}
	return publish(ctx, q, in, b, raw, prev, until)
}

// legacyPublish is the contested-publish path of D14(b): an identity without any bundle may PUT a
// seq-1 bundle over its bearer; it stays pending 24 h (kind 3), a second seq-1 attempt with another
// ik inside the window voids both (`err keys contested`, kind 2 tombstone; reported through
// PubResult.Contested so the void commits) and the identity can only adopt E2EE by registering
// anew. A repeat of the same bundle is idempotent.
func legacyPublish(ctx context.Context, q core.Q, id *core.Ident, b *e2e.Bundle, raw []byte) (*PubResult, error) {
	if b.Seq != 1 {
		return nil, core.Bad("seq want=1")
	}
	in := identInfoOf(id)
	if (b.Flags&e2e.FlagSub != 0) != in.Sub {
		return nil, core.Bad("flags.sub must match the identity kind")
	}
	if err := lockLog(ctx, q); err != nil {
		return nil, err
	}
	var dead string
	err := q.QueryRow(ctx, `SELECT state FROM key_bundles WHERE id = $1 AND state IN ('void', 'revoked') ORDER BY state LIMIT 1`, id.ID).Scan(&dead)
	switch {
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	case dead == "revoked":
		return nil, ErrRevoked
	case dead == "void":
		return nil, ErrContested
	}
	pend, err := loadState(ctx, q, id.ID, "pending")
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if pend != nil {
		if equal(pend.IK, b.IK) {
			return &PubResult{Seq: 1, Leaf: uint64(pend.PendingLeaf), RawHash: e2e.BundleHash(pend.Raw), Pending: true, Until: pend.PendingUntil}, nil
		}
		if _, err := q.Exec(ctx, `UPDATE key_bundles SET state = 'void', pending_until = NULL WHERE id = $1 AND state = 'pending'`, id.ID); err != nil {
			return nil, err
		}
		if _, _, err := appendLeaf(ctx, q, KindTombstone, id.ID, 1, pend.Hash); err != nil {
			return nil, err
		}
		if err := core.Event(ctx, q, "pk", id.ID, "", "key publish contested "+id.ID+": two seq-1 bundles, both void"); err != nil {
			return nil, err
		}
		return &PubResult{Contested: true}, nil
	}
	return publish(ctx, q, in, b, raw, nil, time.Now().Add(PendingWindow).Truncate(time.Second))
}

// promote makes a pending bundle current once its window passed: the previous current is
// superseded and a kind 1 leaf names the now-current bundle.
func promote(ctx context.Context, q core.Q, id string, seq int) error {
	if err := lockLog(ctx, q); err != nil {
		return err
	}
	b, err := scanBundle(q.QueryRow(ctx, `SELECT `+bundleCols+` FROM key_bundles WHERE id = $1 AND seq = $2 AND state = 'pending' AND pending_until <= now()`, id, seq))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE key_bundles SET state = 'superseded' WHERE id = $1 AND state = 'current'`, id); err != nil {
		return err
	}
	idx, _, err := appendLeaf(ctx, q, KindBundle, id, seq, b.Hash)
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE key_bundles SET state = 'current', leaf = $3, pending_until = NULL WHERE id = $1 AND seq = $2`, id, seq, int64(idx)); err != nil {
		return err
	}
	return core.Event(ctx, q, "pk", id, "", fmt.Sprintf("key current %s n=%d fp=%s", id, seq, e2e.FP16(b.Fingerprint())))
}

// promotePending is the janitor task: every pending bundle past its window becomes current.
func (s *svc) promotePending(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT id, seq FROM key_bundles WHERE state = 'pending' AND pending_until <= now() ORDER BY pending_until LIMIT 100`)
	if err != nil {
		return err
	}
	type key struct {
		id  string
		seq int
	}
	var due []key
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.id, &k.seq); err != nil {
			rows.Close()
			return err
		}
		due = append(due, k)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, k := range due {
		if err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error { return promote(ctx, tx, k.id, k.seq) }); err != nil {
			return err
		}
	}
	return nil
}

// CancelPending voids an identity's pending rotation (3.7, called by the cancel route of the sealed
// mailbox package after it verified the previous ik or the revoke code); kind 2 leaf.
func CancelPending(ctx context.Context, q core.Q, id string) error {
	if err := lockLog(ctx, q); err != nil {
		return err
	}
	p, err := loadState(ctx, q, id, "pending")
	if errors.Is(err, pgx.ErrNoRows) {
		return core.E(404, "notfound", "no pending bundle")
	}
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE key_bundles SET state = 'void', pending_until = NULL WHERE id = $1 AND state = 'pending'`, id); err != nil {
		return err
	}
	if _, _, err := appendLeaf(ctx, q, KindTombstone, id, int(p.Seq), p.Hash); err != nil {
		return err
	}
	return core.Event(ctx, q, "pk", id, "", fmt.Sprintf("key rotation cancelled %s n=%d", id, p.Seq))
}

// Tombstone revokes every live bundle of an id (purge, revoke, sub-key deletion) with a kind 2 leaf
// over the latest bundle's hash; GET /v1/keys/{id} then answers `err revoked at=<date>`.
func Tombstone(ctx context.Context, q core.Q, id string) (uint64, error) {
	if err := lockLog(ctx, q); err != nil {
		return 0, err
	}
	var seq int
	var hash []byte
	err := q.QueryRow(ctx, `SELECT seq, hash FROM key_bundles WHERE id = $1 AND state IN ('current', 'pending') ORDER BY (state = 'current') DESC, seq DESC LIMIT 1`, id).Scan(&seq, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNoKeys
	}
	if err != nil {
		return 0, err
	}
	if _, err := q.Exec(ctx, `UPDATE key_bundles SET state = 'revoked', revoked_at = now(), pending_until = NULL WHERE id = $1 AND state IN ('current', 'pending')`, id); err != nil {
		return 0, err
	}
	if _, err := q.Exec(ctx, `DELETE FROM req_nonces WHERE id = $1`, id); err != nil {
		return 0, err
	}
	idx, _, err := appendLeaf(ctx, q, KindTombstone, id, seq, hash)
	if err != nil {
		return 0, err
	}
	return idx, core.Event(ctx, q, "pk", id, "", fmt.Sprintf("key revoked %s n=%d", id, seq))
}

// PlainAllowed implements mail.PolicyFn: a recipient whose current bundle says e2ee refuses
// plaintext mail (`err policy e2ee`); no bundle or policy plain/both allows it. Pending never counts.
func PlainAllowed(ctx context.Context, q core.Q, root string) (bool, error) {
	var policy string
	err := q.QueryRow(ctx, `SELECT policy FROM key_bundles WHERE id = $1 AND state = 'current'`, root).Scan(&policy)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return policy != "e2ee", nil
}

// TreePullAllowed reports whether the root may pull every box of its tree (?all=1): refused for
// 24 h after a key change (26.6).
func TreePullAllowed(ctx context.Context, q core.Q, root string) (bool, error) {
	var changed *time.Time
	err := q.QueryRow(ctx, `SELECT keys_changed_at FROM identities WHERE id = $1`, root).Scan(&changed)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return changed == nil || time.Since(*changed) >= KeyChangeEvery, nil
}
