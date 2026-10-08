package xmail

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/sign"
)

// svc is the package service: deps, the statement signer (receipts) and the pseudonymous network keys.
type svc struct {
	d      *core.Deps
	signer *sign.Signer
	ipk    ipKeys
}

// cur is the service installed by Register (nil = not ready; the ops answer err xmail).
var cur atomic.Pointer[svc]

// Routes lists every pattern Register mounted: all of them run LogMinimal (E2EE 8.2 route test).
var Routes []string

// Register mounts the sealed mailbox (every write behind keys.RequireSig, every read behind
// keys.LogMinimal), its scopes, costs, OpenAPI fragment, llms-full section, the report target x:,
// the storage class, the janitor, the purge hook, the resume and me lines. keys.Register must run
// in the same process: request signatures and the online key live there.
func Register(mux *http.ServeMux, d *core.Deps) {
	signer, err := sign.New(d.Cfg)
	if err != nil {
		panic(err)
	}
	s := &svc{d: d, signer: signer}
	loadEnv()
	cur.Store(s)
	Routes = Routes[:0]
	mount := func(pat string, h http.Handler) {
		Routes = append(Routes, pat)
		mux.Handle(pat, h)
	}
	read := func(fn http.HandlerFunc) http.Handler { return keys.LogMinimal(fn) }
	write := func(max int64, fn http.HandlerFunc) http.Handler { return keys.RequireSigMax(max, fn) }
	mount("POST /v1/x/revoke", read(s.revoke))
	mount("POST /v1/x/rotate", read(s.rotate))
	mount("POST /v1/x/succeed", read(s.succeed))
	mount("GET /v1/x/succ/{id}", read(s.succList))
	mount("POST /v1/x/lease", write(1<<10, s.lease))
	mount("PUT /v1/x/policy", write(4<<10, s.policyPut))
	mount("GET /v1/x/policy", read(s.policyGet))
	mount("PUT /v1/x/block", write(1<<10, s.block))
	mount("DELETE /v1/x/block", write(1<<10, s.block))
	mount("PUT /v1/x/state", write(e2e.StateCap, s.statePut))
	mount("GET /v1/x/state", read(s.stateGet))
	mount("DELETE /v1/x/state", write(1<<10, s.stateDel))
	mount("GET /v1/x/in", read(s.pull))
	mount("GET /v1/x/{id}", read(s.get))
	mount("DELETE /v1/x/{id}", write(1<<10, s.ack))
	mount("POST /v1/x/{to}", write(e2e.MailCap, s.send))
	mount("GET /v1/keys/share", write(1<<10, s.share))
	for pat, scope := range map[string]string{
		"POST /v1/x/{to}": "mb:w", "GET /v1/x/in": "*", "GET /v1/x/{id}": "mb:r", "DELETE /v1/x/{id}": "mb:w",
		"PUT /v1/x/policy": "mb:w", "GET /v1/x/policy": "mb:r", "PUT /v1/x/block": "mb:w", "DELETE /v1/x/block": "mb:w",
		"PUT /v1/x/state": "mb:w", "GET /v1/x/state": "mb:r", "DELETE /v1/x/state": "mb:w", "POST /v1/x/lease": "mb:w",
		"GET /v1/keys/share": "mb:r",
	} {
		d.RegisterScope(pat, scope)
	}
	for _, p := range []string{"GET /v1/x/in", "GET /v1/x/{id}", "DELETE /v1/x/{id}", "GET /v1/x/state", "GET /v1/x/policy"} {
		d.RegisterCost(p, 0.2)
	}
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("xmail", func(context.Context) string { return llmsText })
	d.RegisterTarget("x", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.StorageClass("xmail", MaxBytes, `SELECT pg_total_relation_size('x_env') + pg_total_relation_size('x_ledger') + pg_total_relation_size('x_state')`)
	d.Janitor.Add("xmail", func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error { return purge(ctx, d.DB, root) })
	d.OnResume(func(ctx context.Context, root string) []string { return resumeLines(ctx, d.DB, root) })
	d.MeExtra(func(ctx context.Context, id *core.Ident) []string { return meLines(ctx, d.DB, id) })
}

// loadEnv reads E2E_MAX_BYTES and E2E_STAMP_BITS (9.3); bad values keep the defaults.
func loadEnv() {
	if v := strings.TrimSpace(os.Getenv("E2E_MAX_BYTES")); v != "" {
		if n, err := core.ParseBytes(v); err == nil && n > 0 {
			MaxBytes = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("E2E_STAMP_BITS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 8 && n <= 40 {
			StampBits = n
		}
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// ipKeys derives the pseudonymous per-network counter key of E2EE 8.4: HMAC(k_day, group)[:16],
// k_day random in memory and rotated at UTC midnight, never persisted.
type ipKeys struct {
	mu  sync.Mutex
	day string
	key []byte
}

func (k *ipKeys) of(group string) string {
	day := time.Now().UTC().Format("2006-01-02")
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.day != day {
		k.key = make([]byte, 32)
		rand.Read(k.key)
		k.day = day
	}
	m := hmac.New(sha256.New, k.key)
	m.Write([]byte(group))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// bump adds delta to today's counter and returns the new value (core.counters, metadata only).
func bump(ctx context.Context, q core.Q, scope, kind string, delta int) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, scope, kind, delta).Scan(&n)
	return n, err
}

// randSeq is the random 40-bit sequence offset of a fresh inbox (4.5) and a phantom's sequence.
func randSeq() int64 {
	var b [8]byte
	rand.Read(b[:])
	return int64(binary.BigEndian.Uint64(b[:])>>24) + 1
}

// scrubMode reads the X-Scrub-V pin (26.5): absent = none; older than rules_v - 1 is refused.
func scrubMode(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "none", nil
	}
	v, err := strconv.Atoi(h)
	if err != nil || v < 0 || v > 1<<20 {
		return "", core.Bad("X-Scrub-V must be the rules_v integer of GET /scrub/rules")
	}
	if v < scrub.RulesV-1 {
		return "", core.E(400, "scrub", fmt.Sprintf("stale-rules: have=%d rules_v=%d (GET /scrub/rules, then re-seal)", v, scrub.RulesV))
	}
	return "client", nil
}

// --- send ---------------------------------------------------------------------------------------

// sendIn is one relay request (HTTP or the xraw op).
type sendIn struct {
	to, stamp, scrubV string
	env               []byte
	sig               *e2e.ReqSig
	group             string // caller network key for the pseudonymous daily counter ("" = none)
}

// sendRes is an accepted (or phantom) relay: the receipt material of E2EE 4.4 and 26.3.
type sendRes struct {
	Seq   int64
	At    time.Time
	Rcpt  []byte
	KID   int
	Frank string // signed `frank1 ...` line
	Sig   string // sig=<b64url> over Frank
}

func (r *sendRes) Text() string {
	return fmt.Sprintf("ok seq=%d at=%d rcpt=%s k=%d\n%s\n%s\n", r.Seq, r.At.Unix(), b64(r.Rcpt), r.KID, r.Frank, r.Sig)
}

func (r *sendRes) JSON() map[string]any {
	return map[string]any{"ok": true, "seq": r.Seq, "at": r.At.Unix(), "rcpt": b64(r.Rcpt), "kid": r.KID, "frank": r.Frank, "sig": r.Sig}
}

// inboxRow is the recipient's x_inbox row read under the inbox lock.
type inboxRow struct {
	id, root, mode, poll string
	bits                 int
	maxRows, rows        int
	maxBytes, bytes      int64
	revoked              bool
}

// receipt signs the relay receipt of 4.4 (Ed25519 over "cx1/rcpt" || hdr || u64(seq) || u64(at)) and the
// frank1 statement line (26.3) with the server statement key; both verify at GET /verify.
func (s *svc) receipt(env *e2e.Envelope, seq int64, at time.Time) *sendRes {
	hdr := env.HdrBytes()
	res := &sendRes{Seq: seq, At: at, KID: s.signer.KID()}
	res.Rcpt = s.signer.SignBytes(e2e.RcptBytes(hdr, uint64(seq), uint64(at.Unix())))
	res.Frank = sign.Canonical(TypeFrank, sign.KV{K: "m", V: b64(env.Mid)}, sign.KV{K: "c", V: hex.EncodeToString(env.C)},
		sign.KV{K: "f", V: env.From}, sign.KV{K: "b", V: env.To}, sign.KV{K: "n", V: strconv.FormatInt(seq, 10)},
		sign.KV{K: "t", V: strconv.FormatInt(at.Unix(), 10)}, sign.KV{K: "k", V: strconv.Itoa(s.signer.KID())})
	res.Sig = s.signer.Sign(TypeFrank, res.Frank)
	return res
}

func (s *svc) send(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		core.Fail(w, r, core.Bad("read"))
		return
	}
	sig, _ := keys.SigFrom(r.Context())
	in := &sendIn{to: r.PathValue("to"), stamp: r.Header.Get("X-Stamp"), scrubV: r.Header.Get("X-Scrub-V"), env: body, sig: sig, group: s.d.IPGroup(r)}
	res, err := s.relay(r.Context(), id, in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 201, res.Text(), res.JSON())
}

// relay is the send shared by HTTP and the xraw op: shape checks, the sender gates of 8.1 and 11, the
// insert transaction with its receipt. A blocked sender gets a phantom receipt and nothing is stored.
func (s *svc) relay(ctx context.Context, from *core.Ident, in *sendIn) (*sendRes, error) {
	if in.sig == nil {
		return nil, core.E(401, "sig", "X-Cx-Sig required")
	}
	if s.d.Frozen("mail") {
		return nil, core.Frozen("mail")
	}
	if s.d.Frozen("xmail") {
		return nil, core.Frozen("xmail")
	}
	if !core.ValidIDPrefix(in.to, 'a') {
		return nil, core.Bad("to must be an identity id")
	}
	env, err := e2e.ParseEnvelope(in.env)
	switch {
	case errors.Is(err, e2e.ErrSizeBkt):
		return nil, errSizeBucket
	case err != nil:
		return nil, core.Bad("envelope: " + err.Error())
	case env.From != from.ID:
		return nil, errFrankFrom
	case env.To != in.to:
		return nil, errFrankTo
	}
	scrubM, err := scrubMode(in.scrubV)
	if err != nil {
		return nil, err
	}
	var toRoot string
	var toRevoked *time.Time
	err = s.d.DB.QueryRow(ctx, `SELECT root, revoked_at FROM identities WHERE id = $1`, in.to).Scan(&toRoot, &toRevoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoInbox
	}
	if err != nil {
		return nil, err
	}
	if toRevoked != nil {
		return nil, errRecipient
	}
	if _, found, err := keys.Bundle(ctx, s.d.DB, in.to); err != nil {
		return nil, err
	} else if !found {
		return nil, errNoInbox
	}
	if err := s.senderLive(ctx, from); err != nil {
		return nil, err
	}
	self := toRoot == from.Root
	var res *sendRes
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "x:"+in.to); err != nil {
			return err
		}
		box, err := loadInbox(ctx, tx, in.to, toRoot)
		if err != nil {
			return err
		}
		if box.revoked {
			return errRecipient
		}
		if !self {
			phantom, err := s.gates(ctx, tx, from, box, env, in)
			if err != nil {
				return err
			}
			if phantom {
				res = s.receipt(env, randSeq(), time.Now().Truncate(time.Second))
				return nil
			}
		}
		// The resource controls of 9.3 bind every accepted send, self-addressed included.
		if err := s.limits(ctx, tx, from, box, in); err != nil {
			return err
		}
		res, err = s.insert(ctx, tx, from, box, env, in, scrubM, self)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.d.Notify.Wake("x:" + in.to)
	return res, nil
}

// senderLive refuses revoked and frozen senders (3.7, 8.1).
func (s *svc) senderLive(ctx context.Context, from *core.Ident) error {
	var revoked bool
	if err := s.d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM x_inbox WHERE id = $1 AND revoked_at IS NOT NULL)`, from.ID).Scan(&revoked); err != nil {
		return err
	}
	if revoked {
		return errRevoked
	}
	var until *time.Time
	err := s.d.DB.QueryRow(ctx, `SELECT max(until) FROM x_frozen WHERE id IN ($1, $2) AND until > now()`, from.ID, from.Root).Scan(&until)
	if err != nil {
		return err
	}
	if until != nil {
		return core.E(403, "auth", "mail-frozen until="+until.UTC().Format(time.RFC3339))
	}
	return nil
}

// loadInbox creates the recipient's inbox row on first contact (random sequence offset) and reads it.
func loadInbox(ctx context.Context, q core.Q, id, root string) (*inboxRow, error) {
	if _, err := q.Exec(ctx, `INSERT INTO x_inbox (id, root, next_seq) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`, id, root, randSeq()); err != nil {
		return nil, err
	}
	b := &inboxRow{}
	err := q.QueryRow(ctx, `SELECT id, root, mode, bits, poll, max_rows, rows, max_bytes, bytes, revoked_at IS NOT NULL FROM x_inbox WHERE id = $1`, id).
		Scan(&b.id, &b.root, &b.mode, &b.bits, &b.poll, &b.maxRows, &b.rows, &b.maxBytes, &b.bytes, &b.revoked)
	return b, err
}

// pairInfo reads the directed pair counters of the plaintext lane (shared metadata, 11/27.8):
// replied = the recipient answered within PairWindow; reverse = the recipient wrote to the sender first.
func pairInfo(ctx context.Context, q core.Q, fromRoot, toRoot string) (replied, reverse bool, err error) {
	err = q.QueryRow(ctx, `SELECT coalesce((SELECT last_reply > now() - $3::interval FROM mb_pairs WHERE from_root = $1 AND to_root = $2), false),
		EXISTS (SELECT 1 FROM mb_pairs WHERE from_root = $2 AND to_root = $1 AND sent > 0)`, fromRoot, toRoot, PairWindow.String()).Scan(&replied, &reverse)
	return
}

// gates runs the content-blind controls of E2EE 8.1 and the sender gates of 11 in refusal order;
// phantom is true for a blocked sender (silent block, 27.8: nothing is stored).
func (s *svc) gates(ctx context.Context, q core.Q, from *core.Ident, box *inboxRow, env *e2e.Envelope, in *sendIn) (phantom bool, err error) {
	var blocked bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM x_block WHERE inbox = $1 AND root = $2)
		OR EXISTS (SELECT 1 FROM mb_blocks WHERE owner_root = $3 AND from_root = $2)`, box.id, from.Root, box.root).Scan(&blocked); err != nil {
		return false, err
	}
	if blocked {
		return true, nil
	}
	replied, reverse, err := pairInfo(ctx, q, from.Root, box.root)
	if err != nil {
		return false, err
	}
	var allowed bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM x_allow WHERE inbox = $1 AND root = $2)`, box.id, from.Root).Scan(&allowed); err != nil {
		return false, err
	}
	known := replied || reverse
	switch box.mode {
	case "closed":
		return false, errClosed
	case "allow":
		if !allowed {
			return false, errAllow
		}
	case "stamp":
		if !known && !allowed {
			if err := s.checkStamp(ctx, q, from, box, in.env, in.stamp); err != nil {
				return false, err
			}
		}
	}
	if from.Rep < 0 && !reverse {
		return false, errStanding
	}
	if !from.Seed && from.Age() < MinRootAge {
		return false, errAge
	}
	var unacked int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM x_env WHERE to_id = $1 AND from_root = $2`, box.id, from.Root).Scan(&unacked); err != nil {
		return false, err
	}
	switch {
	case !known && !allowed && unacked >= 1:
		return false, errPending
	case unacked >= MaxUnacked:
		return false, errUnacked
	}
	if !replied {
		if err := core.UseQuota(ctx, q, from, "xsend:"+box.id, PerRecipient); err != nil {
			if errors.Is(err, core.ErrQuota) {
				return false, core.E(429, "quota", "recipient: 20 per day to one inbox until it replies")
			}
			return false, err
		}
	}
	if !known {
		var cold int
		if err := q.QueryRow(ctx, `WITH c AS (INSERT INTO mb_cold (from_root, to_root, day) VALUES ($1, $2, current_date) ON CONFLICT DO NOTHING)
			SELECT count(*) FROM mb_cold WHERE from_root = $1 AND day = current_date AND to_root <> $2`, from.Root, box.root).Scan(&cold); err != nil {
			return false, err
		}
		if cold >= ColdPerDay {
			return false, errCold
		}
	}
	if in.group != "" {
		n, err := bump(ctx, q, "ipk:"+s.ipk.of(in.group), "xsend", 1)
		if err != nil {
			return false, err
		}
		if n > NetPerDay {
			return false, errNet
		}
	}
	return false, nil
}

// limits enforces the resource controls of E2EE 9.3 that bind every accepted send, self-addressed
// included (so a self-send cannot bypass them): the per-root daily send quota, the per-inbox
// row/byte caps and the global live-ciphertext budget. Split out of gates (whose remaining checks
// are the content-blind anti-spam controls that only apply to mail to another root).
func (s *svc) limits(ctx context.Context, q core.Q, from *core.Ident, box *inboxRow, in *sendIn) error {
	if err := core.UseQuota(ctx, q, from, "xsend", SendPerDay); err != nil {
		return err
	}
	size := int64(len(in.env))
	if box.rows >= box.maxRows || box.bytes+size > box.maxBytes {
		return errInboxFull
	}
	var live int64
	if err := q.QueryRow(ctx, `SELECT n FROM x_bytes WHERE k = 'live'`).Scan(&live); err != nil {
		return err
	}
	if live+size > MaxBytes {
		return errBudget
	}
	return nil
}

// stampBits is the first-contact difficulty of an inbox (8.1): the policy's bits (default
// E2E_STAMP_BITS), +4 for roots younger than 24 h, +2 per 60 inbound envelopes in the last hour.
func stampBits(ctx context.Context, q core.Q, from *core.Ident, box *inboxRow) (int, error) {
	bits := box.bits
	if bits == 0 {
		bits = StampBits
	}
	if !from.Seed && from.Age() < YoungRoot {
		bits += 4
	}
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM x_ledger WHERE to_id = $1 AND at > now() - interval '1 hour'`, box.id).Scan(&n); err != nil {
		return 0, err
	}
	if n >= HotInbound {
		bits += 2 * (n / HotInbound)
	}
	return min(bits, 40), nil
}

// checkStamp verifies and spends X-Stamp: pow.LeadingZeros("cx1/stamp:" + to + ":" + hex(sha256(body))
// + ":" + YYYYMMDD, nonce) >= bits, today or yesterday (UTC), single use per (to, body, nonce).
func (s *svc) checkStamp(ctx context.Context, q core.Q, from *core.Ident, box *inboxRow, body []byte, nonce string) error {
	bits, err := stampBits(ctx, q, from, box)
	if err != nil {
		return err
	}
	nonce = strings.TrimSpace(nonce)
	need := core.E(429, "pow", fmt.Sprintf("bits=%d (X-Stamp: hashcash over cx1/stamp:<to>:<sha256 body>:<YYYYMMDD>)", bits))
	if nonce == "" || len(nonce) > 64 {
		return need
	}
	now := time.Now().UTC()
	var prefix string
	for _, day := range []string{now.Format("20060102"), now.Add(-24 * time.Hour).Format("20060102")} {
		p := e2e.StampPrefix(box.id, body, day)
		if pow.LeadingZeros(p, nonce) >= bits {
			prefix = p
			break
		}
	}
	if prefix == "" {
		return need
	}
	h := e2e.Sum([]byte(prefix), []byte(":"), []byte(nonce))[:16]
	tag, err := q.Exec(ctx, `INSERT INTO x_stamps (to_id, h) VALUES ($1, $2) ON CONFLICT DO NOTHING`, box.id, h)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.E(409, "pow", "stamp spent")
	}
	return nil
}

// insert stores the envelope row, its ledger twin and the counters inside the caller's transaction
// and returns the signed receipt. No content_origin row, no events row: the lane stores exactly
// the fields of E2EE 8.2.
func (s *svc) insert(ctx context.Context, q core.Q, from *core.Ident, box *inboxRow, env *e2e.Envelope, in *sendIn, scrubM string, self bool) (*sendRes, error) {
	size := len(in.env)
	var seq int64
	if err := q.QueryRow(ctx, `UPDATE x_inbox SET next_seq = next_seq + 1, rows = rows + 1, bytes = bytes + $2, updated = now() WHERE id = $1 RETURNING next_seq - 1`,
		box.id, size).Scan(&seq); err != nil {
		return nil, err
	}
	at := time.Now().Truncate(time.Second)
	res := s.receipt(env, seq, at)
	exp := at.Add(TTL)
	if _, err := q.Exec(ctx, `INSERT INTO x_env (to_id, seq, mid, from_id, from_root, cs, size, epoch, scrub, hdr, body, rcpt, at, exp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		box.id, seq, env.Mid, from.ID, from.Root, int16(env.CS), size, int64(env.Epoch), scrubM, env.HdrBytes(), in.env, res.Rcpt, at, exp); err != nil {
		if core.IsUniqueViolation(err) {
			return nil, core.E(409, "dup", "an envelope with this mid is already in the inbox")
		}
		return nil, err
	}
	if _, err := q.Exec(ctx, `INSERT INTO x_ledger (to_id, seq, mid, from_id, from_root, size, hdr, rcpt, send_ts, send_nonce, send_sig, at, exp)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		box.id, seq, env.Mid, from.ID, from.Root, size, env.HdrBytes(), res.Rcpt, int64(in.sig.TS), in.sig.Nonce, in.sig.Sig, at, exp); err != nil {
		return nil, err
	}
	if _, err := q.Exec(ctx, `UPDATE x_bytes SET n = n + $1 WHERE k = 'live'`, size); err != nil {
		return nil, err
	}
	if !self {
		if _, err := q.Exec(ctx, `INSERT INTO mb_pairs (from_root, to_root, sent) VALUES ($1, $2, 1)
			ON CONFLICT (from_root, to_root) DO UPDATE SET sent = mb_pairs.sent + 1, last_at = now()`, from.Root, box.root); err != nil {
			return nil, err
		}
		// The recipient hearing from this sender unlocks its own replies (the reverse pair, as in 11).
		if _, err := q.Exec(ctx, `INSERT INTO mb_pairs (from_root, to_root, sent, replies, last_reply) VALUES ($1, $2, 0, 1, now())
			ON CONFLICT (from_root, to_root) DO UPDATE SET replies = mb_pairs.replies + 1, last_reply = now()`, box.root, from.Root); err != nil {
			return nil, err
		}
	}
	if env.Epoch != 0 {
		// A share must outlive every envelope sealed to its epoch by ShareLinger (4.9).
		if _, err := q.Exec(ctx, `UPDATE epoch_shares SET exp = greatest(exp, $3::timestamptz + $4::interval) WHERE root = $1 AND e = $2`,
			box.root, int64(env.Epoch), exp, ShareLinger.String()); err != nil {
			return nil, err
		}
	}
	return res, core.Audit(ctx, q, from.ID, "x", box.id+"/"+strconv.FormatInt(seq, 10), size)
}
