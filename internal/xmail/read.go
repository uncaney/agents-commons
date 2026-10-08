package xmail

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
	"ekaii.fr/commons/internal/e2e"
)

var settleSteps = []time.Duration{100 * time.Millisecond, 400 * time.Millisecond}

// Env is the metadata of one sealed row: everything a listing shows, never the ciphertext.
type Env struct {
	Seq       int64
	From      string
	CS        int
	Size      int
	Scrub     string
	Mid, Rcpt []byte
	At        time.Time
	Hidden    bool
	SendSig   *e2e.ReqSig
}

// Bucket is the padded plaintext bucket of the envelope (26.4 `enc=1 bucket=2k`).
func (e Env) Bucket() string {
	return e2e.BucketName(e.Size - e2e.HdrLen - e2e.Suite(e.CS).EncSize() - 16 - e2e.MACLen)
}

// Line renders `<seq> from <id> <date> enc=1 bucket=<k> cs=<n> scrub=<m> at=<unix> mid=<b64> rcpt=<b64> sig=<ts.nonce.sig>`.
// Every field is server-built or a validated id, so no value can start a line of its own.
func (e Env) Line() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d from %s %s enc=1 bucket=%s cs=%d scrub=%s at=%d mid=%s rcpt=%s", e.Seq, e.From, core.Date(e.At), e.Bucket(), e.CS, e.Scrub, e.At.Unix(), b64(e.Mid), b64(e.Rcpt))
	if e.SendSig != nil {
		b.WriteString(" sig=" + e.SendSig.SendSig())
	}
	if e.Hidden {
		b.WriteString(" hidden=1")
	}
	return b.String()
}

func (e Env) JSON() map[string]any {
	j := map[string]any{"seq": e.Seq, "from": e.From, "cs": e.CS, "enc": true, "bucket": e.Bucket(), "scrub": e.Scrub, "at": e.At.Unix(),
		"mid": b64(e.Mid), "rcpt": b64(e.Rcpt), "hidden": e.Hidden}
	if e.SendSig != nil {
		j["send_sig"] = e.SendSig.SendSig()
	}
	return j
}

const envCols = `x.seq, x.from_id, x.cs, x.size, x.scrub, x.mid, x.rcpt, x.at, x.hidden, l.send_ts, l.send_nonce, l.send_sig`

func scanEnv(rows pgx.Rows) (Env, error) {
	var e Env
	var cs int16
	var ts *int64
	var nonce, sig []byte
	if err := rows.Scan(&e.Seq, &e.From, &cs, &e.Size, &e.Scrub, &e.Mid, &e.Rcpt, &e.At, &e.Hidden, &ts, &nonce, &sig); err != nil {
		return e, err
	}
	e.CS = int(cs)
	if ts != nil && len(nonce) == e2e.NonceSize && len(sig) == 64 {
		e.SendSig = &e2e.ReqSig{TS: uint64(*ts), Nonce: nonce, Sig: sig}
	}
	return e, nil
}

// List returns up to k rows of an inbox with seq > after, oldest first (ledger joined for send_sig).
func List(ctx context.Context, q core.Q, inbox string, after int64, k int) ([]Env, error) {
	if k <= 0 || k > MaxK {
		k = MaxK
	}
	rows, err := q.Query(ctx, `SELECT `+envCols+` FROM x_env x LEFT JOIN x_ledger l ON l.to_id = x.to_id AND l.seq = x.seq
		WHERE x.to_id = $1 AND x.seq > $2 ORDER BY x.seq LIMIT $3`, inbox, after, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Env
	for rows.Next() {
		e, err := scanEnv(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Unread counts the unacked rows of a root's tree (the resume section).
func Unread(ctx context.Context, q core.Q, root string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM x_env x JOIN identities i ON i.id = x.to_id WHERE i.root = $1 AND NOT x.hidden`, root).Scan(&n)
	return n, err
}

// readScope: a scoped token needs mb:r or mb:env for listings; url-class tokens never read bodies.
func readScope(id *core.Ident) error {
	if id.Scopes != nil && !core.ScopeAllowed(id.Scopes, "mb:r") && !core.ScopeAllowed(id.Scopes, "mb:env") {
		return core.E(403, "scope", "mb:env")
	}
	return nil
}

// leaseOK refuses a poller or acker that is not the lease holder while a lease is live (4.9).
func leaseOK(ctx context.Context, q core.Q, id, dev string) error {
	var holder string
	err := q.QueryRow(ctx, `SELECT dev FROM x_lease WHERE id = $1 AND until > now()`, id).Scan(&holder)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if holder != dev {
		return core.E(409, "busy", "lease="+holder)
	}
	return nil
}

func devOf(r *http.Request) string {
	dev := strings.TrimSpace(r.Header.Get("X-Cx-Dev"))
	if dev == "" {
		dev = strings.TrimSpace(r.URL.Query().Get("dev"))
	}
	if !devRe.MatchString(dev) {
		return ""
	}
	return dev
}

type pullParams struct {
	after   int64
	k, wait int
	dev     string
}

type pullRes struct {
	envs    []Env
	next    int64
	retry   int
	revoked *time.Time
}

func (res *pullRes) Text() string {
	var b strings.Builder
	for _, e := range res.envs {
		b.WriteString(e.Line() + "\n")
	}
	fmt.Fprintf(&b, "next=%d", res.next)
	if res.retry > 0 {
		fmt.Fprintf(&b, " retry=%d", res.retry)
	}
	b.WriteByte('\n')
	if res.revoked != nil {
		b.WriteString("revoked=" + core.Date(*res.revoked) + "\n")
	}
	return b.String()
}

func (res *pullRes) JSON() map[string]any {
	rows := make([]map[string]any, 0, len(res.envs))
	for _, e := range res.envs {
		rows = append(rows, e.JSON())
	}
	j := map[string]any{"rows": rows, "next": res.next}
	if res.retry > 0 {
		j["retry_s"] = res.retry
	}
	if res.revoked != nil {
		j["revoked"] = res.revoked.UTC().Format(time.RFC3339)
	}
	return j
}

func parsePull(r *http.Request) (pullParams, error) {
	v := r.URL.Query()
	p := pullParams{dev: devOf(r)}
	var err error
	if x := v.Get("after"); x != "" {
		if p.after, err = strconv.ParseInt(x, 10, 64); err != nil || p.after < 0 {
			return p, core.Bad("after must be a sequence number")
		}
	}
	if x := v.Get("k"); x != "" {
		if p.k, err = strconv.Atoi(x); err != nil || p.k < 1 || p.k > MaxK {
			return p, core.Bad("k must be 1.." + strconv.Itoa(MaxK))
		}
	}
	if x := v.Get("wait"); x != "" {
		if p.wait, err = strconv.Atoi(x); err != nil || p.wait < 0 || p.wait > MaxWait {
			return p, core.Bad("wait must be 0.." + strconv.Itoa(MaxWait))
		}
	}
	return p, nil
}

// read lists the caller's inbox with the long-poll policy of 3.6 (one Waiters slot, shed:longpoll
// and a missing slot answer at once with retry=5). poll=fixed answers after the full wait whatever
// arrives (constant latency, 4.5); early returns on the Notifier topic x:<id>.
func (s *svc) read(ctx context.Context, id *core.Ident, p pullParams, group string) (*pullRes, error) {
	if err := readScope(id); err != nil {
		return nil, err
	}
	if err := leaseOK(ctx, s.d.DB, id.ID, p.dev); err != nil {
		return nil, err
	}
	res := &pullRes{next: p.after}
	poll := "early"
	err := s.d.DB.QueryRow(ctx, `SELECT poll, revoked_at FROM x_inbox WHERE id = $1`, id.ID).Scan(&poll, &res.revoked)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	wait := p.wait
	if wait > 0 && s.d.Shed(nil, "longpoll") {
		wait, res.retry = 0, 5
	}
	if wait > 0 {
		release, ok := s.d.Waiters.Acquire(id.Root, group)
		if !ok {
			wait, res.retry = 0, 5
		} else {
			defer release()
		}
	}
	fixed := poll == "fixed" && wait > 0
	if fixed {
		wait = MaxWait
		t := time.NewTimer(time.Duration(wait) * time.Second)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
		}
		wait = 0
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	settle := len(settleSteps)
	for {
		var c <-chan struct{}
		cancel := func() {}
		if wait > 0 {
			c, cancel = s.d.Notify.Subscribe("x:" + id.ID)
		}
		envs, err := List(ctx, s.d.DB, id.ID, p.after, p.k)
		if err != nil {
			cancel()
			return nil, err
		}
		res.envs = envs
		if len(envs) > 0 {
			res.next = envs[len(envs)-1].Seq
		}
		rem := time.Until(deadline)
		if len(envs) > 0 || wait == 0 || rem <= 0 {
			cancel()
			return res, nil
		}
		if settle < len(settleSteps) {
			rem = min(rem, settleSteps[settle])
			settle++
		}
		t := time.NewTimer(rem)
		select {
		case <-c:
			settle = 0
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return res, nil
		}
		t.Stop()
		cancel()
	}
}

func (s *svc) pull(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	p, err := parsePull(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	res, err := s.read(r.Context(), id, p, s.d.IPGroup(r))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, res.Text(), res.JSON())
}

// parseSeq reads the {id} segment of GET|DELETE /v1/x/{id}: a sequence number of the caller's inbox.
func parseSeq(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, core.Bad("id must be the seq of an envelope in your inbox")
	}
	return n, nil
}

// get is GET /v1/x/{seq}: the raw envelope bytes (application/octet-stream) with the receipt and the
// sender's request signature in headers; ?f=json wraps them in one object. A hidden row answers 410.
func (s *svc) get(w http.ResponseWriter, r *http.Request) {
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
	if id.Scopes != nil && !core.ScopeAllowed(id.Scopes, "mb:r") {
		core.Fail(w, r, core.E(403, "scope", "mb:r"))
		return
	}
	seq, err := parseSeq(r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var body []byte
	var hidden bool
	var at time.Time
	var rcpt, nonce, sig []byte
	var ts *int64
	err = s.d.DB.QueryRow(r.Context(), `SELECT x.body, x.hidden, x.at, x.rcpt, l.send_ts, l.send_nonce, l.send_sig FROM x_env x
		LEFT JOIN x_ledger l ON l.to_id = x.to_id AND l.seq = x.seq WHERE x.to_id = $1 AND x.seq = $2`, id.ID, seq).Scan(&body, &hidden, &at, &rcpt, &ts, &nonce, &sig)
	if errors.Is(err, pgx.ErrNoRows) {
		core.Fail(w, r, core.ErrNotFound)
		return
	}
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if hidden {
		core.Fail(w, r, core.E(410, "gone", "ciphertext deleted after a report"))
		return
	}
	sendSig := ""
	if ts != nil && len(nonce) == e2e.NonceSize && len(sig) == 64 {
		sendSig = (&e2e.ReqSig{TS: uint64(*ts), Nonce: nonce, Sig: sig}).SendSig()
	}
	h := w.Header()
	h.Set("X-Cx-Seq", strconv.FormatInt(seq, 10))
	h.Set("X-Cx-At", strconv.FormatInt(at.Unix(), 10))
	h.Set("X-Cx-Rcpt", b64(rcpt))
	if sendSig != "" {
		h.Set("X-Cx-Send-Sig", sendSig)
	}
	if core.WantJSON(r) {
		core.JSON(w, 200, map[string]any{"seq": seq, "at": at.Unix(), "rcpt": b64(rcpt), "send_sig": sendSig, "env": b64(body)})
		return
	}
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(200)
	w.Write(body)
}

// ack is DELETE /v1/x/{seq} (X-Cx-Sig): deletes the row (every row up to it with ?upto=1); the
// ledger twin stays 30 d. Deletion on ack is the relay's forward secrecy (4.6).
func (s *svc) ack(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	seq, err := parseSeq(r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	n, err := s.ackOp(r.Context(), id, seq, r.URL.Query().Get("upto") == "1", devOf(r))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, fmt.Sprintf("ok n=%d", n), map[string]any{"ok": true, "n": n})
}

func (s *svc) ackOp(ctx context.Context, id *core.Ident, seq int64, upto bool, dev string) (int64, error) {
	if err := leaseOK(ctx, s.d.DB, id.ID, dev); err != nil {
		return 0, err
	}
	var n int64
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var err error
		if upto {
			n, err = deleteEnvs(ctx, tx, `DELETE FROM x_env WHERE to_id = $1 AND seq <= $2`, id.ID, seq)
		} else {
			n, err = deleteEnvs(ctx, tx, `DELETE FROM x_env WHERE to_id = $1 AND seq = $2`, id.ID, seq)
		}
		if err != nil || n == 0 {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "xack", strconv.FormatInt(seq, 10), int(n))
	})
	return n, err
}

// --- lease --------------------------------------------------------------------------------------

// lease is POST /v1/x/lease {"dev"} (X-Cx-Sig): 60 s renewable poll/ack lease for one device.
func (s *svc) lease(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in struct {
		Dev string `json:"dev"`
	}
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	if !devRe.MatchString(in.Dev) {
		core.Fail(w, r, core.Bad("dev must match [A-Za-z0-9._-]{1,32}"))
		return
	}
	var until time.Time
	err = s.d.DB.QueryRow(r.Context(), `INSERT INTO x_lease (id, dev, until) VALUES ($1, $2, now() + $3::interval)
		ON CONFLICT (id) DO UPDATE SET dev = EXCLUDED.dev, until = EXCLUDED.until WHERE x_lease.until <= now() OR x_lease.dev = EXCLUDED.dev
		RETURNING until`, id.ID, in.Dev, LeaseTTL.String()).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		var holder string
		if err := s.d.DB.QueryRow(r.Context(), `SELECT dev FROM x_lease WHERE id = $1`, id.ID).Scan(&holder); err != nil {
			core.Fail(w, r, err)
			return
		}
		core.Fail(w, r, core.E(409, "busy", "lease="+holder))
		return
	}
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, fmt.Sprintf("ok until=%d", until.Unix()), map[string]any{"ok": true, "until": until.Unix()})
}

// --- policy and blocks --------------------------------------------------------------------------

var modes = map[string]bool{"open": true, "stamp": true, "allow": true, "closed": true}

type policyIn struct {
	Mode  *string  `json:"mode"`
	Allow []string `json:"allow"`
	Bits  *int     `json:"bits"`
	Poll  *string  `json:"poll"`
}

// policyPut is PUT /v1/x/policy (X-Cx-Sig): mode, allow list (ids resolved to roots), bits, poll.
func (s *svc) policyPut(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in policyIn
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	switch {
	case in.Mode != nil && !modes[*in.Mode]:
		core.Fail(w, r, core.Bad("mode must be open|stamp|allow|closed"))
		return
	case in.Bits != nil && (*in.Bits < 0 || *in.Bits > 40):
		core.Fail(w, r, core.Bad("bits must be 0..40 (0 = server default)"))
		return
	case in.Poll != nil && *in.Poll != "early" && *in.Poll != "fixed":
		core.Fail(w, r, core.Bad("poll must be early|fixed"))
		return
	case len(in.Allow) > 64:
		core.Fail(w, r, core.Bad("allow holds at most 64 ids"))
		return
	}
	for _, a := range in.Allow {
		if !core.ValidIDPrefix(a, 'a') {
			core.Fail(w, r, core.Bad("allow entries must be identity ids"))
			return
		}
	}
	ctx := r.Context()
	var text string
	var j map[string]any
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := loadInbox(ctx, tx, id.ID, id.Root); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE x_inbox SET mode = coalesce($2, mode), bits = coalesce($3, bits), poll = coalesce($4, poll), updated = now() WHERE id = $1`,
			id.ID, in.Mode, in.Bits, in.Poll); err != nil {
			return err
		}
		if in.Allow != nil {
			if _, err := tx.Exec(ctx, `DELETE FROM x_allow WHERE inbox = $1`, id.ID); err != nil {
				return err
			}
			for _, a := range in.Allow {
				var root string
				if err := tx.QueryRow(ctx, `SELECT root FROM identities WHERE id = $1`, a).Scan(&root); err != nil {
					if errors.Is(err, pgx.ErrNoRows) {
						return core.E(404, "notfound", "allow: unknown identity "+a)
					}
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO x_allow (inbox, root, id) VALUES ($1, $2, $3) ON CONFLICT (inbox, root) DO UPDATE SET id = EXCLUDED.id`, id.ID, root, a); err != nil {
					return err
				}
			}
		}
		var err error
		text, j, err = policyText(ctx, tx, id.ID)
		if err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "xpolicy", "", len(in.Allow))
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, "ok "+text, j)
}

// policyText renders `mode=<m> bits=<n> poll=<p> allow=<ids> blocks=<ids>` (ids, never roots).
func policyText(ctx context.Context, q core.Q, inbox string) (string, map[string]any, error) {
	mode, poll, bits := "stamp", "early", 0
	err := q.QueryRow(ctx, `SELECT mode, poll, bits FROM x_inbox WHERE id = $1`, inbox).Scan(&mode, &poll, &bits)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", nil, err
	}
	list := func(table string) ([]string, error) {
		rows, err := q.Query(ctx, `SELECT id FROM `+table+` WHERE inbox = $1 ORDER BY id`, inbox)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, rows.Err()
	}
	allow, err := list("x_allow")
	if err != nil {
		return "", nil, err
	}
	blocks, err := list("x_block")
	if err != nil {
		return "", nil, err
	}
	eff := bits
	if eff == 0 {
		eff = StampBits
	}
	text := fmt.Sprintf("mode=%s bits=%d poll=%s allow=%s blocks=%s", mode, eff, poll, orDash(strings.Join(allow, ",")), orDash(strings.Join(blocks, ",")))
	return text, map[string]any{"mode": mode, "bits": eff, "poll": poll, "allow": allow, "blocks": blocks}, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (s *svc) policyGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	text, j, err := policyText(r.Context(), s.d.DB, id.ID)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, text, j)
}

// block is PUT|DELETE /v1/x/block {"id"} (X-Cx-Sig): the sender's ROOT is stored; a blocked root
// gets a phantom receipt and nothing is stored (silent block, 27.8).
func (s *svc) block(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	out, err := s.blockOp(r.Context(), id, in.ID, r.Method == http.MethodDelete)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, out, map[string]any{"ok": true})
}

func (s *svc) blockOp(ctx context.Context, id *core.Ident, target string, del bool) (string, error) {
	if !core.ValidIDPrefix(target, 'a') {
		return "", core.Bad("id must be an identity id")
	}
	var root string
	err := s.d.DB.QueryRow(ctx, `SELECT root FROM identities WHERE id = $1`, target).Scan(&root)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", core.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if root == id.Root {
		return "", core.Bad("cannot block your own tree")
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if del {
			_, err := tx.Exec(ctx, `DELETE FROM x_block WHERE inbox = $1 AND root = $2`, id.ID, root)
			return err
		}
		if _, err := loadInbox(ctx, tx, id.ID, id.Root); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO x_block (inbox, root, id) VALUES ($1, $2, $3) ON CONFLICT (inbox, root) DO UPDATE SET id = EXCLUDED.id, at = now()`, id.ID, root, target); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "xblock", root, 1)
	})
	if err != nil {
		return "", err
	}
	if del {
		return "ok unblocked=" + target, nil
	}
	return "ok blocked=" + target, nil
}

// --- resume / me ----------------------------------------------------------------------------------

func resumeLines(ctx context.Context, q core.Q, root string) []string {
	n, err := Unread(ctx, q, root)
	if err != nil || n == 0 {
		return nil
	}
	return []string{fmt.Sprintf("sealed: %d unread", n)}
}

func meLines(ctx context.Context, q core.Q, id *core.Ident) []string {
	var out []string
	if n, err := Unread(ctx, q, id.Root); err == nil && n > 0 {
		out = append(out, fmt.Sprintf("sealed: unread=%d", n))
	}
	var revoked *time.Time
	if err := q.QueryRow(ctx, `SELECT revoked_at FROM x_inbox WHERE id = $1`, id.ID).Scan(&revoked); err == nil && revoked != nil {
		out = append(out, "sealed: revoked="+core.Date(*revoked))
	}
	var until *time.Time
	if err := q.QueryRow(ctx, `SELECT max(until) FROM x_frozen WHERE id IN ($1, $2) AND until > now()`, id.ID, id.Root).Scan(&until); err == nil && until != nil {
		out = append(out, "sealed: mail-frozen until="+core.Date(*until))
	}
	return out
}
