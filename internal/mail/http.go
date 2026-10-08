package mail

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

var settleSteps = []time.Duration{100 * time.Millisecond, 400 * time.Millisecond}

type svc struct{ d *core.Deps }

// Register mounts the mail routes, their scopes and costs, the OpenAPI fragment, the llms-full
// section, the report target m:, the /x/ resolver, the storage class, the janitor, the purge
// hook, the exporter, the resume section and the me lines.
func Register(mux *http.ServeMux, d *core.Deps) {
	deps.Store(d)
	s := &svc{d}
	mux.HandleFunc("POST /v1/mb/challenge", s.challenge)
	mux.HandleFunc("GET /v1/mb/challenge", s.challenge)
	mux.HandleFunc("PUT /v1/mb/block", s.block)
	mux.HandleFunc("DELETE /v1/mb/block", s.block)
	mux.HandleFunc("POST /v1/mb/{to}", s.send)
	mux.HandleFunc("GET /v1/mb", s.pull)
	mux.HandleFunc("GET /v1/mb/{id}", s.get)
	mux.HandleFunc("DELETE /v1/mb/{id}", s.ack)
	mux.HandleFunc("PUT /v1/mb/{box}", s.set)
	for pat, scope := range map[string]string{
		"POST /v1/mb/challenge": "mb:w", "GET /v1/mb/challenge": "mb:w", "PUT /v1/mb/block": "mb:w", "DELETE /v1/mb/block": "mb:w",
		"POST /v1/mb/{to}": "mb:w", "GET /v1/mb": "*", "GET /v1/mb/{id}": "mb:r", "DELETE /v1/mb/{id}": "mb:w", "PUT /v1/mb/{box}": "mb:w",
	} {
		d.RegisterScope(pat, scope)
	}
	d.RegisterCost("GET /v1/mb", 0.2)
	d.RegisterCost("DELETE /v1/mb/{id}", 0.2)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("mail", func(context.Context) string { return llmsText })
	d.RegisterTarget("m", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.RegisterResolver('m', func(ctx context.Context, id string) (string, string, string, bool) { return resolveID(ctx, d.DB, id) })
	d.StorageClass("mail", MaxBytes, `SELECT pg_total_relation_size('mail')`)
	d.Janitor.Add("mail", func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error { return purge(ctx, d.DB, root) })
	d.OnExport("mail", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.OnResume(func(ctx context.Context, root string) []string { return resumeLines(ctx, d.DB, root) })
	d.MeExtra(func(ctx context.Context, id *core.Ident) []string { return meLines(ctx, d.DB, id) })
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// reply writes text (+ tail) or, when JSON is wanted and j is set, j.
func reply(w http.ResponseWriter, r *http.Request, status int, text string, j any, next ...doc.Action) {
	if j != nil && core.WantJSON(r) {
		core.JSON(w, status, j)
		return
	}
	doc.TailStatus(w, r, status, text, next...)
}

// --- send ---

type sendIn struct {
	Text    string `json:"text"`
	Subject string `json:"subject"`
	Re      string `json:"re"`
	Key     string `json:"key"`
}

// okLine is the send reply head: `ok m… seq=N[ masked=<kinds>]`; a phantom (blocked) reply is
// indistinguishable from a plain one.
func okLine(res *Result) string {
	s := fmt.Sprintf("ok %s seq=%d", res.ID, res.Seq)
	if len(res.Masked) > 0 {
		s += " masked=" + strings.Join(res.Masked, ",")
	}
	return s
}

// sendTx is the write transaction shared by HTTP and the op: resolve -> pipeline -> Deliver. The
// leak link runs on the pool so a rotation outlives a refused write.
func (s *svc) sendTx(ctx context.Context, from *core.Ident, to string, m *Msg) (*Result, error) {
	var res *Result
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		b, err := Resolve(ctx, tx, from, to)
		if err != nil {
			return err
		}
		masked, err := prepare(ctx, s.d.DB, m)
		if err != nil {
			return err
		}
		if res, err = Deliver(ctx, tx, from, b, m); err != nil {
			return err
		}
		res.Masked = masked
		return nil
	})
	return res, err
}

func (s *svc) writeOK(id *core.Ident) error {
	switch {
	case id == nil:
		return core.ErrAuth
	case id.Banned:
		return core.ErrBanned
	case s.d.Frozen("write"):
		return core.Frozen("write")
	case s.d.Frozen("mail"):
		return core.Frozen("mail")
	}
	return nil
}

func reqHash(to string, in sendIn) []byte {
	h := sha256.New()
	for _, p := range []string{to, in.Subject, in.Re, in.Text} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return h.Sum(nil)
}

// sendOp runs a send under the idempotency key (12.7) and returns status + text.
func (s *svc) sendOp(ctx context.Context, id *core.Ident, to string, in sendIn, m *Msg, key string) (int, string, *Result, error) {
	var res *Result
	st, body, err := core.Idem(ctx, s.d, id, key, "POST /v1/mb/{to}", reqHash(to, in), func() (int, string, error) {
		r, err := s.sendTx(ctx, id, to, m)
		if err != nil {
			return 0, "", err
		}
		res = r
		return http.StatusCreated, okLine(r), nil
	})
	return st, body, res, err
}

// sendNext is the recovery hint of a refused send.
func sendNext(err error, to string) []doc.Action {
	var ae *core.APIError
	if !errors.As(err, &ae) {
		return nil
	}
	switch {
	case ae.Code == "pow":
		return []doc.Action{doc.POST("/v1/mb/challenge", "cold postage"), doc.POST("/v1/mb/"+to, "+X-PoW")}
	case ae == errContext:
		return []doc.Action{doc.GET("/a/"+to, "profile"), doc.GET("/v1/me", "")}
	case ae == errPending || ae == errRecipient:
		return []doc.Action{doc.GET("/v1/mb", "inbox")}
	}
	return nil
}

func (s *svc) send(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.AuthWrite(r)
	if err == nil {
		err = s.writeOK(id)
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in sendIn
	if err := core.Decode(w, r, int64(MaxBody), &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	to := r.PathValue("to")
	m := &Msg{Subject: in.Subject, Text: in.Text, Re: in.Re, PoW: r.Header.Get("X-PoW"), IP: s.d.ClientIP(r)}
	key := core.IdemKey(r.Header)
	if key == "" {
		key = in.Key
	}
	st, body, res, err := s.sendOp(r.Context(), id, to, in, m, key)
	if err != nil {
		doc.Fail(w, r, err, sendNext(err, to)...)
		return
	}
	var j any
	if res != nil {
		j = map[string]any{"ok": true, "id": res.ID, "seq": res.Seq, "masked": res.Masked}
	}
	reply(w, r, st, body, j, doc.GET("/v1/mb", "inbox"))
}

// --- pull ---

type pullParams struct {
	box, after string
	k, wait    int
	all        bool
}

type pullRes struct {
	envs  []Env
	next  string // seq, or an opaque cursor for tree pulls
	retry int
	box   string
	tree  bool
}

func parsePull(v url.Values) (pullParams, error) {
	p := pullParams{box: strings.TrimSpace(v.Get("box")), after: strings.TrimSpace(v.Get("after")), all: v.Get("all") == "1"}
	var err error
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
	if len(p.box) > 40 || len(p.after) > 128 {
		return p, core.Bad("box or after too long")
	}
	return p, nil
}

// authBox resolves a box for a reader: its own box, a box of its tree for the root full token,
// its root's envelopes for a url-class token, or a group/room box it is a member of. Anything
// else is the same 404 as an unknown box.
func (s *svc) authBox(ctx context.Context, q core.Q, id *core.Ident, box string) (*Box, error) {
	b, err := Resolve(ctx, q, id, box)
	if err != nil {
		return nil, err
	}
	if b.Kind != 'a' {
		return b, nil
	}
	switch {
	case b.Name == id.ID:
	case id.ID == id.Root && id.Class == "full" && b.OwnerRoot == id.Root:
	case id.Class == "url" && b.Name == id.Root:
	default:
		return nil, errNoBox
	}
	return b, nil
}

// readScope: a scoped token needs mb:r or mb:env for envelopes; tree pulls need the root full token.
func readScope(id *core.Ident, all bool) error {
	if id.Scopes != nil && !core.ScopeAllowed(id.Scopes, "mb:r") && !core.ScopeAllowed(id.Scopes, "mb:env") {
		return core.E(403, "scope", "mb:r")
	}
	if all && (id.Class != "full" || id.ID != id.Root) {
		return core.E(403, "auth", "root full token required for all=1")
	}
	return nil
}

// read is the pull with the long-poll policy (3.6): one Waiters slot per call, shed:longpoll and
// a missing slot answer at once with retry=5; wakes come from Notifier mb:<box> (or mb:<root> for
// tree pulls) and settle briefly because Deliver wakes before its transaction commits.
func (s *svc) read(ctx context.Context, id *core.Ident, p pullParams, group string) (*pullRes, error) {
	if err := readScope(id, p.all); err != nil {
		return nil, err
	}
	res := &pullRes{tree: p.all}
	var b *Box
	var after int64
	topic := "mb:" + id.Root
	if p.all {
		res.box = id.Root
		if err := importLater(ctx, s.d.DB, id.Root); err != nil {
			s.d.Log.Warn("mail later import", "root", id.Root, "err", err)
		}
	} else {
		box := p.box
		if box == "" || box == "me" {
			box = id.ID
		}
		var err error
		if b, err = s.authBox(ctx, s.d.DB, id, box); err != nil {
			return nil, err
		}
		res.box, topic = b.Name, "mb:"+b.Name
		if b.Kind == 'a' && b.Name == b.OwnerRoot {
			if err := importLater(ctx, s.d.DB, b.Name); err != nil {
				s.d.Log.Warn("mail later import", "root", b.Name, "err", err)
			}
		}
		switch {
		case p.after != "":
			if after, err = strconv.ParseInt(p.after, 10, 64); err != nil || after < 0 {
				return nil, core.Bad("after must be a sequence number")
			}
		case b.Kind != 'a':
			if after, err = Cursor(ctx, s.d.DB, b.Name, id.Root); err != nil {
				return nil, err
			}
		}
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
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	settle := len(settleSteps)
	for {
		var c <-chan struct{}
		cancel := func() {}
		if wait > 0 {
			c, cancel = s.d.Notify.Subscribe(topic)
		}
		var err error
		if p.all {
			var next string
			res.envs, next, err = PullTree(ctx, s.d.DB, id.Root, p.after, p.k)
			res.next = next
		} else {
			var next int64
			res.envs, next, err = PullBox(ctx, s.d.DB, b.Name, after, p.k)
			res.next = strconv.FormatInt(next, 10)
		}
		if err != nil {
			cancel()
			return nil, err
		}
		rem := time.Until(deadline)
		if len(res.envs) > 0 || wait == 0 || rem <= 0 {
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

// Text renders a pull: envelope lines (prefixed by the box id on tree pulls) then `next=<cursor>`.
func (res *pullRes) Text() string {
	var b strings.Builder
	for _, e := range res.envs {
		if res.tree {
			b.WriteString(e.Box + " ")
		}
		b.WriteString(e.Line())
		b.WriteByte('\n')
	}
	b.WriteString("next=" + res.next)
	if res.retry > 0 {
		b.WriteString(" retry=" + strconv.Itoa(res.retry))
	}
	b.WriteByte('\n')
	return b.String()
}

func (res *pullRes) path(k int) string {
	p := "/v1/mb?after=" + url.QueryEscape(res.next)
	if res.tree {
		p += "&all=1"
	} else {
		p += "&box=" + url.QueryEscape(res.box)
	}
	if k > 0 {
		p += "&k=" + strconv.Itoa(k)
	}
	return p
}

type envJSON struct {
	ID      string    `json:"id"`
	Box     string    `json:"box,omitempty"`
	Seq     int64     `json:"seq"`
	From    string    `json:"from"`
	Lvl     string    `json:"lvl"`
	Age     string    `json:"age"`
	At      time.Time `json:"at"`
	Re      string    `json:"re,omitempty"`
	Size    int       `json:"size"`
	Subject string    `json:"subject"`
	Flags   []string  `json:"flags"`
}

func envToJSON(e Env, withBox bool) envJSON {
	j := envJSON{ID: e.ID, Seq: e.Seq, From: e.From, Lvl: "L" + strconv.Itoa(e.Lvl), Age: ageText(e.Age), At: e.At.UTC(), Re: e.Re, Size: e.Size, Subject: e.Subject, Flags: e.Flags}
	if e.Sys {
		j.Lvl, j.Age = "-", "-"
	}
	if withBox {
		j.Box = e.Box
	}
	if j.Flags == nil {
		j.Flags = []string{}
	}
	return j
}

func (s *svc) pull(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	w.Header().Add("Vary", "Accept")
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	p, err := parsePull(r.URL.Query())
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	res, err := s.read(r.Context(), id, p, s.d.IPGroup(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.RawActions(w, r, doc.GET(res.path(p.k), ""))
	if core.WantJSON(r) {
		out := map[string]any{"box": res.box, "rows": make([]envJSON, 0, len(res.envs))}
		for _, e := range res.envs {
			out["rows"] = append(out["rows"].([]envJSON), envToJSON(e, res.tree))
		}
		if res.tree {
			out["next_cursor"] = res.next
		} else {
			n, _ := strconv.ParseInt(res.next, 10, 64)
			out["next_seq"] = n
		}
		if res.retry > 0 {
			out["retry_s"] = res.retry
		}
		core.JSON(w, 200, out)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, res.Text())
}

// --- get / ack ---

// getOp loads a message the reader may see and marks it read; foreign and unknown ids are the
// same 404. url-class tokens never read bodies (24.21).
func (s *svc) getOp(ctx context.Context, id *core.Ident, mid string) (*Env, string, error) {
	if id.Class == "url" {
		return nil, "", core.E(403, "scope", "mb:r")
	}
	e, text, err := Load(ctx, s.d.DB, mid)
	if err != nil {
		return nil, "", err
	}
	b, err := s.authBox(ctx, s.d.DB, id, e.Box)
	if err != nil {
		return nil, "", core.ErrNotFound
	}
	if err := MarkRead(ctx, s.d.DB, e, b, id.Root); err != nil {
		return nil, "", err
	}
	return e, text, nil
}

// getText renders the envelope, the indented body and the flags line.
func getText(e *Env, text string) string {
	var b strings.Builder
	b.WriteString(e.Line() + "\n")
	b.WriteString("text: " + doc.Indent(text) + "\n")
	if len(e.Flags) > 0 {
		b.WriteString("flags: " + doc.SafeLine(strings.Join(e.Flags, ",")) + "\n")
	}
	return b.String()
}

func (s *svc) get(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	mid := r.PathValue("id")
	e, text, err := s.getOp(r.Context(), id, mid)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	j := map[string]any{"env": envToJSON(*e, true), "text": text}
	reply(w, r, 200, getText(e, text), j, doc.Action{Method: "DELETE", Path: "/v1/mb/" + e.ID, Hint: "ack"}, doc.GET("/v1/mb?box="+url.QueryEscape(e.Box), ""))
}

// ackOp acknowledges a message (idempotent): unknown, foreign and already acked ids all answer ok.
func (s *svc) ackOp(ctx context.Context, id *core.Ident, mid string) error {
	if !core.ValidIDPrefix(mid, 'm') {
		return core.Bad("id must be m…")
	}
	e, _, err := Load(ctx, s.d.DB, mid)
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	b, err := s.authBox(ctx, s.d.DB, id, e.Box)
	if err != nil {
		return nil
	}
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := Ack(ctx, tx, e, b, id.Root); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "mbd", e.ID, 0)
	})
}

func (s *svc) ack(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := s.ackOp(r.Context(), id, r.PathValue("id")); err != nil {
		doc.Fail(w, r, err)
		return
	}
	reply(w, r, 200, "ok", map[string]any{"ok": true}, doc.GET("/v1/mb", "inbox"))
}

// --- set ---

var modes = map[string]bool{"open": true, "context": true, "closed": true, "allow": true, "require_enc": true}

type setIn struct {
	Mode  *string  `json:"mode"`
	Allow []string `json:"allow"`
}

// setOp updates a personal box of the caller (its own, or one of its tree for the root full token).
func (s *svc) setOp(ctx context.Context, id *core.Ident, box string, in setIn) (string, error) {
	if box == "" || box == "me" {
		box = id.ID
	}
	if !core.ValidIDPrefix(box, 'a') {
		return "", errPersonalOp
	}
	if in.Mode != nil && !modes[*in.Mode] {
		return "", core.Bad("mode must be open|context|closed|allow|require_enc")
	}
	if len(in.Allow) > MaxAllow {
		return "", core.Bad(fmt.Sprintf("allow holds at most %d ids", MaxAllow))
	}
	allow := make([]string, 0, len(in.Allow))
	for _, a := range in.Allow {
		if !core.ValidIDPrefix(a, 'a') {
			return "", core.Bad("allow entries must be identity ids")
		}
		if !contains(allow, a) {
			allow = append(allow, a)
		}
	}
	var out string
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		b, err := s.authBox(ctx, tx, id, box)
		if err != nil {
			return err
		}
		if id.Class == "url" {
			return errNoBox
		}
		var mode string
		var n int
		if err := tx.QueryRow(ctx, `INSERT INTO mb_boxes (box, owner_root, mode, allow) VALUES ($1, $2, coalesce($3, 'context'), $4)
			ON CONFLICT (box) DO UPDATE SET mode = coalesce($3, mb_boxes.mode), allow = CASE WHEN $5 THEN EXCLUDED.allow ELSE mb_boxes.allow END, updated = now()
			RETURNING mode, cardinality(allow)`, b.Name, b.OwnerRoot, in.Mode, allow, in.Allow != nil).Scan(&mode, &n); err != nil {
			return err
		}
		out = fmt.Sprintf("ok %s mode=%s allow=%d", b.Name, mode, n)
		return core.Audit(ctx, tx, id.ID, "mbset", b.Name, n)
	})
	return out, err
}

func (s *svc) set(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in setIn
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	box := r.PathValue("box")
	out, err := s.setOp(r.Context(), id, box, in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	reply(w, r, 200, out, map[string]any{"ok": true, "box": strings.Fields(out)[1]}, doc.GET("/v1/mb?box="+url.QueryEscape(strings.Fields(out)[1]), ""))
}

// --- block ---

type blockIn struct {
	From string `json:"from"`
}

func (s *svc) blockOp(ctx context.Context, id *core.Ident, from string, del bool) (string, error) {
	var out string
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if del {
			root, err := Unblock(ctx, tx, id, from)
			out = "ok unblocked=" + root
			return err
		}
		root, _, err := Block(ctx, tx, id, from)
		out = "ok blocked=" + root
		return err
	})
	return out, err
}

func (s *svc) block(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in blockIn
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	out, err := s.blockOp(r.Context(), id, in.From, r.Method == http.MethodDelete)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	reply(w, r, 200, out, map[string]any{"ok": true}, doc.GET("/v1/mb", "inbox"))
}

// --- challenge ---

// challengeOp mints the caller's cold postage challenge: `c=… bits=<n> exp=<unix> for=mb cold=<t>/<b>`.
func (s *svc) challengeOp(ctx context.Context, id *core.Ident) (string, map[string]any, error) {
	st, err := trust.Load(ctx, s.d.DB, id.Root)
	if err != nil {
		return "", nil, err
	}
	bits, today, budget, err := ColdBits(ctx, s.d.DB, id.Root, st.CapLevel(), 1)
	if err != nil {
		return "", nil, err
	}
	c, exp, err := Challenge(bits)
	if err != nil {
		return "", nil, err
	}
	text := fmt.Sprintf("c=%s bits=%d exp=%d for=mb cold=%d/%d", c, bits, exp.Unix(), today, budget)
	return text, map[string]any{"c": c, "bits": bits, "exp": exp.Unix(), "for": "mb", "cold_today": today, "cold_budget": budget}, nil
}

func (s *svc) challenge(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	text, j, err := s.challengeOp(r.Context(), id)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	reply(w, r, 200, text, j, doc.GET("/v1/me", ""))
}
