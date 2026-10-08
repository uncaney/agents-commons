package webhook

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

var (
	kindRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,31}$`)
	tagRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,31}$`)
	fmts   = map[string]bool{"standard": true, "slack": true, "discord": true, "ntfy": true, "a2a": true}
)

// Hook is one outbound webhook row.
type Hook struct {
	ID, Root, URL, Fmt string
	Kinds, Tags        []string
	Q                  string
	Secret             []byte
	LastSeq            int64
	Created            time.Time
}

const hookCols = `id, root, url, fmt, kinds, tags, q, secret, last_seq, created`

func scanHook(row pgx.Row) (*Hook, error) {
	var h Hook
	if err := row.Scan(&h.ID, &h.Root, &h.URL, &h.Fmt, &h.Kinds, &h.Tags, &h.Q, &h.Secret, &h.LastSeq, &h.Created); err != nil {
		return nil, err
	}
	return &h, nil
}

// CreateIn is the POST /v1/hook / op hk body.
type CreateIn struct {
	URL   string   `json:"url"`
	Fmt   string   `json:"fmt"`
	Kinds []string `json:"kinds"`
	Tags  []string `json:"tags"`
	Q     string   `json:"q"`
}

// normList lowercases, trims, validates, dedupes and caps a filter list; never nil.
func normList(in []string, re *regexp.Regexp, what string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !re.MatchString(s) {
			return nil, core.Bad(what + " must match " + re.String())
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
		if len(out) > 20 {
			return nil, core.Bad("at most 20 " + what + "s")
		}
	}
	return out, nil
}

// validURL accepts an http(s) absolute URL <= 512 bytes. The url is owner-private (never fetched,
// never exported), so it is exempt from the tier-1 webhook-url rejection other write paths apply.
func validURL(u string) error {
	u = strings.TrimSpace(u)
	switch {
	case u == "" || len(u) > maxURL || !doc.OneLine(u):
		return core.Bad("url must be one line <= 512 bytes")
	}
	p, err := url.Parse(u)
	if err != nil || (p.Scheme != "http" && p.Scheme != "https") || p.Host == "" {
		return core.Bad("url must be an http(s) URL")
	}
	return nil
}

func (in CreateIn) norm() (*Hook, error) {
	if err := validURL(in.URL); err != nil {
		return nil, err
	}
	in.Fmt = strings.ToLower(strings.TrimSpace(in.Fmt))
	if in.Fmt == "" {
		in.Fmt = "standard"
	}
	if !fmts[in.Fmt] {
		return nil, core.Bad("fmt must be standard|slack|discord|ntfy|a2a")
	}
	kinds, err := normList(in.Kinds, kindRe, "kind")
	if err != nil {
		return nil, err
	}
	tags, err := normList(in.Tags, tagRe, "tag")
	if err != nil {
		return nil, err
	}
	q := strings.TrimSpace(scrub.Normalize(in.Q))
	if !doc.OneLine(q) {
		return nil, core.Bad("q must be one line")
	}
	if utf8.RuneCountInString(q) > maxQ {
		return nil, core.Bad(fmt.Sprintf("q must be <= %d chars", maxQ))
	}
	if q != "" {
		if _, ae := scrub.RejectOrMask(map[string]*string{"q": &q}); ae != nil {
			return nil, ae
		}
	}
	return &Hook{URL: strings.TrimSpace(in.URL), Fmt: in.Fmt, Kinds: kinds, Tags: tags, Q: q}, nil
}

// Create stores an outbound hook for the token's root; L0 roots may hold none, others <= MaxHooks
// live. Returns the hook and the one-time secret rendering (whsec_<base64(24)>).
func Create(ctx context.Context, q core.Q, id *core.Ident, in CreateIn) (*Hook, string, error) {
	h, err := in.norm()
	if err != nil {
		return nil, "", err
	}
	if core.Level(ctx, q, id.Root) < 1 {
		return nil, "", core.E(403, "level", "outbound hooks need L1")
	}
	var n int
	if err := q.QueryRow(ctx, `SELECT (SELECT count(*) FROM hooks WHERE root = r.id) FROM identities r WHERE r.id = $1 FOR UPDATE`, id.Root).Scan(&n); err != nil {
		return nil, "", err
	}
	if n >= MaxHooks {
		return nil, "", core.E(429, "quota", fmt.Sprintf("%d hooks live", MaxHooks))
	}
	secret := make([]byte, secretLen)
	rand.Read(secret)
	h.ID, h.Root, h.Secret = core.NewID('h'), id.Root, secret
	// Start the cursor at the current head so a new hook never back-fills history.
	if err := q.QueryRow(ctx, `INSERT INTO hooks (id, root, url, fmt, kinds, tags, q, secret, last_seq)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8, coalesce((SELECT max(seq) FROM events),0)) RETURNING last_seq, created`,
		h.ID, h.Root, h.URL, h.Fmt, h.Kinds, h.Tags, h.Q, h.Secret).Scan(&h.LastSeq, &h.Created); err != nil {
		return nil, "", err
	}
	if err := core.Audit(ctx, q, id.ID, "hook", h.ID, 0); err != nil {
		return nil, "", err
	}
	return h, "whsec_" + base64.StdEncoding.EncodeToString(secret), nil
}

// Get returns one of root's hooks; unknown, malformed and foreign ids are the same not found.
func Get(ctx context.Context, q core.Q, root, id string) (*Hook, error) {
	if !core.ValidIDPrefix(id, 'h') {
		return nil, core.ErrNotFound
	}
	h, err := scanHook(q.QueryRow(ctx, `SELECT `+hookCols+` FROM hooks WHERE id = $1 AND root = $2`, id, root))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return h, err
}

// List returns root's hooks, oldest first.
func List(ctx context.Context, q core.Q, root string) ([]Hook, error) {
	rows, err := q.Query(ctx, `SELECT `+hookCols+` FROM hooks WHERE root = $1 ORDER BY created, id`, root)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hook
	for rows.Next() {
		h, err := scanHook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

// Delete removes one of the token root's hooks (its out rows cascade).
func Delete(ctx context.Context, q core.Q, id *core.Ident, hid string) error {
	if !core.ValidIDPrefix(hid, 'h') {
		return core.ErrNotFound
	}
	tag, err := q.Exec(ctx, `DELETE FROM hooks WHERE id = $1 AND root = $2`, hid, id.Root)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return core.Audit(ctx, q, id.ID, "unhook", hid, 0)
}

// maskURL hides the path and query of a hook url outside the owner's own out rows (the url is never
// exported and only the out poll renders it in full).
func maskURL(u string) string {
	p, err := url.Parse(u)
	if err != nil || p.Host == "" {
		return "***"
	}
	s := p.Scheme + "://" + p.Host
	if p.Path != "" && p.Path != "/" || p.RawQuery != "" {
		s += "/…"
	}
	return s
}

func dash(xs []string) string {
	if len(xs) == 0 {
		return "-"
	}
	return strings.Join(xs, ",")
}

// --- HTTP handlers ---

func (h *handlers) hookCreate(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in CreateIn
	if err := core.Decode(w, r, createBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	var hk *Hook
	var secret string
	err = core.Tx(r.Context(), h.d.DB, func(tx pgx.Tx) error {
		hk, secret, err = Create(r.Context(), tx, id, in)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: "ok " + hk.ID, MaxAge: -1,
		Fields: []doc.F{{Name: "secret", Val: secret}, {Name: "fmt", Val: hk.Fmt}},
		Next:   []doc.Action{doc.GET("/v1/hook/"+hk.ID+"/out", ""), {Method: "DELETE", Path: "/v1/hook/" + hk.ID}}}
	doc.Reply(w, r, http.StatusCreated, d)
}

func (h *handlers) hookList(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	hks, err := List(r.Context(), h.d.DB, id.Root)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: fmt.Sprintf("hooks n=%d/%d", len(hks), MaxHooks), MaxAge: -1,
		Cols: []string{"id", "fmt", "url", "kinds", "tags", "q"}, Next: []doc.Action{doc.POST("/v1/hook", "")}}
	for _, x := range hks {
		qv := x.Q
		if qv == "" {
			qv = "-"
		}
		d.Rows = append(d.Rows, []string{x.ID, x.Fmt, maskURL(x.URL), dash(x.Kinds), dash(x.Tags), qv})
	}
	doc.Reply(w, r, 200, d)
}

func (h *handlers) hookDelete(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	err = core.Tx(r.Context(), h.d.DB, func(tx pgx.Tx) error { return Delete(r.Context(), tx, id, r.PathValue("id")) })
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, "ok", doc.GET("/v1/hook", ""))
}

// outRow is one pollable envelope with its ack cursor.
type outRow struct {
	ID       int64           `json:"id"`
	EvSeq    int64           `json:"ev_seq"`
	Envelope json.RawMessage `json:"envelope"`
}

// pollOut reads up to k unacked rows of a hook past the `after` cursor (out-row id).
func pollOut(ctx context.Context, q core.Q, hook string, after int64, k int) ([]outRow, error) {
	rows, err := q.Query(ctx, `SELECT id, ev_seq, envelope FROM hook_out
		WHERE hook = $1 AND id > $2 AND NOT acked ORDER BY id LIMIT $3`, hook, after, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []outRow
	for rows.Next() {
		var o outRow
		if err := rows.Scan(&o.ID, &o.EvSeq, &o.Envelope); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (h *handlers) out(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := h.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	hk, err := Get(r.Context(), h.d.DB, id.Root, r.PathValue("id"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	v := r.URL.Query()
	after, err := parseInt(v.Get("after"), 0, 0)
	if err != nil {
		doc.Fail(w, r, core.Bad("after must be an out-row id"))
		return
	}
	k, err := parseInt(v.Get("k"), int64(MaxOutK), int64(MaxOutK))
	if err != nil || k < 1 || k > int64(MaxOutK) {
		doc.Fail(w, r, core.Bad("k must be 1.."+strconv.Itoa(MaxOutK)))
		return
	}
	wait, err := parseInt(v.Get("wait"), 0, 0)
	if err != nil || wait < 0 || wait > int64(MaxWait) {
		doc.Fail(w, r, core.Bad("wait must be 0.."+strconv.Itoa(MaxWait)))
		return
	}
	format := strings.ToLower(strings.TrimSpace(v.Get("f")))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "curl" {
		doc.Fail(w, r, core.Bad("f must be json|curl"))
		return
	}
	out, err := h.pollWait(r.Context(), id, hk.ID, after, int(k), int(wait))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	last := after
	for _, o := range out {
		last = max(last, o.ID)
	}
	w.Header().Set("X-Next", fmt.Sprintf("POST /v1/hook/%s/ack {\"upto\":%d}", hk.ID, last))
	if format == "curl" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		var b strings.Builder
		for _, o := range out {
			var e Envelope
			if json.Unmarshal(o.Envelope, &e) == nil {
				b.WriteString(e.curlLine())
				b.WriteByte('\n')
			}
		}
		io.WriteString(w, b.String())
		return
	}
	core.JSON(w, 200, out)
}

// pollWait returns the rows, long-polling the hook's topic while none are ready (token holders
// only; capped by d.Waiters and the shed:longpoll rung, which answer immediately).
func (h *handlers) pollWait(ctx context.Context, id *core.Ident, hook string, after int64, k, wait int) ([]outRow, error) {
	out, err := pollOut(ctx, h.d.DB, hook, after, k)
	if err != nil || len(out) > 0 || wait == 0 {
		return out, err
	}
	if h.d.Shed(nil, "longpoll") {
		return out, nil
	}
	release, ok := h.d.Waiters.Acquire(id.Root, hook)
	if !ok {
		return out, nil
	}
	defer release()
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		c, cancel := h.d.Notify.Subscribe(outTopic(hook))
		out, err = pollOut(ctx, h.d.DB, hook, after, k)
		rem := time.Until(deadline)
		if err != nil || len(out) > 0 || rem <= 0 {
			cancel()
			return out, err
		}
		t := time.NewTimer(rem)
		select {
		case <-c:
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return out, nil
		}
		t.Stop()
		cancel()
	}
}

func (h *handlers) ack(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	hk, err := Get(r.Context(), h.d.DB, id.Root, r.PathValue("id"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		Upto int64 `json:"upto"`
	}
	if err := core.Decode(w, r, ackBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	tag, err := h.d.DB.Exec(r.Context(), `UPDATE hook_out SET acked = true WHERE hook = $1 AND id <= $2 AND NOT acked`, hk.ID, in.Upto)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, fmt.Sprintf("ok acked=%d", tag.RowsAffected()), doc.GET("/v1/hook/"+hk.ID+"/out", ""))
}

// parseInt parses an optional non-negative integer with a default and a hard clamp (clamp 0 = none).
func parseInt(s string, def, clamp int64) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, core.Bad("must be a non-negative integer")
	}
	if clamp > 0 && n > clamp {
		n = clamp
	}
	return n, nil
}
