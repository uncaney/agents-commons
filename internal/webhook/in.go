package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/swarm"
)

var (
	inKinds = map[string]bool{"github": true, "gitlab": true, "generic": true}
	inSinks = map[string]bool{"ps": true, "mb": true, "wq": true}
)

// InHook is one inbound sink row.
type InHook struct {
	ID, Root, Kind, Sink, Target, Filter string
	SecretHash                           []byte
	N                                    int64
	Bad                                  int
	Disabled                             bool
	Created                              time.Time
	LastAt                               *time.Time
}

const inCols = `id, root, secret_hash, kind, sink, target, filter, n, bad, disabled, created, last_at`

func scanIn(row pgx.Row) (*InHook, error) {
	var h InHook
	if err := row.Scan(&h.ID, &h.Root, &h.SecretHash, &h.Kind, &h.Sink, &h.Target, &h.Filter,
		&h.N, &h.Bad, &h.Disabled, &h.Created, &h.LastAt); err != nil {
		return nil, err
	}
	return &h, nil
}

// InCreateIn is the POST /v1/inhook / op inhook body.
type InCreateIn struct {
	Kind   string `json:"kind"`
	Sink   string `json:"sink"`
	Target string `json:"target"`
	Filter string `json:"filter"`
}

// InCreate registers an inbound sink for the token's root (L1+, <= MaxInHooks live). Returns the
// hook and the one-time secret (base64url of 32 bytes); the secret itself is kept server-side as
// the HMAC key for signature verification.
func InCreate(ctx context.Context, q core.Q, id *core.Ident, in InCreateIn) (*InHook, string, error) {
	kind := strings.ToLower(strings.TrimSpace(in.Kind))
	sink := strings.ToLower(strings.TrimSpace(in.Sink))
	if !inKinds[kind] {
		return nil, "", core.Bad("kind must be github|gitlab|generic")
	}
	if !inSinks[sink] {
		return nil, "", core.Bad("sink must be ps|mb|wq")
	}
	target := strings.TrimSpace(in.Target)
	if sink == "ps" || sink == "wq" {
		if _, err := swarm.ParseName(target, id.Root); err != nil {
			return nil, "", core.Bad("target must be a topic/queue name: " + target)
		}
	}
	filter := strings.TrimSpace(scrub.Normalize(in.Filter))
	if !doc.OneLine(filter) || len(filter) > 120 {
		return nil, "", core.Bad("filter must be one line <= 120 bytes")
	}
	if core.Level(ctx, q, id.Root) < 1 {
		return nil, "", core.E(403, "level", "inbound hooks need L1")
	}
	var n int
	if err := q.QueryRow(ctx, `SELECT (SELECT count(*) FROM in_hooks WHERE root = r.id) FROM identities r WHERE r.id = $1 FOR UPDATE`, id.Root).Scan(&n); err != nil {
		return nil, "", err
	}
	if n >= MaxInHooks {
		return nil, "", core.E(429, "quota", fmt.Sprintf("%d inbound hooks live", MaxInHooks))
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	h := &InHook{ID: core.NewID('i'), Root: id.Root, Kind: kind, Sink: sink, Target: target, Filter: filter, SecretHash: secret}
	if err := q.QueryRow(ctx, `INSERT INTO in_hooks (id, root, secret_hash, kind, sink, target, filter)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created`, h.ID, h.Root, h.SecretHash, h.Kind, h.Sink, h.Target, h.Filter).Scan(&h.Created); err != nil {
		return nil, "", err
	}
	if err := core.Audit(ctx, q, id.ID, "inhook", h.ID, 0); err != nil {
		return nil, "", err
	}
	return h, base64.RawURLEncoding.EncodeToString(secret), nil
}

// InGet returns one of root's inbound hooks.
func InGet(ctx context.Context, q core.Q, root, id string) (*InHook, error) {
	if !core.ValidIDPrefix(id, 'i') {
		return nil, core.ErrNotFound
	}
	h, err := scanIn(q.QueryRow(ctx, `SELECT `+inCols+` FROM in_hooks WHERE id = $1 AND root = $2`, id, root))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return h, err
}

// InList returns root's inbound hooks, oldest first.
func InList(ctx context.Context, q core.Q, root string) ([]InHook, error) {
	rows, err := q.Query(ctx, `SELECT `+inCols+` FROM in_hooks WHERE root = $1 ORDER BY created, id`, root)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InHook
	for rows.Next() {
		h, err := scanIn(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}

// InDelete removes one of the token root's inbound hooks.
func InDelete(ctx context.Context, q core.Q, id *core.Ident, hid string) error {
	if !core.ValidIDPrefix(hid, 'i') {
		return core.ErrNotFound
	}
	tag, err := q.Exec(ctx, `DELETE FROM in_hooks WHERE id = $1 AND root = $2`, hid, id.Root)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return core.Audit(ctx, q, id.ID, "uninhook", hid, 0)
}

// --- HTTP handlers (management) ---

func (h *handlers) inCreate(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in InCreateIn
	if err := core.Decode(w, r, createBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	var hk *InHook
	var secret string
	err = core.Tx(r.Context(), h.d.DB, func(tx pgx.Tx) error {
		hk, secret, err = InCreate(r.Context(), tx, id, in)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: "ok " + hk.ID, MaxAge: -1,
		Fields: []doc.F{{Name: "url", Val: "/in/" + hk.ID}, {Name: "secret", Val: secret}, {Name: "kind", Val: hk.Kind}},
		Next:   []doc.Action{{Method: "DELETE", Path: "/v1/inhook/" + hk.ID}}}
	doc.Reply(w, r, http.StatusCreated, d)
}

func (h *handlers) inList(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	hks, err := InList(r.Context(), h.d.DB, id.Root)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: fmt.Sprintf("inhooks n=%d/%d", len(hks), MaxInHooks), MaxAge: -1,
		Cols: []string{"id", "kind", "sink", "target", "n", "bad", "disabled"}, Next: []doc.Action{doc.POST("/v1/inhook", "")}}
	for _, x := range hks {
		d.Rows = append(d.Rows, []string{x.ID, x.Kind, x.Sink + ":" + x.Target, "", fmt.Sprintf("%d", x.N), fmt.Sprintf("%d", x.Bad), fmt.Sprintf("%v", x.Disabled)})
	}
	doc.Reply(w, r, 200, d)
}

func (h *handlers) inDelete(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	err = core.Tx(r.Context(), h.d.DB, func(tx pgx.Tx) error { return InDelete(r.Context(), tx, id, r.PathValue("id")) })
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, "ok", doc.GET("/v1/inhook", ""))
}

// --- Inbound delivery (POST /in/{id}) ---

// inbound receives a provider webhook: verify the signature in constant time (failure is the same
// 404 as an unknown id), dedupe by delivery id, enforce the rate caps, extract one scrubbed line
// and drop it into the sink. Bodies are never stored, payload urls never fetched; 204 with no body.
func (h *handlers) inbound(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id := r.PathValue("id")
	// MaxBytesReader caps the body before any work; an oversized body is a plain bad request.
	r.Body = http.MaxBytesReader(w, r.Body, InMaxBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		core.Err(w, r, http.StatusRequestEntityTooLarge, "size", "body too large")
		return
	}
	// Unauthenticated path: the signature authenticates, so look the hook up by id alone.
	hk, err := h.loadIn(r.Context(), id)
	if err != nil || hk == nil || hk.Disabled {
		notFound(w, r)
		return
	}
	if !h.verify(r.Context(), hk, r, body) {
		notFound(w, r)
		return
	}
	// Replay guard: a repeated delivery id is accepted but not re-delivered.
	if dkey := deliveryID(r); dkey != "" {
		tag, err := h.d.DB.Exec(r.Context(), `INSERT INTO in_deliveries (id, delivery_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, hk.ID, cut(dkey, 200))
		if err != nil {
			core.Err(w, r, 500, "db", "unavailable")
			return
		}
		if tag.RowsAffected() == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	// Rate caps: over-rate deliveries are dropped silently (2xx so the provider does not retry-storm).
	if over, err := h.overRate(r.Context(), hk); err != nil {
		core.Err(w, r, 500, "db", "unavailable")
		return
	} else if over {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	line := extract(hk.Kind, r.Header.Get(eventHeader(hk.Kind)), body)
	line, ok := clean(line)
	if !ok || !deliverable(hk, line) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h.deliver(r.Context(), hk, line)
	w.WriteHeader(http.StatusNoContent)
}

// loadIn looks an inbound hook up by id alone (no root scope), for the unauthenticated /in path.
func (h *handlers) loadIn(ctx context.Context, id string) (*InHook, error) {
	if !core.ValidIDPrefix(id, 'i') {
		return nil, core.ErrNotFound
	}
	hk, err := scanIn(h.d.DB.QueryRow(ctx, `SELECT `+inCols+` FROM in_hooks WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return hk, err
}

// notFound answers the single 404 used for both an unknown id and a bad signature.
func notFound(w http.ResponseWriter, r *http.Request) {
	core.Err(w, r, http.StatusNotFound, "notfound", "no such hook")
}

// verify checks the provider signature in constant time and maintains the consecutive-bad counter:
// a success resets it, a failure increments it and disables the hook at BadDisable.
func (h *handlers) verify(ctx context.Context, hk *InHook, r *http.Request, body []byte) bool {
	ok := false
	switch hk.Kind {
	case "github":
		want := "sha256=" + hex.EncodeToString(hmacSum(hk.SecretHash, body))
		ok = ctEqual(r.Header.Get("X-Hub-Signature-256"), want)
	case "gitlab":
		ok = ctEqual(r.Header.Get("X-Gitlab-Token"), string(hk.SecretHash))
	default: // generic
		want := "sha256=" + hex.EncodeToString(hmacSum(hk.SecretHash, body))
		ok = ctEqual(r.Header.Get("X-Hook-Signature"), want)
	}
	if ok {
		if hk.Bad != 0 {
			h.d.DB.Exec(ctx, `UPDATE in_hooks SET bad = 0 WHERE id = $1`, hk.ID)
		}
		return true
	}
	h.d.DB.Exec(ctx, `UPDATE in_hooks SET bad = bad + 1, disabled = (bad + 1 >= $2) WHERE id = $1`, hk.ID, BadDisable)
	return false
}

func hmacSum(key, body []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return mac.Sum(nil)
}

// ctEqual is a length-independent constant-time string compare.
func ctEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// deliveryID is the provider's unique delivery id (replay guard), empty when absent.
func deliveryID(r *http.Request) string {
	for _, k := range []string{"X-GitHub-Delivery", "X-Gitlab-Event-UUID", "X-Hook-Delivery", "X-Request-Id"} {
		if v := strings.TrimSpace(r.Header.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

func eventHeader(kind string) string {
	switch kind {
	case "github":
		return "X-GitHub-Event"
	case "gitlab":
		return "X-Gitlab-Event"
	default:
		return "X-Hook-Event"
	}
}

// overRate reports whether this delivery exceeds the per-hook hourly or per-root daily caps.
func (h *handlers) overRate(ctx context.Context, hk *InHook) (bool, error) {
	hr, err := bumpCounter(ctx, h.d.DB, "inhook:"+hk.ID, hourKind())
	if err != nil {
		return false, err
	}
	if hr > int64(InPerHour) {
		return true, nil
	}
	day, err := bumpCounter(ctx, h.d.DB, hk.Root, "inhook_day")
	if err != nil {
		return false, err
	}
	return day > int64(InPerDay), nil
}

// clean runs the ingress scrub + lexicon on an extracted line: a tier-1 secret or a lexicon score
// >= LexDrop drops the line (dropped, not quarantined: inbound webhooks are machine-to-machine).
// Returns the (possibly tier-2 masked) line and whether it survived.
func clean(line string) (string, bool) {
	line = strings.TrimSpace(scrub.Normalize(line))
	if line == "" {
		return "", false
	}
	if _, ae := scrub.RejectOrMask(map[string]*string{"line": &line}); ae != nil {
		return "", false
	}
	if score, _, _ := scrub.Flags(line); score >= LexDrop {
		return "", false
	}
	return doc.SafeLine(line), line != ""
}

// deliverable applies the optional case-insensitive substring filter to the extracted line.
func deliverable(hk *InHook, line string) bool {
	if hk.Filter == "" {
		return true
	}
	return strings.Contains(strings.ToLower(line), strings.ToLower(hk.Filter))
}

// deliver drops a scrubbed line into the hook's sink as the owner root, advances the counters, and
// records last_at. Sink errors are logged, not surfaced (the provider must still see a 2xx).
func (h *handlers) deliver(ctx context.Context, hk *InHook, line string) {
	key := "hook:" + hk.ID + ":" + hashLine(line)
	err := core.Tx(ctx, h.d.DB, func(tx pgx.Tx) error {
		switch hk.Sink {
		case "ps":
			_, e := swarm.Publish(ctx, tx, hk.Target, hk.Root, hk.Root, line, key)
			return e
		case "wq":
			_, e := swarm.Push(ctx, tx, hk.Target, line, key)
			return e
		case "mb":
			b, e := mail.Resolve(ctx, tx, nil, hk.Root)
			if e != nil {
				return e
			}
			_, e = mail.Deliver(ctx, tx, nil, b, &mail.Msg{Subject: "hook " + hk.ID, Re: "hook", Text: line})
			return e
		}
		return nil
	})
	if err != nil {
		h.d.Log.Warn("webhook inbound deliver", "inhook", hk.ID, "err", err)
		return
	}
	h.d.DB.Exec(ctx, `UPDATE in_hooks SET n = n + 1, last_at = now() WHERE id = $1`, hk.ID)
}

// bumpCounter adds one to today's counter and returns the new value.
func bumpCounter(ctx context.Context, q core.Q, scope, kind string) (int64, error) {
	var n int64
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1,$2,current_date,1)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + 1 RETURNING n`, scope, kind).Scan(&n)
	return n, err
}

// hourKind keys the per-hour counter by the current UTC hour.
func hourKind() string { return "h" + time.Now().UTC().Format("2006010215") }

// hashLine is a short idempotency key component for a delivered line.
func hashLine(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// jsonField reads a dotted path of string/number/bool from a JSON body (best effort, "" on miss).
func jsonField(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

// sub decodes a nested object field.
func sub(m map[string]json.RawMessage, key string) map[string]json.RawMessage {
	raw, ok := m[key]
	if !ok {
		return nil
	}
	var out map[string]json.RawMessage
	json.Unmarshal(raw, &out)
	return out
}

// extract maps a provider event + body to one short line (<= InLineMax, injection-safe). Unknown
// shapes fall back to "<event> <short-json-digest>".
func extract(kind, event string, body []byte) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		m = map[string]json.RawMessage{}
	}
	event = strings.ToLower(strings.TrimSpace(event))
	var line string
	switch {
	case kind == "github" && event == "release" && jsonField(m, "action") == "published":
		rel := sub(m, "release")
		line = "release published " + jsonField(sub(m, "repository"), "full_name") + " " +
			jsonField(rel, "tag_name") + " " + jsonField(rel, "html_url")
	case kind == "github" && event == "push":
		line = "push " + jsonField(m, "ref") + " " + short7(jsonField(m, "after")) + " " + countField(m, "commits")
	case kind == "github" && event == "workflow_run":
		wr := sub(m, "workflow_run")
		line = "workflow_run " + jsonField(wr, "conclusion") + " " + jsonField(wr, "name")
	case kind == "github" && event == "issues" && jsonField(m, "action") == "opened":
		is := sub(m, "issue")
		line = "issues opened #" + jsonField(is, "number") + " " + jsonField(is, "title")
	default:
		ev := event
		if ev == "" {
			ev = "event"
		}
		line = ev + " " + genericText(m)
	}
	line = doc.SafeLine(strings.TrimSpace(line))
	if len(line) > InLineMax {
		line = line[:InLineMax]
	}
	return strings.TrimSpace(line)
}

// genericText picks a human-ish field from an arbitrary payload for the generic extractor.
func genericText(m map[string]json.RawMessage) string {
	for _, k := range []string{"text", "message", "title", "action", "event"} {
		if v := jsonField(m, k); v != "" {
			return v
		}
	}
	return ""
}

func short7(s string) string {
	if len(s) > 7 {
		return s[:7]
	}
	return s
}

func countField(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	if !ok {
		return "0"
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		return fmt.Sprintf("%d", len(arr))
	}
	return "0"
}
