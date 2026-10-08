package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// APIError is the wire error: status + short code + detail (+ optional server-built hint lines).
type APIError struct {
	Status int
	Code   string
	Msg    string
	Extra  []string // appended lines such as "expect: …" / "example: …" (never user text)
}

func (e *APIError) Error() string { return "err " + e.Code + " " + e.Msg }

// E builds an APIError.
func E(status int, code, msg string) *APIError {
	return &APIError{Status: status, Code: code, Msg: msg}
}

var (
	ErrAuth     = E(401, "auth", "token required")
	ErrBadToken = E(401, "auth", "invalid token")
	ErrBanned   = E(403, "auth", "banned")
	ErrForbid   = E(403, "auth", "forbidden")
	ErrNotFound = E(404, "notfound", "not found")
	ErrRate     = E(429, "rate", "slow down")
	ErrQuota    = E(429, "quota", "daily quota reached")
	ErrCredits  = E(402, "credits", "insufficient credits")
	ErrSize     = E(413, "size", "body too large")
	ErrDup      = E(409, "dup", "duplicate")
	ErrTaken    = E(409, "taken", "taken")
	ErrPow      = E(400, "pow", "bad proof of work")
	ErrGone     = E(410, "gone", "gone")
)

// Frozen is the 503 for a frozen kind/class; during maintenance mode it names the deadline (27.7).
func Frozen(what string) *APIError {
	if t, ok := MaintenanceUntil(); ok {
		return E(503, "frozen", "maintenance until="+t.UTC().Format(time.RFC3339))
	}
	return E(503, "frozen", what)
}
func Bad(msg string) *APIError { return E(400, "bad", msg) }

// WantJSON reports whether the client asked for JSON (Accept header or ?f=json).
func WantJSON(r *http.Request) bool {
	return r.URL.Query().Get("f") == "json" || strings.Contains(r.Header.Get("Accept"), "application/json")
}

// V2 reports whether the client opted into the v2 wire additions (?v=2 or X-CX-V: 2).
func V2(r *http.Request) bool {
	return r.Header.Get("X-CX-V") == "2" || r.URL.Query().Get("v") == "2"
}

// Err writes an error in the negotiated format.
func Err(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeErr(w, r, status, code, msg, nil)
}

func writeErr(w http.ResponseWriter, r *http.Request, status int, code, msg string, extra []string) {
	h := w.Header()
	if status == 401 && WWWAuthenticate != "" && h.Get("WWW-Authenticate") == "" {
		h.Set("WWW-Authenticate", WWWAuthenticate)
	}
	retry := 0
	if status == 429 || status == 503 {
		retry = retrySeconds(h, status)
		h.Set("Retry-After", strconv.Itoa(retry))
	}
	if WantJSON(r) {
		m := map[string]any{"err": code, "msg": msg}
		if retry > 0 {
			m["retry_s"] = retry
		}
		if len(extra) > 0 {
			m["hint"] = extra
		}
		if V2(r) {
			m["next"] = nextActions(status, retry)
		}
		JSON(w, status, m)
		return
	}
	h.Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	var b strings.Builder
	fmt.Fprintf(&b, "err %s %s\n", code, msg)
	for _, l := range extra {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	if V2(r) {
		b.WriteString("next: " + strings.Join(nextActions(status, retry), " | ") + "\n")
	}
	io.WriteString(w, b.String())
}

// retrySeconds honours a Retry-After the handler already set, else maintenance_until / 120 s for
// 503 and 5 s for 429.
func retrySeconds(h http.Header, status int) int {
	if v, err := strconv.Atoi(h.Get("Retry-After")); err == nil && v > 0 {
		return v
	}
	if status == 503 {
		if t, ok := MaintenanceUntil(); ok {
			if s := int(time.Until(t).Seconds()) + 1; s > 0 {
				return s
			}
		}
		return 120
	}
	return 5
}

func nextActions(status, retry int) []string {
	switch {
	case status == 429 || status == 503:
		return []string{fmt.Sprintf("retry retry_s=%d", retry), "GET /status"}
	case status == 401:
		return []string{"POST /v1/challenge", "GET /help"}
	}
	return []string{"GET /help"}
}

// Fail maps an error to the wire: *APIError as-is, MaxBytes overflow to size, anything else to 500.
func Fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *APIError
	var mb *http.MaxBytesError
	switch {
	case errors.As(err, &ae):
		writeErr(w, r, ae.Status, ae.Code, ae.Msg, ae.Extra)
	case errors.As(err, &mb):
		Err(w, r, 413, "size", "body too large")
	default:
		slog.Error("internal error", "m", r.Method, "p", r.URL.Path, "err", err)
		Err(w, r, 500, "internal", "internal error")
	}
}

// Text writes plain text (adds trailing newline) or, when JSON is wanted and j != nil, j.
func Text(w http.ResponseWriter, r *http.Request, status int, text string, j any) {
	if j != nil && WantJSON(r) {
		JSON(w, status, j)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	io.WriteString(w, text)
}

// OK is Text with status 200.
func OK(w http.ResponseWriter, r *http.Request, text string, j any) { Text(w, r, 200, text, j) }

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

// MaxBytes caps the request body; use before any read.
func MaxBytes(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

// Decode reads a request body (≤ max bytes) into v, rejecting unknown fields. JSON is decoded
// directly; text/plain (field grammar), form bodies and query parameters on POST/PATCH go through
// BodyParserFn (27.2), which turns them into JSON for the same struct; 415 while it is unset.
// Empty body → zero v. Errors carry the route's expect:/example: lines when a schema is registered.
func Decode(w http.ResponseWriter, r *http.Request, max int64, v any) error {
	body, err := ReadAll(w, r, max)
	if err != nil {
		return withExpect(r, err)
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	trim := bytes.TrimSpace(body)
	isJSON := ct == "application/json" || strings.HasSuffix(ct, "+json") ||
		(ct == "" && len(trim) > 0 && (trim[0] == '{' || trim[0] == '['))
	if len(trim) == 0 {
		if isJSON || BodyParserFn == nil || !(r.Method == http.MethodPost || r.Method == http.MethodPatch) || r.URL.RawQuery == "" {
			return nil
		}
		isJSON = false
	}
	if !isJSON {
		if ct == "" {
			ct = "text/plain"
		}
		if BodyParserFn == nil {
			return withExpect(r, E(415, "bad", "content type "+ct))
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		raw, err := BodyParserFn(r, schemaFor(r))
		if err != nil {
			return withExpect(r, err)
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			return nil
		}
		body = raw
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return withExpect(r, Bad(fmt.Sprintf("json at byte %d near %q", se.Offset, window(body, int(se.Offset)))))
		}
		return withExpect(r, Bad("json: "+trimErr(err)))
	}
	if dec.More() {
		return withExpect(r, Bad("json: trailing data"))
	}
	return nil
}

var tokenInWindow = regexp.MustCompile(`cx_[A-Za-z0-9_-]{6,}`)

// window is the scrubbed 20-char context around a syntax error offset.
func window(body []byte, off int) string {
	lo, hi := off-10, off+10
	if lo < 0 {
		lo = 0
	}
	if hi > len(body) {
		hi = len(body)
	}
	s := strings.ToValidUTF8(string(body[lo:hi]), "")
	s = tokenInWindow.ReplaceAllString(s, "cx_…")
	return cleanLine(s, 20)
}

// ReadAll reads the whole body capped at max, mapping overflow to ErrSize.
func ReadAll(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	MaxBytes(w, r, max)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			return nil, ErrSize
		}
		return nil, Bad("read: " + trimErr(err))
	}
	return b, nil
}

func trimErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// schemaIdx maps "METHOD /path/{x}" to the request-body JSON schema of a registered OpenAPI fragment.
var schemaIdx sync.Map

func indexSchemas(frag json.RawMessage) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(frag, &doc) != nil {
		return
	}
	for p, ops := range doc.Paths {
		for m, op := range ops {
			var o struct {
				RequestBody struct {
					Content map[string]struct {
						Schema json.RawMessage `json:"schema"`
					} `json:"content"`
				} `json:"requestBody"`
			}
			if json.Unmarshal(op, &o) != nil {
				continue
			}
			for ct, c := range o.RequestBody.Content {
				if strings.Contains(ct, "json") && len(c.Schema) > 0 {
					schemaIdx.Store(strings.ToUpper(m)+" "+p, c.Schema)
				}
			}
		}
	}
}

// schemaFor finds the schema of the route that is handling r (r.Pattern, else method + path).
func schemaFor(r *http.Request) json.RawMessage {
	pat := r.Pattern
	if pat == "" {
		pat = r.URL.Path
	}
	if !strings.Contains(pat, " ") {
		pat = r.Method + " " + pat
	}
	pat = strings.TrimSuffix(pat, "/{$}")
	pat = strings.TrimSuffix(pat, "{$}")
	pat = strings.ReplaceAll(pat, "...}", "}")
	if v, ok := schemaIdx.Load(pat); ok {
		return v.(json.RawMessage)
	}
	return nil
}

// SchemaFor is the exported lookup for doc/pages: the request-body schema registered for a pattern.
func SchemaFor(pattern string) json.RawMessage {
	if v, ok := schemaIdx.Load(pattern); ok {
		return v.(json.RawMessage)
	}
	return nil
}

// withExpect appends expect:/example: lines to a 400/413/415/422 APIError when the route has a schema.
func withExpect(r *http.Request, err error) error {
	var ae *APIError
	if !errors.As(err, &ae) || len(ae.Extra) > 0 {
		return err
	}
	switch ae.Status {
	case 400, 413, 415, 422:
	default:
		return err
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	lines := Expect(schemaFor(r), ct)
	if len(lines) == 0 {
		return err
	}
	cp := *ae
	cp.Extra = lines
	return &cp
}

type schemaProp struct {
	name, typ string
	max       int
}

// Expect renders "expect: title<=160* symptom<=1000 (* required)" and one minimal "example:" body
// in the given content type (json by default) from a JSON schema; nil when the schema has no fields.
func Expect(schema json.RawMessage, ct string) []string {
	if len(schema) == 0 {
		return nil
	}
	props, required := schemaProps(schema)
	if len(props) == 0 {
		return nil
	}
	var parts []string
	for _, p := range props {
		s := p.name
		if p.typ == "array" {
			s += "[]"
		}
		if p.max > 0 {
			s += "<=" + strconv.Itoa(p.max)
		}
		if required[p.name] {
			s += "*"
		}
		parts = append(parts, s)
	}
	line := "expect: " + strings.Join(parts, " ")
	if len(required) > 0 {
		line += " (* required)"
	}
	var ex []schemaProp
	for _, p := range props {
		if required[p.name] {
			ex = append(ex, p)
		}
	}
	if len(ex) == 0 {
		ex = props[:1]
	}
	return []string{line, "example: " + example(ex, ct)}
}

func example(props []schemaProp, ct string) string {
	val := func(p schemaProp, quote bool) string {
		switch p.typ {
		case "integer", "number":
			return "1"
		case "boolean":
			return "true"
		case "array":
			if quote {
				return `["…"]`
			}
			return "…"
		}
		if quote {
			return `"…"`
		}
		return "…"
	}
	var parts []string
	switch ct {
	case "text/plain":
		for _, p := range props {
			parts = append(parts, p.name+": "+val(p, false))
		}
		return strings.Join(parts, `\n`)
	case "application/x-www-form-urlencoded", "multipart/form-data":
		for _, p := range props {
			parts = append(parts, p.name+"="+val(p, false))
		}
		return strings.Join(parts, "&")
	}
	for _, p := range props {
		parts = append(parts, strconv.Quote(p.name)+":"+val(p, true))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// schemaProps lists the properties of an object schema in document order, plus the required set.
func schemaProps(schema json.RawMessage) ([]schemaProp, map[string]bool) {
	var top struct {
		Properties json.RawMessage `json:"properties"`
		Required   []string        `json:"required"`
	}
	if json.Unmarshal(schema, &top) != nil || len(top.Properties) == 0 {
		return nil, nil
	}
	req := map[string]bool{}
	for _, r := range top.Required {
		req[r] = true
	}
	dec := json.NewDecoder(bytes.NewReader(top.Properties))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, nil
	}
	var out []schemaProp
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			break
		}
		name, _ := t.(string)
		var p struct {
			Type      string `json:"type"`
			MaxLength int    `json:"maxLength"`
			Maximum   int    `json:"maximum"`
			MaxItems  int    `json:"maxItems"`
		}
		if err := dec.Decode(&p); err != nil {
			break
		}
		max := p.MaxLength
		if max == 0 {
			max = p.Maximum
		}
		if max == 0 {
			max = p.MaxItems
		}
		out = append(out, schemaProp{name, p.Type, max})
		if len(out) >= 32 {
			break
		}
	}
	return out, req
}
