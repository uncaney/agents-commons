// Package mcpsse is the legacy HTTP+SSE MCP transport shim (SPEC-v2 27.9, P123). It bridges the
// older two-channel MCP transport onto the single stateless /mcp JSON-RPC handler:
//
//	GET /sse        -> text/event-stream. The first event is `endpoint` carrying
//	                   /messages?s=<HMAC-signed session id> (stateless: no row is stored). A
//	                   `: keepalive` comment is sent every 15 s and the stream is closed hard at
//	                   85 s with a `retry: 1000` line so the client reconnects.
//	POST /messages?s=  -> validates the HMAC session id and calls the in-process /mcp handler
//	                   (mcp.Handler) with the same Authorization header and the same single tool.
//	                   The JSON-RPC response is returned inline (200) and, when a stream for s is
//	                   open on this instance, also pushed to it as a `message` event. d.Notify
//	                   ("sse:<s>") carries the cross-instance wake over the pg NOTIFY bridge.
//
// No new ops, no new tool, no new auth: everything funnels through /mcp. Streams count against
// d.Waiters (4 per IP group) exactly like any other long-poll. The routes are registered as legacy
// in /openapi.json.
package mcpsse

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/mcp"
)

// Tunable stream timings (vars so tests can shrink them). Defaults per SPEC-v2 27.9.
var (
	keepaliveInterval = 15 * time.Second
	maxStreamDur      = 85 * time.Second
	// retryMillis is the SSE `retry:` the hard close advertises.
	retryMillis = 1000
)

// sessionDomain binds a session id's HMAC to this transport and key version (v1).
const sessionDomain = "mcpsse-v1|"

type server struct {
	d   *core.Deps
	h   http.Handler // the in-process /mcp JSON-RPC handler (mcp.Handler)
	hub *hub
}

// Register mounts GET /sse and POST /messages, registers their scopes ("*": the forwarded /mcp
// handler checks auth and per-op scope itself) and documents them as legacy in /openapi.json.
// cmd/gateway and internal/mcp are untouched; this shim only consumes mcp.Handler.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &server{d: d, h: mcp.Handler(d), hub: newHub()}
	routes := []struct {
		pat string
		h   http.HandlerFunc
	}{
		{"GET /sse", s.hSSE},
		{"/sse", methodNotAllowed("GET")},
		{"POST /messages", s.hMessages},
		{"/messages", methodNotAllowed("POST")},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, "*")
	}
	d.RegisterOpenAPI(json.RawMessage(openAPIFragment))
}

func methodNotAllowed(allow string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Allow", allow)
		core.Err(w, r, http.StatusMethodNotAllowed, "bad", allow+" only")
	}
}

// --- GET /sse -----------------------------------------------------------------------------------

// hSSE opens the event stream. It takes a d.Waiters slot (anonymous: 4 per IP group; a token:
// 8 per root) so streams are bounded like any long-poll, mints a stateless signed session id,
// emits the `endpoint` event, then keeps the stream alive with keepalive comments until the hard
// 85 s cap, closing with `retry: 1000`.
func (s *server) hSSE(w http.ResponseWriter, r *http.Request) {
	ident, authErr := s.d.AuthOpt(r)
	if authErr != nil {
		core.Fail(w, r, authErr)
		return
	}
	root := ""
	if ident != nil {
		root = ident.Root
	}
	release, ok := s.d.Waiters.Acquire(root, s.d.IPGroup(r))
	if !ok {
		w.Header().Set("Retry-After", "5")
		core.Err(w, r, http.StatusTooManyRequests, "rate", "too many open streams; retry")
		return
	}
	defer release()

	sess := mintSession(s.d.Cfg.ServerSecret)
	sub, remove := s.hub.add(sess)
	defer remove()
	c, cancel := s.d.Notify.Subscribe("sse:" + sess)
	defer func() { cancel() }()

	es := newSSE(w)
	es.event("endpoint", "/messages?s="+sess)

	ka := time.NewTicker(keepaliveInterval)
	defer ka.Stop()
	hard := time.NewTimer(maxStreamDur)
	defer hard.Stop()
	ctx := r.Context()
	for {
		select {
		case data := <-sub.ch:
			es.event("message", string(data))
		case <-ka.C:
			es.comment("keepalive")
		case <-c:
			// Cross-instance wake over the pg NOTIFY bridge. The wake-only Notifier carries no
			// payload: the response already went inline to the POSTer, and same-instance delivery
			// runs through the hub above. Re-subscribe and keep the stream open.
			cancel()
			c, cancel = s.d.Notify.Subscribe("sse:" + sess)
		case <-hard.C:
			es.retry(retryMillis)
			return
		case <-ctx.Done():
			return
		}
	}
}

// --- POST /messages?s= --------------------------------------------------------------------------

// hMessages validates the signed session id, forwards the request to the in-process /mcp handler
// (same body, same Authorization header, same client-IP headers so quotas and auth are identical),
// returns the JSON-RPC response inline, and, when a stream for s is open here, also pushes it as a
// `message` event (plus a NOTIFY wake for a stream pinned to another instance).
func (s *server) hMessages(w http.ResponseWriter, r *http.Request) {
	sess := r.URL.Query().Get("s")
	if !validSession(s.d.Cfg.ServerSecret, sess) {
		core.Err(w, r, http.StatusForbidden, "bad", "invalid or missing session (GET /sse first)")
		return
	}
	// Forward to /mcp unchanged but for the path; mcp.Handler reads the body (with its own cap),
	// resolves the bearer token and charges the limiter exactly as a direct POST /mcp would.
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/mcp"
	r2.URL.RawQuery = ""
	r2.RequestURI = ""
	rec := &recorder{}
	s.h.ServeHTTP(rec, r2)

	body := rec.buf.Bytes()
	ct := rec.header.Get("Content-Type")
	if ct == "" {
		ct = "application/json"
	}
	code := rec.code
	if code == 0 {
		code = http.StatusOK
	}
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(code)
	w.Write(body)

	// Mirror the response onto any open stream for this session. A pure notification (/mcp replies
	// 202 with an empty body) has nothing to push.
	if code == http.StatusOK && len(bytes.TrimSpace(body)) > 0 {
		s.hub.push(sess, append([]byte(nil), bytes.TrimRight(body, "\n")...))
		s.d.Notify.Wake("sse:" + sess)
	}
}

// --- stateless session ids ----------------------------------------------------------------------

// mintSession returns a fresh stateless session id: a random nonce and an HMAC tag over it, so a
// POST /messages?s= can be verified without any stored row.
func mintSession(secret []byte) string {
	var nonce [16]byte
	rand.Read(nonce[:])
	n := base64.RawURLEncoding.EncodeToString(nonce[:])
	return n + "." + sign(secret, n)
}

// sign is the HMAC tag (first 16 bytes) over the nonce, base64url-encoded.
func sign(secret []byte, nonce string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(sessionDomain + nonce))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:16])
}

// validSession reports whether s is a nonce.tag pair this server minted (constant-time compare).
func validSession(secret []byte, s string) bool {
	nonce, tag, ok := strings.Cut(s, ".")
	if !ok || nonce == "" || tag == "" || len(s) > 128 {
		return false
	}
	want := sign(secret, nonce)
	return subtle.ConstantTimeCompare([]byte(want), []byte(tag)) == 1
}

// --- in-process push hub (same-instance delivery) -----------------------------------------------

type subscriber struct{ ch chan []byte }

// hub maps a session id to the open streams for it on this instance.
type hub struct {
	mu   sync.Mutex
	subs map[string]map[*subscriber]struct{}
}

func newHub() *hub { return &hub{subs: map[string]map[*subscriber]struct{}{}} }

// add registers a stream for sess and returns it with a remove func the caller must defer.
func (h *hub) add(sess string) (*subscriber, func()) {
	sub := &subscriber{ch: make(chan []byte, 16)}
	h.mu.Lock()
	m := h.subs[sess]
	if m == nil {
		m = map[*subscriber]struct{}{}
		h.subs[sess] = m
	}
	m[sub] = struct{}{}
	h.mu.Unlock()
	return sub, func() {
		h.mu.Lock()
		if m := h.subs[sess]; m != nil {
			delete(m, sub)
			if len(m) == 0 {
				delete(h.subs, sess)
			}
		}
		h.mu.Unlock()
	}
}

// push delivers data to every open stream for sess (non-blocking; a full buffer drops the frame).
// It reports whether at least one stream was open here.
func (h *hub) push(sess string, data []byte) bool {
	h.mu.Lock()
	m := h.subs[sess]
	subs := make([]*subscriber, 0, len(m))
	for sub := range m {
		subs = append(subs, sub)
	}
	h.mu.Unlock()
	for _, sub := range subs {
		select {
		case sub.ch <- data:
		default:
		}
	}
	return len(subs) > 0
}

// --- SSE writer ---------------------------------------------------------------------------------

type sse struct {
	w http.ResponseWriter
	f http.Flusher
}

func newSSE(w http.ResponseWriter) *sse {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	f, _ := w.(http.Flusher)
	e := &sse{w, f}
	e.flush()
	return e
}

func (e *sse) flush() {
	if e.f != nil {
		e.f.Flush()
	}
}

// event writes a named SSE event. data is single-line JSON (or a path); embedded newlines are
// folded into continuation data: lines so the frame stays well-formed.
func (e *sse) event(name, data string) {
	var b bytes.Buffer
	b.WriteString("event: " + name + "\n")
	for _, line := range strings.Split(data, "\n") {
		b.WriteString("data: " + line + "\n")
	}
	b.WriteString("\n")
	e.w.Write(b.Bytes())
	e.flush()
}

func (e *sse) comment(s string) {
	e.w.Write([]byte(": " + s + "\n\n"))
	e.flush()
}

func (e *sse) retry(ms int) {
	e.w.Write([]byte("retry: " + strconv.Itoa(ms) + "\n\n"))
	e.flush()
}

// --- in-process response recorder ---------------------------------------------------------------

// recorder captures the /mcp handler's response so it can be both returned inline and pushed.
type recorder struct {
	header http.Header
	code   int
	buf    bytes.Buffer
}

func (rec *recorder) Header() http.Header {
	if rec.header == nil {
		rec.header = http.Header{}
	}
	return rec.header
}

func (rec *recorder) WriteHeader(code int) {
	if rec.code == 0 {
		rec.code = code
	}
}

func (rec *recorder) Write(b []byte) (int, error) {
	if rec.code == 0 {
		rec.code = http.StatusOK
	}
	return rec.buf.Write(b)
}

// openAPIFragment documents the two legacy routes for the merged /openapi.json.
const openAPIFragment = `{"paths":{
"/sse":{"get":{"tags":["mcp"],"summary":"Legacy HTTP+SSE MCP transport: opens a text/event-stream whose first event 'endpoint' carries /messages?s=<session>. Keepalive every 15 s; closed at 85 s with retry:1000. Prefer POST /mcp (streamable HTTP).","responses":{"200":{"description":"text/event-stream"},"429":{"description":"too many open streams"}}}},
"/messages":{"post":{"tags":["mcp"],"summary":"Legacy HTTP+SSE MCP transport: the ?s= session id (from the /sse endpoint event) is validated, then the JSON-RPC body is handled by /mcp and returned inline; an open /sse stream also receives it as a 'message' event.","responses":{"200":{"description":"JSON-RPC response"},"403":{"description":"invalid or missing session"}}}}
}}`
