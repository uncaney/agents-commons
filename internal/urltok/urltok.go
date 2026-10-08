// Package urltok is the read-only capability-URL middleware (SPEC-v2 27.2, 27.8). A url-class
// token carried in the query (?t=cx_…) is honoured only on safe reads under /v1/* and /f/h/*: the
// middleware looks it up by sha256, and when its token_class is "url" it injects it as the bearer
// and marks the request so the rest of the chain treats it as that identity. Any other method with
// ?t= is refused (query tokens are read-only) and a non-url token in a URL never works, so a leaked
// full token in a link is inert. Replies to ?t= reads are never cached or indexed, carry no
// referrer, are forced to txt/md/json, and have their next: paths and Link targets rewritten to
// carry the same ?t= so an agent can keep following the capability.
//
// It is a pure wrapper around http.Handler, installed by the integration package (P60a) between
// pathscrub and botlane, i.e. outside core.Handler, so the injected bearer is what core's auth
// resolves.
package urltok

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/core"
)

type ctxKey struct{}

// WithURLToken marks ctx as served through a url-class capability token (27.2).
func WithURLToken(ctx context.Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, true)
}

// FromContext reports whether the request was authorised by a ?t= capability token.
func FromContext(ctx context.Context) bool {
	v, _ := ctx.Value(ctxKey{}).(bool)
	return v
}

// honoured prefixes: a ?t= token is only ever injected on reads under these (27.2, 27.7).
func honoured(path string) bool {
	return strings.HasPrefix(path, "/v1/") || path == "/v1" ||
		strings.HasPrefix(path, "/f/h/")
}

// Middleware wraps next so a url-class ?t= token authorises safe reads under the honoured prefixes
// (27.2). d supplies the token lookup. The wrapper is pure: requests without ?t= pass through
// untouched.
func Middleware(d *core.Deps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := r.URL.Query().Get("t")
		if tok == "" {
			next.ServeHTTP(w, r)
			return
		}
		// A query token is a read capability: no write method may ride it.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			core.Err(w, r, http.StatusMethodNotAllowed, "auth", "query token is read-only")
			return
		}
		// Outside the honoured read prefixes the token is simply ignored (it is not injected, so it
		// can never authorise anything); the request continues as anonymous.
		if !honoured(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		// Only a url-class token works in a URL. A valid full/scoped token leaked into a link
		// resolves here but is refused: the caller must present it in the Authorization header.
		id, err := d.LookupToken(r.Context(), tok)
		if err != nil || id == nil || id.Class != "url" {
			core.Err(w, r, http.StatusUnauthorized, "auth", "header required")
			return
		}
		// GET read ceiling (mirrors oauth.URLScopeOK on /mcp/t, but using the 27.2 read scopes since
		// ?t= is GET-only): a nil scope set (every scope) is refused, and a non-default url token
		// carrying anything outside core.URLReadScopes can never reach root-filtered private reads.
		if !urlReadOK(id.Scopes) {
			core.Err(w, r, http.StatusForbidden, "scope", "url token exceeds read ceiling")
			return
		}
		// mb:env scope: envelopes only. A url token never reads a specific mail body or asks for
		// bodies inline (?all=1).
		if deniedMailBody(r.URL.Path, r.URL.Query().Get("all")) {
			core.Err(w, r, http.StatusForbidden, "scope", "mb:env")
			return
		}
		r2 := r.Clone(WithURLToken(r.Context()))
		r2.Header.Set("Authorization", "Bearer "+tok)
		r2.Header.Set("Accept", forceText(r2.Header.Get("Accept")))
		tw := &tokWriter{ResponseWriter: w, tok: tok, hdr: make(http.Header), status: http.StatusOK}
		next.ServeHTTP(tw, r2)
		tw.finish()
	})
}

// urlReadOK reports whether a url-class token's scope set stays within core.URLReadScopes, the
// capability-read ceiling for the GET-only ?t= path (27.2). A nil scope set (meaning every scope)
// is refused, matching oauth.URLScopeOK's treatment on /mcp/t.
func urlReadOK(scopes []string) bool {
	if scopes == nil {
		return false
	}
	for _, s := range scopes {
		if !core.ScopeAllowed(core.URLReadScopes, s) {
			return false
		}
	}
	return true
}

// deniedMailBody reports the mb:env limit: GET /v1/mb/{id} (a specific envelope's body) and any
// /v1/mb request asking for inline bodies (?all=1) are forbidden to a url token.
func deniedMailBody(path, all string) bool {
	if !strings.HasPrefix(path, "/v1/mb") {
		return false
	}
	if all == "1" {
		return true
	}
	rest := strings.TrimPrefix(path, "/v1/mb")
	return len(rest) > 1 && rest[0] == '/' // /v1/mb/{id}, not /v1/mb itself
}

// forceText drops text/html from an Accept so a capability read negotiates to txt/md/json (27.2);
// an Accept that becomes empty falls back to text/plain.
func forceText(accept string) string {
	if accept == "" {
		return "text/plain"
	}
	parts := strings.Split(accept, ",")
	kept := parts[:0]
	for _, p := range parts {
		mt := strings.TrimSpace(p)
		if i := strings.IndexByte(mt, ';'); i >= 0 {
			mt = strings.TrimSpace(mt[:i])
		}
		if strings.EqualFold(mt, "text/html") || strings.EqualFold(mt, "application/xhtml+xml") {
			continue
		}
		kept = append(kept, p)
	}
	out := strings.TrimSpace(strings.Join(kept, ","))
	if out == "" {
		return "text/plain"
	}
	return out
}

// tokWriter buffers a capability read's reply so the headers can be stamped private/noindex and the
// body's next: paths rewritten to carry the same ?t= before anything reaches the client.
type tokWriter struct {
	http.ResponseWriter
	tok    string
	hdr    http.Header
	status int
	buf    bytes.Buffer
	seen   bool
}

func (t *tokWriter) Header() http.Header { return t.hdr }

func (t *tokWriter) WriteHeader(status int) {
	if !t.seen {
		t.status, t.seen = status, true
	}
}

func (t *tokWriter) Write(p []byte) (int, error) {
	if !t.seen {
		t.WriteHeader(http.StatusOK)
	}
	return t.buf.Write(p)
}

// finish stamps the capability-reply headers, rewrites next:/Link targets, and flushes to the real
// writer. Called once, after the inner handler returns.
func (t *tokWriter) finish() {
	h := t.ResponseWriter.Header()
	for k, vs := range t.hdr {
		h[k] = vs
	}
	h.Set("Cache-Control", "private, no-store")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex")
	if links := h.Values("Link"); len(links) > 0 {
		out := make([]string, len(links))
		for i, v := range links {
			out[i] = rewriteLink(v, t.tok)
		}
		h.Del("Link")
		for _, v := range out {
			h.Add("Link", v)
		}
	}
	if v := h.Get("X-Next"); v != "" {
		h.Set("X-Next", addParam(v, t.tok))
	}
	body := rewriteBody(t.buf.Bytes(), h.Get("Content-Type"), t.tok)
	if h.Get("Content-Length") != "" {
		h.Set("Content-Length", strconv.Itoa(len(body)))
	}
	t.ResponseWriter.WriteHeader(t.status)
	t.ResponseWriter.Write(body)
}

// rewriteBody carries the ?t= into the reply body: the next: line(s) of a txt/md reply and the
// "next" array of a JSON reply. Anything it does not recognise is returned unchanged.
func rewriteBody(body []byte, ct, tok string) []byte {
	switch {
	case strings.HasPrefix(ct, "text/plain"), strings.HasPrefix(ct, "text/markdown"), ct == "":
		return rewriteNextLines(body, tok)
	case strings.HasPrefix(ct, "application/json"):
		return rewriteJSON(body, tok)
	}
	return body
}

// rewriteNextLines appends the token to every absolute path on a "next:" line.
func rewriteNextLines(body []byte, tok string) []byte {
	lines := bytes.Split(body, []byte("\n"))
	for i, ln := range lines {
		if !bytes.HasPrefix(bytes.TrimLeft(ln, " "), []byte("next:")) {
			continue
		}
		fields := strings.Fields(string(ln))
		for j, f := range fields {
			if strings.HasPrefix(f, "/") {
				fields[j] = addParam(f, tok)
			}
		}
		// Preserve the original leading indentation.
		indent := ln[:len(ln)-len(bytes.TrimLeft(ln, " "))]
		lines[i] = append(append([]byte(nil), indent...), []byte(strings.Join(fields, " "))...)
	}
	return bytes.Join(lines, []byte("\n"))
}

// rewriteJSON appends the token to each path in a top-level "next" array of strings (best effort:
// an unparseable body is returned unchanged).
func rewriteJSON(body []byte, tok string) []byte {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	raw, ok := m["next"]
	if !ok {
		return body
	}
	var arr []string
	if json.Unmarshal(raw, &arr) != nil {
		return body
	}
	for i, s := range arr {
		fields := strings.Fields(s)
		for j, f := range fields {
			if strings.HasPrefix(f, "/") {
				fields[j] = addParam(f, tok)
			}
		}
		arr[i] = strings.Join(fields, " ")
	}
	nb, err := json.Marshal(arr)
	if err != nil {
		return body
	}
	m["next"] = nb
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return out
}

// addParam appends t=<tok> to a path's query (reusing ? or & as needed); a fragment is kept last.
func addParam(path, tok string) string {
	frag := ""
	if i := strings.IndexByte(path, '#'); i >= 0 {
		path, frag = path[:i], path[i:]
	}
	sep := "?"
	if strings.IndexByte(path, '?') >= 0 {
		sep = "&"
	}
	return path + sep + "t=" + tok + frag
}

// rewriteLink appends the token to every <path> target of a Link header value whose target is an
// absolute path (same-origin); absolute URLs and other schemes are left alone.
func rewriteLink(v, tok string) string {
	var b strings.Builder
	rest := v
	for {
		open := strings.IndexByte(rest, '<')
		if open < 0 {
			b.WriteString(rest)
			break
		}
		end := strings.IndexByte(rest[open:], '>')
		if end < 0 {
			b.WriteString(rest)
			break
		}
		end += open
		b.WriteString(rest[:open+1])
		target := rest[open+1 : end]
		if strings.HasPrefix(target, "/") {
			target = addParam(target, tok)
		}
		b.WriteString(target)
		b.WriteByte('>')
		rest = rest[end+1:]
	}
	return b.String()
}
