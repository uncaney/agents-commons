// Package pathscrub keeps secrets out of URLs (SPEC-v2 27.8, 24). A middleware runs a tier-1
// scrub.Scan over the decoded path and query of the read routes that take free text in the URL
// (/q/, /e/, /x/, /f/q/, /v/, /brief, and /kb or /v1/kb with ?q=); any hit is refused with 400
// before a handler, a miss record or a search-log row can see the secret. Request-log path lines
// are masked through MaskPath (installed as core.LogPathFn), and every HTML reply carries
// Referrer-Policy: no-referrer so a leaked path never rides a Referer header to a third party.
//
// It is a pure wrapper around http.Handler, installed by the integration package (P60a) as the
// outermost request wrapper.
package pathscrub

import (
	"net/http"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/scrub"
)

func init() {
	// The request-log path formatter masks secrets even if the integration package never wires it
	// explicitly; idempotent, same function either way.
	if core.LogPathFn == nil {
		core.LogPathFn = MaskPath
	}
}

// scanPrefixes are the routes whose URL carries free user text in the path (27.8). /q/ /e/ /x/
// /f/q/ /v/ /brief.
var scanPrefixes = []string{"/q/", "/e/", "/x/", "/f/q/", "/v/", "/brief"}

// scans reports whether r's URL must be scrubbed: a free-text read path, or a /kb or /v1/kb search
// that carries ?q=.
func scans(r *http.Request) bool {
	p := r.URL.Path
	for _, pre := range scanPrefixes {
		if p == strings.TrimSuffix(pre, "/") || strings.HasPrefix(p, pre) {
			return true
		}
	}
	if (p == "/kb" || p == "/kb/" || p == "/v1/kb") && r.URL.Query().Has("q") {
		return true
	}
	return false
}

// Middleware wraps next: it refuses a URL that carries a tier-1 secret on a scanned read route, and
// stamps Referrer-Policy: no-referrer on every HTML reply. d is unused today but kept in the
// signature for parity with the other request middlewares and future per-Deps policy.
func Middleware(d *core.Deps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if scans(r) {
			if kind, hit := scanURL(r); hit {
				core.Err(w, r, http.StatusBadRequest, "scrub", "query "+kind+" (never put secrets in URLs; POST /v1/q)")
				return
			}
		}
		next.ServeHTTP(&htmlNoRef{ResponseWriter: w}, r)
	})
}

// scanURL runs tier-1 scrub.Scan over the decoded path and the decoded query values (the capability
// token parameter t is the URL-capability mechanism, not a leaked secret, so it is skipped). It
// returns the first tier-1 finding's kind.
func scanURL(r *http.Request) (kind string, hit bool) {
	var b strings.Builder
	b.WriteString(r.URL.Path)
	for k, vs := range r.URL.Query() {
		if k == "t" {
			continue
		}
		for _, v := range vs {
			b.WriteByte(' ')
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(v)
		}
	}
	for _, f := range scrub.Scan("query", b.String()) {
		if f.Tier == 1 {
			return f.Kind, true
		}
	}
	return "", false
}

// MaskPath masks any secret in a request-log path line and truncates it to 200 bytes (27.8). It is
// the formatter core.LogPathFn calls for every request-log line.
func MaskPath(path string) string {
	masked, _ := scrub.Mask(path)
	if len(masked) > 200 {
		masked = masked[:200]
	}
	return masked
}

// htmlNoRef stamps Referrer-Policy: no-referrer on any text/html reply (27.8), so a path that still
// slipped through never leaves on a Referer header.
type htmlNoRef struct {
	http.ResponseWriter
	wrote bool
}

func (h *htmlNoRef) WriteHeader(status int) {
	if !h.wrote {
		h.wrote = true
		hd := h.ResponseWriter.Header()
		if strings.HasPrefix(hd.Get("Content-Type"), "text/html") {
			hd.Set("Referrer-Policy", "no-referrer")
		}
	}
	h.ResponseWriter.WriteHeader(status)
}

func (h *htmlNoRef) Write(p []byte) (int, error) {
	if !h.wrote {
		h.WriteHeader(http.StatusOK)
	}
	return h.ResponseWriter.Write(p)
}

func (h *htmlNoRef) Flush() {
	if !h.wrote {
		h.WriteHeader(http.StatusOK)
	}
	if f, ok := h.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (h *htmlNoRef) Unwrap() http.ResponseWriter { return h.ResponseWriter }
