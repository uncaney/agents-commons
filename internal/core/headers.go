package core

import (
	"net/http"
	"strings"
)

// Headers policy (SPEC-v2 3.7, 27.1, 27.2): one table drives CORS, X-Robots-Tag, TDM, Link and
// Cache-Control. Everything here is server-built; no user text ever enters a header.

var (
	corsPublic      = []string{"/v1/", "/k/", "/t/", "/f/", "/b/", "/export/", "/openapi", "/.well-known/", "/mcp", "/a2a", "/llms", "/index.md", "/AGENTS.md", "/grammar", "/sitemap"}
	noindexPrefixes = []string{"/v1/", "/v1", "/mcp", "/a2a", "/q/", "/d/", "/c/", "/cp/", "/w/", "/quarantine", "/wanted", "/oauth/", "/admin/", "/h/", "/in/", "/internal/", "/ui", "/healthz", "/room/"}
	followPrefixes  = []string{"/e/"}
	tdmReserved     = []string{"/d/", "/v1/", "/v1", "/mcp", "/a2a", "/quarantine", "/wanted", "/in/", "/oauth/", "/admin/", "/cp/", "/c/", "/w/", "/ui", "/room/"}
	contentPrefixes = []string{"/k/", "/kb/", "/t/", "/v/", "/tag/", "/qa/", "/e/", "/err/", "/eco/", "/p/", "/s/", "/svc/", "/dg/", "/f/", "/export/", "/a/", "/st/", "/h/", "/att/", "/ts/", "/gov", "/llms", "/index.md", "/AGENTS.md", "/sitemap", "/skills", "/agents", "/changelog", "/cutoff", "/about", "/legal", "/grammar", "/help"}
)

const (
	allowMethods  = "GET, HEAD, POST, PUT, PATCH, DELETE"
	allowHeaders  = "Authorization, Content-Type, Accept, Idempotency-Key, X-PoW, Mcp-Session-Id, Mcp-Protocol-Version, X-CX-V, X-CX-Mark, X-CX-Abs, X-Edit, X-Scrub-V, X-Next, If-None-Match"
	exposeHeaders = "Link, ETag, RateLimit, RateLimit-Policy, Retry-After, X-Next, Content-Digest, Signature, Signature-Input, Memento-Datetime, Mcp-Session-Id"
	linkCommon    = `</grammar>; rel="help", </q/{q}>; rel="search"; templated, </llms.txt>; rel="service-doc"`
	linkRoot      = `</openapi.json>; rel="service-desc", </.well-known/api-catalog>; rel="api-catalog"`
)

func hasPrefix(p string, list []string) bool {
	for _, x := range list {
		if strings.HasPrefix(p, x) {
			return true
		}
	}
	return false
}

// preflightPath: OPTIONS on these answers 204 with the CORS allow set (3.7).
func preflightPath(p string) bool {
	return p == "/mcp" || p == "/a2a" || strings.HasPrefix(p, "/v1/") || strings.HasPrefix(p, "/mcp/") || strings.HasPrefix(p, "/a2a/")
}

// hasToken reports whether the request carries credentials (bearer or ?t= capability token).
func hasToken(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" || r.URL.Query().Get("t") != ""
}

// LicenseURL maps the content license id (LICENSE_CONTENT) to its URL.
func LicenseURL(id string) string {
	switch strings.ToUpper(id) {
	case "", "CC0-1.0", "CC0":
		return "https://creativecommons.org/publicdomain/zero/1.0/"
	case "CC-BY-4.0":
		return "https://creativecommons.org/licenses/by/4.0/"
	case "CC-BY-SA-4.0":
		return "https://creativecommons.org/licenses/by-sa/4.0/"
	}
	return "https://spdx.org/licenses/" + id + ".html"
}

// preHeaders sets the defaults a handler may still override: security, robots, TDM, CORS.
func (d *Deps) preHeaders(h http.Header, r *http.Request) {
	p := r.URL.Path
	h.Set("X-Content-Type-Options", "nosniff")
	if !strings.HasPrefix(p, "/embed/") {
		h.Set("X-Frame-Options", "DENY")
	}
	h.Set("Referrer-Policy", "no-referrer")
	switch {
	case hasPrefix(p, noindexPrefixes) || ((p == "/kb" || p == "/kb/") && r.URL.Query().Has("q")):
		h.Set("X-Robots-Tag", "noindex")
	case hasPrefix(p, followPrefixes):
		h.Set("X-Robots-Tag", "noindex, follow")
	}
	if hasPrefix(p, tdmReserved) {
		h.Set("tdm-reservation", "1")
	} else {
		h.Set("tdm-reservation", "0")
		h.Set("tdm-policy", d.Cfg.PublicURL+"/legal")
	}
	if hasPrefix(p, corsPublic) {
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Expose-Headers", exposeHeaders)
	}
}

// preflight answers OPTIONS on /mcp, /a2a and /v1/* (3.7).
func preflight(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", allowMethods)
	h.Set("Access-Control-Allow-Headers", allowHeaders)
	h.Set("Access-Control-Expose-Headers", exposeHeaders)
	h.Set("Access-Control-Max-Age", "86400")
	h.Set("Allow", allowMethods+", OPTIONS")
	w.WriteHeader(http.StatusNoContent)
}

// finalHeaders runs when the status is known: private no-store for credentialed requests, the Link
// trio (+ root and license links) on 200/3xx.
func (d *Deps) finalHeaders(h http.Header, r *http.Request, status int, token bool) {
	switch {
	case r.URL.Query().Get("t") != "": // capability URL replies are never cached (27.2)
		h.Set("Cache-Control", "private, no-store")
	case token:
		h.Set("Cache-Control", privateCache(h.Get("Cache-Control")))
	}
	if status < 200 || status >= 400 {
		return
	}
	link := linkCommon
	p := r.URL.Path
	if p == "/" {
		link += ", " + linkRoot
	}
	if p == "/" || hasPrefix(p, contentPrefixes) {
		link += `, <` + LicenseURL(d.Cfg.LicenseContent) + `>; rel="license"`
	}
	h.Add("Link", link)
}

// privateCache turns a handler's Cache-Control into a private one for credentialed requests:
// no value -> "private, no-store"; otherwise "private" replaces public/s-maxage and the rest
// (max-age, immutable, …) is kept.
func privateCache(v string) string {
	if strings.TrimSpace(v) == "" {
		return "private, no-store"
	}
	out := []string{"private"}
	for _, part := range strings.Split(v, ",") {
		p := strings.TrimSpace(part)
		l := strings.ToLower(p)
		if p == "" || l == "public" || l == "private" || strings.HasPrefix(l, "s-maxage") {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, ", ")
}

// setRateHeaders writes the IETF RateLimit headers for the governing bucket (3.6).
func setRateHeaders(h http.Header, info RateInfo) {
	if info.Limit <= 0 {
		return
	}
	h.Set("RateLimit-Policy", itoa(info.Limit)+";w="+itoa(info.Window))
	h.Set("RateLimit", "limit="+itoa(info.Limit)+", remaining="+itoa(info.Remaining)+", reset="+itoa(info.Reset))
	if info.RetryAfter > 0 {
		h.Set("Retry-After", itoa(info.RetryAfter))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
