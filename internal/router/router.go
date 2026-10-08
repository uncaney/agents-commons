// Package router is the forgiving front door (SPEC-v2 27.2): a compile-time alias table mounted
// as explicit GET/HEAD patterns (each a 301 with a relative, server-built Location), a
// single-segment catch handler that resolves bare ids, hashes and task numbers and offers
// did-you-mean suggestions on a miss, and OPTIONS discovery. It mounts after every other package
// and before pages' catch-all; literal routes always win over its wildcards, so it never shadows a
// real page. It owns no storage and performs no writes.
package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
)

// Op is the MCP op shape shared by every package; the router exposes none (HTTP-only surface).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Help names the forgiving behaviours for the op index.
const Help = `router: forgiving front door. Alias routes (/search /docs /openapi.yaml /feed /sitemap … -> canonical, one 301), bare-id/hash/digit shortcuts (GET /<id> -> the object, GET /<64hex> -> /x/, GET /<n> -> /t/<n>), did-you-mean 404s, OPTIONS discovery. The /sitemap.txt plain URL list is served by the web package.`

// OpMeta is empty: the router registers no MCP op.
var OpMeta = map[string]core.OpMeta{}

// Ops returns no ops (the surface is HTTP only).
func Ops(*core.Deps) map[string]Op { return map[string]Op{} }

const (
	maxRemainder = 300 // bytes of free text kept from a path remainder before percent-encoding (8.1)
	aliasMaxAge  = 86400
)

// rt holds the dependencies the dynamic handlers need (bare-id resolution, did-you-mean).
type rt struct{ d *core.Deps }

// Register mounts the alias table and the single-segment catch handler, and declares their scopes
// (all public reads). It must run after every other package so each alias key and the {seg} wildcard
// lose to the real literal routes.
//
// The catch is registered WITHOUT a method ("/{seg}", not "GET /{seg}") so router honours its own
// contract — "literal routes always win over its wildcards": a bare "/{seg}" is a strict superset of
// every single-segment literal, whether method-qualified (GET /sse) or method-less (/mcp, /a2a,
// /messages), so each is more specific and wins. A GET-only "GET /{seg}" is instead *ambiguous* with
// those method-less literals (it matches fewer methods but a more general path) and http.ServeMux
// panics at boot — which left this package silently degraded. The handler dispatches by method, so
// the GET/HEAD bare-id behaviour and OPTIONS discovery are unchanged for the single-segment surface.
// /sitemap.txt is the web package's (it owns the sitemap tree), so the router does not mount it.
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &rt{d: d}
	mountAliases(mux)
	mux.HandleFunc("/{seg}", h.catch)

	for _, p := range append(aliasPatterns(), "/{seg}") {
		d.RegisterScope(p, "*")
	}
}

// --- alias table ---------------------------------------------------------------------------------

// prefixAlias redirects a source pattern to a target prefix with the matched remainder appended
// (percent-encoded, <= 300 bytes, UTF-8 validated). A pattern with no wildcard redirects to the
// bare prefix. wild is the wildcard name captured by the source pattern ("" for the bare form).
type prefixAlias struct {
	pat  string // mux pattern WITHOUT the "GET " method prefix
	to   string // target prefix, kept relative, e.g. "/q/"
	wild string // PathValue name holding the remainder, "" when the pattern is bare
}

// exactAlias redirects a literal source path to a fixed relative target (no remainder).
type exactAlias struct{ pat, to string }

// prefixAliases are the search/error/entry/task/agent families (27.2). Each entry mounts one
// GET pattern; GET also answers HEAD. The remainder is reflected into the Location, never a host.
var prefixAliases = []prefixAlias{
	// /search[/{q...}], /find/{q...} -> /q/ (the /q/ target matches an empty remainder, so the
	// bare forms land on the search index page in one hop).
	{"/search", "/q/", ""},
	{"/search/{r...}", "/q/", "r"},
	{"/find", "/q/", ""},
	{"/find/{r...}", "/q/", "r"},
	// /error[s]/{m...} -> /e/ (the bare forms match /e/ with an empty signature; /err/ is the
	// class hub, left alone, 27.1).
	{"/error", "/e/", ""},
	{"/errors", "/e/", ""},
	{"/error/{r...}", "/e/", "r"},
	{"/errors/{r...}", "/e/", "r"},
	// /entry|/fix|/fixes/{id} -> /k/ (id required: /k/{id} does not match an empty segment).
	{"/entry/{r}", "/k/", "r"},
	{"/fix/{r}", "/k/", "r"},
	{"/fixes/{r}", "/k/", "r"},
	// /task[s]|/issue[s]/{n} -> /t/ (bare /tasks -> /v1/t, an exact alias below).
	{"/task/{r}", "/t/", "r"},
	{"/tasks/{r}", "/t/", "r"},
	{"/issue/{r}", "/t/", "r"},
	{"/issues/{r}", "/t/", "r"},
	// /agent[s]|/u/{id} -> /a/
	{"/agent/{r}", "/a/", "r"},
	{"/agents/{r}", "/a/", "r"},
	{"/u/{r}", "/a/", "r"},
}

// exactAliases are the fixed-page and discovery-document aliases (27.2).
var exactAliases = []exactAlias{
	{"/tasks", "/v1/t"},
	// docs family -> /index.md
	{"/docs", "/index.md"}, {"/doc", "/index.md"}, {"/api", "/index.md"},
	{"/readme", "/index.md"}, {"/README", "/index.md"}, {"/README.md", "/index.md"},
	{"/usage", "/index.md"}, {"/start", "/index.md"}, {"/getting-started", "/index.md"},
	// llms / agents docs
	{"/llm.txt", "/llms.txt"}, {"/llms", "/llms.txt"}, {"/LLMS.txt", "/llms.txt"},
	{"/agents.md", "/AGENTS.md"}, {"/AGENTS.txt", "/AGENTS.md"},
	// openapi
	{"/openapi.yaml", "/openapi.json"}, {"/swagger.json", "/openapi.json"},
	{"/.well-known/openapi.json", "/openapi.json"},
	// agent-manifest json files -> the matching /.well-known/*
	{"/mcp.json", "/.well-known/mcp.json"}, {"/manifest.json", "/.well-known/manifest.json"},
	{"/ai-plugin.json", "/.well-known/ai-plugin.json"}, {"/agent.json", "/.well-known/agent.json"},
	{"/agent-card.json", "/.well-known/agent-card.json"}, {"/a2a.json", "/.well-known/a2a.json"},
	// feeds -> /f/kb.atom (feed.xml/feed.json are owned by the feed package)
	{"/feed", "/f/kb.atom"}, {"/rss", "/f/kb.atom"}, {"/rss.xml", "/f/kb.atom"},
	{"/atom.xml", "/f/kb.atom"}, {"/feeds", "/f/kb.atom"},
	// sitemap / status / join
	{"/sitemap", "/sitemap.xml"},
	// /status.json is served directly by the ops package (the JSON twin of /status), so it is not an
	// alias here: aliasing it would collide with ops' real route on the shared mux.
	{"/health", "/status"}, {"/ping", "/status"},
	{"/join", "/index.md#join"}, {"/register", "/index.md#join"}, {"/signup", "/index.md#join"},
}

// aliasPatterns returns every mux pattern the router mounts for the alias table, each with its
// "GET " method prefix. Used by Register (scopes) and by the no-shadow test.
func aliasPatterns() []string {
	out := make([]string, 0, len(prefixAliases)+len(exactAliases))
	for _, a := range prefixAliases {
		out = append(out, "GET "+a.pat)
	}
	for _, a := range exactAliases {
		out = append(out, "GET "+a.pat)
	}
	return out
}

// mountAliases registers every alias as a GET pattern (HEAD is served by the same pattern).
func mountAliases(mux *http.ServeMux) {
	for _, a := range prefixAliases {
		a := a
		mux.HandleFunc("GET "+a.pat, func(w http.ResponseWriter, r *http.Request) {
			loc := a.to
			if a.wild != "" {
				loc += encodeRemainder(r.PathValue(a.wild))
			}
			redirect(w, r, loc)
		})
	}
	for _, a := range exactAliases {
		a := a
		mux.HandleFunc("GET "+a.pat, func(w http.ResponseWriter, r *http.Request) { redirect(w, r, a.to) })
	}
}

// redirect writes a 301 with a server-built relative Location and a day of shared caching. The
// query string (already percent-encoded by the client) is carried through; the host is never
// taken from the request, so an open redirect is impossible.
func redirect(w http.ResponseWriter, r *http.Request, loc string) {
	if r.URL.RawQuery != "" && !strings.Contains(loc, "?") {
		loc += "?" + r.URL.RawQuery
	}
	h := w.Header()
	h.Set("Cache-Control", "public, max-age=86400")
	h.Set("Location", loc)
	w.WriteHeader(http.StatusMovedPermanently)
}

// encodeRemainder validates, caps at 300 bytes (on a rune boundary) and percent-encodes a path
// remainder so it becomes exactly one safe path segment: "/" -> %2F keeps a protocol-relative
// "//evil" from ever appearing in the Location. Invalid UTF-8 is dropped to the valid prefix.
func encodeRemainder(s string) string {
	if !utf8.ValidString(s) {
		if i := firstInvalid(s); i >= 0 {
			s = s[:i]
		}
	}
	if len(s) > maxRemainder {
		s = s[:maxRemainder]
		for len(s) > 0 && !utf8.RuneStart(s[len(s)-1]) {
			s = s[:len(s)-1]
		}
	}
	return url.PathEscape(s)
}

func firstInvalid(s string) int {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return -1
}
