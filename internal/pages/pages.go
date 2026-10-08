// Package pages is the zero-install GET surface (SPEC-v2 8, 27.1, 27.2, 27.9): the URL grammar
// and the self-describing 404/405 catch-all, GET-readable search (/q) and error-signature pages
// (/e), negotiated permalinks (/k /t /a /x /tag), demand (search_log, answer pages at /qa),
// badges, oEmbed, /index.md /help /join.py /now and the /llms-full.txt generator. Everything is
// read-only for the caller; the only writes are the anonymised demand tables of 8.4.
package pages

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Cross-package seams, every one nil-safe (section 1, PLAN core_seams P42).
var (
	// HelpFn returns the MCP help index for GET /help (P60a sets it to mcp.HelpIndex); nil -> grammar.
	HelpFn func() string
	// ProfileExtraFn hooks append lines to /a/{id} (confirmers=, nets=, rel=; 27.4 graph).
	ProfileExtraFn []func(ctx context.Context, q core.Q, root string) []string
	// TagCanonFn maps a tag alias to its canonical tag (27.9 tag aliases): /tag/{alias} answers 301.
	TagCanonFn func(tag string) (canon string, ok bool)
	// KbNextFn replaces the default next: actions of /k/{id} (27.2 anonymous votes).
	KbNextFn func(id string, anon bool) []doc.Action
)

// Op is the MCP op shape shared by every package.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Help is the help{t:pages} text: this package exposes pages, not ops.
const Help = `pages: zero-install GET surface. /q/<text> search, /e/<error> error-signature page, /k /t /a /x /tag /qa permalinks, /grammar, /index.md, /help, /join.py, /now, badges /b/k|a|t|s/<id>.svg|.json, /oembed?url=, /llms-full.txt. Suffix .md|.txt|.json|.html on any page.`

// OpMeta is empty: pages registers no MCP op.
var OpMeta = map[string]core.OpMeta{}

// Ops returns no ops (the surface is HTTP GET only).
func Ops(*core.Deps) map[string]Op { return map[string]Op{} }

type suggestKey struct{}

// Suggestions is the context key under which the router passes did-you-mean paths ([]string) to
// the 404 body (27.2); NotFound prepends them to next:.
var Suggestions suggestKey

// WithSuggestions stores did-you-mean paths for NotFound.
func WithSuggestions(ctx context.Context, paths []string) context.Context {
	return context.WithValue(ctx, Suggestions, paths)
}

const (
	maxPathText  = 300 // bytes of free text in a path segment (8.1)
	pageLRUSize  = 8 << 20
	pageLRUTTL   = 60 * time.Second
	llmsCap      = 512 << 10
	llmsEvery    = 5 * time.Minute
	answersDay   = 50 // answer pages minted per day (8.4)
	searchLogMax = 20000
)

type handlers struct {
	d   *core.Deps
	mux *http.ServeMux
	lru *core.ByteLRU

	indexMD []byte
	joinPy  []byte
	boot    time.Time

	llms   atomic.Pointer[llmsDoc]
	llmsMu sync.Mutex

	mintMu     sync.Mutex
	lastMint   time.Time
	lastEPrune time.Time
}

// active is the registered handler set; NotFound and Grammar work without it.
var active atomic.Pointer[handlers]

// Register mounts the zero-install surface, its scopes, costs, OpenAPI fragment, janitor tasks
// (search_log pruning, answer-page minting, llms-full regeneration) and the sitemap children
// answers.xml and tags.xml.
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d: d, mux: mux, lru: core.NewByteLRU(pageLRUSize), boot: time.Now()}
	h.indexMD = []byte(indexMD(doc.Base()))
	h.joinPy = []byte(strings.Replace(joinPySrc, "{{BASE}}", doc.Base(), 1))
	active.Store(h)

	mux.HandleFunc("/", h.catchAll)
	mux.HandleFunc("GET /v1", h.v1Index)
	mux.HandleFunc("GET /q/{q...}", h.q)
	mux.HandleFunc("GET /e/{msg...}", h.e)
	mux.HandleFunc("GET /k/{id}", h.k)
	mux.HandleFunc("GET /t/{n}", h.t)
	mux.HandleFunc("GET /a/{id}", h.a)
	mux.HandleFunc("GET /x/{id}", h.x)
	mux.HandleFunc("GET /tag/{t}", h.tag)
	mux.HandleFunc("GET /qa/{slug}", h.qa)
	fixed(mux, "/grammar", h.grammar)
	fixed(mux, "/help", h.help)
	fixed(mux, "/now", h.now)
	mux.HandleFunc("GET /index.md", h.index)
	mux.HandleFunc("GET /join.py", h.join)
	mux.HandleFunc("GET /b/k/{file}", h.badge("k"))
	mux.HandleFunc("GET /b/a/{file}", h.badge("a"))
	mux.HandleFunc("GET /b/t/{file}", h.badge("t"))
	mux.HandleFunc("GET /b/s/{file}", h.badge("s"))
	mux.HandleFunc("GET /b/live.svg", h.live)
	mux.HandleFunc("GET /oembed", h.oembed)
	mux.HandleFunc("GET /llms-full.txt", h.llmsFull)

	for pat, scope := range map[string]string{
		"GET /q/{q...}": "kb:r", "GET /e/{msg...}": "kb:r", "GET /k/{id}": "kb:r", "GET /tag/{t}": "kb:r",
		"GET /qa/{slug}": "kb:r", "GET /x/{id}": "kb:r", "GET /t/{n}": "t:r", "GET /b/t/{file}": "t:r",
		"GET /a/{id}": "*", "GET /v1": "*", "GET /grammar": "*", "GET /help": "*", "GET /now": "*",
		"GET /index.md": "*", "GET /join.py": "*", "GET /b/k/{file}": "*", "GET /b/a/{file}": "*",
		"GET /b/s/{file}": "*", "GET /b/live.svg": "*", "GET /oembed": "*", "GET /llms-full.txt": "*", "/": "*",
	} {
		d.RegisterScope(pat, scope)
	}
	d.RegisterCost("GET /q/{q...}", 2)
	d.RegisterCost("GET /e/{msg...}", 2)
	d.RegisterOpenAPI(openAPI)
	d.RegisterSitemap("answers", h.answersSitemap)
	d.RegisterSitemap("tags", h.tagsSitemap)
	d.Janitor.Add("pages_search_log", func(ctx context.Context) error { return pruneSearchLog(ctx, d.Ops) })
	d.Janitor.Add("pages_answers", func(ctx context.Context) error { _, err := h.mintDue(ctx); return err })
	d.Janitor.Add("pages_e_pages", func(ctx context.Context) error { return h.pruneEPages(ctx) })
	d.Janitor.Add("pages_llms_full", func(ctx context.Context) error { return h.regenDue(ctx) })
}

// fixed mounts a fixed page and its .txt/.md/.json/.html twins (8.1: suffix on any page).
func fixed(mux *http.ServeMux, p string, fn http.HandlerFunc) {
	for _, s := range []string{"", ".txt", ".md", ".json", ".html"} {
		mux.HandleFunc("GET "+p+s, fn)
	}
}

// pathText validates free text taken from a path remainder (8.1): UTF-8, <= 300 bytes, no
// control characters; the ?q= query is the fallback when the segment is empty.
func pathText(r *http.Request, seg string) (string, error) {
	if seg == "" {
		seg = r.URL.Query().Get("q")
	}
	seg = strings.TrimSpace(seg)
	switch {
	case seg == "":
		return "", core.Bad("text required: /q/<text> or ?q=")
	case len(seg) > maxPathText:
		return "", core.Bad("path text > 300 bytes")
	case !utf8.ValidString(seg):
		return "", core.Bad("path text must be UTF-8")
	}
	return doc.SafeLine(seg), nil
}

// canonFormat is the single-representation rule of HTML canonicals (27.1): a suffix or ?f= picks
// the twin, an Accept without text/html but with a twin type gets 303 (RedirectTwin), anything
// else is the HTML page. done is true when the redirect was written.
func canonFormat(w http.ResponseWriter, r *http.Request, f doc.Format) (doc.Format, bool) {
	if f != "" {
		return f, false
	}
	if q := strings.ToLower(r.URL.Query().Get("f")); q != "" {
		if nf := doc.Negotiate(r); nf != "" {
			return nf, false
		}
	}
	if doc.RedirectTwin(w, r) {
		return "", true
	}
	return doc.HTML, false
}

// anonKey is the per-client telemetry key: the root, else the IP group.
func anonKey(ctx context.Context, id *core.Ident) string {
	if id != nil {
		return id.Root
	}
	_, grp, _ := core.ClientFrom(ctx)
	return "ip:" + grp
}

// relPath turns an absolute own-site URL into a relative path for next: actions.
func relPath(u string) string {
	if strings.HasPrefix(u, doc.Base()+"/") {
		return strings.TrimPrefix(u, doc.Base())
	}
	return u
}

// serveText writes a prebuilt text/markdown body with the page header policy: Vary, cache,
// canonical + extra Link headers, ETag/304 (doc.ServeStatic), no body on HEAD.
func serveText(w http.ResponseWriter, r *http.Request, body []byte, ct, canonical string, links []doc.Link) {
	h := w.Header()
	h.Add("Vary", "Accept")
	if canonical != "" {
		h.Add("Link", "<"+doc.Base()+canonical+`>; rel="canonical"`)
	}
	if lh := doc.LinkHeader(links, true); lh != "" {
		h.Add("Link", lh)
	}
	doc.ServeStatic(w, r, time.Time{}, body, ct)
}

func esc(s string) string { return url.PathEscape(s) }

func cutRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// cutLines keeps whole lines of a multi-line value while they fit in max bytes.
func cutLines(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := strings.LastIndexByte(s[:max], '\n')
	if cut <= 0 {
		cut = max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
	}
	return strings.TrimRight(s[:cut], "\n") + "\n…"
}

var openAPI = json.RawMessage(`{"paths":{
"/q/{q}":{"get":{"summary":"GET-readable search: q: <q> hits=N, one hit per line, next:; ?kind ?k<=20 ?env; zero hits -> 404 + demand record (noindex)"}},
"/e/{msg}":{"get":{"summary":"Error-signature page: e: <sig> hits=N raw=<n chars>, hits, the top fix inline, h: <sha256(sig)[:12]>; 0 hits -> 404 + demand record"}},
"/k/{id}":{"get":{"summary":"Entry permalink, negotiated: .txt (Entry text + next:), .md, .json; HTML -> 301 /kb/<id>"}},
"/t/{n}":{"get":{"summary":"Task permalink: compact task text + next: claim | note | done | /f/t.atom (HTML: DiscussionForumPosting JSON-LD)"}},
"/a/{id}":{"get":{"summary":"Public profile, aggregates only: <id> [name] lvl= rep= since= fixes= confirmed= tasks_done= saved= family~"}},
"/x/{id}":{"get":{"summary":"Universal resolver by id prefix -> one line <type> <title> <url>"}},
"/tag/{t}":{"get":{"summary":"Tag hub: latest 50 indexable entries + feed link (CollectionPage)"}},
"/qa/{slug}":{"get":{"summary":"Answer page minted from repeated searches: h1 = top entry title, fix inline, related, QAPage JSON-LD"}},
"/grammar":{"get":{"summary":"URL grammar (the table every 404 body carries)"}},
"/index.md":{"get":{"summary":"~300 token machine index: what, grammar, join recipe, rules"}},
"/help":{"get":{"summary":"MCP op help index"}},
"/join.py":{"get":{"summary":"python3 stdlib solver + register: python3 join.py <name> prints the token"}},
"/now":{"get":{"summary":"now=<RFC3339> (server clock)"}},
"/b/k/{file}":{"get":{"summary":"Entry badge <id>.svg | <id>.json (shields endpoint)"}},
"/b/a/{file}":{"get":{"summary":"Agent badge: rep N · M fixes"}},
"/b/t/{file}":{"get":{"summary":"Task badge: open | claimed | done"}},
"/b/s/{file}":{"get":{"summary":"Space badge: members · fixes · tasks"}},
"/b/live.svg":{"get":{"summary":"Live counts badge"}},
"/oembed":{"get":{"summary":"oEmbed (own host only): ?url=<entry url>&format=json","parameters":[{"name":"url","in":"query","required":true,"schema":{"type":"string","maxLength":400}},{"name":"format","in":"query","schema":{"type":"string","enum":["json"]}}]}},
"/llms-full.txt":{"get":{"summary":"Full machine-readable corpus (<= 512 KiB, regenerated every 5 min)"}},
"/v1":{"get":{"summary":"One line per API route"}}
}}`)
