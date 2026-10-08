package router

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/pages"
)

var (
	hex64Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digitsRe = regexp.MustCompile(`^[0-9]{1,18}$`)
)

// catch is the method dispatcher for the method-less "/{seg}" catch-all (registered without a method
// so every real literal, method-qualified or method-less, stays more specific and wins). OPTIONS gets
// the discovery answer, GET/HEAD the bare-id/suggestion resolution; any other method on an unclaimed
// single segment is a did-you-mean 404 (as it was when it fell through to the pages catch-all).
func (h *rt) catch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodOptions:
		h.options(w, r)
	case http.MethodGet, http.MethodHead:
		h.seg(w, r)
	default:
		h.notFound(w, r, firstSeg(r.URL.Path))
	}
}

// seg handles GET/HEAD /{seg}: one path segment that no literal route claimed. Order (literal
// routes already won): bare id -> 302 to the resolved object (visible only), 64-hex -> /x/<hash>,
// digits -> /t/<n>, an uppercase first segment -> 301 to its lowercase form when that names a real
// route, then a did-you-mean 404 through pages.NotFound. The suffix is preserved throughout.
func (h *rt) seg(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("seg")
	base, suf := doc.SplitSuffix(raw)
	sfx := ""
	if suf != "" {
		sfx = raw[len(base):]
	}
	switch {
	case core.ValidID(base):
		// Bare id: resolve and bounce to the object itself; hidden/quarantined ids (resolver
		// returns ok=false or an empty url) fall through to the same 404 as an unknown id.
		if _, _, u, ok := h.d.Resolve(r.Context(), base); ok && u != "" {
			found(w, r, relOwn(u))
			return
		}
	case hex64Re.MatchString(base):
		found(w, r, "/x/"+base)
		return
	case digitsRe.MatchString(base):
		found(w, r, "/t/"+base)
		return
	default:
		if low := strings.ToLower(base); low != base && knownSeg(low) {
			redirect(w, r, "/"+low+sfx)
			return
		}
	}
	h.notFound(w, r, base)
}

// found writes a 302 to a server-built relative target (no shared caching: visibility can change).
func found(w http.ResponseWriter, r *http.Request, loc string) {
	if r.URL.RawQuery != "" && !strings.Contains(loc, "?") {
		loc += "?" + r.URL.RawQuery
	}
	w.Header().Set("Location", loc)
	w.WriteHeader(http.StatusFound)
}

// relOwn turns an own-site absolute URL into a relative path; a foreign URL is returned unchanged
// (the resolver only ever yields own-site targets, so this is defence in depth).
func relOwn(u string) string {
	if strings.HasPrefix(u, doc.Base()+"/") {
		return strings.TrimPrefix(u, doc.Base())
	}
	if strings.HasPrefix(u, "/") {
		return u
	}
	return u
}

// notFound attaches up to two did-you-mean suggestions (Damerau-Levenshtein <= 2 against the known
// route first segments and alias keys) to the request context and delegates to pages.NotFound,
// which prepends them to the 404's next: line.
func (h *rt) notFound(w http.ResponseWriter, r *http.Request, seg string) {
	if s := suggest(seg); len(s) > 0 {
		r = r.WithContext(pages.WithSuggestions(r.Context(), s))
	}
	pages.NotFound(w, r)
}

// --- OPTIONS discovery ---------------------------------------------------------------------------

// options answers OPTIONS on any path the CORS preflight (core, /v1 /mcp /a2a) did not take:
// OPTIONS / and OPTIONS * -> 200 with the grammar body; any other path -> 204 + Allow + Link
// (added by core on 2xx) + X-Next carrying the GET affordances.
func (h *rt) options(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/" || p == "*" || p == "" {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		body := []byte(pages.Grammar())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			w.Write(body)
		}
		return
	}
	acts := affordances(r, p)
	methods := []string{"GET", "HEAD"}
	for _, a := range acts {
		if a.Method == "POST" {
			methods = append(methods, "POST")
			break
		}
	}
	methods = append(methods, "OPTIONS")
	w.Header().Set("Allow", strings.Join(methods, ", "))
	doc.RawActions(w, r, acts...)
	w.WriteHeader(http.StatusNoContent)
}

// affordances returns the canonical GET (and writing) actions for a path's first segment, used as
// the OPTIONS X-Next discovery hint; unknown paths fall back to the search + help pointers.
func affordances(r *http.Request, p string) []doc.Action {
	acts := []doc.Action{doc.GET(p, "")}
	if extra, ok := afterGET[firstSeg(p)]; ok {
		acts = append(acts, extra...)
	} else {
		acts = append(acts, doc.GET("/grammar", ""))
	}
	return acts
}

// afterGET are the write/related actions offered alongside the GET of the concrete requested path
// under each first segment (next: actions carry no "{}" templates, so the path itself stands in for
// the OpenAPI shape). Next() later drops any action that is not a clean relative path.
var afterGET = map[string][]doc.Action{
	"q":   {doc.POST("/e", "paste a traceback")},
	"e":   {doc.POST("/e", "paste a traceback")},
	"k":   {doc.POST("/v1/kb", "post a fix")},
	"t":   {doc.POST("/v1/t", "open a task")},
	"a":   {doc.GET("/grammar", "")},
	"x":   {doc.GET("/grammar", "")},
	"v":   {doc.POST("/v1/kb", "post a fix")},
	"tag": {doc.GET("/grammar", "")},
	"qa":  {doc.GET("/grammar", "")},
	"f":   {doc.GET("/grammar", "")},
	"s":   {doc.GET("/grammar", "")},
	"w":   {doc.POST("/w/kb", "+X-PoW")},
	"svc": {doc.GET("/svc", "catalog")},
	"gov": {doc.GET("/gov", "")},
	"st":  {doc.GET("/st", "beacons")},
}

func firstSeg(p string) string {
	p = strings.TrimPrefix(p, "/")
	if i := strings.IndexByte(p, '/'); i >= 0 {
		p = p[:i]
	}
	if b, _ := doc.SplitSuffix(p); b != "" {
		return b
	}
	return p
}

// --- sitemap.txt ---------------------------------------------------------------------------------

// sitemapTxt serves GET /sitemap.txt: a plain list of the stable public entry-point URLs, one
// absolute URL per line (27.2). It is a flat, machine-trivial companion to /sitemap.xml.
func sitemapTxt(w http.ResponseWriter, r *http.Request) {
	base := doc.Base()
	var b strings.Builder
	for _, p := range sitemapPaths {
		b.WriteString(base)
		b.WriteString(p)
		b.WriteByte('\n')
	}
	body := []byte(b.String())
	doc.ServeStatic(w, r, time.Time{}, body, "text/plain; charset=utf-8")
}

// sitemapPaths are the durable, indexable entry points (no per-object permalinks: those live in
// /sitemap.xml and its children).
var sitemapPaths = []string{
	"/", "/index.md", "/llms.txt", "/llms-full.txt", "/AGENTS.md", "/grammar", "/help",
	"/openapi.json", "/brief", "/legal", "/status", "/skills", "/tags", "/wanted",
}

// --- did-you-mean ---------------------------------------------------------------------------------

// knownSegsList is the union of the real route first segments and the alias keys; a typo'd first
// segment is matched against it. Kept in sync with the grammar (8.1) and the alias table above.
var knownSegsList = []string{
	// real route first segments and fixed pages (8.1 grammar, 27.1, 27.9)
	"q", "e", "k", "t", "a", "x", "s", "v", "tag", "qa", "since", "cutoff", "dg", "wanted",
	"quarantine", "d", "c", "cp", "f", "b", "export", "oembed", "w", "svc", "att", "ts", "p",
	"gov", "changelog", "st", "lb", "grammar", "help", "index.md", "llms.txt", "llms-full.txt",
	"AGENTS.md", "openapi.json", "legal", "aup.txt", "status", "worker", "wasm", "brief",
	"limits", "skills", "ci", "errsig", "now", "join.py", "robots.txt", "sitemap.xml",
	"favicon.ico", "healthz", "metrics", "mcp", "a2a", "v1", "oauth", "ui", "h", "err", "eco",
	"kb", "anchor", "inj", "pc", "rand", "room", "cx.py", "cx.sh", "cx.mjs", "tags",
	// alias keys (mounted above)
	"search", "find", "error", "errors", "entry", "fix", "fixes", "task", "tasks", "issue",
	"issues", "agent", "agents", "u", "docs", "doc", "api", "readme", "usage", "start",
	"getting-started", "llms", "feed", "rss", "atom.xml", "feeds", "sitemap", "health", "ping",
	"register", "signup",
}

var knownSet = func() map[string]bool {
	m := make(map[string]bool, len(knownSegsList))
	for _, s := range knownSegsList {
		m[s] = true
	}
	return m
}()

func knownSeg(s string) bool { return knownSet[s] }

// suggest returns up to two "/seg" paths whose segment is within Damerau-Levenshtein distance 2 of
// the given (lowercased) first segment, closest first, ties broken by name. An exact match (the
// caller already failed to route it, so this should not happen) and distances > 2 are skipped.
func suggest(seg string) []string {
	seg = strings.ToLower(seg)
	if seg == "" || len(seg) > 64 {
		return nil
	}
	type cand struct {
		name string
		dist int
	}
	var cs []cand
	for _, k := range knownSegsList {
		d := damerau(seg, strings.ToLower(k), 2)
		if d >= 1 && d <= 2 {
			cs = append(cs, cand{k, d})
		}
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].dist != cs[j].dist {
			return cs[i].dist < cs[j].dist
		}
		return cs[i].name < cs[j].name
	})
	out := make([]string, 0, 2)
	for _, c := range cs {
		out = append(out, "/"+c.name)
		if len(out) == 2 {
			break
		}
	}
	return out
}

// damerau is the optimal-string-alignment (restricted Damerau-Levenshtein) distance with an early
// cutoff: it returns max+1 as soon as the whole row exceeds max. Adjacent transpositions cost 1.
func damerau(a, b string, max int) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if d := la - lb; d > max || -d > max {
		return max + 1
	}
	prev2 := make([]int, lb+1)
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		best := cur[0]
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			v := min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				if t := prev2[j-2] + 1; t < v {
					v = t
				}
			}
			cur[j] = v
			if v < best {
				best = v
			}
		}
		if best > max {
			return max + 1
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[lb]
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}
