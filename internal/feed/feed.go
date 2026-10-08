// Package feed renders every d.RegisterFeed source as Atom and JSON Feed 1.1 (SPEC-v2 9.3):
// GET /f/<name>[/<sub>].atom|.json with ?n<=50 (default 20) and ?since=RFC3339. Items carry a
// summary (<= 500 B) plus a link, never a body. Every rendered feed lives in one 16 MiB
// core.ByteLRU for 5 min; ETag/304 and Cache-Control come from doc.ServeStatic. The saved-search
// source q/<query> lives here, behind the trigram semaphore and the shed:feeds rung. Aliases
// /feed.xml and /feed.json answer 301; Links gives pages their <link rel=alternate> tags.
package feed

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

const (
	// CacheBytes bounds the rendered-feed cache (all names together); CacheTTL is its entry TTL.
	CacheBytes = 16 << 20
	CacheTTL   = 5 * time.Minute
	// MaxItems caps ?n and every feed; DefaultN applies without ?n.
	MaxItems = 50
	DefaultN = 20
	// MaxSummary is the per-item summary cap in bytes (the renderer enforces it on every source).
	MaxSummary = 500

	maxName   = 512 // bytes of <name>[/<sub>] after /f/
	maxTitle  = 300
	maxID     = 200
	maxURL    = 1024
	maxAuthor = 80
	maxTags   = 10
	maxTag    = 60
	tagYear   = "2026" // tag: URI date part (the year the authority took the domain)
)

// Format is a feed rendering: Atom or JSON Feed 1.1.
type Format string

const (
	Atom Format = "atom"
	JSON Format = "json"
)

var (
	contentTypes = map[Format]string{Atom: "application/atom+xml; charset=utf-8", JSON: "application/feed+json; charset=utf-8"}
	linkTypes    = map[Format]string{Atom: "application/atom+xml", JSON: "application/feed+json"}
	// suffixes maps a path suffix to its format; .xml and .rss redirect to .atom (aliases).
	suffixes = map[string]Format{".atom": Atom, ".json": JSON, ".xml": "", ".rss": ""}
	epoch    = time.Unix(0, 0).UTC()
)

type svc struct {
	d     *core.Deps
	cache *core.ByteLRU
}

func newSvc(d *core.Deps) *svc { return &svc{d: d, cache: core.NewByteLRU(CacheBytes)} }

// Register mounts GET /f/{name...} (plus the costlier GET /f/q/{query...}), the aliases /feed.xml
// and /feed.json, and registers the saved-search source q, the OpenAPI fragment and the llms
// section. Sources register themselves through d.RegisterFeed; the renderer resolves the longest
// registered prefix of the path and hands the remainder to the source as sub.
func Register(mux *http.ServeMux, d *core.Deps) { newSvc(d).register(mux) }

func (s *svc) register(mux *http.ServeMux) {
	s.d.RegisterFeed("q", s.searchFeed)
	mux.HandleFunc("GET /f/{name...}", s.serve)
	mux.HandleFunc("GET /f/q/{query...}", s.serve)
	mux.HandleFunc("GET /feed.xml", alias("/f/kb.atom"))
	mux.HandleFunc("GET /feed.json", alias("/f/kb.json"))
	s.d.RegisterScope("GET /f/{name...}", "*")
	s.d.RegisterScope("GET /f/q/{query...}", "*")
	s.d.RegisterCost("GET /f/q/{query...}", 2)
	s.d.RegisterOpenAPI(openAPI)
	s.d.RegisterLLMSFull("feeds", func(context.Context) string { return llmsText })
}

// Path is the relative feed path of a name ("kb/react", Atom -> "/f/kb/react.atom").
func Path(name string, f Format) string {
	segs := strings.Split(name, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return "/f/" + strings.Join(segs, "/") + "." + string(f)
}

// Links returns the <link rel=alternate> tags (Atom + JSON Feed) a page head carries for a feed name.
func Links(name string) []doc.Link {
	n := doc.SafeLine(name)
	return []doc.Link{
		{Rel: "alternate", Type: linkTypes[Atom], Href: Path(name, Atom), Title: n + " feed"},
		{Rel: "alternate", Type: linkTypes[JSON], Href: Path(name, JSON), Title: n + " feed (JSON)"},
	}
}

// alias answers 301 to target, keeping the query string (public, max-age=86400).
func alias(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { redirect(w, r, target) }
}

func redirect(w http.ResponseWriter, r *http.Request, target string) {
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	h := w.Header()
	h.Set("Cache-Control", "public, max-age=86400")
	h.Set("Location", target)
	w.WriteHeader(http.StatusMovedPermanently)
}

// splitFormat strips the format suffix of the last path segment: ("kb/react.atom") -> ("kb/react",
// Atom); unknown or missing suffixes come back with Format "".
func splitFormat(rest string) (string, Format) {
	last := rest
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		last = rest[i+1:]
	}
	if i := strings.LastIndexByte(last, '.'); i > 0 {
		if f, ok := suffixes[last[i:]]; ok {
			return rest[:len(rest)-len(last)+i], f
		}
	}
	return rest, ""
}

func checkName(name string) error {
	if name == "" || len(name) > maxName || !doc.OneLine(name) {
		return core.Bad("feed name")
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return core.Bad("feed name")
		}
	}
	return nil
}

// lookup resolves the longest registered prefix of name; sub is the remainder.
func (s *svc) lookup(name string) (fn core.FeedFn, base, sub string, ok bool) {
	feeds := s.d.Feeds()
	segs := strings.Split(name, "/")
	for i := len(segs); i > 0; i-- {
		base = strings.Join(segs[:i], "/")
		if fn, ok = feeds[base]; ok {
			return fn, base, strings.Join(segs[i:], "/"), true
		}
	}
	return nil, "", "", false
}

type params struct {
	n     int
	since time.Time
}

func parseParams(r *http.Request) (params, error) {
	p := params{n: DefaultN}
	q := r.URL.Query()
	if v := strings.TrimSpace(q.Get("n")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return p, core.Bad("n must be 1..50")
		}
		p.n = min(n, MaxItems)
	}
	if v := strings.TrimSpace(q.Get("since")); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return p, core.Bad("since must be RFC3339")
		}
		p.since = t.UTC()
	}
	return p, nil
}

// query is the canonical query string of the non-default parameters ("" when none).
func (p params) query() string {
	var parts []string
	if p.n != DefaultN {
		parts = append(parts, "n="+strconv.Itoa(p.n))
	}
	if !p.since.IsZero() {
		parts = append(parts, "since="+url.QueryEscape(p.since.Format(time.RFC3339)))
	}
	if len(parts) == 0 {
		return ""
	}
	return "?" + strings.Join(parts, "&")
}

func (s *svc) serve(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/f/")
	name, f := splitFormat(rest)
	if f == "" {
		if name == "" {
			name = "kb"
		}
		if err := checkName(name); err != nil {
			doc.Fail(w, r, err)
			return
		}
		redirect(w, r, Path(name, Atom))
		return
	}
	if err := checkName(name); err != nil {
		doc.Fail(w, r, err)
		return
	}
	fn, base, sub, ok := s.lookup(name)
	if !ok {
		doc.Fail(w, r, core.E(404, "notfound", "no feed "+cutBytes(name, 80)))
		return
	}
	p, err := parseParams(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	key := r.URL.Path + "\x00" + p.query()
	shed := s.d.Shed(r, "feeds")
	if b, ok := s.cache.Get(key); ok && !(shed && base == "q") {
		s.write(w, r, b, base, sub, f, p)
		return
	}
	if shed {
		w.Header().Set("Retry-After", "30")
		doc.Fail(w, r, core.ErrBusy("feeds"))
		return
	}
	want := p.n
	if !p.since.IsZero() {
		want = MaxItems // the source has no since filter: take the full window, filter, then cut
	}
	items, err := fn(r.Context(), sub, want)
	if err != nil {
		var ae *core.APIError
		if errors.As(err, &ae) && ae.Status == 503 && w.Header().Get("Retry-After") == "" {
			w.Header().Set("Retry-After", "2")
		}
		doc.Fail(w, r, err)
		return
	}
	m := newMeta(base, sub, f, p, normalize(items, p))
	b := pack(m.updated, m.render())
	s.cache.Put(key, b, CacheTTL)
	s.write(w, r, b, base, sub, f, p)
}

// write serves a packed cache value through doc.ServeStatic with the alternate-format Link header.
func (s *svc) write(w http.ResponseWriter, r *http.Request, b []byte, base, sub string, f Format, p params) {
	mod, body := unpack(b)
	name := base
	if sub != "" {
		name += "/" + sub
	}
	w.Header().Add("Link", doc.LinkHeader([]doc.Link{{Rel: "alternate", Type: linkTypes[other(f)], Href: Path(name, other(f)) + p.query()}}, true))
	doc.ServeStatic(w, r, mod, body, contentTypes[f])
}

func other(f Format) Format {
	if f == Atom {
		return JSON
	}
	return Atom
}

// pack prefixes body with the feed's max updated time (unix seconds) so one cache value carries
// both the Last-Modified and the bytes; unpack reverses it.
func pack(mod time.Time, body []byte) []byte {
	b := make([]byte, 8, 8+len(body))
	if !mod.IsZero() {
		binary.BigEndian.PutUint64(b, uint64(mod.Unix()))
	}
	return append(b, body...)
}

func unpack(b []byte) (time.Time, []byte) {
	if len(b) < 8 {
		return time.Time{}, nil
	}
	var mod time.Time
	if s := binary.BigEndian.Uint64(b); s != 0 {
		mod = time.Unix(int64(s), 0).UTC()
	}
	return mod, b[8:]
}

// normalize applies the renderer's own guards to a source's items: every text through SafeLine,
// summary <= 500 B, items without a summary, id or usable link dropped, relative links made
// absolute, zero times filled, the since filter, then the first n.
func normalize(items []core.FeedItem, p params) []core.FeedItem {
	out := make([]core.FeedItem, 0, min(len(items), p.n))
	base := doc.Base()
	for _, it := range items {
		it.Summary = cutBytes(doc.SafeLine(strings.TrimSpace(it.Summary)), MaxSummary)
		it.ID = doc.SafeLine(strings.TrimSpace(it.ID))
		it.URL = absURL(base, strings.TrimSpace(it.URL))
		if it.Summary == "" || it.ID == "" || len(it.ID) > maxID || it.URL == "" {
			continue
		}
		if it.Title = cutBytes(doc.SafeLine(strings.TrimSpace(it.Title)), maxTitle); it.Title == "" {
			it.Title = it.ID
		}
		if it.Updated.IsZero() {
			it.Updated = it.Published
		}
		if it.Published.IsZero() {
			it.Published = it.Updated
		}
		if it.Updated.IsZero() {
			it.Updated, it.Published = epoch, epoch
		}
		it.Updated, it.Published = it.Updated.UTC(), it.Published.UTC()
		if !p.since.IsZero() && !it.Updated.After(p.since) {
			continue
		}
		it.Author = cutBytes(doc.SafeLine(strings.TrimSpace(it.Author)), maxAuthor)
		it.Tags = cleanTags(it.Tags)
		out = append(out, it)
		if len(out) == p.n {
			break
		}
	}
	return out
}

// absURL accepts a site-relative path or an http(s) URL; anything else drops the item.
func absURL(base, u string) string {
	switch {
	case u == "" || len(u) > maxURL || !doc.OneLine(u):
		return ""
	case strings.HasPrefix(u, "/"):
		return base + u
	case strings.HasPrefix(u, "https://"), strings.HasPrefix(u, "http://"):
		return u
	}
	return ""
}

func cleanTags(tags []string) []string {
	out := make([]string, 0, min(len(tags), maxTags))
	for _, t := range tags {
		if t = cutBytes(doc.SafeLine(strings.TrimSpace(t)), maxTag); t != "" {
			out = append(out, t)
		}
		if len(out) == maxTags {
			break
		}
	}
	return out
}

// cutBytes cuts s to at most n bytes on a rune boundary.
func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return strings.TrimSpace(s[:n])
}

// meta is one rendered feed's header: what both formats share.
type meta struct {
	base, sub string
	name      string
	idBase    string // namespace of the entry ids in tag: URIs (q renders KB entries: kb/<id>)
	f         Format
	title     string
	home      string
	self, alt string
	updated   time.Time // max item Updated; zero for an empty feed
	items     []core.FeedItem
}

func newMeta(base, sub string, f Format, p params, items []core.FeedItem) *meta {
	m := &meta{base: base, sub: sub, name: base, idBase: base, f: f, items: items}
	if sub != "" {
		m.name += "/" + sub
	}
	if base == "q" {
		m.idBase = "kb" // the same entry keeps one id across the kb, kb/<tag> and q/<query> feeds
	}
	m.title = host() + ": " + cutBytes(m.name, 120)
	m.home = homeFor(base, sub)
	m.self = doc.Base() + Path(m.name, f) + p.query()
	m.alt = doc.Base() + Path(m.name, other(f)) + p.query()
	for _, it := range items {
		if it.Updated.After(m.updated) {
			m.updated = it.Updated
		}
	}
	return m
}

func (m *meta) render() []byte {
	if m.f == JSON {
		return renderJSON(m)
	}
	return renderAtom(m)
}

// feedUpdated is the feed-level updated time (the Unix epoch for an empty feed: stable, valid).
func (m *meta) feedUpdated() time.Time {
	if m.updated.IsZero() {
		return epoch
	}
	return m.updated
}

// host is the site hostname used in tag: URIs and feed titles.
func host() string {
	if u, err := url.Parse(doc.Base()); err == nil && u.Host != "" {
		return u.Host
	}
	return "agents.ekaii.fr"
}

// tagURI is the Atom entry id: tag:<host>,2026:<name>/<id> (the id's own "<name>/" prefix is
// not doubled, e.g. tasks publish ids "t/<n>").
func tagURI(base, id string) string {
	p := id
	if !strings.HasPrefix(id, base+"/") {
		p = base + "/" + id
	}
	return "tag:" + host() + "," + tagYear + ":" + p
}

// homeFor is the HTML page a feed mirrors (9.3 names); unknown names fall back to /<name>[/<sub>].
func homeFor(base, sub string) string {
	b := doc.Base()
	esc := url.PathEscape(sub)
	switch base {
	case "kb":
		if sub == "" {
			return b + "/kb/"
		}
		return b + "/tag/" + esc
	case "a", "v", "s", "q", "st", "ps":
		return b + "/" + base + "/" + esc
	case "t":
		return b + "/v1/t"
	case "ch":
		return b + "/cutoff"
	case "wanted":
		return b + "/wanted"
	case "log":
		return b + "/changelog"
	case "p":
		return b + "/gov"
	}
	if sub == "" {
		return b + "/" + base
	}
	return b + "/" + base + "/" + esc
}

// authorURL is the pseudonymous author's page when the author is an agent id ("" for seed etc.).
func authorURL(author string) string {
	if core.ValidIDPrefix(author, 'a') {
		return doc.Base() + "/a/" + author
	}
	return ""
}
