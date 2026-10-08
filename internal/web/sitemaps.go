// Package web also owns robots.txt and the sitemap tree (9.2): a /sitemap.xml index whose children
// are served under /sitemaps/{file} - a fixed pages.xml, monthly kb-YYYY-MM.xml, and every child a
// package registers through d.RegisterSitemap. The whole set is regenerated into memory by the
// janitor every 5 min and served with ETag/Last-Modified via doc.ServeStatic.
package web

import (
	"context"
	"encoding/xml"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
)

// regenEvery is how often the janitor refreshes the in-memory sitemap set (9.2).
const regenEvery = 5 * time.Minute

// fixedPages is pages.xml (9.2 + REV3): the stable public pages, never /wanted or /quarantine.
var fixedPages = []string{
	"/", "/kb/", "/worker", "/legal", "/export/", "/llms.txt", "/AGENTS.md",
	"/openapi.json", "/svc", "/gov", "/changelog", "/cutoff", "/status",
	"/roadmap", "/tags", "/skills", "/limits", "/brief", "/ci", "/errsig",
	"/transparency", "/rand/about", "/inj/about",
}

type smap struct {
	d       *core.Deps
	started time.Time
	mu      sync.Mutex // serializes rebuild
	state   atomic.Pointer[smState]
}

// smState is one regenerated snapshot: the rendered robots/index/txt bytes plus each child file.
type smState struct {
	at       time.Time
	robots   []byte
	index    []byte
	indexMod time.Time
	txt      []byte // /sitemap.txt: the plain URL list of the pages child (REV3)
	txtMod   time.Time
	files    map[string]smFile
}

type smFile struct {
	body []byte
	mod  time.Time
}

// --- sitemap XML shapes (encoding/xml escapes every text node) ---------------------------------

type urlset struct {
	XMLName xml.Name `xml:"http://www.sitemaps.org/schemas/sitemap/0.9 urlset"`
	URLs    []smURL  `xml:"url"`
}

type smURL struct {
	Loc     string `xml:"loc"`
	LastMod string `xml:"lastmod,omitempty"`
}

type sitemapIndex struct {
	XMLName  xml.Name `xml:"http://www.sitemaps.org/schemas/sitemap/0.9 sitemapindex"`
	Sitemaps []smRef  `xml:"sitemap"`
}

type smRef struct {
	Loc     string `xml:"loc"`
	LastMod string `xml:"lastmod,omitempty"`
}

// RegisterSitemaps mounts GET /robots.txt, /sitemap.xml, /sitemap.txt and /sitemaps/{file}, builds
// the first snapshot, and registers the 5-min janitor that regenerates it (9.2). It returns the
// instance (integration ignores it; tests force a rebuild through it).
func RegisterSitemaps(mux *http.ServeMux, d *core.Deps) *smap {
	s := &smap{d: d, started: time.Now().UTC()}
	_ = s.rebuild(context.Background())
	routes := []struct {
		pat string
		fn  http.HandlerFunc
	}{
		{"GET /robots.txt", s.robots},
		{"GET /sitemap.xml", s.sitemapXML},
		{"GET /sitemap.txt", s.sitemapTXT},
		{"GET /sitemaps/{file}", s.child},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.fn)
		d.RegisterScope(rt.pat, "*")
		d.RegisterCost(rt.pat, 0.2)
	}
	d.Janitor.Add("web_sitemaps", s.regen)
	return s
}

// regen is the janitor task: it rebuilds only when the snapshot is older than regenEvery.
func (s *smap) regen(ctx context.Context) error {
	if st := s.state.Load(); st != nil && time.Since(st.at) < regenEvery {
		return nil
	}
	return s.rebuild(ctx)
}

// load returns the current snapshot, building one lazily if none exists yet.
func (s *smap) load(ctx context.Context) *smState {
	if st := s.state.Load(); st != nil {
		return st
	}
	_ = s.rebuild(ctx)
	if st := s.state.Load(); st != nil {
		return st
	}
	return &smState{robots: buildRobots(doc.Base()), files: map[string]smFile{}}
}

// rebuild regenerates the whole set from the DB and registry into memory. Child errors are skipped
// (the snapshot still publishes); the first is returned so the janitor logs it.
func (s *smap) rebuild(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	base := doc.Base()
	files := make(map[string]smFile)
	var refs []smRef
	idxMod := s.started
	add := func(name string, urls []core.SitemapURL) {
		mod := maxMod(urls, s.started)
		files[name] = smFile{renderURLset(urls), mod}
		refs = append(refs, smRef{Loc: base + "/sitemaps/" + name + ".xml", LastMod: iso(mod)})
		if mod.After(idxMod) {
			idxMod = mod
		}
	}

	// pages.xml - fixed public pages, lastmod = process start (no per-page writes).
	purls := make([]core.SitemapURL, 0, len(fixedPages))
	for _, p := range fixedPages {
		purls = append(purls, core.SitemapURL{Loc: base + p, LastMod: s.started})
	}
	add("pages", purls)

	var firstErr error
	keep := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	// kb-YYYY-MM.xml - indexable entries grouped by created month (<= 5000/file, lastmod =
	// greatest(created, confirmed_at)).
	if months, err := kb.IndexableMonths(ctx, s.d.DB); err != nil {
		keep(err)
	} else {
		for _, ym := range months {
			urls, err := kb.IndexableByMonth(ctx, s.d.DB, ym)
			if err != nil {
				keep(err)
				continue
			}
			if len(urls) == 0 {
				continue
			}
			add("kb-"+ym, urls)
		}
	}

	// Registry children (libs, tags, answers, svc, spaces, claims, att, export, hubs, tasks, gov,
	// st, agents, skills, ...): each lists only rows that pass trust.Indexable.
	for name, fn := range s.d.Sitemaps() {
		urls, err := fn(ctx)
		if err != nil {
			keep(err)
			continue
		}
		add(name, urls)
	}

	sort.Slice(refs, func(i, j int) bool { return refs[i].Loc < refs[j].Loc })
	s.state.Store(&smState{
		at:       time.Now(),
		robots:   buildRobots(base),
		index:    renderIndex(refs),
		indexMod: idxMod,
		txt:      pagesTxt(purls),
		txtMod:   s.started,
		files:    files,
	})
	return firstErr
}

func (s *smap) sitemapXML(w http.ResponseWriter, r *http.Request) {
	st := s.load(r.Context())
	doc.ServeStatic(w, r, st.indexMod, st.index, "application/xml")
}

func (s *smap) sitemapTXT(w http.ResponseWriter, r *http.Request) {
	st := s.load(r.Context())
	doc.ServeStatic(w, r, st.txtMod, st.txt, "text/plain; charset=utf-8")
}

// child serves one /sitemaps/{file}; an unknown file is 404.
func (s *smap) child(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutSuffix(r.PathValue("file"), ".xml")
	if !ok || name == "" {
		http.NotFound(w, r)
		return
	}
	st := s.load(r.Context())
	f, ok := st.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	doc.ServeStatic(w, r, f.mod, f.body, "application/xml")
}

// --- rendering helpers -------------------------------------------------------------------------

func iso(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// maxMod is the greatest LastMod across urls, or fallback when none carry one.
func maxMod(urls []core.SitemapURL, fallback time.Time) time.Time {
	var m time.Time
	for _, u := range urls {
		if u.LastMod.After(m) {
			m = u.LastMod
		}
	}
	if m.IsZero() {
		return fallback
	}
	return m
}

func renderURLset(urls []core.SitemapURL) []byte {
	set := urlset{URLs: make([]smURL, 0, len(urls))}
	for _, u := range urls {
		set.URLs = append(set.URLs, smURL{Loc: u.Loc, LastMod: iso(u.LastMod)})
	}
	b, err := xml.Marshal(set)
	if err != nil {
		b = []byte(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>`)
	}
	return append([]byte(xml.Header), append(b, '\n')...)
}

func renderIndex(refs []smRef) []byte {
	b, err := xml.Marshal(sitemapIndex{Sitemaps: refs})
	if err != nil {
		b = []byte(`<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></sitemapindex>`)
	}
	return append([]byte(xml.Header), append(b, '\n')...)
}

func pagesTxt(urls []core.SitemapURL) []byte {
	var b strings.Builder
	for _, u := range urls {
		b.WriteString(u.Loc)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}
