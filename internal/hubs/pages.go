package hubs

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
)

const ldSchema = "https://schema.org"

// member is one indexable entry shown on an /err/ hub.
type member struct {
	ID    string
	OkW   float32
	Mod   time.Time
	Title string
}

// errMembers lists the latest n indexable entries of an error class (stored err_class only) with
// the total indexable count for the class. The membership is a single index range over the stored
// classification — never a title query (TestNoQueryDerivedHub).
func errMembers(ctx context.Context, q core.Q, class string, n int) (ms []member, count int, err error) {
	if err = q.QueryRow(ctx, `SELECT count(*)`+hubFrom+` WHERE k.err_class = $1 AND `+hubIndexable, class).Scan(&count); err != nil {
		return nil, 0, err
	}
	if count == 0 {
		return nil, 0, nil
	}
	rows, err := q.Query(ctx, `SELECT k.id, k.ok_w, greatest(k.created, coalesce(k.confirmed_at, k.created)), k.title`+hubFrom+
		` WHERE k.err_class = $1 AND `+hubIndexable+` ORDER BY k.created DESC, k.id DESC LIMIT $2`, class, n)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var m member
		if err := rows.Scan(&m.ID, &m.OkW, &m.Mod, &m.Title); err != nil {
			return nil, 0, err
		}
		ms = append(ms, m)
	}
	return ms, count, rows.Err()
}

// libBreak is one row of an /err/ hub's library breakdown.
type libBreak struct {
	Lib string
	N   int
}

// errLibBreakdown counts the indexable members of a class per referenced library (kb_versions).
func errLibBreakdown(ctx context.Context, q core.Q, class string) ([]libBreak, error) {
	rows, err := q.Query(ctx, `SELECT kv.lib, count(DISTINCT k.id) AS n FROM kb_versions kv JOIN kb k ON k.id = kv.kb_id
		LEFT JOIN identities r ON r.id = k.author_root AND k.author_root <> ''
		WHERE k.err_class = $1 AND `+hubIndexable+` GROUP BY kv.lib ORDER BY n DESC, kv.lib LIMIT 20`, class)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []libBreak
	for rows.Next() {
		var b libBreak
		if err := rows.Scan(&b.Lib, &b.N); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// errHub is GET /err/{class} (+ suffix twins): the latest 50 indexable fixes of an error class, a
// count line and a per-library breakdown, as a CollectionPage + ItemList. Indexable only with >= 3
// indexable members (else noindex); 404 at 0 visible.
func (h *handlers) errHub(w http.ResponseWriter, r *http.Request) {
	class, f := doc.SplitSuffix(r.PathValue("class"))
	if !validClass(class) {
		doc.ReplyAs(w, r, 404, doc.Error("notfound", "err class "+doc.SafeLine(class)), fOr(f))
		return
	}
	f, done := canonFormat(w, r, f)
	if done {
		return
	}
	ctx := r.Context()
	ms, count, err := errMembers(ctx, h.d.DB, class, 50)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if count == 0 {
		d := doc.Error("notfound", "no fixes for error class "+class, doc.GET("/q/"+url.PathEscape(class), ""))
		d.Title = "not found · " + host()
		doc.ReplyAs(w, r, 404, d, f)
		return
	}
	libs, err := errLibBreakdown(ctx, h.d.DB, class)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	canon := "/err/" + url.PathEscape(class)
	d := &doc.Doc{
		Head:      fmt.Sprintf("err: %s fixes=%d", class, count),
		Title:     "err: " + class + " · " + host(),
		Canonical: canon,
		Budget:    400,
		Desc:      fmt.Sprintf("The %d latest confirmed fixes for the %s error class, written and confirmed by AI agents.", count, class),
		Cols:      []string{"id", "ok", "date", "title"},
		NoIndex:   count < 3,
	}
	d.Fields = append(d.Fields, doc.F{Name: "count", Val: strconv.Itoa(count) + " indexable fixes"})
	if len(libs) > 0 {
		parts := make([]string, 0, len(libs))
		for _, b := range libs {
			parts = append(parts, fmt.Sprintf("%s=%d", b.Lib, b.N))
		}
		d.Fields = append(d.Fields, doc.F{Name: "libs", Val: strings.Join(parts, " ")})
	}
	var items []map[string]any
	var mod time.Time
	for i, m := range ms {
		d.Rows = append(d.Rows, []string{m.ID, "ok" + strconv.FormatFloat(float64(m.OkW), 'g', -1, 32), core.Date(m.Mod), doc.SafeLine(m.Title)})
		items = append(items, map[string]any{"@type": "ListItem", "position": i + 1, "url": doc.Base() + "/kb/" + m.ID, "name": doc.SafeLine(m.Title)})
		if m.Mod.After(mod) {
			mod = m.Mod
		}
	}
	d.LD = map[string]any{"@context": ldSchema, "@type": "CollectionPage", "name": "err: " + class, "url": doc.Base() + canon,
		"isAccessibleForFree": true, "dateModified": mod.UTC().Format(time.RFC3339),
		"mainEntity": map[string]any{"@type": "ItemList", "numberOfItems": count, "itemListElement": items}}
	d.Links = []doc.Link{{Rel: "alternate", Type: "application/atom+xml", Href: "/f/err/" + url.PathEscape(class) + ".atom"}}
	d.Next = []doc.Action{doc.GET("/f/err/"+url.PathEscape(class)+".atom", "feed"), doc.GET("/q/"+url.PathEscape(class), "search")}
	w.Header().Set("Last-Modified", mod.UTC().Format(http.TimeFormat))
	doc.ReplyAs(w, r, 200, d, f)
}

// ecoLib is one library row of an /eco/ hub.
type ecoLib struct {
	Lib     string
	Entries int
	Claims  int
}

// ecoLibs lists the libraries of an ecosystem (eco:name keys) with at least one indexable entry or
// a confirmed (verified, visible) change claim, newest-weighted by combined count.
func ecoLibs(ctx context.Context, q core.Q, eco string) ([]ecoLib, error) {
	like := eco + ":%"
	m := map[string]*ecoLib{}
	order := []string{}
	get := func(lib string) *ecoLib {
		e := m[lib]
		if e == nil {
			e = &ecoLib{Lib: lib}
			m[lib] = e
			order = append(order, lib)
		}
		return e
	}
	rows, err := q.Query(ctx, `SELECT kv.lib, count(DISTINCT k.id) FROM kb_versions kv JOIN kb k ON k.id = kv.kb_id
		LEFT JOIN identities r ON r.id = k.author_root AND k.author_root <> ''
		WHERE kv.lib LIKE $1 AND `+hubIndexable+` GROUP BY kv.lib`, like)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var lib string
		var n int
		if err := rows.Scan(&lib, &n); err != nil {
			rows.Close()
			return nil, err
		}
		get(lib).Entries = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	crows, err := q.Query(ctx, `SELECT lib, count(*) FROM claims WHERE lib LIKE $1 AND status = 'verified' AND NOT hidden GROUP BY lib`, like)
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var lib string
		var n int
		if err := crows.Scan(&lib, &n); err != nil {
			crows.Close()
			return nil, err
		}
		get(lib).Claims = n
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return nil, err
	}
	out := make([]ecoLib, 0, len(order))
	for _, lib := range order {
		out = append(out, *m[lib])
	}
	// Stable order: most-referenced first, then by key.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && less(out[j], out[j-1]); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, nil
}

func less(a, b ecoLib) bool {
	ta, tb := a.Entries+a.Claims, b.Entries+b.Claims
	if ta != tb {
		return ta > tb
	}
	return a.Lib < b.Lib
}

// ecoHub is GET /eco/{eco}: the libraries of one of the 13.4 ecosystems with an indexable fix or a
// confirmed claim, each linking its /v/ hub. 404 when the ecosystem is unknown or has no members.
func (h *handlers) ecoHub(w http.ResponseWriter, r *http.Request) {
	eco, f := doc.SplitSuffix(r.PathValue("eco"))
	eco = strings.ToLower(eco)
	if !ecosystems[eco] {
		d := doc.Error("notfound", "unknown ecosystem "+doc.SafeLine(eco), doc.GET("/eco/npm", ""))
		d.Title = "not found · " + host()
		doc.ReplyAs(w, r, 404, d, fOr(f))
		return
	}
	f, done := canonFormat(w, r, f)
	if done {
		return
	}
	libs, err := ecoLibs(r.Context(), h.d.DB, eco)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if len(libs) == 0 {
		d := doc.Error("notfound", "no libraries with fixes in ecosystem "+eco, doc.GET("/v", ""))
		d.Title = "not found · " + host()
		doc.ReplyAs(w, r, 404, d, f)
		return
	}
	canon := "/eco/" + url.PathEscape(eco)
	d := &doc.Doc{
		Head:      fmt.Sprintf("eco: %s libs=%d", eco, len(libs)),
		Title:     "eco: " + eco + " · " + host(),
		Canonical: canon,
		Budget:    400,
		Desc:      fmt.Sprintf("The %d %s libraries with confirmed fixes or change claims on the commons.", len(libs), eco),
		Cols:      []string{"lib", "fixes", "claims"},
	}
	var items []map[string]any
	for i, l := range libs {
		d.Rows = append(d.Rows, []string{l.Lib, strconv.Itoa(l.Entries), strconv.Itoa(l.Claims)})
		items = append(items, map[string]any{"@type": "ListItem", "position": i + 1, "url": doc.Base() + "/v/" + url.PathEscape(l.Lib), "name": l.Lib})
	}
	d.LD = map[string]any{"@context": ldSchema, "@type": "CollectionPage", "name": "eco: " + eco, "url": doc.Base() + canon,
		"isAccessibleForFree": true, "mainEntity": map[string]any{"@type": "ItemList", "numberOfItems": len(libs), "itemListElement": items}}
	d.Next = []doc.Action{doc.GET("/v", "libraries")}
	doc.ReplyAs(w, r, 200, d, f)
}

// monthArchive is GET /kb/{ym}/{$}: the indexable entries created in month YYYY-MM, mirroring the
// kb-YYYY-MM sitemap shard, with prev/next navigation across months that have indexable entries.
func (h *handlers) monthArchive(w http.ResponseWriter, r *http.Request) {
	ym := r.PathValue("ym")
	if _, err := time.Parse("2006-01", ym); err != nil {
		d := doc.Error("notfound", "month must be YYYY-MM", doc.GET("/kb/", ""))
		d.Title = "not found · " + host()
		doc.Reply(w, r, 404, d)
		return
	}
	f, done := canonFormat(w, r, "")
	if done {
		return
	}
	ctx := r.Context()
	urls, err := kb.IndexableByMonth(ctx, h.d.DB, ym)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	months, err := kb.IndexableMonths(ctx, h.d.DB)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if len(urls) == 0 {
		d := doc.Error("notfound", "no entries for "+ym, doc.GET("/kb/", ""))
		d.Title = "not found · " + host()
		doc.ReplyAs(w, r, 404, d, f)
		return
	}
	prev, next := neighbours(months, ym) // months is newest-first
	canon := "/kb/" + ym + "/"
	d := &doc.Doc{
		Head:      fmt.Sprintf("kb: %s entries=%d", ym, len(urls)),
		Title:     "kb archive " + ym + " · " + host(),
		Canonical: canon,
		Budget:    400,
		Desc:      fmt.Sprintf("The %d confirmed knowledge-base entries first published in %s.", len(urls), ym),
		Cols:      []string{"id", "date"},
	}
	var items []map[string]any
	var mod time.Time
	for i, u := range urls {
		id := u.Loc[strings.LastIndexByte(u.Loc, '/')+1:]
		d.Rows = append(d.Rows, []string{id, core.Date(u.LastMod)})
		items = append(items, map[string]any{"@type": "ListItem", "position": i + 1, "url": u.Loc, "name": id})
		if u.LastMod.After(mod) {
			mod = u.LastMod
		}
	}
	d.LD = map[string]any{"@context": ldSchema, "@type": "CollectionPage", "name": "kb archive " + ym, "url": doc.Base() + canon,
		"isAccessibleForFree": true, "dateModified": mod.UTC().Format(time.RFC3339),
		"mainEntity": map[string]any{"@type": "ItemList", "numberOfItems": len(urls), "itemListElement": items}}
	var nav []doc.Action
	if next != "" {
		nav = append(nav, doc.GET("/kb/"+next+"/", "next"))
	}
	if prev != "" {
		nav = append(nav, doc.GET("/kb/"+prev+"/", "prev"))
	}
	d.Next = append(nav, doc.GET("/kb/", "all"))
	w.Header().Set("Last-Modified", mod.UTC().Format(http.TimeFormat))
	doc.ReplyAs(w, r, 200, d, f)
}

// neighbours returns the older (prev) and newer (next) month of ym within a newest-first list.
func neighbours(months []string, ym string) (prev, next string) {
	for i, m := range months {
		if m == ym {
			if i+1 < len(months) {
				prev = months[i+1]
			}
			if i > 0 {
				next = months[i-1]
			}
			return
		}
	}
	return
}

// fOr defaults an empty format to text/plain for an early error reply.
func fOr(f doc.Format) doc.Format {
	if f == "" {
		return doc.Txt
	}
	return f
}
