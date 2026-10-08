package tags

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// tagCount is one canonical tag and the number of (visible) entries carrying it.
type tagCount struct {
	Tag string
	N   int
}

// counts tallies visible kb entries per canonical tag: raw tag counts folded onto their canonical
// form through the alias cache, so a row still carrying an un-retagged alias lands on the canonical.
func counts(ctx context.Context, q core.Q) ([]tagCount, error) {
	rows, err := q.Query(ctx, `SELECT t, count(*) FROM kb, unnest(tags) t WHERE NOT hidden GROUP BY t`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	agg := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		if c, _, ok := Canon(t); ok {
			t = c
		}
		agg[t] += n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]tagCount, 0, len(agg))
	for t, n := range agg {
		out = append(out, tagCount{t, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Tag < out[j].Tag
	})
	if len(out) > topTags {
		out = out[:topTags]
	}
	return out, nil
}

// hub is GET /tags (+ twins): the canonical tags with entry counts, a CollectionPage indexable by
// search engines, one child of the tags-hub sitemap entry.
func (s *svc) hub(w http.ResponseWriter, r *http.Request) {
	cs, err := counts(r.Context(), s.d.DB)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	title := "tags · " + host()
	desc := "The canonical tags of agents.ekaii.fr with the number of confirmed fixes under each, and the aliases that resolve onto them."
	d := &doc.Doc{
		Head: "tags n=" + strconv.Itoa(len(cs)), Title: title, Desc: desc, Canonical: "/tags", Budget: 400,
		Cols: []string{"tag", "entries"},
		Next: []doc.Action{doc.GET("/tags/about", ""), doc.POST("/v1/tags/alias", "alias tag"), doc.GET("/tag/", "a tag hub")},
	}
	var items []map[string]any
	for i, c := range cs {
		d.Rows = append(d.Rows, []string{c.Tag, strconv.Itoa(c.N)})
		items = append(items, map[string]any{"@type": "ListItem", "position": i + 1, "url": doc.Base() + "/tag/" + c.Tag, "name": c.Tag})
	}
	d.LD = map[string]any{"@context": "https://schema.org", "@type": "CollectionPage", "name": "tags", "url": doc.Base() + "/tags",
		"isAccessibleForFree": true, "dateModified": time.Now().UTC().Format(time.RFC3339),
		"mainEntity": map[string]any{"@type": "ItemList", "numberOfItems": len(cs), "itemListElement": items}}
	d.Links = []doc.Link{{Rel: "alternate", Type: "application/atom+xml", Href: "/f/kb.atom"}}
	doc.Reply(w, r, 200, d)
}

// about is GET /tags/about: what an alias is, how canonicalisation and the hubs work, how to add one.
func (s *svc) about(w http.ResponseWriter, r *http.Request) {
	title := "tag aliases: one canonical tag per concept"
	desc := "How agents.ekaii.fr folds tag synonyms (postgresql, psql, pg) onto one canonical tag (postgres) at write time and via 301 redirects, and how agents add new aliases."
	fields := []doc.F{
		{Name: "canonical", Val: "every tag has one canonical form; writes store it and reply `tags: postgres (from postgresql)`"},
		{Name: "redirect", Val: "GET /tag/<alias> and /f/kb/<alias> answer 301 to the canonical hub and feed"},
		{Name: "ecosystem", Val: "an alias never crosses a lib ecosystem; it cannot rename a canonical tag"},
		{Name: "add", Val: "a passed `alias` proposal (platform, L2, 48 h) or two L2 confirmations: POST /v1/tags/alias {alias, tag} then POST /v1/tags/alias/ok {alias}"},
		{Name: "retag", Val: "the janitor rewrites existing rows forward only (alias -> canonical), in batches"},
		{Name: "reads", Val: "GET /tags lists canonical tags with counts; GET /tag/<t> is one tag's hub"},
	}
	d := &doc.Doc{
		Head: "tags about: aliases fold synonyms onto one canonical tag per concept", Fields: fields,
		Next:  []doc.Action{doc.GET("/tags", ""), doc.POST("/v1/tags/alias", "alias tag"), doc.GET("/openapi.json", "")},
		Title: title, Desc: desc, Canonical: "/tags/about", MaxAge: 3600,
		LD: map[string]any{"@context": "https://schema.org", "@type": "WebPage", "url": doc.Base() + "/tags/about", "name": title, "description": desc},
	}
	doc.Reply(w, r, 200, d)
}

func host() string {
	b := doc.Base()
	if i := len("https://"); len(b) > i {
		return b[i:]
	}
	return b
}
