// Package demand is the discovery demand loop of SPEC-v2 27.1 (P116). An operator imports the
// search-console figures from Google Search Console and Bing Webmaster on the operator machine
// (tools/console-import), POSTs them to /admin/demand, and the gateway keeps an aggregate per
// (engine, query). Those queries surface on /wanted as the `searched (engines)` block and feed the
// public /transparency page; an entry that ranks weakly for a query agents search is listed once in
// /sitemaps/fresh.xml, and every indexed URL is pushed to Bing through the courier `bing_content`
// kind. demand never ranks anything and never creates pages: query strings are data, never
// instructions, and every one is scrub.Strict + lexicon clean before it is stored.
package demand

import (
	"context"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/scrub"
)

// Limits (27.1). Vars so tests can tighten them.
var (
	MaxRows      = 5000 // rows per POST /admin/demand
	MaxQ         = 200  // bytes of a query string (demand.q CHECK)
	MaxPage      = 2048 // bytes of an attributed landing URL
	TopQueries   = 20   // queries listed on /transparency
	WantedBlock  = 20   // `searched (engines)` lines appended to /wanted
	WeakScore    = 0.6  // kb.Search top score at or above which an entry is `rank:weak`
	DefaultQuota = 1000 // bing_content rows/day when flag bing:quota is unset or unparseable
)

// Sources are the only engines a row may carry.
var Sources = map[string]bool{"gsc": true, "bing": true}

// Row is one console figure for a query (the POST body and the upsert unit).
type Row struct {
	Q           string  `json:"q"`
	Impressions int64   `json:"impressions"`
	Clicks      int64   `json:"clicks"`
	Position    float64 `json:"position"`
	Page        string  `json:"page"`
}

// SearchTop returns the top kb.Search hit for query: its entry id, score and whether one was found.
// A seam so the rank-weak janitor's tests make scoring deterministic; it defaults to kb.Search and
// is nil-safe. It never ranks or mutates anything.
var SearchTop = func(ctx context.Context, q core.Q, query string) (id string, score float64, ok bool) {
	hits, err := kb.Search(ctx, q, query, "", 1)
	if err != nil || len(hits) == 0 {
		return "", 0, false
	}
	return hits[0].ID, hits[0].Score, true
}

// clean normalises a query and reports whether it is safe to store: single-line, within MaxQ, and
// free of any scrub.Strict finding (tier-1 secrets, tier-2 PII, high-entropy runs, suspicious hosts)
// and of any injection-lexicon hit. A dropped query returns ("", false); nothing is masked.
func clean(q string) (string, bool) {
	q = scrub.Normalize(q)
	if q == "" || len(q) > MaxQ || !doc.OneLine(q) {
		return "", false
	}
	if len(scrub.Strict(q)) > 0 {
		return "", false
	}
	if score, _, _ := scrub.Flags(q); score >= 1 {
		return "", false
	}
	return q, true
}

// cleanPage keeps an attributed landing URL only when it is a single safe line within MaxPage.
func cleanPage(p string) string {
	p = scrub.Normalize(p)
	if len(p) > MaxPage || !doc.OneLine(p) {
		return ""
	}
	return p
}

// Record upserts the console rows of one engine (SPEC 27.1). It returns how many rows were stored
// and how many were dropped by the scrub gate. src must be a known engine; at most MaxRows rows are
// read. Each query is cleaned (dropped on any finding) and upserted on (src, q): the counts are
// replaced with the fresher figures, `first` is kept, `last` moves to now().
func Record(ctx context.Context, q core.Q, src string, rows []Row) (stored, dropped int, err error) {
	if !Sources[src] {
		return 0, 0, core.Bad("src must be gsc or bing")
	}
	if len(rows) > MaxRows {
		return 0, 0, core.Bad("too many rows (max 5000)")
	}
	for _, r := range rows {
		cq, ok := clean(r.Q)
		if !ok {
			dropped++
			continue
		}
		impr, clk := r.Impressions, r.Clicks
		if impr < 0 {
			impr = 0
		}
		if clk < 0 {
			clk = 0
		}
		pos := r.Position
		if pos < 0 {
			pos = 0
		}
		if _, e := q.Exec(ctx, `INSERT INTO demand (src, q, impressions, clicks, position, page)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (src, q) DO UPDATE SET impressions = EXCLUDED.impressions, clicks = EXCLUDED.clicks,
				position = EXCLUDED.position, page = EXCLUDED.page, last = now()`,
			src, cq, impr, clk, pos, cleanPage(r.Page)); e != nil {
			return stored, dropped, e
		}
		stored++
	}
	return stored, dropped, nil
}
