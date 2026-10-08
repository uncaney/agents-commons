package demand

import (
	"context"
	"fmt"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// QStat is one demand query for /wanted and /transparency.
type QStat struct {
	Src         string
	Q           string
	Impressions int64
	Clicks      int64
	Position    float64
}

// topQueries returns the k queries with the most impressions, highest-demand first.
func topQueries(ctx context.Context, q core.Q, k int) ([]QStat, error) {
	if k <= 0 || k > 500 {
		k = 50
	}
	rows, err := q.Query(ctx, `SELECT src, q, impressions, clicks, position FROM demand
		ORDER BY impressions DESC, clicks DESC, q LIMIT $1`, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []QStat
	for rows.Next() {
		var s QStat
		if err := rows.Scan(&s.Src, &s.Q, &s.Impressions, &s.Clicks, &s.Position); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// WantedLines is know.WantedExtraFn: the `searched (engines)` block appended to GET /wanted, kind q,
// noindex (the page already is). A leading header line then one `q <query> …` line per top query.
func WantedLines(ctx context.Context, q core.Q) []string {
	stats, err := topQueries(ctx, q, WantedBlock)
	if err != nil || len(stats) == 0 {
		return nil
	}
	out := make([]string, 0, len(stats)+1)
	out = append(out, fmt.Sprintf("searched (engines): %d queries", len(stats)))
	for _, s := range stats {
		out = append(out, fmt.Sprintf("q %s %s impr=%d clicks=%d pos=%.1f",
			doc.SafeLine(s.Q), s.Src, s.Impressions, s.Clicks, s.Position))
	}
	return out
}

// Totals are the aggregate impression/click counts for /transparency.
type Totals struct {
	Impressions int64
	Clicks      int64
	Queries     int64
}

// monthTotals sums impressions and clicks over the rows seen in the last 30 days (the console figures
// are a rolling 28 d window, so this is `this month` for the descriptive page).
func monthTotals(ctx context.Context, q core.Q) (Totals, error) {
	var t Totals
	err := q.QueryRow(ctx, `SELECT coalesce(sum(impressions), 0), coalesce(sum(clicks), 0), count(*)
		FROM demand WHERE last > now() - interval '30 days'`).Scan(&t.Impressions, &t.Clicks, &t.Queries)
	return t, err
}

// freshSitemap lists each rank_weak entry once with the entry's real lastmod, greatest(created,
// confirmed_at) (never rank_weak.since, never now()). Hidden, expired and superseded entries drop out.
func freshSitemap(ctx context.Context, q core.Q) ([]core.SitemapURL, error) {
	rows, err := q.Query(ctx, `SELECT k.id, greatest(k.created, coalesce(k.confirmed_at, k.created))
		FROM rank_weak r JOIN kb k ON k.id = r.kb_id
		WHERE NOT k.hidden AND k.expires_at > now() AND k.superseded_by = ''
		ORDER BY greatest(k.created, coalesce(k.confirmed_at, k.created)) DESC LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.SitemapURL
	for rows.Next() {
		var id string
		var lastmod time.Time
		if err := rows.Scan(&id, &lastmod); err != nil {
			return nil, err
		}
		out = append(out, core.SitemapURL{Loc: doc.Base() + "/kb/" + id, LastMod: lastmod})
	}
	return out, rows.Err()
}
