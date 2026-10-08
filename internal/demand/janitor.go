package demand

import (
	"context"
	"encoding/json"
	"strconv"

	"ekaii.fr/commons/internal/core"
)

// MarkWeak refreshes rank_weak (SPEC 27.1): for the highest-demand queries, the top kb.Search hit
// scoring >= WeakScore marks that entry weak (once; `since` is set on first mark and never moved).
// Entries that have since disappeared are swept so /sitemaps/fresh.xml never cites a dead URL.
// demand never ranks: SearchTop is read-only and the mark is a note, not a promotion.
func MarkWeak(ctx context.Context, d *core.Deps) error {
	if _, err := d.DB.Exec(ctx, `DELETE FROM rank_weak r WHERE NOT EXISTS
		(SELECT 1 FROM kb k WHERE k.id = r.kb_id AND NOT k.hidden AND k.expires_at > now() AND k.superseded_by = '')`); err != nil {
		return err
	}
	stats, err := topQueries(ctx, d.DB, 200)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, s := range stats {
		if seen[s.Q] {
			continue
		}
		seen[s.Q] = true
		id, score, ok := weakLookup(ctx, d.DB, s.Q)
		if !ok || score < WeakScore {
			continue
		}
		if _, err := d.DB.Exec(ctx, `INSERT INTO rank_weak (kb_id) VALUES ($1) ON CONFLICT (kb_id) DO NOTHING`, id); err != nil {
			return err
		}
	}
	return nil
}

// weakLookup is SearchTop guarded against a nil seam (a build that cleared it).
func weakLookup(ctx context.Context, q core.Q, query string) (string, float64, bool) {
	if SearchTop == nil {
		return "", 0, false
	}
	return SearchTop(ctx, q, query)
}

// bingBatch bounds how many indexnow outbox rows OnIndexable reads per run.
var bingBatch = 500

// OnIndexable tails the egress_outbox `indexnow` rows (every indexed URL the platform announces) and
// enqueues a `bing_content` push for each new URL, up to the daily quota in flag bing:quota. A
// cursor flag (bing:cursor) keeps the last fully-pushed outbox id so nothing is pushed twice and a
// quota stop resumes from the same row next run. The courier fetches the rendition and signs it off.
func OnIndexable(ctx context.Context, d *core.Deps) error {
	cursor, _ := strconv.ParseInt(d.FlagStr("bing:cursor"), 10, 64)
	quota := DefaultQuota
	if v, err := strconv.Atoi(d.FlagStr("bing:quota")); err == nil && v >= 0 {
		quota = v
	}
	var today int
	if err := d.DB.QueryRow(ctx, `SELECT count(*) FROM egress_outbox
		WHERE kind = 'bing_content' AND created > now() - interval '1 day'`).Scan(&today); err != nil {
		return err
	}
	rows, err := d.DB.Query(ctx, `SELECT id, payload FROM egress_outbox
		WHERE kind = 'indexnow' AND id > $1 ORDER BY id LIMIT $2`, cursor, bingBatch)
	if err != nil {
		return err
	}
	type job struct {
		id      int64
		payload json.RawMessage
	}
	var jobs []job
	for rows.Next() {
		var j job
		if err := rows.Scan(&j.id, &j.payload); err != nil {
			rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	last := cursor
	for _, j := range jobs {
		if today >= quota {
			break // quota reached: leave the cursor on the last fully-pushed row, resume next run
		}
		var p struct {
			URLs []string `json:"urls"`
		}
		if err := json.Unmarshal(j.payload, &p); err != nil {
			last = j.id // a malformed indexnow row is skipped, never retried
			continue
		}
		stop := false
		for _, u := range p.URLs {
			if today >= quota {
				stop = true
				break
			}
			if u == "" || len(u) > MaxPage {
				continue
			}
			if err := core.Egress(ctx, d.DB, "bing_content", map[string]any{"url": u}); err != nil {
				if err == core.ErrOutboxFull {
					stop = true
					break
				}
				return err
			}
			today++
		}
		if stop {
			break // do not advance past a partially-pushed row
		}
		last = j.id
	}
	if last != cursor {
		return d.SetFlag(ctx, "bing:cursor", true, strconv.FormatInt(last, 10))
	}
	return nil
}
