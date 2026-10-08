package cache

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"ekaii.fr/commons/internal/core"
)

// export writes the root's cache rows (kind cache, with the inline output it produced) and its
// saved-ledger days (kind saved) as JSONL (3.4 export-me).
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	rows, err := q.Query(ctx, `SELECT `+cols+` FROM cache WHERE producer_root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	for rows.Next() {
		x, err := scanRow(rows)
		if err != nil {
			rows.Close()
			return err
		}
		rec := map[string]any{"kind": "cache", "key": x.Key, "ns": x.NS, "attest": x.Attest, "cost_tokens": x.CostTokens, "producers": x.Producers,
			"conflict": x.Conflict, "hits": x.Hits, "hazard": x.Hazard, "created": x.Created.UTC(), "expires": x.Expires.UTC()}
		if x.Blob != "" {
			rec["blob"] = x.Blob
		} else {
			rec["out"] = x.Out
		}
		if x.Job != "" {
			rec["job"] = x.Job
		}
		if err := enc.Encode(rec); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = q.Query(ctx, `SELECT day, src, tokens FROM saved WHERE root = $1 ORDER BY day, src`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var day time.Time
		var src string
		var tokens int64
		if err := rows.Scan(&day, &src, &tokens); err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "saved", "day": day.Format("2006-01-02"), "src": src, "tokens": tokens}); err != nil {
			return err
		}
	}
	return rows.Err()
}
