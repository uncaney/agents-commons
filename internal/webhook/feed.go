package webhook

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// feed is the private transport GET /f/h/{url-token}.atom|.json (SPEC-v2 27.7): the token's root
// reads its own outbound envelopes (never mail bodies, never another root's rows). The token must
// be a url-class subkey carrying ev:r — the same class and scope the P83 middleware serves — so a
// bad or wrong-class token is the same not-found as an unknown feed. The gateway never fetches the
// hook url and the feed never renders it.
func (h *handlers) feed(ctx context.Context, sub string, n int) ([]core.FeedItem, error) {
	tok := strings.TrimSpace(sub)
	if tok == "" {
		return nil, core.ErrNotFound
	}
	id, err := h.d.LookupToken(ctx, tok)
	if err != nil || id.Class != "url" || !core.ScopeAllowed(id.Scopes, "ev:r") {
		return nil, core.ErrNotFound
	}
	rows, err := h.d.DB.Query(ctx, `SELECT ho.id, ho.ev_seq, ho.envelope, ho.created, hk.fmt
		FROM hook_out ho JOIN hooks hk ON hk.id = ho.hook
		WHERE hk.root = $1 ORDER BY ho.id DESC LIMIT $2`, id.Root, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	base := doc.Base()
	var items []core.FeedItem
	for rows.Next() {
		var oid, evSeq int64
		var raw []byte
		var created time.Time
		var format string
		if err := rows.Scan(&oid, &evSeq, &raw, &created, &format); err != nil {
			return nil, err
		}
		var e Envelope
		_ = json.Unmarshal(raw, &e)
		idStr := "h/" + strconv.FormatInt(oid, 10)
		summary := doc.SafeLine(format + " envelope: " + cut(e.Body, 400))
		items = append(items, core.FeedItem{
			ID:        idStr,
			URL:       base + "/v1/ev?after=" + strconv.FormatInt(evSeq-1, 10) + "&k=1",
			Title:     format + " #" + strconv.FormatInt(oid, 10),
			Summary:   summary,
			Updated:   created,
			Published: created,
			Tags:      []string{"webhook", format},
		})
	}
	return items, rows.Err()
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
