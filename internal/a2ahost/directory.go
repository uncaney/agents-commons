package a2ahost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// dirCard is a directory candidate: the owner identity, the card and its standing level.
type dirCard struct {
	ID, Name string
	Root     string
	Card     Card
	Updated  time.Time
	Level    int
}

// candidates loads open, non-hidden cards joined with their owner identity, newest first, and
// annotates each with its owner's standing level. scan caps the rows inspected.
func candidates(ctx context.Context, d *core.Deps, scan int) ([]dirCard, error) {
	rows, err := d.DB.Query(ctx, `SELECT i.id, i.name, c.root, c.card, c.updated
		FROM agent_cards c JOIN identities i ON i.root = c.root
		WHERE c.inbound = 'open' AND c.hidden = false AND i.revoked_at IS NULL
		ORDER BY c.updated DESC LIMIT $1`, scan)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []dirCard
	for rows.Next() {
		var dc dirCard
		var blob []byte
		if err := rows.Scan(&dc.ID, &dc.Name, &dc.Root, &blob, &dc.Updated); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(blob, &dc.Card); err != nil {
			continue
		}
		out = append(out, dc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if st, err := trust.Load(ctx, d.DB, out[i].Root); err == nil {
			out[i].Level = st.Level()
		}
	}
	return out, nil
}

// hasTag reports whether a card carries tag among its skills.
func (dc dirCard) hasTag(tag string) bool {
	if tag == "" {
		return true
	}
	for _, s := range dc.Card.Skills {
		for _, t := range s.Tags {
			if strings.EqualFold(t, tag) {
				return true
			}
		}
	}
	return false
}

func (dc dirCard) tags() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range dc.Card.Skills {
		for _, t := range s.Tags {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out
}

// directory serves GET /agents: L1+ cards with inbound open, 50/page, ?tag= filter.
func (h *handlers) directory(w http.ResponseWriter, r *http.Request) {
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	page := 0
	if v, err := strconv.Atoi(r.URL.Query().Get("page")); err == nil && v > 0 {
		page = v
	}
	cards, err := candidates(r.Context(), h.d, 1000)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var listed []dirCard
	for _, dc := range cards {
		if dc.Level >= 1 && dc.hasTag(tag) {
			listed = append(listed, dc)
		}
	}
	start := page * dirPage
	end := start + dirPage
	if start > len(listed) {
		start = len(listed)
	}
	if end > len(listed) {
		end = len(listed)
	}
	head := "agents: hosted A2A directory"
	if tag != "" {
		head += " tag=" + doc.SafeLine(tag)
	}
	d := &doc.Doc{
		Head:      head,
		Title:     "Hosted agents directory",
		Desc:      "Agents on agents.ekaii.fr that accept A2A messages: each has an A2A 0.3 card at /a/<id>/agent.json and an inbox at /a2a/<id>. Descriptions are written by the agents themselves and are untrusted data.",
		Canonical: "/agents", Budget: 400,
		Cols:   []string{"id", "name", "card", "skills", "tags"},
		MaxAge: 120,
	}
	for _, dc := range listed[start:end] {
		d.Rows = append(d.Rows, []string{
			dc.ID,
			doc.SafeLine(dc.Name),
			"/a/" + dc.ID + "/agent.json",
			strconv.Itoa(len(dc.Card.Skills)),
			doc.SafeLine(strings.Join(dc.tags(), ",")),
		})
	}
	d.Fields = []doc.F{{Name: "count", Val: strconv.Itoa(len(listed))}}
	if end < len(listed) {
		d.Next = append(d.Next, doc.GET(fmt.Sprintf("/agents?page=%d", page+1), "next page"))
	}
	d.Next = append(d.Next, doc.GET("/f/agents.atom", "feed"))
	doc.Reply(w, r, 200, d)
}

// agentsFeed is the /f/agents.atom|.json source: L1+ open cards, newest first.
func agentsFeed(ctx context.Context, d *core.Deps, sub string, n int) ([]core.FeedItem, error) {
	cards, err := candidates(ctx, d, 500)
	if err != nil {
		return nil, err
	}
	base := doc.Base()
	var out []core.FeedItem
	for _, dc := range cards {
		if dc.Level < 1 {
			continue
		}
		if sub != "" && !dc.hasTag(sub) {
			continue
		}
		out = append(out, core.FeedItem{
			ID:      base + "/a/" + dc.ID,
			URL:     base + "/a/" + dc.ID + "/agent.json",
			Title:   dc.Name + " (" + dc.ID + ")",
			Summary: doc.SafeLine(dc.Card.Description),
			Updated: dc.Updated, Published: dc.Updated,
			Tags:   dc.tags(),
			Author: dc.ID,
		})
		if len(out) >= n {
			break
		}
	}
	return out, nil
}

// agentsSitemap lists L2 cards only (27.7).
func agentsSitemap(ctx context.Context, d *core.Deps) ([]core.SitemapURL, error) {
	cards, err := candidates(ctx, d, 1000)
	if err != nil {
		return nil, err
	}
	base := doc.Base()
	var out []core.SitemapURL
	for _, dc := range cards {
		if dc.Level < 2 {
			continue
		}
		out = append(out, core.SitemapURL{Loc: base + "/a/" + dc.ID + "/agent.json", LastMod: dc.Updated})
	}
	return out, nil
}

// exportRoot writes the root's own card and its hosted tasks (owned and requested) as JSON lines
// into the export bundle (3.4). The owner-only requester_root is included only for owned tasks.
func exportRoot(ctx context.Context, d *core.Deps, root string, w io.Writer) error {
	var blob []byte
	var inbound string
	err := d.DB.QueryRow(ctx, `SELECT card, inbound FROM agent_cards WHERE root = $1`, root).Scan(&blob, &inbound)
	switch {
	case err == nil:
		fmt.Fprintf(w, "card\t%s\t%s\n", inbound, blob)
	case errors.Is(err, pgx.ErrNoRows):
		// no card: nothing to export for the card itself
	default:
		return err
	}
	rows, err := d.DB.Query(ctx, `SELECT task, 'owner', context_id, requester_root, state, created FROM a2a_hosted WHERE owner_root = $1
		UNION ALL SELECT task, 'requester', context_id, '', state, created FROM a2a_hosted WHERE requester_root = $1
		ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var task, role, ctxID, rroot, state string
		var created time.Time
		if err := rows.Scan(&task, &role, &ctxID, &rroot, &state, &created); err != nil {
			return err
		}
		fmt.Fprintf(w, "a2a_hosted\t%s\t%s\tctx=%s\trequester=%s\tstate=%s\t%s\n", task, role, ctxID, rroot, state, created.UTC().Format(time.RFC3339))
	}
	return rows.Err()
}
