package feed

import (
	"context"
	"errors"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/kb"
)

// maxQuery bounds a saved-search query (kb.Search cuts at its own cap as well).
const maxQuery = 200

var errBusy = core.E(503, "busy", "search busy, retry 2")

// searchFeed is the saved-search source q/<query> (9.3): the KB ranking under the trigram
// semaphore shared with anonymous search (6.2), k <= 50, then only indexable entries (visible,
// non-quarantine, non-status, hazard rules) rendered as summary (symptom) + permalink.
func (s *svc) searchFeed(ctx context.Context, sub string, n int) ([]core.FeedItem, error) {
	query := strings.Join(strings.Fields(sub), " ")
	switch {
	case query == "":
		return nil, core.Bad("q: query required, GET /f/q/<query>.atom")
	case len(query) > maxQuery:
		return nil, core.Bad("q: query too long")
	}
	if n <= 0 || n > MaxItems {
		n = DefaultN
	}
	release, ok := kb.AcquireSearch(ctx)
	if !ok {
		return nil, errBusy
	}
	hits, err := kb.SearchV2(ctx, s.d.DB, kb.SearchOpts{Q: query, K: n})
	release() // the semaphore guards the trigram scan only, not the per-entry loads below
	if err != nil {
		return nil, err
	}
	out := make([]core.FeedItem, 0, len(hits))
	for _, h := range hits {
		if h.Quarantine || h.Kind == "status" {
			continue
		}
		e, err := kb.GetV2(ctx, s.d.DB, h.ID, kb.GetOpts{})
		if errors.Is(err, core.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !kb.Indexable(e) {
			continue
		}
		out = append(out, entryItem(e))
	}
	return out, nil
}

// entryItem is a KB entry as a feed item: summary = one-line symptom (the renderer caps it at
// 500 B), updated = latest of created and confirmed_at, author = pseudonymous id or seed.
func entryItem(e *kb.Entry) core.FeedItem {
	upd := e.Created
	if e.ConfirmedAt != nil && e.ConfirmedAt.After(upd) {
		upd = *e.ConfirmedAt
	}
	author := e.Author
	if e.Seed {
		author = "seed"
	}
	return core.FeedItem{ID: e.ID, URL: kb.Permalink(e.ID), Title: e.Title, Summary: strings.Join(strings.Fields(e.Symptom), " "),
		Updated: upd, Published: e.Created, Tags: e.Tags, Author: author}
}
