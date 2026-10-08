package kb

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Tombstone is what remains of a removed entry (6.1 kb_tombstones): enough for a 410 body with the
// single-line title, the export tombstone feed and the sitemap/IndexNow removal trail.
type Tombstone struct {
	ID           string    `json:"id"`
	Title        string    `json:"title"`
	Reason       string    `json:"reason"` // expire | retract | purge | hidden | merged
	SupersededBy string    `json:"superseded_by,omitempty"`
	At           time.Time `json:"at"`
}

// Line is the 410 head: `gone retracted superseded_by=k…`.
func (t *Tombstone) Line() string {
	s := "gone " + t.Reason
	if t.SupersededBy != "" {
		s += " superseded_by=" + t.SupersededBy
	}
	return s
}

// Gone looks an id up in kb_tombstones; false when the id is unknown (or on a query error).
func Gone(ctx context.Context, q core.Q, id string) (*Tombstone, bool) {
	if !core.ValidIDPrefix(id, 'k') {
		return nil, false
	}
	var t Tombstone
	err := q.QueryRow(ctx, `SELECT id, title, reason, superseded_by, at FROM kb_tombstones WHERE id = $1`, id).
		Scan(&t.ID, &t.Title, &t.Reason, &t.SupersededBy, &t.At)
	if err != nil {
		return nil, false
	}
	t.Title = doc.SafeLine(t.Title)
	return &t, true
}

// tombstone upserts one tombstone row (a later removal of the same id wins).
func tombstone(ctx context.Context, q core.Q, id, title, reason, successor string) error {
	_, err := q.Exec(ctx, `INSERT INTO kb_tombstones (id, title, reason, superseded_by) VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, reason = EXCLUDED.reason,
		superseded_by = CASE WHEN EXCLUDED.superseded_by <> '' THEN EXCLUDED.superseded_by ELSE kb_tombstones.superseded_by END, at = now()`,
		id, title, reason, successor)
	return err
}

// Remove deletes one entry inside the caller's tx and leaves a tombstone of the given reason: the
// mirror drops it, the dumps forget it and IndexNow learns about the removal (9.5, 9.6).
func Remove(ctx context.Context, q core.Q, id, reason, successor string) error {
	var title, kind string
	var tags []string
	err := q.QueryRow(ctx, `DELETE FROM kb WHERE id = $1 RETURNING title, kind, tags`, id).Scan(&title, &kind, &tags)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := tombstone(ctx, q, id, title, reason, successor); err != nil {
		return err
	}
	if err := enqueue(ctx, q, id, ""); err != nil {
		return err
	}
	indexNow(ctx, q, id, nil, tags)
	core.ExportRemove(ctx, "kb", id)
	return nil
}

// Expire deletes expired entries, writing a tombstone (expire) for each and telling the mirror
// and IndexNow (janitor task kb_expire).
func Expire(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `WITH e AS (DELETE FROM kb WHERE expires_at <= now() RETURNING id, title, superseded_by, tags),
		t AS (INSERT INTO kb_tombstones (id, title, reason, superseded_by) SELECT id, title, 'expire', superseded_by FROM e
		      ON CONFLICT (id) DO UPDATE SET reason = 'expire', at = now()),
		o AS (INSERT INTO forge_outbox (kind, ref, payload) SELECT 'kb', id, ''::bytea FROM e)
		SELECT id, tags FROM e`)
	if err != nil {
		return err
	}
	type gone struct {
		id   string
		tags []string
	}
	var expired []gone
	for rows.Next() {
		var g gone
		if err := rows.Scan(&g.id, &g.tags); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for i, g := range expired {
		if i < 200 { // one outbox row per entry; a mass expiry never floods the outbox
			indexNow(ctx, q, g.id, nil, g.tags)
		}
		core.ExportRemove(ctx, "kb", g.id)
	}
	return nil
}

// expire keeps the v1 name for the janitor registration.
func expire(ctx context.Context, q core.Q) error { return Expire(ctx, q) }

// purgeHidden removes entries hidden by votes (hidden_at set by the vote path, or by HideBy with
// reason report) 30 d ago without a restore (4.7) with a `hidden` tombstone (janitor task
// kb_hidden_purge). Rows hidden through the report target (Target.Hide) or a notice never get a
// hidden_at and therefore wait for a restore or the operator (4.8).
func purgeHidden(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT id FROM kb WHERE hidden AND hidden_at IS NOT NULL AND hidden_at < now() - interval '30 days'
		AND (restored_at IS NULL OR restored_at < hidden_at) AND (immune_until IS NULL OR immune_until < now()) LIMIT 200`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := Remove(ctx, q, id, "hidden", ""); err != nil && !errors.Is(err, core.ErrNotFound) {
			return err
		}
	}
	return nil
}

// purge removes the entries and votes of a purged root tree (OnPurge hook): tombstones `purge`,
// mirror drops, IndexNow removals, and the collapsed sums of the entries it had voted on.
func purge(ctx context.Context, q core.Q, root string) error {
	rows, err := q.Query(ctx, `SELECT id FROM kb WHERE author_root = $1 AND author_root <> ''`, root)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := Remove(ctx, q, id, "purge", ""); err != nil && !errors.Is(err, core.ErrNotFound) {
			return err
		}
	}
	voted, err := q.Query(ctx, `DELETE FROM kb_votes WHERE root = $1 RETURNING kb_id`, root)
	if err != nil {
		return err
	}
	var touched []string
	for voted.Next() {
		var id string
		if err := voted.Scan(&id); err != nil {
			voted.Close()
			return err
		}
		touched = append(touched, id)
	}
	voted.Close()
	if err := voted.Err(); err != nil {
		return err
	}
	for _, id := range touched {
		if err := recount(ctx, q, id); err != nil && !errors.Is(err, core.ErrNotFound) {
			return err
		}
	}
	return nil
}
