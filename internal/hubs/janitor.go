package hubs

import (
	"context"

	"ekaii.fr/commons/internal/core"
)

// backfillErrClass fills kb.err_class for rows left NULL (27.1): the Go extractor runs over the
// title, storing the class on a match and ” when none, so the row is not reprocessed. Batched.
func backfillErrClass(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT id, title FROM kb WHERE err_class IS NULL ORDER BY created DESC LIMIT 500`)
	if err != nil {
		return err
	}
	var ids, classes []string
	for rows.Next() {
		var id, title string
		if err := rows.Scan(&id, &title); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
		classes = append(classes, ErrClass(title))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	_, err = q.Exec(ctx, `UPDATE kb SET err_class = v.cls
		FROM (SELECT unnest($1::text[]) AS id, unnest($2::text[]) AS cls) v
		WHERE kb.id = v.id AND kb.err_class IS NULL`, ids, classes)
	return err
}

// relatedSrc is one entry whose related: graph needs a refresh.
type relatedSrc struct {
	id      string
	tsQuery string
	tags    []string
}

// refreshRelated recomputes the <= 5 related entry ids of read (views >= 1), indexable entries
// (27.1): a trigram match over title||symptom boosted by shared tags and shared libraries, over
// indexable candidates only. The result (possibly empty) is stored so a row is not reprocessed for
// six hours.
func refreshRelated(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT k.id, k.title || ' ' || k.symptom, k.tags`+hubFrom+
		` WHERE `+hubIndexable+`
		AND EXISTS (SELECT 1 FROM kb_reads_daily d WHERE d.kb_id = k.id AND d.views > 0)
		AND NOT EXISTS (SELECT 1 FROM kb_related kr WHERE kr.kb_id = k.id AND kr.at > now() - interval '6 hours')
		ORDER BY k.created DESC LIMIT 100`)
	if err != nil {
		return err
	}
	var srcs []relatedSrc
	for rows.Next() {
		var s relatedSrc
		if err := rows.Scan(&s.id, &s.tsQuery, &s.tags); err != nil {
			rows.Close()
			return err
		}
		srcs = append(srcs, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, s := range srcs {
		ids, err := relatedFor(ctx, q, s)
		if err != nil {
			return err
		}
		if ids == nil {
			ids = []string{}
		}
		if _, err := q.Exec(ctx, `INSERT INTO kb_related (kb_id, ids, at) VALUES ($1, $2, now())
			ON CONFLICT (kb_id) DO UPDATE SET ids = EXCLUDED.ids, at = now()`, s.id, ids); err != nil {
			return err
		}
	}
	return nil
}

// relatedFor returns up to five indexable entry ids related to a source (trigram over
// title||symptom, boosted by shared tags and shared libraries), excluding the source itself.
func relatedFor(ctx context.Context, q core.Q, s relatedSrc) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT k.id`+hubFrom+`
		WHERE k.id <> $1 AND `+hubIndexable+`
		AND ( (k.title || ' ' || k.symptom) % $2
		      OR k.tags && $3::text[]
		      OR EXISTS (SELECT 1 FROM kb_versions a JOIN kb_versions b ON a.lib = b.lib WHERE a.kb_id = $1 AND b.kb_id = k.id) )
		ORDER BY
		  (CASE WHEN k.tags && $3::text[] THEN 0.3 ELSE 0 END)
		  + (CASE WHEN EXISTS (SELECT 1 FROM kb_versions a JOIN kb_versions b ON a.lib = b.lib WHERE a.kb_id = $1 AND b.kb_id = k.id) THEN 0.3 ELSE 0 END)
		  + similarity(k.title || ' ' || k.symptom, $2) DESC, k.created DESC
		LIMIT 5`, s.id, s.tsQuery, s.tags)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
