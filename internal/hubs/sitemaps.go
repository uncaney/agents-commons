package hubs

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
)

// errFeed renders the indexable fixes of an error class as feed items for /f/err/<class> (9.3):
// summary + link, never the body.
func errFeed(ctx context.Context, q core.Q, sub string, n int) ([]core.FeedItem, error) {
	if !validClass(sub) {
		return nil, core.ErrNotFound
	}
	if n <= 0 || n > 50 {
		n = 20
	}
	rows, err := q.Query(ctx, `SELECT k.id, k.title, k.symptom, k.created, greatest(k.created, coalesce(k.confirmed_at, k.created)), k.tags, k.author, k.seed`+hubFrom+
		` WHERE k.err_class = $1 AND `+hubIndexable+` ORDER BY k.created DESC, k.id DESC LIMIT $2`, sub, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.FeedItem
	for rows.Next() {
		var id, title, symptom, author string
		var created, updated time.Time
		var tags []string
		var seed bool
		if err := rows.Scan(&id, &title, &symptom, &created, &updated, &tags, &author, &seed); err != nil {
			return nil, err
		}
		if seed {
			author = "seed"
		}
		out = append(out, core.FeedItem{ID: id, URL: kb.Permalink(id), Title: doc.SafeLine(title),
			Summary: doc.SafeLine(strings.Join(strings.Fields(symptom), " ")), Updated: updated, Published: created, Tags: tags, Author: author})
	}
	return out, rows.Err()
}

// hubsSitemap lists the /err/, /eco/ and /kb/<ym>/ hub URLs for /sitemaps/hubs.xml (9.2): error
// classes with >= 3 indexable members, ecosystems with at least one member library, and the
// months that have indexable entries. All children come from stored, confirmed data.
func hubsSitemap(ctx context.Context, q core.Q) ([]core.SitemapURL, error) {
	var out []core.SitemapURL
	rows, err := q.Query(ctx, `SELECT k.err_class, max(greatest(k.created, coalesce(k.confirmed_at, k.created)))`+hubFrom+
		` WHERE k.err_class IS NOT NULL AND k.err_class <> '' AND `+hubIndexable+
		` GROUP BY k.err_class HAVING count(*) >= 3 ORDER BY k.err_class`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var class string
		var mod time.Time
		if err := rows.Scan(&class, &mod); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, core.SitemapURL{Loc: doc.Base() + "/err/" + url.PathEscape(class), LastMod: mod})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	ecos := make([]string, 0, len(ecosystems))
	for e := range ecosystems {
		ecos = append(ecos, e)
	}
	for i := 1; i < len(ecos); i++ {
		for j := i; j > 0 && ecos[j] < ecos[j-1]; j-- {
			ecos[j], ecos[j-1] = ecos[j-1], ecos[j]
		}
	}
	for _, eco := range ecos {
		libs, err := ecoLibs(ctx, q, eco)
		if err != nil {
			return nil, err
		}
		if len(libs) > 0 {
			out = append(out, core.SitemapURL{Loc: doc.Base() + "/eco/" + eco})
		}
	}

	mrows, err := q.Query(ctx, `SELECT to_char(k.created AT TIME ZONE 'UTC', 'YYYY-MM') AS ym, max(greatest(k.created, coalesce(k.confirmed_at, k.created)))`+hubFrom+
		` WHERE `+hubIndexable+` GROUP BY ym ORDER BY ym DESC LIMIT 240`)
	if err != nil {
		return nil, err
	}
	defer mrows.Close()
	for mrows.Next() {
		var ym string
		var mod time.Time
		if err := mrows.Scan(&ym, &mod); err != nil {
			return nil, err
		}
		out = append(out, core.SitemapURL{Loc: doc.Base() + "/kb/" + ym + "/", LastMod: mod})
	}
	return out, mrows.Err()
}

// tasksSitemap lists /t/<n> for indexable tasks (27.1): visible, un-quarantined, flag- and
// hazard-free tasks that are done or carry at least one note from an L1+ author; lastmod is the
// last note (or close/creation).
func tasksSitemap(ctx context.Context, q core.Q) ([]core.SitemapURL, error) {
	rows, err := q.Query(ctx, `SELECT t.n,
		greatest(t.created, coalesce(t.closed_at, t.created), coalesce((SELECT max(at) FROM task_notes tn WHERE tn.n = t.n), t.created)) AS mod
		FROM tasks t
		WHERE NOT t.quarantine AND t.state <> 'hidden' AND t.flags = '{}' AND t.hazard = '{}' AND t.created <= now() - interval '1 hour'
		AND ( t.state = 'done'
		      OR EXISTS (SELECT 1 FROM task_notes tn JOIN identities nr ON nr.id = tn.root
		                 WHERE tn.n = t.n AND nr.revoked_at IS NULL AND nr.rep > -10
		                 AND (nr.seed OR (nr.rep >= 1 AND nr.created <= now() - interval '24 hours'))) )
		ORDER BY t.n DESC LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.SitemapURL
	for rows.Next() {
		var n int64
		var mod time.Time
		if err := rows.Scan(&n, &mod); err != nil {
			return nil, err
		}
		out = append(out, core.SitemapURL{Loc: doc.Base() + "/t/" + strconv.FormatInt(n, 10), LastMod: mod})
	}
	return out, rows.Err()
}

// govSitemap lists /p/<id> for closed proposals (27.1, 27.5): a decided, visible proposal.
func govSitemap(ctx context.Context, q core.Q) ([]core.SitemapURL, error) {
	rows, err := q.Query(ctx, `SELECT id, coalesce(decided_at, passed_at, applied_at, created) AS mod FROM proposals
		WHERE NOT hidden AND flags = '{}' AND created <= now() - interval '1 hour'
		AND state IN ('passed', 'failed', 'applied', 'vetoed', 'withdrawn', 'dup', 'accepted', 'declined', 'deferred', 'shipped')
		ORDER BY created DESC LIMIT 5000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.SitemapURL
	for rows.Next() {
		var id string
		var mod time.Time
		if err := rows.Scan(&id, &mod); err != nil {
			return nil, err
		}
		out = append(out, core.SitemapURL{Loc: doc.Base() + "/p/" + id, LastMod: mod})
	}
	return out, rows.Err()
}
