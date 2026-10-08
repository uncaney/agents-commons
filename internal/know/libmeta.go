package know

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Registry metadata (13.4): the courier kind libmeta fills libs; the gateway enqueues only for
// seeded aliases or keys referenced by an L1+ write, deduped by requested_at (7 d), 500/day
// through core.Egress's kind caps; anonymous page reads of arbitrary keys never enqueue.

// RequestLibMeta enqueues a libmeta fetch for key on behalf of root (13.4 enqueue rules): the key
// must be the target of a seeded alias or root must be L1+ (core.LevelFn). Dedupe and caps are
// silent (nil); only database errors return.
func RequestLibMeta(ctx context.Context, q core.Q, key, root string) error {
	key, err := ParseKey(key)
	if err != nil {
		return err
	}
	referenced := root != "" && core.Level(ctx, q, root) >= 1
	err = requestLibMeta(ctx, q, key, referenced)
	if errors.Is(err, core.ErrOutboxFull) {
		return nil
	}
	return err
}

// requestLibMeta is the shared enqueue: referenced marks a key an L1+ write cited.
func requestLibMeta(ctx context.Context, q core.Q, key string, referenced bool) error {
	if !referenced {
		seeded, err := seededKey(ctx, q, key)
		if err != nil {
			return err
		}
		if !seeded {
			return nil
		}
	}
	// due = the row was new or its last request is older than the refresh window (read before the upsert)
	var due bool
	err := q.QueryRow(ctx, `WITH cur AS (SELECT requested_at FROM libs WHERE key = $1 FOR UPDATE),
		up AS (INSERT INTO libs (key, referenced, requested_at) VALUES ($1, $2, now())
			ON CONFLICT (key) DO UPDATE SET referenced = libs.referenced OR EXCLUDED.referenced,
				requested_at = CASE WHEN libs.requested_at IS NULL OR libs.requested_at < now() - $3::interval THEN now() ELSE libs.requested_at END
			RETURNING key)
		SELECT NOT EXISTS (SELECT 1 FROM cur) OR EXISTS (SELECT 1 FROM cur WHERE requested_at IS NULL OR requested_at < now() - $3::interval)`,
		key, referenced, pgInterval(LibMetaRefresh)).Scan(&due)
	if err != nil {
		return err
	}
	if !due {
		return nil
	}
	return core.Egress(ctx, q, "libmeta", map[string]string{"key": key})
}

// Enqueueable reports whether a key may be enqueued at all (seeded or referenced); for tests and
// the weekly refresh.
func Enqueueable(ctx context.Context, q core.Q, key string) (bool, error) {
	var referenced bool
	err := q.QueryRow(ctx, `SELECT coalesce((SELECT referenced FROM libs WHERE key = $1), false)`, key).Scan(&referenced)
	if err != nil {
		return false, err
	}
	if referenced {
		return true, nil
	}
	return seededKey(ctx, q, key)
}

// libResult mirrors cmd/courier/kind_libmeta.go's libResult (courier-produced: validated here).
type libResult struct {
	Key      string `json:"key"`
	Display  string `json:"display"`
	Homepage string `json:"homepage"`
	Repo     string `json:"repo"`
	Docs     string `json:"docs"`
	Registry string `json:"registry"`
	Latest   string `json:"latest"`
	LatestAt string `json:"latest_at"`
	Versions []struct {
		V          string `json:"v"`
		At         string `json:"at"`
		Yanked     bool   `json:"yanked"`
		Deprecated bool   `json:"deprecated"`
		Pre        bool   `json:"pre"`
	} `json:"versions"`
	Err string `json:"err"`
}

const (
	maxMetaVersions = 500
	maxMetaText     = 200
)

// cleanMetaURL keeps absolute http(s) URLs without userinfo (<= 400 chars).
func cleanMetaURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxSourceURL || !doc.OneLine(s) {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return ""
	}
	return u.String()
}

func metaTime(s string) time.Time {
	for _, l := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000Z", "2006-01-02"} {
		if t, err := time.Parse(l, strings.TrimSpace(s)); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// ApplyLibMeta stores a courier libmeta result (13.4): validated text and URLs, <= 500 versions,
// unknown-version flags of the lib's claims recomputed, LibMetaHookFn told. A result with err set
// records the error and the fetch time so the key is not retried for a week.
func ApplyLibMeta(ctx context.Context, q core.Q, result json.RawMessage) error {
	if len(result) == 0 || len(result) > 1<<20 {
		return core.Bad("libmeta result")
	}
	var r libResult
	if err := json.Unmarshal(result, &r); err != nil {
		return core.Bad("libmeta result: " + err.Error())
	}
	key, err := ParseKey(r.Key)
	if err != nil {
		return err
	}
	rels := make([]Release, 0, len(r.Versions))
	for _, v := range r.Versions {
		if v.V == "" || len(v.V) > 100 || !doc.OneLine(v.V) {
			continue
		}
		rels = append(rels, Release{V: v.V, At: metaTime(v.At), Yanked: v.Yanked, Deprecated: v.Deprecated, Pre: v.Pre || !Parseable(v.V) || strings.Contains(VKey(v.V), "-")})
	}
	sort.SliceStable(rels, func(i, j int) bool { return VKey(rels[i].V) < VKey(rels[j].V) })
	if len(rels) > maxMetaVersions {
		rels = rels[len(rels)-maxMetaVersions:]
	}
	versions, _ := json.Marshal(rels)
	var latestAt *time.Time
	if t := metaTime(r.LatestAt); !t.IsZero() {
		latestAt = &t
	}
	return inTx(ctx, q, func(q core.Q) error {
		if _, err := q.Exec(ctx, `INSERT INTO libs (key, display, homepage, repo, docs, registry, latest, latest_at, versions, fetched_at, fetch_err)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, now(), $10)
			ON CONFLICT (key) DO UPDATE SET display = EXCLUDED.display, homepage = EXCLUDED.homepage, repo = EXCLUDED.repo, docs = EXCLUDED.docs,
			registry = EXCLUDED.registry, latest = EXCLUDED.latest, latest_at = EXCLUDED.latest_at,
			versions = CASE WHEN jsonb_array_length(EXCLUDED.versions) > 0 OR EXCLUDED.fetch_err <> '' THEN EXCLUDED.versions ELSE libs.versions END,
			fetched_at = now(), fetch_err = EXCLUDED.fetch_err`,
			key, cutRunes(doc.SafeLine(r.Display), maxMetaText), cleanMetaURL(r.Homepage), cleanMetaURL(r.Repo), cleanMetaURL(r.Docs),
			cleanMetaURL(r.Registry), cutRunes(doc.SafeLine(r.Latest), 100), latestAt, string(versions), cutRunes(doc.SafeLine(r.Err), maxMetaText)); err != nil {
			return err
		}
		if len(rels) > 0 {
			if _, err := q.Exec(ctx, `UPDATE claims c SET unknown_version = NOT EXISTS (SELECT 1 FROM jsonb_array_elements($2::jsonb) e
				WHERE lower(e->>'v') = lower(c.v_to) OR lower(e->>'v') = 'v' || lower(c.v_to)) WHERE c.lib = $1 AND c.v_to <> ''`, key, string(versions)); err != nil {
				return err
			}
		}
		if LibMetaHookFn != nil {
			if err := LibMetaHookFn(ctx, q, key, result); err != nil {
				return err
			}
		}
		return nil
	})
}

// LibMetaResult has the egress.ResultFunc shape for egress.ResultFn["libmeta"].
func LibMetaResult(ctx context.Context, d *core.Deps, q core.Q, payload, result json.RawMessage) error {
	if len(result) == 0 {
		return nil
	}
	return ApplyLibMeta(ctx, q, result)
}

// Releases returns the registry versions of key, oldest first (13.4 libs.versions).
func Releases(ctx context.Context, q core.Q, key string) ([]Release, error) {
	key, err := ParseKey(key)
	if err != nil {
		return nil, err
	}
	var raw []byte
	err = q.QueryRow(ctx, `SELECT versions FROM libs WHERE key = $1`, key).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rels []Release
	if err := json.Unmarshal(raw, &rels); err != nil {
		return nil, err
	}
	return rels, nil
}

// LibMetaRefresh is the weekly janitor: keys with >= 1 visible row and a fetch older than 7 d are
// re-enqueued (caps apply through core.Egress).
func RefreshLibMeta(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT l.key FROM libs l WHERE (l.fetched_at IS NULL OR l.fetched_at < now() - $1::interval)
		AND (l.requested_at IS NULL OR l.requested_at < now() - $1::interval)
		AND (l.referenced OR EXISTS (SELECT 1 FROM lib_alias a WHERE a.key = l.key AND a.seeded))
		AND (EXISTS (SELECT 1 FROM claims c WHERE c.lib = l.key AND NOT c.hidden AND c.status IN ('verified', 'unverified'))
		  OR EXISTS (SELECT 1 FROM digests g WHERE g.lib = l.key AND NOT g.hidden AND g.status = 'live'))
		ORDER BY l.fetched_at NULLS FIRST LIMIT 100`, pgInterval(LibMetaRefresh))
	if err != nil {
		return err
	}
	var keys []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, k)
	}
	rows.Close()
	for _, k := range keys {
		if _, err := q.Exec(ctx, `UPDATE libs SET requested_at = now() WHERE key = $1`, k); err != nil {
			return err
		}
		if err := core.Egress(ctx, q, "libmeta", map[string]string{"key": k}); err != nil {
			if errors.Is(err, core.ErrOutboxFull) {
				return nil
			}
			return err
		}
	}
	return nil
}
