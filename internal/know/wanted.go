package know

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

// Demand (8.4, 13.5): misses become wanted rows keyed by sha256(key); distinct super-groups are
// counted through a day-keyed HMAC set (no IP stored, rows older than a day are not re-countable).

var wantedKeyRe = map[string]*regexp.Regexp{
	"e":   regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,160}$`),
	"v":   regexp.MustCompile(`^[a-z]+:[A-Za-z0-9@_][A-Za-z0-9_.:/@+-]{0,199}@[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`),
	"dg":  regexp.MustCompile(`^[a-z]+:[A-Za-z0-9@_][A-Za-z0-9_.:/@+-]{0,199}/[a-z0-9.-]{1,48}$`),
	"h":   regexp.MustCompile(`^[0-9a-f]{12,64}$`),
	"q":   regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,200}$`),
	"svc": regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}\x00[0-9a-f]{64}$`),
}

// wantedSecret holds the server secret the day key derives from (set by Register; tests set it too).
var wantedSecret atomic.Pointer[[]byte]

// SetWantedSecret installs the server secret used for the wanted day key.
func SetWantedSecret(s []byte) {
	b := append([]byte(nil), s...)
	wantedSecret.Store(&b)
}

// dayKey is HKDF(server_secret, "wanted"|YYYY-MM-DD).
func dayKey(t time.Time) []byte {
	var secret []byte
	if p := wantedSecret.Load(); p != nil {
		secret = *p
	}
	k, err := hkdf.Key(sha256.New, secret, nil, "wanted|"+t.UTC().Format("2006-01-02"), 32)
	if err != nil {
		return make([]byte, 32)
	}
	return k
}

// grpHash is HMAC(day key, super-group)[:16].
func grpHash(super string, t time.Time) []byte {
	m := hmac.New(sha256.New, dayKey(t))
	m.Write([]byte(super))
	return m.Sum(nil)[:16]
}

func wantedH(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:]
}

// RecordMiss counts a miss of key under kind (e v dg h q svc) from the caller's super-group (root
// is informational). Only regex-valid, lexicon-clean keys are stored; a nil error is returned for
// anything refused so callers never fail a read on it.
func RecordMiss(ctx context.Context, q core.Q, kind, key, super, root string) error {
	re, ok := wantedKeyRe[kind]
	if !ok || q == nil {
		return nil
	}
	key = strings.TrimSpace(key)
	if kind == "e" || kind == "q" {
		key = scrub.Normalize(key)
	}
	if !re.MatchString(key) {
		return nil
	}
	if kind != "svc" && !doc.OneLine(key) {
		return nil
	}
	if score, _, _ := scrub.Flags(key); score >= 1 && kind != "svc" && kind != "h" {
		return nil
	}
	h := wantedH(key)
	// For kind "h" the key is a 64-hex errsig hash; store the RAW hash bytes so kb.FilledHook ->
	// FillWantedHash(rawsig) matches (otherwise the kind-h demand fill never fires).
	if kind == "h" {
		if b, e := hex.DecodeString(key); e == nil && len(b) == 32 {
			h = b
		}
	}
	if kind == "svc" {
		key = strings.ReplaceAll(key, "\x00", "/") // text columns cannot hold NUL; the hash keeps the raw key
	}
	return inTx(ctx, q, func(q core.Q) error {
		var n int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM wanted WHERE kind = $1`, kind).Scan(&n); err != nil {
			return err
		}
		if n >= WantedPerKind {
			var exists bool
			if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM wanted WHERE kind = $1 AND h = $2)`, kind, h).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return nil // the kind is full; the weekly prune makes room
			}
		}
		if _, err := q.Exec(ctx, `INSERT INTO wanted (kind, key, h, n, groups) VALUES ($1, $2, $3, 1, 0)
			ON CONFLICT (kind, h) DO UPDATE SET n = wanted.n + 1, last = now()`, kind, key, h); err != nil {
			return err
		}
		if super != "" {
			var grps int
			if err := q.QueryRow(ctx, `SELECT count(*) FROM wanted_grp WHERE kind = $1 AND h = $2`, kind, h).Scan(&grps); err != nil {
				return err
			}
			if grps < WantedGroups {
				if _, err := q.Exec(ctx, `INSERT INTO wanted_grp (kind, h, grp_h) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, kind, h, grpHash(super, time.Now())); err != nil {
					return err
				}
			}
		}
		_, err := q.Exec(ctx, `UPDATE wanted SET groups = (SELECT count(*) FROM wanted_grp g WHERE g.kind = wanted.kind AND g.h = wanted.h) WHERE kind = $1 AND h = $2`, kind, h)
		return err
	})
}

// fillWanted deletes the wanted row of (kind, key) and returns the reply line `filled wanted n=…`.
func fillWanted(ctx context.Context, q core.Q, kind, key string) (string, error) {
	var n int
	err := q.QueryRow(ctx, `DELETE FROM wanted WHERE kind = $1 AND h = $2 RETURNING n`, kind, wantedH(key)).Scan(&n)
	if err != nil {
		return "", nil
	}
	q.Exec(ctx, `DELETE FROM wanted_grp WHERE kind = $1 AND h = $2`, kind, wantedH(key))
	return fmt.Sprintf("filled wanted n=%d", n), nil
}

// FillWanted is fillWanted for other packages (kb titles through kb.FilledHook use the hash form).
func FillWanted(ctx context.Context, q core.Q, kind, key string) (string, error) {
	return fillWanted(ctx, q, kind, key)
}

// FillWantedHash deletes wanted rows of kind e (and h) whose hash equals h; the kb.FilledHook shape.
func FillWantedHash(ctx context.Context, q core.Q, h []byte) (string, error) {
	var n int
	err := q.QueryRow(ctx, `WITH d AS (DELETE FROM wanted WHERE h = $1 AND kind IN ('e', 'h', 'q') RETURNING n) SELECT coalesce(sum(n), 0) FROM d`, h).Scan(&n)
	if err != nil || n == 0 {
		return "", nil
	}
	q.Exec(ctx, `DELETE FROM wanted_grp WHERE h = $1`, h)
	return fmt.Sprintf("filled wanted n=%d", n), nil
}

// WantedRow is one /wanted line.
type WantedRow struct {
	Kind, Key string
	N, Groups int
	Last      time.Time
}

func (w WantedRow) String() string {
	key := w.Key
	if w.Kind == "svc" {
		name, sha, _ := strings.Cut(key, "/")
		key = name + " " + sha[:min(12, len(sha))]
	}
	if w.Kind == "h" {
		key += " (error text unknown)"
	}
	return fmt.Sprintf("%s %s n=%d groups=%d last=%s", w.Kind, doc.SafeLine(key), w.N, w.Groups, core.Date(w.Last))
}

// Wanted lists the top k gaps (8.4): n >= 3, >= 3 distinct super-groups, age >= 1 h, ordered by
// groups desc, n desc; lexicon-scored keys are excluded at write time.
func Wanted(ctx context.Context, q core.Q, k int) ([]WantedRow, error) {
	if k <= 0 || k > 50 {
		k = 50
	}
	rows, err := q.Query(ctx, `SELECT kind, key, n, groups, last FROM wanted WHERE n >= 3 AND groups >= 3 AND first <= now() - interval '1 hour'
		ORDER BY groups DESC, n DESC, last DESC LIMIT $1`, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WantedRow
	for rows.Next() {
		var w WantedRow
		if err := rows.Scan(&w.Kind, &w.Key, &w.N, &w.Groups, &w.Last); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// WantedDoc renders GET /wanted (noindex).
func WantedDoc(ctx context.Context, q core.Q, k int) (*doc.Doc, error) {
	rows, err := Wanted(ctx, q, k)
	if err != nil {
		return nil, err
	}
	d := &doc.Doc{Head: fmt.Sprintf("wanted: %d gaps (n>=3 agents, >=3 networks)", len(rows)), Title: "wanted: gaps agents asked for",
		Desc: "Libraries, versions, error signatures and digests agents looked for and did not find.", Canonical: "/wanted", NoIndex: true, Budget: 400}
	for _, w := range rows {
		d.Rows = append(d.Rows, []string{w.String()})
	}
	if WantedExtraFn != nil {
		for _, l := range WantedExtraFn(ctx, q) {
			d.Rows = append(d.Rows, []string{doc.SafeLine(l)})
		}
	}
	d.Next = []doc.Action{doc.POST("/v1/kb", "title=<key>"), doc.POST("/v1/v", "post a claim"), doc.GET("/f/wanted.atom", "")}
	return d, nil
}

// wantedFeed is the /f/wanted source.
func wantedFeed(ctx context.Context, q core.Q, n int) ([]core.FeedItem, error) {
	rows, err := Wanted(ctx, q, n)
	if err != nil {
		return nil, err
	}
	out := make([]core.FeedItem, 0, len(rows))
	for _, w := range rows {
		out = append(out, core.FeedItem{ID: "wanted/" + w.Kind + "/" + fmt.Sprintf("%x", wantedH(w.Key))[:16], URL: doc.Base() + "/wanted",
			Title: w.String(), Summary: fmt.Sprintf("%d agents in %d networks", w.N, w.Groups), Updated: w.Last, Published: w.Last, Tags: []string{w.Kind}})
	}
	return out, nil
}

// WantedPrune is the janitor: per-kind cap (lowest demand first), the global row cap (lowest n
// older than 30 d), and group hashes older than a day (not re-countable).
func WantedPrune(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `DELETE FROM wanted_grp WHERE at < now() - interval '1 day'`); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM wanted w USING (SELECT kind, h, row_number() OVER (PARTITION BY kind ORDER BY n DESC, groups DESC, last DESC) AS rn FROM wanted) r
		WHERE w.kind = r.kind AND w.h = r.h AND r.rn > $1`, WantedPerKind); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `DELETE FROM wanted WHERE (kind, h) IN (SELECT kind, h FROM wanted WHERE last < now() - interval '30 days'
		ORDER BY n ASC LIMIT greatest(0, (SELECT count(*) FROM wanted) - $1))`, WantedMaxRows)
	return err
}
