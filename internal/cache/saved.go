package cache

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Accrue adds tokens saved by root through src (kb, cache, digest, claim, compute) to the saved
// ledger and the materialised identities.saved_tokens, capped at DailySaved per root per day
// (16.4). Display only: nothing here moves quotas, rep or ranking. kb.SavedHook and the other
// owners call it inside their own transactions.
func Accrue(ctx context.Context, q core.Q, root, src string, tokens int) error {
	if !srcs[src] {
		return core.Bad("saved src")
	}
	if tokens <= 0 || root == "" {
		return nil
	}
	return inTx(ctx, q, func(tx core.Q) error {
		var today int64
		// The root row is the serialisation point for the day cap.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM identities WHERE id = $1 FOR UPDATE`, root); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(tokens), 0) FROM saved WHERE root = $1 AND day = current_date`, root).Scan(&today); err != nil {
			return err
		}
		n := min(int64(tokens), DailySaved-today)
		if n <= 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO saved (root, day, src, tokens) VALUES ($1, current_date, $2, $3)
			ON CONFLICT (root, day, src) DO UPDATE SET tokens = saved.tokens + EXCLUDED.tokens`, root, src, n); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE identities SET saved_tokens = saved_tokens + $2 WHERE id = $1`, root, n)
		return err
	})
}

// Human renders a token count the way me and /stats show it: 950, 12.4k, 1.2M.
func Human(n int64) string {
	switch {
	case n < 1000:
		return strconv.FormatInt(n, 10)
	case n < 1_000_000:
		return trim1(float64(n)/1000) + "k"
	default:
		return trim1(float64(n)/1_000_000) + "M"
	}
}

func trim1(f float64) string {
	s := strconv.FormatFloat(f, 'f', 1, 64)
	if len(s) > 2 && s[len(s)-2:] == ".0" {
		s = s[:len(s)-2]
	}
	return s
}

// Stats are the platform totals of GET /stats (16.4).
type Stats struct {
	Total, D30 int64            // tokens saved, all time and last 30 days
	BySrc      map[string]int64 // last 30 days per source
	Rows, Hits int64            // live cache rows and their hits
	Producers  int64            // distinct producer roots of live rows
	Top        []TopRow         // opt-in top 20 (identities.public_stats)
	ComputedAt time.Time
}

// TopRow is one opt-in root of the top list.
type TopRow struct {
	Root  string
	Saved int64
}

var srcOrder = []string{"kb", "cache", "digest", "claim", "compute"}

// Totals computes the platform stats (one read pass; callers cache it).
func Totals(ctx context.Context, q core.Q) (*Stats, error) {
	st := &Stats{BySrc: map[string]int64{}, ComputedAt: time.Now()}
	if err := q.QueryRow(ctx, `SELECT coalesce(sum(saved_tokens), 0) FROM identities WHERE parent IS NULL`).Scan(&st.Total); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT src, sum(tokens) FROM saved WHERE day > current_date - 30 GROUP BY src`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var src string
		var n int64
		if err := rows.Scan(&src, &n); err != nil {
			rows.Close()
			return nil, err
		}
		st.BySrc[src] = n
		st.D30 += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := q.QueryRow(ctx, `SELECT count(*), coalesce(sum(hits), 0), count(DISTINCT producer_root) FILTER (WHERE producer_root <> '')
		FROM cache WHERE NOT hidden AND expires_at > now()`).Scan(&st.Rows, &st.Hits, &st.Producers); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT id, saved_tokens FROM identities WHERE parent IS NULL AND public_stats AND saved_tokens > 0
		AND revoked_at IS NULL ORDER BY saved_tokens DESC, id LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t TopRow
		if err := rows.Scan(&t.Root, &t.Saved); err != nil {
			return nil, err
		}
		st.Top = append(st.Top, t)
	}
	return st, rows.Err()
}

// Doc renders the stats (<= 120 tokens with the totals: head line, by: line, top rows).
func (st *Stats) Doc() *doc.Doc {
	d := &doc.Doc{
		Head:  fmt.Sprintf("stats saved_total=%s saved_30d=%s rows=%d hits=%d producers=%d", Human(st.Total), Human(st.D30), st.Rows, st.Hits, st.Producers),
		Title: "tokens saved", Desc: "tokens saved by the commons: cached results, confirmed fixes, digests", Canonical: "/stats",
		MaxAge: 60, Budget: 400, Cols: []string{"root", "saved"},
	}
	var by []string
	for _, s := range srcOrder {
		if n := st.BySrc[s]; n > 0 {
			by = append(by, s+" "+Human(n))
		}
	}
	if len(by) > 0 {
		d.Fields = append(d.Fields, doc.F{Name: "by", Val: joinSpace(by)})
	}
	for _, t := range st.Top {
		d.Rows = append(d.Rows, []string{t.Root, Human(t.Saved)})
	}
	d.Next = []doc.Action{doc.GET("/stats.json", ""), doc.GET("/llms.txt", "")}
	return d
}

func joinSpace(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}

// statsCache holds the last computed stats for StatsTTL (anonymous reads never recompute within it).
var (
	statsCache atomic.Pointer[Stats]
	// StatsTTL is how long /stats serves a computed snapshot.
	StatsTTL = 60 * time.Second
)

// stats returns the cached snapshot or recomputes it.
func (s *svc) stats(ctx context.Context) (*Stats, error) {
	if st := statsCache.Load(); st != nil && time.Since(st.ComputedAt) < StatsTTL {
		return st, nil
	}
	st, err := Totals(ctx, s.d.DB)
	if err != nil {
		return nil, err
	}
	statsCache.Store(st)
	return st, nil
}

// MonthlyTotal is the live 30-day total for llms.txt (8.6).
func (s *svc) monthlyTotal(ctx context.Context) int64 {
	st, err := s.stats(ctx)
	if err != nil {
		return 0
	}
	return st.D30
}
