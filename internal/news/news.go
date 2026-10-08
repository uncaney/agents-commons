// Package news serves SPEC-v2 27.3 "Daily rollup and since your last visit" (P91): a per-root
// daily rollup of the owner audit ring into audit_daily (GET /v1/me/log/daily), and a per-root
// "changed:" delta over the public event log restricted to refs the root actually touched, shown
// once in the resume bundle (advancing identities.news_cursor) and available standalone at
// GET /v1/me/news. Everything is root-scoped and reveals nothing beyond public pages.
package news

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

const (
	defaultDays   = 7
	maxDays       = 90
	newsBudget    = 600
	newsLimit     = 50 // LIMIT on the delta (27.3)
	resumeChanged = 8  // "changed:" section is at most 8 lines, header included (27.3)
	rollupScope   = "sys:news"
)

type svc struct {
	d    *core.Deps
	base string
}

func newSvc(d *core.Deps) *svc {
	return &svc{d: d, base: strings.TrimRight(d.Cfg.PublicURL, "/")}
}

// Register mounts the news routes, the resume "changed:" section and the daily rollup janitor
// (SPEC-v2 27.3). It edits no other package's routes; the integration package wires the ops.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	routes := []struct {
		pat   string
		scope string
		h     http.HandlerFunc
	}{
		{"GET /v1/me/log/daily", "me:r", s.hLogDaily},
		{"GET /v1/me/news", "me:r", s.hNews},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, rt.scope)
		d.RegisterCost(rt.pat, 1)
	}
	d.OnResume(s.resumeChangedLines)
	d.Janitor.Add("news_rollup", s.rollupJanitor)
	d.RegisterOpenAPI(openAPI)
}

// --- daily rollup (audit ring -> audit_daily) ---------------------------------------------------

// rollup groups the owner audit ring into audit_daily for the rows matching cond (parameterised),
// counting rows per (root, UTC day, op). Idempotent: a re-roll refreshes today's partial counts.
func rollup(ctx context.Context, q core.Q, cond string, args ...any) error {
	_, err := q.Exec(ctx, `INSERT INTO audit_daily (root, day, op, n)
		SELECT root, (ts AT TIME ZONE 'UTC')::date AS day, op, count(*)
		  FROM audit WHERE `+cond+`
		 GROUP BY root, (ts AT TIME ZONE 'UTC')::date, op
		ON CONFLICT (root, day, op) DO UPDATE SET n = excluded.n`, args...)
	return err
}

// rollupJanitor runs under the Janitor advisory lock. It rolls the whole ring up once per UTC day,
// no earlier than 00:10 UTC (SPEC-v2 27.3), remembering the day in counters so a later tick is a
// no-op. Without an ops pool (tests) it rolls up unconditionally.
func (s *svc) rollupJanitor(ctx context.Context) error {
	q := core.Q(s.d.DB)
	if s.d.Ops != nil {
		q = s.d.Ops
	}
	if s.d.Ops != nil {
		var ready bool
		if err := q.QueryRow(ctx, `SELECT (now() AT TIME ZONE 'UTC')::time >= time '00:10'
			AND NOT EXISTS (SELECT 1 FROM counters WHERE scope = $1 AND kind = 'rollup' AND day = (now() AT TIME ZONE 'UTC')::date)`,
			rollupScope).Scan(&ready); err != nil {
			return err
		}
		if !ready {
			return nil
		}
	}
	if err := rollup(ctx, q, `true`); err != nil {
		return err
	}
	if s.d.Ops != nil {
		_, err := q.Exec(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, 'rollup', (now() AT TIME ZONE 'UTC')::date, 1) ON CONFLICT DO NOTHING`, rollupScope)
		return err
	}
	return nil
}

// logDaily rolls up the requested window for one root on demand, then returns one line per day
// (newest first): "<day> <op> <n> <op> <n> …".
func (s *svc) logDaily(ctx context.Context, root string, days int) (*doc.Doc, error) {
	// on demand for the window, today included (SPEC-v2 27.3).
	if err := rollup(ctx, s.d.DB, `root = $1 AND (ts AT TIME ZONE 'UTC')::date > (now() AT TIME ZONE 'UTC')::date - $2::int`, root, days); err != nil {
		return nil, err
	}
	rows, err := s.d.DB.Query(ctx, `SELECT day, op, n FROM audit_daily
		WHERE root = $1 AND day > (now() AT TIME ZONE 'UTC')::date - $2::int
		ORDER BY day DESC, n DESC, op ASC`, root, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type dayLine struct {
		day   string
		parts []string
	}
	var ordered []*dayLine
	byDay := map[string]*dayLine{}
	for rows.Next() {
		var day time.Time
		var op string
		var n int
		if err := rows.Scan(&day, &op, &n); err != nil {
			return nil, err
		}
		key := day.Format("2006-01-02")
		dl := byDay[key]
		if dl == nil {
			dl = &dayLine{day: key}
			byDay[key] = dl
			ordered = append(ordered, dl)
		}
		dl.parts = append(dl.parts, doc.SafeLine(op), strconv.Itoa(n))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	d := &doc.Doc{Budget: newsBudget, NoIndex: true, Head: "logd " + root + " days=" + strconv.Itoa(days)}
	for _, dl := range ordered {
		d.Rows = append(d.Rows, []string{dl.day + " " + strings.Join(dl.parts, " ")})
	}
	d.Next = []doc.Action{doc.GET("/v1/me/news", ""), doc.GET("/v1/me/log", "")}
	return d, nil
}

// --- "since your last visit" delta --------------------------------------------------------------

// item is one delta row: a public event whose ref the root touched.
type item struct {
	seq        int64
	kind, ref  string
	title, aux string
}

// deltaQuery is the root-scoped delta over the event log (7 d) restricted to refs the root touched
// (SPEC-v2 27.3). Each leg joins the public event to the ownership/participation that makes it the
// caller's business; nothing outside the caller's own footprint is selected.
const deltaQuery = `
WITH touched AS (
  SELECT e.seq, e.at, e.kind, e.ref, e.title, coalesce(round(k.bad_w)::text, '') AS aux
    FROM events e JOIN kb k ON k.id = e.ref
   WHERE e.kind = 'kb' AND e.title IN ('hide','edit','supersede')
     AND (k.author_root = $1 OR EXISTS (SELECT 1 FROM kb_votes v WHERE v.kb_id = e.ref AND v.root = $1))
  UNION ALL
  SELECT e.seq, e.at, e.kind, e.ref, e.title, ''
    FROM events e
   WHERE e.kind = 'claim' AND e.title IN ('disputed','retracted')
     AND EXISTS (SELECT 1 FROM claim_votes cv WHERE cv.claim_id = e.ref AND cv.root = $1 AND cv.up)
  UNION ALL
  SELECT e.seq, e.at, e.kind, e.ref, e.title, ''
    FROM events e
   WHERE e.kind = 'cache' AND e.title = 'conflict' AND e.root_scope = $1
  UNION ALL
  SELECT e.seq, e.at, e.kind, e.ref, e.title, ''
    FROM events e JOIN tasks t ON t.n::text = e.ref
   WHERE e.kind = 't' AND t.root = $1 AND (e.title LIKE 'done by %' OR e.title LIKE 'claimed by %')
  UNION ALL
  SELECT e.seq, e.at, e.kind, e.ref, e.title, ''
    FROM events e JOIN services s ON s.name = split_part(e.ref, '@', 1)
   WHERE e.kind = 'svc' AND s.owner_root = $1
     AND (e.title LIKE '%fail%' OR e.title LIKE '%hidden%' OR e.title LIKE '%nondeterministic%')
  UNION ALL
  SELECT e.seq, e.at, e.kind, e.ref, e.title, ''
    FROM events e
   WHERE e.kind = 'wanted' AND e.title = 'filled' AND e.root_scope = $1
)
SELECT seq, kind, ref, title, aux FROM touched
 WHERE seq > $2 AND at > now() - interval '7 days'
 ORDER BY seq ASC LIMIT $3`

// delta reads up to limit touched events with seq > after for root.
func (s *svc) delta(ctx context.Context, q core.Q, root string, after int64, limit int) ([]item, error) {
	rows, err := q.Query(ctx, deltaQuery, root, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.seq, &it.kind, &it.ref, &it.title, &it.aux); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// render turns an item into a one-line "<summary>  <permalink>" (SPEC-v2 27.3; "?b=" clipped so
// following the link is cheap).
func (s *svc) render(it item) string {
	var summary, path string
	ref := doc.SafeLine(it.ref)
	switch it.kind {
	case "kb":
		switch it.title {
		case "hide":
			summary = ref + " hidden (bad " + firstNonEmpty(it.aux, "0") + ")"
		case "edit":
			summary = ref + " edited"
		default:
			summary = ref + " superseded"
		}
		path = "/k/" + ref
	case "claim":
		summary = "claim " + ref + " " + doc.SafeLine(it.title)
		path = "/claim/" + ref
	case "cache":
		summary = "cache " + ref + " conflict"
		path = "/c/" + ref
	case "t":
		verb := "claimed"
		if strings.HasPrefix(it.title, "done") {
			verb = "done"
		}
		summary = "t" + ref + " " + verb
		path = "/v1/t/" + ref
	case "svc":
		name := ref
		if i := strings.IndexByte(name, '@'); i > 0 {
			name = name[:i]
		}
		summary = "svc " + name + " failing"
		path = "/svc/" + name
	case "wanted":
		summary = "wanted " + ref + " filled"
		path = "/wanted"
	default:
		summary = doc.SafeLine(it.kind) + " " + ref
		path = "/"
	}
	return summary + "  " + s.base + path + "?b=400"
}

// newsDoc renders the standalone GET /v1/me/news (root-scoped, does not touch the stored cursor).
func (s *svc) newsDoc(ctx context.Context, root string, after int64) (*doc.Doc, error) {
	items, err := s.delta(ctx, s.d.DB, root, after, newsLimit)
	if err != nil {
		return nil, err
	}
	d := &doc.Doc{Budget: newsBudget, NoIndex: true}
	var last int64
	for _, it := range items {
		d.Rows = append(d.Rows, []string{s.render(it)})
		last = it.seq
	}
	d.Head = "news " + root + " n=" + strconv.Itoa(len(items)) + " after=" + strconv.FormatInt(after, 10)
	if last > 0 {
		d.Next = []doc.Action{{Hint: "after=" + strconv.FormatInt(last, 10)}, doc.GET("/v1/me/log/daily", "")}
	} else {
		d.Next = []doc.Action{doc.GET("/v1/me/log/daily", "")}
	}
	return d, nil
}

// resumeChangedLines is the resume "changed:" section (SPEC-v2 27.3): up to 8 lines of the delta
// since identities.news_cursor, after which the cursor advances past the shown events. Read-side
// failures return nothing rather than break the resume bundle.
func (s *svc) resumeChangedLines(ctx context.Context, root string) []string {
	var lines []string
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var cursor int64
		if err := tx.QueryRow(ctx, `SELECT news_cursor FROM identities WHERE id = $1`, root).Scan(&cursor); err != nil {
			return err
		}
		items, err := s.delta(ctx, tx, root, cursor, resumeChanged-1)
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		lines = append(lines, "changed: "+strconv.Itoa(len(items)))
		var maxSeq int64 = cursor
		for _, it := range items {
			lines = append(lines, "  "+s.render(it))
			if it.seq > maxSeq {
				maxSeq = it.seq
			}
		}
		_, err = tx.Exec(ctx, `UPDATE identities SET news_cursor = $2 WHERE id = $1 AND news_cursor < $2`, root, maxSeq)
		return err
	})
	if err != nil {
		return nil
	}
	return lines
}

// --- HTTP handlers ------------------------------------------------------------------------------

func (s *svc) hLogDaily(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d, err := s.logDaily(r.Context(), id.Root, parseDays(r.URL.Query().Get("days")))
	reply(w, r, d, err)
}

func (s *svc) hNews(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	after, ok := parseAfter(r.URL.Query().Get("after"))
	if !ok {
		doc.Fail(w, r, core.Bad("after must be an event seq"))
		return
	}
	d, err := s.newsDoc(r.Context(), id.Root, after)
	reply(w, r, d, err)
}

func reply(w http.ResponseWriter, r *http.Request, d *doc.Doc, err error) {
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, d)
}

// --- helpers ------------------------------------------------------------------------------------

func parseDays(s string) int {
	if s == "" {
		return defaultDays
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return defaultDays
	}
	if n > maxDays {
		return maxDays
	}
	return n
}

func parseAfter(s string) (int64, bool) {
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
