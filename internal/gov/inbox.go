package gov

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Operator inbox (SPEC-v2 18.5): everything the operator machine polls through the read-only token. Items are
// derived from the event log (core.Event rows of kinds p and ops), copied once into inbox_items
// keyed by the events seq (the poll cursor) and capped at InboxDailyCap new items per kind and
// day; the overflow collapses into one summary row per kind. Proposal rows are re-read on every
// poll so a decided proposal leaves the inbox at once. Every title is agent text: cleaned here,
// cleaned again by cxa, never a command.

const (
	InboxDailyCap = 20
	inboxMaxK     = 100
	inboxScan     = 500
	inboxLookback = 200
	inboxKeepD    = 90
)

var inboxKindRe = regexp.MustCompile(`^[a-z][a-z_-]{0,23}$`)

// InboxRow is one GET /admin/inbox row; the JSON names are the 18.5 contract cxa reads.
type InboxRow struct {
	Cursor   int64     `json:"cursor"`
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	Scope    string    `json:"scope"`
	Title    string    `json:"title"`
	SupportW float64   `json:"support_w"`
	Groups   int       `json:"groups"`
	Created  time.Time `json:"created"`
	URL      string    `json:"url"`
	Status   string    `json:"status"`
	Summary  bool      `json:"summary,omitempty"`
	More     int       `json:"more,omitempty"`
}

// Line renders a row for text clients: `<cursor> <kind> <id> <status> <scope> support=<w> groups=<n> <title>`.
func (r InboxRow) Line() string {
	return fmt.Sprintf("%d %s %s %s %s support=%s groups=%d %s", r.Cursor, r.Kind, r.ID, r.Status, r.Scope, fw(r.SupportW), r.Groups, doc.SafeLine(r.Title))
}

// classify maps an event to an inbox kind; ok is false for events the inbox ignores.
func classify(kind, ref, title string) (string, bool) {
	switch kind {
	case "p":
		f := strings.Fields(title)
		if len(f) < 2 {
			return "", false
		}
		switch f[0] {
		case "awaiting_operator":
			if kindRe.MatchString(f[1]) {
				return f[1], true // platform | doc | svc-bless | a later awaitOperator kind
			}
		case "check":
			return "code", true
		case "revisit":
			return "revisit", true
		}
		return "", false
	case "ops":
		switch {
		case strings.HasPrefix(ref, "pin:"):
			return "pin", true
		case ref == "audit_fail":
			return "audit_fail", true
		case ref == "disk" || strings.HasPrefix(ref, "freeze"):
			return "freeze", true
		case strings.HasPrefix(ref, "digest:"):
			return "digest", true
		case ref == "unfunded":
			return "unfunded", true
		case strings.HasPrefix(ref, "notice") || core.ValidIDPrefix(ref, 'n') || strings.HasPrefix(title, "notice") || strings.HasPrefix(title, "counter"):
			return "notice", true
		case strings.HasPrefix(ref, "audit:") || strings.Contains(title, "audit"):
			return "audit", true
		case strings.HasPrefix(title, "compute:"):
			return "compute", true
		}
		return "ops", true
	}
	return "", false
}

// Ingest copies new inbox-relevant events into inbox_items under an advisory lock, looking back a
// little past the last seq so a row committed out of order is not lost (inserts are idempotent),
// counts each new row per kind and day and marks the rows past InboxDailyCap as overflow.
func Ingest(ctx context.Context, d *core.Deps) error {
	return core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('gov:inbox'))`); err != nil {
			return err
		}
		var last int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(seq), 0) FROM inbox_items`).Scan(&last); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT seq, at, kind, ref, title FROM events WHERE seq > $1 AND kind IN ('p', 'ops') ORDER BY seq LIMIT $2`, max(last-inboxLookback, 0), inboxScan)
		if err != nil {
			return err
		}
		type ev struct {
			seq              int64
			at               time.Time
			kind, ref, title string
		}
		var evs []ev
		for rows.Next() {
			var e ev
			if err := rows.Scan(&e.seq, &e.at, &e.kind, &e.ref, &e.title); err != nil {
				rows.Close()
				return err
			}
			evs = append(evs, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, e := range evs {
			ik, ok := classify(e.kind, e.ref, e.title)
			if !ok {
				continue
			}
			day := e.at.UTC().Format("2006-01-02")
			tag, err := tx.Exec(ctx, `INSERT INTO inbox_items (seq, at, day, kind, ref, title) VALUES ($1, $2, $3::date, $4, $5, $6) ON CONFLICT (seq) DO NOTHING`,
				e.seq, e.at, day, ik, truncRunes(doc.SafeLine(e.ref), 200), truncRunes(doc.SafeLine(e.title), 160))
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				continue
			}
			var n int
			if err := tx.QueryRow(ctx, `INSERT INTO inbox_counts (kind, day, n) VALUES ($1, $2::date, 1) ON CONFLICT (kind, day) DO UPDATE SET n = inbox_counts.n + 1 RETURNING n`, ik, day).Scan(&n); err != nil {
				return err
			}
			if n > InboxDailyCap {
				if _, err := tx.Exec(ctx, `UPDATE inbox_items SET overflow = true WHERE seq = $1`, e.seq); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

type inboxItem struct {
	seq            int64
	at             time.Time
	day, kind, ref string
	title          string
	overflow       bool
}

// Inbox lists the operator inbox after cursor since: rows in cursor order (k <= 100 per poll), one
// kind when kind is set; overflow rows collapse into one summary row per kind and day unless all
// is set. A proposal that appears in several events (one per check) keeps its latest row only.
func Inbox(ctx context.Context, q core.Q, since int64, k int, kind string, all bool) ([]InboxRow, error) {
	if k <= 0 || k > inboxMaxK {
		k = 50
	}
	rows, err := q.Query(ctx, `SELECT seq, at, day::text, kind, ref, title, overflow FROM inbox_items WHERE seq > $1 AND ($2 = '' OR kind = $2) ORDER BY seq LIMIT $3`, since, kind, inboxScan)
	if err != nil {
		return nil, err
	}
	var items []inboxItem
	for rows.Next() {
		var it inboxItem
		if err := rows.Scan(&it.seq, &it.at, &it.day, &it.kind, &it.ref, &it.title, &it.overflow); err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	type sumKey struct{ kind, day string }
	sums := map[sumKey]*InboxRow{}
	var sumOrder []sumKey
	seen := map[string]int{}
	out := []InboxRow{}
	var lastOut int64
	truncated := false
	for _, it := range items {
		if it.overflow && !all {
			key := sumKey{it.kind, it.day}
			s := sums[key]
			if s == nil {
				s = &InboxRow{Kind: it.kind, Created: it.at, Summary: true, Status: "summary"}
				sums[key] = s
				sumOrder = append(sumOrder, key)
			}
			s.More++
			s.Cursor = it.seq
			continue
		}
		if len(out) >= k {
			truncated = true
			continue
		}
		row, ok, err := inboxRow(ctx, q, it)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if row.ID != "" && core.ValidIDPrefix(row.ID, 'p') {
			if i, dup := seen[row.ID]; dup {
				out[i] = row
				continue
			}
			seen[row.ID] = len(out)
		}
		out = append(out, row)
		lastOut = it.seq
	}
	for _, key := range sumOrder {
		s := sums[key]
		s.Title = fmt.Sprintf("%s +%d more (see /admin/inbox?kind=%s&all=1)", s.Kind, s.More, s.Kind)
		s.URL = "/admin/inbox?kind=" + s.Kind + "&all=1"
		s.ID = "summary:" + s.Kind + ":" + key.day
		// a truncated page never moves the cursor past rows the client has not seen
		if truncated && lastOut > 0 && s.Cursor > lastOut {
			s.Cursor = lastOut
		}
		out = append(out, *s)
	}
	return out, nil
}

// inboxRow enriches one stored item with its live status; ok is false when it no longer belongs
// in the inbox (decided proposal, hidden row, decided notice).
func inboxRow(ctx context.Context, q core.Q, it inboxItem) (InboxRow, bool, error) {
	row := InboxRow{Cursor: it.seq, ID: it.ref, Kind: it.kind, Scope: "platform", Title: it.title, Created: it.at, Status: "new", URL: "/admin/stats"}
	switch {
	case core.ValidIDPrefix(it.ref, 'p'):
		p, err := load(ctx, q, it.ref)
		if errors.Is(err, core.ErrNotFound) {
			return row, false, nil
		}
		if err != nil {
			return row, false, err
		}
		if p.Hidden {
			return row, false, nil
		}
		switch it.kind {
		case "code":
			if p.CheckStatus == "" || p.Terminal() {
				return row, false, nil
			}
			row.Status = p.State + " check=" + p.CheckStatus
		case "revisit":
			if p.State != "deferred" {
				return row, false, nil
			}
			row.Status = p.State
		default:
			if p.State != "awaiting_operator" {
				return row, false, nil
			}
			row.Status = p.State
		}
		row.ID, row.Scope, row.Title, row.SupportW, row.Groups, row.Created, row.URL = p.ID, scopeName(p.Scope), p.title(), p.YesW, p.Groups, p.Created, "/p/"+p.ID
		if n, ok, err := taskOf(ctx, q, p.ID); err != nil {
			return row, false, err
		} else if ok {
			row.Title += " task=#" + strconv.FormatInt(n, 10)
		}
	case it.kind == "pin":
		row.ID, row.URL = strings.TrimPrefix(it.ref, "pin:"), "/v1/pins"
	case it.kind == "notice":
		row.URL = "/admin/notices"
		if core.ValidIDPrefix(it.ref, 'n') {
			ok, err := noticeStatus(ctx, q, it.ref, &row)
			if err != nil || !ok {
				return row, false, err
			}
		}
	case it.kind == "audit_fail":
		row.URL = "/admin/audit"
	}
	return row, true, nil
}

// colSeen caches the columns a later migration adds (proposals.task, revisit_at: 0172); only a
// positive answer is cached so a column appearing after boot is picked up.
var colSeen sync.Map

// hasColumn reports whether a table has a column (expand-only migrations of later packages).
func hasColumn(ctx context.Context, q core.Q, table, col string) (bool, error) {
	key := table + "." + col
	if _, ok := colSeen.Load(key); ok {
		return true, nil
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)`, table, col).Scan(&ok); err != nil {
		return false, err
	}
	if ok {
		colSeen.Store(key, true)
	}
	return ok, nil
}

// taskOf returns proposals.task when the roadmap column exists and is set (27.5).
func taskOf(ctx context.Context, q core.Q, id string) (int64, bool, error) {
	ok, err := hasColumn(ctx, q, "proposals", "task")
	if err != nil || !ok {
		return 0, false, err
	}
	var n *int64
	if err := q.QueryRow(ctx, `SELECT task FROM proposals WHERE id = $1`, id).Scan(&n); err != nil || n == nil {
		return 0, false, err
	}
	return *n, true, nil
}

// noticeStatus reads a notice's action and decision when the notices table exists (4.8 is a
// later wave: to_regclass guard); a decided notice leaves the inbox.
func noticeStatus(ctx context.Context, q core.Q, id string, row *InboxRow) (bool, error) {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('notices') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		return true, err
	}
	var action, decision string
	err := q.QueryRow(ctx, `SELECT action, coalesce(decision, '') FROM notices WHERE id = $1`, id).Scan(&action, &decision)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if decision != "" {
		return false, nil
	}
	row.Status = action
	row.URL = "/notice/" + id
	return true, nil
}

// hInbox is GET /admin/inbox?since=&k=&kind=&all= (poll token): JSON rows with cursor ids.
func (s *psvc) hInbox(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	since, _ := strconv.ParseInt(v.Get("since"), 10, 64)
	if since < 0 {
		since = 0
	}
	k, _ := strconv.Atoi(v.Get("k"))
	kind := v.Get("kind")
	if kind != "" && !inboxKindRe.MatchString(kind) {
		core.Fail(w, r, core.Bad("kind"))
		return
	}
	ctx := r.Context()
	if err := Ingest(ctx, s.d); err != nil {
		core.Fail(w, r, err)
		return
	}
	rows, err := Inbox(ctx, s.d.DB, since, k, kind, v.Get("all") == "1")
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.AdminArg(r, fmt.Sprintf("since=%d kind=%s rows=%d", since, kind, len(rows)))
	w.Header().Set("Cache-Control", "private, no-store")
	core.JSON(w, 200, rows)
}

// inboxRetention drops stored items and counters older than inboxKeepD days.
func inboxRetention(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `DELETE FROM inbox_items WHERE at < now() - ($1::int * interval '1 day')`, inboxKeepD); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `DELETE FROM inbox_counts WHERE day < current_date - $1::int`, inboxKeepD)
	return err
}
