// Package events serves the event log (SPEC-v2 19.1). core.Event appends rows inside other
// packages' transactions; this package reads them by cursor (GET /v1/ev, op ev) with a long-poll
// on the notifier topic "ev", filters by kinds, keeps root-scoped rows visible to their root only,
// stores per-root watches (saved filters: kinds, tags, free-text q), feeds /f/ch through Public
// and retains 7 days / 1M rows.
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

const (
	// MaxWait is the longest long-poll (seconds), the per-request budget of 3.6.
	MaxWait = 85
	// MaxK and DefK bound ?k= (rows per reply).
	MaxK = 200
	DefK = 50
	// MaxWatches is the live watches cap per root (19.1).
	MaxWatches = 20
	MaxKinds   = 20
	MaxTags    = 20
	MaxQ       = 120 // runes of a watch query
	Topic      = "ev"

	scanCap   = 2000 // rows examined per read when tags/q filter in Go
	batchRows = 200
	watchBody = 4 << 10
)

// Retention and storage knobs (21.2); vars so tests can lower them.
var (
	KeepFor             = 7 * 24 * time.Hour
	MaxRows       int64 = 1_000_000
	MaxBytes      int64 = 512 << 20 // storage class 'events' cap
	WatchesPerDay       = 50        // watch creations per root per day (x5 established)

	kindRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,31}$`)
	tagRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,31}$`)
	settleSteps = []time.Duration{100 * time.Millisecond, 400 * time.Millisecond}
)

// Row is one event.
type Row struct {
	Seq              int64
	At               time.Time
	Kind, Ref, Title string
	Scoped           bool // root-scoped row (never public)
}

// Line renders "<seq> <kind> <ref> <title>" (user text never at column 0).
func (r Row) Line() string {
	ref := doc.SafeLine(r.Ref)
	if ref == "" {
		ref = "-"
	}
	return strings.TrimRight(strconv.FormatInt(r.Seq, 10)+" "+doc.SafeLine(r.Kind)+" "+ref+" "+doc.SafeLine(r.Title), " ")
}

// Text renders rows then the `next=<seq>` cursor line (`retry=<s>` appended when the caller
// could not wait).
func Text(rows []Row, next int64, retry int) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.Line())
		b.WriteByte('\n')
	}
	b.WriteString("next=" + strconv.FormatInt(next, 10))
	if retry > 0 {
		b.WriteString(" retry=" + strconv.Itoa(retry))
	}
	b.WriteByte('\n')
	return b.String()
}

// Filter selects rows for Query.
type Filter struct {
	After  int64 // cursor: rows with seq > After (clamped to the head)
	Latest bool  // no cursor: the newest K matching rows, oldest first
	Kinds  []string
	Tags   []string
	Q      string
	Root   string // "" = public rows only; else public rows plus the ones scoped to Root
	K      int    // 0 = DefK
}

func clampK(k int) int {
	if k <= 0 {
		return DefK
	}
	return min(k, MaxK)
}

func (f Filter) inGo() bool { return len(f.Tags) > 0 || f.Q != "" }

// fetch reads up to n rows past the cursor (seq > cursor ascending, or seq < cursor descending),
// with the visibility and kinds filters in SQL.
func fetch(ctx context.Context, q core.Q, f Filter, cursor int64, n int, desc bool) ([]Row, error) {
	var b strings.Builder
	args := []any{cursor}
	b.WriteString(`SELECT seq, at, kind, ref, title, root_scope IS NOT NULL FROM events WHERE seq `)
	if desc {
		b.WriteString(`< $1`)
	} else {
		b.WriteString(`> $1`)
	}
	if f.Root == "" {
		b.WriteString(` AND root_scope IS NULL`)
	} else {
		args = append(args, f.Root)
		b.WriteString(` AND (root_scope IS NULL OR root_scope = $2)`)
	}
	if len(f.Kinds) > 0 {
		args = append(args, f.Kinds)
		fmt.Fprintf(&b, ` AND kind = ANY($%d)`, len(args))
	}
	b.WriteString(` ORDER BY seq`)
	if desc {
		b.WriteString(` DESC`)
	}
	args = append(args, n)
	fmt.Fprintf(&b, ` LIMIT $%d`, len(args))
	rows, err := q.Query(ctx, b.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.Seq, &r.At, &r.Kind, &r.Ref, &r.Title, &r.Scoped); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Head is the latest sequence number (0 when the log is empty).
func Head(ctx context.Context, q core.Q) (int64, error) {
	var head int64
	err := q.QueryRow(ctx, `SELECT coalesce(max(seq), 0) FROM events`).Scan(&head)
	return head, err
}

// Query reads matching rows and the cursor to continue from: the seq of the last returned row
// when K rows were found, else the last seq examined (so sparse filters still make progress).
// A cursor past the head is clamped to it. At most scanCap rows are examined per call.
func Query(ctx context.Context, q core.Q, f Filter) (rows []Row, next int64, err error) {
	k := clampK(f.K)
	head, err := Head(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	if f.Latest {
		rows, _, err = scan(ctx, q, f, head+1, k, true)
		slices.Reverse(rows)
		return rows, head, err
	}
	after := max(min(f.After, head), 0)
	rows, end, err := scan(ctx, q, f, after, k, false)
	if err != nil {
		return nil, 0, err
	}
	return rows, max(after, end), nil
}

// scan walks the log from cursor in batches (seq ascending, or descending past it), applying
// Match to each row until k rows match, the log is exhausted or scanCap rows were examined. end
// is the last seq examined: every row between cursor and end that is not returned failed the
// filter, so a cursor client may skip them.
func scan(ctx context.Context, q core.Q, f Filter, cursor int64, k int, desc bool) (out []Row, end int64, err error) {
	examined := 0
	for len(out) < k && examined < scanCap {
		n := k - len(out)
		if f.inGo() {
			n = min(batchRows, scanCap-examined)
		}
		batch, err := fetch(ctx, q, f, cursor, n, desc)
		if err != nil {
			return nil, 0, err
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			cursor = r.Seq
			if Match(nil, f.Tags, f.Q, r) {
				out = append(out, r)
				if len(out) == k {
					break
				}
			}
		}
		examined += len(batch)
		if len(batch) < n {
			break
		}
	}
	return out, cursor, nil
}

// Public returns the newest n public rows (newest first), optionally restricted to kinds: the
// source of the /f/ch feed and of other packages' public listings.
func Public(ctx context.Context, q core.Q, kinds []string, n int) ([]Row, error) {
	return fetch(ctx, q, Filter{Kinds: kinds}, 1<<62, clampK(n), true)
}

// words splits s into lowercased runs of letters and digits.
func words(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

func hasWords(set map[string]bool, ws []string) bool {
	for _, w := range ws {
		if !set[w] {
			return false
		}
	}
	return true
}

// Match is the watch matcher (19.1, reused by webhooks 27.7): the kind must be in kinds (empty =
// any); every tag must equal the ref or have all its words in the title; every word of q must be
// in the title. Words are lowercased runs of letters and digits.
func Match(kinds, tags []string, q string, r Row) bool {
	if len(kinds) > 0 && !slices.Contains(kinds, r.Kind) {
		return false
	}
	if len(tags) == 0 && q == "" {
		return true
	}
	set := map[string]bool{}
	for _, w := range words(r.Title) {
		set[w] = true
	}
	ref := strings.ToLower(r.Ref)
	for _, t := range tags {
		t = strings.ToLower(t)
		if t != ref && !hasWords(set, words(t)) {
			return false
		}
	}
	return hasWords(set, words(q))
}

// Retain deletes rows older than KeepFor and the oldest rows beyond maxRows, in batches of 50k
// (janitor task events_retain). Returns the number of rows deleted.
func Retain(ctx context.Context, q core.Q, maxRows int64) (int64, error) {
	var total int64
	for _, st := range []struct {
		sql string
		arg any
	}{
		{`DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE at < now() - $1::interval ORDER BY seq LIMIT 50000)`, fmt.Sprintf("%d seconds", int64(KeepFor.Seconds()))},
		{`DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE seq <= (SELECT max(seq) FROM events) - $1 ORDER BY seq LIMIT 50000)`, maxRows},
	} {
		for i := 0; i < 20; i++ {
			tag, err := q.Exec(ctx, st.sql, st.arg)
			if err != nil {
				return total, err
			}
			total += tag.RowsAffected()
			if tag.RowsAffected() < 50000 {
				break
			}
		}
	}
	return total, nil
}

type handlers struct{ d *core.Deps }

// Register mounts GET /v1/ev and the watches routes, registers scopes, the long-poll cost, the
// OpenAPI fragment, the llms-full section, the feed source `ch`, the storage class, the retention
// janitor, the purge hook and the watches exporter.
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d}
	mux.HandleFunc("GET /v1/ev", h.ev)
	mux.HandleFunc("POST /v1/watch", h.watchCreate)
	mux.HandleFunc("GET /v1/watch", h.watchList)
	mux.HandleFunc("GET /v1/watch/{id}", h.watchGet)
	mux.HandleFunc("DELETE /v1/watch/{id}", h.watchDelete)
	d.RegisterScope("GET /v1/ev", "ev:r")
	d.RegisterScope("GET /v1/watch", "ev:r")
	d.RegisterScope("GET /v1/watch/{id}", "ev:r")
	d.RegisterScope("POST /v1/watch", "w")
	d.RegisterScope("DELETE /v1/watch/{id}", "w")
	d.RegisterCost("GET /v1/ev", 0.2)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("events", func(context.Context) string { return llmsText })
	d.RegisterFeed("ch", h.feed)
	d.StorageClass("events", MaxBytes, `SELECT pg_total_relation_size('events')`)
	d.Janitor.Add("events_retain", func(ctx context.Context) error { _, err := Retain(ctx, d.DB, MaxRows); return err })
	d.OnPurge(func(ctx context.Context, root string) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM watches WHERE root = $1`, root)
		return err
	})
	d.OnExport("watches", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
}

// feed is the `ch` source (9.3): public rows, sub = optional kinds list ("kb,t").
func (h *handlers) feed(ctx context.Context, sub string, n int) ([]core.FeedItem, error) {
	kinds, err := parseKinds(sub)
	if err != nil {
		return nil, err
	}
	rows, err := Public(ctx, h.d.DB, kinds, n)
	if err != nil {
		return nil, err
	}
	items := make([]core.FeedItem, 0, len(rows))
	for _, r := range rows {
		title := doc.SafeLine(r.Title)
		if title == "" {
			title = doc.SafeLine(r.Kind + " " + r.Ref)
		}
		items = append(items, core.FeedItem{ID: "ev/" + strconv.FormatInt(r.Seq, 10), URL: rowURL(r), Title: title,
			Summary: doc.SafeLine(strings.TrimSpace(r.Kind + " " + r.Ref + ": " + r.Title)), Updated: r.At, Published: r.At, Tags: []string{r.Kind}})
	}
	return items, nil
}

// rowURL links an event to its object when the kind has a page, else to the event itself.
func rowURL(r Row) string {
	switch r.Kind {
	case "kb":
		if core.ValidIDPrefix(r.Ref, 'k') {
			return "/k/" + r.Ref
		}
	case "t":
		if n, err := strconv.ParseInt(r.Ref, 10, 64); err == nil && n > 0 {
			return "/t/" + r.Ref
		}
	}
	return "/v1/ev?after=" + strconv.FormatInt(r.Seq-1, 10) + "&k=1"
}

// parseKinds validates a comma-separated kinds list.
func parseKinds(s string) ([]string, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	return normList(strings.Split(s, ","), MaxKinds, kindRe, "kind")
}

// normList lowercases, trims, validates, dedupes and caps a filter list; never nil.
func normList(in []string, max int, re *regexp.Regexp, what string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !re.MatchString(s) {
			return nil, core.Bad(what + " must match " + re.String())
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
		if len(out) > max {
			return nil, core.Bad(fmt.Sprintf("at most %d %ss", max, what))
		}
	}
	return out, nil
}

// evParams are the GET /v1/ev (and op ev) arguments.
type evParams struct {
	after  int64
	latest bool
	kinds  []string
	w      string
	wait   int
	k      int
}

func parseEv(v url.Values) (evParams, error) {
	var p evParams
	if s, ok := v["after"]; ok {
		n, err := strconv.ParseInt(strings.TrimSpace(s[0]), 10, 64)
		if err != nil || n < 0 {
			return p, core.Bad("after must be a sequence number")
		}
		p.after = n
	} else {
		p.latest = true
	}
	kinds, err := parseKinds(v.Get("kinds"))
	if err != nil {
		return p, err
	}
	p.kinds = kinds
	if p.w = v.Get("w"); p.w != "" && !core.ValidIDPrefix(p.w, 'w') {
		return p, core.ErrNotFound
	}
	if s := v.Get("wait"); s != "" {
		if p.wait, err = strconv.Atoi(s); err != nil || p.wait < 0 || p.wait > MaxWait {
			return p, core.Bad("wait must be 0.." + strconv.Itoa(MaxWait))
		}
	}
	if s := v.Get("k"); s != "" {
		if p.k, err = strconv.Atoi(s); err != nil || p.k < 1 || p.k > MaxK {
			return p, core.Bad("k must be 1.." + strconv.Itoa(MaxK))
		}
	}
	return p, nil
}

type evResult struct {
	rows  []Row
	next  int64
	retry int // 5 when a requested wait could not be honoured
}

// read resolves the watch, applies the long-poll policy (3.6: tokens only, d.Waiters slot,
// shed:longpoll) and polls Query until rows appear or the wait ends. core.Event wakes Topic
// before the writer's commit, so an empty re-read after a wake settles briefly and re-reads.
func (h *handlers) read(ctx context.Context, id *core.Ident, p evParams, group string) (*evResult, error) {
	f := Filter{After: p.after, Latest: p.latest, Kinds: p.kinds, K: p.k}
	if id != nil {
		f.Root = id.Root
	}
	if p.w != "" {
		if id == nil {
			return nil, core.ErrAuth
		}
		wt, err := Get(ctx, h.d.DB, id.Root, p.w)
		if err != nil {
			return nil, err
		}
		if f.Kinds, err = intersect(p.kinds, wt.Kinds); err != nil {
			return nil, err
		}
		f.Tags, f.Q = wt.Tags, wt.Q
	}
	if !f.Latest {
		// Clamp a cursor past the head once, here: clamping per re-read against a moving head
		// would hide the rows a long-poll is waiting for.
		head, err := Head(ctx, h.d.DB)
		if err != nil {
			return nil, err
		}
		f.After = min(f.After, head)
	}
	res := &evResult{}
	wait := p.wait
	if wait > 0 && (id == nil || f.Latest || h.d.Shed(nil, "longpoll")) {
		wait, res.retry = 0, 5
	}
	if wait > 0 {
		release, ok := h.d.Waiters.Acquire(id.Root, group)
		if !ok {
			wait, res.retry = 0, 5
		} else {
			defer release()
		}
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	settle := len(settleSteps)
	for {
		var c <-chan struct{}
		cancel := func() {}
		if wait > 0 {
			c, cancel = h.d.Notify.Subscribe(Topic) // subscribe, then read, so a wake in between is kept
		}
		rows, next, err := Query(ctx, h.d.DB, f)
		if err != nil {
			cancel()
			return nil, err
		}
		res.rows, res.next = rows, next
		rem := time.Until(deadline)
		if len(rows) > 0 || wait == 0 || rem <= 0 {
			cancel()
			return res, nil
		}
		if settle < len(settleSteps) {
			rem = min(rem, settleSteps[settle])
			settle++
		}
		t := time.NewTimer(rem)
		select {
		case <-c:
			settle = 0
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return res, nil
		}
		t.Stop()
		cancel()
	}
}

// intersect narrows a watch's kinds by the request's; both set and disjoint is a client error.
func intersect(req, watch []string) ([]string, error) {
	switch {
	case len(req) == 0:
		return watch, nil
	case len(watch) == 0:
		return req, nil
	}
	var out []string
	for _, k := range req {
		if slices.Contains(watch, k) {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil, core.Bad("kinds outside the watch")
	}
	return out, nil
}

// evPath builds the continuation path for X-Next.
func evPath(next int64, kinds []string, w string) string {
	p := "/v1/ev?after=" + strconv.FormatInt(next, 10)
	if len(kinds) > 0 {
		p += "&kinds=" + strings.Join(kinds, ",")
	}
	if w != "" {
		p += "&w=" + w
	}
	return p
}

// fit applies a byte budget to rows: whole lines, at least one, dropped from the end (cursor
// reads) or from the start (latest window keeps the newest).
func fit(rows []Row, maxBytes int, fromEnd bool) []Row {
	if maxBytes <= 0 || len(rows) == 0 {
		return rows
	}
	used, n := 32, 0
	for i := range rows {
		j := i
		if fromEnd {
			j = len(rows) - 1 - i
		}
		used += len(rows[j].Line()) + 1
		if used > maxBytes && n > 0 {
			break
		}
		n++
	}
	if fromEnd {
		return rows[len(rows)-n:]
	}
	return rows[:n]
}

// ev serves GET /v1/ev: rows then `next=<seq>` (txt) or {"rows":[…],"next_seq":n} (json); the
// continuation travels in X-Next. Never cached.
func (h *handlers) ev(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Cache-Control", "no-store")
	hd.Add("Vary", "Accept")
	id, err := h.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	p, err := parseEv(r.URL.Query())
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	res, err := h.read(r.Context(), id, p, h.d.IPGroup(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	rows := res.rows
	if b := doc.BudgetFor(r, 400); b > 0 {
		if rows = fit(rows, b*4, p.latest); !p.latest && len(rows) < len(res.rows) {
			res.next = rows[len(rows)-1].Seq
		}
	}
	doc.RawActions(w, r, doc.GET(evPath(res.next, p.kinds, p.w), ""))
	if doc.Negotiate(r) == doc.JSON {
		type jrow struct {
			Seq   int64     `json:"seq"`
			At    time.Time `json:"at"`
			Kind  string    `json:"kind"`
			Ref   string    `json:"ref"`
			Title string    `json:"title"`
		}
		out := struct {
			Rows  []jrow `json:"rows"`
			Next  int64  `json:"next_seq"`
			Retry int    `json:"retry_s,omitempty"`
		}{Rows: make([]jrow, 0, len(rows)), Next: res.next, Retry: res.retry}
		for _, x := range rows {
			out.Rows = append(out.Rows, jrow{x.Seq, x.At.UTC(), x.Kind, x.Ref, x.Title})
		}
		core.JSON(w, 200, out)
		return
	}
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, Text(rows, res.next, res.retry))
}

// export writes the root's watches as JSONL (export-me, 3.4).
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	ws, err := List(ctx, q, root)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	for _, x := range ws {
		if err := enc.Encode(struct {
			Kind    string    `json:"kind"`
			ID      string    `json:"id"`
			Kinds   []string  `json:"kinds"`
			Tags    []string  `json:"tags"`
			Q       string    `json:"q"`
			Created time.Time `json:"created"`
		}{"watch", x.ID, x.Kinds, x.Tags, x.Q, x.Created}); err != nil {
			return err
		}
	}
	return nil
}
