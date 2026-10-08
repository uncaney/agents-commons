// Package announce is the operator announcement and maintenance plane (SPEC-v2 27.7, P115). The
// operator posts a maintenance / incident / change / notice through POST /admin/announce; the row is
// recorded, published as a signed ann1 line on topic g:sys by the system root and on the /f/sys
// feed, listed on GET /status while active or upcoming, and (for maintenance) surfaced on /v1/me and
// /v1/me/resume. A maintenance announce also toggles maintenance mode (flags freeze:write +
// maintenance_until), so writers get 503 err frozen with a Retry-After computed from the deadline.
// GET /status/history renders the last 90 days of ops' status_daily counters. Announcement text is
// operator-authored but still scrubbed, one-lined and capped; it is published and described, never
// executed.
package announce

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/ops"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/swarm"
)

// Op is an MCP operation (compact text, *core.APIError on failure).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5): ann is a public read.
var OpMeta = map[string]core.OpMeta{
	"ann": {Scope: "*", Cost: 1},
}

// Help is the help{t:announce} line of this package.
const Help = `announce (operator status): ann{} active and upcoming maintenance/incident/change/notice lines (also GET /status, /f/sys.atom, signed on topic g:sys). Maintenance freezes writes until the window ends.`

func init() { sign.RegisterTypes(annType) }

const (
	annType     = "ann1"         // signed statement type
	sysTopic    = "g:sys"        // public topic the signed line is published to
	sysFeed     = "sys"          // /f/sys.atom|.json
	maxText     = 300            // announcement text cap (matches the CHECK)
	maxNotices  = 20             // active+upcoming lines shown on /status
	historyDays = 90             // /status/history span
	flagFreeze  = "freeze:write" // write freeze flag set during maintenance mode
	flagUntil   = "maintenance_until"
)

var kinds = map[string]bool{"maintenance": true, "incident": true, "change": true, "notice": true}

type svc struct{ d *core.Deps }

// Register mounts POST /admin/announce (admin), GET /status/history (+ twins) and its feed, wires the
// /status notice seam (ops.StatusExtraFn) and the me/resume maintenance notice (d.MeExtra,
// d.OnResume), and registers the scopes and OpenAPI. It edits no other package's routes.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}

	mux.HandleFunc("POST /admin/announce", d.AdminOnly(s.hAnnounce))
	d.RegisterScope("POST /admin/announce", "admin")
	d.RegisterCost("POST /admin/announce", 1)

	// status_daily history (90 days). ops.Register only mounts this route when it is still free, so
	// announce owns it when it registers first; otherwise the ops handler stands in unchanged.
	if free(mux, "/status/history") {
		mux.HandleFunc("GET /status/history", s.hHistory)
		for _, ext := range []string{".txt", ".md", ".json"} {
			mux.HandleFunc("GET /status/history"+ext, s.hHistory)
		}
		d.RegisterScope("GET /status/history", "*")
		d.RegisterCost("GET /status/history", 1)
	}

	// Active and upcoming announcements appear on GET /status (a process-wide seam read by ops).
	ops.StatusExtraFn = func(ctx context.Context) []string { return s.statusLines(ctx) }
	// Maintenance notice on /v1/me and /v1/me/resume.
	d.MeExtra(func(ctx context.Context, id *core.Ident) []string { return s.maintenanceNotice(ctx) })
	d.OnResume(func(ctx context.Context, root string) []string { return s.maintenanceNotice(ctx) })
	// The /f/sys feed renders the recent announcements.
	d.RegisterFeed(sysFeed, func(ctx context.Context, sub string, n int) ([]core.FeedItem, error) {
		return s.feed(ctx, n)
	})
	d.RegisterOpenAPI(json.RawMessage(openAPI))
}

// Ops returns the MCP operations: ann (public read of active and upcoming announcements).
func Ops(d *core.Deps) map[string]Op {
	s := &svc{d: d}
	return map[string]Op{
		"ann": func(ctx context.Context, _ *core.Ident, _ json.RawMessage) (string, error) {
			lines := s.statusLines(ctx)
			if len(lines) == 0 {
				return "no active or upcoming announcements", nil
			}
			return strings.Join(lines, "\n"), nil
		},
	}
}

// free reports whether no handler is registered for GET path on mux (a catch-all does not count).
func free(mux *http.ServeMux, path string) bool {
	_, pat := mux.Handler(&http.Request{Method: http.MethodGet, URL: &url.URL{Path: path}, Host: "localhost"})
	return pat != "GET "+path && pat != path
}

// Ann is one announcement row.
type Ann struct {
	ID           int64
	Kind, Text   string
	Starts, Ends time.Time
	Created      time.Time
}

// hAnnounce is POST /admin/announce {kind, starts, ends, text} (admin token via core AdminOnly;
// cxa announce <kind> <starts> <ends> <text>). It records the row, publishes the signed ann1 line on
// g:sys and the sys feed, and (for maintenance) recomputes maintenance mode. The whole thing is one
// transaction so a row is never published without being stored.
func (s *svc) hAnnounce(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kind, Starts, Ends, Text string
	}
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	kind := strings.TrimSpace(in.Kind)
	if !kinds[kind] {
		core.Fail(w, r, core.Bad("kind must be maintenance|incident|change|notice"))
		return
	}
	starts, err := parseTime(in.Starts)
	if err != nil {
		core.Fail(w, r, core.Bad("starts: RFC3339 timestamp"))
		return
	}
	ends, err := parseTime(in.Ends)
	if err != nil {
		core.Fail(w, r, core.Bad("ends: RFC3339 timestamp"))
		return
	}
	if !ends.After(starts) {
		core.Fail(w, r, core.Bad("ends must be after starts"))
		return
	}
	text := strings.TrimSpace(scrub.Normalize(in.Text))
	if text == "" {
		core.Fail(w, r, core.Bad("text required"))
		return
	}
	if utf8.RuneCountInString(text) > maxText {
		core.Fail(w, r, core.E(413, "size", "text > "+strconv.Itoa(maxText)))
		return
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"text": &text}); aerr != nil {
		core.Fail(w, r, aerr)
		return
	}
	text = doc.SafeLine(text)

	ctx := r.Context()
	a := &Ann{Kind: kind, Text: text, Starts: starts, Ends: ends}
	var line string
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `INSERT INTO announcements (kind, text, starts, ends)
			VALUES ($1, $2, $3, $4) RETURNING id, created`, kind, text, starts, ends).Scan(&a.ID, &a.Created); e != nil {
			return e
		}
		line = a.Line()
		published := line + " " + sign.Sign(annType, line)
		// Publish on g:sys as the system root (bypasses the namespace gate and daily caps). The
		// idempotency key is the row id so a retried transaction never double-posts.
		if _, e := swarm.Publish(ctx, tx, sysTopic, core.SystemID, core.SystemID, published, "ann:"+strconv.FormatInt(a.ID, 10)); e != nil {
			return e
		}
		if kind == "maintenance" {
			return s.applyMaintenance(ctx, tx, a)
		}
		return nil
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if kind == "maintenance" {
		// Load the committed flags into the in-memory cache (freeze:write + maintenance_until).
		if e := s.d.RefreshFlags(ctx); e != nil {
			core.Fail(w, r, e)
			return
		}
	}
	core.AdminArg(r, "announce "+kind+" "+starts.UTC().Format(time.RFC3339)+".."+ends.UTC().Format(time.RFC3339))
	_, maint := core.MaintenanceUntil()
	core.OK(w, r, "ok ann #"+strconv.FormatInt(a.ID, 10)+" "+kind,
		map[string]any{"id": a.ID, "kind": kind, "starts": starts.UTC().Format(time.RFC3339),
			"ends": ends.UTC().Format(time.RFC3339), "text": text, "statement": line, "maintenance": maint})
}

// applyMaintenance sets or clears maintenance mode from the maintenance announcement just posted
// (27.7: set/cleared by the same admin call with kind maintenance, latest call wins). When that
// window is active now (starts <= now < ends) it sets freeze:write and maintenance_until=<ends>; a
// future- or past-dated window clears both, so an upcoming window is only listed, never freezes
// writes early. The flag write happens in the same transaction and is picked up by RefreshFlags.
func (s *svc) applyMaintenance(ctx context.Context, tx pgx.Tx, a *Ann) error {
	now := time.Now()
	active := !a.Starts.After(now) && a.Ends.After(now)
	if !active {
		if e := s.setFlagTx(ctx, tx, flagFreeze, false, ""); e != nil {
			return e
		}
		return s.setFlagTx(ctx, tx, flagUntil, false, "")
	}
	if e := s.setFlagTx(ctx, tx, flagFreeze, true, ""); e != nil {
		return e
	}
	return s.setFlagTx(ctx, tx, flagUntil, true, a.Ends.UTC().Format(time.RFC3339))
}

// setFlagTx upserts a flag inside the handler transaction and refreshes the in-memory cache after
// the row is written (d.SetFlag would open its own pool connection and miss the uncommitted row).
func (s *svc) setFlagTx(ctx context.Context, tx pgx.Tx, k string, on bool, val string) error {
	if _, e := tx.Exec(ctx, `INSERT INTO flags (k, v, s) VALUES ($1, $2, $3)
		ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, s = EXCLUDED.s, updated = now()`, k, on, val); e != nil {
		return e
	}
	return nil
}

// Line is the signed statement line: ann1 kind=<kind> from=<RFC3339> to=<RFC3339> text=<text> k=<kid>.
// text is last so its single spaces stay unambiguous.
func (a *Ann) Line() string {
	return sign.Canonical(annType,
		sign.KV{K: "kind", V: a.Kind},
		sign.KV{K: "from", V: a.Starts.UTC().Format(time.RFC3339)},
		sign.KV{K: "to", V: a.Ends.UTC().Format(time.RFC3339)},
		sign.KV{K: "text", V: a.Text},
		sign.KV{K: "k", V: strconv.Itoa(sign.KID())})
}

// statusLines renders active and upcoming announcements for GET /status and the ann op, newest
// window first, capped and one-lined by the ops seam.
func (s *svc) statusLines(ctx context.Context) []string {
	rows, err := s.d.DB.Query(ctx, `SELECT kind, text, starts, ends FROM announcements
		WHERE ends > now() ORDER BY starts LIMIT $1`, maxNotices)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	now := time.Now()
	for rows.Next() {
		var a Ann
		if err := rows.Scan(&a.Kind, &a.Text, &a.Starts, &a.Ends); err != nil {
			return out
		}
		out = append(out, a.statusLine(now))
	}
	return out
}

// statusLine is "<kind> <state> <from>..<to> <text>": state is active while the window is open, else
// upcoming.
func (a *Ann) statusLine(now time.Time) string {
	state := "upcoming"
	if !a.Starts.After(now) {
		state = "active"
	}
	line := a.Kind + " " + state + " " + a.Starts.UTC().Format(time.RFC3339) + ".." + a.Ends.UTC().Format(time.RFC3339) + " " + a.Text
	if utf8.RuneCountInString(line) > maxText {
		line = string([]rune(line)[:maxText])
	}
	return doc.SafeLine(line)
}

// maintenanceNotice returns the me/resume line when a maintenance window is active or starts within
// 24 h: "notice: maintenance <from>..<to> read-only".
func (s *svc) maintenanceNotice(ctx context.Context) []string {
	var starts, ends time.Time
	err := s.d.DB.QueryRow(ctx, `SELECT starts, ends FROM announcements
		WHERE kind = 'maintenance' AND ends > now() AND starts < now() + interval '24 hours'
		ORDER BY starts LIMIT 1`).Scan(&starts, &ends)
	if err != nil {
		return nil
	}
	return []string{"notice: maintenance " + starts.UTC().Format(time.RFC3339) + ".." + ends.UTC().Format(time.RFC3339) + " read-only"}
}

// feed renders the most recent announcements as feed items for /f/sys.atom|.json.
func (s *svc) feed(ctx context.Context, n int) ([]core.FeedItem, error) {
	if n <= 0 || n > 100 {
		n = 50
	}
	rows, err := s.d.DB.Query(ctx, `SELECT id, kind, text, starts, ends, created FROM announcements
		ORDER BY created DESC, id DESC LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.FeedItem
	base := doc.Base()
	for rows.Next() {
		var a Ann
		if err := rows.Scan(&a.ID, &a.Kind, &a.Text, &a.Starts, &a.Ends, &a.Created); err != nil {
			return nil, err
		}
		id := "ann-" + strconv.FormatInt(a.ID, 10)
		out = append(out, core.FeedItem{
			ID: id, URL: base + "/status", Title: a.Kind + ": " + a.Text,
			Summary: a.Starts.UTC().Format(time.RFC3339) + ".." + a.Ends.UTC().Format(time.RFC3339),
			Updated: a.Created, Published: a.Created, Author: core.SystemID, Tags: []string{a.Kind},
		})
	}
	return out, rows.Err()
}

// hHistory serves GET /status/history (+ twins): one line per day for 90 days from ops' status_daily
// counters.
func (s *svc) hHistory(w http.ResponseWriter, r *http.Request) {
	stats, err := ops.History(r.Context(), s.d.DB, historyDays)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: "status history days=" + strconv.Itoa(historyDays) + " rows=" + strconv.Itoa(len(stats)),
		Title: "status history", Desc: "Requests, 5xx replies and seconds shed per day, last 90 days.",
		Canonical: "/status/history", MaxAge: 300, Cols: []string{"day", "reqs", "5xx", "shed_s"},
		Next: []doc.Action{doc.GET("/status", "")}}
	for _, st := range stats {
		d.Rows = append(d.Rows, []string{st.Day.UTC().Format("2006-01-02"),
			strconv.FormatInt(st.Reqs, 10), strconv.FormatInt(st.E5xx, 10), strconv.Itoa(st.ShedSeconds)})
	}
	doc.Reply(w, r, 200, d)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, strings.TrimSpace(s))
}

const openAPI = `{"paths":{
"/admin/announce":{"post":{"operationId":"announce","tags":["ops"],"summary":"Post an operator announcement (admin): records it, publishes a signed ann1 line on g:sys and /f/sys, lists it on /status; kind maintenance also freezes writes until ends","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["kind","starts","ends","text"],"properties":{"kind":{"type":"string","enum":["maintenance","incident","change","notice"]},"starts":{"type":"string","format":"date-time"},"ends":{"type":"string","format":"date-time"},"text":{"type":"string","maxLength":300}}}}}},"responses":{"200":{"description":"ok ann #<id> <kind>"},"400":{"description":"err bad | err scrub"},"401":{"description":"err auth"},"413":{"description":"err size"}}}},
"/status/history":{"get":{"operationId":"statusHistory","tags":["ops"],"summary":"One line per day for 90 days: requests, 5xx replies, seconds shed (.txt/.md/.json twins)","responses":{"200":{"description":"text/plain table; ETag, cached 5 min"}}}}
}}`
