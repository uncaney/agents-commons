package ops

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

const (
	statusMaxAge = 300 // Cache-Control max-age of /status (edge-cached 5 min, 21.1)
	historyDays  = 90
	maxNotices   = 20
)

// status serves GET /status (+ twins): coarse state only (no counts), so the page is safe to
// cache at the edge and tells nothing about load beyond the shed level and frozen kinds.
func (o *Ops) status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	lvl, names := o.Level()
	frozen := o.frozen()
	until, maint := core.MaintenanceUntil()
	state := "ok"
	switch {
	case maint:
		state = "maintenance"
	case lvl > 0 || len(frozen) > 0:
		state = "degraded"
	}
	classes := o.d.StorageClasses()
	nf := 0
	for _, c := range classes {
		if c.Frozen {
			nf++
		}
	}
	d := &doc.Doc{Head: "status " + state, Title: "status", Desc: "Coarse service status: shed level, frozen kinds, maintenance window, notices.",
		Canonical: "/status", MaxAge: statusMaxAge}
	d.Fields = append(d.Fields,
		doc.F{Name: "state", Val: state},
		doc.F{Name: "shed", Val: dash(strings.Join(names, ","))},
		doc.F{Name: "level", Val: strconv.Itoa(lvl) + "/" + strconv.Itoa(len(Levels))},
		doc.F{Name: "frozen", Val: dash(strings.Join(frozen, ","))},
		doc.F{Name: "storage", Val: fmt.Sprintf("%d classes, %d frozen", len(classes), nf)})
	if maint {
		d.Fields = append(d.Fields, doc.F{Name: "maintenance_until", Val: until.UTC().Format(time.RFC3339)})
	}
	for _, l := range o.extra(ctx) {
		d.Fields = append(d.Fields, doc.F{Name: "notice", Val: l})
	}
	d.Fields = append(d.Fields, doc.F{Name: "as_of", Val: time.Now().UTC().Truncate(5 * time.Minute).Format("2006-01-02T15:04Z")})
	d.Next = []doc.Action{doc.GET("/status/history", "90 days"), doc.GET("/healthz", "?v=2 adds levels"), doc.GET("/llms.txt", "")}
	doc.Reply(w, r, 200, d)
}

// extra runs StatusExtraFn: at most maxNotices lines, each flattened to one line of <= 300 chars.
func (o *Ops) extra(ctx context.Context) []string {
	if StatusExtraFn == nil {
		return nil
	}
	var out []string
	for _, l := range StatusExtraFn(ctx) {
		l = doc.SafeLine(strings.TrimSpace(l))
		if l == "" {
			continue
		}
		if len(l) > 300 {
			l = l[:300]
		}
		out = append(out, l)
		if len(out) == maxNotices {
			break
		}
	}
	return out
}

// frozen lists the freeze flags that are on (v1 kinds and freeze:<class>), sorted.
func (o *Ops) frozen() []string {
	var out []string
	for _, k := range []string{"reg", "write", "compute", "all"} {
		if o.d.Flag(k) || o.d.Flag("freeze:"+k) {
			out = append(out, k)
		}
	}
	for _, c := range o.d.StorageClasses() {
		if c.Frozen && c.Name != "" {
			out = append(out, c.Name)
		}
	}
	sort.Strings(out)
	return dedupe(out)
}

func dedupe(xs []string) []string {
	out := xs[:0]
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Healthz serves GET /healthz: a DB ping; with ?v=2 (or X-CX-V: 2) the shed levels, frozen kinds
// and maintenance_until (21.1, 27.7). Never cached.
func (o *Ops) Healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	w.Header().Set("Cache-Control", "no-store")
	if err := o.d.DB.Ping(ctx); err != nil {
		core.Err(w, r, 503, "db", "unavailable")
		return
	}
	if !core.V2(r) {
		core.OK(w, r, "ok", map[string]bool{"ok": true})
		return
	}
	lvl, names := o.Level()
	frozen := o.frozen()
	text := fmt.Sprintf("ok shed=%d levels=%s frozen=%s", lvl, dash(strings.Join(names, ",")), dash(strings.Join(frozen, ",")))
	j := map[string]any{"ok": true, "shed": lvl, "levels": names, "frozen": frozen}
	if t, ok := core.MaintenanceUntil(); ok {
		text += " maintenance_until=" + t.UTC().Format(time.RFC3339)
		j["maintenance_until"] = t.UTC().Format(time.RFC3339)
	}
	core.OK(w, r, text, j)
}

// DayStat is one status_daily row.
type DayStat struct {
	Day         time.Time
	Reqs, E5xx  int64
	ShedSeconds int
}

// History returns the last `days` status_daily rows, newest first (P115 renders /status/history
// from these when it owns the route).
func History(ctx context.Context, q core.Q, days int) ([]DayStat, error) {
	if days <= 0 || days > 400 {
		days = historyDays
	}
	rows, err := q.Query(ctx, `SELECT day, reqs, e5xx, shed_s FROM status_daily
		WHERE day > current_date - $1::int ORDER BY day DESC`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DayStat
	for rows.Next() {
		var s DayStat
		if err := rows.Scan(&s.Day, &s.Reqs, &s.E5xx, &s.ShedSeconds); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Line renders "<day> reqs=<n> 5xx=<n> shed_s=<n>".
func (s DayStat) Line() string {
	return fmt.Sprintf("%s reqs=%d 5xx=%d shed_s=%d", s.Day.UTC().Format("2006-01-02"), s.Reqs, s.E5xx, s.ShedSeconds)
}

// HistoryLines renders rows one per line.
func HistoryLines(stats []DayStat) []string {
	out := make([]string, len(stats))
	for i, s := range stats {
		out[i] = s.Line()
	}
	return out
}

// history serves GET /status/history when no other package owns it.
func (o *Ops) history(w http.ResponseWriter, r *http.Request) {
	stats, err := History(r.Context(), o.d.DB, historyDays)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: fmt.Sprintf("status history days=%d rows=%d", historyDays, len(stats)), Title: "status history",
		Desc: "Requests, 5xx replies and seconds shed per day, last 90 days.", Canonical: "/status/history", MaxAge: statusMaxAge,
		Cols: []string{"day", "reqs", "5xx", "shed_s"}, Next: []doc.Action{doc.GET("/status", "")}}
	for _, s := range stats {
		d.Rows = append(d.Rows, []string{s.Day.UTC().Format("2006-01-02"), strconv.FormatInt(s.Reqs, 10), strconv.FormatInt(s.E5xx, 10), strconv.Itoa(s.ShedSeconds)})
	}
	doc.Reply(w, r, 200, d)
}
