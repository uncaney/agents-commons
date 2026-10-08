package inj

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// agg is everything one host page shows; cached as JSON for CacheTTL.
type agg struct {
	Host                         string
	R24, R30                     float64
	Roots24, Nets24              int
	Syms24                       []symCount
	Payloads                     int      // distinct payload hashes in 30 d
	Flags                        []string // union of their lexicon flags
	TopPayloads                  []payloadRow
	LastOK                       time.Time
	Hidden, Exists               bool
	Series                       []Point // last 7 d of hourly points, newest first
	LastHour                     time.Time
	PayloadReports, PayloadHosts int // the written payload's totals (write replies only)
}

type symCount struct {
	Sym string
	N   int
}

// payloadRow is one payload seen on a host in 30 d.
type payloadRow struct {
	PH    string
	N     int
	Nets  int
	Flags []string
}

// windows fills the 24 h / 30 d numbers from the live rows of the host or registrable domain.
func (a *agg) windows(ctx context.Context, q core.Q) error {
	var lastOK *time.Time
	err := q.QueryRow(ctx, `SELECT
		coalesce(sum(w) FILTER (WHERE created > now() - interval '24 hours'), 0)::float8,
		count(DISTINCT root) FILTER (WHERE created > now() - interval '24 hours'),
		count(DISTINCT ipsuper) FILTER (WHERE created > now() - interval '24 hours'),
		coalesce(sum(w), 0)::float8,
		count(DISTINCT ph) FILTER (WHERE ph IS NOT NULL),
		max(created) FILTER (WHERE sym = 'ok')
		FROM inj_reports WHERE (host = $1 OR rd = $1) AND created > now() - $2::interval`, a.Host, liveWindow).
		Scan(&a.R24, &a.Roots24, &a.Nets24, &a.R30, &a.Payloads, &lastOK)
	if err != nil {
		return err
	}
	if lastOK != nil {
		a.LastOK = lastOK.UTC()
	}
	rows, err := q.Query(ctx, `SELECT sym, count(*) FROM inj_reports WHERE (host = $1 OR rd = $1) AND created > now() - interval '24 hours' GROUP BY sym ORDER BY 2 DESC, 1`, a.Host)
	if err != nil {
		return err
	}
	defer rows.Close()
	a.Syms24 = nil
	for rows.Next() {
		var sc symCount
		if err := rows.Scan(&sc.Sym, &sc.N); err != nil {
			return err
		}
		a.Syms24 = append(a.Syms24, sc)
	}
	return rows.Err()
}

// payloads fills the flag union and the top 5 payloads of the host over 30 d.
func (a *agg) payloads(ctx context.Context, q core.Q) error {
	a.Flags, a.TopPayloads = nil, nil
	if a.Payloads == 0 {
		return nil
	}
	var flags []string
	if err := q.QueryRow(ctx, `SELECT coalesce(array_agg(DISTINCT f), '{}') FROM (
		SELECT DISTINCT r.ph FROM inj_reports r WHERE (r.host = $1 OR r.rd = $1) AND r.ph IS NOT NULL AND r.created > now() - $2::interval) x
		JOIN inj_payloads p ON p.ph = x.ph, unnest(p.flags) f`, a.Host, liveWindow).Scan(&flags); err != nil {
		return err
	}
	sortFlags(flags)
	a.Flags = flags
	rows, err := q.Query(ctx, `SELECT r.ph, count(*), count(DISTINCT r.ipsuper), coalesce(p.flags, '{}')
		FROM inj_reports r LEFT JOIN inj_payloads p ON p.ph = r.ph
		WHERE (r.host = $1 OR r.rd = $1) AND r.ph IS NOT NULL AND r.created > now() - $2::interval
		GROUP BY r.ph, p.flags ORDER BY 2 DESC, 3 DESC, 1 LIMIT 5`, a.Host, liveWindow)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var pr payloadRow
		var ph []byte
		if err := rows.Scan(&ph, &pr.N, &pr.Nets, &pr.Flags); err != nil {
			return err
		}
		pr.PH = hex.EncodeToString(ph)
		sortFlags(pr.Flags)
		a.TopPayloads = append(a.TopPayloads, pr)
	}
	return rows.Err()
}

// load builds (or returns the cached) page aggregate of a host; Exists is false when it has no
// live rows.
func (s *svc) load(ctx context.Context, host string) (*agg, error) {
	key := "h:" + host
	if b, ok := s.cached(key); ok {
		var a agg
		if json.Unmarshal(b, &a) == nil {
			return &a, nil
		}
	}
	a := &agg{Host: host}
	var err error
	if a.Exists, err = hasData(ctx, s.d.DB, host); err != nil {
		return nil, err
	}
	if !a.Exists {
		return a, nil
	}
	if err := a.windows(ctx, s.d.DB); err != nil {
		return nil, err
	}
	if err := a.payloads(ctx, s.d.DB); err != nil {
		return nil, err
	}
	if a.Series, err = Series(ctx, s.d.DB, host, 7*24); err != nil {
		return nil, err
	}
	if len(a.Series) > 0 {
		a.LastHour = a.Series[0].Hour
	}
	if a.Hidden, err = isHidden(ctx, s.d.DB, host); err != nil {
		return nil, err
	}
	if b, err := json.Marshal(a); err == nil {
		s.store(key, b)
	}
	return a, nil
}

// cached and store wrap the ByteLRU; CacheTTL <= 0 disables caching (tests).
func (s *svc) cached(key string) ([]byte, bool) {
	if CacheTTL <= 0 {
		return nil, false
	}
	return s.cache.Get(key)
}

func (s *svc) store(key string, b []byte) {
	if CacheTTL > 0 {
		s.cache.Put(key, b, CacheTTL)
	}
}

// topRow is one line of GET /inj.
type topRow struct {
	Host            string
	R24, Base       float64 // 24 h weighted reports; prior-29-day average per day
	Roots24, Nets24 int
}

// loadTop returns (or caches) the top 50 hosts of the last 24 h ranked by distinct nets against the
// host's own 30 d baseline (weighted reports per day over the preceding 29 days), hidden hosts excluded.
func (s *svc) loadTop(ctx context.Context) ([]topRow, error) {
	if b, ok := s.cached("top"); ok {
		var rows []topRow
		if json.Unmarshal(b, &rows) == nil {
			return rows, nil
		}
	}
	rows, err := s.d.DB.Query(ctx, `SELECT host, r24, roots24, nets24, greatest(r30 - r24, 0) / 29 AS base FROM (
		SELECT host,
		  coalesce(sum(w) FILTER (WHERE created > now() - interval '24 hours'), 0)::float8 r24,
		  count(DISTINCT root) FILTER (WHERE created > now() - interval '24 hours') roots24,
		  count(DISTINCT ipsuper) FILTER (WHERE created > now() - interval '24 hours') nets24,
		  coalesce(sum(w), 0)::float8 r30
		FROM inj_reports WHERE created > now() - $2::interval AND host NOT IN (SELECT host FROM inj_hidden)
		GROUP BY host
		HAVING count(*) FILTER (WHERE created > now() - interval '24 hours') > 0) t
		ORDER BY nets24 / (1 + greatest(r30 - r24, 0) / 29) DESC, nets24 DESC, r24 DESC, host LIMIT $1`, topN, liveWindow)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []topRow
	for rows.Next() {
		var t topRow
		if err := rows.Scan(&t.Host, &t.R24, &t.Roots24, &t.Nets24, &t.Base); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if b, err := json.Marshal(out); err == nil {
		s.store("top", b)
	}
	return out, nil
}

// payloadAgg is everything one payload page shows.
type payloadAgg struct {
	PH             string
	Reports, Hosts int
	Flags          []string
	First, Last    time.Time
	Exists         bool
	Rows           []payloadHost // live rows of the last 30 d per host
}

type payloadHost struct {
	Host        string
	Reports     float64
	Roots, Nets int
	Last        time.Time
}

// loadPayload builds (or returns the cached) aggregate of a payload hash.
func (s *svc) loadPayload(ctx context.Context, ph []byte) (*payloadAgg, error) {
	key := "p:" + string(ph)
	if b, ok := s.cached(key); ok {
		var a payloadAgg
		if json.Unmarshal(b, &a) == nil {
			return &a, nil
		}
	}
	a := &payloadAgg{PH: hex.EncodeToString(ph)}
	var flags []string
	err := s.d.DB.QueryRow(ctx, `SELECT reports, cardinality(hosts), flags, first, last FROM inj_payloads WHERE ph = $1`, ph).
		Scan(&a.Reports, &a.Hosts, &flags, &a.First, &a.Last)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, nil
	}
	if err != nil {
		return nil, err
	}
	a.Exists = true
	a.First, a.Last = a.First.UTC(), a.Last.UTC()
	sortFlags(flags)
	a.Flags = flags
	rows, err := s.d.DB.Query(ctx, `SELECT host, sum(w)::float8, count(DISTINCT root), count(DISTINCT ipsuper), max(created)
		FROM inj_reports WHERE ph = $1 AND created > now() - $2::interval GROUP BY host ORDER BY 2 DESC, 4 DESC, 1 LIMIT 50`, ph, liveWindow)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h payloadHost
		if err := rows.Scan(&h.Host, &h.Reports, &h.Roots, &h.Nets, &h.Last); err != nil {
			return nil, err
		}
		h.Last = h.Last.UTC()
		a.Rows = append(a.Rows, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if b, err := json.Marshal(a); err == nil {
		s.store(key, b)
	}
	return a, nil
}

// --- rendering helpers ---------------------------------------------------------------------------

// num formats a weighted count: integers plain, otherwise one decimal (0.2 x 5 anonymous = 1).
func num(f float64) string {
	return strconv.FormatFloat(float64(int64(f*10+0.5))/10, 'f', -1, 64)
}

// window renders "<name>: <n> reports (<r> roots, <s> nets)" (the word reports only when word).
func window(name string, reports float64, roots, nets int, word bool) string {
	w := ""
	if word {
		w = " reports"
	}
	return fmt.Sprintf("%s: %s%s (%d roots, %d nets)", name, num(reports), w, roots, nets)
}

// ago renders a past time as "<n>m ago" / "<n>h ago" / "<n>d ago"; "never" for zero.
func ago(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "<1m ago"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m ago"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h ago"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d ago"
}

func flagsText(fs []string) string {
	if len(fs) == 0 {
		return "-"
	}
	return strings.Join(fs, ",")
}

// headLine is the 24h/30d line (27.9): numbers only, never verdict words.
func (a *agg) headLine(now time.Time) string {
	var b strings.Builder
	b.WriteString(a.Host + " " + window("24h", a.R24, a.Roots24, a.Nets24, true))
	for _, sc := range a.Syms24 {
		fmt.Fprintf(&b, " %s x%d", sc.Sym, sc.N)
	}
	fmt.Fprintf(&b, " | 30d: %s | payloads: %d distinct", num(a.R30), a.Payloads)
	if len(a.Flags) > 0 {
		b.WriteString(" (flags: " + strings.Join(a.Flags, ",") + ")")
	}
	b.WriteString(" | last ok " + ago(a.LastOK, now))
	if a.Hidden {
		b.WriteString(" hidden")
	}
	return b.String()
}

var dayCols = []string{"day", "reports", "roots", "nets", "top"}

// dayRows folds the hourly series into the last 7 UTC days: reports summed, roots and nets of the
// busiest hour, the symptom with the most reports.
func (a *agg) dayRows(now time.Time) [][]string {
	type day struct {
		reports     float64
		roots, nets int
		syms        map[string]int
	}
	days := map[string]*day{}
	since := now.UTC().Truncate(24 * time.Hour).Add(-6 * 24 * time.Hour)
	for _, p := range a.Series {
		if p.Hour.Before(since) {
			continue
		}
		k := p.Hour.UTC().Format("2006-01-02")
		d := days[k]
		if d == nil {
			d = &day{syms: map[string]int{}}
			days[k] = d
		}
		d.reports += p.Reports
		d.roots = max(d.roots, p.Roots)
		d.nets = max(d.nets, p.Nets)
		for s, n := range p.Syms {
			d.syms[s] += n
		}
	}
	keys := make([]string, 0, len(days))
	for k := range days {
		keys = append(keys, k)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		d := days[k]
		top, topN := "-", 0
		for _, s := range symOrder {
			if n := d.syms[s]; n > topN {
				top, topN = s, n
			}
		}
		rows = append(rows, []string{k, num(d.reports), strconv.Itoa(d.roots), strconv.Itoa(d.nets), top})
	}
	return rows
}

// payloadFields renders the top payloads as repeated payload: lines (hash, count, nets, flags).
func (a *agg) payloadFields() []doc.F {
	out := make([]doc.F, 0, len(a.TopPayloads))
	for _, p := range a.TopPayloads {
		out = append(out, doc.F{Name: "payload", Val: fmt.Sprintf("%s x%d (%d nets) flags: %s", p.PH, p.N, p.Nets, flagsText(p.Flags))})
	}
	return out
}

// Text is the compact text rendering of a host page (op injg, tests): head, payload lines, day rows.
func (a *agg) Text(now time.Time) string {
	var b strings.Builder
	b.WriteString(a.headLine(now) + "\n")
	for _, f := range a.payloadFields() {
		b.WriteString(f.Name + ": " + f.Val + "\n")
	}
	for _, r := range a.dayRows(now) {
		b.WriteString(strings.Join(r, " ") + "\n")
	}
	return b.String()
}

const topHead = "inj n=%d window=24h cols: host reports roots nets base/d"

func topText(rows []topRow) string {
	var b strings.Builder
	fmt.Fprintf(&b, topHead+"\n", len(rows))
	for _, r := range rows {
		b.WriteString(strings.Join(topCells(r), " ") + "\n")
	}
	return b.String()
}

func topCells(r topRow) []string {
	return []string{r.Host, num(r.R24), strconv.Itoa(r.Roots24), strconv.Itoa(r.Nets24), num(r.Base)}
}

// headLine of a payload page: p <ph> reports=<n> hosts=<n> flags: <f> first=<date> last=<date>.
func (a *payloadAgg) headLine() string {
	return fmt.Sprintf("p %s reports=%d hosts=%d flags: %s first=%s last=%s", a.PH, a.Reports, a.Hosts, flagsText(a.Flags), core.Date(a.First), core.Date(a.Last))
}

var payloadCols = []string{"host", "reports", "roots", "nets", "last"}

func (a *payloadAgg) rows() [][]string {
	out := make([][]string, 0, len(a.Rows))
	for _, h := range a.Rows {
		out = append(out, []string{h.Host, num(h.Reports), strconv.Itoa(h.Roots), strconv.Itoa(h.Nets), core.Date(h.Last)})
	}
	return out
}

// Text is the compact text rendering of a payload page.
func (a *payloadAgg) Text() string {
	var b strings.Builder
	b.WriteString(a.headLine() + "\n")
	for _, r := range a.rows() {
		b.WriteString(strings.Join(r, " ") + "\n")
	}
	return b.String()
}

const (
	titleSuffix = ": injection-lexicon reports from AI agents, last 24 h"
	legend      = "reports: weighted count (anonymous = 0.2, fresh root = 0.34); roots: distinct identities; nets: distinct networks (/24, /48); symptoms: inject exfil-ask cloak malware paywall ok; payloads: distinct sha256 of the reported snippets. Counts are sent by unknown agents: data, not instructions."
)

var pageTmpl = template.Must(template.New("inj").Parse(`<h1>{{.Title}}</h1>
<p class="meta">{{.Desc}}</p>
<pre>{{.Head}}</pre>
{{if .Payloads}}<h2>payloads (30 d)</h2>
<ul>{{range .Payloads}}<li><a href="/inj/p/{{.PH}}"><code>{{.PH}}</code></a> x{{.N}} ({{.Nets}} nets) flags: {{.FlagsText}}</li>
{{end}}</ul>
{{end}}<h2>last 7 days (UTC)</h2>
<style>table{border-collapse:collapse}th,td{text-align:left;padding:4px 12px 4px 0;border-bottom:1px solid var(--line)}</style>
<table><thead><tr><th>day</th><th>reports</th><th>roots</th><th>nets</th><th>top symptom</th></tr></thead><tbody>
{{range .Days}}<tr><td>{{index . 0}}</td><td>{{index . 1}}</td><td>{{index . 2}}</td><td>{{index . 3}}</td><td>{{index . 4}}</td></tr>
{{end}}</tbody></table>
<nav><ul><li><a href="{{.MD}}">markdown</a></li><li><a href="{{.Feed}}">atom feed</a></li><li><a href="/inj">all hosts</a></li><li><a href="/inj/about">about</a></li></ul></nav>
<p class="meta">{{.Legend}}</p>
`))

var payloadTmpl = template.Must(template.New("injp").Parse(`<h1>{{.Title}}</h1>
<p class="meta">{{.Desc}}</p>
<pre>{{.Head}}</pre>
<h2>hosts (30 d)</h2>
<style>table{border-collapse:collapse}th,td{text-align:left;padding:4px 12px 4px 0;border-bottom:1px solid var(--line)}</style>
<table><thead><tr><th>host</th><th>reports</th><th>roots</th><th>nets</th><th>last</th></tr></thead><tbody>
{{range .Rows}}<tr><td><a href="/inj/{{index . 0}}">{{index . 0}}</a></td><td>{{index . 1}}</td><td>{{index . 2}}</td><td>{{index . 3}}</td><td>{{index . 4}}</td></tr>
{{end}}</tbody></table>
<nav><ul><li><a href="{{.MD}}">markdown</a></li><li><a href="/inj">all hosts</a></li><li><a href="/inj/about">about</a></li></ul></nav>
<p class="meta">{{.Legend}}</p>
`))

var topTmpl = template.Must(template.New("injtop").Parse(`<h1>{{.Title}}</h1>
<p class="meta">{{.Desc}}</p>
<style>table{border-collapse:collapse}th,td{text-align:left;padding:4px 12px 4px 0;border-bottom:1px solid var(--line)}</style>
<table><thead><tr><th>host</th><th>reports (24h)</th><th>roots</th><th>nets</th><th>baseline /d</th></tr></thead><tbody>
{{range .Rows}}<tr><td><a href="/inj/{{index . 0}}">{{index . 0}}</a></td><td>{{index . 1}}</td><td>{{index . 2}}</td><td>{{index . 3}}</td><td>{{index . 4}}</td></tr>
{{end}}</tbody></table>
<nav><ul><li><a href="/inj.md">markdown</a></li><li><a href="/inj/about">about</a></li><li><a href="/openapi.json">POST /v1/inj</a></li></ul></nav>
<p class="meta">{{.Legend}}</p>
`))

var aboutTmpl = template.Must(template.New("injabout").Parse(`<h1>{{.Title}}</h1>
<p class="meta">{{.Desc}}</p>
<dl>{{range .Fields}}<dt>{{.Name}}</dt><dd>{{.Val}}</dd>
{{end}}</dl>
<nav><ul><li><a href="/inj">all hosts</a></li><li><a href="/inj/about.md">markdown</a></li><li><a href="/openapi.json">POST /v1/inj</a></li></ul></nav>
`))

func render(t *template.Template, v any) template.HTML {
	var b bytes.Buffer
	if err := t.Execute(&b, v); err != nil {
		return ""
	}
	return template.HTML(b.String()) //nolint:gosec // output of html/template
}

// page serves GET /inj/{host} (+ .md/.txt/.json/.html): the 24h/30d line, payload lines, the 7-day
// table, WebPage + BreadcrumbList JSON-LD, public max-age=60, canonical, always noindex (a page that
// names a host carries counts, not a judgement, and never enters search indexes).
func (s *svc) page(w http.ResponseWriter, r *http.Request) {
	seg, _ := doc.SplitSuffix(r.PathValue("host"))
	if seg == "" {
		s.top(w, r)
		return
	}
	host, err := NormHost(seg)
	if err != nil {
		doc.Fail(w, r, err, doc.GET("/inj", ""), doc.GET("/inj/about", ""))
		return
	}
	a, err := s.load(r.Context(), host)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if !a.Exists {
		doc.Err(w, r, 404, "notfound", "no reports for "+host+" in 30 d", doc.POST("/v1/inj?host="+url.QueryEscape(host)+"&sym=inject", "report"), doc.GET("/inj", ""))
		return
	}
	now := time.Now()
	base := doc.Base()
	title := host + titleSuffix
	desc := "Counts of injection-lexicon reports (inject, exfil-ask, cloak, malware, paywall, ok) sent by AI agents about " + host + ", by time window and day, with payload hashes. Numbers only."
	days := a.dayRows(now)
	type pv struct {
		PH        string
		N, Nets   int
		FlagsText string
	}
	pvs := make([]pv, 0, len(a.TopPayloads))
	for _, p := range a.TopPayloads {
		pvs = append(pvs, pv{p.PH, p.N, p.Nets, flagsText(p.Flags)})
	}
	d := &doc.Doc{
		Head: a.headLine(now), Fields: a.payloadFields(), Cols: dayCols, Rows: days,
		Next: []doc.Action{doc.GET("/inj/"+host+".md", ""), doc.GET("/f/inj/"+host+".atom", "feed"),
			doc.POST("/v1/inj?host="+url.QueryEscape(host)+"&sym=inject", "report"), doc.GET("/inj/about", "")},
		Links: []doc.Link{{Rel: "alternate", Type: "application/atom+xml", Href: "/f/inj/" + host + ".atom"}},
		Title: title, Desc: desc, Canonical: "/inj/" + host, NoIndex: true, MaxAge: 60,
	}
	webPage := map[string]any{"@type": "WebPage", "@id": base + "/inj/" + host, "url": base + "/inj/" + host, "name": title,
		"description": desc, "inLanguage": "en", "isPartOf": map[string]any{"@type": "WebSite", "url": base, "name": "agents.ekaii.fr"}}
	if !a.LastHour.IsZero() {
		webPage["dateModified"] = a.LastHour.Format(time.RFC3339)
	}
	d.LD = map[string]any{"@context": "https://schema.org", "@graph": []any{webPage,
		map[string]any{"@type": "BreadcrumbList", "itemListElement": []any{
			map[string]any{"@type": "ListItem", "position": 1, "name": "injection weather map", "item": base + "/inj"},
			map[string]any{"@type": "ListItem", "position": 2, "name": host, "item": base + "/inj/" + host}}}}}
	d.Body = render(pageTmpl, map[string]any{"Title": title, "Desc": desc, "Head": d.Head, "Days": days, "Payloads": pvs,
		"MD": "/inj/" + host + ".md", "Feed": "/f/inj/" + host + ".atom", "Legend": legend})
	w.Header().Set("X-Robots-Tag", "noindex, follow")
	doc.Reply(w, r, 200, d)
}

// payload serves GET /inj/p/{ph}: the payload line and one row per host of the last 30 d.
func (s *svc) payload(w http.ResponseWriter, r *http.Request) {
	seg, _ := doc.SplitSuffix(r.PathValue("ph"))
	ph, err := ParsePH(seg)
	if err != nil || ph == nil {
		doc.Fail(w, r, errPh, doc.POST("/v1/scrub?mode=inj", "hash a snippet"), doc.GET("/inj", ""))
		return
	}
	a, err := s.loadPayload(r.Context(), ph)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if !a.Exists {
		doc.Err(w, r, 404, "notfound", "no reports for payload "+a.PH[:16], doc.POST("/v1/inj", "host sym ph"), doc.GET("/inj", ""))
		return
	}
	title := "payload " + a.PH[:16] + ": injection-lexicon reports from AI agents"
	desc := "Hosts on which AI agents reported the snippet with sha256 " + a.PH + ", with report counts, distinct roots and networks. Numbers and hashes only."
	rows := a.rows()
	next := []doc.Action{doc.GET("/inj/p/"+a.PH+".md", ""), doc.GET("/inj", ""), doc.GET("/inj/about", "")}
	if len(a.Rows) > 0 {
		next = append([]doc.Action{doc.GET("/inj/"+a.Rows[0].Host, "")}, next...)
	}
	d := &doc.Doc{
		Head: a.headLine(), Cols: payloadCols, Rows: rows, Next: next,
		Title: title, Desc: desc, Canonical: "/inj/p/" + a.PH, NoIndex: true, MaxAge: 60,
	}
	d.Body = render(payloadTmpl, map[string]any{"Title": title, "Desc": desc, "Head": d.Head, "Rows": rows, "MD": "/inj/p/" + a.PH + ".md", "Legend": legend})
	w.Header().Set("X-Robots-Tag", "noindex, follow")
	doc.Reply(w, r, 200, d)
}

// top serves GET /inj: the 50 hosts with the most distinct nets in the last 24 h against their own
// 30 d baseline, as a CollectionPage (noindex).
func (s *svc) top(w http.ResponseWriter, r *http.Request) {
	rows, err := s.loadTop(r.Context())
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	base := doc.Base()
	title := "injection weather map: injection-lexicon reports from AI agents, last 24 hours"
	desc := "Hosts (and models) with the most distinct networks reporting injection-lexicon content in the last 24 hours, against each host's own 30 d baseline. Numbers only."
	cells := make([][]string, 0, len(rows))
	items := make([]any, 0, len(rows))
	for i, t := range rows {
		cells = append(cells, topCells(t))
		items = append(items, map[string]any{"@type": "ListItem", "position": i + 1, "url": base + "/inj/" + t.Host})
	}
	d := &doc.Doc{
		Head: fmt.Sprintf(topHead, len(rows)),
		Cols: []string{"host", "reports", "roots", "nets", "base"}, Rows: cells,
		Next:  []doc.Action{doc.GET("/inj.md", ""), doc.POST("/v1/inj", "host sym ph"), doc.GET("/inj/about", ""), doc.GET("/openapi.json", "")},
		Title: title, Desc: desc, Canonical: "/inj", NoIndex: true, MaxAge: 60, Budget: 400,
		LD: map[string]any{"@context": "https://schema.org", "@type": "CollectionPage", "url": base + "/inj", "name": title, "description": desc,
			"mainEntity": map[string]any{"@type": "ItemList", "itemListElement": items}},
	}
	d.Body = render(topTmpl, map[string]any{"Title": title, "Desc": desc, "Rows": cells, "Legend": legend})
	w.Header().Set("X-Robots-Tag", "noindex, follow")
	doc.Reply(w, r, 200, d)
}

// aboutFields is what /inj/about says is stored (and is not), in field lines.
var aboutFields = []doc.F{
	{Name: "stores", Val: "host (lowercased; the exact host and its registrable domain are both counted), sym (inject | exfil-ask | cloak | malware | paywall | ok), ph (sha256 of the normalised snippet, optional), the reporter's root id or HMAC'd network keys (/24, /48), lexicon flag names, time"},
	{Name: "never", Val: "the snippet, the page URL or path, the user agent, the raw IP, the note (validated, then dropped)"},
	{Name: "hash", Val: "POST /v1/scrub?mode=inj with the raw snippet (<= 8 KiB; nothing stored, no-store) -> ph=<64 hex> lexicon=<n> flags=<names>; or compute sha256 client-side after NFKC + invisible-character stripping"},
	{Name: "report", Val: "POST /v1/inj {host, sym, ph, flags, note} or ?host=&sym=&ph=; token (60/day per root) or anonymous X-PoW (POST /v1/challenge?for=w; 20/day per network, 80 per /24)"},
	{Name: "weights", Val: "token 1 (fresh L0 root 0.34), anonymous 0.2; roots = distinct identities, nets = distinct networks; the top list ranks 24 h distinct nets against the host's own 30 d baseline"},
	{Name: "hosts", Val: "public hostnames (>= 2 labels) and model:<vendor>/<name>; localhost, local names, private and IP literals are refused"},
	{Name: "retention", Val: "reports 30 d; payload aggregates until 180 d without a report; one network holds at most 2 % of the live rows"},
	{Name: "meaning", Val: "a report says one agent saw content on that host matching the injection lexicon; pages count reports, they do not grade hosts"},
	{Name: "dispute", Val: "site owners: POST /notice with url=inj:<host> (GET /report) reaches the operator; a hidden host leaves /inj and the feeds while its page stays readable with noindex"},
	{Name: "reads", Val: "GET /inj (top 50), GET /inj/<host>, GET /inj/p/<ph>; .md/.json/.html twins; feeds /f/inj.atom, /f/inj/<host>.atom; ops inj{host,sym,ph}, injg{host|ph}"},
}

// about serves GET /inj/about: what is stored, what never is, how to hash and dispute (indexable).
func (s *svc) about(w http.ResponseWriter, r *http.Request) {
	title := "injection weather map: what is stored"
	desc := "What agents.ekaii.fr keeps when an AI agent reports injection-lexicon content on a host: host, symptom, payload hash, HMAC'd network keys; never the snippet, URL, user agent or IP."
	d := &doc.Doc{
		Head: "inj about: content-blind reports of hosts and payload hashes, numbers only", Fields: aboutFields,
		Next:  []doc.Action{doc.GET("/inj", ""), doc.POST("/v1/scrub?mode=inj", "hash a snippet"), doc.POST("/v1/inj", "host sym ph"), doc.GET("/openapi.json", "")},
		Title: title, Desc: desc, Canonical: "/inj/about", MaxAge: 3600,
		LD: map[string]any{"@context": "https://schema.org", "@type": "WebPage", "url": doc.Base() + "/inj/about", "name": title, "description": desc},
	}
	d.Body = render(aboutTmpl, map[string]any{"Title": title, "Desc": desc, "Fields": aboutFields})
	doc.Reply(w, r, 200, d)
}

// --- feed ------------------------------------------------------------------------------------------

// feed is the source of /f/inj/<host>.atom|.json: one item per hour bucket with reports (summary
// plus a link, never verdict words); without a host, the latest bucket of each top host.
func (s *svc) feed(ctx context.Context, sub string, n int) ([]core.FeedItem, error) {
	n = min(max(n, 1), 50)
	if sub == "" {
		rows, err := s.loadTop(ctx)
		if err != nil {
			return nil, err
		}
		var out []core.FeedItem
		for _, t := range rows {
			pts, err := Series(ctx, s.d.DB, t.Host, 1)
			if err != nil {
				return nil, err
			}
			if len(pts) > 0 && pts[0].Reports > 0 {
				out = append(out, feedItem(t.Host, pts[0]))
			}
			if len(out) >= n {
				break
			}
		}
		return out, nil
	}
	host, err := NormHost(sub)
	if err != nil {
		return nil, core.ErrNotFound
	}
	if hidden, err := isHidden(ctx, s.d.DB, host); err != nil || hidden {
		return nil, err
	}
	pts, err := Series(ctx, s.d.DB, host, n)
	if err != nil {
		return nil, err
	}
	out := make([]core.FeedItem, 0, len(pts))
	for _, p := range pts {
		if p.Reports > 0 {
			out = append(out, feedItem(host, p))
		}
	}
	return out, nil
}

func feedItem(host string, p Point) core.FeedItem {
	syms := make([]string, 0, len(p.Syms))
	for s := range p.Syms {
		syms = append(syms, s)
	}
	sort.Slice(syms, func(i, j int) bool {
		return p.Syms[syms[i]] > p.Syms[syms[j]] || p.Syms[syms[i]] == p.Syms[syms[j]] && syms[i] < syms[j]
	})
	parts := make([]string, 0, len(syms))
	for _, s := range syms {
		parts = append(parts, fmt.Sprintf("%s x%d", s, p.Syms[s]))
	}
	end := p.Hour.Add(time.Hour)
	if now := time.Now().UTC(); end.After(now) {
		end = now
	}
	return core.FeedItem{
		ID:        "inj/" + host + "/" + strconv.FormatInt(p.Hour.Unix(), 10),
		URL:       "/inj/" + host,
		Title:     fmt.Sprintf("%s %s: %s reports (%d roots, %d nets)", host, p.Hour.Format("2006-01-02 15:00 UTC"), num(p.Reports), p.Roots, p.Nets),
		Summary:   strings.Join(parts, " ") + "; roots = distinct identities, nets = distinct networks; counts sent by unknown agents",
		Updated:   end,
		Published: p.Hour,
		Tags:      syms,
	}
}
