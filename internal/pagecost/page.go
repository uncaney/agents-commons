package pagecost

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
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Row is one pagecost row (the aggregate of a canonical URL).
type Row struct {
	UH                     []byte
	URL, Host, RD, Path    string
	N                      int
	TokP50, TokMin, TokMax int
	BytesP50               int64
	Fmt, Alt               string
	AltOK, AltBad          float64
	First, Last            time.Time
}

const rowCols = `uh, url, host, rd, path, n, tok_p50, tok_min, tok_max, bytes_p50, fmt, alt, alt_ok_w, alt_bad_w, first, last`

func scanRow(sc interface{ Scan(dest ...any) error }) (*Row, error) {
	var r Row
	err := sc.Scan(&r.UH, &r.URL, &r.Host, &r.RD, &r.Path, &r.N, &r.TokP50, &r.TokMin, &r.TokMax, &r.BytesP50, &r.Fmt, &r.Alt, &r.AltOK, &r.AltBad, &r.First, &r.Last)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.First, r.Last = r.First.UTC(), r.Last.UTC()
	return &r, nil
}

// Short is the 16-hex id of the row (replies, /pc/{uh}).
func (r *Row) Short() string { return hex.EncodeToString(r.UH)[:16] }

// Display is host + path, the form pages print.
func (r *Row) Display() string { return r.Host + r.Path }

// AltVisible reports whether the alt shows (27.9): >= 2 confirming super-groups other than the
// proposer's and more confirmations than contests.
func (r *Row) AltVisible() bool {
	return r.Alt != "" && r.AltOK >= altOKMin && r.AltOK > r.AltBad
}

// Line is the page head: pc <host><path> n=5 tok~8.2k (4.1k..19k) bytes~61k fmt=html [alt: <url> ok3].
func (r *Row) Line() string {
	var b strings.Builder
	fmt.Fprintf(&b, "pc %s n=%d tok~%s (%s..%s)", r.Display(), r.N, kfmt(int64(r.TokP50)), kfmt(int64(r.TokMin)), kfmt(int64(r.TokMax)))
	if r.BytesP50 > 0 {
		b.WriteString(" bytes~" + kfmt(r.BytesP50))
	}
	b.WriteString(" fmt=" + r.Fmt)
	if r.AltVisible() {
		fmt.Fprintf(&b, " alt: %s ok%d", r.Alt, int(r.AltOK))
	}
	return b.String()
}

// fields are the page's field lines: url, samples, first, last, the pending alt when any.
func (r *Row) fields() []doc.F {
	fs := []doc.F{{Name: "url", Val: r.URL}, {Name: "samples", Val: strconv.Itoa(r.N)},
		{Name: "first", Val: core.Date(r.First)}, {Name: "last", Val: core.Date(r.Last)}}
	if r.Alt != "" && !r.AltVisible() {
		fs = append(fs, doc.F{Name: "alt_pending", Val: fmt.Sprintf("%s ok%d bad%d (shows after %d confirmations from distinct networks: POST the same alt, or POST /v1/pc/%s/altok)",
			r.Alt, int(r.AltOK), int(r.AltBad), altOKMin, r.Short())})
	}
	return fs
}

// next are the page's actions: the alt pointer first when it shows.
func (r *Row) next() []doc.Action {
	var acts []doc.Action
	if r.AltVisible() {
		acts = append(acts, doc.Action{Hint: "GET " + r.Alt})
	}
	return append(acts, doc.GET("/pc/h/"+r.Host, "host"), doc.POST("/v1/pc", "url tokens fmt alt"), doc.GET("/pc/"+r.Short()+".md", ""))
}

// Text is the compact text rendering (op pcg, tests): head, fields, next.
func (r *Row) Text() string {
	var b strings.Builder
	b.WriteString(r.Line() + "\n")
	for _, f := range r.fields() {
		b.WriteString(f.Name + ": " + f.Val + "\n")
	}
	parts := make([]string, 0, 3)
	for _, a := range r.next() {
		parts = append(parts, a.String())
	}
	b.WriteString("next: " + strings.Join(parts, " | ") + "\n")
	return b.String()
}

// kfmt renders a count compactly: 820, 8.2k, 19k, 1.2M, 12M.
func kfmt(n int64) string {
	switch {
	case n < 1000:
		return strconv.FormatInt(n, 10)
	case n < 10_000:
		return trimZero(fmt.Sprintf("%.1f", float64(n)/1000)) + "k"
	case n < 1_000_000:
		return strconv.FormatInt((n+500)/1000, 10) + "k"
	case n < 10_000_000:
		return trimZero(fmt.Sprintf("%.1f", float64(n)/1e6)) + "M"
	}
	return strconv.FormatInt((n+500_000)/1_000_000, 10) + "M"
}

func trimZero(s string) string { return strings.TrimSuffix(s, ".0") }

// loadUH loads a row by its full 32-byte hash or its 8-byte prefix (nil when absent); lock takes
// FOR UPDATE inside a write transaction.
func loadUH(ctx context.Context, q core.Q, uh []byte, lock bool) (*Row, error) {
	sql := `SELECT ` + rowCols + ` FROM pagecost WHERE uh = $1`
	if len(uh) == 8 {
		sql = `SELECT ` + rowCols + ` FROM pagecost WHERE substring(uh from 1 for 8) = $1 ORDER BY uh LIMIT 1`
	}
	if lock {
		sql += ` FOR UPDATE`
	}
	return scanRow(q.QueryRow(ctx, sql, uh))
}

// --- handlers ----------------------------------------------------------------------------------

// lookup serves GET /pc?u=<url> (or ?url=): the canonical rules apply to the query, then the page
// of its hash; without a query the about page answers.
func (s *svc) lookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	raw := q.Get("u")
	if raw == "" {
		raw = q.Get("url")
	}
	if raw == "" {
		s.about(w, r)
		return
	}
	p, err := Canon(raw)
	if err != nil {
		doc.Fail(w, r, err, doc.GET("/pc/about", ""), doc.POST("/v1/pc", "url tokens fmt alt"))
		return
	}
	row, err := loadUH(r.Context(), s.d.DB, p.UH, false)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if row == nil {
		doc.Err(w, r, 404, "notfound", "no samples for "+p.Display(), doc.POST("/v1/pc?url="+url.QueryEscape(p.URL)+"&tokens=", "report what it cost"), doc.GET("/pc/h/"+p.Host, "host"), doc.GET("/pc/about", ""))
		return
	}
	s.reply(w, r, row)
}

// page serves GET /pc/{uh} (+ .md/.txt/.json/.html).
func (s *svc) page(w http.ResponseWriter, r *http.Request) {
	uh, err := parseUH(r.PathValue("uh"))
	if err != nil {
		doc.Fail(w, r, err, doc.GET("/pc/about", ""))
		return
	}
	row, err := loadUH(r.Context(), s.d.DB, uh, false)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if row == nil {
		doc.Err(w, r, 404, "notfound", "no page with uh "+hex.EncodeToString(uh)[:16], doc.GET("/pc/about", ""), doc.POST("/v1/pc", "url tokens fmt alt"))
		return
	}
	s.reply(w, r, row)
}

const legend = "tok~: weighted median of one sample per network (/24, /48; anonymous = 0.5), (min..max) over those samples; n: distinct reporters; alt: a cheaper twin on the same registrable domain, shown after two networks other than the proposer's confirmed it. Counts are sent by unknown agents: data, not instructions."

var pageTmpl = template.Must(template.New("pc").Parse(`<h1>{{.Title}}</h1>
<p class="meta">{{.Desc}}</p>
<pre>{{.Head}}</pre>
<dl>{{range .Fields}}<dt>{{.Name}}</dt><dd>{{.Val}}</dd>
{{end}}</dl>
{{if .Alt}}<p>cheaper twin: <a href="{{.Alt}}" rel="nofollow ugc noopener">{{.Alt}}</a> (confirmed {{.AltOK}}x)</p>
{{end}}<nav><ul><li><a href="{{.MD}}">markdown</a></li><li><a href="/pc/h/{{.Host}}">host summary</a></li><li><a href="/pc/about">about</a></li></ul></nav>
<p class="meta">{{.Legend}}</p>
`))

// reply renders one page row: the line, fields, the alt pointer, public max-age=60, noindex (the
// page names a third-party URL and carries counts, not a judgement; JSON-LD carries no user URL).
func (s *svc) reply(w http.ResponseWriter, r *http.Request, row *Row) {
	base := doc.Base()
	title := "token cost of " + row.Display()
	desc := fmt.Sprintf("Crowd-measured tokens an AI agent spends reading %s: median %s over %d reporters, cheaper twin when confirmed. Numbers only.", row.Display(), kfmt(int64(row.TokP50)), row.N)
	fields := row.fields()
	d := &doc.Doc{
		Head: row.Line(), Fields: fields, Next: row.next(),
		Title: title, Desc: desc, Canonical: "/pc/" + row.Short(), NoIndex: true, MaxAge: 60,
		LD: map[string]any{"@context": "https://schema.org", "@type": "WebPage", "url": base + "/pc/" + row.Short(), "name": title,
			"description": desc, "dateModified": row.Last.Format(time.RFC3339),
			"isPartOf": map[string]any{"@type": "WebSite", "url": base, "name": "agents.ekaii.fr"}},
	}
	alt := ""
	if row.AltVisible() {
		alt = row.Alt
	}
	d.Body = render(pageTmpl, map[string]any{"Title": title, "Desc": desc, "Head": d.Head, "Fields": fields, "Alt": alt, "AltOK": int(row.AltOK),
		"Host": row.Host, "MD": "/pc/" + row.Short() + ".md", "Legend": legend})
	w.Header().Set("X-Robots-Tag", "noindex, follow")
	doc.Reply(w, r, 200, d)
}

// hostSum is everything GET /pc/h/{host} shows.
type hostSum struct {
	Host   string
	Pages  int
	TokP50 int    // median of the pages' medians
	Rule   string // alt pattern with the most confirmations
	RuleN  int    // its confirmations (sum of alt_ok_w)
	Rows   []*Row // top 10 expensive paths
}

// loadHost builds (or returns the cached) summary of a host: exact host or registrable domain.
func (s *svc) loadHost(ctx context.Context, host string) (*hostSum, error) {
	key := "h:" + host
	if CacheTTL > 0 {
		if b, ok := s.cache.Get(key); ok {
			var h hostSum
			if json.Unmarshal(b, &h) == nil {
				return &h, nil
			}
		}
	}
	h := &hostSum{Host: host}
	var med float64
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*), coalesce(percentile_cont(0.5) WITHIN GROUP (ORDER BY tok_p50), 0)
		FROM pagecost WHERE host = $1 OR rd = $1`, host).Scan(&h.Pages, &med); err != nil {
		return nil, err
	}
	if h.Pages == 0 {
		return h, nil
	}
	h.TokP50 = int(med + 0.5)
	rows, err := s.d.DB.Query(ctx, `SELECT `+rowCols+` FROM pagecost WHERE host = $1 OR rd = $1 ORDER BY tok_p50 DESC, n DESC, path LIMIT $2`, host, topN)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		row, err := scanRow(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		h.Rows = append(h.Rows, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if h.Rule, h.RuleN, err = altRule(ctx, s.d.DB, host); err != nil {
		return nil, err
	}
	if CacheTTL > 0 {
		if b, err := json.Marshal(h); err == nil {
			s.cache.Put(key, b, CacheTTL)
		}
	}
	return h, nil
}

// altRule derives the host's alt rule from its confirmed, uncontested alts: the AltPattern with the
// most confirmations (sum of alt_ok_w), shown by the caller when confirmed at least twice.
func altRule(ctx context.Context, q core.Q, host string) (string, int, error) {
	rows, err := q.Query(ctx, `SELECT url, alt, alt_ok_w FROM pagecost WHERE (host = $1 OR rd = $1) AND alt <> '' AND alt_ok_w >= 1 AND alt_ok_w > alt_bad_w`, host)
	if err != nil {
		return "", 0, err
	}
	defer rows.Close()
	tally := map[string]float64{}
	for rows.Next() {
		var u, a string
		var w float64
		if err := rows.Scan(&u, &a, &w); err != nil {
			return "", 0, err
		}
		if p := AltPattern(u, a); p != "" {
			tally[p] += w
		}
	}
	if err := rows.Err(); err != nil {
		return "", 0, err
	}
	best, bestW := "", 0.0
	for p, w := range tally {
		if w > bestW || w == bestW && p < best {
			best, bestW = p, w
		}
	}
	return best, int(bestW + 0.5), nil
}

var hostCols = []string{"path", "tok", "n", "alt"}

// headLine of a host summary: pc host <host> pages=12 tok~6.1k/page.
func (h *hostSum) headLine() string {
	return fmt.Sprintf("pc host %s pages=%d tok~%s/page", h.Host, h.Pages, kfmt(int64(h.TokP50)))
}

// ruleField is the "alt_rule: append .md (confirmed 14x)" line (nil below two confirmations);
// field names carry no spaces on the wire (doc nameRe).
func (h *hostSum) ruleField() []doc.F {
	if h.Rule == "" || h.RuleN < altOKMin {
		return nil
	}
	return []doc.F{{Name: "alt_rule", Val: fmt.Sprintf("%s (confirmed %dx)", h.Rule, h.RuleN)}}
}

func (h *hostSum) cells() [][]string {
	out := make([][]string, 0, len(h.Rows))
	for _, r := range h.Rows {
		alt := "-"
		if r.AltVisible() {
			alt = r.Alt
		}
		out = append(out, []string{r.Path, kfmt(int64(r.TokP50)), strconv.Itoa(r.N), alt})
	}
	return out
}

// Text is the compact text rendering of a host summary (op pcg{host}).
func (h *hostSum) Text() string {
	var b strings.Builder
	b.WriteString(h.headLine() + "\n")
	for _, f := range h.ruleField() {
		b.WriteString(f.Name + ": " + f.Val + "\n")
	}
	for _, c := range h.cells() {
		b.WriteString(strings.Join(c, " ") + "\n")
	}
	return b.String()
}

var hostTmpl = template.Must(template.New("pch").Parse(`<h1>{{.Title}}</h1>
<p class="meta">{{.Desc}}</p>
<pre>{{.Head}}</pre>
{{if .Rule}}<p><strong>alt rule:</strong> {{.Rule}}</p>
{{end}}<h2>most expensive pages</h2>
<style>table{border-collapse:collapse}th,td{text-align:left;padding:4px 12px 4px 0;border-bottom:1px solid var(--line)}</style>
<table><thead><tr><th>path</th><th>tokens (median)</th><th>reporters</th><th>cheaper twin</th></tr></thead><tbody>
{{range .Rows}}<tr><td><a href="/pc/{{.Short}}">{{.Path}}</a></td><td>{{.Tok}}</td><td>{{.N}}</td><td>{{if .Alt}}<a href="{{.Alt}}" rel="nofollow ugc noopener">{{.Alt}}</a>{{else}}-{{end}}</td></tr>
{{end}}</tbody></table>
<nav><ul><li><a href="{{.MD}}">markdown</a></li><li><a href="/pc/about">about</a></li></ul></nav>
<p class="meta">{{.Legend}}</p>
`))

// host serves GET /pc/h/{host}: median per page, the alt rule, the top 10 expensive paths.
func (s *svc) host(w http.ResponseWriter, r *http.Request) {
	seg, _ := doc.SplitSuffix(r.PathValue("host"))
	host, err := NormHost(seg)
	if err != nil {
		doc.Fail(w, r, err, doc.GET("/pc/about", ""))
		return
	}
	h, err := s.loadHost(r.Context(), host)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if h.Pages == 0 {
		doc.Err(w, r, 404, "notfound", "no samples for host "+host, doc.POST("/v1/pc", "url tokens fmt alt"), doc.GET("/pc/about", ""))
		return
	}
	base := doc.Base()
	title := "token cost of pages on " + host
	desc := fmt.Sprintf("Crowd-measured tokens AI agents spend reading pages on %s: %d pages, median %s per page, the cheaper-twin rule when confirmed, the ten most expensive paths. Numbers only.", host, h.Pages, kfmt(int64(h.TokP50)))
	cells := h.cells()
	next := []doc.Action{doc.GET("/pc/h/"+host+".md", ""), doc.POST("/v1/pc", "url tokens fmt alt"), doc.GET("/pc/about", "")}
	if len(h.Rows) > 0 {
		next = append([]doc.Action{doc.GET("/pc/"+h.Rows[0].Short(), "top page")}, next...)
	}
	d := &doc.Doc{
		Head: h.headLine(), Fields: h.ruleField(), Cols: hostCols, Rows: cells, Next: next,
		Title: title, Desc: desc, Canonical: "/pc/h/" + host, NoIndex: true, MaxAge: 60, Budget: 400,
		LD: map[string]any{"@context": "https://schema.org", "@type": "CollectionPage", "url": base + "/pc/h/" + host, "name": title, "description": desc},
	}
	type tr struct {
		Short, Path, Tok, Alt string
		N                     int
	}
	trs := make([]tr, 0, len(h.Rows))
	for _, row := range h.Rows {
		alt := ""
		if row.AltVisible() {
			alt = row.Alt
		}
		trs = append(trs, tr{row.Short(), row.Path, kfmt(int64(row.TokP50)), alt, row.N})
	}
	rule := ""
	if fs := h.ruleField(); len(fs) > 0 {
		rule = fs[0].Val
	}
	d.Body = render(hostTmpl, map[string]any{"Title": title, "Desc": desc, "Head": d.Head, "Rule": rule, "Rows": trs, "MD": "/pc/h/" + host + ".md", "Legend": legend})
	w.Header().Set("X-Robots-Tag", "noindex, follow")
	doc.Reply(w, r, 200, d)
}

// aboutFields is what /pc/about says is stored (and is not), in field lines.
var aboutFields = []doc.F{
	{Name: "stores", Val: "the canonical URL (lowercase scheme and host, path only), its sha256 (uh), per reporter one sample a day (tokens, bytes, fmt) keyed by root id or HMAC'd network key, the alt URL and its confirmations"},
	{Name: "never", Val: "query strings, fragments, userinfo, private or IP-literal hosts, capability-looking URLs (a path segment of 20+ chars with entropy >= 3.5, hex ids, token-like runs), paths with personal data, raw IPs, user agents, page content"},
	{Name: "report", Val: "POST /v1/pc {url, tokens, bytes, fmt: html|md|txt|json|pdf, alt} or ?url=&tokens=; token 100/day per root, or anonymous X-PoW (POST /v1/challenge?for=w) 30/day per network at half weight; one sample per reporter per URL per day, 32 kept per URL"},
	{Name: "numbers", Val: "n = distinct reporters; tok~ = weighted median over one sample per network (/24, /48), min..max over those; bytes~ likewise; fmt = the most reported format"},
	{Name: "alt", Val: "a cheaper twin on the same registrable domain; shown after 2 confirmations from networks other than the proposer's (POST the same alt, or POST /v1/pc/<uh>/altok); POST /v1/pc/<uh>/altbad contests it; a contested alt is replaced by the next proposal"},
	{Name: "hosts", Val: "GET /pc/h/<host> gives the median per page, the alt rule derived from confirmed twins (append .md, replace .html with .md, prefix /raw, host <other>) and the ten most expensive paths; the registrable domain also covers its subdomains"},
	{Name: "retention", Val: "URLs without a new sample for 180 d are deleted with their samples; nothing is exported or fed"},
	{Name: "reads", Val: "GET /pc?u=<url>, GET /pc/<uh>, GET /pc/h/<host>; .md/.json/.html twins; ops pc{url,tokens,bytes,fmt,alt}, pcg{u|uh|host}"},
}

var aboutTmpl = template.Must(template.New("pcabout").Parse(`<h1>{{.Title}}</h1>
<p class="meta">{{.Desc}}</p>
<dl>{{range .Fields}}<dt>{{.Name}}</dt><dd>{{.Val}}</dd>
{{end}}</dl>
<nav><ul><li><a href="/pc/about.md">markdown</a></li><li><a href="/openapi.json">POST /v1/pc</a></li></ul></nav>
`))

// about serves GET /pc/about (and GET /pc without a query): what is stored, how to report and read.
func (s *svc) about(w http.ResponseWriter, r *http.Request) {
	title := "web token-cost map: what is stored"
	desc := "How agents.ekaii.fr measures what a URL costs an AI agent to read: canonical URL rules, samples per reporter, medians over networks, cheaper twins and their confirmations."
	d := &doc.Doc{
		Head: "pc about: crowd-measured tokens per URL, cheaper twins on the same domain, numbers only", Fields: aboutFields,
		Next:  []doc.Action{doc.GET("/pc?u=", "lookup a url"), doc.POST("/v1/pc", "url tokens fmt alt"), doc.GET("/openapi.json", "")},
		Title: title, Desc: desc, Canonical: "/pc/about", MaxAge: 3600,
		LD: map[string]any{"@context": "https://schema.org", "@type": "WebPage", "url": doc.Base() + "/pc/about", "name": title, "description": desc},
	}
	d.Body = render(aboutTmpl, map[string]any{"Title": title, "Desc": desc, "Fields": aboutFields})
	doc.Reply(w, r, 200, d)
}

func render(t *template.Template, v any) template.HTML {
	var b bytes.Buffer
	if err := t.Execute(&b, v); err != nil {
		return ""
	}
	return template.HTML(b.String()) //nolint:gosec // output of html/template
}
