package doc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/core"
)

// opts is the per-request rendering state.
type opts struct {
	status  int
	abs     bool
	mark    string
	nextOff bool
	sel     []string
	budget  int // tokens; 0 = unbounded
	retryS  int
	path    string
	query   url.Values
}

func optsFor(r *http.Request, status int, d *Doc, f Format) opts {
	def := d.Budget
	if def <= 0 {
		def = DefaultBudget
	}
	o := opts{status: status, abs: Abs(r) || f == MD, mark: Mark(r), nextOff: NextOff(r), sel: Fields(r),
		budget: BudgetFor(r, def), path: r.URL.Path, query: r.URL.Query()}
	if status == 429 || status == 503 {
		o.retryS = d.RetryS // ReplyAs fills a default from the Retry-After already set on w
	}
	return o
}

// block is one renderable unit of the body: a txt line or an md field/row block.
type block struct {
	text string
	row  int // row index, -1 for fields
}

var reservedJSON = map[string]bool{"head": true, "err": true, "msg": true, "rows": true, "next": true, "more": true, "retry_s": true}

func (d *Doc) headLine() string {
	if d.Code != "" {
		return strings.TrimSpace("err " + SafeLine(d.Code) + " " + SafeLine(d.Head))
	}
	return SafeLine(d.Head)
}

// fields returns the renderable fields after ?s= selection (invalid or reserved names dropped).
func (d *Doc) fields(sel []string) []F {
	var want map[string]bool
	if len(sel) > 0 {
		want = map[string]bool{}
		for _, s := range sel {
			want[s] = true
		}
	}
	out := make([]F, 0, len(d.Fields))
	for _, f := range d.Fields {
		if !nameRe.MatchString(f.Name) || f.Name == "next" || (want != nil && !want[f.Name]) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// cols returns the selected column indices (nil = every column).
func (d *Doc) cols(sel []string) []int {
	if len(sel) == 0 || len(d.Cols) == 0 {
		return nil
	}
	var idx []int
	for _, s := range sel {
		for i, c := range d.Cols {
			if c == s {
				idx = append(idx, i)
			}
		}
	}
	if idx == nil {
		return []int{}
	}
	return idx
}

// rowLine renders one row: cells SafeLine'd and space-joined; a line that would start with a
// reserved prefix (first cell empty or hostile) is pushed off column 0.
func (d *Doc) rowLine(row []string, cols []int) string {
	cells := make([]string, 0, len(row))
	if cols == nil {
		for _, c := range row {
			cells = append(cells, SafeLine(c))
		}
	} else {
		for _, i := range cols {
			if i < len(row) {
				cells = append(cells, SafeLine(row[i]))
			}
		}
	}
	line := strings.Join(cells, " ")
	if line == "" || line[0] == ' ' || strings.HasPrefix(line, "next:") || strings.HasPrefix(line, "> ") || strings.HasPrefix(line, "…") {
		line = "- " + line
	}
	return line
}

// txtBlocks returns the body as txt lines (fields then rows).
func (d *Doc) txtBlocks(o opts) []block {
	var out []block
	for _, f := range d.fields(o.sel) {
		if f.Multi {
			for _, l := range strings.Split(f.Name+": "+markWrap(o.mark, Indent(f.Val)), "\n") {
				out = append(out, block{l, -1})
			}
		} else {
			out = append(out, block{f.Name + ": " + markWrap(o.mark, SafeLine(f.Val)), -1})
		}
	}
	cols := d.cols(o.sel)
	for i, row := range d.Rows {
		out = append(out, block{markWrap(o.mark, d.rowLine(row, cols)), i})
	}
	return out
}

// mdSpan escapes an inline value and wraps it in data markers (markers stay unescaped so a
// literal "[/data m]" in content renders as "\[/data m\]").
func mdSpan(mark, s string) string {
	if mark == "" {
		return MDEscape(s)
	}
	return "[data " + mark + "]" + MDEscape(s) + "[/data " + mark + "]"
}

// mdBlocks returns the body as Markdown blocks (one per field or row).
func (d *Doc) mdBlocks(o opts) []block {
	var out []block
	for _, f := range d.fields(o.sel) {
		if f.Multi {
			v := strings.TrimRight(CleanMulti(f.Val), "\n")
			fence := MarkdownFence(v)
			out = append(out, block{"**" + f.Name + "**:\n" + fence + "\n" + markWrap(o.mark, v) + "\n" + fence, -1})
		} else {
			out = append(out, block{"**" + f.Name + "**: " + mdSpan(o.mark, f.Val), -1})
		}
	}
	cols := d.cols(o.sel)
	for i, row := range d.Rows {
		out = append(out, block{"- " + mdSpan(o.mark, d.rowLine(row, cols)), i})
	}
	return out
}

// truncate keeps whole blocks while they fit in avail bytes and returns the "… +n more" line
// (empty when everything fits). The continuation URL carries ?after=<cursor> when the cut falls
// inside rows and the Doc has a Cursor, else ?b=0 (the unbounded rendering).
func (d *Doc) truncate(blocks []block, avail int, o opts) ([]block, string) {
	used := 0
	for i, b := range blocks {
		used += len(b.text) + 1
		if used > avail {
			more := len(blocks) - i
			q := url.Values{}
			for k, v := range o.query {
				if k != "after" {
					q[k] = v
				}
			}
			last := -1
			if i > 0 {
				last = blocks[i-1].row
			}
			if last >= 0 && d.Cursor != nil {
				q.Set("after", d.Cursor(last))
			} else {
				q.Set("b", "0")
			}
			return blocks[:i], "… +" + strconv.Itoa(more) + " more: " + o.path + "?" + q.Encode()
		}
	}
	return blocks, ""
}

func (d *Doc) tail(o opts) string {
	if o.nextOff {
		return ""
	}
	return tailLine(Next(d.Next...), o.abs, o.retryS)
}

// budgeted applies the token budget to blocks, reserving room for head, tail and the more line.
func (d *Doc) budgeted(blocks []block, o opts, head, tail string) ([]block, string) {
	if o.budget <= 0 {
		return blocks, ""
	}
	avail := o.budget*4 - len(head) - len(tail) - len(o.path) - 96
	return d.truncate(blocks, max(avail, 0), o)
}

func renderTxt(d *Doc, o opts, withTail bool) string {
	head, tail := d.headLine(), ""
	if withTail {
		tail = d.tail(o)
	}
	blocks, more := d.budgeted(d.txtBlocks(o), o, head, tail)
	var b strings.Builder
	if head != "" {
		b.WriteString(head + "\n")
	}
	for _, bl := range blocks {
		b.WriteString(bl.text + "\n")
	}
	if more != "" {
		b.WriteString(more + "\n")
	}
	if tail != "" {
		b.WriteString(tail + "\n")
	}
	return b.String()
}

func renderMD(d *Doc, o opts) string {
	head := d.headLine()
	h1 := d.Title
	if h1 == "" {
		h1 = head
	}
	var b strings.Builder
	b.WriteString("# " + MDEscape(h1) + "\n")
	if d.Title != "" && head != "" {
		b.WriteString("\n" + MDEscape(head) + "\n")
	}
	tail := d.tail(o)
	blocks, more := d.budgeted(d.mdBlocks(o), o, head, tail)
	for _, bl := range blocks {
		b.WriteString("\n" + bl.text + "\n")
	}
	if more != "" {
		b.WriteString("\n" + more + "\n")
	}
	if tail != "" {
		b.WriteString("\nnext:\n")
		for _, a := range Next(d.Next...) {
			a.Path = absPath(a.Path, o.abs)
			b.WriteString("- " + a.String() + "\n")
		}
		if o.retryS > 0 {
			b.WriteString("- retry_s=" + strconv.Itoa(o.retryS) + "\n")
		}
	}
	if d.Canonical != "" {
		b.WriteString("\npermalink: " + Base() + d.Canonical + "\n")
	}
	return b.String()
}

// jw is a tiny ordered JSON object writer (encoding/json sorts map keys).
type jw struct {
	bytes.Buffer
	n int
}

func jsonBytes(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte("null")
	}
	return bytes.TrimRight(b.Bytes(), "\n")
}

func (j *jw) key(k string) {
	if j.n > 0 {
		j.WriteByte(',')
	}
	j.n++
	j.Write(jsonBytes(k))
	j.WriteByte(':')
}

func (j *jw) put(k string, v any) { j.key(k); j.Write(jsonBytes(v)) }

func actionsJSON(acts []Action, abs bool) []map[string]string {
	out := make([]map[string]string, 0, len(acts))
	for _, a := range acts {
		m := map[string]string{"method": a.Method, "path": absPath(a.Path, abs)}
		if a.Hint != "" {
			m["hint"] = a.Hint
		}
		out = append(out, m)
	}
	return out
}

// jsonRows encodes rows (objects keyed by Cols when set, else arrays), truncated to the budget;
// it returns the encoded array, the number of rows kept and the continuation URL ("" = all).
func (d *Doc) jsonRows(o opts) ([]byte, int, string) {
	var b bytes.Buffer
	b.WriteByte('[')
	avail := 1 << 30
	if o.budget > 0 {
		avail = o.budget * 4
	}
	cols := d.cols(o.sel)
	n := 0
	for i, row := range d.Rows {
		var enc []byte
		if len(d.Cols) > 0 {
			w := &jw{}
			w.WriteByte('{')
			for ci, c := range d.Cols {
				if ci < len(row) && (cols == nil || contains(cols, ci)) {
					w.put(c, row[ci])
				}
			}
			w.WriteByte('}')
			enc = w.Bytes()
		} else {
			cells := make([]string, 0, len(row))
			for ci, c := range row {
				if cols == nil || contains(cols, ci) {
					cells = append(cells, c)
				}
			}
			enc = jsonBytes(cells)
		}
		if b.Len()+len(enc)+1 > avail && n > 0 {
			q := url.Values{}
			for k, v := range o.query {
				if k != "after" {
					q[k] = v
				}
			}
			if d.Cursor != nil {
				q.Set("after", d.Cursor(i-1))
			} else {
				q.Set("b", "0")
			}
			b.WriteByte(']')
			return b.Bytes(), n, o.path + "?" + q.Encode()
		}
		if n > 0 {
			b.WriteByte(',')
		}
		b.Write(enc)
		n++
	}
	b.WriteByte(']')
	return b.Bytes(), n, ""
}

func contains(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func renderJSON(d *Doc, o opts) []byte {
	w := &jw{}
	w.WriteByte('{')
	if d.Code != "" {
		w.put("err", d.Code)
		w.put("msg", d.Head)
	} else if d.Head != "" {
		w.put("head", d.Head)
	}
	vals := map[string][]string{}
	var order []string
	for _, f := range d.fields(o.sel) {
		if reservedJSON[f.Name] {
			continue
		}
		if _, ok := vals[f.Name]; !ok {
			order = append(order, f.Name)
		}
		vals[f.Name] = append(vals[f.Name], f.Val)
	}
	for _, k := range order {
		if v := vals[k]; len(v) == 1 {
			w.put(k, v[0])
		} else {
			w.put(k, v)
		}
	}
	if len(d.Rows) > 0 || len(d.Cols) > 0 {
		rows, kept, more := d.jsonRows(o)
		w.key("rows")
		w.Write(rows)
		if more != "" {
			w.put("more", map[string]any{"n": len(d.Rows) - kept, "url": more})
		}
	}
	if !o.nextOff {
		w.put("next", actionsJSON(Next(d.Next...), o.abs))
	}
	if o.retryS > 0 {
		w.put("retry_s", o.retryS)
	}
	w.WriteString("}\n")
	return w.Bytes()
}

func renderProblem(d *Doc, o opts) []byte {
	w := &jw{}
	w.WriteByte('{')
	w.put("type", Base()+"/help/err/"+url.PathEscape(d.Code))
	w.put("title", d.Code)
	w.put("status", o.status)
	w.put("detail", d.Head)
	w.put("instance", o.path)
	for _, f := range d.fields(o.sel) {
		if !reservedJSON[f.Name] && f.Name != "type" && f.Name != "title" && f.Name != "status" && f.Name != "detail" && f.Name != "instance" {
			w.put(f.Name, f.Val)
		}
	}
	if !o.nextOff {
		w.put("next", actionsJSON(Next(d.Next...), o.abs))
	}
	if o.retryS > 0 {
		w.put("retry_s", o.retryS)
	}
	w.WriteString("}\n")
	return w.Bytes()
}

// anonFeasible reports actions that work with X-PoW instead of a token.
func anonFeasible(a Action) bool {
	switch {
	case a.Method == "POST" && strings.HasPrefix(a.Path, "/w/"):
	case a.Method == "PUT" && strings.HasPrefix(a.Path, "/d/"):
	case a.Method == "POST" && (strings.HasPrefix(a.Path, "/v1/ts") || strings.HasPrefix(a.Path, "/v1/beacon")):
	default:
		return false
	}
	return true
}

func shQuote(u string) string { return "'" + strings.ReplaceAll(u, "'", "%27") + "'" }

func renderSh(d *Doc, o opts) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	txt := strings.TrimRight(renderTxt(d, o, false), "\n")
	for _, l := range strings.Split(txt, "\n") {
		b.WriteString("# " + l + "\n")
	}
	acts := Next(d.Next...)
	if len(acts) > 0 && !o.nextOff {
		b.WriteString("# next:\n")
	}
	for _, a := range acts {
		if o.nextOff {
			break
		}
		if a.Method == "" {
			b.WriteString("# " + SafeLine(a.Hint) + "\n")
			continue
		}
		comment := a.Hint
		if comment == "" {
			comment = a.Method + " " + a.Path
		}
		b.WriteString("# " + SafeLine(comment) + "\n")
		p, _, _ := strings.Cut(a.Path, "?")
		var cmd strings.Builder
		cmd.WriteString("curl -sS -X " + a.Method)
		switch {
		case anonFeasible(a):
			cmd.WriteString(` -H "X-PoW: $CX_POW"`)
		case a.Method != "GET" || strings.HasPrefix(a.Path, "/v1/"):
			cmd.WriteString(` -H "Authorization: Bearer $CX_TOKEN"`)
		}
		if a.Method == "POST" || a.Method == "PUT" || a.Method == "PATCH" {
			if sc, ok := SchemaFor(a.Method, p); ok {
				if exp := expectLine(sc); exp != "" {
					b.WriteString("# body: " + exp + "\n")
				}
				cmd.WriteString(` -H "Content-Type: text/plain" --data-binary $'` + shSkeleton(sc) + "'")
			}
		}
		cmd.WriteString(" " + shQuote(Base()+a.Path))
		b.WriteString(cmd.String() + "\n")
	}
	if o.retryS > 0 {
		b.WriteString("# retry_s=" + strconv.Itoa(o.retryS) + "\n")
	}
	return b.String()
}

// render produces the body and content type for one format.
func render(d *Doc, o opts, f Format) ([]byte, string) {
	switch f {
	case MD:
		return []byte(renderMD(d, o)), "text/markdown; charset=utf-8"
	case JSON:
		return renderJSON(d, o), "application/json"
	case Problem:
		if d.Code != "" {
			return renderProblem(d, o), "application/problem+json"
		}
		return renderJSON(d, o), "application/json"
	case JSONLD:
		if d.LD != nil {
			return append(jsonBytes(d.LD), '\n'), "application/ld+json"
		}
		return renderJSON(d, o), "application/json"
	case HTML:
		return renderHTML(d, o), "text/html; charset=utf-8"
	case Sh:
		return []byte(renderSh(d, o)), "text/x-shellscript; charset=utf-8"
	default:
		return []byte(renderTxt(d, o, true)), "text/plain; charset=utf-8"
	}
}

// Render returns the body and content type of d in format f for request r (pure; used by MCP
// resources and tests).
func Render(r *http.Request, status int, d *Doc, f Format) ([]byte, string) {
	return render(d, optsFor(r, status, d, f), f)
}

// --- headers and writing -----------------------------------------------------------------------

// ETag is the weak validator of a body: W/"<sha256[:16]>".
func ETag(body []byte) string {
	s := sha256.Sum256(body)
	return `W/"` + hex.EncodeToString(s[:])[:16] + `"`
}

// NotModified reports whether If-None-Match matches etag (weak comparison, "*" matches).
func NotModified(r *http.Request, etag string) bool {
	inm := r.Header.Get("If-None-Match")
	if inm == "" {
		return false
	}
	want := strings.TrimPrefix(etag, "W/")
	for _, t := range strings.Split(inm, ",") {
		t = strings.TrimSpace(t)
		if t == "*" || strings.TrimPrefix(t, "W/") == want {
			return true
		}
	}
	return false
}

const (
	ccPage   = "public, max-age=300, stale-while-revalidate=3600, stale-if-error=604800"
	ccAPI    = "public, max-age=60, stale-while-revalidate=600"
	ccNoCach = "no-store"
)

// cacheControl implements the Cache-Control rules (token -> private, anonymous GET -> public).
func cacheControl(r *http.Request, status int, d *Doc) string {
	switch {
	case d != nil && d.MaxAge < 0:
		return ccNoCach
	case HasToken(r):
		return "private, no-store"
	case r.Method != http.MethodGet && r.Method != http.MethodHead:
		return ccNoCach
	case d != nil && d.MaxAge > 0:
		return "public, max-age=" + strconv.Itoa(d.MaxAge) + ", stale-while-revalidate=" + strconv.Itoa(d.MaxAge*12) + ", stale-if-error=604800"
	case status == 200:
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			return ccAPI
		}
		return ccPage
	case status == 404 || status == 410:
		return "public, max-age=60"
	default:
		return ccNoCach
	}
}

func hasRel(h http.Header, rel string) bool {
	for _, v := range h.Values("Link") {
		if strings.Contains(v, `rel="`+rel+`"`) {
			return true
		}
	}
	return false
}

// linkValue formats one Link header member.
func linkValue(l Link, abs bool) string {
	s := "<" + absPath(l.Href, abs) + `>; rel="` + l.Rel + `"`
	if l.Type != "" {
		s += `; type="` + l.Type + `"`
	}
	if l.Title != "" {
		s += `; title="` + strings.ReplaceAll(SafeLine(l.Title), `"`, "'") + `"`
	}
	return s
}

// LinkHeader formats links as one Link header value.
func LinkHeader(links []Link, abs bool) string {
	parts := make([]string, 0, len(links))
	for _, l := range links {
		if l.Href != "" && l.Rel != "" {
			parts = append(parts, linkValue(l, abs))
		}
	}
	return strings.Join(parts, ", ")
}

func setHeaders(h http.Header, r *http.Request, status int, d *Doc, o opts, f Format) {
	if !strings.Contains(strings.ToLower(h.Get("Vary")), "accept") {
		h.Add("Vary", "Accept")
	}
	h.Set("Cache-Control", cacheControl(r, status, d))
	if d.NoIndex && h.Get("X-Robots-Tag") == "" {
		h.Set("X-Robots-Tag", "noindex")
	}
	if d.Canonical != "" && !hasRel(h, "canonical") {
		h.Add("Link", linkValue(Link{Rel: "canonical", Href: d.Canonical}, o.abs))
	}
	for _, l := range d.Links {
		if l.Href != "" && l.Rel != "" && OneLine(l.Href) && OneLine(l.Rel) {
			h.Add("Link", linkValue(l, o.abs))
		}
	}
	if status < 300 && d.Code == "" && !hasRel(h, "license") {
		h.Add("Link", `<`+CurrentSite().License+`>; rel="license"`)
	}
	if o.retryS > 0 && h.Get("Retry-After") == "" {
		h.Set("Retry-After", strconv.Itoa(o.retryS))
	}
	if f == HTML {
		h.Set("Content-Security-Policy", csp())
	}
}

// writeBody sends body with ETag/304 handling (GET/HEAD, 200) and no body on HEAD.
func writeBody(w http.ResponseWriter, r *http.Request, status int, body []byte, ct string) {
	h := w.Header()
	if status == 200 && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		et := ETag(body)
		h.Set("ETag", et)
		if NotModified(r, et) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	h.Set("Content-Type", ct)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

// Reply renders d in the negotiated format with the header policy (ETag/304, Cache-Control,
// Vary, Link, X-Robots-Tag, Retry-After, CSP on HTML).
func Reply(w http.ResponseWriter, r *http.Request, status int, d *Doc) {
	ReplyAs(w, r, status, d, Negotiate(r))
}

// ReplyAs is Reply with an explicit format.
func ReplyAs(w http.ResponseWriter, r *http.Request, status int, d *Doc, f Format) {
	if d == nil {
		d = &Doc{}
	}
	o := optsFor(r, status, d, f)
	if (status == 429 || status == 503) && o.retryS <= 0 {
		if n, _ := strconv.Atoi(w.Header().Get("Retry-After")); n > 0 {
			o.retryS = n
		} else if status == 503 {
			o.retryS = 120
		} else {
			o.retryS = 60
		}
	}
	body, ct := render(d, o, f)
	setHeaders(w.Header(), r, status, d, o, f)
	writeBody(w, r, status, body, ct)
}

// ReplyJSONArray writes a v1 array-shaped JSON reply unchanged (no next), with the header policy.
func ReplyJSONArray(w http.ResponseWriter, r *http.Request, status int, v any) {
	body := append(jsonBytes(v), '\n')
	d := &Doc{}
	setHeaders(w.Header(), r, status, d, optsFor(r, status, d, JSON), JSON)
	writeBody(w, r, status, body, "application/json")
}

// Tail writes v1 hand-built text (status 200) plus the next: tail; budgets truncate at line
// boundaries after the first (head) line.
func Tail(w http.ResponseWriter, r *http.Request, text string, next ...Action) {
	TailStatus(w, r, 200, text, next...)
}

// TailStatus is Tail with an explicit status.
func TailStatus(w http.ResponseWriter, r *http.Request, status int, text string, next ...Action) {
	d := &Doc{Next: next}
	o := optsFor(r, status, d, Txt)
	text = strings.TrimRight(text, "\n")
	var head string
	var blocks []block
	if text != "" {
		lines := strings.Split(text, "\n")
		head = lines[0]
		for _, l := range lines[1:] {
			blocks = append(blocks, block{l, -1})
		}
	}
	tail := d.tail(o)
	blocks, more := d.budgeted(blocks, o, head, tail)
	var b strings.Builder
	if head != "" {
		b.WriteString(head + "\n")
	}
	for _, bl := range blocks {
		b.WriteString(bl.text + "\n")
	}
	if more != "" {
		b.WriteString(more + "\n")
	}
	if tail != "" {
		b.WriteString(tail + "\n")
	}
	setHeaders(w.Header(), r, status, d, o, Txt)
	writeBody(w, r, status, []byte(b.String()), "text/plain; charset=utf-8")
}

// RawActions writes the actions of a raw-body reply as headers: X-Next: <METHOD> <path> | … and
// Link: <path>; rel="edit" for the first PUT/PATCH. Honours ?next=0 and ?abs=1.
func RawActions(w http.ResponseWriter, r *http.Request, acts ...Action) {
	acts = Next(acts...)
	if NextOff(r) || len(acts) == 0 {
		return
	}
	abs := Abs(r)
	parts := make([]string, 0, len(acts))
	edit := false
	for _, a := range acts {
		a.Path = absPath(a.Path, abs)
		parts = append(parts, a.String())
		if !edit && (a.Method == "PUT" || a.Method == "PATCH") {
			w.Header().Add("Link", "<"+a.Path+`>; rel="edit"`)
			edit = true
		}
	}
	w.Header().Set("X-Next", strings.Join(parts, " | "))
}

// --- errors --------------------------------------------------------------------------------------

// recovery holds the default next: lines per error code.
var recovery = map[string][]Action{
	"auth":     {POST("/v1/challenge", ""), POST("/w/kb", "+X-PoW"), GET("/help", "")},
	"pow":      {POST("/v1/challenge?for=w", ""), GET("/help", "")},
	"notfound": {GET("/grammar", ""), GET("/help", "")},
	"quota":    {GET("/v1/me", "")},
	"rate":     {GET("/v1/me", "")},
	"credits":  {GET("/v1/me", ""), GET("/worker", "")},
	"scope":    {GET("/v1/me", "")},
	"bad":      {GET("/help", ""), GET("/openapi.json", "")},
	"size":     {GET("/openapi.json", "limits")},
}

// Error builds an error Doc ("err <code> <msg>" + next: recovery; defaults by code).
func Error(code, msg string, next ...Action) *Doc {
	if len(next) == 0 {
		next = recovery[code]
	}
	if len(next) == 0 {
		next = []Action{GET("/help", "")}
	}
	return &Doc{Code: code, Head: msg, Next: next, NoIndex: true}
}

// Err writes an error in the negotiated format (problem+json when asked). Decoding errors
// (400/413/415/422) on a route with a known schema gain expect:/example: lines.
func Err(w http.ResponseWriter, r *http.Request, status int, code, msg string, next ...Action) {
	d := Error(code, msg, next...)
	if status == 400 || status == 413 || status == 415 || status == 422 {
		d.Fields = append(d.Fields, ExpectFields(r.Method+" "+r.URL.Path, r.Header.Get("Content-Type"))...)
	}
	Reply(w, r, status, d)
}

// Fail maps an error to the wire like core.Fail: *core.APIError as-is, MaxBytes -> 413 size,
// anything else -> 500 (logged).
func Fail(w http.ResponseWriter, r *http.Request, err error, next ...Action) {
	var ae *core.APIError
	var mb *http.MaxBytesError
	switch {
	case errors.As(err, &ae):
		Err(w, r, ae.Status, ae.Code, ae.Msg, next...)
	case errors.As(err, &mb):
		Err(w, r, 413, "size", "body too large", next...)
	default:
		slog.Error("internal error", "m", r.Method, "p", r.URL.Path, "err", err)
		Err(w, r, 500, "internal", "internal error", next...)
	}
}

// Pre renders the txt body (without the tail) for a <pre> element.
func Pre(d *Doc, r *http.Request) template.HTML {
	return template.HTML(template.HTMLEscapeString(renderTxt(d, optsFor(r, 200, d, HTML), false)))
}
