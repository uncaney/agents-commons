package doc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"ekaii.fr/commons/internal/core"
)

// Schema is the compiled request-body schema of one route (from its OpenAPI fragment).
type Schema struct {
	Props      []Prop
	Additional bool // additionalProperties: true
}

// Prop is one body field: Type string|integer|number|boolean|array|object; Max is maxLength
// (string), maxItems (array) or maximum (numbers); Min is minimum.
type Prop struct {
	Name, Type, Items string
	Max, Min          int
	HasMax, HasMin    bool
	Enum              []string
	Required          bool
}

func (s *Schema) prop(name string) (Prop, bool) {
	for _, p := range s.Props {
		if p.Name == name {
			return p, true
		}
	}
	return Prop{}, false
}

// orderedKeys returns the top-level keys of a JSON object in document order.
func orderedKeys(raw json.RawMessage) []string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var keys []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return keys
		}
		if k, ok := t.(string); ok {
			keys = append(keys, k)
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return keys
		}
	}
	return keys
}

// Compile turns a JSON Schema object (or an OpenAPI operation / requestBody / content object that
// contains one) into a Schema. Unusable input gives an empty, permissive Schema.
func Compile(raw json.RawMessage) *Schema {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return &Schema{Additional: true}
	}
	if rb, ok := m["requestBody"]; ok {
		return Compile(rb)
	}
	if c, ok := m["content"]; ok { // {"<media type>": {"schema": …}}
		var mm map[string]json.RawMessage
		if json.Unmarshal(c, &mm) == nil {
			for _, ct := range sortedKeys(mm) {
				var cc map[string]json.RawMessage
				if json.Unmarshal(mm[ct], &cc) == nil {
					if sc, ok := cc["schema"]; ok {
						return Compile(sc)
					}
				}
			}
		}
		return &Schema{Additional: true}
	}
	if sc, ok := m["schema"]; ok {
		return Compile(sc)
	}
	s := &Schema{}
	if ap, ok := m["additionalProperties"]; ok && string(ap) == "true" {
		s.Additional = true
	}
	var req []string
	json.Unmarshal(m["required"], &req)
	var props map[string]struct {
		Type       string          `json:"type"`
		MaxLength  *int            `json:"maxLength"`
		MaxItems   *int            `json:"maxItems"`
		Maximum    *int            `json:"maximum"`
		Minimum    *int            `json:"minimum"`
		Enum       []string        `json:"enum"`
		Items      json.RawMessage `json:"items"`
		Properties json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(m["properties"], &props) != nil || props == nil {
		return s
	}
	for _, name := range orderedKeys(m["properties"]) {
		pr, ok := props[name]
		if !ok || !parseNameRe.MatchString(name) {
			continue
		}
		p := Prop{Name: name, Type: pr.Type, Enum: pr.Enum}
		if p.Type == "" {
			p.Type = "string"
		}
		switch {
		case pr.MaxLength != nil && p.Type == "string":
			p.Max, p.HasMax = *pr.MaxLength, true
		case pr.MaxItems != nil && p.Type == "array":
			p.Max, p.HasMax = *pr.MaxItems, true
		case pr.Maximum != nil:
			p.Max, p.HasMax = *pr.Maximum, true
		}
		if pr.Minimum != nil {
			p.Min, p.HasMin = *pr.Minimum, true
		}
		if p.Type == "array" {
			var it struct {
				Type string `json:"type"`
			}
			json.Unmarshal(pr.Items, &it)
			p.Items = it.Type
			if p.Items == "" {
				p.Items = "string"
			}
		}
		for _, r := range req {
			if r == name {
				p.Required = true
			}
		}
		s.Props = append(s.Props, p)
	}
	return s
}

func sortedKeys(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- registry ----------------------------------------------------------------------------------

type routeSchema struct {
	method string
	segs   []string
	schema *Schema
}

var (
	regMu   sync.RWMutex
	routes  []routeSchema
	bodyOps = map[string]bool{"post": true, "put": true, "patch": true, "delete": true}
)

// RegisterSchema registers the body schema of "<METHOD> <path template>" (OpenAPI {param} or Go
// mux {param}/{rest...} segments). Later registrations of the same route win.
func RegisterSchema(method, pathTemplate string, schema json.RawMessage) {
	method = strings.ToUpper(method)
	p, _, _ := strings.Cut(pathTemplate, "?")
	rs := routeSchema{method, strings.Split(strings.Trim(p, "/"), "/"), Compile(schema)}
	regMu.Lock()
	defer regMu.Unlock()
	for i, r := range routes {
		if r.method == rs.method && strings.Join(r.segs, "/") == strings.Join(rs.segs, "/") {
			routes[i] = rs
			return
		}
	}
	routes = append(routes, rs)
}

// RegisterFragment registers every request body found in an OpenAPI fragment ({"paths": {…}}).
func RegisterFragment(frag json.RawMessage) {
	var doc struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(frag, &doc) != nil {
		return
	}
	for p, ops := range doc.Paths {
		for m, op := range ops {
			if !bodyOps[strings.ToLower(m)] {
				continue
			}
			var o struct {
				RequestBody json.RawMessage `json:"requestBody"`
			}
			if json.Unmarshal(op, &o) == nil && len(o.RequestBody) > 0 {
				RegisterSchema(m, p, o.RequestBody)
			}
		}
	}
}

// ResetSchemas clears the registry (tests).
func ResetSchemas() {
	regMu.Lock()
	routes = nil
	regMu.Unlock()
}

func segMatch(tmpl []string, p string) bool {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, t := range tmpl {
		if strings.HasPrefix(t, "{") && strings.HasSuffix(t, "...}") {
			return i < len(segs)
		}
		if i >= len(segs) {
			return false
		}
		if !(strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}")) && t != segs[i] {
			return false
		}
	}
	return len(segs) == len(tmpl)
}

// SchemaFor finds the body schema of a method and concrete (or template) path.
func SchemaFor(method, p string) (*Schema, bool) {
	method = strings.ToUpper(method)
	p, _, _ = strings.Cut(p, "?")
	regMu.RLock()
	defer regMu.RUnlock()
	for _, r := range routes {
		if r.method == method && segMatch(r.segs, p) {
			return r.schema, true
		}
	}
	return nil, false
}

// splitRoute parses "POST /v1/kb" or "/v1/kb" (POST default).
func splitRoute(route string) (string, string) {
	m, p, ok := strings.Cut(strings.TrimSpace(route), " ")
	if !ok {
		return "POST", m
	}
	return strings.ToUpper(m), strings.TrimSpace(p)
}

// --- expect / example --------------------------------------------------------------------------

func (p Prop) spec() string {
	s := p.Name
	switch p.Type {
	case "array":
		s += "[]"
		if p.HasMax {
			s += "<=" + strconv.Itoa(p.Max)
		}
	case "integer", "number":
		s += ":int"
		if p.Type == "number" {
			s = p.Name + ":num"
		}
		if p.HasMin || p.HasMax {
			s += " "
			if p.HasMin {
				s += strconv.Itoa(p.Min)
			}
			s += ".."
			if p.HasMax {
				s += strconv.Itoa(p.Max)
			}
		}
	case "boolean":
		s += ":bool"
	case "object":
		s += ":{}"
	default:
		if len(p.Enum) > 0 {
			s += ":(" + strings.Join(p.Enum, "|") + ")"
		} else if p.HasMax {
			s += "<=" + strconv.Itoa(p.Max)
		}
	}
	if p.Required {
		s += "*"
	}
	return s
}

// expectLine renders "title<=160* symptom<=1000 … (* required)".
func expectLine(s *Schema) string {
	if s == nil || len(s.Props) == 0 {
		return ""
	}
	parts := make([]string, 0, len(s.Props)+1)
	req := false
	for _, p := range s.Props {
		parts = append(parts, p.spec())
		req = req || p.Required
	}
	if req {
		parts = append(parts, "(* required)")
	}
	return strings.Join(parts, " ")
}

// exampleProps are the required fields (or the first field when none is required).
func (s *Schema) exampleProps() []Prop {
	var out []Prop
	for _, p := range s.Props {
		if p.Required {
			out = append(out, p)
		}
	}
	if len(out) == 0 && len(s.Props) > 0 {
		out = s.Props[:1]
	}
	return out
}

func (p Prop) placeholder() string {
	if len(p.Enum) > 0 {
		return p.Enum[0]
	}
	switch p.Type {
	case "integer", "number":
		if p.HasMin {
			return strconv.Itoa(p.Min)
		}
		return "1"
	case "boolean":
		return "true"
	}
	return "<" + p.Name + ">"
}

// example renders a minimal body in the given content type (JSON default).
func (s *Schema) example(ct string) string {
	props := s.exampleProps()
	if len(props) == 0 {
		return ""
	}
	switch {
	case strings.HasPrefix(ct, "text/"):
		lines := make([]string, 0, len(props))
		for _, p := range props {
			lines = append(lines, p.Name+": "+p.placeholder())
		}
		return strings.Join(lines, "\n")
	case strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/"):
		v := url.Values{}
		for _, p := range props {
			v.Set(p.Name, p.placeholder())
		}
		return v.Encode()
	default:
		w := &jw{}
		w.WriteByte('{')
		for _, p := range props {
			switch p.Type {
			case "integer", "number", "boolean":
				w.key(p.Name)
				w.WriteString(p.placeholder())
			case "array":
				w.put(p.Name, []string{p.placeholder()})
			default:
				w.put(p.Name, p.placeholder())
			}
		}
		w.WriteByte('}')
		return w.String()
	}
}

// shSkeleton renders the $'…' body of a curl line: "title: <title>\nfix: <fix>" (\n literal).
func shSkeleton(s *Schema) string {
	props := s.exampleProps()
	lines := make([]string, 0, len(props))
	for _, p := range props {
		lines = append(lines, p.Name+": "+strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(p.placeholder()))
	}
	return strings.Join(lines, `\n`)
}

// ExpectFields returns the expect:/example: fields for a route in the request's content type
// (nil when the route has no registered schema).
func ExpectFields(route, ct string) []F {
	m, p := splitRoute(route)
	s, ok := SchemaFor(m, p)
	if !ok {
		return nil
	}
	ct, _, _ = mime.ParseMediaType(ct)
	if ct == "" {
		ct = "application/json"
	}
	out := []F{{Name: "expect", Val: expectLine(s)}}
	if ex := s.example(ct); ex != "" {
		out = append(out, F{Name: "example", Val: ex, Multi: strings.Contains(ex, "\n")})
	}
	return out
}

// Expect returns the "expect: …" and "example: …" txt lines core.Decode appends to decoding
// errors on route ("POST /v1/kb"), JSON example.
func Expect(route string) []string { return ExpectCT(route, "application/json") }

// ExpectCT is Expect with the request's content type driving the example.
func ExpectCT(route, ct string) []string {
	var lines []string
	for _, f := range ExpectFields(route, ct) {
		if f.Multi {
			lines = append(lines, f.Name+": "+Indent(f.Val))
		} else {
			lines = append(lines, f.Name+": "+SafeLine(f.Val))
		}
	}
	return lines
}

// --- Parse (core.BodyParserFn) -----------------------------------------------------------------

const (
	maxParseBytes  = 1 << 20
	maxParseLines  = 2000
	maxParseFields = 32
	maxPartBytes   = 256 << 10
)

var (
	parseNameRe = regexp.MustCompile(`^[a-z_][a-z_-]{0,23}$`)
	fieldLineRe = regexp.MustCompile(`^([a-z_][a-z_-]{0,23}):(?: (.*))?$`)
)

func e422(msg string) error { return core.E(422, "bad", msg) }

type fieldSet struct {
	names []string
	vals  map[string][]string
}

func newFieldSet() *fieldSet { return &fieldSet{vals: map[string][]string{}} }

func (f *fieldSet) add(name, v string) error {
	if _, ok := f.vals[name]; !ok {
		if len(f.names) >= maxParseFields {
			return e422("too many fields")
		}
		f.names = append(f.names, name)
	}
	f.vals[name] = append(f.vals[name], v)
	return nil
}

func normName(n string) string { return strings.ReplaceAll(n, "-", "_") }

// parseText reads the txt grammar in reverse (head line and next:/… lines ignored).
func parseText(body []byte) (*fieldSet, error) {
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	if len(lines) > maxParseLines {
		return nil, e422("too many lines")
	}
	fs, cur := newFieldSet(), ""
	for i, l := range lines {
		switch {
		case l == "" || l == "  ":
			if cur != "" {
				fs.vals[cur][0] += "\n"
			}
		case strings.HasPrefix(l, "  "):
			if cur == "" {
				if i == 0 {
					continue
				}
				return nil, e422("bad line " + strconv.Itoa(i+1))
			}
			fs.vals[cur][0] += "\n" + l[2:]
		default:
			if m := fieldLineRe.FindStringSubmatch(l); m != nil {
				name := normName(m[1])
				if name == "next" {
					cur = ""
					continue
				}
				if _, dup := fs.vals[name]; dup {
					return nil, e422("dup field " + name)
				}
				if err := fs.add(name, m[2]); err != nil {
					return nil, err
				}
				cur = name
				continue
			}
			cur = ""
			if i == 0 || strings.HasPrefix(l, "…") {
				continue
			}
			return nil, e422("bad line " + strconv.Itoa(i+1))
		}
	}
	for _, n := range fs.names {
		v := strings.TrimRight(fs.vals[n][0], "\n")
		fs.vals[n][0] = strings.TrimPrefix(v, "\n")
	}
	return fs, nil
}

func parseForm(body []byte) (*fieldSet, error) {
	fs := newFieldSet()
	for _, kv := range strings.Split(string(body), "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		k, err1 := url.QueryUnescape(k)
		v, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			return nil, e422("bad form encoding")
		}
		k = normName(k)
		if !parseNameRe.MatchString(k) {
			return nil, e422("bad field " + truncRunes(SafeLine(k), 24))
		}
		if err := fs.add(k, v); err != nil {
			return nil, err
		}
	}
	return fs, nil
}

func parseMultipart(body []byte, boundary string) (*fieldSet, error) {
	if boundary == "" {
		return nil, e422("multipart boundary missing")
	}
	fs := newFieldSet()
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return fs, nil
		}
		if err != nil {
			return nil, e422("bad multipart body")
		}
		name := normName(part.FormName())
		if !parseNameRe.MatchString(name) {
			return nil, e422("bad field " + truncRunes(SafeLine(name), 24))
		}
		if part.FileName() != "" {
			return nil, e422("bad field " + name + ": files not accepted")
		}
		v, err := io.ReadAll(io.LimitReader(part, maxPartBytes+1))
		if err != nil || len(v) > maxPartBytes {
			return nil, e422("bad field " + name + ": too large")
		}
		if err := fs.add(name, string(v)); err != nil {
			return nil, err
		}
	}
}

func parseBool(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true, true
	case "false", "0", "no", "off", "":
		return false, true
	}
	return false, false
}

// toJSON coerces the fields through the schema into an ordered JSON object.
func (f *fieldSet) toJSON(s *Schema) (json.RawMessage, error) {
	w := &jw{}
	w.WriteByte('{')
	for _, name := range f.names {
		vals := f.vals[name]
		p, known := s.prop(name)
		if !known {
			if !s.Additional && len(s.Props) > 0 {
				return nil, e422("bad field " + name)
			}
			p = Prop{Name: name, Type: "string"}
		}
		bad := func(what string) error { return e422("bad field " + name + ": " + what) }
		switch p.Type {
		case "integer":
			n, err := strconv.Atoi(strings.TrimSpace(vals[0]))
			if err != nil || len(vals) > 1 {
				return nil, bad("integer expected")
			}
			w.put(name, n)
		case "number":
			x, err := strconv.ParseFloat(strings.TrimSpace(vals[0]), 64)
			if err != nil || len(vals) > 1 {
				return nil, bad("number expected")
			}
			w.put(name, x)
		case "boolean":
			b, ok := parseBool(vals[0])
			if !ok || len(vals) > 1 {
				return nil, bad("boolean expected")
			}
			w.put(name, b)
		case "array":
			items := vals
			if len(vals) == 1 {
				items = nil
				for _, it := range strings.Split(vals[0], ",") {
					if it = strings.TrimSpace(it); it != "" {
						items = append(items, it)
					}
				}
			}
			if p.HasMax && len(items) > p.Max {
				return nil, bad("at most " + strconv.Itoa(p.Max) + " items")
			}
			if p.Items == "integer" {
				ns := make([]int, 0, len(items))
				for _, it := range items {
					n, err := strconv.Atoi(it)
					if err != nil {
						return nil, bad("integer items expected")
					}
					ns = append(ns, n)
				}
				w.put(name, ns)
			} else {
				if items == nil {
					items = []string{}
				}
				w.put(name, items)
			}
		case "object":
			v := strings.TrimSpace(vals[0])
			if len(vals) > 1 || !strings.HasPrefix(v, "{") || !json.Valid([]byte(v)) {
				return nil, bad("JSON object expected")
			}
			w.key(name)
			w.WriteString(v)
		default:
			if len(vals) > 1 {
				return nil, e422("dup field " + name)
			}
			w.put(name, vals[0])
		}
	}
	w.WriteByte('}')
	return json.RawMessage(w.Bytes()), nil
}

// Parse implements core.BodyParserFn: it reads a text/plain (txt grammar in reverse),
// application/x-www-form-urlencoded or multipart/form-data body (plus query parameters on
// POST/PATCH, lowest precedence) and returns the equivalent JSON object coerced through schema.
// A JSON body (declared or sniffed from a leading "{") is returned unchanged. Bounds: the caller's
// MaxBytesReader first, then 1 MiB, <= 2000 lines, <= 32 fields, names [a-z_]{1,24}; a repeated
// field -> 422 dup field; unknown field -> 422 bad field <name>.
func Parse(r *http.Request, schema json.RawMessage) (json.RawMessage, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxParseBytes+1))
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			return nil, core.ErrSize
		}
		return nil, core.Bad("read: " + truncRunes(err.Error(), 120))
	}
	if len(body) > maxParseBytes {
		return nil, core.ErrSize
	}
	ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "" {
		ct = "text/plain"
		if bytes.HasPrefix(bytes.TrimLeft(body, " \t\r\n"), []byte("{")) {
			ct = "application/json"
		}
	}
	var fs *fieldSet
	switch ct {
	case "application/json":
		if len(bytes.TrimSpace(body)) == 0 {
			return json.RawMessage("{}"), nil
		}
		if !json.Valid(body) {
			return nil, core.Bad("json: invalid")
		}
		return json.RawMessage(body), nil
	case "text/plain", "text/markdown":
		fs, err = parseText(body)
	case "application/x-www-form-urlencoded":
		fs, err = parseForm(body)
	case "multipart/form-data":
		fs, err = parseMultipart(body, params["boundary"])
	default:
		return nil, core.E(415, "bad", "content type "+truncRunes(SafeLine(ct), 60))
	}
	if err != nil {
		return nil, err
	}
	s := Compile(schema)
	if r.Method == http.MethodPost || r.Method == http.MethodPatch {
		q := r.URL.Query()
		for _, k := range sortedQueryKeys(q) {
			name := normName(k)
			if _, has := fs.vals[name]; has || !parseNameRe.MatchString(name) {
				continue
			}
			if _, known := s.prop(name); !known {
				continue
			}
			for _, v := range q[k] {
				if err := fs.add(name, v); err != nil {
					return nil, err
				}
			}
		}
	}
	return fs.toJSON(s)
}

func sortedQueryKeys(q url.Values) []string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
