// cx-json-schema: validate a JSON document against a JSON Schema subset (drafts 7 / 2020-12
// core keywords). Input {"schema":{...},"data":...}. Output "valid" or "invalid <n>" followed by
// one "<path>: <message>" line per failure (deterministic order). Keywords: type (incl. arrays,
// integer), enum, const, properties, required, additionalProperties, patternProperties,
// minProperties, maxProperties, items (schema or tuple), prefixItems, additionalItems, minItems,
// maxItems, uniqueItems, minimum, maximum, exclusiveMinimum, exclusiveMaximum, multipleOf,
// minLength, maxLength, pattern (RE2), format (email, uri, date-time, date, time, uuid, ipv4,
// ipv6, hostname), allOf, anyOf, oneOf, not, if/then/else, $ref to #/definitions/... or
// #/$defs/..., true/false schemas.
package main

import (
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

type failure struct{ path, msg string }

type validator struct {
	root  any
	fails []failure
	depth int
}

func (v *validator) fail(path, msg string) {
	if len(v.fails) < 200 {
		v.fails = append(v.fails, failure{path, msg})
	}
}

func typeName(x any) string {
	switch t := x.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		if t == math.Trunc(t) {
			return "integer"
		}
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func numOf(x any) (float64, bool) {
	f, ok := x.(float64)
	return f, ok
}

func num(f float64) string { return sio.Number(f) }

func equal(a, b any) bool { return sio.Compact(a) == sio.Compact(b) }

func (v *validator) resolve(ref string) (any, bool) {
	if !strings.HasPrefix(ref, "#") {
		return nil, false
	}
	cur := v.root
	for _, seg := range strings.Split(strings.TrimPrefix(ref, "#"), "/") {
		if seg == "" {
			continue
		}
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		switch t := cur.(type) {
		case map[string]any:
			nx, ok := t[seg]
			if !ok {
				return nil, false
			}
			cur = nx
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(t) {
				return nil, false
			}
			cur = t[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// check validates data at path against schema, appending failures.
func (v *validator) check(schema any, data any, path string) {
	v.depth++
	defer func() { v.depth-- }()
	if v.depth > 64 {
		v.fail(path, "schema nesting too deep")
		return
	}
	switch s := schema.(type) {
	case bool:
		if !s {
			v.fail(path, "schema is false")
		}
	case map[string]any:
		v.checkObject(s, data, path)
	default:
		v.fail(path, "schema must be an object or boolean")
	}
}

// probe reports whether data passes schema without recording failures.
func (v *validator) probe(schema any, data any, path string) bool {
	saved := v.fails
	v.fails = nil
	v.check(schema, data, path)
	ok := len(v.fails) == 0
	v.fails = saved
	return ok
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (v *validator) checkObject(s map[string]any, data any, path string) {
	if ref, ok := s["$ref"].(string); ok {
		target, found := v.resolve(ref)
		if !found {
			v.fail(path, "unresolvable $ref "+ref)
			return
		}
		v.check(target, data, path)
	}
	if t, ok := s["type"]; ok {
		var types []string
		switch tt := t.(type) {
		case string:
			types = []string{tt}
		case []any:
			for _, x := range tt {
				if sx, ok := x.(string); ok {
					types = append(types, sx)
				}
			}
		}
		got := typeName(data)
		match := false
		for _, want := range types {
			if want == got || (want == "number" && got == "integer") {
				match = true
			}
		}
		if !match && len(types) > 0 {
			v.fail(path, "type is "+got+", want "+strings.Join(types, "|"))
		}
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range e {
			if equal(x, data) {
				found = true
			}
		}
		if !found {
			v.fail(path, "value not in enum")
		}
	}
	if c, ok := s["const"]; ok && !equal(c, data) {
		v.fail(path, "value differs from const "+sio.Compact(c))
	}
	if f, ok := numOf(data); ok {
		if m, ok := numOf(s["minimum"]); ok && f < m {
			v.fail(path, num(f)+" < minimum "+num(m))
		}
		if m, ok := numOf(s["maximum"]); ok && f > m {
			v.fail(path, num(f)+" > maximum "+num(m))
		}
		if m, ok := numOf(s["exclusiveMinimum"]); ok && f <= m {
			v.fail(path, num(f)+" <= exclusiveMinimum "+num(m))
		}
		if m, ok := numOf(s["exclusiveMaximum"]); ok && f >= m {
			v.fail(path, num(f)+" >= exclusiveMaximum "+num(m))
		}
		if m, ok := numOf(s["multipleOf"]); ok && m > 0 {
			if q := f / m; math.Abs(q-math.Round(q)) > 1e-9 {
				v.fail(path, num(f)+" is not a multiple of "+num(m))
			}
		}
	}
	if str, ok := data.(string); ok {
		n := float64(len([]rune(str)))
		if m, ok := numOf(s["minLength"]); ok && n < m {
			v.fail(path, "length "+num(n)+" < minLength "+num(m))
		}
		if m, ok := numOf(s["maxLength"]); ok && n > m {
			v.fail(path, "length "+num(n)+" > maxLength "+num(m))
		}
		if p, ok := s["pattern"].(string); ok {
			re, err := regexp.Compile(p)
			if err != nil {
				v.fail(path, "bad pattern "+strconv.Quote(p))
			} else if !re.MatchString(str) {
				v.fail(path, "does not match pattern "+p)
			}
		}
		if f, ok := s["format"].(string); ok {
			if msg := checkFormat(f, str); msg != "" {
				v.fail(path, msg)
			}
		}
	}
	if arr, ok := data.([]any); ok {
		n := float64(len(arr))
		if m, ok := numOf(s["minItems"]); ok && n < m {
			v.fail(path, num(n)+" items < minItems "+num(m))
		}
		if m, ok := numOf(s["maxItems"]); ok && n > m {
			v.fail(path, num(n)+" items > maxItems "+num(m))
		}
		if u, ok := s["uniqueItems"].(bool); ok && u {
			seen := map[string]bool{}
			for i, x := range arr {
				k := sio.Compact(x)
				if seen[k] {
					v.fail(path+"/"+strconv.Itoa(i), "duplicate item")
				}
				seen[k] = true
			}
		}
		prefix, _ := s["prefixItems"].([]any)
		for i, x := range arr {
			ip := path + "/" + strconv.Itoa(i)
			if i < len(prefix) {
				v.check(prefix[i], x, ip)
				continue
			}
			items, ok := s["items"]
			if !ok {
				continue
			}
			if list, isList := items.([]any); isList { // draft-7 tuple form
				if i < len(list) {
					v.check(list[i], x, ip)
				} else if add, ok := s["additionalItems"]; ok {
					v.check(add, x, ip)
				}
				continue
			}
			v.check(items, x, ip)
		}
	}
	if obj, ok := data.(map[string]any); ok {
		n := float64(len(obj))
		if m, ok := numOf(s["minProperties"]); ok && n < m {
			v.fail(path, num(n)+" properties < minProperties "+num(m))
		}
		if m, ok := numOf(s["maxProperties"]); ok && n > m {
			v.fail(path, num(n)+" properties > maxProperties "+num(m))
		}
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if rs, ok := r.(string); ok {
					if _, has := obj[rs]; !has {
						v.fail(path, "missing required property "+strconv.Quote(rs))
					}
				}
			}
		}
		props, _ := s["properties"].(map[string]any)
		patterns, _ := s["patternProperties"].(map[string]any)
		for _, k := range sortedKeys(obj) {
			covered := false
			if ps, ok := props[k]; ok {
				v.check(ps, obj[k], path+"/"+k)
				covered = true
			}
			for _, pat := range sortedKeys(patterns) {
				if re, err := regexp.Compile(pat); err == nil && re.MatchString(k) {
					v.check(patterns[pat], obj[k], path+"/"+k)
					covered = true
				}
			}
			if covered {
				continue
			}
			switch add := s["additionalProperties"].(type) {
			case bool:
				if !add {
					v.fail(path+"/"+k, "additional property not allowed")
				}
			case map[string]any:
				v.check(add, obj[k], path+"/"+k)
			}
		}
	}
	if all, ok := s["allOf"].([]any); ok {
		for _, sub := range all {
			v.check(sub, data, path)
		}
	}
	if anyOf, ok := s["anyOf"].([]any); ok {
		pass := false
		for _, sub := range anyOf {
			if v.probe(sub, data, path) {
				pass = true
				break
			}
		}
		if !pass {
			v.fail(path, "matches none of anyOf")
		}
	}
	if one, ok := s["oneOf"].([]any); ok {
		n := 0
		for _, sub := range one {
			if v.probe(sub, data, path) {
				n++
			}
		}
		if n != 1 {
			v.fail(path, "matches "+strconv.Itoa(n)+" of oneOf, want exactly 1")
		}
	}
	if not, ok := s["not"]; ok && v.probe(not, data, path) {
		v.fail(path, "matches the not schema")
	}
	if cond, ok := s["if"]; ok {
		if v.probe(cond, data, path) {
			if then, ok := s["then"]; ok {
				v.check(then, data, path)
			}
		} else if els, ok := s["else"]; ok {
			v.check(els, data, path)
		}
	}
}

var (
	emailRe    = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	uuidRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hostnameRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
	uriRe      = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:\S+$`)
)

func checkFormat(f, s string) string {
	ok := true
	switch f {
	case "email":
		ok = emailRe.MatchString(s)
	case "uuid":
		ok = uuidRe.MatchString(s)
	case "hostname":
		ok = hostnameRe.MatchString(s)
	case "uri", "url":
		ok = uriRe.MatchString(s)
	case "date-time":
		_, err := time.Parse(time.RFC3339, s)
		ok = err == nil
	case "date":
		_, err := time.Parse("2006-01-02", s)
		ok = err == nil
	case "time":
		_, err := time.Parse("15:04:05Z07:00", s)
		if err != nil {
			_, err = time.Parse("15:04:05", s)
		}
		ok = err == nil
	case "ipv4":
		a, err := netip.ParseAddr(s)
		ok = err == nil && a.Is4()
	case "ipv6":
		a, err := netip.ParseAddr(s)
		ok = err == nil && a.Is6()
	default:
		return ""
	}
	if !ok {
		return "not a valid " + f
	}
	return ""
}

func main() {
	in := sio.Read()
	m, ok := sio.Object(in)
	if !ok {
		sio.Fail(`input must be {"schema": {...}, "data": ...}`)
	}
	schema, ok := m["schema"]
	if !ok {
		sio.Fail("schema required")
	}
	v := &validator{root: schema}
	v.check(schema, m["data"], "$")
	if len(v.fails) == 0 {
		sio.Outln("valid")
		return
	}
	sio.Outln("invalid " + strconv.Itoa(len(v.fails)))
	for _, f := range v.fails {
		sio.Outln(f.path + ": " + f.msg)
	}
}
