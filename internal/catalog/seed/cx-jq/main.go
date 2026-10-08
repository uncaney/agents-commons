// cx-jq: a jq subset over one JSON document. JSON form {"q":".a[0].b","json":{...}} (or
// "in":"<json text>", "raw":true for unquoted strings); text form: the query on the first line,
// the document after it. Supported: . .key ."key" .[n] .[-n] .[a:b] .[] pipes | commas ,
// literals, [f] and {k: f, k2} construction, // alternative, == != < <= > >= and or not,
// + - * /, select(f) map(f) map_values(f) has(k) keys length type add reverse sort sort_by
// unique unique_by group_by min max min_by max_by first last tostring tonumber tojson fromjson
// to_entries from_entries flatten join(s) split(s) ascii_downcase ascii_upcase ltrimstr(s)
// rtrimstr(s) startswith(s) endswith(s) contains(x) floor ceil round abs any all range(n) empty
// recurse (..) values. Results print one per line as compact JSON (object keys sorted).
package main

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

// --- lexer ----------------------------------------------------------------------------------------

type tok struct {
	kind string // id num str op field end
	val  string
	num  float64
}

func isIdent(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

var ops = []string{"//", "==", "!=", "<=", ">=", "|", ",", ".", "[", "]", "(", ")", "{", "}", ":", ";", "<", ">", "+", "-", "*", "/", "?"}

func lex(s string) ([]tok, error) {
	var toks []tok
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '.' && i+1 < len(s) && s[i+1] == '.':
			toks = append(toks, tok{kind: "op", val: ".."})
			i += 2
		case c == '.' && i+1 < len(s) && isIdent(s[i+1]) && !isDigit(s[i+1]):
			j := i + 1
			for j < len(s) && isIdent(s[j]) {
				j++
			}
			toks = append(toks, tok{kind: "field", val: s[i+1 : j]})
			i = j
		case c == '.' && i+1 < len(s) && s[i+1] == '"':
			str, j, err := lexString(s, i+1)
			if err != nil {
				return nil, err
			}
			toks = append(toks, tok{kind: "field", val: str})
			i = j
		case c == '"':
			str, j, err := lexString(s, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, tok{kind: "str", val: str})
			i = j
		case isDigit(c):
			j := i
			for j < len(s) && (isDigit(s[j]) || s[j] == '.' || s[j] == 'e' || s[j] == 'E') {
				j++
			}
			f, err := strconv.ParseFloat(s[i:j], 64)
			if err != nil {
				return nil, errors.New("bad number " + strconv.Quote(s[i:j]))
			}
			toks = append(toks, tok{kind: "num", num: f, val: s[i:j]})
			i = j
		case isIdent(c):
			j := i
			for j < len(s) && isIdent(s[j]) {
				j++
			}
			toks = append(toks, tok{kind: "id", val: s[i:j]})
			i = j
		default:
			matched := false
			for _, op := range ops {
				if strings.HasPrefix(s[i:], op) {
					toks = append(toks, tok{kind: "op", val: op})
					i += len(op)
					matched = true
					break
				}
			}
			if !matched {
				return nil, errors.New("unexpected " + strconv.Quote(string(c)) + " at " + strconv.Itoa(i))
			}
		}
	}
	return append(toks, tok{kind: "end"}), nil
}

func lexString(s string, i int) (string, int, error) {
	j := i + 1
	for j < len(s) {
		if s[j] == '\\' {
			j += 2
			continue
		}
		if s[j] == '"' {
			v, err := sio.Parse(s[i : j+1])
			if err != nil {
				return "", 0, errors.New("bad string literal")
			}
			return v.(string), j + 1, nil
		}
		j++
	}
	return "", 0, errors.New("unterminated string")
}

// --- parser (Pratt) -------------------------------------------------------------------------------

type node struct {
	kind string // identity field index slice iter recurse lit pipe comma bin alt array object call neg
	s    string
	v    any
	a, b *node
	args []*node
	keys []objKey
	opt  bool
}

type objKey struct {
	key string
	k   *node // computed key
	val *node
}

type parser struct {
	toks []tok
	i    int
}

func (p *parser) peek() tok { return p.toks[p.i] }
func (p *parser) next() tok { t := p.toks[p.i]; p.i++; return t }

func (p *parser) isOp(val string) bool { t := p.peek(); return t.kind == "op" && t.val == val }

func (p *parser) expect(val string) error {
	t := p.next()
	if t.kind != "op" || t.val != val {
		return errors.New("expected " + strconv.Quote(val) + ", got " + strconv.Quote(t.val))
	}
	return nil
}

var binPrec = map[string]int{"|": 1, ",": 2, "//": 3, "or": 4, "and": 5, "==": 6, "!=": 6, "<": 6, "<=": 6, ">": 6, ">=": 6, "+": 7, "-": 7, "*": 8, "/": 8}

func (p *parser) parse(minPrec int) (*node, error) {
	left, err := p.postfix()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		op := t.val
		if t.kind != "op" && !(t.kind == "id" && (op == "and" || op == "or")) {
			return left, nil
		}
		prec, ok := binPrec[op]
		if !ok || prec < minPrec {
			return left, nil
		}
		p.next()
		right, err := p.parse(prec + 1)
		if err != nil {
			return nil, err
		}
		switch op {
		case "|":
			left = &node{kind: "pipe", a: left, b: right}
		case ",":
			left = &node{kind: "comma", a: left, b: right}
		case "//":
			left = &node{kind: "alt", a: left, b: right}
		default:
			left = &node{kind: "bin", s: op, a: left, b: right}
		}
	}
}

func (p *parser) postfix() (*node, error) {
	n, err := p.primary()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		switch {
		case t.kind == "field":
			p.next()
			n = &node{kind: "field", s: t.val, a: n}
		case p.isOp("["):
			p.next()
			if p.isOp("]") {
				p.next()
				n = &node{kind: "iter", a: n}
				continue
			}
			var lo, hi *node
			if !p.isOp(":") {
				if lo, err = p.parse(1); err != nil {
					return nil, err
				}
			}
			if p.isOp(":") {
				p.next()
				if !p.isOp("]") {
					if hi, err = p.parse(1); err != nil {
						return nil, err
					}
				}
				if err := p.expect("]"); err != nil {
					return nil, err
				}
				n = &node{kind: "slice", a: n, args: []*node{lo, hi}}
				continue
			}
			if err := p.expect("]"); err != nil {
				return nil, err
			}
			n = &node{kind: "index", a: n, b: lo}
		case p.isOp("?"):
			p.next()
			n.opt = true
		case p.isOp(".") && p.toks[p.i+1].kind == "op" && p.toks[p.i+1].val == "[":
			p.next()
		default:
			return n, nil
		}
	}
}

func (p *parser) primary() (*node, error) {
	t := p.next()
	switch t.kind {
	case "field":
		return &node{kind: "field", s: t.val, a: &node{kind: "identity"}}, nil
	case "num":
		return &node{kind: "lit", v: t.num}, nil
	case "str":
		return &node{kind: "lit", v: t.val}, nil
	case "id":
		switch t.val {
		case "true":
			return &node{kind: "lit", v: true}, nil
		case "false":
			return &node{kind: "lit", v: false}, nil
		case "null":
			return &node{kind: "lit", v: nil}, nil
		}
		call := &node{kind: "call", s: t.val}
		if p.isOp("(") {
			p.next()
			for {
				arg, err := p.parse(1)
				if err != nil {
					return nil, err
				}
				call.args = append(call.args, arg)
				if p.isOp(";") {
					p.next()
					continue
				}
				break
			}
			if err := p.expect(")"); err != nil {
				return nil, err
			}
		}
		return call, nil
	case "op":
		switch t.val {
		case ".":
			return &node{kind: "identity"}, nil
		case "..":
			return &node{kind: "recurse"}, nil
		case "-":
			n, err := p.postfix()
			if err != nil {
				return nil, err
			}
			return &node{kind: "neg", a: n}, nil
		case "(":
			n, err := p.parse(1)
			if err != nil {
				return nil, err
			}
			return n, p.expect(")")
		case "[":
			if p.isOp("]") {
				p.next()
				return &node{kind: "array"}, nil
			}
			n, err := p.parse(1)
			if err != nil {
				return nil, err
			}
			return &node{kind: "array", a: n}, p.expect("]")
		case "{":
			obj := &node{kind: "object"}
			for !p.isOp("}") {
				var k objKey
				kt := p.next()
				switch {
				case kt.kind == "id" || kt.kind == "str":
					k.key = kt.val
				case kt.kind == "field":
					k.key = kt.val
					k.val = &node{kind: "field", s: kt.val, a: &node{kind: "identity"}}
				case kt.kind == "op" && kt.val == "(":
					kn, err := p.parse(1)
					if err != nil {
						return nil, err
					}
					if err := p.expect(")"); err != nil {
						return nil, err
					}
					k.k = kn
				default:
					return nil, errors.New("bad object key " + strconv.Quote(kt.val))
				}
				if p.isOp(":") {
					p.next()
					v, err := p.parse(3)
					if err != nil {
						return nil, err
					}
					k.val = v
				} else if k.val == nil {
					k.val = &node{kind: "field", s: k.key, a: &node{kind: "identity"}}
				}
				obj.keys = append(obj.keys, k)
				if p.isOp(",") {
					p.next()
				}
			}
			p.next()
			return obj, nil
		}
	}
	return nil, errors.New("unexpected token " + strconv.Quote(t.val))
}

// --- evaluation -----------------------------------------------------------------------------------

type evalErr struct{ msg string }

func (e evalErr) Error() string { return e.msg }

func fail(msg string) { panic(evalErr{msg}) }

func typeOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
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

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	}
	return true
}

func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// eval returns the stream of outputs of n applied to v.
func eval(n *node, v any) []any {
	switch n.kind {
	case "identity":
		return []any{v}
	case "lit":
		return []any{n.v}
	case "recurse":
		var out []any
		var walk func(any)
		walk = func(x any) {
			out = append(out, x)
			switch t := x.(type) {
			case []any:
				for _, e := range t {
					walk(e)
				}
			case map[string]any:
				for _, k := range keysOf(t) {
					walk(t[k])
				}
			}
		}
		walk(v)
		return out
	case "field":
		var out []any
		for _, x := range eval(n.a, v) {
			switch t := x.(type) {
			case nil:
				out = append(out, nil)
			case map[string]any:
				out = append(out, t[n.s])
			default:
				if n.opt {
					continue
				}
				fail("cannot index " + typeOf(x) + " with " + strconv.Quote(n.s))
			}
		}
		return out
	case "index":
		var out []any
		for _, x := range eval(n.a, v) {
			for _, idx := range eval(n.b, v) {
				switch t := x.(type) {
				case nil:
					out = append(out, nil)
				case []any:
					f, ok := idx.(float64)
					if !ok {
						if n.opt {
							continue
						}
						fail("array index must be a number")
					}
					i := int(f)
					if i < 0 {
						i += len(t)
					}
					if i < 0 || i >= len(t) {
						out = append(out, nil)
					} else {
						out = append(out, t[i])
					}
				case map[string]any:
					k, ok := idx.(string)
					if !ok {
						if n.opt {
							continue
						}
						fail("object index must be a string")
					}
					out = append(out, t[k])
				default:
					if n.opt {
						continue
					}
					fail("cannot index " + typeOf(x))
				}
			}
		}
		return out
	case "slice":
		var out []any
		for _, x := range eval(n.a, v) {
			lo, hi := 0, -1
			if n.args[0] != nil {
				lo = int(num(eval1(n.args[0], v)))
			}
			if n.args[1] != nil {
				hi = int(num(eval1(n.args[1], v)))
			}
			switch t := x.(type) {
			case nil:
				out = append(out, nil)
			case []any:
				a, b := bounds(lo, hi, len(t), n.args[1] == nil)
				out = append(out, append([]any{}, t[a:b]...))
			case string:
				r := []rune(t)
				a, b := bounds(lo, hi, len(r), n.args[1] == nil)
				out = append(out, string(r[a:b]))
			default:
				fail("cannot slice " + typeOf(x))
			}
		}
		return out
	case "iter":
		var out []any
		for _, x := range eval(n.a, v) {
			switch t := x.(type) {
			case []any:
				out = append(out, t...)
			case map[string]any:
				for _, k := range keysOf(t) {
					out = append(out, t[k])
				}
			default:
				if n.opt {
					continue
				}
				fail("cannot iterate over " + typeOf(x))
			}
		}
		return out
	case "pipe":
		var out []any
		for _, x := range eval(n.a, v) {
			out = append(out, eval(n.b, x)...)
		}
		return out
	case "comma":
		return append(eval(n.a, v), eval(n.b, v)...)
	case "alt":
		var out []any
		for _, x := range evalSafe(n.a, v) {
			if truthy(x) {
				out = append(out, x)
			}
		}
		if len(out) == 0 {
			return eval(n.b, v)
		}
		return out
	case "neg":
		var out []any
		for _, x := range eval(n.a, v) {
			out = append(out, -num(x))
		}
		return out
	case "array":
		if n.a == nil {
			return []any{[]any{}}
		}
		return []any{append([]any{}, eval(n.a, v)...)}
	case "object":
		results := []map[string]any{{}}
		for _, k := range n.keys {
			var keys []string
			if k.k != nil {
				for _, kv := range eval(k.k, v) {
					s, ok := kv.(string)
					if !ok {
						fail("object key must be a string")
					}
					keys = append(keys, s)
				}
			} else {
				keys = []string{k.key}
			}
			vals := eval(k.val, v)
			var next []map[string]any
			for _, r := range results {
				for _, key := range keys {
					for _, val := range vals {
						m := make(map[string]any, len(r)+1)
						for kk, vv := range r {
							m[kk] = vv
						}
						m[key] = val
						next = append(next, m)
					}
				}
			}
			results = next
		}
		out := make([]any, len(results))
		for i, r := range results {
			out[i] = r
		}
		return out
	case "bin":
		var out []any
		for _, r := range eval(n.b, v) {
			for _, l := range eval(n.a, v) {
				out = append(out, binop(n.s, l, r))
			}
		}
		return out
	case "call":
		return call(n, v)
	}
	fail("unknown node " + n.kind)
	return nil
}

func evalSafe(n *node, v any) (out []any) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(evalErr); !ok {
				panic(r)
			}
			out = nil
		}
	}()
	return eval(n, v)
}

func eval1(n *node, v any) any {
	r := eval(n, v)
	if len(r) == 0 {
		fail("expression produced no value")
	}
	return r[0]
}

func bounds(lo, hi, n int, open bool) (int, int) {
	if lo < 0 {
		lo += n
	}
	if open {
		hi = n
	} else if hi < 0 {
		hi += n
	}
	lo = max(0, min(lo, n))
	hi = max(lo, min(hi, n))
	return lo, hi
}

func num(v any) float64 {
	f, ok := v.(float64)
	if !ok {
		fail(typeOf(v) + " is not a number")
	}
	return f
}

var typeOrder = map[string]int{"null": 0, "boolean": 1, "number": 2, "string": 3, "array": 4, "object": 5}

func compare(a, b any) int {
	ta, tb := typeOf(a), typeOf(b)
	if ta != tb {
		return cmp(typeOrder[ta], typeOrder[tb])
	}
	switch x := a.(type) {
	case nil:
		return 0
	case bool:
		y := b.(bool)
		switch {
		case x == y:
			return 0
		case !x:
			return -1
		}
		return 1
	case float64:
		y := b.(float64)
		switch {
		case x < y:
			return -1
		case x > y:
			return 1
		}
		return 0
	case string:
		return strings.Compare(x, b.(string))
	case []any:
		y := b.([]any)
		for i := 0; i < len(x) && i < len(y); i++ {
			if c := compare(x[i], y[i]); c != 0 {
				return c
			}
		}
		return cmp(len(x), len(y))
	case map[string]any:
		y := b.(map[string]any)
		kx, ky := keysOf(x), keysOf(y)
		if c := compare(toAny(kx), toAny(ky)); c != 0 {
			return c
		}
		for _, k := range kx {
			if c := compare(x[k], y[k]); c != 0 {
				return c
			}
		}
		return 0
	}
	return 0
}

func cmp(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func binop(op string, l, r any) any {
	switch op {
	case "==":
		return compare(l, r) == 0
	case "!=":
		return compare(l, r) != 0
	case "<":
		return compare(l, r) < 0
	case "<=":
		return compare(l, r) <= 0
	case ">":
		return compare(l, r) > 0
	case ">=":
		return compare(l, r) >= 0
	case "and":
		return truthy(l) && truthy(r)
	case "or":
		return truthy(l) || truthy(r)
	case "+":
		switch x := l.(type) {
		case nil:
			return r
		case float64:
			if r == nil {
				return x
			}
			return x + num(r)
		case string:
			if r == nil {
				return x
			}
			y, ok := r.(string)
			if !ok {
				fail("cannot add string and " + typeOf(r))
			}
			return x + y
		case []any:
			if r == nil {
				return x
			}
			y, ok := r.([]any)
			if !ok {
				fail("cannot add array and " + typeOf(r))
			}
			return append(append([]any{}, x...), y...)
		case map[string]any:
			if r == nil {
				return x
			}
			y, ok := r.(map[string]any)
			if !ok {
				fail("cannot add object and " + typeOf(r))
			}
			m := map[string]any{}
			for k, v := range x {
				m[k] = v
			}
			for k, v := range y {
				m[k] = v
			}
			return m
		}
		fail("cannot add " + typeOf(l) + " and " + typeOf(r))
	case "-":
		if xa, ok := l.([]any); ok {
			ya, ok := r.([]any)
			if !ok {
				fail("cannot subtract " + typeOf(r) + " from array")
			}
			out := []any{}
			for _, e := range xa {
				keep := true
				for _, f := range ya {
					if compare(e, f) == 0 {
						keep = false
					}
				}
				if keep {
					out = append(out, e)
				}
			}
			return out
		}
		return num(l) - num(r)
	case "*":
		if s, ok := l.(string); ok {
			k := int(num(r))
			if k <= 0 {
				return nil
			}
			return strings.Repeat(s, k)
		}
		return num(l) * num(r)
	case "/":
		if s, ok := l.(string); ok {
			return toAny(strings.Split(s, str(r)))
		}
		d := num(r)
		if d == 0 {
			fail("division by zero")
		}
		return num(l) / d
	}
	fail("unknown operator " + op)
	return nil
}

func str(v any) string {
	s, ok := v.(string)
	if !ok {
		fail(typeOf(v) + " is not a string")
	}
	return s
}

func argStr(n *node, i int, v any) string {
	if len(n.args) <= i {
		fail(n.s + " needs an argument")
	}
	return str(eval1(n.args[i], v))
}

func arrayOf(v any, fn string) []any {
	arr, ok := v.([]any)
	if !ok {
		fail(fn + " needs an array")
	}
	return arr
}

func call(n *node, v any) []any {
	switch n.s {
	case "empty":
		return nil
	case "not":
		return []any{!truthy(v)}
	case "length":
		switch t := v.(type) {
		case nil:
			return []any{0.0}
		case bool:
			fail("boolean has no length")
		case float64:
			return []any{math.Abs(t)}
		case string:
			return []any{float64(len([]rune(t)))}
		case []any:
			return []any{float64(len(t))}
		case map[string]any:
			return []any{float64(len(t))}
		}
	case "type":
		return []any{typeOf(v)}
	case "keys":
		switch t := v.(type) {
		case map[string]any:
			return []any{toAny(keysOf(t))}
		case []any:
			out := make([]any, len(t))
			for i := range t {
				out[i] = float64(i)
			}
			return []any{out}
		}
		fail(typeOf(v) + " has no keys")
	case "values":
		if v == nil {
			return nil
		}
		return []any{v}
	case "has":
		k := eval1(n.args[0], v)
		switch t := v.(type) {
		case map[string]any:
			_, ok := t[str(k)]
			return []any{ok}
		case []any:
			i := int(num(k))
			return []any{i >= 0 && i < len(t)}
		}
		fail("cannot check has on " + typeOf(v))
	case "add":
		var acc any
		for _, e := range arrayOf(v, "add") {
			acc = binop("+", acc, e)
		}
		return []any{acc}
	case "reverse":
		switch t := v.(type) {
		case []any:
			out := make([]any, len(t))
			for i, e := range t {
				out[len(t)-1-i] = e
			}
			return []any{out}
		case string:
			r := []rune(t)
			for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
				r[i], r[j] = r[j], r[i]
			}
			return []any{string(r)}
		}
		fail("cannot reverse " + typeOf(v))
	case "first", "last":
		arr := arrayOf(v, n.s)
		if len(arr) == 0 {
			return []any{nil}
		}
		if n.s == "first" {
			return []any{arr[0]}
		}
		return []any{arr[len(arr)-1]}
	case "flatten":
		out := []any{}
		var walk func([]any)
		walk = func(a []any) {
			for _, e := range a {
				if sub, ok := e.([]any); ok {
					walk(sub)
				} else {
					out = append(out, e)
				}
			}
		}
		walk(arrayOf(v, "flatten"))
		return []any{out}
	case "sort", "unique", "min", "max", "sort_by", "min_by", "max_by", "unique_by", "group_by":
		arr := arrayOf(v, n.s)
		key := func(e any) any { return e }
		if strings.HasSuffix(n.s, "_by") {
			key = func(e any) any { return eval1(n.args[0], e) }
		}
		sorted := append([]any{}, arr...)
		sort.SliceStable(sorted, func(i, j int) bool { return compare(key(sorted[i]), key(sorted[j])) < 0 })
		switch n.s {
		case "sort", "sort_by":
			return []any{sorted}
		case "min", "min_by":
			if len(sorted) == 0 {
				return []any{nil}
			}
			return []any{sorted[0]}
		case "max", "max_by":
			if len(sorted) == 0 {
				return []any{nil}
			}
			return []any{sorted[len(sorted)-1]}
		case "group_by":
			groups := []any{}
			for i := 0; i < len(sorted); {
				j := i
				for j < len(sorted) && compare(key(sorted[i]), key(sorted[j])) == 0 {
					j++
				}
				groups = append(groups, append([]any{}, sorted[i:j]...))
				i = j
			}
			return []any{groups}
		}
		out := []any{}
		for i, e := range sorted {
			if i == 0 || compare(key(sorted[i-1]), key(e)) != 0 {
				out = append(out, e)
			}
		}
		return []any{out}
	case "select":
		var out []any
		for _, c := range eval(n.args[0], v) {
			if truthy(c) {
				out = append(out, v)
			}
		}
		return out
	case "map":
		out := []any{}
		for _, e := range arrayOf(v, "map") {
			out = append(out, eval(n.args[0], e)...)
		}
		return []any{out}
	case "map_values":
		m, ok := v.(map[string]any)
		if !ok {
			fail("map_values needs an object")
		}
		out := map[string]any{}
		for k, e := range m {
			if r := eval(n.args[0], e); len(r) > 0 {
				out[k] = r[0]
			}
		}
		return []any{out}
	case "to_entries":
		m, ok := v.(map[string]any)
		if !ok {
			fail("to_entries needs an object")
		}
		out := []any{}
		for _, k := range keysOf(m) {
			out = append(out, map[string]any{"key": k, "value": m[k]})
		}
		return []any{out}
	case "from_entries":
		out := map[string]any{}
		for _, e := range arrayOf(v, "from_entries") {
			m, ok := e.(map[string]any)
			if !ok {
				fail("from_entries needs objects")
			}
			k := m["key"]
			if k == nil {
				k = m["name"]
			}
			if k == nil {
				k = m["k"]
			}
			val := m["value"]
			if val == nil {
				val = m["v"]
			}
			ks, ok := k.(string)
			if !ok {
				ks = sio.Compact(k)
			}
			out[ks] = val
		}
		return []any{out}
	case "tostring":
		if s, ok := v.(string); ok {
			return []any{s}
		}
		return []any{sio.Compact(v)}
	case "tojson":
		return []any{sio.Compact(v)}
	case "fromjson":
		out, err := sio.Parse(str(v))
		if err != nil {
			fail("fromjson: " + err.Error())
		}
		return []any{out}
	case "tonumber":
		switch t := v.(type) {
		case float64:
			return []any{t}
		case string:
			f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
			if err != nil {
				fail("cannot parse " + strconv.Quote(t) + " as number")
			}
			return []any{f}
		}
		fail("cannot convert " + typeOf(v) + " to number")
	case "join":
		arr := arrayOf(v, "join")
		sep := argStr(n, 0, v)
		parts := make([]string, len(arr))
		for i, e := range arr {
			switch t := e.(type) {
			case nil:
				parts[i] = ""
			case string:
				parts[i] = t
			default:
				parts[i] = sio.Compact(e)
			}
		}
		return []any{strings.Join(parts, sep)}
	case "split":
		return []any{toAny(strings.Split(str(v), argStr(n, 0, v)))}
	case "ascii_downcase":
		return []any{strings.ToLower(str(v))}
	case "ascii_upcase":
		return []any{strings.ToUpper(str(v))}
	case "ltrimstr":
		return []any{strings.TrimPrefix(str(v), argStr(n, 0, v))}
	case "rtrimstr":
		return []any{strings.TrimSuffix(str(v), argStr(n, 0, v))}
	case "startswith":
		return []any{strings.HasPrefix(str(v), argStr(n, 0, v))}
	case "endswith":
		return []any{strings.HasSuffix(str(v), argStr(n, 0, v))}
	case "contains":
		switch t := v.(type) {
		case string:
			return []any{strings.Contains(t, argStr(n, 0, v))}
		case []any:
			want, _ := eval1(n.args[0], v).([]any)
			for _, w := range want {
				found := false
				for _, e := range t {
					if compare(e, w) == 0 {
						found = true
					}
				}
				if !found {
					return []any{false}
				}
			}
			return []any{true}
		}
		fail("contains on " + typeOf(v))
	case "floor":
		return []any{math.Floor(num(v))}
	case "ceil":
		return []any{math.Ceil(num(v))}
	case "round":
		return []any{math.Round(num(v))}
	case "abs":
		return []any{math.Abs(num(v))}
	case "recurse":
		return eval(&node{kind: "recurse"}, v)
	case "any":
		for _, e := range arrayOf(v, "any") {
			if truthy(e) {
				return []any{true}
			}
		}
		return []any{false}
	case "all":
		for _, e := range arrayOf(v, "all") {
			if !truthy(e) {
				return []any{false}
			}
		}
		return []any{true}
	case "range":
		hi := int(num(eval1(n.args[0], v)))
		out := []any{}
		for i := 0; i < hi && i < 100000; i++ {
			out = append(out, float64(i))
		}
		return out
	case "ascii", "implode", "explode", "test", "match", "env", "input", "inputs", "now", "debug", "limit", "until", "while", "reduce", "foreach", "def":
		fail(n.s + " is not supported by cx-jq")
	}
	fail("unknown function " + n.s)
	return nil
}

// --- main -----------------------------------------------------------------------------------------

func render(v any) string {
	if f, ok := v.(float64); ok {
		return sio.Number(f)
	}
	return sio.Compact(v)
}

func main() {
	in := sio.Read()
	var q string
	var document any
	raw := false
	if m, ok := sio.Object(in); ok {
		q, raw = sio.Str(m, "q"), sio.Bool(m, "raw")
		if d, ok := m["json"]; ok {
			document = d
		} else {
			text := sio.Str(m, "in")
			if strings.TrimSpace(text) == "" {
				text = "null"
			}
			var err error
			if document, err = sio.Parse(text); err != nil {
				sio.Fail("bad json document: " + err.Error())
			}
		}
	} else {
		var text string
		q, text = sio.Line(in)
		if strings.TrimSpace(text) == "" {
			text = "null"
		}
		var err error
		if document, err = sio.Parse(text); err != nil {
			sio.Fail("bad json document: " + err.Error())
		}
	}
	q = strings.TrimSpace(q)
	if q == "" {
		q = "."
	}
	toks, err := lex(q)
	if err != nil {
		sio.Fail("query: " + err.Error())
	}
	p := &parser{toks: toks}
	ast, err := p.parse(1)
	if err != nil {
		sio.Fail("query: " + err.Error())
	}
	if p.peek().kind != "end" {
		sio.Fail("query: unexpected " + strconv.Quote(p.peek().val))
	}
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(evalErr); ok {
				sio.Fail(e.msg)
			}
			panic(r)
		}
	}()
	for _, out := range eval(ast, document) {
		if s, ok := out.(string); ok && raw {
			sio.Outln(s)
			continue
		}
		sio.Outln(render(out))
	}
}
