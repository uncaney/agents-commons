// cx-semver: semantic version arithmetic. Text protocol, one command per input:
//
//	compare A B          -> -1 | 0 | 1
//	satisfies V RANGE    -> true | false   (^ ~ >= > <= < = x/* wildcards, "a b" AND, "||" OR)
//	valid V              -> true | false
//	parse V              -> {"major","minor","patch","prerelease","build"}
//	sort V...            -> one version per line, ascending
//	max RANGE V...       -> the highest version satisfying RANGE (or "none")
//
// JSON form: {"op":"compare","args":["1.2.0","1.10.0"]}.
package main

import (
	"sort"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

type ver struct {
	major, minor, patch int
	pre                 []string
	build               string
}

func isIdentChars(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func digits(s string) (int, bool) {
	if s == "" || len(s) > 9 {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, _ := strconv.Atoi(s)
	return n, true
}

// parse reads [v]MAJOR.MINOR.PATCH[-pre][+build].
func parse(s string) (ver, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	v := ver{}
	if core, build, ok := strings.Cut(s, "+"); ok {
		if !isIdentChars(build) {
			return v, false
		}
		v.build, s = build, core
	}
	if core, pre, ok := strings.Cut(s, "-"); ok {
		if !isIdentChars(pre) {
			return v, false
		}
		v.pre, s = strings.Split(pre, "."), core
		for _, p := range v.pre {
			if p == "" {
				return v, false
			}
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false
	}
	var ok1, ok2, ok3 bool
	v.major, ok1 = digits(parts[0])
	v.minor, ok2 = digits(parts[1])
	v.patch, ok3 = digits(parts[2])
	return v, ok1 && ok2 && ok3
}

func (v ver) String() string {
	s := strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor) + "." + strconv.Itoa(v.patch)
	if len(v.pre) > 0 {
		s += "-" + strings.Join(v.pre, ".")
	}
	if v.build != "" {
		s += "+" + v.build
	}
	return s
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// compare orders two versions per semver 2.0 (build metadata ignored).
func compare(a, b ver) int {
	if c := cmpInt(a.major, b.major); c != 0 {
		return c
	}
	if c := cmpInt(a.minor, b.minor); c != 0 {
		return c
	}
	if c := cmpInt(a.patch, b.patch); c != 0 {
		return c
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xi, xok := digits(x)
		yi, yok := digits(y)
		switch {
		case xok && yok:
			if c := cmpInt(xi, yi); c != 0 {
				return c
			}
		case xok:
			return -1
		case yok:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpInt(len(a.pre), len(b.pre))
}

// comparator is one bound of a range.
type comparator struct {
	op string
	v  ver
}

func (c comparator) ok(v ver) bool {
	d := compare(v, c.v)
	switch c.op {
	case ">":
		return d > 0
	case ">=":
		return d >= 0
	case "<":
		return d < 0
	case "<=":
		return d <= 0
	}
	return d == 0
}

// parseRange turns a node-style range into alternatives of AND-ed comparators.
func parseRange(s string) ([][]comparator, bool) {
	var alts [][]comparator
	for _, alt := range strings.Split(s, "||") {
		var set []comparator
		fields := strings.Fields(strings.TrimSpace(alt))
		if len(fields) == 0 {
			fields = []string{"*"}
		}
		for i := 0; i < len(fields); i++ {
			f := fields[i]
			if i+2 < len(fields) && fields[i+1] == "-" { // hyphen range
				lo, ok1 := parse(f)
				hi, ok2 := parse(fields[i+2])
				if !ok1 || !ok2 {
					return nil, false
				}
				set = append(set, comparator{">=", lo}, comparator{"<=", hi})
				i += 2
				continue
			}
			cs, ok := parseComparator(f)
			if !ok {
				return nil, false
			}
			set = append(set, cs...)
		}
		alts = append(alts, set)
	}
	return alts, true
}

func wild(s string) bool { return s == "" || s == "x" || s == "X" || s == "*" }

// parseComparator expands one token: an operator plus a (possibly partial) version, or a bare
// partial version (1.2 means >=1.2.0 <1.3.0; 1.x likewise; * everything).
func parseComparator(tok string) ([]comparator, bool) {
	op := ""
	for _, p := range []string{">=", "<=", ">", "<", "=", "^", "~"} {
		if strings.HasPrefix(tok, p) {
			op, tok = p, strings.TrimPrefix(tok, p)
			break
		}
	}
	tok = strings.TrimPrefix(strings.TrimSpace(tok), "v")
	var pre []string
	if core, p, ok := strings.Cut(tok, "-"); ok {
		if !isIdentChars(p) {
			return nil, false
		}
		pre, tok = strings.Split(p, "."), core
	}
	parts := strings.Split(tok, ".")
	if len(parts) > 3 {
		return nil, false
	}
	for len(parts) < 3 {
		parts = append(parts, "")
	}
	for _, p := range parts {
		if _, ok := digits(p); !ok && !wild(p) {
			return nil, false
		}
	}
	num := func(s string) int { n, _ := digits(s); return n }
	lo := ver{pre: pre}
	switch {
	case wild(parts[0]):
		if op == "" || op == ">=" || op == "^" || op == "~" {
			return nil, true // any version
		}
		return []comparator{{op, ver{}}}, true
	case wild(parts[1]):
		lo.major = num(parts[0])
		if op == "" || op == "^" || op == "~" || op == "=" {
			return []comparator{{">=", lo}, {"<", ver{major: lo.major + 1}}}, true
		}
		return []comparator{{op, lo}}, true
	case wild(parts[2]):
		lo.major, lo.minor = num(parts[0]), num(parts[1])
		switch op {
		case "", "~", "=":
			return []comparator{{">=", lo}, {"<", ver{major: lo.major, minor: lo.minor + 1}}}, true
		case "^":
			if lo.major == 0 {
				return []comparator{{">=", lo}, {"<", ver{major: 0, minor: lo.minor + 1}}}, true
			}
			return []comparator{{">=", lo}, {"<", ver{major: lo.major + 1}}}, true
		}
		return []comparator{{op, lo}}, true
	}
	lo.major, lo.minor, lo.patch = num(parts[0]), num(parts[1]), num(parts[2])
	switch op {
	case "", "=":
		return []comparator{{"=", lo}}, true
	case "~":
		return []comparator{{">=", lo}, {"<", ver{major: lo.major, minor: lo.minor + 1}}}, true
	case "^":
		switch {
		case lo.major > 0:
			return []comparator{{">=", lo}, {"<", ver{major: lo.major + 1}}}, true
		case lo.minor > 0:
			return []comparator{{">=", lo}, {"<", ver{minor: lo.minor + 1}}}, true
		}
		return []comparator{{">=", lo}, {"<", ver{patch: lo.patch + 1}}}, true
	}
	return []comparator{{op, lo}}, true
}

// satisfies applies the node rule that prerelease versions only match comparators naming a
// prerelease of the same major.minor.patch.
func satisfies(v ver, alts [][]comparator) bool {
	for _, set := range alts {
		ok := true
		for _, c := range set {
			if !c.ok(v) {
				ok = false
				break
			}
		}
		if ok && len(v.pre) > 0 {
			ok = false
			for _, c := range set {
				if len(c.v.pre) > 0 && c.v.major == v.major && c.v.minor == v.minor && c.v.patch == v.patch {
					ok = true
				}
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func mustParse(s string) ver {
	v, ok := parse(s)
	if !ok {
		sio.Fail("invalid version " + strconv.Quote(s))
	}
	return v
}

func main() {
	in := sio.Read()
	var op string
	var args []string
	if m, ok := sio.Object(in); ok {
		op, args = sio.Str(m, "op"), sio.Strs(m, "args")
	} else {
		line, _ := sio.Line(in)
		f := strings.Fields(line)
		if len(f) == 0 {
			sio.Fail("usage: compare A B | satisfies V RANGE | valid V | parse V | sort V... | max RANGE V...")
		}
		op, args = f[0], f[1:]
	}
	switch op {
	case "compare":
		if len(args) != 2 {
			sio.Fail("compare needs two versions")
		}
		sio.Outln(strconv.Itoa(compare(mustParse(args[0]), mustParse(args[1]))))
	case "satisfies":
		if len(args) < 2 {
			sio.Fail("satisfies needs a version and a range")
		}
		alts, ok := parseRange(strings.Join(args[1:], " "))
		if !ok {
			sio.Fail("invalid range " + strconv.Quote(strings.Join(args[1:], " ")))
		}
		sio.Outln(strconv.FormatBool(satisfies(mustParse(args[0]), alts)))
	case "valid":
		if len(args) != 1 {
			sio.Fail("valid needs one version")
		}
		_, ok := parse(args[0])
		sio.Outln(strconv.FormatBool(ok))
	case "parse":
		if len(args) != 1 {
			sio.Fail("parse needs one version")
		}
		v := mustParse(args[0])
		sio.Outln(sio.Compact(map[string]any{"major": v.major, "minor": v.minor, "patch": v.patch, "prerelease": strings.Join(v.pre, "."), "build": v.build}))
	case "sort":
		vs := make([]ver, 0, len(args))
		for _, a := range args {
			vs = append(vs, mustParse(a))
		}
		sort.SliceStable(vs, func(i, j int) bool { return compare(vs[i], vs[j]) < 0 })
		for _, v := range vs {
			sio.Outln(v.String())
		}
	case "max":
		if len(args) < 2 {
			sio.Fail("max needs a range and versions")
		}
		alts, ok := parseRange(args[0])
		if !ok {
			sio.Fail("invalid range " + strconv.Quote(args[0]))
		}
		var best *ver
		for _, a := range args[1:] {
			v := mustParse(a)
			if satisfies(v, alts) && (best == nil || compare(v, *best) > 0) {
				vv := v
				best = &vv
			}
		}
		if best == nil {
			sio.Outln("none")
		} else {
			sio.Outln(best.String())
		}
	default:
		sio.Fail("unknown command " + strconv.Quote(op))
	}
}
