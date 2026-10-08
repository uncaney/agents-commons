// cx-regex: RE2 regular expressions. JSON form {"op":"test|match|find|replace|split|explain",
// "re":"...","text":"...","repl":"...","flags":"ims"}; text form: op on line 1, the pattern on
// line 2, the text after. Outputs: test -> true|false; match -> the first match as JSON
// {match,start,end,groups}; find -> JSON array of matches; replace -> the replaced text; split ->
// JSON array; explain -> one line per pattern element.
package main

import (
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

func compile(re, flags string) *regexp.Regexp {
	prefix := ""
	for _, f := range flags {
		switch f {
		case 'i', 'm', 's', 'U':
			prefix += string(f)
		}
	}
	if prefix != "" {
		re = "(?" + prefix + ")" + re
	}
	r, err := regexp.Compile(re)
	if err != nil {
		sio.Fail("bad regex: " + err.Error())
	}
	return r
}

func matchObj(re *regexp.Regexp, text string, idx []int) map[string]any {
	m := map[string]any{"match": text[idx[0]:idx[1]], "start": idx[0], "end": idx[1]}
	groups := map[string]any{}
	list := []any{}
	for i := 1; i < len(idx)/2; i++ {
		var g any
		if idx[2*i] >= 0 {
			g = text[idx[2*i]:idx[2*i+1]]
		}
		list = append(list, g)
		if name := re.SubexpNames()[i]; name != "" {
			groups[name] = g
		}
	}
	m["groups"] = list
	if len(groups) > 0 {
		m["named"] = groups
	}
	return m
}

// explain walks the parsed syntax tree and prints one line per element, indented by depth.
func explain(re string, flags string) []string {
	mode := syntax.Perl
	for _, f := range flags {
		switch f {
		case 'i':
			mode |= syntax.FoldCase
		case 's':
			mode |= syntax.DotNL
		case 'm':
			mode &^= syntax.OneLine
		}
	}
	tree, err := syntax.Parse(re, mode)
	if err != nil {
		sio.Fail("bad regex: " + err.Error())
	}
	var out []string
	var walk func(n *syntax.Regexp, depth int)
	walk = func(n *syntax.Regexp, depth int) {
		pad := strings.Repeat("  ", depth)
		line := func(s string) { out = append(out, pad+s) }
		rep := func(lo, hi int, greedy bool) string {
			s := ""
			switch {
			case hi == -1:
				s = strconv.Itoa(lo) + " or more times"
			case lo == hi:
				s = "exactly " + strconv.Itoa(lo) + " times"
			default:
				s = strconv.Itoa(lo) + " to " + strconv.Itoa(hi) + " times"
			}
			if !greedy {
				s += " (lazy)"
			}
			return s
		}
		switch n.Op {
		case syntax.OpLiteral:
			line("literal " + strconv.Quote(string(n.Rune)))
		case syntax.OpCharClass:
			var parts []string
			for i := 0; i+1 < len(n.Rune); i += 2 {
				if n.Rune[i] == n.Rune[i+1] {
					parts = append(parts, strconv.QuoteRune(n.Rune[i]))
				} else {
					parts = append(parts, strconv.QuoteRune(n.Rune[i])+"-"+strconv.QuoteRune(n.Rune[i+1]))
				}
				if len(parts) == 8 {
					parts = append(parts, "…")
					break
				}
			}
			line("one character of " + strings.Join(parts, " "))
		case syntax.OpAnyCharNotNL:
			line("any character except newline")
		case syntax.OpAnyChar:
			line("any character")
		case syntax.OpBeginLine:
			line("start of line")
		case syntax.OpEndLine:
			line("end of line")
		case syntax.OpBeginText:
			line("start of text")
		case syntax.OpEndText:
			line("end of text")
		case syntax.OpWordBoundary:
			line("word boundary")
		case syntax.OpNoWordBoundary:
			line("not a word boundary")
		case syntax.OpCapture:
			name := "group " + strconv.Itoa(n.Cap)
			if n.Name != "" {
				name += " named " + n.Name
			}
			line("capture " + name + ":")
			for _, s := range n.Sub {
				walk(s, depth+1)
			}
		case syntax.OpStar:
			line("repeat " + rep(0, -1, n.Flags&syntax.NonGreedy == 0) + ":")
			walk(n.Sub[0], depth+1)
		case syntax.OpPlus:
			line("repeat " + rep(1, -1, n.Flags&syntax.NonGreedy == 0) + ":")
			walk(n.Sub[0], depth+1)
		case syntax.OpQuest:
			lazy := ""
			if n.Flags&syntax.NonGreedy != 0 {
				lazy = " (lazy)"
			}
			line("optional" + lazy + ":")
			walk(n.Sub[0], depth+1)
		case syntax.OpRepeat:
			line("repeat " + rep(n.Min, n.Max, n.Flags&syntax.NonGreedy == 0) + ":")
			walk(n.Sub[0], depth+1)
		case syntax.OpConcat:
			for _, s := range n.Sub {
				walk(s, depth)
			}
		case syntax.OpAlternate:
			line("one of:")
			for i, s := range n.Sub {
				out = append(out, pad+"  alternative "+strconv.Itoa(i+1)+":")
				walk(s, depth+2)
			}
		case syntax.OpEmptyMatch:
			line("empty")
		default:
			line(n.Op.String())
		}
	}
	walk(tree, 0)
	return out
}

func main() {
	in := sio.Read()
	var op, re, text, repl, flags string
	if m, ok := sio.Object(in); ok {
		op, re, text, repl, flags = sio.Str(m, "op"), sio.Str(m, "re"), sio.Str(m, "text"), sio.Str(m, "repl"), sio.Str(m, "flags")
	} else {
		var rest string
		op, rest = sio.Line(in)
		re, text = sio.Line([]byte(rest))
		if f := strings.Fields(op); len(f) == 2 {
			op, flags = f[0], f[1]
		}
	}
	if re == "" {
		sio.Fail("usage: test|match|find|replace|split|explain, then the pattern, then the text")
	}
	if op == "explain" {
		for _, l := range explain(re, flags) {
			sio.Outln(l)
		}
		return
	}
	r := compile(re, flags)
	switch op {
	case "test":
		sio.Outln(strconv.FormatBool(r.MatchString(text)))
	case "match":
		idx := r.FindStringSubmatchIndex(text)
		if idx == nil {
			sio.Outln("null")
			return
		}
		sio.Outln(sio.Compact(matchObj(r, text, idx)))
	case "find":
		out := []any{}
		for _, idx := range r.FindAllStringSubmatchIndex(text, 1000) {
			out = append(out, matchObj(r, text, idx))
		}
		sio.Outln(sio.Compact(out))
	case "replace":
		sio.Out(r.ReplaceAllString(text, repl))
	case "split":
		sio.Outln(sio.Compact(r.Split(text, -1)))
	default:
		sio.Fail("unknown op " + strconv.Quote(op))
	}
}
