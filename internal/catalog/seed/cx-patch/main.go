// cx-patch: apply a unified diff to a text. Input {"base":"...","diff":"...","reverse":false}.
// Output: the patched text exactly (bytes as given, newline state from the diff markers), or
// "error: hunk N does not apply at line L" with exit status 1. Context must match exactly
// (fuzz 0); hunk offsets are honoured in order; a single-file diff is expected (--- / +++ headers
// optional). Pairs with cx-diff.
package main

import (
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

type hunk struct {
	aStart, aLen, bStart, bLen int
	lines                      []string // with their leading ' ', '-', '+' or '\'
}

func parseRange(s string) (int, int, bool) {
	s = strings.TrimLeft(s, "-+")
	start, n := s, "1"
	if a, b, ok := strings.Cut(s, ","); ok {
		start, n = a, b
	}
	st, err1 := strconv.Atoi(start)
	ln, err2 := strconv.Atoi(n)
	return st, ln, err1 == nil && err2 == nil
}

func parseDiff(d string) ([]hunk, bool) {
	var hunks []hunk
	lines := strings.Split(strings.TrimSuffix(d, "\n"), "\n")
	i := 0
	for i < len(lines) {
		l := lines[i]
		switch {
		case strings.HasPrefix(l, "@@ "):
			f := strings.Fields(l)
			if len(f) < 3 {
				return nil, false
			}
			as, al, ok1 := parseRange(f[1])
			bs, bl, ok2 := parseRange(f[2])
			if !ok1 || !ok2 {
				return nil, false
			}
			h := hunk{aStart: as, aLen: al, bStart: bs, bLen: bl}
			i++
			got := 0
			for i < len(lines) && (got < al || countPlus(h.lines) < bl || strings.HasPrefix(lines[i], "\\")) {
				x := lines[i]
				if x == "" {
					x = " " // a blank context line with the leading space stripped
				}
				switch x[0] {
				case ' ', '-':
					got++
				case '+', '\\':
				default:
					return nil, false
				}
				h.lines = append(h.lines, x)
				i++
				if got >= al && countPlus(h.lines) >= bl && (i >= len(lines) || !strings.HasPrefix(lines[i], "\\")) {
					break
				}
			}
			hunks = append(hunks, h)
		case strings.HasPrefix(l, "--- ") || strings.HasPrefix(l, "+++ ") || strings.HasPrefix(l, "diff ") || strings.HasPrefix(l, "index ") || l == "":
			i++
		default:
			return nil, false
		}
	}
	return hunks, len(hunks) > 0
}

func countPlus(lines []string) int {
	n := 0
	for _, l := range lines {
		if l[0] == '+' || l[0] == ' ' {
			n++
		}
	}
	return n
}

func reverse(hs []hunk) []hunk {
	out := make([]hunk, len(hs))
	for i, h := range hs {
		r := hunk{aStart: h.bStart, aLen: h.bLen, bStart: h.aStart, bLen: h.aLen}
		for _, l := range h.lines {
			switch l[0] {
			case '-':
				r.lines = append(r.lines, "+"+l[1:])
			case '+':
				r.lines = append(r.lines, "-"+l[1:])
			default:
				r.lines = append(r.lines, l)
			}
		}
		out[i] = r
	}
	return out
}

func noApply(h, line int) {
	sio.Fail("hunk " + strconv.Itoa(h) + " does not apply at line " + strconv.Itoa(line))
}

func main() {
	in := sio.Read()
	m, ok := sio.Object(in)
	if !ok {
		sio.Fail(`input must be {"base":"...","diff":"..."}`)
	}
	baseText, diff := sio.Str(m, "base"), sio.Str(m, "diff")
	hs, ok := parseDiff(diff)
	if !ok {
		sio.Fail("cannot parse unified diff")
	}
	if sio.Bool(m, "reverse") {
		hs = reverse(hs)
	}
	baseNL := baseText == "" || strings.HasSuffix(baseText, "\n")
	var base []string
	if baseText != "" {
		base = strings.Split(strings.TrimSuffix(baseText, "\n"), "\n")
	}
	var out []string
	pos := 0 // next base line to copy (0-based)
	outNL := baseNL
	for hi, h := range hs {
		start := h.aStart - 1
		if h.aLen == 0 {
			start = h.aStart // insertion after line aStart
		}
		if start < pos || start > len(base) {
			noApply(hi+1, h.aStart)
		}
		out = append(out, base[pos:start]...)
		cur := start
		for li, l := range h.lines {
			switch l[0] {
			case ' ', '-':
				if cur >= len(base) || base[cur] != l[1:] {
					noApply(hi+1, cur+1)
				}
				if l[0] == ' ' {
					out = append(out, l[1:])
				}
				cur++
			case '+':
				out = append(out, l[1:])
			case '\\':
				// "No newline at end of file" refers to the previous line: the new side when it
				// was a '+' or ' ' line, the old side when it was '-'.
				if li > 0 && (h.lines[li-1][0] == '+' || h.lines[li-1][0] == ' ') && cur >= len(base) {
					outNL = false
				}
				if li > 0 && h.lines[li-1][0] == ' ' && li == len(h.lines)-1 {
					outNL = false
				}
			}
		}
		if h.bLen > 0 && hi == len(hs)-1 && cur >= len(base) && !hasNoNL(h.lines) {
			outNL = true
		}
		pos = cur
	}
	out = append(out, base[pos:]...)
	text := strings.Join(out, "\n")
	if outNL && len(out) > 0 {
		text += "\n"
	}
	sio.Out(text)
}

func hasNoNL(lines []string) bool {
	for _, l := range lines {
		if l[0] == '\\' {
			return true
		}
	}
	return false
}
