// Package textdiff is the shared line diff behind every delta read (SPEC-v2 27.3): a bounded Myers
// shortest-edit-script over lines with a unified-hunk renderer whose every line is indented two
// spaces so user text can never start a reply line at column zero. The bounds (<= 400 lines per
// side, edit distance D <= 2000) keep one request cheap; past them the caller renders
// "too different" rather than a diff.
package textdiff

import (
	"errors"
	"strconv"
	"strings"
)

// Limits (27.3, mirrors the digest diff of 13.3).
const (
	MaxLines = 400
	MaxD     = 2000
)

// ErrTooDifferent is returned when either side has more than MaxLines lines or the edit distance
// exceeds MaxD. Callers render the string "too different".
var ErrTooDifferent = errors.New("too different")

// kind of one edit.
type kind int

const (
	eq kind = iota
	del
	ins
)

type edit struct {
	k    kind
	line string
}

// splitLines splits s into lines without a trailing empty element from a terminating newline, so
// "a\n" and "a" diff identically (the renderer never shows a phantom blank line).
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

// Equal reports whether a and b are identical line for line (the cheap path for "ok unchanged").
func Equal(a, b string) bool {
	la, lb := splitLines(a), splitLines(b)
	if len(la) != len(lb) {
		return false
	}
	for i := range la {
		if la[i] != lb[i] {
			return false
		}
	}
	return true
}

// script computes the Myers shortest edit script from a to b, bounded by MaxD. It returns the edits
// in source order or ErrTooDifferent.
func script(a, b []string) ([]edit, error) {
	if len(a) > MaxLines || len(b) > MaxLines {
		return nil, ErrTooDifferent
	}
	n, m := len(a), len(b)
	max := n + m
	if max == 0 {
		return nil, nil
	}
	// v holds the furthest-reaching x on each diagonal k; one trace per edit distance d.
	offset := max
	v := make([]int, 2*max+1)
	var trace [][]int
	found := -1
	for d := 0; d <= max && d <= MaxD; d++ {
		snap := make([]int, len(v))
		copy(snap, v)
		trace = append(trace, snap)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[offset+k-1] < v[offset+k+1]) {
				x = v[offset+k+1] // down (insertion)
			} else {
				x = v[offset+k-1] + 1 // right (deletion)
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[offset+k] = x
			if x >= n && y >= m {
				found = d
				break
			}
		}
		if found >= 0 {
			break
		}
	}
	if found < 0 {
		return nil, ErrTooDifferent
	}
	return backtrack(a, b, trace, offset, n, m), nil
}

// backtrack walks the saved traces from the end to the start, emitting edits, then reverses them.
func backtrack(a, b []string, trace [][]int, offset, n, m int) []edit {
	var out []edit
	x, y := n, m
	for d := len(trace) - 1; d > 0; d-- {
		v := trace[d]
		k := x - y
		var prevK int
		if k == -d || (k != d && v[offset+k-1] < v[offset+k+1]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := v[offset+prevK]
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			out = append(out, edit{eq, a[x-1]})
			x--
			y--
		}
		if x == prevX {
			out = append(out, edit{ins, b[y-1]})
		} else {
			out = append(out, edit{del, a[x-1]})
		}
		x, y = prevX, prevY
	}
	for x > 0 && y > 0 { // the d==0 diagonal of leading equal lines
		out = append(out, edit{eq, a[x-1]})
		x--
		y--
	}
	// reverse into source order
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Unified renders a vs b as standard unified-diff hunks (3 lines of context): a "@@ -a,l +b,l @@"
// header per hunk, then one line per edit prefixed by a ' ', '+' or '-' marker. Equal inputs render
// "". Returns ErrTooDifferent past the bounds. The delta package places this inside a reply field,
// where the field's own two-space indent puts every marker "inside the field" (27.3); Indented is
// the standalone two-space-indented form.
func Unified(a, b string) (string, error) {
	return UnifiedContext(a, b, 3)
}

// Indented is Unified with every rendered line prefixed by two spaces, so the hunk is safe to print
// on its own without a line ever starting at column zero (27.3 "every line indented 2 spaces").
func Indented(a, b string) (string, error) {
	u, err := Unified(a, b)
	if err != nil || u == "" {
		return u, err
	}
	var sb strings.Builder
	for _, ln := range strings.Split(strings.TrimRight(u, "\n"), "\n") {
		sb.WriteString("  ")
		sb.WriteString(ln)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// UnifiedContext is Unified with a caller-chosen context width.
func UnifiedContext(a, b string, ctx int) (string, error) {
	la, lb := splitLines(a), splitLines(b)
	ed, err := script(la, lb)
	if err != nil {
		return "", err
	}
	hs := hunks(ed, ctx)
	if len(hs) == 0 {
		return "", nil
	}
	var sb strings.Builder
	for _, h := range hs {
		sb.WriteString("@@ -")
		sb.WriteString(strconv.Itoa(h.aStart))
		sb.WriteByte(',')
		sb.WriteString(strconv.Itoa(h.aLen))
		sb.WriteString(" +")
		sb.WriteString(strconv.Itoa(h.bStart))
		sb.WriteByte(',')
		sb.WriteString(strconv.Itoa(h.bLen))
		sb.WriteString(" @@\n")
		for _, e := range h.edits {
			switch e.k {
			case ins:
				sb.WriteByte('+')
			case del:
				sb.WriteByte('-')
			default:
				sb.WriteByte(' ')
			}
			sb.WriteString(oneLine(e.line))
			sb.WriteByte('\n')
		}
	}
	return sb.String(), nil
}

type hunk struct {
	aStart, aLen, bStart, bLen int
	edits                      []edit
}

// pe is one edit with its 1-based positions in a and b (0 before the first line of a side).
type pe struct {
	e    edit
	aPos int
	bPos int
}

// hunks groups the edit script into unified hunks with up to ctx lines of surrounding equal
// context, dropping runs of equal lines longer than 2*ctx between changes.
func hunks(ed []edit, ctx int) []hunk {
	ps := make([]pe, 0, len(ed))
	ai, bi := 0, 0
	changed := false
	for _, e := range ed {
		switch e.k {
		case eq:
			ai++
			bi++
			ps = append(ps, pe{e, ai, bi})
		case del:
			ai++
			ps = append(ps, pe{e, ai, bi})
			changed = true
		case ins:
			bi++
			ps = append(ps, pe{e, ai, bi})
			changed = true
		}
	}
	if !changed {
		return nil
	}
	keep := make([]bool, len(ps))
	for i, p := range ps {
		if p.e.k == eq {
			continue
		}
		lo := i - ctx
		if lo < 0 {
			lo = 0
		}
		hi := i + ctx
		if hi >= len(ps) {
			hi = len(ps) - 1
		}
		for j := lo; j <= hi; j++ {
			keep[j] = true
		}
	}
	var out []hunk
	i := 0
	for i < len(ps) {
		if !keep[i] {
			i++
			continue
		}
		j := i
		for j < len(ps) && keep[j] {
			j++
		}
		seg := ps[i:j]
		h := hunk{edits: make([]edit, 0, len(seg))}
		h.aStart, h.bStart = max1(seg[0].aPos), max1(seg[0].bPos)
		for _, p := range seg {
			h.edits = append(h.edits, p.e)
			switch p.e.k {
			case eq:
				h.aLen++
				h.bLen++
			case del:
				h.aLen++
			case ins:
				h.bLen++
			}
		}
		out = append(out, h)
		i = j
	}
	return out
}

func max1(n int) int {
	if n < 1 {
		return 1
	}
	return n
}

// oneLine strips control characters so a diffed line can never break the line-oriented wire format.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s)
}
