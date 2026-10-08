package know

import (
	"strings"
)

// Bounded Myers line diff (13.3): <= MaxDiffLines per side and an edit distance <= MaxDiffD,
// otherwise the pages say `too different`. P79's internal/textdiff may replace this later.
const (
	MaxDiffLines = 400
	MaxDiffD     = 2000
)

// LineDiff returns the unified line diff of a and b (lines prefixed ` `, `-`, `+`), ok false when
// a side exceeds MaxDiffLines or the edit distance exceeds MaxDiffD.
func LineDiff(a, b string) (diff string, ok bool) {
	al, bl := splitLines(a), splitLines(b)
	if len(al) > MaxDiffLines || len(bl) > MaxDiffLines {
		return "", false
	}
	ops, ok := myers(al, bl, MaxDiffD)
	if !ok {
		return "", false
	}
	var sb strings.Builder
	changed := false
	for _, o := range ops {
		if o != "" && o[0] != ' ' {
			changed = true
		}
		sb.WriteString(o)
		sb.WriteByte('\n')
	}
	if !changed {
		return "", true // unchanged: no hunk to show
	}
	return strings.TrimRight(sb.String(), "\n"), true
}

func splitLines(s string) []string {
	s = strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// myers is the classic O((N+M)D) greedy algorithm with a D ceiling; it returns the edit script as
// prefixed lines.
func myers(a, b []string, maxD int) ([]string, bool) {
	n, m := len(a), len(b)
	max := n + m
	if max == 0 {
		return nil, true
	}
	if maxD > max {
		maxD = max
	}
	off := maxD + 1
	v := make([]int, 2*off+2)
	var trace [][]int
	for d := 0; d <= maxD; d++ {
		trace = append(trace, append([]int(nil), v...))
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
				x = v[off+k+1]
			} else {
				x = v[off+k-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x, y = x+1, y+1
			}
			v[off+k] = x
			if x >= n && y >= m {
				return backtrack(trace, a, b, off), true
			}
		}
	}
	return nil, false
}

func backtrack(trace [][]int, a, b []string, off int) []string {
	x, y := len(a), len(b)
	var out []string
	for d := len(trace) - 1; d >= 0; d-- {
		v := trace[d]
		k := x - y
		var pk int
		if k == -d || (k != d && v[off+k-1] < v[off+k+1]) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := v[off+pk]
		py := px - pk
		for x > px && y > py {
			x, y = x-1, y-1
			out = append(out, " "+a[x])
		}
		if d > 0 {
			if x == px {
				y--
				out = append(out, "+"+b[y])
			} else {
				x--
				out = append(out, "-"+a[x])
			}
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
