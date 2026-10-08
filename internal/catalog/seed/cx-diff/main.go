// cx-diff: unified diff of two texts (Myers algorithm, line-based). Input {"a":"...","b":"...",
// "name_a":"a","name_b":"b","context":3}. Output: the unified diff ("--- a", "+++ b", @@ hunks),
// or nothing when the texts are equal. Inputs are capped at 20000 lines each.
package main

import (
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

const maxLines = 20000

type op struct {
	kind byte // ' ' '-' '+'
	text string
}

// splitLines keeps a marker for a missing final newline, as diff(1) does.
func splitLines(s string) ([]string, bool) {
	if s == "" {
		return nil, true
	}
	nl := strings.HasSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n"), nl
}

// myers returns the edit script turning a into b (O((N+M)D) time, bounded by maxLines).
func myers(a, b []string) []op {
	n, m := len(a), len(b)
	max := n + m
	if max == 0 {
		return nil
	}
	v := make([]int, 2*max+2)
	var trace [][]int
	off := max
	var d int
loop:
	for d = 0; d <= max; d++ {
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
				break loop
			}
		}
	}
	var ops []op
	x, y := n, m
	for d = len(trace) - 1; d >= 0; d-- {
		vv := trace[d]
		k := x - y
		var prevK int
		if k == -d || (k != d && vv[off+k-1] < vv[off+k+1]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := vv[off+prevK]
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			x, y = x-1, y-1
			ops = append(ops, op{' ', a[x]})
		}
		if d > 0 {
			if x == prevX {
				y--
				ops = append(ops, op{'+', b[y]})
			} else {
				x--
				ops = append(ops, op{'-', a[x]})
			}
		}
	}
	for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
		ops[i], ops[j] = ops[j], ops[i]
	}
	return ops
}

type hunk struct {
	aStart, aLen, bStart, bLen int
	lines                      []string
}

// hunks groups the edit script into unified hunks with ctx lines of context.
func hunks(ops []op, ctx int, aNL, bNL bool, nA, nB int) []hunk {
	var out []hunk
	i := 0
	aLine, bLine := 0, 0
	for i < len(ops) {
		for i < len(ops) && ops[i].kind == ' ' {
			i, aLine, bLine = i+1, aLine+1, bLine+1
		}
		if i >= len(ops) {
			break
		}
		start := max(0, i-ctx)
		h := hunk{aStart: aLine - (i - start) + 1, bStart: bLine - (i - start) + 1}
		j := i
		for j < len(ops) {
			k := j
			for k < len(ops) && ops[k].kind != ' ' {
				k++
			}
			run := k
			for run < len(ops) && ops[run].kind == ' ' && run-k < 2*ctx {
				run++
			}
			if run < len(ops) && ops[run].kind != ' ' {
				j = run
				continue
			}
			j = min(k+ctx, len(ops))
			break
		}
		for _, o := range ops[start:j] {
			h.lines = append(h.lines, string(o.kind)+o.text)
			switch o.kind {
			case ' ':
				h.aLen, h.bLen = h.aLen+1, h.bLen+1
			case '-':
				h.aLen++
			case '+':
				h.bLen++
			}
		}
		aLine += countKinds(ops[i:j], ' ', '-')
		bLine += countKinds(ops[i:j], ' ', '+')
		out = append(out, h)
		i = j
	}
	for hi := range out {
		h := &out[hi]
		for li := len(h.lines) - 1; li >= 0; li-- {
			l := h.lines[li]
			aEnd := h.aStart+h.aLen-1 == nA && (l[0] == ' ' || l[0] == '-')
			bEnd := h.bStart+h.bLen-1 == nB && (l[0] == ' ' || l[0] == '+')
			if (aEnd && !aNL) || (bEnd && !bNL) {
				if li == len(h.lines)-1 || h.lines[li+1] != "\\ No newline at end of file" {
					h.lines = append(h.lines[:li+1], append([]string{"\\ No newline at end of file"}, h.lines[li+1:]...)...)
				}
			}
			if aEnd || bEnd {
				break
			}
		}
	}
	return out
}

func countKinds(ops []op, kinds ...byte) int {
	n := 0
	for _, o := range ops {
		for _, k := range kinds {
			if o.kind == k {
				n++
			}
		}
	}
	return n
}

func rangeText(start, n int) string {
	if n == 1 {
		return strconv.Itoa(start)
	}
	if n == 0 {
		return strconv.Itoa(start-1) + ",0"
	}
	return strconv.Itoa(start) + "," + strconv.Itoa(n)
}

func main() {
	in := sio.Read()
	m, ok := sio.Object(in)
	if !ok {
		sio.Fail(`input must be {"a":"...","b":"...","name_a":"a","name_b":"b","context":3}`)
	}
	ta, tb := sio.Str(m, "a"), sio.Str(m, "b")
	a, aNL := splitLines(ta)
	b, bNL := splitLines(tb)
	if len(a) > maxLines || len(b) > maxLines {
		sio.Fail("inputs over " + strconv.Itoa(maxLines) + " lines")
	}
	ctx := int(sio.Num(m, "context", 3))
	if ctx <= 0 || ctx > 20 {
		ctx = 3
	}
	nameA, nameB := sio.Str(m, "name_a"), sio.Str(m, "name_b")
	if nameA == "" {
		nameA = "a"
	}
	if nameB == "" {
		nameB = "b"
	}
	if ta == tb {
		return
	}
	hs := hunks(myers(a, b), ctx, aNL, bNL, len(a), len(b))
	var out strings.Builder
	out.WriteString("--- " + nameA + "\n+++ " + nameB + "\n")
	for _, h := range hs {
		out.WriteString("@@ -" + rangeText(h.aStart, h.aLen) + " +" + rangeText(h.bStart, h.bLen) + " @@\n")
		for _, l := range h.lines {
			out.WriteString(l + "\n")
		}
	}
	sio.Out(out.String())
}
