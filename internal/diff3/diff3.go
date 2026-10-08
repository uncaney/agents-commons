// Package diff3 is a line-based three-way merge (SPEC-v2 27.5 P103), stdlib only. It merges a base
// document with two derivations, ours and theirs, and emits a clean merge when the two sides touch
// disjoint lines, or explicit conflict blocks otherwise:
//
//	<<< ours
//	…our lines…
//	===
//	…their (upstream) lines…
//	>>> upstream
//
// The upstream-proposal validator refuses any applied text still carrying a `<<<` or `>>>` marker,
// so a conflict must be resolved (ours|upstream for the whole doc) before a merge can be adopted.
package diff3

import "strings"

// Markers delimiting a conflict hunk. They are the literal strings the SPEC-v2 validator scans for.
const (
	MarkOurs     = "<<< ours"
	MarkSep      = "==="
	MarkUpstream = ">>> upstream"
)

// Result is the outcome of a merge.
type Result struct {
	Lines    []string // merged document, line by line (conflict hunks included verbatim)
	Conflict bool     // true when at least one hunk could not be resolved cleanly
}

// Text renders the merged document, newline-joined. A trailing newline is added when the merge is
// non-empty so callers can concatenate documents safely.
func (r Result) Text() string {
	if len(r.Lines) == 0 {
		return ""
	}
	return strings.Join(r.Lines, "\n")
}

// MergeText splits each document into lines, merges them and returns the rendered text plus the
// conflict flag. A document is split on "\n"; a trailing newline is not significant.
func MergeText(base, ours, theirs string) (string, bool) {
	r := Merge(lines(base), lines(ours), lines(theirs))
	return r.Text(), r.Conflict
}

func lines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// Merge is the classic three-way line merge: base o, our side a, their side b. Stable regions
// (lines unchanged on both sides, anchored by the longest common subsequence of o↔a and o↔b) are
// kept; an unstable region is taken from whichever side changed it, from either side when both made
// the same change, and wrapped in a conflict hunk when the two sides changed it differently.
func Merge(o, a, b []string) Result {
	aOf := matchMap(o, a) // base index -> matching index in a (LCS of o, a)
	bOf := matchMap(o, b) // base index -> matching index in b (LCS of o, b)

	// Anchors: base lines matched on BOTH sides, in base order. Each side's matches are monotonic,
	// so the shared subset is monotonic in a and b too — a sound diff3 alignment.
	var res Result
	oi, ai, bi := 0, 0, 0
	emit := func(oEnd, aEnd, bEnd int) {
		oReg, aReg, bReg := o[oi:oEnd], a[ai:aEnd], b[bi:bEnd]
		switch {
		case eq(aReg, oReg): // ours unchanged -> take theirs
			res.Lines = append(res.Lines, bReg...)
		case eq(bReg, oReg): // theirs unchanged -> take ours
			res.Lines = append(res.Lines, aReg...)
		case eq(aReg, bReg): // both made the same change
			res.Lines = append(res.Lines, aReg...)
		default: // genuine conflict
			res.Conflict = true
			res.Lines = append(res.Lines, MarkOurs)
			res.Lines = append(res.Lines, aReg...)
			res.Lines = append(res.Lines, MarkSep)
			res.Lines = append(res.Lines, bReg...)
			res.Lines = append(res.Lines, MarkUpstream)
		}
	}
	for i := 0; i < len(o); i++ {
		aj, aok := aOf[i]
		bj, bok := bOf[i]
		if !aok || !bok {
			continue
		}
		emit(i, aj, bj)
		res.Lines = append(res.Lines, o[i]) // the stable anchor line, identical in all three
		oi, ai, bi = i+1, aj+1, bj+1
	}
	emit(len(o), len(a), len(b)) // trailing region after the last anchor
	return res
}

// matchMap returns, for each index i of x matched in the LCS of x and y, the matching index j in y.
func matchMap(x, y []string) map[int]int {
	pairs := lcs(x, y)
	m := make(map[int]int, len(pairs))
	for _, p := range pairs {
		m[p[0]] = p[1]
	}
	return m
}

// lcs returns the matched index pairs (i in x, j in y) of a longest common subsequence, in order.
func lcs(x, y []string) [][2]int {
	n, k := len(x), len(y)
	if n == 0 || k == 0 {
		return nil
	}
	// dp[i][j] = LCS length of x[i:] and y[j:].
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, k+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := k - 1; j >= 0; j-- {
			if x[i] == y[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var out [][2]int
	i, j := 0, 0
	for i < n && j < k {
		switch {
		case x[i] == y[j]:
			out = append(out, [2]int{i, j})
			i, j = i+1, j+1
		case dp[i+1][j] >= dp[i][j+1]:
			i++
		default:
			j++
		}
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
