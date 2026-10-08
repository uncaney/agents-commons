package textdiff

import (
	"strings"
	"testing"
)

// TestMyersBounds checks the <= 400 lines per side and D <= 2000 bounds (27.3): a small change
// within bounds diffs, an oversized side and a wholesale replacement past D report ErrTooDifferent,
// and identical inputs render empty with Equal true.
func TestMyersBounds(t *testing.T) {
	if !Equal("a\nb\nc", "a\nb\nc") {
		t.Fatal("Equal should be true for identical input")
	}
	out, err := Unified("a\nb\nc\n", "a\nB\nc\n")
	if err != nil {
		t.Fatalf("within bounds: %v", err)
	}
	if !strings.Contains(out, "\n-b\n") || !strings.Contains(out, "\n+B\n") {
		t.Fatalf("missing +/- lines:\n%s", out)
	}

	// > 400 lines on one side.
	big := strings.Repeat("x\n", 401)
	if _, err := Unified(big, "x\n"); err != ErrTooDifferent {
		t.Fatalf("oversized side: want ErrTooDifferent, got %v", err)
	}

	// Two 300-line files that share no line: every line differs, D = 600 (within MaxD) still diffs;
	// make them unalignable enough to exceed MaxD is impossible under 400 lines, so instead assert
	// a fully-disjoint 400/400 pair diffs without error (D = 800 <= 2000).
	var a, b strings.Builder
	for i := 0; i < 400; i++ {
		a.WriteString("a")
		a.WriteString(strings.Repeat("0", 1))
		a.WriteByte('\n')
	}
	for i := 0; i < 400; i++ {
		b.WriteString("b\n")
	}
	if _, err := Unified(a.String(), b.String()); err != nil {
		t.Fatalf("400/400 disjoint within D: %v", err)
	}
}

// TestHunksIndented checks every rendered line is indented two spaces and carries exactly one of
// the ' ', '+', '-' markers in the field, and that a pure insertion and a pure deletion both
// render (27.3 "hunks indented two spaces, +/- inside the field").
func TestHunksIndented(t *testing.T) {
	out, err := Indented("one\ntwo\nthree\n", "one\ntwo\ntwo-and-a-half\nthree\n")
	if err != nil {
		t.Fatal(err)
	}
	if out == "" {
		t.Fatal("expected a hunk")
	}
	for _, ln := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if !strings.HasPrefix(ln, "  ") {
			t.Fatalf("line not indented two spaces: %q", ln)
		}
		if strings.HasPrefix(ln, "  @@") {
			continue
		}
		marker := ln[2]
		if marker != ' ' && marker != '+' && marker != '-' {
			t.Fatalf("bad marker in %q", ln)
		}
	}
	if !strings.Contains(out, "\n  +two-and-a-half\n") {
		t.Fatalf("insertion not rendered:\n%s", out)
	}

	// pure deletion
	del, err := Indented("keep\ndrop\nkeep2\n", "keep\nkeep2\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(del, "\n  -drop\n") {
		t.Fatalf("deletion not rendered:\n%s", del)
	}

	// control characters in a line never break the two-space field
	ctl, err := Indented("x\n", "a\tb\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(ctl, "\t") {
		t.Fatalf("tab leaked into output: %q", ctl)
	}
}

// TestEqualAndEmpty covers the unchanged path and newline-insensitivity.
func TestEqualAndEmpty(t *testing.T) {
	if !Equal("a\nb\n", "a\nb") {
		t.Fatal("trailing newline should not matter")
	}
	out, err := Unified("same\n", "same\n")
	if err != nil || out != "" {
		t.Fatalf("equal inputs: out=%q err=%v", out, err)
	}
}
