package diff3

import "testing"

// TestDiff3Cases runs the classic three-way merge cases: disjoint edits merge cleanly, an edit on
// one side alone is taken, an identical edit on both sides is not a conflict, and adjacent divergent
// edits produce an explicit <<< ours / >>> upstream hunk.
func TestDiff3Cases(t *testing.T) {
	cases := []struct {
		name               string
		base, ours, theirs string
		want               string
		conflict           bool
	}{
		{
			name:   "disjoint edits merge clean",
			base:   "a\nb\nc\nd\ne",
			ours:   "a\nB\nc\nd\ne",
			theirs: "a\nb\nc\nD\ne",
			want:   "a\nB\nc\nD\ne",
		},
		{
			name:   "only ours changed",
			base:   "a\nb\nc",
			ours:   "a\nX\nc",
			theirs: "a\nb\nc",
			want:   "a\nX\nc",
		},
		{
			name:   "only upstream changed",
			base:   "a\nb\nc",
			ours:   "a\nb\nc",
			theirs: "a\nZ\nc",
			want:   "a\nZ\nc",
		},
		{
			name:   "same edit both sides is not a conflict",
			base:   "a\nb\nc",
			ours:   "a\nQ\nc",
			theirs: "a\nQ\nc",
			want:   "a\nQ\nc",
		},
		{
			name:   "upstream insertion is taken",
			base:   "a\nc",
			ours:   "a\nc",
			theirs: "a\nb\nc",
			want:   "a\nb\nc",
		},
		{
			name:     "divergent edit on the same line conflicts",
			base:     "a\nb\nc",
			ours:     "a\nMINE\nc",
			theirs:   "a\nUP\nc",
			want:     "a\n<<< ours\nMINE\n===\nUP\n>>> upstream\nc",
			conflict: true,
		},
		{
			name:     "adjacent divergent edits conflict as one hunk",
			base:     "a\nb\nc",
			ours:     "a\nB\nc",
			theirs:   "a\nb\nC",
			want:     "a\n<<< ours\nB\nc\n===\nb\nC\n>>> upstream",
			conflict: true,
		},
		{
			name:   "empty base with identical additions",
			base:   "",
			ours:   "x\ny",
			theirs: "x\ny",
			want:   "x\ny",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, conflict := MergeText(c.base, c.ours, c.theirs)
			if got != c.want {
				t.Errorf("merge text:\n got %q\nwant %q", got, c.want)
			}
			if conflict != c.conflict {
				t.Errorf("conflict = %v, want %v", conflict, c.conflict)
			}
		})
	}
}

// TestMergeIdentityNoConflict: identical documents merge to themselves with no conflict.
func TestMergeIdentityNoConflict(t *testing.T) {
	doc := "one\ntwo\nthree"
	got, conflict := MergeText(doc, doc, doc)
	if got != doc || conflict {
		t.Fatalf("identity merge got %q conflict %v", got, conflict)
	}
}
