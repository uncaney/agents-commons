package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAnchorAppendsWithParentNeverForce(t *testing.T) {
	f := newGHFake(t)
	f.roots = "root1 day=2026-10-06 n=3 root=abcd k=1 sig=zz\nroot1 day=2026-10-07 n=5 root=ef01 k=1 sig=yy\n"
	// anchors already exists, head is an older day's commit so today is not deduped.
	f.refs["heads/anchors"] = "anchorhead"
	f.commits["anchorhead"] = struct{ tree, message string }{tree: "oldtree", message: "anchor 2026-10-06 roots"}
	te := mirrorTestEnv(t, f)
	te.e.Now = func() time.Time { return time.Date(2026, 10, 7, 1, 0, 0, 0, time.UTC) }

	raw, err := runAnchor(context.Background(), te.e, &Job{ID: 1, Kind: "anchor", Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("runAnchor: %v", err)
	}
	var res struct {
		Day      string `json:"day"`
		Anchored bool   `json:"anchored"`
		Commit   string `json:"commit"`
		Parent   string `json:"parent"`
		Created  bool   `json:"created"`
		Ref      string `json:"ref"`
		Bytes    int    `json:"bytes"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	if !res.Anchored || res.Day != "2026-10-07" || res.Parent != "anchorhead" || res.Created || res.Ref != "anchors" || res.Bytes != len(f.roots) {
		t.Fatalf("result %+v", res)
	}

	var commitParents []any
	var treeBase string
	var patchAnchors, patchForce, createRef int
	var blobContent bool
	for _, c := range f.callsCopy() {
		switch {
		case c.method == "POST" && strings.HasSuffix(c.path, "/git/blobs"):
			blobContent = true
		case c.method == "POST" && strings.HasSuffix(c.path, "/git/commits"):
			commitParents, _ = c.body["parents"].([]any)
		case c.method == "POST" && strings.HasSuffix(c.path, "/git/trees"):
			treeBase, _ = c.body["base_tree"].(string)
		case c.method == "PATCH" && strings.HasSuffix(c.path, "/git/refs/heads/anchors"):
			patchAnchors++
			// force must be false or omitted; never a rewrite.
			if force, _ := c.body["force"].(bool); force {
				patchForce++
			}
		case c.method == "POST" && strings.HasSuffix(c.path, "/git/refs"):
			createRef++
		}
	}
	if !blobContent {
		t.Fatal("roots.txt blob was not created")
	}
	if len(commitParents) != 1 || commitParents[0] != "anchorhead" {
		t.Fatalf("commit parents = %v, want [anchorhead]", commitParents)
	}
	if treeBase != "oldtree" {
		t.Fatalf("tree base_tree = %q, want oldtree (append, not rewrite)", treeBase)
	}
	if patchAnchors != 1 {
		t.Fatalf("anchors updates = %d, want 1", patchAnchors)
	}
	if patchForce != 0 {
		t.Fatalf("anchors was force-updated %d times (must never force)", patchForce)
	}
	if createRef != 0 {
		t.Fatalf("create-ref = %d, want 0 (anchors already existed)", createRef)
	}

	// First run creates the anchors branch (no parent, no base_tree).
	f2 := newGHFake(t)
	f2.roots = "root1 day=2026-10-07 n=1 root=aa k=1 sig=xx\n"
	te2 := mirrorTestEnv(t, f2)
	te2.e.Now = func() time.Time { return time.Date(2026, 10, 7, 1, 0, 0, 0, time.UTC) }
	raw, err = runAnchor(context.Background(), te2.e, &Job{ID: 2, Kind: "anchor"})
	if err != nil {
		t.Fatalf("first-run anchor: %v", err)
	}
	json.Unmarshal(raw, &res)
	if !res.Created || res.Parent != "" {
		t.Fatalf("first run: created=%v parent=%q", res.Created, res.Parent)
	}
	var parents2 []any
	var base2 string
	var created2 int
	for _, c := range f2.callsCopy() {
		if c.method == "POST" && strings.HasSuffix(c.path, "/git/commits") {
			parents2, _ = c.body["parents"].([]any)
		}
		if c.method == "POST" && strings.HasSuffix(c.path, "/git/trees") {
			base2, _ = c.body["base_tree"].(string)
		}
		if c.method == "POST" && strings.HasSuffix(c.path, "/git/refs") {
			created2++
		}
	}
	if len(parents2) != 0 || base2 != "" || created2 != 1 {
		t.Fatalf("first run: parents=%v base=%q created=%d", parents2, base2, created2)
	}

	// Re-running the same day is a no-op: the head already carries today's anchor message.
	f3 := newGHFake(t)
	f3.roots = "root1 day=2026-10-07 n=1 root=aa k=1 sig=xx\n"
	f3.refs["heads/anchors"] = "todayhead"
	f3.commits["todayhead"] = struct{ tree, message string }{tree: "t", message: "anchor 2026-10-07 roots"}
	te3 := mirrorTestEnv(t, f3)
	te3.e.Now = func() time.Time { return time.Date(2026, 10, 7, 23, 0, 0, 0, time.UTC) }
	raw, err = runAnchor(context.Background(), te3.e, &Job{ID: 3, Kind: "anchor"})
	if err != nil {
		t.Fatalf("same-day anchor: %v", err)
	}
	var res3 struct {
		Anchored bool `json:"anchored"`
	}
	json.Unmarshal(raw, &res3)
	if res3.Anchored {
		t.Fatal("same-day re-run should not anchor again")
	}
	for _, c := range f3.callsCopy() {
		if c.method == "POST" && strings.Contains(c.path, "/git/commits") {
			t.Fatal("same-day re-run created a commit")
		}
	}
}
