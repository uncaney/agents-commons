package machineclaims

import (
	"context"
	"strings"
	"testing"
)

// TestIngestEOLCycles: endoflife cycles become verified release claims (always) and eol claims (only
// for a dated/past cycle), each cycle kept distinct by its ?cycle= source URL.
func TestIngestEOLCycles(t *testing.T) {
	d := newDeps(t)
	result := eolResult{Product: "node", Lib: "docker:node", Cycles: []eolCycle{
		{Cycle: "18", ReleaseDate: "2022-04-19", EOL: "2025-04-30", Latest: "18.19.0"},
		{Cycle: "21", ReleaseDate: "2023-10-17", EOL: "", Latest: "21.6.0"}, // not yet eol
	}}
	ingest(t, d, "eol", eolPayload{Product: "node", Lib: "docker:node"}, result)

	// Two release claims (one per cycle), one eol claim (the dated cycle).
	if n := countClaims(t, d, "docker:node", "release"); n != 2 {
		t.Fatalf("release claims = %d, want 2", n)
	}
	if n := countClaims(t, d, "docker:node", "eol"); n != 1 {
		t.Fatalf("eol claims = %d, want 1 (only the dated cycle)", n)
	}
	id, _, vto, title, src, status, srcKind, tier, _ := claimRow(t, d, "docker:node", "eol")
	if status != "verified" || srcKind != "machine" || tier != "official" {
		t.Fatalf("eol claim status/src/tier = %s/%s/%s", status, srcKind, tier)
	}
	if vto != "18.19.0" {
		t.Fatalf("eol vto = %q, want the cycle latest", vto)
	}
	if !strings.Contains(src, "endoflife.date/node") || !strings.Contains(src, "cycle=18") {
		t.Fatalf("eol source_url = %q", src)
	}
	if !strings.Contains(title, "end-of-life") {
		t.Fatalf("eol title = %q", title)
	}
	_ = id

	// The product's lib is marked fetched; re-ingest stays idempotent on (lib, kind, source_url).
	var fetched bool
	if err := testPool.QueryRow(context.Background(), `SELECT fetched_at IS NOT NULL FROM machine_state WHERE kind='eol' AND key='docker:node'`).Scan(&fetched); err != nil || !fetched {
		t.Fatalf("eol machine_state fetched=%v err=%v", fetched, err)
	}
	ingest(t, d, "eol", eolPayload{Product: "node", Lib: "docker:node"}, result)
	if n := countClaims(t, d, "docker:node", "release"); n != 2 {
		t.Fatalf("release claims after re-ingest = %d, want 2", n)
	}

	// An unknown product is a no-op.
	ingest(t, d, "eol", eolPayload{Product: "nope", Lib: "docker:nope"}, eolResult{Product: "nope", Cycles: []eolCycle{{Cycle: "1", ReleaseDate: "2020-01-01"}}})
	if n := countClaims(t, d, "docker:nope", "release"); n != 0 {
		t.Fatalf("unknown product wrote %d claims", n)
	}
}

// TestEnqueueEOLProducts: each tracked product is enqueued once, skipped on a second pass inside the
// weekly window.
func TestEnqueueEOLProducts(t *testing.T) {
	d := newDeps(t)
	if err := EnqueueEOL(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if n := countEgress(t, "eol"); n != len(Products()) {
		t.Fatalf("eol jobs = %d, want %d", n, len(Products()))
	}
	if err := EnqueueEOL(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if n := countEgress(t, "eol"); n != len(Products()) {
		t.Fatalf("eol jobs after second pass = %d, want %d", n, len(Products()))
	}
}
