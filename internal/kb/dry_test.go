package kb

import (
	"context"
	"strings"
	"testing"
)

// countTables returns the row counts of the content tables a dry run must not touch.
func countTables(t *testing.T) map[string]int {
	t.Helper()
	ctx := context.Background()
	out := map[string]int{}
	for _, tbl := range []string{"kb", "kb_votes", "kb_versions", "kb_revisions", "kb_tombstones", "wanted"} {
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM `+tbl).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		out[tbl] = n
	}
	return out
}

func TestDryRunVerdictNoRows(t *testing.T) {
	e := newTraceEnv(t)
	_, tok := e.registerL(t, uniqName(), 2)

	// An existing entry to collide with in the dup case.
	dupTitle := uniq("quux frobnicator panics on cold startup")
	dupID := e.seedFix(t, dupTitle, "the frobnicator panics on a cold startup", "warm it first")

	before := countTables(t)

	// 1) A clean, unique post would be accepted.
	okTitle := uniq("totally novel widget alignment drift")
	st, body, _ := e.do(t, "POST", "/v1/kb/dry", tok, map[string]any{
		"kind": "fix", "title": okTitle, "symptom": "the widget drifts out of alignment", "fix": "recalibrate"})
	if st != 200 {
		t.Fatalf("dry ok: %d %s", st, body)
	}
	if !strings.HasPrefix(first(body), "dry: would ok") {
		t.Errorf("verdict = %q, want would ok", first(body))
	}
	for _, want := range []string{"masked=", "hazard=", "quota kb ", "flags:"} {
		if !strings.Contains(body, want) {
			t.Errorf("dry reply missing %q:\n%s", want, body)
		}
	}

	// 2) A near-duplicate is flagged (code dup, dup=<id>, a similarity).
	st, body, _ = e.do(t, "POST", "/v1/kb/dry", tok, map[string]any{
		"kind": "fix", "title": dupTitle, "symptom": "the frobnicator panics on a cold startup", "fix": "warm it"})
	if st != 200 {
		t.Fatalf("dry dup: %d %s", st, body)
	}
	if !strings.Contains(body, "would err dup") || !strings.Contains(body, "dup="+dupID) || !strings.Contains(body, "sim=") {
		t.Errorf("dup verdict = %q (dupID %s)", first(body), dupID)
	}

	// 3) A tier-1 secret in a field rejects (code scrub); the secret never appears in the reply.
	const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"
	st, body, _ = e.do(t, "POST", "/v1/kb/dry", tok, map[string]any{
		"kind": "fix", "title": uniq("leaky config"), "symptom": "set bearer " + jwt + " in env", "fix": "rotate"})
	if st != 200 {
		t.Fatalf("dry scrub: %d %s", st, body)
	}
	if !strings.Contains(body, "would err scrub") {
		t.Errorf("scrub verdict = %q", first(body))
	}
	if strings.Contains(body, jwt) {
		t.Errorf("secret leaked in dry reply:\n%s", body)
	}

	// 4) A tier-2 PII value is masked but the post would still be accepted.
	st, body, _ = e.do(t, "POST", "/v1/kb/dry", tok, map[string]any{
		"kind": "fix", "title": uniq("contact drift"), "symptom": "ping ops@example.com when it drifts", "fix": "page them"})
	if st != 200 {
		t.Fatalf("dry mask: %d %s", st, body)
	}
	if !strings.Contains(body, "masked=email") {
		t.Errorf("mask verdict = %q, want masked=email", first(body))
	}

	// No content table changed across any of the dry runs.
	after := countTables(t)
	for tbl, n := range before {
		if after[tbl] != n {
			t.Errorf("table %s row count changed: %d -> %d (dry run persisted)", tbl, n, after[tbl])
		}
	}
}
