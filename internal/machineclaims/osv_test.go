package machineclaims

import (
	"context"
	"encoding/json"
	"testing"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/know"
)

// TestOSVQueryBatchFromValidatedKeys: the querybatch is built only from validated keys and the
// versions already in libs.versions, mapping the ecosystem to its OSV name and dropping junk.
func TestOSVQueryBatchFromValidatedKeys(t *testing.T) {
	qs := osvQueries("pypi:requests", []know.Release{{V: "2.30.0"}, {V: "2.31.0"}, {V: "bad version"}, {V: "2.30.0"}})
	if len(qs) != 2 {
		t.Fatalf("queries = %d (%+v), want 2 (junk and dup dropped)", len(qs), qs)
	}
	for _, q := range qs {
		if q.Lib != "pypi:requests" || q.Eco != "PyPI" || q.Name != "requests" {
			t.Fatalf("query %+v", q)
		}
	}
	// An ecosystem OSV does not index yields nothing.
	if q := osvQueries("docker:node", []know.Release{{V: "20"}}); len(q) != 0 {
		t.Fatalf("docker queries = %+v, want none", q)
	}

	// End to end through EnqueueOSV: a referenced lib with versions is enqueued, a bare one is not.
	d := newDeps(t)
	seedLib(t, d, "pypi:requests", true, []know.Release{{V: "2.30.0"}, {V: "2.31.0"}})
	seedLib(t, d, "pypi:lonely", false, []know.Release{{V: "1.0.0"}}) // not referenced, not seeded
	if err := EnqueueOSV(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if n := countEgress(t, "osv"); n != 1 {
		t.Fatalf("osv jobs = %d, want 1 (only the referenced lib)", n)
	}
	var payload []byte
	if err := testPool.QueryRow(context.Background(), `SELECT payload FROM egress_outbox WHERE kind = 'osv'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var p osvPayload
	if err := json.Unmarshal(payload, &p); err != nil || len(p.Queries) != 2 || p.Queries[0].Lib != "pypi:requests" {
		t.Fatalf("osv payload %s err=%v", payload, err)
	}
	// A second pass inside the weekly window re-enqueues nothing.
	if err := EnqueueOSV(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if n := countEgress(t, "osv"); n != 1 {
		t.Fatalf("osv jobs after second pass = %d, want 1", n)
	}
}

// TestIngestOSVRanges: an osv ack becomes a verified security claim with the affected range as its
// version span and the osv.dev permalink as its source, and a lib with no vulns is still marked
// fetched. Re-ingesting the same id is idempotent.
func TestIngestOSVRanges(t *testing.T) {
	d := newDeps(t)
	payload := osvPayload{Queries: []osvQuery{
		{Lib: "pypi:requests", Eco: "PyPI", Name: "requests", Version: "2.30.0"},
		{Lib: "pypi:safe", Eco: "PyPI", Name: "safe", Version: "9.9.9"},
	}}
	result := osvResult{Items: []osvItem{{
		Lib: "pypi:requests", V: "2.30.0", Vulns: []osvVuln{{
			ID: "GHSA-j8r2-6x86-q33q", Summary: "Unintended leak of Proxy-Authorization header",
			Details: "requests leaks the header on redirect",
			Affected: []osvAffected{{
				Package: osvPkg{Ecosystem: "PyPI", Name: "requests"},
				Ranges:  []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}, {Fixed: "2.31.0"}}}},
			}},
		}},
	}}}
	ingest(t, d, "osv", payload, result)

	id, vfrom, vto, title, src, status, srcKind, tier, state := claimRow(t, d, "pypi:requests", "security")
	if status != "verified" || srcKind != "machine" || tier != "official" || state != "ok" {
		t.Fatalf("claim status/src/tier/state = %s/%s/%s/%s", status, srcKind, tier, state)
	}
	if vfrom != "" || vto != "2.31.0" {
		t.Fatalf("range = %q->%q, want ->2.31.0 (introduced 0 drops)", vfrom, vto)
	}
	if src != "https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q" {
		t.Fatalf("source_url = %q", src)
	}
	if title[:4] != "GHSA" {
		t.Fatalf("title = %q", title)
	}
	_ = id

	// Both queried libs are marked fetched (the clean one too, so it is not re-enqueued at once).
	for _, lib := range []string{"pypi:requests", "pypi:safe"} {
		var fetched bool
		if err := testPool.QueryRow(context.Background(), `SELECT fetched_at IS NOT NULL FROM machine_state WHERE kind='osv' AND key=$1`, lib).Scan(&fetched); err != nil || !fetched {
			t.Fatalf("machine_state osv %s fetched=%v err=%v", lib, fetched, err)
		}
	}

	// Idempotent re-ingest: still one security row.
	ingest(t, d, "osv", payload, result)
	if n := countClaims(t, d, "pypi:requests", "security"); n != 1 {
		t.Fatalf("security claims after re-ingest = %d, want 1", n)
	}

	// A bad OSV id is dropped silently (no claim, no error).
	bad := osvResult{Items: []osvItem{{Lib: "pypi:requests", V: "2.30.0", Vulns: []osvVuln{{ID: "../../etc/passwd", Summary: "x",
		Affected: []osvAffected{{Package: osvPkg{Name: "requests"}, Ranges: []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "2.31.0"}}}}}}}}}}}
	ingest(t, d, "osv", payload, bad)
	if n := countClaims(t, d, "pypi:requests", "security"); n != 1 {
		t.Fatalf("bad-id ingest added a claim: %d", n)
	}
}

// TestMachineClaimsNoRepAndVerified: machine claims are written verified by the system root and the
// system root neither gains nor logs reputation.
func TestMachineClaimsNoRepAndVerified(t *testing.T) {
	d := newDeps(t)
	payload := osvPayload{Queries: []osvQuery{{Lib: "npm:lodash", Eco: "npm", Name: "lodash", Version: "4.17.0"}}}
	result := osvResult{Items: []osvItem{{Lib: "npm:lodash", V: "4.17.0", Vulns: []osvVuln{{
		ID: "GHSA-p6mc-m468-83gw", Summary: "Prototype pollution in lodash",
		Affected: []osvAffected{{Package: osvPkg{Ecosystem: "npm", Name: "lodash"},
			Ranges: []osvRange{{Type: "SEMVER", Events: []osvEvent{{Introduced: "0"}, {Fixed: "4.17.19"}}}}}},
	}}}}}
	ingest(t, d, "osv", payload, result)

	_, _, vto, _, _, status, _, _, _ := claimRow(t, d, "npm:lodash", "security")
	if status != "verified" || vto != "4.17.19" {
		t.Fatalf("status/vto = %s/%s", status, vto)
	}
	var rep, logs int
	testPool.QueryRow(context.Background(), `SELECT rep FROM identities WHERE id = $1`, core.SystemID).Scan(&rep)
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM rep_log WHERE root = $1`, core.SystemID).Scan(&logs)
	if rep != 0 || logs != 0 {
		t.Fatalf("system root rep=%d rep_log=%d, want 0/0", rep, logs)
	}
}
