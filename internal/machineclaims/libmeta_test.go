package machineclaims

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/know"
)

// TestLibmetaDeprecatedYanked: the libmeta hook turns a registry result into a release claim for the
// latest version, a deprecated claim per npm-deprecated version and a removed claim per yanked
// version.
func TestLibmetaDeprecatedYanked(t *testing.T) {
	d := newDeps(t)
	// npm result: latest 4.17.21, an older deprecated version.
	npm := map[string]any{
		"key": "npm:lodash", "display": "lodash", "latest": "4.17.21", "latest_at": "2021-02-20",
		"versions": []map[string]any{
			{"v": "4.17.21", "at": "2021-02-20"},
			{"v": "3.10.1", "at": "2015-08-01", "deprecated": true},
		},
	}
	meta, _ := json.Marshal(npm)
	if err := LibMetaHook(context.Background(), d.DB, "npm:lodash", meta); err != nil {
		t.Fatal(err)
	}
	if n := countClaims(t, d, "npm:lodash", "release"); n != 1 {
		t.Fatalf("release claims = %d, want 1 (latest)", n)
	}
	if n := countClaims(t, d, "npm:lodash", "deprecated"); n != 1 {
		t.Fatalf("deprecated claims = %d, want 1", n)
	}
	_, _, dvto, _, dsrc, status, srcKind, _, _ := claimRow(t, d, "npm:lodash", "deprecated")
	if dvto != "3.10.1" || status != "verified" || srcKind != "machine" {
		t.Fatalf("deprecated claim vto/status/src = %s/%s/%s", dvto, status, srcKind)
	}
	if !strings.Contains(dsrc, "npmjs.com/package/lodash/v/3.10.1") {
		t.Fatalf("deprecated source_url = %q", dsrc)
	}

	// pypi result: a yanked version becomes a removed claim.
	pypi := map[string]any{
		"key": "pypi:requests", "display": "requests", "latest": "2.31.0", "latest_at": "2023-05-22",
		"versions": []map[string]any{
			{"v": "2.31.0", "at": "2023-05-22"},
			{"v": "2.29.0", "at": "2023-04-26", "yanked": true},
		},
	}
	meta, _ = json.Marshal(pypi)
	if err := LibMetaHook(context.Background(), d.DB, "pypi:requests", meta); err != nil {
		t.Fatal(err)
	}
	if n := countClaims(t, d, "pypi:requests", "removed"); n != 1 {
		t.Fatalf("removed claims = %d, want 1", n)
	}
	_, _, rvto, _, rsrc, _, _, tier, _ := claimRow(t, d, "pypi:requests", "removed")
	if rvto != "2.29.0" || tier != "official" {
		t.Fatalf("removed claim vto/tier = %s/%s", rvto, tier)
	}
	if !strings.Contains(rsrc, "pypi.org/project/requests/2.29.0/") {
		t.Fatalf("removed source_url = %q", rsrc)
	}

	// An errored libmeta result writes nothing.
	meta, _ = json.Marshal(map[string]any{"key": "pypi:gone", "err": "not found"})
	if err := LibMetaHook(context.Background(), d.DB, "pypi:gone", meta); err != nil {
		t.Fatal(err)
	}
	if n := countClaims(t, d, "pypi:gone", "release"); n != 0 {
		t.Fatalf("errored result wrote %d claims", n)
	}
	_ = know.Release{}
}
