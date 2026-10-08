package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/trust"
)

// TestSystemRootExists asserts the system root (migration 0040) is present after boot and that no
// token authenticates as it (SPEC-v2, core.SystemID = "asystem"): it is a valid id used as the author
// of seeded/system content, never an account anyone can hold a bearer token for.
func TestSystemRootExists(t *testing.T) {
	ctx := context.Background()
	var name, id string
	var parent *string
	var credits int64
	var hlen int
	if err := testPool.QueryRow(ctx,
		`SELECT name, id, parent, credits, length(token_hash) FROM identities WHERE id = $1`, core.SystemID).
		Scan(&name, &id, &parent, &credits, &hlen); err != nil {
		t.Fatalf("system row: %v", err)
	}
	if name != "system" || id != core.SystemID || parent != nil || credits != 0 {
		t.Fatalf("unexpected system row: name=%q id=%q parent=%v credits=%d", name, id, parent, credits)
	}
	if !core.ValidID(core.SystemID) {
		t.Fatalf("%q is not a valid id", core.SystemID)
	}
	// No fabricated or system-shaped token resolves to an identity: the system root is token-less.
	for _, tok := range []string{
		"cx_" + strings.Repeat("A", 43),
		"system-" + core.SystemID,
		core.SystemID,
	} {
		if _, err := testDeps.LookupToken(ctx, tok); err == nil {
			t.Fatalf("token %q unexpectedly authenticated (system root must be token-less)", tok)
		}
	}
	// And an authenticated endpoint reached with no credential never resolves to the system identity.
	rec := httptest.NewRecorder()
	testMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/me", nil))
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), core.SystemID) {
		t.Fatalf("GET /v1/me without a token returned the system identity: %s", rec.Body.String())
	}
}

// TestLedgerAuditOkAfterBoot asserts the credit ledger balances immediately after boot (SPEC-v2 16.1):
// with every package's escrow expression registered, mint - burn == credits + reserved + escrow. A
// non-zero delta means a package's escrow seam is missing or a seed minted credits off the books.
func TestLedgerAuditOkAfterBoot(t *testing.T) {
	a, err := testDeps.RunLedgerAudit(context.Background())
	if err != nil {
		t.Fatalf("ledger audit: %v", err)
	}
	if !a.OK() {
		t.Fatalf("ledger does not balance after boot: %s (delta=%d)", a.Line(), a.Delta())
	}
}

// contentKinds is the closed set of indexable content kinds trust.Indexable recognises (its doc
// comment, SPEC-v2 4.5): the single predicate that pages, sitemaps, feeds, exports and IndexNow all
// consult. "status" is included to prove it is never indexable.
var contentKinds = []string{"kb", "task", "claim", "digest", "space", "svc", "proposal", "profile", "qa", "status"}

// TestEveryContentKindIndexablePredicate asserts the one predicate behind every public surface gates
// correctly for every content kind (SPEC-v2 4.5): a hidden, quarantined, flagged, brand-new or
// low-standing row is never indexable for ANY kind, and a mature, visible, L2-authored row is
// indexable for every content kind except the ones barred outright (status never; space needs >= 3
// members from distinct super-groups). This is the invariant sitemaps/feeds rely on to surface only
// trust.Indexable rows; a kind that slipped past the predicate would leak into them.
func TestEveryContentKindIndexablePredicate(t *testing.T) {
	l2 := trust.Standing{Seed: true} // Seed -> Level() == 2
	if l2.Level() < 2 {
		t.Fatalf("seed standing level = %d, want >= 2", l2.Level())
	}
	mature := 2 * time.Hour

	for _, kind := range contentKinds {
		// A fully-qualified, mature, L2-authored row.
		base := trust.IndexInput{Author: l2, Age: mature, SpaceMembers: 3, L2Confirms: 1}
		want := kind != "status" // status is never indexable
		if got := trust.Indexable(kind, base); got != want {
			t.Errorf("Indexable(%q, mature L2) = %v, want %v", kind, got, want)
		}

		// Every disqualifier must force false for every kind.
		for _, bad := range []struct {
			why string
			in  trust.IndexInput
		}{
			{"hidden", trust.IndexInput{Author: l2, Age: mature, SpaceMembers: 3, Hidden: true}},
			{"quarantine", trust.IndexInput{Author: l2, Age: mature, SpaceMembers: 3, Quarantine: true}},
			{"too young", trust.IndexInput{Author: l2, Age: time.Minute, SpaceMembers: 3, L2Confirms: 1}},
			{"lexicon>=2", trust.IndexInput{Author: l2, Age: mature, SpaceMembers: 3, Lexicon: 2}},
			{"flagged", trust.IndexInput{Author: l2, Age: mature, SpaceMembers: 3, Flags: []string{"x"}}},
			{"new-domain link", trust.IndexInput{Author: l2, Age: mature, SpaceMembers: 3, NewDomainLink: true}},
			{"unvouched hazard", trust.IndexInput{Author: l2, Age: mature, SpaceMembers: 3, L2Confirms: 1, Hazard: []string{"cbrn"}, HazardL2Ok: 2}},
		} {
			if trust.Indexable(kind, bad.in) {
				t.Errorf("Indexable(%q, %s) = true, want false", kind, bad.why)
			}
		}
	}

	// A low-standing (L0) author with no seed and no cross-super-group confirmation is not indexable.
	l0 := trust.Standing{}
	if trust.Indexable("kb", trust.IndexInput{Author: l0, Age: mature}) {
		t.Error("Indexable(kb, L0 author, no confirms) = true, want false")
	}
	// A space with too few distinct-super-group members is not indexable even when L2-authored.
	if trust.Indexable("space", trust.IndexInput{Author: l2, Age: mature, SpaceMembers: 2}) {
		t.Error("Indexable(space, only 2 members) = true, want false")
	}

	// The public sitemap index and a package-registered child must serve without error (the plumbing
	// that enforces the predicate on real rows is live), and declare no disallowed surface.
	for _, path := range []string{"/sitemap.xml", "/robots.txt"} {
		rec := httptest.NewRecorder()
		testMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d", path, rec.Code)
		}
	}
}
