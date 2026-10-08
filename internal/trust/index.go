package trust

import "time"

// IndexInput is everything the indexability predicate (SPEC-v2 4.5) needs about one item.
type IndexInput struct {
	Author        Standing      // author / creator / publisher / proposer root
	Seed          bool          // seed row (operator notes)
	Quarantine    bool          // 4.4
	Hidden        bool          // not visible (hidden, retracted, expired, archived, frozen)
	Status        bool          // kb kind status (never indexed)
	Lexicon       int           // lexicon score (4.6)
	Flags         []string      // lexicon / provenance flags; must be empty
	Hazard        []string      // hazard families (4.5)
	HazardL2Ok    int           // ok votes from L2 roots (hazard entries need >= 3)
	NewDomainLink bool          // links to a registrable domain first seen on the site
	Age           time.Duration // since creation
	L2Confirms    int           // confirmations by L2 roots from another super-group
	SpaceMembers  int           // spaces: members from distinct super-groups
}

// Indexable is the single predicate pages, sitemaps, feeds, exports and IndexNow consult (4.5):
// visible AND NOT quarantine AND kind <> status AND lexicon < 2 AND flags = {} AND (hazard = {} OR
// L2 ok >= 3) AND no first-seen-domain link AND age >= 1 h AND (author L2 OR seed OR >= 1 L2
// confirmation from another super-group; spaces: creator L2 AND >= 3 members from distinct
// super-groups). kind is one of kb, task, claim, digest, space, svc, proposal, profile, qa.
func Indexable(kind string, in IndexInput) bool {
	if in.Hidden || in.Quarantine || in.Status || kind == "status" {
		return false
	}
	if in.Lexicon >= 2 || len(in.Flags) > 0 || in.NewDomainLink {
		return false
	}
	if len(in.Hazard) > 0 && in.HazardL2Ok < 3 {
		return false
	}
	if in.Age < time.Hour {
		return false
	}
	authorL2 := in.Author.Level() >= 2
	if kind == "space" {
		return authorL2 && in.SpaceMembers >= 3
	}
	return authorL2 || in.Seed || in.L2Confirms >= 1
}
