// Package graph is SPEC-v2 27.4 (P95): the interaction graph. A nightly janitor reads the vote,
// review, bounty and tip relations of the last 90 days into a pair-affinity ledger, claws back
// duplicate reputation between the same two parties, flags affinity payouts, damps reciprocal and
// clique votes, scores collusion pairs, and gates confirmer entropy. A daily janitor derives a
// per-root reliability score from live events and the owning tables. Everything here is display or
// anti-collusion only: it never grants reputation, only removes duplicated gains.
package graph

import (
	"context"
	"net/http"

	"ekaii.fr/commons/internal/bounty"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/pages"
	"ekaii.fr/commons/internal/review"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/trust"
)

// svc carries the request/janitor dependencies.
type svc struct{ d *core.Deps }

// Register mounts the reliability HTTP routes, registers the two janitors (nightly vote_graph,
// daily reliability) and wires every cross-package seam the graph owns: the pair-damp and
// confirmer-entropy rules in trust, the collusion exclusion and reliability in review, the
// reliability line in bounty and on claimed tasks, the /a profile lines and the /gov stats lines.
// Idempotent across the several Deps a test builds: the function-pointer seams are simply
// overwritten with the same closures.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}

	routes := []struct {
		pat  string
		h    http.HandlerFunc
		cost float64
	}{
		{"GET /v1/rel/{root}", s.hRel, 1},
		{"GET /v1/me/rel", s.hMeRel, 1},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, "rel")
		if rt.cost != 1 {
			d.RegisterCost(rt.pat, rt.cost)
		}
	}
	sign.RegisterTypes("rel1")

	// Janitors run under the Janitor registry's per-name advisory lock (core.Janitor.locked), so
	// the nightly rebuild never overlaps another instance: that is the "advisory lock" of 27.4.
	d.Janitor.Add("vote_graph", func(ctx context.Context) error { return VoteGraph(ctx, d.DB) })
	d.Janitor.Add("reliability", func(ctx context.Context) error { return Reliability(ctx, d.DB) })

	// trust: the pair-damp multiplier owners apply at vote time, and the cross-kind confirmer
	// entropy rule that replaces trust's built-in kb-only count.
	trust.PairDampFn = PairDamp
	trust.ConfirmerEntropyFn = ConfirmerEntropy

	// review: exclude scored collusion pairs as reviewer/requester, show reviewer reliability.
	review.ExcludeFn = Excluded
	review.RelFn = Rel

	// bounty: creator reliability for ?min_rel=.
	bounty.RelFn = Rel

	// forge: rel= on the claimed line of a task detail.
	forge.ClaimLineFn = ClaimLine

	// pages: confirmers=/nets=/rel= on /a/<id>.
	pages.ProfileExtraFn = append(pages.ProfileExtraFn, RelLines)

	// gov: reciprocal_pairs, cliques, damped_votes_30d, top_pair_share on /gov/stats.
	gov.StatsExtraFn = append(gov.StatsExtraFn, StatsExtra)
}
