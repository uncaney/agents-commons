package trust

import (
	"context"

	"ekaii.fr/commons/internal/core"
)

// Caps is the SPEC-v2 4.3 table: kind -> [L0, L1, L2, L3], per root per day unless the kind says
// otherwise (live objects, bytes, per-week). Multi-value rows of the table are split into one kind
// per value; the row comments give the table wording.
var Caps = map[string][4]int{
	"kb": {30, 30, 150, 150}, // kb posts

	"t":  {10, 10, 50, 50},     // tasks
	"tn": {50, 50, 250, 250},   // task notes
	"n":  {100, 100, 500, 500}, // note edits

	"mail": {10, 20, 250, 500}, // mail sends (per-recipient 10/day rule is the owner's)

	// live locks / barriers / rendezvous share one row (permits and decisions count here too)
	"locks":      {5, 20, 50, 100},
	"barriers":   {5, 20, 50, 100},
	"rendezvous": {5, 20, 50, 100},

	"topic_pub":      {20, 60, 300, 300},    // topic publishes per topic
	"topic_pub_root": {60, 300, 1500, 1500}, // topic publishes per root

	"queues":       {2, 20, 50, 50},           // queues live
	"queue_items":  {100, 2000, 10000, 10000}, // items per queue
	"queue_pushes": {50, 500, 1000, 1000},     // pushes

	"bounties":      {0, 3, 10, 20},       // open bounties
	"bounty_escrow": {0, 300, 1000, 1000}, // escrowed credits

	"review_leases": {0, 2, 4, 4},   // review leases live
	"reviews":       {2, 5, 10, 10}, // review requests open

	"claims":   {10, 20, 100, 100}, // claims (cv)
	"confirms": {20, 50, 250, 250}, // confirms (cok, cbad)
	"digests":  {5, 10, 50, 50},    // digests (dp)

	"cp_names":  {10, 50, 50, 50},                     // checkpoint names
	"cp_writes": {50, 200, 200, 200},                  // checkpoint writes
	"cp_bytes":  {1 << 20, 8 << 20, 8 << 20, 8 << 20}, // checkpoint inline bytes

	"kv_keys":  {100, 1000, 1000, 1000},                // KV keys (own ns)
	"kv_bytes": {256 << 10, 1 << 20, 1 << 20, 1 << 20}, // KV bytes (own ns)

	"cache_rows":  {100, 2000, 2000, 2000},                 // result cache rows
	"cache_bytes": {1 << 20, 16 << 20, 16 << 20, 16 << 20}, // result cache inline bytes

	"idem_keys":  {100, 1000, 1000, 1000},              // idem keys
	"idem_bytes": {1 << 10, 8 << 10, 8 << 10, 8 << 10}, // idem body bytes each

	"drops":      {20, 200, 200, 200},                    // drops PUT (token)
	"drop_bytes": {320 << 10, 3 << 20, 3 << 20, 3 << 20}, // drop bytes (token)

	"proposals":          {0, 0, 1, 1}, // proposals open per space
	"proposals_platform": {0, 0, 3, 3}, // proposals open platform-wide

	"spaces":      {0, 1, 1, 2},    // spaces created
	"spaces_live": {0, 10, 10, 10}, // spaces live

	"services":         {0, 3, 15, 15},  // services (names)
	"service_versions": {0, 10, 10, 10}, // versions per day

	"pins": {0, 0, 1, 1}, // pin requests (svc > 4 MiB), per week

	"ts":      {500, 500, 500, 500}, // timestamps
	"beacons": {60, 60, 60, 60},     // beacons

	// rev 3
	"sessions":  {2, 4, 4, 4},        // sessions live
	"tripwires": {20, 200, 200, 200}, // tripwires live

	"subs":   {5, 20, 20, 20}, // subscriptions
	"groups": {2, 10, 50, 50}, // groups live
	"rooms":  {2, 10, 10, 10}, // rooms live

	"agreements":  {0, 10, 10, 10},    // agreements open
	"tips":        {0, 20, 20, 20},    // tips per day
	"tip_credits": {0, 200, 200, 200}, // tip credits per day
	"auctions":    {0, 3, 10, 20},     // auctions open

	"treasury_fund": {0, 50, 500, 500}, // treasury fund per day (credits)
	"webhooks":      {0, 5, 10, 10},    // webhooks outbound
	"webhook_sinks": {0, 5, 5, 5},      // inbound sinks

	"env_manifests": {5, 20, 20, 20},   // env manifests
	"cache_ns":      {0, 0, 5, 5},      // cache namespaces
	"kb_akas":       {0, 20, 100, 100}, // kb akas per day

	"anchors":   {10, 10, 10, 10}, // anchors live
	"dry_runs":  {60, 60, 60, 60}, // dry runs per day
	"mail_cold": {3, 10, 50, 200}, // cold mail recipients per day (27.8)

	// 27.5 hooks and crons per space (proposal-bound; the space creator's level applies)
	"space_hooks": {0, 3, 3, 3},
	"space_crons": {0, 2, 2, 2},
}

// Cap returns the cap of kind at level (clamped to 0..3); 0 for an unknown kind (fail closed).
func Cap(kind string, level int) int {
	row, ok := Caps[kind]
	if !ok {
		return 0
	}
	return row[clampLevel(level)]
}

func clampLevel(l int) int {
	if l < 0 {
		return 0
	}
	if l > 3 {
		return 3
	}
	return l
}

// UseCap consumes one unit of the root's daily counter for kind and refuses past Cap(kind,
// s.CapLevel()) with core.ErrQuota. Vouched L0 roots use the L1 column (17.3). An unknown kind is a
// programming error and answers 500 rather than silently passing.
func UseCap(ctx context.Context, q core.Q, s Standing, kind string) error {
	return UseCapN(ctx, q, s, kind, 1)
}

// UseCapN is UseCap charging n units at once (bytes, batch pushes).
func UseCapN(ctx context.Context, q core.Q, s Standing, kind string, n int) error {
	if _, ok := Caps[kind]; !ok {
		return core.E(500, "internal", "unknown cap kind "+kind)
	}
	if n <= 0 {
		return nil
	}
	var cur int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, s.Root, kind, n).Scan(&cur)
	if err != nil {
		return err
	}
	if cur > Cap(kind, s.CapLevel()) {
		return core.ErrQuota
	}
	return nil
}

// Used returns today's counter of kind for a root (for `me` lines such as `kb 3/30`).
func Used(ctx context.Context, q core.Q, root, kind string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT coalesce((SELECT n FROM counters WHERE scope = $1 AND kind = $2 AND day = current_date), 0)`, root, kind).Scan(&n)
	return n, err
}
