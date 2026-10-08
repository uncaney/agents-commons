// Package machineclaims turns two machine sources into verified claims under the system root
// (SPEC-v2 27.9): OSV.dev vulnerability ranges (courier kind `osv`) become `security` claims, and
// endoflife.date product cycles (courier kind `eol`) become `eol` and `release` claims; registry
// metadata applied by know (the libmeta courier kind) additionally yields `release`,
// `deprecated` and `removed` claims through a hook. Every row is written by know.CreateClaim as the
// system root with src `machine`, source_tier official, source_state ok and status verified, and is
// deduped by the partial unique index (lib, kind, source_url) WHERE src = 'machine' (0142).
//
// Machine claims never gain or give reputation (know enforces this for the system root) and can be
// disputed like any claim: three disputes hide the row and, through know.MachineDisputedFn, pause
// that product for 30 days (an operator inbox event). Enqueueing follows the libmeta rules: only
// keys that are the target of a seeded alias or were referenced by an L1+ write, refreshed weekly,
// capped at 500 jobs per kind per day through core.Egress. Everything these sources return is
// untrusted data: ids are regex-validated, text is one-lined and capped, versions are single tokens.
package machineclaims

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/egress"
	"ekaii.fr/commons/internal/know"
)

// Tunables (vars so tests can tighten them).
var (
	// DailyCap is the per-kind daily ceiling on enqueued jobs (27.9: 500/day per kind).
	DailyCap = 500
	// Refresh is the weekly cadence a key or product is re-enqueued at.
	Refresh = 7 * 24 * time.Hour
	// PauseDur is how long a product is paused after three disputes hide a machine row.
	PauseDur = 30 * 24 * time.Hour
	// enqueueBatch bounds how many keys/products one janitor pass enqueues.
	enqueueBatch = 200
	// maxOSVQueries caps the querybatch entries of one osv job (OSV allows <= 1000).
	maxOSVQueries = 1000
)

// osvEcosystem maps a commons ecosystem to its OSV.dev name; ecosystems OSV does not index map to
// "" and are skipped when a batch is built.
var osvEcosystem = map[string]string{
	"pypi": "PyPI", "npm": "npm", "go": "Go", "crates": "crates.io", "gem": "RubyGems",
	"maven": "Maven", "nuget": "NuGet",
}

// productMap embeds the endoflife.date products P117 tracks, each bound to the commons lib key its
// eol/release claims hang off. Runtimes and servers map to their official image key; language
// frameworks to their package key.
var productMap = map[string]string{
	"node":       "docker:node",
	"python":     "docker:python",
	"go":         "go:go",
	"postgresql": "docker:postgres",
	"ubuntu":     "docker:ubuntu",
	"debian":     "docker:debian",
	"django":     "pypi:django",
	"rails":      "gem:rails",
	"nginx":      "docker:nginx",
	"redis":      "docker:redis",
}

// systemAuthor is the author every machine claim is written as (the system root, 27.9).
func systemAuthor() *core.Ident { return &core.Ident{ID: core.SystemID, Root: core.SystemID} }

// Register wires the package: the osv/eol ack handlers, the libmeta release/deprecated hook, the
// 3-dispute pause, and the weekly enqueue janitors. No public route or MCP op is mounted (claims are
// read through know); mux is unused and kept for the uniform package signature.
func Register(mux *http.ServeMux, d *core.Deps) {
	_ = mux
	hookDeps = d
	egress.ResultFn["osv"] = IngestOSV
	egress.ResultFn["eol"] = IngestEOL
	know.LibMetaHookFn = LibMetaHook
	know.MachineDisputedFn = func(ctx context.Context, q core.Q, lib, id string) {
		if err := PauseProduct(ctx, q, lib, id); err != nil && d != nil && d.Log != nil {
			d.Log.Error("machineclaims pause", "lib", lib, "id", id, "err", err)
		}
	}
	if d != nil && d.Janitor != nil {
		d.Janitor.Add("machineclaims_osv", weekly(func(ctx context.Context) error { return EnqueueOSV(ctx, d) }))
		d.Janitor.Add("machineclaims_eol", weekly(func(ctx context.Context) error { return EnqueueEOL(ctx, d) }))
	}
}

// weekly runs fn at most once per Refresh per instance (the janitor ticks far more often); the
// per-key machine_state freshness is the durable gate, this only spares the scan.
func weekly(fn func(ctx context.Context) error) func(ctx context.Context) error {
	var last time.Time
	return func(ctx context.Context) error {
		if !last.IsZero() && time.Since(last) < Refresh/7 {
			return nil
		}
		last = time.Now()
		return fn(ctx)
	}
}

// PauseProduct records a 30-day pause for lib across both machine kinds and raises an operator
// inbox event (27.9). Called from know.MachineDisputedFn inside the dispute's transaction.
func PauseProduct(ctx context.Context, q core.Q, lib, id string) error {
	for _, kind := range [...]string{"osv", "eol"} {
		if _, err := q.Exec(ctx, `INSERT INTO machine_state (kind, key, paused_until) VALUES ($1, $2, now() + $3::interval)
			ON CONFLICT (kind, key) DO UPDATE SET paused_until = EXCLUDED.paused_until`,
			kind, lib, pgInterval(PauseDur)); err != nil {
			return err
		}
	}
	return core.Event(ctx, q, "machine_paused", id, "", "machine source paused 30d after 3 disputes: "+lib)
}

// Paused reports whether lib is currently paused for kind (test and enqueue helper).
func Paused(ctx context.Context, q core.Q, kind, key string) (bool, error) {
	var paused bool
	err := q.QueryRow(ctx, `SELECT coalesce((SELECT paused_until > now() FROM machine_state WHERE kind = $1 AND key = $2), false)`, kind, key).Scan(&paused)
	return paused, err
}

// markFetched upserts the last-ingested time for (kind, key), leaving any pause untouched.
func markFetched(ctx context.Context, q core.Q, kind, key string) error {
	_, err := q.Exec(ctx, `INSERT INTO machine_state (kind, key, fetched_at) VALUES ($1, $2, now())
		ON CONFLICT (kind, key) DO UPDATE SET fetched_at = now()`, kind, key)
	return err
}

// dailyRemaining is how many more jobs of kind may be enqueued today (27.9: 500/day per kind).
func dailyRemaining(ctx context.Context, q core.Q, kind string) (int, error) {
	var used int
	err := q.QueryRow(ctx, `SELECT count(*) FROM egress_outbox WHERE kind = $1 AND created > now() - interval '1 day'`, kind).Scan(&used)
	if err != nil {
		return 0, err
	}
	if n := DailyCap - used; n > 0 {
		return n, nil
	}
	return 0, nil
}

// pgInterval renders a duration as a Postgres interval literal.
func pgInterval(d time.Duration) string {
	return strconv.FormatInt(int64(d/time.Second), 10) + " seconds"
}

// skippable reports whether a know.CreateClaim error is a client-side rejection (bad range, lexicon,
// duplicate) to skip rather than a database failure to retry the whole ack on.
func skippable(err error) bool {
	var ae *core.APIError
	return errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500
}
