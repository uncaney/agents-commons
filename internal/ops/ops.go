// Package ops is the operations plane of the gateway (SPEC-v2 21.1-21.3, 27.1, 27.7): an
// OpenMetrics registry fed by d.Observe and gauges, served on METRICS_LISTEN by its own server and
// never mounted on the public mux; the shed ladder sampler (5 s, hysteresis) that sets and clears
// the shed:<level> flags; GET /status (coarse, cached 5 min) and /healthz?v=2; the status_daily
// counters behind /status/history; the weekly operator digest; retention janitors; and
// MigrateCheck for `gateway -migrate-check`.
//
// Wiring (P60a): o := ops.Register(mux, d); go o.Run(ctx); go o.ServeMetrics(ctx,
// cfg.MetricsListen). core.Register already owns GET /healthz, so install o.Middleware around
// d.Handler(mux) for /healthz?v=2 (Register mounts the route itself on a mux where it is free).
// Other packages feed gauges through ops.SetGauge ("quarantine_occ", "anon_bits",
// "wal_last_archived_age_s"); P115 appends announcement lines to /status through StatusExtraFn.
package ops

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"ekaii.fr/commons/internal/core"
)

// StatusExtraFn appends lines (announcements, notices) to GET /status; nil-safe, each line is
// flattened and capped before rendering.
var StatusExtraFn func(ctx context.Context) []string

// Ops is one gateway instance's operations state.
type Ops struct {
	d        *core.Deps
	m        *Registry
	ladder   *Ladder
	daily    dailyCounters
	win      window
	prev     poolSnap
	inst     string
	started  time.Time
	inflight atomic.Int64
}

var current atomic.Pointer[Ops]

// Register mounts GET /status (+ .txt/.md/.json twins), GET /status/history and GET /healthz when
// the mux has no handler for them, feeds the registry from d.Observe and adds the janitor tasks
// (daily counters, SQL gauges, retention, weekly digest). It returns the instance for Run,
// ServeMetrics and Middleware.
func Register(mux *http.ServeMux, d *core.Deps) *Ops {
	var b [4]byte
	rand.Read(b[:])
	o := &Ops{d: d, m: NewRegistry(), ladder: NewLadder(), inst: hex.EncodeToString(b[:]), started: time.Now()}
	o.declare()
	if v, err := strconv.Atoi(os.Getenv("ORIGIN_RETENTION_DAYS")); err == nil && v > 0 {
		OriginKeep = time.Duration(v) * 24 * time.Hour
	}
	d.Observe(o.observe)
	mux.HandleFunc("GET /status", o.status)
	for _, ext := range []string{".txt", ".md", ".json"} {
		mux.HandleFunc("GET /status"+ext, o.status) // wildcards cannot glue to literals: one route per twin
	}
	if free(mux, "/status/history") {
		mux.HandleFunc("GET /status/history", o.history)
		for _, ext := range []string{".txt", ".md", ".json"} {
			mux.HandleFunc("GET /status/history"+ext, o.history)
		}
	}
	if free(mux, "/healthz") {
		mux.HandleFunc("GET /healthz", o.Healthz)
	}
	d.RegisterOpenAPI(json.RawMessage(openAPI))
	d.Janitor.Add("ops_daily", o.flushDaily)
	d.Janitor.Add("ops_gauges", o.refreshGauges)
	d.Janitor.Add("ops_retention", o.retention)
	d.Janitor.Add("ops_digest", o.digestTask)
	current.Store(o)
	return o
}

// free reports whether no handler is registered for GET path on mux (a catch-all does not count).
func free(mux *http.ServeMux, path string) bool {
	_, pat := mux.Handler(&http.Request{Method: http.MethodGet, URL: &url.URL{Path: path}, Host: "localhost"})
	return pat != "GET "+path && pat != path
}

// Middleware serves /healthz?v=2 (levels, maintenance) in front of a mux where core owns
// GET /healthz and counts in-flight requests; install it outside d.Handler.
func (o *Ops) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && (r.Method == http.MethodGet || r.Method == http.MethodHead) && core.V2(r) {
			o.Healthz(w, r)
			return
		}
		o.inflight.Add(1)
		defer o.inflight.Add(-1)
		next.ServeHTTP(w, r)
	})
}

// Run samples the load signals every SampleEvery and walks the shed ladder until ctx is done.
func (o *Ops) Run(ctx context.Context) {
	t := time.NewTicker(SampleEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			o.tick(ctx, now)
		}
	}
}

// SetGauge sets a custom gauge on the latest registered instance (cx_<name>); unknown names are
// created on first use (bounded), so packages built later can report without an ops change.
func SetGauge(name string, v float64) {
	if o := current.Load(); o != nil {
		o.SetGauge(name, v)
	}
}

// SetGauge sets a custom gauge cx_<name> on this instance.
func (o *Ops) SetGauge(name string, v float64) { o.m.SetCustom(name, v) }

// Registry exposes the metrics registry (tests, extra collectors).
func (o *Ops) Registry() *Registry { return o.m }

// q is the pool janitor-side work should use: the ops pool when present, else the request pool.
func (o *Ops) q() core.Q {
	if o.d.Ops != nil {
		return o.d.Ops
	}
	return o.d.DB
}

const openAPI = `{"paths":{
"/status":{"get":{"summary":"coarse service status: shed level, frozen kinds, maintenance, notices (cached 5 min; .txt/.md/.json twins)"}},
"/status/history":{"get":{"summary":"one line per day for 90 days: requests, 5xx, seconds shed"}},
"/healthz":{"get":{"summary":"liveness; ?v=2 adds shed levels, frozen kinds and maintenance_until"}}
}}`
