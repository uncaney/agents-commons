package ops

import (
	"bufio"
	"context"
	"errors"
	"math"
	"net/http"
	"regexp"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ekaii.fr/commons/internal/core"
)

// Registry is a small OpenMetrics/Prometheus text registry (stdlib only): declared families of
// gauges, counters and histograms with bounded label cardinality. Every label value is
// server-built (mux patterns, class names, flag keys, table names) and escaped on output.
type Registry struct {
	mu      sync.Mutex
	fams    map[string]*family
	order   []string
	routes  map[string]bool
	dropped uint64
}

type kind uint8

const (
	gauge kind = iota
	counter
	histogram
)

type family struct {
	name, help string
	kind       kind
	labels     []string
	samples    map[string]*sample
}

type sample struct {
	lv     []string
	v      float64
	counts []uint64
	sum    float64
	n      uint64
}

const (
	maxRoutes  = 256
	maxSamples = 1024
	prefix     = "cx_"
)

var (
	buckets      = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120}
	customNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

func NewRegistry() *Registry { return &Registry{fams: map[string]*family{}, routes: map[string]bool{}} }

// Declare adds a family (idempotent); label names are fixed per family.
func (r *Registry) Declare(name, help string, k kind, labels ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.declareLocked(name, help, k, labels...)
}

func (r *Registry) declareLocked(name, help string, k kind, labels ...string) *family {
	if f, ok := r.fams[name]; ok {
		return f
	}
	f := &family{name: name, help: help, kind: k, labels: labels, samples: map[string]*sample{}}
	r.fams[name] = f
	r.order = append(r.order, name)
	return f
}

func (r *Registry) sampleLocked(f *family, lv []string) *sample {
	if len(lv) != len(f.labels) {
		return nil
	}
	key := strings.Join(lv, "\x00")
	s, ok := f.samples[key]
	if !ok {
		if len(f.samples) >= maxSamples {
			r.dropped++
			return nil
		}
		s = &sample{lv: append([]string(nil), lv...)}
		if f.kind == histogram {
			s.counts = make([]uint64, len(buckets))
		}
		f.samples[key] = s
	}
	return s
}

// Set sets a gauge sample.
func (r *Registry) Set(name string, v float64, lv ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.fams[name]; ok && f.kind == gauge {
		if s := r.sampleLocked(f, lv); s != nil {
			s.v = v
		}
	}
}

// Add increments a counter (or gauge) sample.
func (r *Registry) Add(name string, dv float64, lv ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.fams[name]; ok && f.kind != histogram {
		if s := r.sampleLocked(f, lv); s != nil {
			s.v += dv
		}
	}
}

// Observe records a histogram observation.
func (r *Registry) Observe(name string, v float64, lv ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.fams[name]
	if !ok || f.kind != histogram {
		return
	}
	s := r.sampleLocked(f, lv)
	if s == nil {
		return
	}
	for i, b := range buckets {
		if v <= b {
			s.counts[i]++
		}
	}
	s.sum += v
	s.n++
}

// Reset drops every sample of a family (gauges whose label set shrinks are rebuilt by the caller).
func (r *Registry) Reset(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.fams[name]; ok {
		f.samples = map[string]*sample{}
	}
}

// SetCustom sets the unlabelled gauge cx_<name>, declaring it on first use (bounded by maxSamples
// families in total through the same cap as samples).
func (r *Registry) SetCustom(name string, v float64) {
	if !customNameRe.MatchString(name) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	full := prefix + name
	f, ok := r.fams[full]
	if !ok {
		if len(r.fams) >= maxSamples {
			r.dropped++
			return
		}
		f = r.declareLocked(full, "custom gauge fed by another package", gauge)
	}
	if f.kind != gauge || len(f.labels) != 0 {
		return
	}
	if s := r.sampleLocked(f, nil); s != nil {
		s.v = v
	}
}

// route bounds the route label: past maxRoutes distinct values new ones fold into "other".
func (r *Registry) route(route string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.routes[route] {
		return route
	}
	if len(r.routes) >= maxRoutes {
		return "other"
	}
	r.routes[route] = true
	return route
}

// WriteText renders the registry; openmetrics switches to the OpenMetrics 1.0 dialect (counter
// family names without _total, trailing # EOF).
func (r *Registry) WriteText(w *bufio.Writer, openmetrics bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, name := range r.order {
		f := r.fams[name]
		fam := name
		if openmetrics && f.kind == counter {
			fam = strings.TrimSuffix(name, "_total")
		}
		w.WriteString("# HELP " + fam + " " + escapeHelp(f.help) + "\n")
		w.WriteString("# TYPE " + fam + " " + [...]string{"gauge", "counter", "histogram"}[f.kind] + "\n")
		keys := make([]string, 0, len(f.samples))
		for k := range f.samples {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := f.samples[k]
			if f.kind != histogram {
				w.WriteString(name + labelSet(f.labels, s.lv, "", "") + " " + fmtFloat(s.v) + "\n")
				continue
			}
			var cum uint64
			for i, b := range buckets {
				cum += s.counts[i]
				w.WriteString(name + "_bucket" + labelSet(f.labels, s.lv, "le", fmtFloat(b)) + " " + strconv.FormatUint(cum, 10) + "\n")
			}
			w.WriteString(name + "_bucket" + labelSet(f.labels, s.lv, "le", "+Inf") + " " + strconv.FormatUint(s.n, 10) + "\n")
			w.WriteString(name + "_sum" + labelSet(f.labels, s.lv, "", "") + " " + fmtFloat(s.sum) + "\n")
			w.WriteString(name + "_count" + labelSet(f.labels, s.lv, "", "") + " " + strconv.FormatUint(s.n, 10) + "\n")
		}
	}
	if openmetrics {
		w.WriteString("# EOF\n")
	}
}

func labelSet(names, values []string, extraK, extraV string) string {
	if len(names) == 0 && extraK == "" {
		return ""
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n + `="` + escapeLabel(values[i]) + `"`)
	}
	if extraK != "" {
		if len(names) > 0 {
			b.WriteByte(',')
		}
		b.WriteString(extraK + `="` + extraV + `"`)
	}
	b.WriteByte('}')
	return b.String()
}

// escapeLabel applies the exposition-format escapes and caps the value (server-built, but a mux
// pattern or table name is still never trusted to be short).
func escapeLabel(v string) string {
	if len(v) > 120 {
		v = v[:120]
	}
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	return strings.ReplaceAll(strings.ReplaceAll(v, "\n", `\n`), "\r", "")
}

func escapeHelp(h string) string {
	return strings.ReplaceAll(strings.ReplaceAll(h, `\`, `\\`), "\n", `\n`)
}

func fmtFloat(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// --- the gateway's families and collectors --------------------------------------------------

func (o *Ops) declare() {
	m := o.m
	m.Declare("cx_requests_total", "requests by mux pattern, route class and status", counter, "class", "route", "status")
	m.Declare("cx_request_seconds", "request duration by route class", histogram, "class")
	m.Declare("cx_responses_5xx_total", "5xx replies by route class", counter, "class")
	m.Declare("cx_inflight", "requests in flight (through ops.Middleware)", gauge)
	m.Declare("cx_shed_level", "highest shed rung on: 0 none, 1 feeds, 2 anon-search, 3 longpoll, 4 anon-write, 5 compute", gauge)
	m.Declare("cx_shed_rung", "1 while the rung's shed flag is on", gauge, "level")
	m.Declare("cx_pressure", "load pressure of the last sample (shed ladder input, 0..1+)", gauge)
	m.Declare("cx_shed_changes_total", "rung transitions by this instance", counter, "dir")
	m.Declare("cx_pool_conns", "pgx pool connections by state", gauge, "pool", "state")
	m.Declare("cx_pool_max_conns", "pgx pool size", gauge, "pool")
	m.Declare("cx_pool_acquire_total", "pool acquires", counter, "pool")
	m.Declare("cx_pool_empty_acquire_total", "acquires that waited for a free connection", counter, "pool")
	m.Declare("cx_pool_acquire_wait_seconds_total", "time spent waiting for a free connection", counter, "pool")
	m.Declare("cx_waiters", "live long-polls", gauge)
	m.Declare("cx_waiters_max", "long-poll cap", gauge)
	m.Declare("cx_limiter_keys", "rate limiter buckets", gauge)
	m.Declare("cx_notifier_topics", "live notifier topics", gauge)
	m.Declare("cx_outbox_depth", "egress outbox live rows per kind", gauge, "kind")
	m.Declare("cx_outbox_cap", "egress outbox live-row cap per kind", gauge, "kind")
	m.Declare("cx_replicas", "compute replicas by state", gauge, "state")
	m.Declare("cx_replica_oldest_queued_seconds", "age of the oldest queued replica", gauge)
	m.Declare("cx_jobs_active", "queued or running jobs", gauge)
	m.Declare("cx_storage_used_bytes", "storage class usage (last governor measurement)", gauge, "class")
	m.Declare("cx_storage_cap_bytes", "storage class cap", gauge, "class")
	m.Declare("cx_storage_frozen", "1 while the class is frozen", gauge, "class")
	m.Declare("cx_frozen", "1 while the kind is frozen", gauge, "what")
	m.Declare("cx_table_rows_estimate", "pg_class.reltuples of retention-managed tables", gauge, "table")
	m.Declare("cx_retention_deleted_total", "rows deleted by the retention janitor", counter, "table")
	m.Declare("cx_janitor_seconds", "last duration of an ops janitor task", gauge, "task")
	m.Declare("cx_janitor_runs_total", "ops janitor task runs", counter, "task", "result")
	m.Declare("cx_go_goroutines", "goroutines", gauge)
	m.Declare("cx_go_mem_bytes", "Go memory in use (total minus released)", gauge)
	m.Declare("cx_go_memlimit_bytes", "GOMEMLIMIT (0 when unset)", gauge)
	m.Declare("cx_process_start_time_seconds", "unix start time", gauge)
	m.Declare("cx_uptime_seconds", "seconds since start", gauge)
	m.Set("cx_process_start_time_seconds", float64(o.started.Unix()))
	m.Set("cx_waiters_max", core.MaxWaiters)
	m.Set("cx_shed_level", 0)
	for _, l := range Levels {
		m.Set("cx_shed_rung", 0, l)
	}
}

// observe is the d.Observe callback: counters, histogram, daily counters and the sampler window.
func (o *Ops) observe(route string, status int, dur time.Duration) {
	class := classOf(route)
	if status == 404 || status == 405 {
		route = "unmatched"
	}
	o.m.Add("cx_requests_total", 1, class, o.m.route(route), strconv.Itoa(status))
	o.m.Observe("cx_request_seconds", dur.Seconds(), class)
	var e5 int64
	if status >= 500 {
		o.m.Add("cx_responses_5xx_total", 1, class)
		e5 = 1
	}
	o.daily.add(time.Now(), 1, e5, 0)
	o.win.add(dur)
}

// classOf maps a route (mux pattern or "METHOD /seg") to its class label.
func classOf(route string) string {
	_, p, ok := strings.Cut(route, " ")
	if !ok {
		p = route
	}
	switch {
	case p == "/healthz" || p == "/status" || strings.HasPrefix(p, "/status."):
		return "health"
	case strings.HasPrefix(p, "/admin/"):
		return "admin"
	case strings.HasPrefix(p, "/internal/"):
		return "internal"
	case p == "/mcp" || strings.HasPrefix(p, "/mcp/"):
		return "mcp"
	case p == "/a2a" || strings.HasPrefix(p, "/a2a/"):
		return "a2a"
	case strings.HasPrefix(p, "/f/") || p == "/feed.xml" || p == "/feed.json":
		return "feed"
	case strings.HasPrefix(p, "/q/") || strings.HasPrefix(p, "/e/") || strings.HasPrefix(p, "/x/") || strings.HasPrefix(p, "/h/") || p == "/v1/kb" || p == "/brief":
		return "search"
	case strings.HasPrefix(p, "/v1/"):
		return "api"
	case strings.HasPrefix(p, "/robots.txt") || strings.HasPrefix(p, "/sitemap") || strings.HasPrefix(p, "/llms") || p == "/index.md" ||
		p == "/AGENTS.md" || strings.HasPrefix(p, "/.well-known/") || strings.HasPrefix(p, "/openapi") || strings.HasPrefix(p, "/export/"):
		return "static"
	}
	return "page"
}

// runtimeGauges refreshes the in-memory gauges (scrape time and every sample: cheap, no DB).
func (o *Ops) runtimeGauges() {
	m, d := o.m, o.d
	m.Set("cx_waiters", float64(d.Waiters.Len()))
	m.Set("cx_limiter_keys", float64(d.Lim.Len()))
	m.Set("cx_notifier_topics", float64(d.Notify.Len()))
	m.Set("cx_inflight", float64(o.inflight.Load()))
	m.Set("cx_go_goroutines", float64(runtime.NumGoroutine()))
	used, limit := goMem()
	m.Set("cx_go_mem_bytes", float64(used))
	m.Set("cx_go_memlimit_bytes", float64(limit))
	m.Set("cx_uptime_seconds", time.Since(o.started).Seconds())
	for name, pool := range map[string]interface{ Stat() poolStat }{"request": statOf(d.DB), "ops": statOf(d.Ops)} {
		if pool == nil {
			continue
		}
		st := pool.Stat()
		m.Set("cx_pool_conns", float64(st.AcquiredConns()), name, "acquired")
		m.Set("cx_pool_conns", float64(st.IdleConns()), name, "idle")
		m.Set("cx_pool_conns", float64(st.ConstructingConns()), name, "constructing")
		m.Set("cx_pool_max_conns", float64(st.MaxConns()), name)
		m.Set("cx_pool_acquire_total", float64(st.AcquireCount()), name)
		m.Set("cx_pool_empty_acquire_total", float64(st.EmptyAcquireCount()), name)
		m.Set("cx_pool_acquire_wait_seconds_total", st.EmptyAcquireWaitTime().Seconds(), name)
	}
	for _, what := range []string{"reg", "write", "compute", "all"} {
		m.Set("cx_frozen", b2f(d.Frozen(what)), what)
	}
	lvl, _ := o.Level()
	m.Set("cx_shed_level", float64(lvl))
	for _, l := range Levels {
		m.Set("cx_shed_rung", b2f(d.Flag("shed:"+l)), l)
	}
}

// goMem returns the Go runtime's memory in use and the memory limit (0 when unset).
func goMem() (used, limit int64) {
	s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(s)
	if s[0].Value.Kind() == metrics.KindUint64 && s[1].Value.Kind() == metrics.KindUint64 {
		used = int64(s[0].Value.Uint64()) - int64(s[1].Value.Uint64())
	}
	if l := debug.SetMemoryLimit(-1); l > 0 && l < math.MaxInt64 {
		limit = l
	}
	return used, limit
}

// refreshGauges is the janitor task behind the SQL-backed gauges (outbox, replicas, storage, table
// estimates); it runs on the ops pool so a slow query never blocks a request.
func (o *Ops) refreshGauges(ctx context.Context) (err error) {
	defer o.timed("ops_gauges", time.Now(), &err)
	q, m := o.q(), o.m
	rows, err := q.Query(ctx, `SELECT kind, count(*) FROM egress_outbox WHERE done_at IS NULL GROUP BY kind`)
	if err != nil {
		return err
	}
	m.Reset("cx_outbox_depth")
	m.Reset("cx_outbox_cap")
	for rows.Next() {
		var k string
		var n int64
		if err := rows.Scan(&k, &n); err != nil {
			rows.Close()
			return err
		}
		m.Set("cx_outbox_depth", float64(n), k)
		m.Set("cx_outbox_cap", float64(core.EgressCap(k)), k)
	}
	rows.Close()
	var queued, leased, active int64
	var oldest float64
	if err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'queued'), count(*) FILTER (WHERE state = 'leased'),
		coalesce(extract(epoch FROM now() - min(created) FILTER (WHERE state = 'queued')), 0)
		FROM replicas WHERE state IN ('queued', 'leased')`).Scan(&queued, &leased, &oldest); err != nil {
		return err
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE status IN ('queued', 'running')`).Scan(&active); err != nil {
		return err
	}
	m.Set("cx_replicas", float64(queued), "queued")
	m.Set("cx_replicas", float64(leased), "leased")
	m.Set("cx_replica_oldest_queued_seconds", oldest)
	m.Set("cx_jobs_active", float64(active))
	m.Reset("cx_storage_used_bytes")
	m.Reset("cx_storage_cap_bytes")
	m.Reset("cx_storage_frozen")
	for _, c := range o.d.StorageClasses() {
		m.Set("cx_storage_used_bytes", float64(c.Used), c.Name)
		m.Set("cx_storage_cap_bytes", float64(c.Cap), c.Name)
		m.Set("cx_storage_frozen", b2f(c.Frozen), c.Name)
	}
	rows, err = q.Query(ctx, `SELECT relname, greatest(reltuples, 0)::bigint FROM pg_class
		WHERE relkind = 'r' AND relnamespace = current_schema()::regnamespace AND relname = ANY($1)`, retentionTables)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var n int64
		if err := rows.Scan(&t, &n); err != nil {
			return err
		}
		m.Set("cx_table_rows_estimate", float64(n), t)
	}
	return rows.Err()
}

// timed records an ops janitor task's duration and result.
func (o *Ops) timed(task string, start time.Time, err *error) {
	o.m.Set("cx_janitor_seconds", time.Since(start).Seconds(), task)
	res := "ok"
	if *err != nil {
		res = "err"
	}
	o.m.Add("cx_janitor_runs_total", 1, task, res)
}

// MetricsHandler serves GET /metrics only: text/plain 0.0.4 by default, OpenMetrics when the
// Accept header asks for it. Mount it on its own server (ServeMetrics), never on the public mux.
func (o *Ops) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", o.metrics)
	return mux
}

func (o *Ops) metrics(w http.ResponseWriter, r *http.Request) {
	o.runtimeGauges()
	om := strings.Contains(r.Header.Get("Accept"), "application/openmetrics-text")
	if om {
		w.Header().Set("Content-Type", "application/openmetrics-text; version=1.0.0; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "no-store")
	bw := bufio.NewWriter(w)
	o.m.WriteText(bw, om)
	bw.Flush()
}

// ServeMetrics runs the metrics server on addr (METRICS_LISTEN, e.g. ":9100" on the data network)
// until ctx is done; an empty addr disables it.
func (o *Ops) ServeMetrics(ctx context.Context, addr string) error {
	if addr == "" {
		return nil
	}
	srv := &http.Server{Addr: addr, Handler: o.MetricsHandler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
