package core

import (
	"context"
	"fmt"
	"net/http"
	"runtime/debug"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Handler wraps the mux with recovery, the headers policy (3.7), auth resolution, rate budgets
// (3.6) with RateLimit headers, client network keys in the context, observers and logging.
// Must be the innermost wrapper around the mux so every package's routes get the same treatment.
func (d *Deps) Handler(mux http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200, d: d, r: r, token: hasToken(r)}
		d.preHeaders(w.Header(), r)
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				d.Log.Error("panic", "path", r.URL.Path, "err", rec, "stack", string(debug.Stack()))
				if !sw.wrote {
					Err(sw, r, 500, "internal", "internal error")
				}
			}
			dur := time.Since(start)
			d.Log.Info("req", "m", r.Method, "p", logPath(r), "s", sw.status, "ms", dur.Milliseconds(), "ip", d.ClientIP(r))
			d.observe(routeOf(r), sw.status, dur)
		}()
		if r.Method == http.MethodOptions && preflightPath(r.URL.Path) {
			preflight(sw)
			return
		}
		r = d.resolveAuth(r)
		ip, grp, sup := d.ClientIP(r), d.IPGroup(r), d.IPSuper(r)
		r = r.WithContext(WithClient(r.Context(), ip, grp, sup))
		sw.r = r
		ok, info := d.Take(r, identFrom(r), d.CostOf(patternOf(mux, r)))
		setRateHeaders(w.Header(), info)
		if !ok {
			Fail(sw, r, ErrRate)
			return
		}
		mux.ServeHTTP(sw, r)
	})
}

// patternOf pre-matches the request against a *ServeMux to find its pattern (for RegisterCost).
func patternOf(mux http.Handler, r *http.Request) string {
	if m, ok := mux.(*http.ServeMux); ok {
		_, pat := m.Handler(r)
		return pat
	}
	return ""
}

// routeOf is the observer key: the matched pattern, else METHOD /first-segment.
func routeOf(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	p := r.URL.Path
	if i := strings.IndexByte(p[1:], '/'); i >= 0 {
		p = p[:i+1]
	}
	return r.Method + " " + p
}

// logPath formats the request path for the log line through LogPathFn (pathscrub masks secrets).
func logPath(r *http.Request) string {
	if LogPathFn == nil {
		return r.URL.Path
	}
	s := LogPathFn(r.URL.RequestURI())
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
	d      *Deps
	r      *http.Request
	token  bool
}

func (s *statusWriter) WriteHeader(c int) {
	if !s.wrote {
		s.status, s.wrote = c, true
		s.d.finalHeaders(s.Header(), s.r, c, s.token)
	}
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Flush() {
	if !s.wrote {
		s.WriteHeader(http.StatusOK)
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// UseNetQuota is UseIPQuota charging both network keys (4.3): the IP group at limit and the
// super-group at 4x limit. ip may be a raw address or an IPGroup string.
func UseNetQuota(ctx context.Context, q Q, ip, kind string, limit int) error {
	n, err := bump(ctx, q, "ip:"+IPGroup(ip), kind, 1)
	if err != nil {
		return err
	}
	s, err := bump(ctx, q, "sup:"+IPSuper(ip), kind, 1)
	if err != nil {
		return err
	}
	if n > limit || s > 4*limit {
		return ErrQuota
	}
	return nil
}

// Storage governor (21.2).

type storageClass struct {
	name     string
	capBytes int64
	usedSQL  string
}

const (
	govFreezeAt = 0.9
	govLiftAt   = 0.8
	pgFreezeAt  = 0.8
	pgLiftAt    = 0.7
	diskMinFree = 2 << 30
	diskOKFree  = diskMinFree + (diskMinFree / 4)
)

// StorageClass registers a table owner's class: usedSQL returns one bigint (bytes in use).
func (d *Deps) StorageClass(name string, capBytes int64, usedSQL string) {
	d.hmu.Lock()
	d.h.classes[name] = &storageClass{name, capBytes, usedSQL}
	d.hmu.Unlock()
}

// StorageClasses lists the registered classes plus the built-in pg class with the last measured
// usage (RunGovernor) and their freeze state, sorted by name.
func (d *Deps) StorageClasses() []StorageClassInfo {
	d.hmu.RLock()
	out := make([]StorageClassInfo, 0, len(d.h.classes)+1)
	for _, c := range d.h.classes {
		out = append(out, StorageClassInfo{Name: c.name, Cap: c.capBytes})
	}
	d.hmu.RUnlock()
	out = append(out, StorageClassInfo{Name: "pg", Cap: d.Cfg.PGMaxBytes})
	usage := d.usage.Load()
	for i := range out {
		if usage != nil {
			out[i].Used = (*usage)[out[i].Name]
		}
		out[i].Frozen = d.Frozen(out[i].Name)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RunGovernor measures every class, flips freeze:<class> at 90 % (lifts at 80 %), freezes writes
// at 80 % of PG_MAX_BYTES (lifts at 70 %) and freezes everything plus registration when DATA_DIR
// has less than 2 GiB free. Janitor task "governor".
func (d *Deps) RunGovernor(ctx context.Context) error {
	q := Q(d.DB)
	if d.Ops != nil {
		q = d.Ops
	}
	d.hmu.RLock()
	classes := make([]*storageClass, 0, len(d.h.classes))
	for _, c := range d.h.classes {
		classes = append(classes, c)
	}
	d.hmu.RUnlock()
	usage := map[string]int64{}
	var firstErr error
	for _, c := range classes {
		var used int64
		if err := q.QueryRow(ctx, c.usedSQL).Scan(&used); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("class %s: %w", c.name, err)
			}
			continue
		}
		usage[c.name] = used
		if c.capBytes <= 0 {
			continue
		}
		ratio := float64(used) / float64(c.capBytes)
		switch {
		case ratio >= govFreezeAt:
			d.govFlag(ctx, "freeze:"+c.name, true)
		case ratio <= govLiftAt:
			d.govFlag(ctx, "freeze:"+c.name, false)
		}
	}
	var pg int64
	if err := q.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&pg); err == nil {
		usage["pg"] = pg
		if d.Cfg.PGMaxBytes > 0 {
			ratio := float64(pg) / float64(d.Cfg.PGMaxBytes)
			switch {
			case ratio >= pgFreezeAt:
				d.govFlag(ctx, "freeze:pg", true)
				d.govFlag(ctx, "freeze:write", true)
			case ratio <= pgLiftAt:
				d.govFlag(ctx, "freeze:pg", false)
				d.govFlag(ctx, "freeze:write", false)
			}
		}
	} else if firstErr == nil {
		firstErr = err
	}
	d.usage.Store(&usage)
	if free, err := DiskFree(d.Cfg.DataDir); err == nil {
		d.govMu.Lock()
		was := d.govDisk
		d.govMu.Unlock()
		switch {
		case free < diskMinFree && !was:
			d.govMu.Lock()
			d.govDisk = true
			d.govMu.Unlock()
			for _, c := range classes {
				d.govFlag(ctx, "freeze:"+c.name, true)
			}
			d.govFlag(ctx, "freeze:write", true)
			d.govFlag(ctx, "freeze:reg", true)
			Event(ctx, d.DB, "ops", "disk", "", fmt.Sprintf("low disk: %d MiB free, writes and registration frozen", free>>20))
			d.Log.Error("storage governor: low disk", "free", free)
		case free >= diskOKFree && was:
			d.govMu.Lock()
			d.govDisk = false
			d.govMu.Unlock()
			for _, c := range classes {
				d.govFlag(ctx, "freeze:"+c.name, false)
			}
			d.govFlag(ctx, "freeze:write", false)
			d.govFlag(ctx, "freeze:reg", false)
		}
	}
	return firstErr
}

// govFlag switches a governor-owned flag; it never lifts a flag the operator set by hand.
func (d *Deps) govFlag(ctx context.Context, key string, on bool) {
	d.govMu.Lock()
	was := d.govSet[key]
	if on {
		d.govSet[key] = true
	} else {
		delete(d.govSet, key)
	}
	d.govMu.Unlock()
	var err error
	switch {
	case on && !d.Flag(key):
		err = d.SetFlag(ctx, key, true, "")
	case !on && was && d.Flag(key):
		err = d.SetFlag(ctx, key, false, "")
	}
	if err != nil {
		d.Log.Warn("storage governor flag", "key", key, "on", on, "err", err)
	}
}

// DiskFree returns the bytes available to unprivileged writers on path's filesystem.
func DiskFree(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// CheckBudget fails when the class caps (incl. pg) exceed DISK_BUDGET (0 = unchecked); main runs it
// at boot and behind -check-budget.
func CheckBudget(classes []StorageClassInfo, diskBudget int64) error {
	if diskBudget <= 0 {
		return nil
	}
	var sum int64
	var names []string
	for _, c := range classes {
		if c.Cap > 0 {
			sum += c.Cap
			names = append(names, fmt.Sprintf("%s=%d", c.Name, c.Cap))
		}
	}
	if sum > diskBudget {
		return fmt.Errorf("storage class caps sum to %d bytes > DISK_BUDGET %d (%s)", sum, diskBudget, strings.Join(names, " "))
	}
	return nil
}
