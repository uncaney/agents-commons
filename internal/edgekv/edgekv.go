// Package edgekv is the gateway side of the outage-proof crawl surface (SPEC-v2 27.1): an in-process
// janitor fetches the static crawl files the edge Cloudflare Worker falls back to (robots.txt,
// sitemap.xml and its children, llms.txt, index.md, the .well-known bundle and the IndexNow key
// file), compares each one's sha256 with a row of the existing `flags` table keyed `edgekv:<path>`
// (no migration), and enqueues `core.Egress("kv_mirror", …)` for the ones that changed, coalesced to
// at most 48 KV writes per rolling day so the Workers-Free KV write budget is never approached. The
// courier kind `kv_mirror` performs the write; egress.ResultFn["kv_mirror"] records it by storing the
// new sha so an unchanged file is never re-enqueued. The watcher calls mux.ServeHTTP directly, so it
// reads exactly what a crawler would and never leaves the box.
package edgekv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/egress"
)

const (
	// DailyWrites is the coalescing budget: at most this many kv_mirror rows are enqueued per rolling
	// 24 h (Workers Free allows 1000 KV writes/day; this stays far under on purpose, SPEC 27.1).
	DailyWrites = 48
	// MaxValue is the per-file value cap: a larger body is skipped (llms-full is never mirrored).
	MaxValue = 64 << 10
	// Interval is how often the watcher sweeps (SPEC 27.1: every 30 min).
	Interval = 30 * time.Minute
	// maxChildSitemaps bounds how many /sitemaps/* children one sweep discovers from the index.
	maxChildSitemaps = 50
)

// wellKnownPaths are the stable .well-known documents worth mirroring; a path that 404s on this
// gateway is simply skipped, so a superset is harmless (it mirrors whatever actually answers 200).
var wellKnownPaths = []string{
	"/.well-known/agent.json",
	"/.well-known/mcp.json",
	"/.well-known/mcp/server.json",
	"/.well-known/api-catalog",
	"/.well-known/security.txt",
	"/.well-known/ai-plugin.json",
}

var locRe = regexp.MustCompile(`<loc>\s*([^<\s]{1,1000})\s*</loc>`)

// Watcher mirrors the static crawl files into the edge KV. It is created by Register and runs from
// the janitor; Sweep is exported so tests can drive one pass without the interval gate.
type Watcher struct {
	d     *core.Deps
	mux   http.Handler
	base  []string // the fixed paths (crawl files, IndexNow key file, well-known bundle)
	every time.Duration

	mu   sync.Mutex
	last time.Time
}

// New builds a watcher over mux with the default path set derived from d (the IndexNow key file is
// per-server). Register uses it; tests use it with a stub mux.
func New(d *core.Deps, mux http.Handler) *Watcher {
	base := []string{"/robots.txt", "/sitemap.xml", "/llms.txt", "/index.md"}
	base = append(base, wellKnownPaths...)
	if key := egress.IndexNowKey(d.Cfg.ServerSecret); key != "" {
		base = append(base, "/"+key+".txt")
	}
	return &Watcher{d: d, mux: mux, base: base, every: Interval}
}

// Register wires the watcher's janitor task and the kv_mirror result handler. It is the package's
// own entry point (mux lets the janitor fetch in-process); no public route is mounted.
func Register(mux *http.ServeMux, d *core.Deps) {
	w := New(d, mux)
	egress.ResultFn["kv_mirror"] = KvMirrorResult
	if d.Janitor != nil {
		d.Janitor.Add("edgekv", w.Run)
	}
}

// Run is the janitor entry point: it sweeps at most once per Interval regardless of tick frequency.
func (w *Watcher) Run(ctx context.Context) error {
	w.mu.Lock()
	if !w.last.IsZero() && time.Since(w.last) < w.every {
		w.mu.Unlock()
		return nil
	}
	w.last = time.Now()
	w.mu.Unlock()
	_, err := w.Sweep(ctx)
	return err
}

// Sweep fetches every watched path in-process, enqueues a kv_mirror job for each changed file within
// the daily budget, and returns how many it enqueued. It is idempotent: an unchanged file, a file
// already queued, and everything past the budget are left alone.
func (w *Watcher) Sweep(ctx context.Context) (int, error) {
	budget, err := w.budget(ctx)
	if err != nil {
		return 0, err
	}
	paths := w.paths(ctx)
	enqueued := 0
	for _, path := range paths {
		if budget <= 0 {
			w.d.Log.Warn("edgekv: daily write budget exhausted", "limit", DailyWrites)
			break
		}
		status, body, ct, lastMod := w.fetch(ctx, path)
		if status != http.StatusOK {
			continue
		}
		if len(body) > MaxValue {
			w.d.Log.Warn("edgekv: file over value cap, not mirrored", "path", path, "bytes", len(body))
			continue
		}
		sum := hex.EncodeToString(sha256Sum(body))
		cur, err := w.storedSha(ctx, path)
		if err != nil {
			return enqueued, err
		}
		if cur == sum {
			continue // unchanged
		}
		queued, err := w.alreadyQueued(ctx, path)
		if err != nil {
			return enqueued, err
		}
		if queued {
			continue // a write for this path is already in flight; the sha updates when it lands
		}
		payload := kvPayload{Path: path, CT: ct, Body: base64.StdEncoding.EncodeToString(body), LastModified: lastMod}
		if err := core.Egress(ctx, w.d.DB, "kv_mirror", payload); err != nil {
			if errors.Is(err, core.ErrOutboxFull) || errors.Is(err, core.ErrSize) {
				w.d.Log.Warn("edgekv: enqueue skipped", "path", path, "err", err)
				continue
			}
			return enqueued, err
		}
		enqueued++
		budget--
	}
	return enqueued, nil
}

type kvPayload struct {
	Path         string `json:"path"`
	CT           string `json:"ct"`
	Body         string `json:"body"`
	LastModified string `json:"last_modified"`
}

// paths is the working set for one sweep: the fixed paths plus any /sitemaps/* children discovered
// in the sitemap index (deduped, same order).
func (w *Watcher) paths(ctx context.Context) []string {
	out := append([]string(nil), w.base...)
	seen := map[string]bool{}
	for _, p := range out {
		seen[p] = true
	}
	if status, body, _, _ := w.fetch(ctx, "/sitemap.xml"); status == http.StatusOK {
		for _, child := range childSitemaps(body) {
			if !seen[child] {
				seen[child] = true
				out = append(out, child)
			}
		}
	}
	return out
}

// childSitemaps extracts same-site /sitemaps/* paths from a sitemap index body (<= maxChildSitemaps).
func childSitemaps(body []byte) []string {
	var out []string
	for _, m := range locRe.FindAllSubmatch(body, -1) {
		loc := string(m[1])
		path := locPath(loc)
		if len(path) > len("/sitemaps/") && path[:len("/sitemaps/")] == "/sitemaps/" && !bytes.Contains([]byte(path), []byte("..")) {
			out = append(out, path)
			if len(out) >= maxChildSitemaps {
				break
			}
		}
	}
	return out
}

// locPath returns the path of a <loc> value, accepting both an absolute URL and a bare path.
func locPath(loc string) string {
	if i := strings.Index(loc, "://"); i >= 0 {
		rest := loc[i+3:]
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			return stripQuery(rest[j:])
		}
		return "/"
	}
	if strings.HasPrefix(loc, "/") {
		return stripQuery(loc)
	}
	return ""
}

func stripQuery(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return p
}

// fetch runs one in-process GET through the mux and returns the status, body, content-type and
// Last-Modified. It is exactly what a crawler would receive, minus the request pipeline (no limiter,
// no shed): the watcher must see static bytes even while the box sheds load.
func (w *Watcher) fetch(ctx context.Context, path string) (status int, body []byte, ct, lastMod string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return 0, nil, "", ""
	}
	rec := &capture{hdr: http.Header{}, status: http.StatusOK}
	w.mux.ServeHTTP(rec, req)
	return rec.status, rec.buf.Bytes(), rec.hdr.Get("Content-Type"), rec.hdr.Get("Last-Modified")
}

// capture is a minimal http.ResponseWriter that records one response in memory.
type capture struct {
	hdr    http.Header
	buf    bytes.Buffer
	status int
	wrote  bool
}

func (c *capture) Header() http.Header { return c.hdr }
func (c *capture) WriteHeader(s int) {
	if !c.wrote {
		c.status = s
		c.wrote = true
	}
}
func (c *capture) Write(b []byte) (int, error) {
	c.wrote = true
	return c.buf.Write(b)
}

// budget returns how many kv_mirror rows may still be enqueued in the current rolling day.
func (w *Watcher) budget(ctx context.Context) (int, error) {
	var today int
	err := w.d.DB.QueryRow(ctx, `SELECT count(*) FROM egress_outbox WHERE kind = 'kv_mirror' AND created > now() - interval '1 day'`).Scan(&today)
	if err != nil {
		return 0, err
	}
	if today >= DailyWrites {
		return 0, nil
	}
	return DailyWrites - today, nil
}

// storedSha returns the sha recorded for a path's last mirror (flags row edgekv:<path>), "" if none.
func (w *Watcher) storedSha(ctx context.Context, path string) (string, error) {
	var s string
	err := w.d.DB.QueryRow(ctx, `SELECT s FROM flags WHERE k = $1`, flagKey(path)).Scan(&s)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return s, nil
}

// alreadyQueued reports whether an undone kv_mirror row for this path exists.
func (w *Watcher) alreadyQueued(ctx context.Context, path string) (bool, error) {
	var ok bool
	err := w.d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM egress_outbox WHERE kind = 'kv_mirror' AND done_at IS NULL AND payload->>'path' = $1)`, path).Scan(&ok)
	return ok, err
}

func flagKey(path string) string { return "edgekv:" + path }

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// KvMirrorResult is egress.ResultFn["kv_mirror"] (wired by Register and the integration package): it
// records a successful KV write by storing the written body's sha in flags edgekv:<path>, so the next
// sweep treats the file as mirrored. A skipped (dead-lettered) write carries no path change and is a
// no-op here.
func KvMirrorResult(ctx context.Context, d *core.Deps, q core.Q, payload, result json.RawMessage) error {
	var p kvPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	if !core.ValidFlagKey(flagKey(p.Path)) {
		return nil
	}
	var res struct {
		Skipped string `json:"skipped"`
	}
	if len(result) > 0 {
		json.Unmarshal(result, &res)
	}
	if res.Skipped != "" {
		return nil // nothing was written
	}
	body, err := base64.StdEncoding.DecodeString(p.Body)
	if err != nil {
		return nil // malformed payload: leave the sha untouched so the file is retried
	}
	sum := hex.EncodeToString(sha256Sum(body))
	_, err = q.Exec(ctx, `INSERT INTO flags (k, v, s) VALUES ($1, true, $2)
		ON CONFLICT (k) DO UPDATE SET v = true, s = EXCLUDED.s, updated = now()`, flagKey(p.Path), sum)
	return err
}
