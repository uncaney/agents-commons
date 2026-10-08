package demand

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/egress"
	"ekaii.fr/commons/internal/know"
)

// Op is an MCP op (same service layer as the HTTP handlers).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5). `demand` is the ops-token import; `wanted`
// with kind q and `transparency` are public reads.
var OpMeta = map[string]core.OpMeta{
	"demand":       {Scope: "ops", Cost: 1, Mutating: true},
	"transparency": {Scope: "kb:r", Cost: 1},
}

// maxRender caps the rendition the internal route returns to the courier (pages are small).
const maxRender = 512 << 10

// internalOnce guards the single global registration of the /internal/render route.
var internalOnce sync.Once

type handlers struct {
	d   *core.Deps
	mux *http.ServeMux // the public mux, for the internal render route
}

// Register mounts POST /admin/demand (ops token), the public GET /transparency page, the
// bearer-only internal render route, the `fresh` sitemap child, the /wanted engines block, scopes,
// OpenAPI and the rank-weak + Bing-push janitor tasks. It edits no other package's routes.
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d: d, mux: mux}
	mux.HandleFunc("POST /admin/demand", d.OpsOnly(h.adminDemand))
	mux.HandleFunc("GET /transparency", h.transparency)
	d.RegisterScope("POST /admin/demand", "ops")
	d.RegisterCost("POST /admin/demand", 1)
	d.RegisterOpenAPI(openAPI)
	d.RegisterSitemap("fresh", func(ctx context.Context) ([]core.SitemapURL, error) { return freshSitemap(ctx, d.DB) })
	know.WantedExtraFn = func(ctx context.Context, q core.Q) []string { return WantedLines(ctx, q) }
	// The internal render route is global to the INTERNAL_LISTEN mux; register it once (production
	// calls Register once, tests build many Deps).
	internalOnce.Do(func() { egress.RegisterInternal("GET /internal/render", h.render) })
	if d.Janitor != nil {
		d.Janitor.Add("demand_rank_weak", func(ctx context.Context) error { return MarkWeak(ctx, d) })
		d.Janitor.Add("demand_bing_push", func(ctx context.Context) error { return OnIndexable(ctx, d) })
	}
}

// adminDemand serves POST /admin/demand {src, rows}: the operator's console import (ops token).
func (h *handlers) adminDemand(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Src  string `json:"src"`
		Rows []Row  `json:"rows"`
	}
	if err := core.Decode(w, r, int64(MaxRows*512+4096), &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	stored, dropped, err := Record(r.Context(), h.d.DB, in.Src, in.Rows)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.AdminArg(r, fmt.Sprintf("%s stored=%d dropped=%d", in.Src, stored, dropped))
	core.OK(w, r, fmt.Sprintf("ok demand src=%s stored=%d dropped=%d", in.Src, stored, dropped),
		map[string]any{"ok": true, "src": in.Src, "stored": stored, "dropped": dropped})
}

// transparency renders GET /transparency: a public, indexable, descriptive page of the demand the
// platform receives (monthly impressions/clicks and the top queries). Query strings are rendered
// line-safe; no identity or IP is ever involved.
func (h *handlers) transparency(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	totals, err := monthTotals(ctx, h.d.DB)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	stats, err := topQueries(ctx, h.d.DB, TopQueries)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{
		Head:      "transparency: what agents search for",
		Title:     "transparency: search demand",
		Desc:      "Monthly impressions, clicks and the top queries agents search for on the commons. No identities, no IP addresses: only aggregate search-console figures.",
		Canonical: "/transparency", Budget: 400,
		Fields: []doc.F{
			{Name: "month", Val: fmt.Sprintf("impressions=%d clicks=%d queries=%d (last 30 days)", totals.Impressions, totals.Clicks, totals.Queries)},
		},
		Cols: []string{"query", "engine", "impressions", "clicks", "position"},
	}
	for _, s := range stats {
		d.Rows = append(d.Rows, []string{doc.SafeLine(s.Q), s.Src,
			fmt.Sprintf("%d", s.Impressions), fmt.Sprintf("%d", s.Clicks), fmt.Sprintf("%.1f", s.Position)})
	}
	d.Next = []doc.Action{doc.GET("/wanted", "gaps agents asked for"), doc.GET("/kb/", "the knowledge base")}
	d.MaxAge = 300
	doc.Reply(w, r, 200, d)
}

// render serves GET /internal/render?url= on INTERNAL_LISTEN (bearer-only, never public): the exact
// full HTTP/1.1 response the courier base64-encodes into a Bing SubmitContent push. The url must be
// an absolute URL under PUBLIC_URL; the page is rendered through the public mux unchanged.
func (h *handlers) render(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	p, ok := h.underPublic(raw)
	if !ok {
		core.Err(w, r, 400, "bad", "url must be an absolute URL under PUBLIC_URL")
		return
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, p, nil)
	req.Header.Set("Accept", "text/html")
	h.mux.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = nil
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	var buf bytes.Buffer
	if err := resp.Write(&buf); err != nil {
		core.Err(w, r, 500, "internal", "render failed")
		return
	}
	b := buf.Bytes()
	if len(b) > maxRender {
		b = b[:maxRender]
	}
	hdr := w.Header()
	hdr.Set("Content-Type", "message/http")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("X-Robots-Tag", "noindex")
	w.WriteHeader(200)
	w.Write(b)
}

// underPublic reports whether raw is an absolute URL on the PUBLIC_URL origin and returns its
// path+query (what the public mux is asked for). Fragments, userinfo and a foreign host are refused.
func (h *handlers) underPublic(raw string) (string, bool) {
	if raw == "" || len(raw) > MaxPage || !doc.OneLine(raw) {
		return "", false
	}
	base, err := url.Parse(strings.TrimRight(h.d.Cfg.PublicURL, "/"))
	if err != nil || base.Host == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.Fragment != "" {
		return "", false
	}
	if !strings.EqualFold(u.Scheme, base.Scheme) || !strings.EqualFold(u.Host, base.Host) {
		return "", false
	}
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "", false
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p, true
}

// Ops are the MCP ops for the demand loop. The import op takes the ops scope; the reads mirror the
// HTTP text.
func Ops(d *core.Deps) map[string]Op {
	ops := map[string]Op{}
	ops["demand"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			Src  string `json:"src"`
			Rows []Row  `json:"rows"`
		}
		if len(a) > 0 && string(a) != "null" {
			if err := json.Unmarshal(a, &in); err != nil {
				return "", core.Bad("a: " + err.Error())
			}
		}
		stored, dropped, err := Record(ctx, d.DB, in.Src, in.Rows)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("ok demand src=%s stored=%d dropped=%d", in.Src, stored, dropped), nil
	}
	ops["transparency"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		totals, err := monthTotals(ctx, d.DB)
		if err != nil {
			return "", err
		}
		stats, err := topQueries(ctx, d.DB, TopQueries)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "transparency: impressions=%d clicks=%d queries=%d (last 30 days)", totals.Impressions, totals.Clicks, totals.Queries)
		for _, s := range stats {
			fmt.Fprintf(&b, "\nq %s %s impr=%d clicks=%d pos=%.1f", doc.SafeLine(s.Q), s.Src, s.Impressions, s.Clicks, s.Position)
		}
		return b.String(), nil
	}
	return ops
}
