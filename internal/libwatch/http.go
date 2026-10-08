package libwatch

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

type svc struct {
	d         *core.Deps
	anonCache *core.ByteLRU
	probeC    *core.ByteLRU
}

// Register mounts the libwatch routes (27.3), their scopes and costs, the OpenAPI fragment, the
// llms-full section, the storage class, the alert and release janitors, the export-me writer, the
// purge hook and the resume section. Routes and MCP ops only: a later integration package wires
// cmd/gateway and internal/mcp.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d, anonCache: core.NewByteLRU(8 << 20), probeC: core.NewByteLRU(8 << 20)}
	routes := []struct {
		pat, scope string
		cost       float64
		fn         http.HandlerFunc
	}{
		{"POST /v1/env", "env:w", 1, s.post},
		{"GET /v1/env", "env:r", 0.2, s.list},
		{"GET /v1/env/{name}", "env:r", 1, s.get},
		{"PUT /v1/env/{name}", "env:w", 1, s.put},
		{"GET /v/env", "", 2, s.anon},
		{"GET /cutoff/probe", "", 1, s.probe},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.fn)
		if rt.scope != "" {
			d.RegisterScope(rt.pat, rt.scope)
		}
		d.RegisterCost(rt.pat, rt.cost)
	}
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("libwatch", func(context.Context) string { return llmsText })
	d.StorageClass("libwatch", StorageCap, `SELECT pg_total_relation_size('env_manifests') + pg_total_relation_size('lib_releases')`)
	d.Janitor.Add("libwatch_alerts", hourly("libwatch_alerts", func(ctx context.Context) error { return AlertJanitor(ctx, d.DB) }))
	d.Janitor.Add("libwatch_releases", hourly("libwatch_releases", func(ctx context.Context) error { return FillLibReleases(ctx, d.DB) }))
	d.OnPurge(func(ctx context.Context, root string) error { return purge(ctx, d.DB, root) })
	d.OnExport("libwatch", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.OnResume(func(ctx context.Context, root string) []string { return resumeLines(ctx, d.DB, root) })
}

// hourly runs fn at most once per hour per instance (the janitor ticks every 30 s).
func hourly(name string, fn func(ctx context.Context) error) func(ctx context.Context) error {
	var last time.Time
	return func(ctx context.Context) error {
		if time.Since(last) < time.Hour {
			return nil
		}
		last = time.Now()
		return fn(ctx)
	}
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// writeText emits a plain-text body; writeReport also offers JSON when asked.
func writeText(w http.ResponseWriter, r *http.Request, status int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, text)
}

func (rep *report) json() map[string]any {
	rows := make([]map[string]any, 0, len(rep.lines))
	for _, l := range rep.lines {
		rows = append(rows, map[string]any{"key": l.Key, "have": l.Have, "latest": l.Latest,
			"brk": l.Brk, "sec": l.Sec, "eol": l.Eol, "newest": l.Newest})
	}
	return map[string]any{"name": rep.name, "libs": rep.total, "known": rep.known, "drift": rep.cnt, "rows": rows}
}

func replyReport(w http.ResponseWriter, r *http.Request, rep *report) {
	if core.WantJSON(r) {
		core.JSON(w, 200, rep.json())
		return
	}
	writeText(w, r, 200, rep.Text())
}

// --- POST /v1/env ---

func (s *svc) post(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if s.d.Frozen("write") {
		doc.Fail(w, r, core.Frozen("write"))
		return
	}
	format := strings.TrimSpace(r.URL.Query().Get("fmt"))
	if format == "" {
		format = "env"
	}
	name, err := cleanName(r.URL.Query().Get("name"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	body, err := core.ReadAll(w, r, MaxBody)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	deps, err := ParseFormat(format, body)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	entries := resolve(r.Context(), s.d.DB, format, deps)
	if err := storeManifest(r.Context(), s.d, id.Root, name, entries); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := buildReport(r.Context(), s.d.DB, name, entries, r.URL.Query().Get("all") == "1", false)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	replyReport(w, r, rep)
}

// --- GET /v1/env (list) ---

func (s *svc) list(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	rows, err := s.d.DB.Query(r.Context(), `SELECT name, jsonb_array_length(libs), alerts, updated
		FROM env_manifests WHERE root = $1 ORDER BY name`, id.Root)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	defer rows.Close()
	d := &doc.Doc{Head: "env manifests", NoIndex: true, Cols: []string{"name", "libs", "alerts", "updated"}}
	for rows.Next() {
		var name string
		var n int
		var alerts bool
		var upd time.Time
		if err := rows.Scan(&name, &n, &alerts, &upd); err != nil {
			doc.Fail(w, r, err)
			return
		}
		d.Rows = append(d.Rows, []string{name, strconv.Itoa(n), boolWord(alerts), core.Date(upd)})
	}
	d.Head = "env manifests=" + strconv.Itoa(len(d.Rows))
	d.Next = []doc.Action{doc.POST("/v1/env?fmt=pkg", "post a manifest")}
	doc.Reply(w, r, 200, d)
}

func boolWord(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// --- GET /v1/env/{name} ---

func (s *svc) get(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	name, err := cleanName(r.PathValue("name"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	entries, _, err := loadManifest(r.Context(), s.d.DB, id.Root, name)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := buildReport(r.Context(), s.d.DB, name, entries, r.URL.Query().Get("all") == "1", false)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	replyReport(w, r, rep)
}

// --- PUT /v1/env/{name} ---

type putIn struct {
	Alerts *bool `json:"alerts"`
}

func (s *svc) put(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	name, err := cleanName(r.PathValue("name"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in putIn
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if in.Alerts == nil {
		doc.Fail(w, r, core.Bad("alerts required"))
		return
	}
	if err := setAlerts(r.Context(), s.d.DB, id.Root, name, *in.Alerts); err != nil {
		doc.Fail(w, r, err)
		return
	}
	out := "ok " + name + " alerts=" + boolWord(*in.Alerts)
	if core.WantJSON(r) {
		core.JSON(w, 200, map[string]any{"ok": true, "name": name, "alerts": *in.Alerts})
		return
	}
	doc.TailStatus(w, r, 200, out, doc.GET("/v1/env/"+name, ""))
}

// --- GET /v/env (anonymous) ---

func (s *svc) anon(w http.ResponseWriter, r *http.Request) {
	libsParam := strings.TrimSpace(r.URL.Query().Get("libs"))
	if libsParam == "" {
		doc.Fail(w, r, core.Bad("libs required (a@1,b@2, <= 20)"))
		return
	}
	deps, _ := ParseFormat("env", []byte(libsParam))
	if len(deps) > MaxAnonLibs {
		doc.Fail(w, r, core.Bad("at most 20 libs"))
		return
	}
	ck := "env\x00" + libsParam + "\x00" + r.URL.Query().Get("all")
	if b, ok := s.anonCache.Get(ck); ok {
		writeText(w, r, 200, string(b))
		return
	}
	entries := resolve(r.Context(), s.d.DB, "env", deps)
	rep, err := buildReport(r.Context(), s.d.DB, "", entries, r.URL.Query().Get("all") == "1", true)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	text := rep.Text()
	s.anonCache.Put(ck, []byte(text), 60*time.Second)
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeText(w, r, 200, text)
}

// --- GET /cutoff/probe ---

func (s *svc) probe(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	seed := strings.TrimSpace(qv.Get("seed"))
	if seed == "" || len(seed) > 128 {
		doc.Fail(w, r, core.Bad("seed required (<= 128 chars)"))
		return
	}
	day := time.Now().UTC().Truncate(24 * time.Hour)
	ans := strings.TrimSpace(qv.Get("a"))
	if ans == "" {
		s.probeList(w, r, seed, qv.Get("n"), day)
		return
	}
	s.probeAnswer(w, r, seed, ans, qv.Get("save") == "1", day)
}

func (s *svc) sample(ctx context.Context, seed string, n int, day time.Time) ([]ProbeItem, error) {
	return probeSample(ctx, s.d.DB, s.d.Cfg.ServerSecret, seed, n, day)
}

func (s *svc) probeList(w http.ResponseWriter, r *http.Request, seed, nStr string, day time.Time) {
	n := 10
	if nStr != "" {
		v, err := strconv.Atoi(nStr)
		if err != nil {
			doc.Fail(w, r, core.Bad("n must be an integer"))
			return
		}
		n = v
	}
	items, err := s.sample(r.Context(), seed, n, day)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	noStore(w)
	writeText(w, r, 200, listText(seed, items))
}

func (s *svc) probeAnswer(w http.ResponseWriter, r *http.Request, seed, ans string, save bool, day time.Time) {
	answers := parseAnswers(ans)
	// The answers index the real+decoy list, so the real count is the total minus the decoys.
	nReal := len(answers) - probeDecoys
	if nReal < probeMinN {
		nReal = probeMinN
	}
	if nReal > probeMaxN {
		nReal = probeMaxN
	}
	items, err := s.sample(r.Context(), seed, nReal, day)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	est := estimate(items, answers)
	noStore(w)
	if save && est.Cutoff != "?" {
		if id, _ := s.d.AuthOpt(r); id != nil {
			if _, err := s.d.DB.Exec(r.Context(), `UPDATE identities SET cutoff = $2 WHERE id = $1`, id.Root, est.Cutoff); err != nil {
				doc.Fail(w, r, err)
				return
			}
		}
	}
	writeText(w, r, 200, est.Text()+"\n")
}
