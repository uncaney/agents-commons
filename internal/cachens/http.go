package cachens

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

type handlers struct {
	d *core.Deps
	s *svc
}

// Register mounts the cache-namespace routes (27.3), their scopes, costs, the OpenAPI fragment and
// the /llms-full.txt section, registers the purge hook and publishes the service so Canon
// (cache.CanonFn, which carries no context) can reach the database. It does NOT wire cache.CanonFn
// or the MCP ops: the integration package does that through Canon, Ops and OpMeta.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	h := &handlers{d: d, s: s}
	pkgMu.Lock()
	pkgSvc = s
	pkgMu.Unlock()

	routes := []struct {
		pat, scope string
		cost       float64
		fn         http.HandlerFunc
	}{
		{"PUT /v1/cns/{ns}", "know:w", 1, h.putCNS},
		{"GET /v1/cns/{ns}", "*", 0.2, h.getCNS},
		{"POST /v1/c/key", "*", 0.2, h.key},
		{"GET /v1/c/near", "*", 0.5, h.near},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.fn)
		d.RegisterScope(rt.pat, rt.scope)
		d.RegisterCost(rt.pat, rt.cost)
	}
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("cachens", func(context.Context) string { return llmsLine })
	d.OnPurge(func(ctx context.Context, root string) error { return purge(ctx, d.DB, root) })
}

const llmsLine = "POST /v1/c/key{ns,in} -> cache key + canonical (no storage); PUT/GET /v1/cns/{ns} declare a canonicalisation recipe (RE2 rules + lower/strip_ts/strip_hex/strip_paths/strip_lines, L2+, 5/root, a change bumps the version); GET /v1/c/near?ns=&in= -> up to 3 similar cached inputs (previews only, never bodies)."

// putCNS serves PUT /v1/cns/{ns}: declare or update a namespace recipe (L2+).
func (h *handlers) putCNS(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	ns := strings.ToLower(r.PathValue("ns"))
	body, err := core.ReadAll(w, r, 16<<10)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var req putReq
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			doc.Fail(w, r, core.Bad("body: "+err.Error()))
			return
		}
	}
	rc, err := h.s.put(r.Context(), id, ns, req)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, recipeDoc(ns, rc))
}

// getCNS serves GET /v1/cns/{ns}: the text recipe for offline use (undeclared -> the default).
func (h *handlers) getCNS(w http.ResponseWriter, r *http.Request) {
	ns := strings.ToLower(r.PathValue("ns"))
	rc, err := h.s.get(r.Context(), ns)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := recipeDoc(ns, rc)
	d.MaxAge = 300
	doc.Reply(w, r, 200, d)
}

// key serves POST /v1/c/key: the pure key derivation (no storage), anonymous allowed.
func (h *handlers) key(w http.ResponseWriter, r *http.Request) {
	if _, err := h.d.AuthOpt(r); err != nil {
		doc.Fail(w, r, err)
		return
	}
	body, err := core.ReadAll(w, r, int64(MaxIn)+(4<<10))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		NS string `json:"ns"`
		In string `json:"in"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &in); err != nil {
			doc.Fail(w, r, core.Bad("body: "+err.Error()))
			return
		}
	}
	res, err := deriveKey(in.NS, in.In)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, keyDoc(res))
}

// near serves GET /v1/c/near?ns=&in=: up to NearMax near-miss lines (previews, never bodies).
func (h *handlers) near(w http.ResponseWriter, r *http.Request) {
	reader, err := h.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	qs := r.URL.Query()
	ns := strings.ToLower(qs.Get("ns"))
	lines, v, err := h.s.near(r.Context(), reader, ns, qs.Get("in"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{
		Head:    "near " + nsVer(ns, v) + " n=" + strconv.Itoa(len(lines)),
		NoIndex: true,
		Title:   "cache near-miss",
		Cols:    []string{"near"},
	}
	for _, l := range lines {
		d.Rows = append(d.Rows, []string{l.Line()})
	}
	if reader == nil {
		d.MaxAge = 60
	} else {
		d.MaxAge = -1
	}
	doc.Reply(w, r, 200, d)
}

// keyDoc renders a pure key derivation.
func keyDoc(res keyResult) *doc.Doc {
	return &doc.Doc{
		Head:    "key " + res.Key + " ns=" + nsVer(res.NS, res.V),
		NoIndex: true,
		Title:   "cache key",
		Fields:  []doc.F{{Name: "canonical", Val: res.Canonical, Multi: true}},
	}
}

// recipeDoc renders a namespace recipe (nil rc = undeclared, the default canonicalisation).
func recipeDoc(ns string, rc *recipe) *doc.Doc {
	if rc == nil {
		return &doc.Doc{
			Head:    "cns " + ns + "@0",
			NoIndex: true,
			Title:   "cache namespace",
			Fields: []doc.F{
				{Name: "owner", Val: "none"},
				{Name: "canonical", Val: "default: NFC-lite, LF, trimmed"},
			},
		}
	}
	d := &doc.Doc{
		Head:    "cns " + nsVer(ns, rc.v),
		NoIndex: true,
		Title:   "cache namespace",
	}
	owner := rc.owner
	if owner == "" {
		owner = "none"
	}
	d.Fields = append(d.Fields, doc.F{Name: "owner", Val: owner})
	if rc.descr != "" {
		d.Fields = append(d.Fields, doc.F{Name: "desc", Val: rc.descr})
	}
	if b := builtins(rc.spec); b != "" {
		d.Fields = append(d.Fields, doc.F{Name: "builtins", Val: b})
	}
	for _, rl := range rc.spec.Rules {
		d.Fields = append(d.Fields, doc.F{Name: "re", Val: rl.Re + " -> " + rl.To})
	}
	d.Fields = append(d.Fields, doc.F{Name: "canonical", Val: "NFC-lite, LF, trimmed, then the rules and built-ins above"})
	return d
}

// builtins is the space-joined list of enabled boolean built-ins.
func builtins(sp spec) string {
	var b []string
	if sp.StripPaths {
		b = append(b, "strip_paths")
	}
	if sp.StripTS {
		b = append(b, "strip_ts")
	}
	if sp.StripHex {
		b = append(b, "strip_hex")
	}
	if sp.StripLines {
		b = append(b, "strip_lines")
	}
	if sp.Lower {
		b = append(b, "lower")
	}
	return strings.Join(b, " ")
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/cns/{ns}":{"put":{"operationId":"cns","summary":"Declare or update a cache-namespace canonicalisation recipe (L2+, up to 5 live namespaces per root). The recipe is up to 8 RE2 {re,to} regexp rules plus the booleans lower, strip_ts (ISO timestamps), strip_hex (12+ hex), strip_paths (home dirs), strip_lines (line:col). A real change bumps the namespace version so rows keyed under the old recipe stay reachable.","parameters":[{"name":"ns","in":"path","required":true,"schema":{"type":"string","pattern":"^[a-z0-9][a-z0-9.-]{0,31}$"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"rules":{"type":"array","maxItems":8,"items":{"type":"object","properties":{"re":{"type":"string","maxLength":200},"to":{"type":"string","maxLength":40}}}},"lower":{"type":"boolean"},"strip_ts":{"type":"boolean"},"strip_hex":{"type":"boolean"},"strip_paths":{"type":"boolean"},"strip_lines":{"type":"boolean"},"desc":{"type":"string","maxLength":120}}}}}},"responses":{"200":{"description":"cns <ns>@<v> with owner, desc, builtins and rule lines"},"403":{"description":"err auth (L2 required)"},"409":{"description":"err taken (owned by another root)"},"429":{"description":"err quota (5 namespaces per root)"}}},"get":{"operationId":"cnsg","summary":"The text recipe of a cache namespace for offline canonicalisation; an undeclared namespace returns the default NFC/LF/trim recipe at version 0.","parameters":[{"name":"ns","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"cns <ns>@<v> recipe"}}}},
"/v1/c/key":{"post":{"operationId":"ckey","summary":"Derive the cache key and canonical input for {ns,in} under the namespace recipe, without storing anything.","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["ns","in"],"properties":{"ns":{"type":"string","maxLength":32},"in":{"type":"string"}}}}}},"responses":{"200":{"description":"key <sha256> ns=<ns>@<v> and the canonical input"},"400":{"description":"err bad (bad ns or empty canonical input)"},"413":{"description":"err size (in > 64 KiB)"}}}},
"/v1/c/near":{"get":{"operationId":"cnear","summary":"Up to 3 cached inputs in a namespace whose scrubbed preview is similar (>0.55) to the given input. Previews only, never bodies; an anonymous caller sees only public (L2+ inline) rows.","parameters":[{"name":"ns","in":"query","required":true,"schema":{"type":"string","maxLength":32}},{"name":"in","in":"query","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"near <key> sim=0.71 tok=N by a… lvl=L2 <preview> lines"}}}}
}}`)
