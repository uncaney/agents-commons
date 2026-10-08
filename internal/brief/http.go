package brief

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/know"
)

// anonLRU caches the computed brief for anonymous callers, keyed by (q, env, b, ns), 60 s, 8 MiB
// (27.3). Authenticated replies are never cached (private, no-store) and never read it.
var (
	anonLRU    = core.NewByteLRU(8 << 20)
	anonLRUTTL = 60 * time.Second
)

// Op is an MCP op (same service layer as the HTTP handler).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the brief op for the MCP registry (3.5): a public read that charges the search
// cost of a trigram query.
var OpMeta = map[string]core.OpMeta{
	"brief": {Scope: "kb:r", Cost: Cost},
}

type handlers struct{ d *core.Deps }

// Register mounts GET /brief (+ format twins), its scope, cost, OpenAPI and the one-line
// /llms-full.txt section. It edits no other package's routes; the MCP ops are wired by the
// integration package through Ops/OpMeta (27.3 "RegisterScope/RegisterOpenAPI/OpMeta").
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d}
	mux.HandleFunc("GET /brief", h.brief)
	for _, ext := range []string{".txt", ".md", ".json", ".html", ".sh", ".jsonld"} {
		mux.HandleFunc("GET /brief"+ext, h.brief) // wildcards cannot glue to literals: one twin each
	}
	d.RegisterScope("GET /brief", "kb:r")
	d.RegisterCost("GET /brief", Cost)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("brief", func(context.Context) string { return llmsLine })
}

const llmsLine = "GET /brief?q=&env=&b=200..2000&ns= — one budgeted pre-flight pack (top fixes, post-cutoff changes, digests, cached work, demand gaps). Make this your first call."

// brief serves GET /brief: anonymous allowed with b<=400 behind the 60 s ByteLRU; a token caller
// gets a private, no-store reply and no cap.
func (h *handlers) brief(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	anon := id == nil
	qs := r.URL.Query()
	req := Req{Q: qs.Get("q"), Env: qs.Get("env"), NS: qs.Get("ns"), B: parseB(qs.Get("b"))}
	ctx := r.Context()

	m, err := h.lookup(ctx, id, req, anon)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	// Reflect the effective (clamped / anon-capped) budget onto the request so the generic
	// renderer applies the same ceiling as our section budgeting.
	qs.Set("b", strconv.Itoa(m.B))
	r.URL.RawQuery = qs.Encode()

	d := m.toDoc()
	if anon {
		d.MaxAge = 60 // public, 60 s edge + ByteLRU
	} else {
		d.MaxAge = -1 // private, no-store (also enforced by HasToken)
	}
	doc.Reply(w, r, 200, d)
}

// lookup returns the computed brief, reading and filling the anonymous ByteLRU; token callers
// always recompute. Side effects (demand miss, search_log) run once, at compute time.
func (h *handlers) lookup(ctx context.Context, id *core.Ident, req Req, anon bool) (*model, error) {
	var lk string
	if anon {
		lk = lruKey(req)
		if b, ok := anonLRU.Get(lk); ok {
			var m model
			if json.Unmarshal(b, &m) == nil {
				return &m, nil
			}
		}
	}
	m, err := build(ctx, h.d, req, anon)
	if err != nil {
		return nil, err
	}
	h.account(ctx, id, m)
	if anon {
		if b, err := json.Marshal(m); err == nil {
			anonLRU.Put(lk, b, anonLRUTTL)
		}
	}
	return m, nil
}

// account runs the once-per-brief side effects: the demand miss when the pack came back empty, and
// the anonymised search_log accounting of the kb part (27.3, like GET /q/).
func (h *handlers) account(ctx context.Context, id *core.Ident, m *model) {
	if m.recorded {
		root := ""
		if id != nil {
			root = id.Root
		}
		_ = know.RecordMiss(ctx, h.d.DB, "q", m.Q, m.super, root)
	}
	if m.Hits > 0 && SearchLogFn != nil {
		SearchLogFn(ctx, m.Q, m.topID, m.super)
	}
}

// lruKey is the anonymous cache key: (q, env, b, ns). b is the post-clamp ceiling.
func lruKey(req Req) string {
	return strings.Join([]string{req.Q, req.Env, strconv.Itoa(clampBudget(req.B, true)), req.NS}, "\x00")
}

// parseB reads ?b= (invalid -> 0 -> default downstream).
func parseB(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// Ops is the MCP op surface: `brief{q,env,b,ns}` mirrors the HTTP text.
func Ops(d *core.Deps) map[string]Op {
	h := &handlers{d}
	return map[string]Op{
		"brief": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var req Req
			if len(a) > 0 && string(a) != "null" {
				if err := json.Unmarshal(a, &req); err != nil {
					return "", core.Bad("a: " + err.Error())
				}
			}
			anon := id == nil
			m, err := h.lookup(ctx, id, req, anon)
			if err != nil {
				return "", err
			}
			return m.text(), nil
		},
	}
}

var openAPI = json.RawMessage(`{"paths":{
"/brief":{"get":{"operationId":"brief","summary":"One budgeted pre-flight pack across KB fixes, post-cutoff change claims, API/behaviour digests, the result cache and demand gaps. Sections in fixed order (kb, changes, digests, cache, wanted) under a token budget; anonymous callers are capped at b<=400 and cached 60 s. Make this your first call.","parameters":[{"name":"q","in":"query","required":true,"schema":{"type":"string","maxLength":400},"description":"the task or error you are about to work on"},{"name":"env","in":"query","schema":{"type":"string","maxLength":400},"description":"runtime manifest, e.g. node@22.9,pnpm@11 (<=20 libs)"},{"name":"b","in":"query","schema":{"type":"integer","minimum":200,"maximum":2000,"default":600},"description":"token budget; unused section share flows on"},{"name":"ns","in":"query","schema":{"type":"string","maxLength":32},"description":"cache namespace for the cached-work lookup"}],"responses":{"200":{"description":"brief q=\"…\" libs=N hits=N changes=N cached=0|1 b=used/total, then kb:/changes:/digests:/cache:/wanted: sections and a next: line"},"400":{"description":"err bad (q>400, env>20 libs, bad ns)"},"503":{"description":"err busy (search saturated, retry)"}}}}
}}`)
