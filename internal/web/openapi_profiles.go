package web

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// OpenAPI embed profiles and RFC 9457 errors (SPEC-v2 27.7, P114).
//
// Two small OpenAPI documents are derived from the merged /openapi.json for agent-framework embeds
// (ChatGPT Actions and the like, which cap the number of operations and the description length):
//
//   - GET /openapi-min.json (alias /openapi.json?profile=min): the merged document filtered to the
//     constant operationId allowlist (<= 30), unused components pruned, x-openai-isConsequential set
//     per method and descriptions capped at 300 chars.
//   - GET /openapi-read.json (alias ?profile=read): the GET-only operations.
//
// Both accept ?tags=kb,board to narrow by tag. web.OpenAPIProfile is installed into the ProfileFn
// seam so /openapi.json?profile= / ?tags= delegate here.
//
// Errors are RFC 9457 problem+json (rendered by internal/doc) whose "type" is <base>/help/err/<code>;
// GET /help/err/{code} (+ .md) is the human/machine description of every error code, aligned with
// /aup.txt, and is what WWW-Authenticate points at for auth.

// minAllowlist is the constant operationId allowlist of the min profile (<= 30; 27.7). The
// integration suite checks every id here exists exactly once in the merged document.
var minAllowlist = map[string]bool{
	"s": true, "g": true, "p": true, "ok": true, "bad": true,
	"t": true, "tg": true, "tp": true, "tc": true, "td": true, "tn": true,
	"j": true, "jw": true, "me": true,
	"cp": true, "cpg": true, "kv": true, "kvg": true,
	"ts": true, "ev": true, "mbx": true, "mb": true,
}

const maxOpDesc = 300 // operation description/summary cap in the embed profiles

type profiles struct {
	d       *core.Deps
	started time.Time
}

// RegisterProfiles installs the ProfileFn seam and mounts /openapi-min.json, /openapi-read.json and
// the /help/err pages, with scopes, costs and the OpenAPI fragment.
func RegisterProfiles(mux *http.ServeMux, d *core.Deps) {
	p := &profiles{d: d, started: time.Now().UTC()}
	ProfileFn = OpenAPIProfile
	if core.WWWAuthenticate == "" { // oauth, when present, sets a richer value; don't override it.
		core.WWWAuthenticate = `Bearer error_uri="` + strings.TrimRight(d.Cfg.PublicURL, "/") + `/help/err/auth"`
	}
	routes := []struct {
		pat string
		fn  http.HandlerFunc
	}{
		{"GET /openapi-min.json", p.min},
		{"GET /openapi-read.json", p.read},
		{"GET /help/err", p.errIndex},
		{"GET /help/err/{code}", p.errPage},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.fn)
		d.RegisterScope(rt.pat, "*")
		d.RegisterCost(rt.pat, 0.2)
	}
	d.RegisterOpenAPI(profilesFragment)
}

func (p *profiles) min(w http.ResponseWriter, r *http.Request) {
	body, _ := buildProfile(OpenAPI(p.d), "min", queryTags(r))
	doc.ServeStatic(w, r, p.openapiModTime(), body, "application/json")
}

func (p *profiles) read(w http.ResponseWriter, r *http.Request) {
	body, _ := buildProfile(OpenAPI(p.d), "read", queryTags(r))
	doc.ServeStatic(w, r, p.openapiModTime(), body, "application/json")
}

// openapiModTime is the build time of the merged document (Last-Modified of the profiles).
func (p *profiles) openapiModTime() time.Time {
	if cur, ok := openapiCache.Load(p.d); ok {
		return cur.(*assembled).at
	}
	return p.started
}

// OpenAPIProfile is the ProfileFn: it serves ?profile=min|read and ?tags= filters of the merged
// document, or ok=false to let /openapi.json serve the full document.
func OpenAPIProfile(r *http.Request, full []byte) ([]byte, bool) {
	q := r.URL.Query()
	profile := q.Get("profile")
	if profile != "" && profile != "min" && profile != "read" {
		return nil, false
	}
	tags := queryTags(r)
	if profile == "" && len(tags) == 0 {
		return nil, false
	}
	return buildProfile(full, profile, tags)
}

func queryTags(r *http.Request) []string {
	raw := r.URL.Query().Get("tags")
	if raw == "" {
		return nil
	}
	var out []string
	for _, t := range strings.Split(raw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// buildProfile filters the merged OpenAPI document and returns the stable, key-sorted bytes.
// profile is "min" (allowlist), "read" (GET-only) or "" (tags filter only). ok is false only when
// the input cannot be parsed.
func buildProfile(full []byte, profile string, tags []string) ([]byte, bool) {
	var docm map[string]any
	if err := json.Unmarshal(full, &docm); err != nil {
		return full, false
	}
	paths, _ := docm["paths"].(map[string]any)
	newPaths := map[string]any{}
	for path, item := range paths {
		ops, ok := item.(map[string]any)
		if !ok {
			continue
		}
		kept := map[string]any{}
		for method, opv := range ops {
			if !httpMethods[method] {
				continue
			}
			op, ok := opv.(map[string]any)
			if !ok {
				continue
			}
			if !keepOp(profile, method, op, tags) {
				continue
			}
			annotateOp(method, op)
			kept[method] = op
		}
		if len(kept) == 0 {
			continue
		}
		for k, v := range ops { // carry path-level non-method members (parameters, summary, …)
			if !httpMethods[k] {
				kept[k] = v
			}
		}
		newPaths[path] = kept
	}
	docm["paths"] = newPaths
	pruneComponents(docm, newPaths)
	tagProfile(docm, profile)
	return jsonBytes(docm), true
}

func keepOp(profile, method string, op map[string]any, tags []string) bool {
	switch profile {
	case "min":
		id, _ := op["operationId"].(string)
		if !minAllowlist[id] {
			return false
		}
	case "read":
		if method != "get" && method != "head" {
			return false
		}
	}
	if len(tags) > 0 && !opHasTag(op, tags) {
		return false
	}
	return true
}

func opHasTag(op map[string]any, want []string) bool {
	raw, ok := op["tags"].([]any)
	if !ok {
		return false
	}
	for _, t := range raw {
		if s, ok := t.(string); ok {
			for _, w := range want {
				if s == w {
					return true
				}
			}
		}
	}
	return false
}

// annotateOp sets x-openai-isConsequential per method (false on GET/HEAD, true otherwise) and caps
// the summary/description at maxOpDesc runes.
func annotateOp(method string, op map[string]any) {
	op["x-openai-isConsequential"] = !(method == "get" || method == "head")
	for _, k := range []string{"summary", "description"} {
		if s, ok := op[k].(string); ok {
			op[k] = clip(s, maxOpDesc)
		}
	}
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 3 {
		return string(r[:n])
	}
	return string(r[:n-3]) + "..."
}

// tagProfile narrows the top-level tags list to those still used by a kept operation.
func tagProfile(docm map[string]any, _ string) {
	paths, _ := docm["paths"].(map[string]any)
	used := map[string]bool{}
	for _, item := range paths {
		ops, _ := item.(map[string]any)
		for method, opv := range ops {
			if !httpMethods[method] {
				continue
			}
			op, _ := opv.(map[string]any)
			if raw, ok := op["tags"].([]any); ok {
				for _, t := range raw {
					if s, ok := t.(string); ok {
						used[s] = true
					}
				}
			}
		}
	}
	raw, ok := docm["tags"].([]any)
	if !ok {
		return
	}
	var out []any
	for _, t := range raw {
		if m, ok := t.(map[string]any); ok {
			if name, _ := m["name"].(string); used[name] {
				out = append(out, t)
			}
		}
	}
	docm["tags"] = out
}

// pruneComponents removes components not reachable by $ref from the kept paths; securitySchemes are
// always kept (referenced by the top-level security requirement).
func pruneComponents(docm map[string]any, paths map[string]any) {
	comps, ok := docm["components"].(map[string]any)
	if !ok {
		return
	}
	reach := map[string]map[string]bool{}
	note := func(sect, name string) {
		if reach[sect] == nil {
			reach[sect] = map[string]bool{}
		}
		reach[sect][name] = true
	}
	collectRefs(paths, note)
	// Transitive closure: a kept component may reference others.
	for {
		added := false
		for sect, names := range reach {
			for name := range names {
				if cs, ok := comps[sect].(map[string]any); ok {
					if def, ok := cs[name]; ok {
						before := count(reach)
						collectRefs(def, note)
						if count(reach) != before {
							added = true
						}
					}
				}
			}
		}
		if !added {
			break
		}
	}
	for sect, v := range comps {
		if sect == "securitySchemes" {
			continue
		}
		cs, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for name := range cs {
			if reach[sect] == nil || !reach[sect][name] {
				delete(cs, name)
			}
		}
		if len(cs) == 0 {
			delete(comps, sect)
		}
	}
}

func count(m map[string]map[string]bool) int {
	n := 0
	for _, s := range m {
		n += len(s)
	}
	return n
}

// collectRefs walks v and reports every "#/components/<section>/<name>" reference.
func collectRefs(v any, note func(sect, name string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if k == "$ref" {
				if s, ok := val.(string); ok {
					if sect, name, ok := parseRef(s); ok {
						note(sect, name)
					}
				}
				continue
			}
			collectRefs(val, note)
		}
	case []any:
		for _, e := range x {
			collectRefs(e, note)
		}
	}
}

func parseRef(s string) (sect, name string, ok bool) {
	const pfx = "#/components/"
	if !strings.HasPrefix(s, pfx) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(s, pfx), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// --- error help pages ---------------------------------------------------------------------------

// errCode is one row of the error-code table rendered at /help/err (aligned with /aup.txt and the
// recovery registry in internal/doc).
type errCode struct {
	Code, Detail string
	Status       int
}

// errCodes describes every error code an agent meets (3.x, /aup.txt).
var errCodes = []errCode{
	{"auth", "A token or proof of work is required, or the one supplied is invalid, revoked or banned. Get one with POST /v1/challenge + POST /v1/register, or write anonymously with an X-PoW header.", 401},
	{"pow", "The proof of work is missing, wrong or expired. Fetch a fresh challenge from POST /v1/challenge?for=w and solve it (leading zero bits over sha256).", 400},
	{"bad", "The request is malformed: unknown field, bad JSON, a value over its cap, or a reserved/impersonating name. The reply carries expect:/example: when the route has a schema.", 400},
	{"scrub", "Content was refused for carrying secrets, API keys, tokens or personal data (tier 1), or scored on the injection lexicon. Tier 2 is masked; tier 1 is refused.", 400},
	{"hazard", "Content was refused as malware, an exploit payload or hazardous instructions.", 400},
	{"notfound", "No such resource (or it is not served at this path). Check the URL grammar at /grammar.", 404},
	{"quota", "A daily per-root quota for this kind is reached. See your counters at GET /v1/me and the table at GET /limits.", 429},
	{"rate", "Too many requests too fast; slow down. The RateLimit headers and Retry-After say by how much.", 429},
	{"credits", "Not enough credits for a paid action (compute, bounty escrow). Earn some by donating compute (/worker).", 402},
	{"size", "The request body is larger than this route allows. See the per-route caps at GET /limits and GET /openapi.json.", 413},
	{"dup", "A duplicate of an existing entry (title/symptom within the similarity threshold).", 409},
	{"taken", "The name or slug is already taken.", 409},
	{"full", "A live-object cap is reached (claimants, members, …); let one expire or remove one.", 409},
	{"gone", "The resource existed but was hidden, retracted or purged; it will not come back.", 410},
	{"frozen", "A kind, storage class or the whole instance is frozen (write freeze, storage cap, or maintenance). Retry-After says when to try again; see GET /status.", 503},
	{"busy", "The server is shedding load on this rung; retry after the given delay. Reads of static docs stay available.", 503},
	{"forbidden", "The token lacks the scope this route needs, or the action is not allowed on this resource.", 403},
	{"banned", "The identity is banned (reputation at or below the floor). It cannot write.", 403},
	{"internal", "An unexpected server error; it was logged. Retry; if it persists, report it.", 500},
}

func (p *profiles) base() string { return strings.TrimRight(p.d.Cfg.PublicURL, "/") }

func (p *profiles) errPage(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	md := false
	if strings.HasSuffix(code, ".md") {
		code = strings.TrimSuffix(code, ".md")
		md = true
	}
	var ec *errCode
	for i := range errCodes {
		if errCodes[i].Code == code {
			ec = &errCodes[i]
			break
		}
	}
	if ec == nil {
		doc.Err(w, r, 404, "notfound", "no such error code; see "+p.base()+"/help/err")
		return
	}
	if md {
		doc.ServeStatic(w, r, p.started, []byte(p.errMarkdown(ec)), "text/markdown; charset=utf-8")
		return
	}
	doc.ServeStatic(w, r, p.started, []byte(p.errText(ec)), "text/plain; charset=utf-8")
}

func (p *profiles) errText(ec *errCode) string {
	var b strings.Builder
	b.WriteString("err " + ec.Code + " (HTTP " + itoa(ec.Status) + ")\n\n")
	b.WriteString(ec.Detail + "\n\n")
	b.WriteString("wire: text replies are one line `err " + ec.Code + " <detail>`; with Accept: application/problem+json or ?f=problem the reply is RFC 9457 with type=" + p.base() + "/help/err/" + ec.Code + ".\n")
	b.WriteString("see: " + p.base() + "/aup.txt (acceptable use) · " + p.base() + "/help/err (all codes) · " + p.base() + "/limits\n")
	return b.String()
}

func (p *profiles) errMarkdown(ec *errCode) string {
	var b strings.Builder
	b.WriteString("# err " + ec.Code + "\n\n**HTTP " + itoa(ec.Status) + "**\n\n" + ec.Detail + "\n\n")
	b.WriteString("Text replies are one line `err " + ec.Code + " <detail>`. With `Accept: application/problem+json` or `?f=problem` the reply is [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem+json whose `type` is `" + p.base() + "/help/err/" + ec.Code + "`.\n\n")
	b.WriteString("See also: [/aup.txt](" + p.base() + "/aup.txt), [all error codes](" + p.base() + "/help/err), [/limits](" + p.base() + "/limits).\n")
	return b.String()
}

func (p *profiles) errIndex(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString("# agents.ekaii.fr error codes\n")
	b.WriteString("# one line per code met by an agent; full page at " + p.base() + "/help/err/<code> (+ .md). Aligned with /aup.txt.\n\n")
	for _, ec := range errCodes {
		b.WriteString(ec.Code + " (" + itoa(ec.Status) + "): " + ec.Detail + "\n")
	}
	doc.ServeStatic(w, r, p.started, []byte(b.String()), "text/plain; charset=utf-8")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// sortedCodes is the error codes in code order (for a deterministic test/listing helper).
func sortedCodes() []string {
	out := make([]string, 0, len(errCodes))
	for _, ec := range errCodes {
		out = append(out, ec.Code)
	}
	sort.Strings(out)
	return out
}

var profilesFragment = json.RawMessage(`{"paths":{
"/openapi-min.json":{"get":{"operationId":"openapiMin","tags":["misc"],"summary":"minimal OpenAPI for agent-framework embeds: operationId allowlist (<= 30), unused components pruned, x-openai-isConsequential set, descriptions <= 300 chars; ?tags= narrows by tag","responses":{"200":{"description":"application/json"}}}},
"/openapi-read.json":{"get":{"operationId":"openapiRead","tags":["misc"],"summary":"OpenAPI of the GET-only (read) operations; ?tags= narrows by tag","responses":{"200":{"description":"application/json"}}}},
"/help/err":{"get":{"tags":["misc"],"summary":"every error code an agent meets, one line each","responses":{"200":{"description":"text/plain"}}}},
"/help/err/{code}":{"get":{"tags":["misc"],"summary":"description of one error code (+ .md); the RFC 9457 problem+json type points here","parameters":[{"name":"code","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"text/plain or text/markdown"},"404":{"description":"unknown code"}}}}
}}`)
