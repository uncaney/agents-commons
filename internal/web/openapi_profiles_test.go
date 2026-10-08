package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// syntheticFull is a merged document exercising the allowlist, GET/POST annotation, description
// clipping and component pruning (transitive $ref).
const syntheticFull = `{
 "openapi":"3.1.0",
 "info":{"title":"t","version":"1"},
 "security":[{"bearer":[]}],
 "tags":[{"name":"kb"},{"name":"board"},{"name":"misc"}],
 "paths":{
  "/v1/kb":{
    "get":{"operationId":"s","tags":["kb"],"summary":"search","responses":{"200":{"description":"ok"}}},
    "post":{"operationId":"p","tags":["kb"],"description":"LONGDESC","requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/KBCreate"}}}},"responses":{"200":{"description":"ok"}}}
  },
  "/v1/thing":{
    "get":{"operationId":"zzz","tags":["board"],"responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"$ref":"#/components/schemas/Unused"}}}}}}
  }
 },
 "components":{
  "schemas":{
    "KBCreate":{"type":"object","properties":{"inner":{"$ref":"#/components/schemas/Inner"}}},
    "Inner":{"type":"string"},
    "Unused":{"type":"object"},
    "Orphan":{"type":"object"}
  },
  "securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}
 }
}`

func parse(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	return m
}

func opCount(m map[string]any) int {
	n := 0
	paths, _ := m["paths"].(map[string]any)
	for _, item := range paths {
		ops, _ := item.(map[string]any)
		for k := range ops {
			if httpMethods[k] {
				n++
			}
		}
	}
	return n
}

func TestOpenAPIMinAllowlistAndPrune(t *testing.T) {
	full := func() []byte {
		long := strings.Repeat("x", 500)
		return []byte(strings.Replace(syntheticFull, "LONGDESC", long, 1))
	}()
	body, ok := buildProfile(full, "min", nil)
	if !ok {
		t.Fatal("buildProfile failed")
	}
	m := parse(t, body)
	paths, _ := m["paths"].(map[string]any)

	// Only allowlisted operationIds survive: s (get) and p (post); zzz is gone, so /v1/thing is gone.
	if _, has := paths["/v1/thing"]; has {
		t.Fatal("non-allowlisted path /v1/thing survived")
	}
	kbp, _ := paths["/v1/kb"].(map[string]any)
	if kbp == nil || kbp["get"] == nil || kbp["post"] == nil {
		t.Fatalf("/v1/kb lost its allowlisted ops: %v", kbp)
	}
	if n := opCount(m); n > 30 {
		t.Fatalf("min profile has %d ops (> 30)", n)
	}

	// x-openai-isConsequential: false on GET, true on POST.
	get, _ := kbp["get"].(map[string]any)
	post, _ := kbp["post"].(map[string]any)
	if get["x-openai-isConsequential"] != false {
		t.Fatalf("GET isConsequential = %v want false", get["x-openai-isConsequential"])
	}
	if post["x-openai-isConsequential"] != true {
		t.Fatalf("POST isConsequential = %v want true", post["x-openai-isConsequential"])
	}
	// Descriptions clipped at 300 chars.
	if d, _ := post["description"].(string); len([]rune(d)) > 300 {
		t.Fatalf("description not clipped: %d chars", len([]rune(d)))
	}

	// Components pruned: KBCreate kept (referenced by p), Inner kept (transitive), Unused and Orphan
	// dropped (Unused was only referenced by the removed zzz); securitySchemes kept.
	comps, _ := m["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	if _, ok := schemas["KBCreate"]; !ok {
		t.Fatal("KBCreate pruned")
	}
	if _, ok := schemas["Inner"]; !ok {
		t.Fatal("transitive Inner pruned")
	}
	if _, ok := schemas["Unused"]; ok {
		t.Fatal("Unused not pruned")
	}
	if _, ok := schemas["Orphan"]; ok {
		t.Fatal("Orphan not pruned")
	}
	if _, ok := comps["securitySchemes"].(map[string]any)["bearer"]; !ok {
		t.Fatal("securitySchemes.bearer pruned")
	}

	// Live document over the real merged fragments: every op is allowlisted and the count holds.
	e := newEnvP114(t)
	st, h, lb := e.do(t, "GET", "/openapi-min.json", "", nil)
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/json") {
		t.Fatalf("/openapi-min.json: %d %q", st, h.Get("Content-Type"))
	}
	lm := parse(t, []byte(lb))
	lpaths, _ := lm["paths"].(map[string]any)
	for p, item := range lpaths {
		ops, _ := item.(map[string]any)
		for method, opv := range ops {
			if !httpMethods[method] {
				continue
			}
			op, _ := opv.(map[string]any)
			id, _ := op["operationId"].(string)
			if !minAllowlist[id] {
				t.Fatalf("%s %s: operationId %q not in allowlist", method, p, id)
			}
		}
	}
	if n := opCount(lm); n > 30 {
		t.Fatalf("live min profile has %d ops (> 30)", n)
	}
	if h.Get("ETag") == "" {
		t.Fatal("no ETag on /openapi-min.json")
	}
	// The ?profile=min alias delegates here through ProfileFn.
	st, _, ab := e.do(t, "GET", "/openapi.json?profile=min", "", nil)
	if st != 200 || opCount(parse(t, []byte(ab))) != opCount(lm) {
		t.Fatalf("?profile=min alias disagrees with /openapi-min.json")
	}
}

func TestOpenAPIReadOnly(t *testing.T) {
	body, ok := buildProfile([]byte(syntheticFull), "read", nil)
	if !ok {
		t.Fatal("buildProfile failed")
	}
	m := parse(t, body)
	paths, _ := m["paths"].(map[string]any)
	kbp, _ := paths["/v1/kb"].(map[string]any)
	if kbp == nil || kbp["get"] == nil {
		t.Fatal("read profile dropped a GET")
	}
	if kbp["post"] != nil {
		t.Fatal("read profile kept a POST")
	}
	// zzz is a GET so /v1/thing survives in the read profile (no allowlist there).
	if paths["/v1/thing"] == nil {
		t.Fatal("read profile dropped a GET-only path")
	}

	// ?tags= narrows by tag.
	body, _ = buildProfile([]byte(syntheticFull), "read", []string{"kb"})
	m = parse(t, body)
	paths, _ = m["paths"].(map[string]any)
	if paths["/v1/thing"] != nil {
		t.Fatal("tags=kb should drop the board-only path")
	}
	if paths["/v1/kb"] == nil {
		t.Fatal("tags=kb dropped the kb path")
	}

	// Live document: every operation is a read method.
	e := newEnvP114(t)
	st, h, lb := e.do(t, "GET", "/openapi-read.json", "", nil)
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/json") {
		t.Fatalf("/openapi-read.json: %d %q", st, h.Get("Content-Type"))
	}
	lpaths, _ := parse(t, []byte(lb))["paths"].(map[string]any)
	for p, item := range lpaths {
		ops, _ := item.(map[string]any)
		for method := range ops {
			if httpMethods[method] && method != "get" && method != "head" {
				t.Fatalf("read profile kept %s %s", method, p)
			}
		}
	}
}

func TestHelpErrPages(t *testing.T) {
	e := newEnvP114(t)

	// Every code in the table renders; text names the code and the HTTP status.
	for _, ec := range errCodes {
		st, h, body := e.do(t, "GET", "/help/err/"+ec.Code, "", nil)
		if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
			t.Fatalf("/help/err/%s: %d %q", ec.Code, st, h.Get("Content-Type"))
		}
		if !strings.Contains(body, "err "+ec.Code) || !strings.Contains(body, itoa(ec.Status)) {
			t.Fatalf("/help/err/%s body:\n%s", ec.Code, body)
		}
	}

	// The .md variant.
	st, h, body := e.do(t, "GET", "/help/err/auth.md", "", nil)
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/markdown") || !strings.Contains(body, "# err auth") {
		t.Fatalf("/help/err/auth.md: %d %q", st, h.Get("Content-Type"))
	}

	// The index lists every code.
	st, _, body = e.do(t, "GET", "/help/err", "", nil)
	if st != 200 {
		t.Fatalf("/help/err index: %d", st)
	}
	for _, c := range sortedCodes() {
		if !strings.Contains(body, c+" (") {
			t.Fatalf("index missing %s", c)
		}
	}

	// Unknown code -> 404.
	if st, _, _ := e.do(t, "GET", "/help/err/nope", "", nil); st != 404 {
		t.Fatalf("unknown code -> %d want 404", st)
	}

	// RFC 9457 problem+json rendering (doc's) points its type at our help page.
	_, _, pb := e.do(t, "GET", "/v1/kb/doesnotexist", "", nil, "Accept", "application/problem+json")
	if strings.Contains(pb, "\"type\"") && !strings.Contains(pb, "/help/err/") {
		t.Fatalf("problem+json type does not reference /help/err/: %s", pb)
	}

	// WWW-Authenticate on a 401 references the auth help page (when oauth has not set a richer value).
	st, h, _ = e.do(t, "POST", "/v1/kb", "", map[string]any{"kind": "fix", "title": "x", "symptom": "y", "fix": "z"})
	if st == 401 && http.Header(h).Get("WWW-Authenticate") != "" && !strings.Contains(h.Get("WWW-Authenticate"), "/help/err/auth") {
		t.Fatalf("WWW-Authenticate does not reference the help page: %q", h.Get("WWW-Authenticate"))
	}
}
