package integration

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"ekaii.fr/commons/internal/core"
)

// muxPatterns walks the net/http.ServeMux routing tree by reflection and returns every registered
// pattern string (e.g. "GET /v1/me", "/", "GET /{$}"). ServeMux exposes no public enumeration, so
// the route table is read straight from its tree: this is the authoritative list of what the gateway
// actually serves, the ground truth the parity tests compare openapi + scopes against.
func muxPatterns(mux *http.ServeMux) []string {
	acc := func(v reflect.Value) reflect.Value {
		return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	}
	root := reflect.ValueOf(mux).Elem().FieldByName("tree")
	var out []string
	var walk func(n reflect.Value)
	walk = func(n reflect.Value) {
		if pat := acc(n.FieldByName("pattern")); !pat.IsNil() {
			out = append(out, pat.MethodByName("String").Call(nil)[0].String())
		}
		ch := n.FieldByName("children")
		sl := acc(ch.FieldByName("s"))
		for i := 0; i < sl.Len(); i++ {
			if v := acc(sl.Index(i).FieldByName("value")); !v.IsNil() {
				walk(v.Elem())
			}
		}
		if mp := acc(ch.FieldByName("m")); !mp.IsNil() {
			for _, k := range mp.MapKeys() {
				if v := mp.MapIndex(k); !v.IsNil() {
					walk(v.Elem())
				}
			}
		}
		for _, f := range []string{"multiChild", "emptyChild"} {
			if c := acc(n.FieldByName(f)); !c.IsNil() {
				walk(c.Elem())
			}
		}
	}
	walk(root)
	sort.Strings(out)
	return out
}

// splitPattern turns a mux pattern into (method, path). Methodless patterns ("/" catch-all) return
// an empty method.
func splitPattern(p string) (method, path string) {
	if i := strings.IndexByte(p, ' '); i >= 0 {
		return p[:i], p[i+1:]
	}
	return "", p
}

// openapiPath normalises a mux path to its OpenAPI path-template form: "/{$}" -> "/" and a trailing
// multi-wildcard "{x...}" -> "{x}" (OpenAPI has no multi syntax).
func openapiPath(path string) string {
	if path == "/{$}" {
		return "/"
	}
	for {
		i := strings.Index(path, "...}")
		if i < 0 {
			break
		}
		path = path[:i] + "}" + path[i+len("...}"):]
	}
	return path
}

var httpMethodSet = map[string]bool{"get": true, "head": true, "post": true, "put": true, "patch": true, "delete": true, "options": true, "trace": true}

// oaDoc is the subset of /openapi.json the parity tests read.
type oaDoc struct {
	Paths map[string]map[string]json.RawMessage `json:"paths"`
}

func openapiFor(t *testing.T) oaDoc {
	t.Helper()
	rec := httptest.NewRecorder()
	testMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /openapi.json: status %d", rec.Code)
	}
	var d oaDoc
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("parse /openapi.json: %v", err)
	}
	return d
}

// muxSlots maps each served (method, openapi-path) slot to the mux pattern that produced it, and
// reports any two distinct patterns that collapse onto the same slot (a real route-table collision).
func muxSlots(t *testing.T) (map[[2]string]string, []string) {
	t.Helper()
	slots := map[[2]string]string{}
	var collisions []string
	for _, pat := range muxPatterns(testMux) {
		method, path := splitPattern(pat)
		if method == "" {
			continue
		}
		key := [2]string{strings.ToLower(method), openapiPath(path)}
		if prev, ok := slots[key]; ok && prev != pat {
			collisions = append(collisions, prev+" & "+pat+" -> "+key[0]+" "+key[1])
			continue
		}
		slots[key] = pat
	}
	return slots, collisions
}

// concreteURL turns an OpenAPI path template into a concrete request path by replacing every {token}
// (and {token...}) segment with a sample value, so it can be routed against the live mux.
func concreteURL(p string) string {
	for {
		i := strings.IndexByte(p, '{')
		if i < 0 {
			break
		}
		j := strings.IndexByte(p[i:], '}')
		if j < 0 {
			break
		}
		p = p[:i] + "x" + p[i+j+1:]
	}
	if p == "" {
		p = "/"
	}
	return p
}

// TestRouteTableInOpenAPI asserts the route-table/OpenAPI parity the SPEC-v2 9.1 contract guarantees:
// (a) /openapi.json declares no fictional route — every path+method it lists is actually routed by
// the mux to a real handler (not the "/" catch-all); and (b) each is declared exactly once — no two
// mux routes collapse onto one OpenAPI slot, so every entry maps back to a single real handler. The
// reverse direction (every mux route present in /openapi.json) is deliberately NOT required: the SPEC
// keeps HTML pages, content-negotiation suffix aliases (.md/.txt/.json/...), the /.well-known/* alias
// set and group-internal routes out of the machine API schema (documented instead via /llms.txt,
// sitemaps and the ?profile= embeds, 9.1/9.2/27.7). See docs/FIXUP-LOG.md for the rationale.
func TestRouteTableInOpenAPI(t *testing.T) {
	oa := openapiFor(t)
	if _, collisions := muxSlots(t); len(collisions) > 0 {
		t.Fatalf("%d OpenAPI-slot collision(s) (two routes, one path+method):\n  %s", len(collisions), strings.Join(collisions, "\n  "))
	}
	var fictional []string
	for p, methods := range oa.Paths {
		url := concreteURL(p)
		for m := range methods {
			lm := strings.ToLower(m)
			if !httpMethodSet[lm] {
				continue // parameters/summary/etc. keys, not an HTTP method
			}
			_, matched := testMux.Handler(httptest.NewRequest(strings.ToUpper(lm), url, nil))
			if matched == "" || matched == "/" {
				fictional = append(fictional, strings.ToUpper(lm)+" "+p)
			}
		}
	}
	if len(fictional) > 0 {
		sort.Strings(fictional)
		t.Fatalf("%d OpenAPI entry(ies) the mux does not route to a real handler (openapi lies):\n  %s", len(fictional), strings.Join(fictional, "\n  "))
	}
}

// scopeOK reports whether a registered route scope is well-formed: "*" (the route checks per
// operation itself: MCP/A2A/public), a mintable scope in core's vocabulary (core.ValidScope, so a
// scoped subkey can actually be issued to reach the route), or one of the privileged full-only
// capabilities a scoped token is never minted with (only a full/root token reaches the route).
var privilegedScopes = map[string]bool{"admin": true, "keys": true, "ops": true, "rel": true}

func scopeOK(s string) bool {
	return s == "*" || core.ValidScope(s) || privilegedScopes[s]
}

// TestEveryRouteHasScope asserts every scope a route registers via d.RegisterScope (SPEC-v2 3.5) is
// well-formed: a route that registers a scope outside the vocabulary is unreachable by any token that
// could satisfy it (a scoped subkey can never hold an unknown scope, so auth 403s it against a
// non-"full" token) — exactly the silent cross-package wiring gap this package exists to catch. A
// missing registration is allowed (auth defaults such a route to "full"); a malformed one is not.
func TestEveryRouteHasScope(t *testing.T) {
	var bad []string
	for _, pat := range muxPatterns(testMux) {
		s, ok := testDeps.ScopeOf(pat)
		if !ok {
			continue // no scope registered -> auth requires a full token; a safe default, not a bug
		}
		if s == "" || !scopeOK(s) {
			bad = append(bad, pat+" -> "+strconv.Quote(s))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Fatalf("%d route(s) registered an unrecognised scope (unreachable by any scoped token):\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
}

// TestCatchAllShadowsNothing asserts the pages "/" catch-all and the router never shadow a specific
// route (SPEC-v2 8.2): for every concrete, method-qualified pattern, ServeMux must resolve a request
// to that handler and never fall through to the bare "/" catch-all.
func TestCatchAllShadowsNothing(t *testing.T) {
	var shadowed []string
	for _, pat := range muxPatterns(testMux) {
		method, path := splitPattern(pat)
		if method == "" || strings.ContainsAny(path, "{*") {
			continue // only concrete, method-qualified paths have a single ground-truth target
		}
		_, matched := testMux.Handler(httptest.NewRequest(method, path, nil))
		if matched == "/" || matched == "" {
			shadowed = append(shadowed, pat+" -> "+matched)
		}
	}
	if len(shadowed) > 0 {
		sort.Strings(shadowed)
		t.Fatalf("%d route(s) shadowed by the catch-all:\n  %s", len(shadowed), strings.Join(shadowed, "\n  "))
	}
}

// TestPublicMuxNoInternal asserts the public mux never exposes a courier-facing /internal/ route:
// those live on the separate egress listener (egress.Serve), never on the public ServeMux (SPEC-v2
// 1, 27.1).
func TestPublicMuxNoInternal(t *testing.T) {
	var leaked []string
	for _, pat := range muxPatterns(testMux) {
		if _, path := splitPattern(pat); strings.HasPrefix(path, "/internal/") || path == "/internal" {
			leaked = append(leaked, pat)
		}
	}
	if len(leaked) > 0 {
		t.Fatalf("internal route(s) on the public mux:\n  %s", strings.Join(leaked, "\n  "))
	}
}
