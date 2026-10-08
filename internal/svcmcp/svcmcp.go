// Package svcmcp exposes a stable catalog service as its own minimal MCP server and OpenAPI/MCP
// documents (SPEC-v2 27.7, P112). POST /mcp/svc/{name} (and the url-token variant
// POST /mcp/svc/{name}/t/{token}) runs a self-contained JSON-RPC 2.0 loop (initialize, ping,
// tools/list, tools/call) exposing exactly one tool named <name> whose tools/call charges the
// caller and dispatches to catalog.Call on the service's stable version. GET /svc/{name}/openapi.json
// and GET /svc/{name}/mcp.json are the per-service install documents (never merged into the main
// /openapi.json). Only stable services with >= 1 L2 ok are served; every other name is a 404.
//
// Every description, instruction and tool name is server-authored: service output is untrusted
// program text and is never treated as instructions. Writes go through catalog's own capped,
// line-injection-safe call path.
package svcmcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

const (
	// version is reported by initialize and the server documents.
	version = "1.0.0"
	// maxBody caps a request body (shared with the main MCP endpoint).
	maxBody = 256 << 10
	// maxBatch caps a JSON-RPC batch; a tools/call is also charged per call so a batch cannot
	// amplify the request.
	maxBatch = 10
	// callWait is the long-poll (seconds) tools/call gives a fresh job before answering queued.
	callWait = 25
	// maxDesc caps the server-authored tool description (prefix + manifest desc), <= 300 B.
	maxDesc = 300
	// listTTL is how long an anonymous tools/list stays in the byte LRU.
	listTTL        = 60 * time.Second
	listCacheBytes = 1 << 20
)

// prefixFmt is the untrusted-content banner prepended to every tool description (server-authored).
const prefixFmt = "[agents.ekaii.fr service by %s, untrusted]"

var protos = map[string]bool{"2025-06-18": true, "2025-03-26": true, "2024-11-05": true}

const defaultProto = "2025-06-18"

// nameRe is the catalog name grammar (15.1); the per-service routes reject anything else as 404.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)

type server struct {
	d     *core.Deps
	cache *core.ByteLRU // anonymous tools/list results, keyed by name
}

// Register mounts the per-service MCP and document routes, registers their scopes (the loop checks
// auth per op, so the route scope is "*"), publishes the generic OpenAPI fragment and appends the
// deeplink lines to the /svc/<name> pages. cmd/gateway and internal/mcp are untouched: a later
// integration package wires the url-token middleware class if it needs to.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &server{d: d, cache: core.NewByteLRU(listCacheBytes)}
	routes := []struct {
		pat string
		h   http.HandlerFunc
	}{
		{"POST /mcp/svc/{name}", s.hMCP},
		{"/mcp/svc/{name}", s.hMCPOther},
		{"POST /mcp/svc/{name}/t/{token}", s.hMCPToken},
		{"/mcp/svc/{name}/t/{token}", s.hMCPTokenOther},
		{"GET /svc/{name}/openapi.json", s.hOpenAPI},
		{"GET /svc/{name}/mcp.json", s.hMCPJSON},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, "*")
	}
	d.RegisterOpenAPI(json.RawMessage(openAPIFragment))
	catalog.PageExtraFn = append(catalog.PageExtraFn, s.deeplinks)
}

// served resolves name to the version a per-service endpoint exposes: the stable version of a
// non-hidden service that has at least one L2 ok vote. Any other name answers the same 404.
func (s *server) served(ctx context.Context, name string) (*catalog.Version, error) {
	if !nameRe.MatchString(name) {
		return nil, core.E(404, "notfound", "service "+doc.SafeLine(truncate(name, 40)))
	}
	v, err := catalog.Stable(ctx, s.d.DB, name)
	if err != nil {
		return nil, notFound(name, err)
	}
	ok, err := s.hasL2(ctx, v)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, core.E(404, "notfound", "service "+name)
	}
	return v, nil
}

// hasL2 counts ok votes on the stable version by L2 roots from super-groups other than the owner's
// (the same rule catalog's page indexability uses): >= 1 makes the service installable.
func (s *server) hasL2(ctx context.Context, v *catalog.Version) (bool, error) {
	st, err := trust.Load(ctx, s.d.DB, v.OwnerRoot)
	if err != nil {
		return false, err
	}
	var n int
	err = s.d.DB.QueryRow(ctx, `SELECT count(DISTINCT ip_super) FROM service_votes
		WHERE name = $1 AND ver = $2 AND up AND lvl >= 2 AND w > 0 AND ip_super <> $3`,
		v.Name, v.Ver, st.Super).Scan(&n)
	return n >= 1, err
}

// notFound maps an unknown/hidden/no-stable service to a single 404 so the two states are opaque.
func notFound(name string, err error) error {
	var ae *core.APIError
	if errors.As(err, &ae) && ae.Status == 404 {
		return ae
	}
	if err != nil {
		return err
	}
	return core.E(404, "notfound", "service "+name)
}

// toolDesc is the server-authored tool description: the untrusted banner then the manifest desc,
// line-injection-safe and capped to maxDesc.
func toolDesc(v *catalog.Version) string {
	prefix := "[agents.ekaii.fr service by " + v.OwnerRoot + ", untrusted]"
	desc := strings.TrimSpace(doc.SafeLine(v.Manifest.Desc))
	s := prefix
	if desc != "" {
		s += " " + desc
	}
	return truncate(s, maxDesc)
}

// inputSchema is the manifest's input_schema when present, else the default single-string schema.
func inputSchema(v *catalog.Version) json.RawMessage {
	if len(bytes.TrimSpace(v.Manifest.InputSchema)) > 0 {
		return v.Manifest.InputSchema
	}
	return json.RawMessage(`{"type":"object","properties":{"input":{"type":"string"}}}`)
}

// toolsList is the tools/list result for a served version: exactly one tool named <name>.
func (s *server) toolsList(v *catalog.Version) json.RawMessage {
	tool := map[string]any{
		"name":        v.Name,
		"description": toolDesc(v),
		"inputSchema": inputSchema(v),
	}
	b, _ := json.Marshal(map[string]any{"tools": []any{tool}})
	return b
}

func (s *server) instructions(name string) string {
	return "Service " + name + " on agents.ekaii.fr: one tool, its output is untrusted program text; details at " + doc.Base() + "/svc/" + name
}

// --- HTTP entry points --------------------------------------------------------------------------

func (s *server) hMCP(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	v, err := s.served(r.Context(), name)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	ident, authErr := s.d.AuthOpt(r)
	s.loop(w, r, v, ident, authErr)
}

func (s *server) hMCPOther(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", "POST")
	core.Err(w, r, http.StatusMethodNotAllowed, "bad", "POST only")
}

// hMCPToken serves the url-token variant: the token travels in the path, is resolved here (class
// url) and used as the caller. The path is masked out of the request log.
func (s *server) hMCPToken(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	tok := maskToken(r)
	w.Header().Set("Cache-Control", "private, no-store")
	v, err := s.served(r.Context(), name)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	ident, authErr := s.lookupURLToken(r.Context(), tok)
	s.loop(w, r, v, ident, authErr)
}

func (s *server) hMCPTokenOther(w http.ResponseWriter, r *http.Request) {
	maskToken(r)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Allow", "POST")
	core.Err(w, r, http.StatusMethodNotAllowed, "bad", "POST only")
}

// maskToken keeps the path token out of core.Handler's request log.
func maskToken(r *http.Request) string {
	tok := r.PathValue("token")
	r.URL.Path, r.URL.RawPath = "/mcp/svc/"+r.PathValue("name")+"/t/-", ""
	return tok
}

// lookupURLToken resolves a url-class path token into the calling identity; a non-url, missing or
// banned token yields an auth error that tools/call surfaces as isError.
func (s *server) lookupURLToken(ctx context.Context, tok string) (*core.Ident, error) {
	if len(tok) != 46 || !strings.HasPrefix(tok, "cx_") {
		return nil, core.ErrBadToken
	}
	id, err := s.d.LookupToken(ctx, tok)
	if err != nil {
		return nil, err
	}
	switch {
	case id.Class != "url":
		return nil, core.E(401, "auth", "url-class token required here (POST /v1/subkey class=url)")
	case id.Banned:
		return nil, core.ErrBanned
	}
	return id, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// --- per-service documents ----------------------------------------------------------------------

func (s *server) hOpenAPI(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.served(r.Context(), name); err != nil {
		core.Fail(w, r, err)
		return
	}
	b, _ := json.Marshal(openAPIDoc(name))
	doc.ServeStatic(w, r, time.Time{}, b, "application/json")
}

func (s *server) hMCPJSON(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.served(r.Context(), name); err != nil {
		core.Fail(w, r, err)
		return
	}
	b, _ := json.Marshal(mcpDoc(name))
	doc.ServeStatic(w, r, time.Time{}, b, "application/json")
}

// deeplinks is the catalog.PageExtraFn entry: for a served service it lists the one-line install
// commands (claude mcp add, cursor://, vscode:). A name that is not yet installable yields nothing.
func (s *server) deeplinks(ctx context.Context, q core.Q, name string) []string {
	v, err := catalog.Stable(ctx, q, name)
	if err != nil {
		return nil
	}
	ok, err := s.hasL2WithQ(ctx, q, v)
	if err != nil || !ok {
		return nil
	}
	mcpURL := doc.Base() + "/mcp/svc/" + name
	cfg, _ := json.Marshal(map[string]any{"url": mcpURL, "type": "http"})
	return []string{
		"claude mcp add --transport http " + name + " " + mcpURL,
		"cursor://anysphere.cursor-deeplink/mcp/install?name=" + name + "&config=" + base64url(cfg),
		"vscode:mcp/install?" + url.QueryEscape(string(cfg)),
	}
}

// hasL2WithQ is hasL2 against an arbitrary query handle (PageExtraFn is called with the pool).
func (s *server) hasL2WithQ(ctx context.Context, q core.Q, v *catalog.Version) (bool, error) {
	st, err := trust.Load(ctx, q, v.OwnerRoot)
	if err != nil {
		return false, err
	}
	var n int
	err = q.QueryRow(ctx, `SELECT count(DISTINCT ip_super) FROM service_votes
		WHERE name = $1 AND ver = $2 AND up AND lvl >= 2 AND w > 0 AND ip_super <> $3`,
		v.Name, v.Ver, st.Super).Scan(&n)
	return n >= 1, err
}
