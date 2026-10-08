package oauth

import (
	"net/http"
	"net/url"
	"strings"

	"ekaii.fr/commons/internal/core"
)

// MCPHandler serves the MCP endpoint behind POST /mcp/t/{token} (mcp.URLTokenHandler, set by the
// integration package). The route checks the token (class url, within URLScopes), injects it as
// `Authorization: Bearer` and forwards the request with path /mcp; while nil the route answers 503.
var MCPHandler http.Handler

// URLScopes is the scope ceiling of a url-class token on /mcp/t (19.4 plus the 27.2 read scopes):
// a token carrying anything else is refused there, so a leaked URL can never reach credits, mail
// bodies or the tree.
var URLScopes = []string{"kb:r", "kb:w", "t:r", "t:w", "n:w", "cp:r", "kv:r", "mb:env", "ev:r", "me:r"}

// URLScopeOK reports whether a url-class token's scope set stays within URLScopes (nil, meaning
// every scope, is refused).
func URLScopeOK(scopes []string) bool {
	if scopes == nil {
		return false
	}
	for _, s := range scopes {
		if !core.ScopeAllowed(URLScopes, s) {
			return false
		}
	}
	return true
}

// maskPath keeps the path token out of the request log core.Handler writes when the handler returns.
func maskPath(r *http.Request) string {
	tok := r.PathValue("token")
	r.URL.Path, r.URL.RawPath = "/mcp/t/-", ""
	return tok
}

// mcpTokenOther answers every non-POST method on /mcp/t/{token} like /mcp does (405, Allow: POST).
func (s *svc) mcpTokenOther(w http.ResponseWriter, r *http.Request) {
	maskPath(r)
	noStore(w)
	w.Header().Set("Allow", "POST")
	core.Err(w, r, http.StatusMethodNotAllowed, "bad", "POST only")
}

// mcpToken is POST /mcp/t/{token} for URL-only clients: the url-class token travels in the path.
func (s *svc) mcpToken(w http.ResponseWriter, r *http.Request) {
	tok := maskPath(r)
	noStore(w)
	if len(tok) != 46 || !strings.HasPrefix(tok, "cx_") {
		core.Fail(w, r, core.ErrBadToken)
		return
	}
	id, err := s.d.LookupToken(r.Context(), tok)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	switch {
	case id.Class != "url":
		core.Fail(w, r, core.E(401, "auth", "url-class token required here (POST /v1/subkey class=url); other tokens go in the Authorization header of POST /mcp"))
	case id.Banned:
		core.Fail(w, r, core.ErrBanned)
	case !URLScopeOK(id.Scopes):
		core.Fail(w, r, core.E(403, "scope", "url tokens on /mcp/t may hold only "+strings.Join(URLScopes, " ")))
	case MCPHandler == nil:
		core.Fail(w, r, core.E(503, "unavailable", "mcp not wired"))
	default:
		r2 := r.Clone(r.Context())
		r2.URL = &url.URL{Path: "/mcp", RawQuery: r.URL.RawQuery}
		r2.RequestURI = ""
		r2.Header.Set("Authorization", "Bearer "+tok)
		MCPHandler.ServeHTTP(w, r2)
	}
}
