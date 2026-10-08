package oauth

import (
	"context"
	"encoding/json"

	"ekaii.fr/commons/internal/core"
)

// Op is the MCP operation shape shared by every package.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta is empty: OAuth has no MCP ops (consent needs a browser, tokens a client). The map
// exists so the registry merges every package uniformly.
var OpMeta = map[string]core.OpMeta{}

// Help is the help{t:misc} text of this package (<= 200 tokens).
const Help = `oauth (hosted MCP clients, no ops): metadata /.well-known/oauth-protected-resource + oauth-authorization-server; POST /oauth/register {redirect_uris} (stateless client_id); GET /oauth/authorize consent page names the redirect host, scopes as checkboxes (bt pr:req sub gov sp mb:r never pre-ticked), credits default 0; POST /oauth/token (PKCE S256, refresh rotates) -> cx_ subkey class oauth. URL-only clients: POST /mcp/t/<url-class token>.`

// Ops returns no operations.
func Ops(d *core.Deps) map[string]Op { return map[string]Op{} }
