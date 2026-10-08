package web

import (
	"net/http"
	"os"

	"ekaii.fr/commons/internal/doc"
)

// registryKey is the MCP registry publisher key: flag mcp_registry_key (set live by the
// operator) or the MCP_REGISTRY_KEY environment variable.
func (s *srv) registryKey() string {
	if k := s.d.FlagStr("mcp_registry_key"); k != "" {
		return k
	}
	return os.Getenv("MCP_REGISTRY_KEY")
}

// wellKnown serves one document of the bundle owned by web (9.1). Every body comes from the
// Descriptor; the seams (A2ACardFn, CardSigFn) are read per request so they may be set after
// Register. ServeStatic gives ETag/304, Last-Modified and the public cache policy.
func (s *srv) wellKnown(wk WellKnownDoc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		switch wk.Path {
		case "/.well-known/agent.json", "/.well-known/agent-card.json":
			body = jsonBytes(s.desc.AgentCard())
		case "/.well-known/mcp.json":
			body = jsonBytes(s.desc.MCPCard())
		case "/.well-known/mcp/server.json":
			body = jsonBytes(s.desc.ServerJSON())
		case "/.well-known/api-catalog":
			body = jsonBytes(s.desc.APICatalog())
		case "/.well-known/security.txt":
			body = []byte(s.desc.SecurityTxt(s.started.AddDate(1, 0, 0)))
		case "/.well-known/ai-plugin.json":
			body = jsonBytes(s.desc.AIPlugin())
		case "/.well-known/mcp-registry-auth":
			txt, ok := s.desc.RegistryAuth(s.registryKey())
			if !ok {
				doc.Err(w, r, 404, "notfound", "no registry key published")
				return
			}
			body = []byte(txt)
		default:
			doc.Err(w, r, 404, "notfound", "not served here")
			return
		}
		doc.ServeStatic(w, r, s.started, body, wk.Type)
	}
}
