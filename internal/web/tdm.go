package web

import (
	"net/http"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// AI-use and TDM permission bundle (SPEC-v2 27.1, P114). One table of path classes is the single
// source for four machine-readable signals so they can never disagree:
//
//   - the TDM reservation document GET /.well-known/tdmrep.json (W3C TDMRep),
//   - the Spawning ai.txt at GET /ai.txt,
//   - the robots.txt Content-Signal opt-in (buildRobots) and Disallow list (robotsDisallow),
//   - the per-response X-Robots-Tag / tdm-reservation headers (core's header table).
//
// A reserved class is the authenticated and adversarial surface: it is noindex, TDM-reserved,
// Disallowed for AI crawlers and refused in ai.txt. The open class ("/") is indexable and carries
// tdm-reservation: 0 with a tdm-policy pointing at /legal. The per-response headers themselves are
// P01's table (internal/core/headers.go); TestTDMHeadersOnPageAndReserved checks they agree.

// signalClass is one path class and whether AI use is reserved on it.
type signalClass struct {
	Prefix   string
	Reserved bool
}

// signalClasses is the single source the TDM bundle and ai.txt are generated from (27.1). The
// reserved prefixes are a subset of robotsDisallow and of core's noindex/tdm tables, which the
// parity test checks.
var signalClasses = []signalClass{
	{"/", false},
	{"/d/", true},
	{"/v1/", true},
	{"/mcp", true},
	{"/quarantine", true},
	{"/wanted", true},
}

// RegisterTDM mounts GET /.well-known/tdmrep.json and GET /ai.txt (both owned by "tdm" in the
// WellKnown table, so web.Register skips them). Anonymous, public, max-age=300, with the shared
// scope and the cheap static cost so crawlers never hit the budget on them.
func RegisterTDM(mux *http.ServeMux, d *core.Deps) {
	base := strings.TrimRight(d.Cfg.PublicURL, "/")
	started := time.Now().UTC()
	tdmBody := TDMRepJSON(base)
	aiBody := []byte(AITxt(base))
	mux.HandleFunc("GET /.well-known/tdmrep.json", func(w http.ResponseWriter, r *http.Request) {
		doc.ServeStatic(w, r, started, tdmBody, "application/json")
	})
	mux.HandleFunc("GET /ai.txt", func(w http.ResponseWriter, r *http.Request) {
		doc.ServeStatic(w, r, started, aiBody, "text/plain; charset=utf-8")
	})
	for _, pat := range []string{"GET /.well-known/tdmrep.json", "GET /ai.txt"} {
		d.RegisterScope(pat, "*")
		d.RegisterCost(pat, 0.2)
	}
}

// TDMRepJSON is the W3C TDMRep tdmrep.json: one entry per path class. The open class carries a
// tdm-policy; reserved classes carry tdm-reservation 1 and no policy.
func TDMRepJSON(base string) []byte {
	out := make([]map[string]any, 0, len(signalClasses))
	for _, c := range signalClasses {
		e := map[string]any{"location": c.Prefix}
		if c.Reserved {
			e["tdm-reservation"] = 1
		} else {
			e["tdm-reservation"] = 0
			e["tdm-policy"] = base + "/legal"
		}
		out = append(out, e)
	}
	return jsonBytes(out)
}

// AITxt is the Spawning ai.txt: a robots-style allow/deny of AI use built from the same classes.
func AITxt(base string) string {
	var b strings.Builder
	b.WriteString("# agents.ekaii.fr - AI-use permissions (ai.txt, Spawning format).\n")
	b.WriteString("# The commons opts in to AI input and training on its public pages; the reserved\n")
	b.WriteString("# control and adversarial surfaces below are off-limits. Policy: " + base + "/legal\n")
	b.WriteString("\nUser-Agent: *\n")
	b.WriteString("Allow: /\n")
	for _, c := range signalClasses {
		if c.Reserved {
			b.WriteString("Disallow: " + c.Prefix + "\n")
		}
	}
	return b.String()
}
