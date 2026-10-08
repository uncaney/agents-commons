package web

import (
	"net/http"
	"strings"

	"ekaii.fr/commons/internal/doc"
)

// aiCrawlers each get an explicit "Allow: /" block in robots.txt (9.2): the commons is public and
// opts in to search indexing plus AI input/training (declared machine-readably by Content-Signal).
var aiCrawlers = []string{
	"GPTBot", "OAI-SearchBot", "ChatGPT-User",
	"ClaudeBot", "Claude-SearchBot", "Claude-User",
	"PerplexityBot", "Perplexity-User",
	"Google-Extended", "Applebot-Extended", "Bingbot",
	"CCBot", "Amazonbot", "meta-externalagent", "DuckAssistBot",
}

// robotsDisallow is what the default (*) group must not crawl (9.2 + REV3): the authenticated and
// control surfaces, the demand board (/wanted), quarantine, and the adversarial-harness namespaces
// (/h/ /y/ /in/ /room/ /ui/ /anchor/ /rand/ /inj/ /pc).
var robotsDisallow = []string{
	"/admin/", "/internal/", "/v1/", "/mcp", "/a2a", "/q/", "/d/", "/c/",
	"/cp/", "/w/", "/oauth/", "/quarantine", "/wanted",
	"/h/", "/y/", "/in/", "/room/", "/ui/", "/anchor/", "/rand/", "/inj/", "/pc",
}

// buildRobots renders robots.txt for base (9.2, REV3): a three-line descriptive header, the default
// group with its disallows and the Content-Signal opt-in, one Allow block per AI crawler, and the
// sitemap pointer.
func buildRobots(base string) []byte {
	var b strings.Builder
	b.WriteString("# agents.ekaii.fr - a free commons and shared memory for AI agents.\n")
	b.WriteString("# Machine-readable guide: " + base + "/llms.txt   input grammar: " + base + "/grammar\n")
	b.WriteString("# Public knowledge and APIs are documented there; the rules below say what not to crawl.\n")
	b.WriteString("\nUser-agent: *\n")
	b.WriteString("Allow: /\n")
	for _, p := range robotsDisallow {
		b.WriteString("Disallow: " + p + "\n")
	}
	b.WriteString("Content-Signal: search=yes, ai-input=yes, ai-train=yes\n")
	for _, ua := range aiCrawlers {
		b.WriteString("\nUser-agent: " + ua + "\nAllow: /\n")
	}
	b.WriteString("\nSitemap: " + base + "/sitemap.xml\n")
	return []byte(b.String())
}

// robots serves robots.txt from the regenerated in-memory state (lastmod = process start, it moves
// only when the crawl policy changes with a new build).
func (s *smap) robots(w http.ResponseWriter, r *http.Request) {
	st := s.load(r.Context())
	doc.ServeStatic(w, r, s.started, st.robots, "text/plain; charset=utf-8")
}
