package tripwire

import "strings"

// Classes is the stored UA vocabulary (CHECK constraint of tripwire_hits.ua_class).
var Classes = []string{"browser", "bot", "agent", "curl", "unknown"}

// uaPrefixes is the prefix table UAClass scans in order on the lowercased User-Agent: the first
// match wins, so crawler prefixes (which announce themselves as compatible browsers) come before
// the browser prefixes and "claudebot" before "claude". The UA string itself is never stored.
var uaPrefixes = []struct{ prefix, class string }{
	// crawlers, link previewers and monitors
	{"mozilla/5.0 (compatible;", "bot"}, {"mozilla/5.0 (compatible ", "bot"}, {"googlebot", "bot"}, {"bingbot", "bot"},
	{"duckduckbot", "bot"}, {"yandex", "bot"}, {"baiduspider", "bot"}, {"facebookexternalhit", "bot"},
	{"meta-externalagent", "bot"}, {"twitterbot", "bot"}, {"slackbot", "bot"}, {"slack-imgproxy", "bot"},
	{"discordbot", "bot"}, {"telegrambot", "bot"}, {"whatsapp", "bot"}, {"linkedinbot", "bot"}, {"applebot", "bot"},
	{"petalbot", "bot"}, {"ahrefsbot", "bot"}, {"semrushbot", "bot"}, {"mj12bot", "bot"}, {"dotbot", "bot"},
	{"gptbot", "bot"}, {"chatgpt-user", "bot"}, {"oai-searchbot", "bot"}, {"claudebot", "bot"}, {"claude-web", "bot"},
	{"claude-user", "bot"}, {"claude-searchbot", "bot"}, {"anthropic-ai", "bot"}, {"ccbot", "bot"}, {"bytespider", "bot"},
	{"perplexitybot", "bot"}, {"amazonbot", "bot"}, {"ia_archiver", "bot"}, {"archive.org_bot", "bot"},
	{"uptimerobot", "bot"}, {"pingdom", "bot"}, {"site24x7", "bot"}, {"betterstack", "bot"}, {"statuscake", "bot"},
	{"headlesschrome", "bot"},
	// command-line fetchers
	{"curl/", "curl"}, {"wget/", "curl"}, {"httpie/", "curl"}, {"libcurl", "curl"}, {"powershell", "curl"},
	{"mozilla/5.0 (windows nt; windows nt", "curl"}, {"lwp-", "curl"}, {"fetch/", "curl"}, {"aria2/", "curl"},
	// HTTP libraries and agent runtimes
	{"python-requests/", "agent"}, {"python-urllib/", "agent"}, {"python-httpx/", "agent"}, {"python/", "agent"},
	{"aiohttp/", "agent"}, {"go-http-client/", "agent"}, {"node-fetch/", "agent"}, {"node/", "agent"},
	{"undici", "agent"}, {"axios/", "agent"}, {"okhttp/", "agent"}, {"java/", "agent"}, {"apache-httpclient/", "agent"},
	{"ruby", "agent"}, {"faraday", "agent"}, {"guzzlehttp/", "agent"}, {"dart:io", "agent"}, {"reqwest/", "agent"},
	{"ureq/", "agent"}, {"deno/", "agent"}, {"bun/", "agent"}, {"cx/", "agent"}, {"cxw/", "agent"}, {"mcp", "agent"},
	{"langchain", "agent"}, {"llamaindex", "agent"}, {"openai", "agent"}, {"anthropic", "agent"}, {"claude", "agent"},
	{"agent", "agent"}, {"bot", "agent"},
	// browsers
	{"mozilla/", "browser"}, {"opera/", "browser"}, {"safari", "browser"}, {"dalvik/", "browser"}, {"lynx/", "browser"},
	{"w3m/", "browser"}, {"links (", "browser"},
}

// UAClass maps a User-Agent to its stored class through the prefix table; anything else (and an
// empty UA) is unknown. The input is never kept.
func UAClass(ua string) string {
	u := strings.ToLower(strings.TrimSpace(ua))
	if u == "" {
		return "unknown"
	}
	for _, p := range uaPrefixes {
		if strings.HasPrefix(u, p.prefix) {
			return p.class
		}
	}
	return "unknown"
}
