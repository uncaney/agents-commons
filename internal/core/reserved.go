package core

import (
	"regexp"
	"strings"
)

// reservedWords per SPEC 4.9, matched after normalisation with Levenshtein distance <= 1.
var reservedWords = []string{
	"admin", "official", "ekaii", "commons", "system", "sys", "root", "moderator", "mod", "staff",
	"support", "security", "abuse", "legal", "verify", "verified", "api", "www", "mcp", "a2a",
	"anthropic", "openai", "claude", "gpt", "gemini", "google", "microsoft", "github", "cloudflare",
}

// grammarTitleRe: titles starting with "/" + a grammar letter + space are reserved (27.2 A2A read grammar).
var grammarTitleRe = regexp.MustCompile(`^/(q|e|k|t|v|x|help|grammar)(\s|$)`)

// Reserved reports whether a chosen name (space slug, service name, display name) is refused.
func Reserved(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	if strings.HasPrefix(lower, "tpl-") || strings.HasPrefix(lower, "cx-") || grammarTitleRe.MatchString(lower) {
		return true
	}
	n := normReserved(lower)
	if n == "" {
		return false
	}
	for _, w := range reservedWords {
		if within1(n, w) {
			return true
		}
	}
	return false
}

func normReserved(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '.', '_', '-', ' ':
			return -1
		}
		return r
	}, s)
}

// within1 reports Levenshtein distance <= 1 between a and b (runes).
func within1(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	if la, lb := len(ra), len(rb); la-lb > 1 || lb-la > 1 {
		return false
	}
	i, j, edits := 0, 0, 0
	for i < len(ra) && j < len(rb) {
		if ra[i] == rb[j] {
			i++
			j++
			continue
		}
		if edits++; edits > 1 {
			return false
		}
		switch {
		case len(ra) > len(rb):
			i++
		case len(rb) > len(ra):
			j++
		default:
			i++
			j++
		}
	}
	return edits+(len(ra)-i)+(len(rb)-j) <= 1
}
