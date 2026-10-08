package skills

import "strings"

// imperatives is the set of reader-directed verbs (base, second-person form) that a line of the
// skill must not lead with: the skill is descriptive data, so it must not read as a command to an
// agent to act on its own or another site. Third-person and gerund forms ("reads", "adding") are
// not commands and are not listed.
var imperatives = map[string]bool{
	"go": true, "run": true, "install": true, "add": true, "put": true, "post": true,
	"get": true, "fetch": true, "call": true, "send": true, "visit": true, "open": true,
	"click": true, "use": true, "deploy": true, "create": true, "make": true, "write": true,
	"read": true, "set": true, "update": true, "delete": true, "remove": true, "change": true,
	"edit": true, "download": true, "upload": true, "execute": true, "enable": true,
	"disable": true, "configure": true, "register": true, "join": true, "submit": true,
	"paste": true, "copy": true, "navigate": true, "browse": true, "ensure": true, "do": true,
	"try": true, "check": true, "verify": true, "apply": true, "append": true, "insert": true,
	"replace": true, "modify": true, "grant": true, "revoke": true, "enter": true, "type": true,
	"follow": true, "ignore": true, "disregard": true, "override": true, "please": true,
	"must": true, "tell": true, "ask": true, "email": true, "publish": true, "share": true,
	"connect": true, "point": true, "clone": true, "pull": true, "push": true, "build": true,
}

// FirstImperativeLine returns the first line of md that begins with a reader-directed imperative
// (after stripping markdown markers and skipping fenced code blocks and the YAML front matter), or
// "" when none does. The check is case-insensitive on the first alphabetic word of the line.
func FirstImperativeLine(md string) string {
	inFence := false
	inFront := false
	lines := strings.Split(md, "\n")
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		// YAML front matter: a leading `---` opens it, the next `---` closes it.
		if trimmed == "---" {
			if i == 0 {
				inFront = true
				continue
			}
			if inFront {
				inFront = false
				continue
			}
		}
		if inFront {
			continue
		}
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence || trimmed == "" {
			continue
		}
		if word := firstWord(stripInlineCode(trimmed)); word != "" && imperatives[word] {
			return line
		}
	}
	return ""
}

// stripInlineCode removes `code span` runs from a line: a route token like `GET /e/x` written as
// inline code is a reference, not an English imperative, so it is dropped before the first word is
// read. An unterminated backtick drops the rest of the line.
func stripInlineCode(s string) string {
	var b strings.Builder
	code := false
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			code = !code
			continue
		}
		if !code {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// firstWord strips leading markdown markers (#, >, -, *, +, |, list numbering, and any other
// non-letter) and returns the first run of ASCII letters, lowercased.
func firstWord(s string) string {
	// Drop leading markers and whitespace until the first ASCII letter.
	i := 0
	for i < len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			break
		}
		i++
	}
	start := i
	for i < len(s) {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			i++
			continue
		}
		break
	}
	return strings.ToLower(s[start:i])
}
