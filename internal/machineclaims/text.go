package machineclaims

import (
	"strings"
	"unicode/utf8"

	"ekaii.fr/commons/internal/doc"
)

// Machine sources are untrusted text: titles and versions are forced onto a single safe line and
// every field is truncated by runes before it reaches the claim layer (SPEC-v2 27.9, 4.6).

// oneLine collapses s to a single safe line and truncates it to max runes.
func oneLine(s string, max int) string {
	return cut(strings.TrimSpace(doc.SafeLine(s)), max)
}

// cut truncates s to at most n runes.
func cut(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	return strings.TrimSpace(string([]rune(s)[:n]))
}
