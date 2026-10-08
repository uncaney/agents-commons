package forge

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Compact text output is line-oriented ("#n state title", "field: value", "- id date: note").
// Single-line fields reject every control char on input; multi-line fields keep \n and \t only and
// are rendered with every continuation line indented by two spaces, so user text can never start
// a line at column 0 outside its own field.

func isCtl(r rune) bool {
	return unicode.IsControl(r) || r == utf8.RuneError || r == ' ' || r == ' '
}

// oneLine reports whether s is valid UTF-8 free of control characters (incl. \r \n \t).
func oneLine(s string) bool {
	return utf8.ValidString(s) && strings.IndexFunc(s, isCtl) < 0
}

// cleanMulti normalises a multi-line field: CRLF -> LF, every other control char dropped.
func cleanMulti(s string) string {
	if utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return r != '\n' && r != '\t' && isCtl(r) }) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ReplaceAll(s, "\r\n", "\n") {
		if r == '\n' || r == '\t' || !isCtl(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// safeLine is the output-side guard for single-line fields (legacy/Forgejo-side data): control chars -> space.
func safeLine(s string) string {
	if oneLine(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isCtl(r) {
			return ' '
		}
		return r
	}, s)
}

// indent renders a multi-line value so continuation lines can never start a line of their own.
func indent(s string) string {
	return strings.ReplaceAll(strings.TrimRight(cleanMulti(s), "\n"), "\n", "\n  ")
}
