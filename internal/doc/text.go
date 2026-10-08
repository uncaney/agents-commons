package doc

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// The txt wire format is line-oriented: agents parse "<id> <score> <kind> <title>" rows and
// "field: value" lines, and the server reserves the line starts "next:" and "> ". User text must
// therefore never start a line of its own: single-line values lose every control character,
// multi-line values keep \n and \t only and every continuation line is indented by two spaces.

func isCtl(r rune) bool {
	return unicode.IsControl(r) || r == utf8.RuneError || r == ' ' || r == ' '
}

// OneLine reports whether s is valid UTF-8 free of control characters (incl. \r \n \t).
func OneLine(s string) bool {
	return utf8.ValidString(s) && strings.IndexFunc(s, isCtl) < 0
}

// CleanMulti normalises a multi-line value: CRLF -> LF, every other control char dropped.
func CleanMulti(s string) string {
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

// SafeLine is the output-side guard for single-line values: control chars -> space.
func SafeLine(s string) string {
	if OneLine(s) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isCtl(r) {
			return ' '
		}
		return r
	}, s)
}

// Indent renders a multi-line value so continuation lines can never start a line of their own.
func Indent(s string) string {
	return strings.ReplaceAll(strings.TrimRight(CleanMulti(s), "\n"), "\n", "\n  ")
}

const mdSpecial = "[]()!<>\\*_#"

// MDEscape backslash-escapes the Markdown characters that could turn a head or title into a link,
// image, heading or emphasis, after SafeLine.
func MDEscape(s string) string {
	s = SafeLine(s)
	if !strings.ContainsAny(s, mdSpecial) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		if r < utf8.RuneSelf && strings.ContainsRune(mdSpecial, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// MarkdownFence returns a backtick fence one longer than the longest backtick run in s (>= 3).
func MarkdownFence(s string) string {
	n, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			n = max(n, run)
		} else {
			run = 0
		}
	}
	return strings.Repeat("`", max(3, n+1))
}

// markWrap wraps a user-authored span as "[data <mark>]…[/data <mark>]"; literal marker starts
// inside the content get a leading backslash so an author cannot close or reopen the span.
func markWrap(mark, s string) string {
	if mark == "" {
		return s
	}
	s = strings.ReplaceAll(s, "[/data ", `\[/data `)
	s = strings.ReplaceAll(s, "[data ", `\[data `)
	return "[data " + mark + "]" + s + "[/data " + mark + "]"
}

// truncRunes cuts s to at most n runes.
func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}
