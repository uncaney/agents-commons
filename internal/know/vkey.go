package know

import (
	"strings"
)

// VKey is the sortable version key of 13.4: a leading v/V is dropped, build metadata (+…) is
// ignored, the string is split on `.` and `-`, numeric segments are zero-padded to 6 digits (the
// release part is padded to at least 3 segments), a prerelease part sorts before its release
// (`-` < `~`), and anything unparseable becomes `~` + raw (sorts last, excluded from ranges).
func VKey(ver string) string {
	raw := strings.TrimSpace(ver)
	v := strings.ToLower(raw)
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if len(v) > 1 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	if v == "" || !vkeyChars(v) {
		return "~" + raw
	}
	rel, pre, hasPre := strings.Cut(v, "-")
	segs := strings.Split(rel, ".")
	var b strings.Builder
	for i, s := range segs {
		if !allDigits(s) {
			if i == 0 {
				return "~" + raw
			}
			// a non-numeric release segment ("1.0.rc1") is a prerelease identifier
			pre, hasPre = strings.TrimPrefix(strings.Join(segs[i:], ".")+"-"+pre, "-"), true
			pre = strings.TrimSuffix(pre, "-")
			segs = segs[:i]
			break
		}
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(pad6(s))
	}
	for n := len(segs); n < 3; n++ {
		b.WriteString(".000000")
	}
	if !hasPre || pre == "" {
		b.WriteByte('~')
		return b.String()
	}
	b.WriteByte('-')
	for i, id := range strings.FieldsFunc(pre, func(r rune) bool { return r == '.' || r == '-' }) {
		if i > 0 {
			b.WriteByte('.')
		}
		if allDigits(id) {
			b.WriteString(pad6(id))
		} else {
			b.WriteString(id)
		}
	}
	return b.String()
}

// Parseable reports whether VKey(ver) is a real key (not the `~` fallback).
func Parseable(ver string) bool { return !strings.HasPrefix(VKey(ver), "~") }

func vkeyChars(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c == '.', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func pad6(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		s = "0"
	}
	if len(s) >= 6 {
		return s
	}
	return strings.Repeat("0", 6-len(s)) + s
}

// ParseRange splits `<a>..<b>` (one path segment); ok false unless both ends parse.
func ParseRange(s string) (from, to string, ok bool) {
	from, to, ok = strings.Cut(s, "..")
	if !ok || from == "" || to == "" || !Parseable(from) || !Parseable(to) {
		return "", "", false
	}
	return from, to, true
}
