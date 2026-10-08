// Package sio is the stdin/stdout protocol shared by the seed tools (SPEC-v2 15.3): read stdin
// fully; an input starting with '{' is a JSON object, anything else is text whose first line
// carries the command. Errors go to stdout as "error: ..." with exit status 1 so a caller sees
// them inline. It carries its own reflection-free JSON parser and encoder: encoding/json and fmt
// pull reflect into a wasip1 binary (+2.5 MiB and +0.5 MiB on a 1.9 MiB runtime), which would
// push every tool past the 4 MiB unpinned cap. Values are nil, bool, float64, string, []any and
// map[string]any; objects encode with sorted keys. Portable Go: the same sources run natively
// (tests, go vet) and as GOOS=wasip1.
package sio

import (
	"errors"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Read returns the whole standard input (empty on error).
func Read() []byte {
	b, _ := io.ReadAll(os.Stdin)
	return b
}

// IsJSON reports whether the input is a JSON object (after leading whitespace).
func IsJSON(b []byte) bool {
	t := strings.TrimLeft(string(b), " \t\r\n")
	return len(t) > 0 && t[0] == '{'
}

// Object decodes a JSON-object input; false when the input is not JSON. A malformed object is
// an error exit.
func Object(b []byte) (map[string]any, bool) {
	if !IsJSON(b) {
		return nil, false
	}
	v, err := Parse(string(b))
	if err != nil {
		Fail("bad json input: " + err.Error())
	}
	m, ok := v.(map[string]any)
	if !ok {
		Fail("bad json input: not an object")
	}
	return m, true
}

// Line splits a text input into its first line (trimmed) and the rest (the payload, as-is).
func Line(b []byte) (string, string) {
	s := string(b)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(strings.TrimSuffix(s[:i], "\r")), s[i+1:]
	}
	return strings.TrimSpace(s), ""
}

// Fail prints "error: <msg>" on stdout and exits 1.
func Fail(msg string) {
	io.WriteString(os.Stdout, "error: "+msg+"\n")
	os.Exit(1)
}

// Out writes s to stdout.
func Out(s string) { io.WriteString(os.Stdout, s) }

// Outln writes s and a newline to stdout.
func Outln(s string) { io.WriteString(os.Stdout, s+"\n") }

// Str returns m[k] when it is a string, else "".
func Str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// Num returns m[k] when it is a number, else def.
func Num(m map[string]any, k string, def float64) float64 {
	if f, ok := m[k].(float64); ok {
		return f
	}
	return def
}

// Bool returns m[k] when it is a boolean, else false.
func Bool(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
}

// Strs returns m[k] as a list of strings (non-strings rendered compact).
func Strs(m map[string]any, k string) []string {
	arr, _ := m[k].([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, Compact(e))
		}
	}
	return out
}

// --- parser ---------------------------------------------------------------------------------------

type parser struct {
	s     string
	i     int
	depth int
}

// Parse decodes one JSON value (trailing whitespace allowed, nothing else).
func Parse(s string) (any, error) {
	p := &parser{s: s}
	p.ws()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, p.errf("trailing data")
	}
	return v, nil
}

func (p *parser) errf(msg string) error {
	return errors.New(msg + " at offset " + strconv.Itoa(p.i))
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\r', '\n':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value() (any, error) {
	if p.i >= len(p.s) {
		return nil, p.errf("unexpected end")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		return p.str()
	case c == 't' && strings.HasPrefix(p.s[p.i:], "true"):
		p.i += 4
		return true, nil
	case c == 'f' && strings.HasPrefix(p.s[p.i:], "false"):
		p.i += 5
		return false, nil
	case c == 'n' && strings.HasPrefix(p.s[p.i:], "null"):
		p.i += 4
		return nil, nil
	case c == '-' || c >= '0' && c <= '9':
		return p.number()
	}
	return nil, p.errf("unexpected character " + strconv.QuoteRune(rune(p.s[p.i])))
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > 256 {
		return p.errf("nesting too deep")
	}
	return nil
}

func (p *parser) object() (any, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	p.i++
	m := map[string]any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return m, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.errf("expected object key")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.errf("expected ':'")
		}
		p.i++
		p.ws()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		m[k.(string)] = v
		p.ws()
		if p.i >= len(p.s) {
			return nil, p.errf("unterminated object")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return m, nil
		default:
			return nil, p.errf("expected ',' or '}'")
		}
	}
}

func (p *parser) array() (any, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	p.i++
	arr := []any{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return arr, nil
	}
	for {
		p.ws()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.ws()
		if p.i >= len(p.s) {
			return nil, p.errf("unterminated array")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return arr, nil
		default:
			return nil, p.errf("expected ',' or ']'")
		}
	}
}

func (p *parser) str() (any, error) {
	p.i++ // opening quote
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return nil, p.errf("bad escape")
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				b.WriteByte(e)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				r, err := p.hex4()
				if err != nil {
					return nil, err
				}
				if utf16.IsSurrogate(r) && strings.HasPrefix(p.s[p.i:], "\\u") {
					p.i += 2
					r2, err := p.hex4()
					if err != nil {
						return nil, err
					}
					r = utf16.DecodeRune(r, r2)
				}
				b.WriteRune(r)
			default:
				return nil, p.errf("bad escape")
			}
		case c < 0x20:
			return nil, p.errf("control character in string")
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return nil, p.errf("unterminated string")
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.s) {
		return 0, p.errf("bad \\u escape")
	}
	n, err := strconv.ParseUint(p.s[p.i:p.i+4], 16, 32)
	if err != nil {
		return 0, p.errf("bad \\u escape")
	}
	p.i += 4
	return rune(n), nil
}

func (p *parser) number() (any, error) {
	j := p.i
	if j < len(p.s) && p.s[j] == '-' {
		j++
	}
	for j < len(p.s) && (p.s[j] >= '0' && p.s[j] <= '9' || p.s[j] == '.' || p.s[j] == 'e' || p.s[j] == 'E' || p.s[j] == '+' || p.s[j] == '-') {
		j++
	}
	f, err := strconv.ParseFloat(p.s[p.i:j], 64)
	if err != nil {
		return nil, p.errf("bad number")
	}
	p.i = j
	return f, nil
}

// --- encoder --------------------------------------------------------------------------------------

// Compact renders v as compact JSON: objects with sorted keys, numbers as integers when whole,
// strings escaped without HTML escaping. Accepts the parser's types plus int, int64, []string and
// map[string]string.
func Compact(v any) string {
	var b strings.Builder
	encode(&b, v)
	return b.String()
}

func encode(b *strings.Builder, v any) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case float64:
		b.WriteString(Number(t))
	case int:
		b.WriteString(strconv.Itoa(t))
	case int64:
		b.WriteString(strconv.FormatInt(t, 10))
	case string:
		b.WriteString(Quote(t))
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			encode(b, e)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(Quote(e))
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(Quote(k))
			b.WriteByte(':')
			encode(b, t[k])
		}
		b.WriteByte('}')
	case map[string]string:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(Quote(k))
			b.WriteByte(':')
			b.WriteString(Quote(t[k]))
		}
		b.WriteByte('}')
	default:
		b.WriteString("null")
	}
}

// Number renders a float the way JSON readers expect: whole values without a fraction.
func Number(f float64) string {
	switch {
	case math.IsNaN(f) || math.IsInf(f, 0):
		return "null"
	case f == math.Trunc(f) && math.Abs(f) < 1e15:
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// Quote renders s as a JSON string literal (RFC 8259 escapes, UTF-8 kept, invalid bytes -> U+FFFD).
func Quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
			i++
		case c == '\\':
			b.WriteString(`\\`)
			i++
		case c == '\n':
			b.WriteString(`\n`)
			i++
		case c == '\r':
			b.WriteString(`\r`)
			i++
		case c == '\t':
			b.WriteString(`\t`)
			i++
		case c < 0x20:
			const hexd = "0123456789abcdef"
			b.WriteString(`\u00`)
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&0xf])
			i++
		case c < utf8.RuneSelf:
			b.WriteByte(c)
			i++
		default:
			r, n := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && n == 1 {
				b.WriteString(`�`)
			} else {
				b.WriteString(s[i : i+n])
			}
			i += n
		}
	}
	b.WriteByte('"')
	return b.String()
}
