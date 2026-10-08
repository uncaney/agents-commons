package wasmscan

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Error mirrors core.APIError (status, short code, message) without importing core, so the donor
// and the CLI can use this package; the gateway maps it with core.E(e.Status, e.Code, e.Msg).
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return "err " + e.Code + " " + e.Msg }

const buildHint = "build with wasi-sdk preview1, GOOS=wasip1 or --target wasm32-wasip1"

// Check applies the submit rules of 14.3 for a job allowed mb MiB of linear memory (mb <= 0
// skips the memory rule): wasi_snapshot_preview1 functions as the only imports, 32-bit memory
// whose declared minimum fits, and a _start export.
func (i Info) Check(mb int) error {
	switch {
	case i.BadImport != "":
		return &Error{400, "bad", "import " + safe(i.BadImport, 96) + ": only " + WASI + " is available"}
	case i.Truncated && i.ImportCount > MaxImports:
		return &Error{400, "bad", fmt.Sprintf("%d imports: only %s is available", i.ImportCount, WASI)}
	case i.Memory64:
		return &Error{400, "bad", "memory64 unsupported; " + buildHint}
	case mb > 0 && uint64(i.MinPages)*PageSize > uint64(mb)<<20:
		return &Error{400, "oom", fmt.Sprintf("declared min memory %d pages (%d MiB) > mb=%d", i.MinPages, (uint64(i.MinPages)*PageSize+(1<<20-1))>>20, mb)}
	case !i.HasStart:
		return &Error{400, "bad", "no _start export (component model/preview2 unsupported; " + buildHint + ")"}
	}
	return nil
}

// Line renders the binfo summary, e.g.
// "wasm size=2099466 imports=wasi_snapshot_preview1:fd_write,… memory=min2 max65536 funcs=1803
// has_start=1 producers=Go1.27.1" plus " truncated=1" when a limit stopped a walk. Module text
// (import names, producers) is reduced to single tokens, so the result is always one line.
func (i Info) Line() string {
	var b strings.Builder
	fmt.Fprintf(&b, "wasm size=%d imports=", i.Size)
	if len(i.Imports) == 0 {
		b.WriteByte('-')
	}
	for k, im := range i.Imports {
		if k == 8 {
			b.WriteString(",…")
			break
		}
		if k > 0 {
			b.WriteByte(',')
		}
		b.WriteString(safe(im.Module, 48))
		b.WriteByte(':')
		b.WriteString(safe(im.Name, 48))
	}
	b.WriteString(" memory=")
	switch {
	case !i.HasMemory:
		b.WriteByte('-')
	case i.HasMax:
		fmt.Fprintf(&b, "min%d max%d", i.MinPages, i.MaxPages)
	default:
		fmt.Fprintf(&b, "min%d", i.MinPages)
	}
	if i.Memory64 {
		b.WriteString(" memory64=1")
	}
	fmt.Fprintf(&b, " funcs=%d has_start=%d producers=", i.Funcs, flag(i.HasStart))
	if p := safe(i.Producers, 96); p != "" {
		b.WriteString(p)
	} else {
		b.WriteByte('-')
	}
	if i.Truncated {
		b.WriteString(" truncated=1")
	}
	return b.String()
}

func flag(v bool) int {
	if v {
		return 1
	}
	return 0
}

// safe reduces module text to one token of at most max runes: invalid UTF-8, controls, spaces,
// format characters, ',' and '=' become '?', so a line of "k=v" fields stays parseable.
func safe(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	s = strings.Map(func(r rune) rune {
		if !unicode.IsGraphic(r) || unicode.IsSpace(r) || r == ',' || r == '=' || r == utf8.RuneError {
			return '?'
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

// producers reads the body of a "producers" custom section (fields language / processed-by /
// sdk, each a list of name+version) into one token such as "Go1.27.1", "Rust1.75.0" or
// "C11+clang16.0.0+Emscripten3.1.0". Malformed content yields what was read so far.
func producers(r *reader) string {
	type entry struct{ name, ver string }
	var lang, proc, sdk []entry
	read := func() (entry, bool) {
		n, err := r.name()
		if err != nil {
			return entry{}, false
		}
		v, err := r.name()
		if err != nil {
			return entry{}, false
		}
		if len(n) > 32 {
			n = n[:32]
		}
		if k := bytes.IndexByte(v, ' '); k >= 0 { // "1.75.0 (hash date)" -> "1.75.0"
			v = v[:k]
		}
		if len(v) > 32 {
			v = v[:32]
		}
		return entry{string(n), string(v)}, true
	}
	n, err := r.count(2)
	if err != nil {
		return ""
	}
fields:
	for i := 0; i < n && i < 8; i++ {
		field, err := r.name()
		if err != nil {
			break
		}
		m, err := r.count(2)
		if err != nil {
			break
		}
		for j := 0; j < m; j++ {
			e, ok := read()
			if !ok {
				break fields
			}
			if j >= 8 {
				continue
			}
			switch string(field) {
			case "language":
				lang = append(lang, e)
			case "processed-by":
				proc = append(proc, e)
			case "sdk":
				sdk = append(sdk, e)
			}
		}
	}
	var toks []string
	tok := func(e entry) string {
		v := e.ver
		if len(v) >= len(e.name) && strings.EqualFold(v[:len(e.name)], e.name) { // Go + go1.27.1
			v = v[len(e.name):]
		}
		return safe(e.name+v, 32)
	}
	for _, p := range proc { // "Go cmd/compile" or "rustc" restate the language: fold them in
		folded := false
		for k := range lang {
			if l := lang[k]; strings.HasPrefix(strings.ToLower(p.name), strings.ToLower(l.name)) {
				if l.ver == "" {
					lang[k].ver = p.ver
				}
				folded = true
				break
			}
		}
		if !folded {
			sdk = append([]entry{p}, sdk...)
		}
	}
	for _, e := range append(lang, sdk...) {
		if t := tok(e); t != "" && len(toks) < 4 {
			toks = append(toks, t)
		}
	}
	return strings.Join(toks, "+")
}
