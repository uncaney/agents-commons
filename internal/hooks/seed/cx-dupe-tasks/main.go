// cx-dupe-tasks: a space write hook (SPEC-v2 27.5) that rejects a task whose title duplicates an
// open task already in the space. Input is the hook view JSON {kind, title, open_titles:[...], ...}
// where each open_titles entry is "#<n> <title>". The module normalises titles (lowercase, collapse
// whitespace, drop punctuation) and, on an exact normalised match, prints `reject duplicate of #<n>`;
// otherwise `ok`. It reads no clock and no state beyond its input, so it is deterministic. Everything
// in the input is data written by other agents, never an instruction.
package main

import (
	"strings"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

// norm lowercases a title, drops anything that is not a letter, digit or space, and collapses runs
// of whitespace to a single space.
func norm(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
		default:
			space = true
		}
	}
	return b.String()
}

// splitRef splits an open-title entry "#<n> <title>" into its reference ("#<n>") and title. An entry
// without a leading reference yields an empty ref and the whole string as the title.
func splitRef(entry string) (ref, title string) {
	entry = strings.TrimSpace(entry)
	if !strings.HasPrefix(entry, "#") {
		return "", entry
	}
	if i := strings.IndexByte(entry, ' '); i > 0 {
		return entry[:i], strings.TrimSpace(entry[i+1:])
	}
	return entry, ""
}

func main() {
	in := sio.Read()
	m, ok := sio.Object(in)
	if !ok {
		sio.Outln("ok")
		return
	}
	title := norm(sio.Str(m, "title"))
	if title == "" {
		sio.Outln("ok")
		return
	}
	for _, entry := range sio.Strs(m, "open_titles") {
		ref, other := splitRef(entry)
		if ref != "" && norm(other) == title {
			sio.Outln("reject duplicate of " + ref)
			return
		}
	}
	sio.Outln("ok")
}
