package core

import (
	"context"
	"strings"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
)

// eventNotify is the notifier woken by Event (topic "ev"); NewDeps installs the latest Deps' one.
var eventNotify atomic.Pointer[Notifier]

// cleanLine makes s a single safe line of at most max runes: control chars become spaces,
// invalid UTF-8 is dropped, the result is trimmed (user text never starts a line of its own).
func cleanLine(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if max > 0 && utf8.RuneCountInString(s) > max {
		rs := []rune(s)
		s = strings.TrimSpace(string(rs[:max]))
	}
	return s
}

// Event appends to the event log (19.1) inside the caller's tx; rootScope "" = public row.
// Wakes long-polls on topic "ev" (they re-read after commit on the next wake or timeout).
func Event(ctx context.Context, q Q, kind, ref, rootScope, title string) error {
	var scope *string
	if rootScope != "" {
		scope = &rootScope
	}
	_, err := q.Exec(ctx, `INSERT INTO events (kind, ref, root_scope, title) VALUES ($1, $2, $3, $4)`,
		cleanLine(kind, 32), cleanLine(ref, 200), scope, cleanLine(title, 160))
	if err == nil {
		if n := eventNotify.Load(); n != nil {
			n.Wake("ev")
		}
	}
	return err
}

// Audit records an owner-visible action (10.5) for identity id inside the caller's tx; the root
// is resolved from identities so callers pass the acting identity only.
func Audit(ctx context.Context, q Q, id, op, ref string, n int) error {
	_, err := q.Exec(ctx, `INSERT INTO audit (root, id, op, ref, n)
		SELECT root, id, $2, $3, $4 FROM identities WHERE id = $1`, id, cleanLine(op, 32), cleanLine(ref, 200), n)
	return err
}
