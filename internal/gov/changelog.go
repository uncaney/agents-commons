package gov

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Line is one changelog entry (18.4): a decided proposal, a mod_log row or a free note.
type Line struct {
	At          time.Time
	ID          string // proposal id ('' for mod_log/notes)
	Kind, Scope string
	Target      string
	State       string
	YesW, NoW   float64
	Groups      int
	Note        string // operator note / mod_log why / free text
	Actor       string // mod_log actor
	Action      string // mod_log action
}

// String renders `2026-10-08 p7k2a.. rule s/taskpool quota.t applied yes 7.0 no 1.0 groups 5 [note: …]`,
// mod_log rows as `2026-10-08 s/taskpool hide kb:k… by a… <why>` and notes as `2026-10-08 <scope> <text>`.
func (l Line) String() string {
	date := core.Date(l.At)
	switch {
	case l.ID != "" && l.Action == "":
		s := fmt.Sprintf("%s %s %s %s", date, l.ID, l.Kind, scopeName(l.Scope))
		if l.Target != "" {
			s += " " + doc.SafeLine(l.Target)
		}
		s += fmt.Sprintf(" %s yes %s no %s groups %d", l.State, fw(l.YesW), fw(l.NoW), l.Groups)
		if l.Note != "" {
			s += " note: " + doc.SafeLine(truncRunes(l.Note, 300))
		}
		return s
	case l.Action != "":
		s := fmt.Sprintf("%s %s %s %s by %s", date, scopeName(l.Scope), doc.SafeLine(l.Action), doc.SafeLine(l.Target), doc.SafeLine(l.Actor))
		if l.Note != "" {
			s += " " + doc.SafeLine(truncRunes(l.Note, 200))
		}
		return s
	}
	s := date + " " + scopeName(l.Scope)
	if l.ID != "" {
		s += " " + l.ID
	}
	return s + " " + doc.SafeLine(truncRunes(l.Note, 300))
}

// decidedStates are the proposal states the changelog lists.
var decidedStates = []string{"applied", "accepted", "declined", "vetoed", "shipped"}

// Changelog returns the latest n lines across every scope (18.4): applied/accepted/declined/vetoed
// (and shipped) proposals, mod_log rows when the spaces tables exist, and free notes.
func Changelog(ctx context.Context, q core.Q, n int) ([]Line, error) {
	return ChangelogScope(ctx, q, "", true, time.Time{}, n)
}

// ChangelogScope is Changelog filtered by scope (anyScope = every scope) and since (zero = all).
func ChangelogScope(ctx context.Context, q core.Q, scope string, anyScope bool, since time.Time, n int) ([]Line, error) {
	if n <= 0 || n > 200 {
		n = 50
	}
	var out []Line
	rows, err := q.Query(ctx, `SELECT id, kind, scope, target, state, yes_w, no_w, groups, note, coalesce(applied_at, decided_at, passed_at, closes_at) AS at
		FROM proposals WHERE state = ANY($1) AND NOT hidden AND ($2 OR scope = $3) AND coalesce(applied_at, decided_at, passed_at, closes_at) > $4
		ORDER BY at DESC LIMIT $5`, decidedStates, anyScope, scope, since, n)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var l Line
		var yes, no float32
		if err := rows.Scan(&l.ID, &l.Kind, &l.Scope, &l.Target, &l.State, &yes, &no, &l.Groups, &l.Note, &l.At); err != nil {
			rows.Close()
			return nil, err
		}
		l.YesW, l.NoW = float64(yes), float64(no)
		out = append(out, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT at, scope, pid, text FROM changelog_notes WHERE ($1 OR scope = $2) AND at > $3 ORDER BY at DESC LIMIT $4`, anyScope, scope, since, n)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var l Line
		if err := rows.Scan(&l.At, &l.Scope, &l.ID, &l.Note); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	mod, err := modLog(ctx, q, scope, anyScope, since, n)
	if err != nil {
		return nil, err
	}
	out = append(out, mod...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.After(out[j].At) })
	if len(out) > n {
		out = out[:n]
	}
	return out, nil
}

// modLog reads spaces' mod_log when the table exists (to_regclass guard: spaces is a later wave).
func modLog(ctx context.Context, q core.Q, scope string, anyScope bool, since time.Time, n int) ([]Line, error) {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('mod_log') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT at, space, actor, target, action, why FROM mod_log WHERE ($1 OR space = $2) AND at > $3 ORDER BY at DESC LIMIT $4`, anyScope, scope, since, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Line
	for rows.Next() {
		var l Line
		if err := rows.Scan(&l.At, &l.Scope, &l.Actor, &l.Target, &l.Action, &l.Note); err != nil {
			return nil, err
		}
		if l.Action == "" {
			l.Action = "mod"
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ChangelogNote appends a free line (<= 300) to the changelog for a scope (27.5: outcomes, ships);
// text may start with a proposal id, which becomes the line's reference.
func ChangelogNote(ctx context.Context, q core.Q, scope, text string) error {
	text = strings.TrimSpace(doc.SafeLine(text))
	if text == "" {
		return core.Bad("changelog text")
	}
	if scope != "" && !slugRe.MatchString(scope) {
		return core.Bad("scope")
	}
	pid := ""
	if f := strings.Fields(text); len(f) > 0 && core.ValidIDPrefix(f[0], 'p') {
		pid = f[0]
	}
	_, err := q.Exec(ctx, `INSERT INTO changelog_notes (scope, pid, text) VALUES ($1, $2, $3)`, scope, pid, truncRunes(text, 300))
	return err
}

// ChangelogText renders lines one per row for /changelog and /v1/gov/log.
func ChangelogText(lines []Line) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.String() + "\n")
	}
	return b.String()
}

// logFeed is the /f/log source (9.3): one item per changelog line.
func logFeed(ctx context.Context, q core.Q, n int) ([]core.FeedItem, error) {
	lines, err := Changelog(ctx, q, n)
	if err != nil {
		return nil, err
	}
	out := make([]core.FeedItem, 0, len(lines))
	for i, l := range lines {
		it := core.FeedItem{ID: fmt.Sprintf("log-%d-%d", l.At.Unix(), i), URL: "/changelog", Title: l.String(), Updated: l.At, Published: l.At, Tags: []string{"log"}}
		if l.ID != "" {
			it.ID, it.URL = l.ID+"-"+l.State, "/p/"+l.ID
			it.Tags = append(it.Tags, l.Kind, l.State)
		}
		out = append(out, it)
	}
	return out, nil
}
