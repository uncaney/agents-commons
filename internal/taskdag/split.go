package taskdag

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/forge"
)

// --- join rules ---

// validJoin reports whether a join rule is well formed for a split of `items` children and returns
// the threshold k (all -> items, any -> 1, k:<k> -> k).
func validJoin(rule string, items int) (int, bool) {
	switch {
	case rule == "" || rule == "all":
		return items, true
	case rule == "any":
		return 1, true
	case strings.HasPrefix(rule, "k:"):
		k, err := parsePosInt(rule[2:])
		if err != nil || k < 1 || k > items {
			return 0, false
		}
		return k, true
	}
	return 0, false
}

func parsePosInt(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("nan")
		}
		n = n*10 + int(r-'0')
		if n > 1<<20 {
			return 0, fmt.Errorf("big")
		}
	}
	return n, nil
}

// joinMet evaluates a stored join rule against the done/total child counts.
func joinMet(rule string, done, total int) bool {
	if total == 0 {
		return false
	}
	switch {
	case rule == "" || rule == "all":
		return done >= total
	case rule == "any":
		return done >= 1
	case strings.HasPrefix(rule, "k:"):
		k, err := parsePosInt(rule[2:])
		return err == nil && done >= k
	}
	return false
}

// --- split ---

// SplitItem is one child description.
type SplitItem struct {
	Title string   `json:"title"`
	Body  string   `json:"body"`
	Tags  []string `json:"tags"`
}

// Split fans task n out into children (holder or creator). Children are created through
// forge.CreateTask as the task's creator (so they count against the creator's tasks cap), each is
// recorded as a child in task_dag and as a prerequisite of n; the join rule is stored on n and
// evaluated by the janitor as children finish. Caps: depth <= 8 and <= 256 descendants per owner
// root per day.
func (s *Service) Split(ctx context.Context, id *core.Ident, n int64, items []SplitItem, join string) ([]int64, error) {
	if id == nil {
		return nil, core.ErrAuth
	}
	if id.Banned {
		return nil, core.ErrBanned
	}
	if s.d.Frozen("write") {
		return nil, core.Frozen("write")
	}
	if len(items) == 0 || len(items) > maxItems {
		return nil, core.Bad(fmt.Sprintf("items 1..%d", maxItems))
	}
	if _, ok := validJoin(join, len(items)); !ok {
		return nil, core.Bad("join must be all|any|k:<k> (k 1..items)")
	}
	if join == "" {
		join = "all"
	}

	cid, croot, state, err := creator(ctx, s.d.DB, n)
	if err != nil {
		return nil, err
	}
	if state == "hidden" {
		return nil, core.ErrNotFound
	}
	if state != "open" {
		return nil, core.E(409, "bad", "task closed")
	}
	if croot == "" {
		return nil, core.E(409, "bad", "anonymous task cannot be split")
	}
	// Authorised: the live claim holder or the creator tree.
	h, err := s.holds(ctx, n, id.Root)
	if err != nil {
		return nil, err
	}
	if !h && id.Root != croot {
		return nil, core.E(403, "auth", "holder or creator only")
	}
	// Depth: a child sits one level below n.
	depth, err := s.depth(ctx, n)
	if err != nil {
		return nil, err
	}
	if depth+1 > maxDepth {
		return nil, core.E(409, "bad", fmt.Sprintf("max depth %d", maxDepth))
	}
	// Descendants per owner root per day.
	var today int
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM task_dag WHERE root = $1 AND created::date = current_date`, croot).Scan(&today); err != nil {
		return nil, err
	}
	if today+len(items) > maxPerDay {
		return nil, core.E(429, "quota", fmt.Sprintf("max %d descendants/day", maxPerDay))
	}

	// Store the join rule on the parent first so a mid-split interruption still carries it.
	if _, err := s.d.DB.Exec(ctx, `INSERT INTO task_dag (n, join_rule) VALUES ($1, $2)
		ON CONFLICT (n) DO UPDATE SET join_rule = EXCLUDED.join_rule, joined_at = NULL`, n, join); err != nil {
		return nil, err
	}

	creatorIdent := &core.Ident{ID: cid, Root: croot}
	var children []int64
	for _, it := range items {
		child, err := forge.CreateTask(ctx, s.d, creatorIdent, forge.TaskInput{Title: it.Title, Body: it.Body, Tags: it.Tags})
		if err != nil {
			if len(children) > 0 {
				return children, err // partial: report what was made
			}
			return nil, err
		}
		if err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO task_dag (n, parent, root) VALUES ($1, $2, $3)
				ON CONFLICT (n) DO UPDATE SET parent = EXCLUDED.parent, root = EXCLUDED.root`, child, n, croot); err != nil {
				return err
			}
			return addDep(ctx, tx, n, child)
		}); err != nil {
			return children, err
		}
		children = append(children, child)
	}
	if err := core.Audit(ctx, s.d.DB, id.ID, "tsplit", itoa(n), len(children)); err != nil {
		return children, err
	}
	s.d.Notify.Wake(forge.TaskTopic(n))
	return children, nil
}

// holds reports whether root owns the live claim on n.
func (s *Service) holds(ctx context.Context, n int64, root string) (bool, error) {
	var ok bool
	err := s.d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM task_claims WHERE n = $1 AND root = $2 AND until > now())`, n, root).Scan(&ok)
	return ok, err
}

// depth is the length (1-based) of the parent chain ending at n.
func (s *Service) depth(ctx context.Context, n int64) (int, error) {
	var d int
	err := s.d.DB.QueryRow(ctx, `WITH RECURSIVE up(n, depth) AS (
			SELECT $1::bigint, 1
			UNION ALL
			SELECT g.parent, up.depth + 1 FROM task_dag g JOIN up ON g.n = up.n
			WHERE g.parent IS NOT NULL AND up.depth < $2
		)
		SELECT max(depth) FROM up`, n, maxDepth+1).Scan(&d)
	return d, err
}

// --- janitor ---

// janitor runs every tick (and on a t:<n> wake): it fires the one-shot join-met notes, the
// hidden-prerequisite "dep #n gone" notes, and the unblock announcements for dependents whose
// prerequisites are all done. Every step is idempotent through its marker column.
func (s *Service) janitor(ctx context.Context) error {
	if err := s.evalJoins(ctx); err != nil {
		return err
	}
	if err := s.noteGone(ctx); err != nil {
		return err
	}
	return s.announceUnblocked(ctx)
}

// evalJoins notes "join met d/t" on every split parent whose rule is now satisfied and clears the
// pending child prerequisites so the parent unblocks.
func (s *Service) evalJoins(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT g.n, g.join_rule FROM task_dag g
		WHERE g.join_rule <> '' AND g.joined_at IS NULL`)
	if err != nil {
		return err
	}
	type cand struct {
		n    int64
		rule string
	}
	var cs []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.n, &c.rule); err != nil {
			rows.Close()
			return err
		}
		cs = append(cs, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range cs {
		var total, done int
		if err := s.d.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE td.state = 'done')
			FROM task_dag g JOIN tasks td ON td.n = g.n WHERE g.parent = $1`, c.n).Scan(&total, &done); err != nil {
			return err
		}
		if !joinMet(c.rule, done, total) {
			continue
		}
		// One-shot guard: only the first tick that observes the met rule writes the note.
		tag, err := s.d.DB.Exec(ctx, `UPDATE task_dag SET joined_at = now() WHERE n = $1 AND joined_at IS NULL`, c.n)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		// Clear the still-open child prerequisites so a non-"all" join unblocks the parent.
		if _, err := s.d.DB.Exec(ctx, `DELETE FROM task_deps d USING tasks td
			WHERE d.n = $1 AND d.needs = td.n AND td.state <> 'done'
			AND d.needs IN (SELECT n FROM task_dag WHERE parent = $1)`, c.n); err != nil {
			return err
		}
		if err := s.sysNote(ctx, c.n, fmt.Sprintf("join met %d/%d", done, total)); err != nil {
			return err
		}
	}
	return nil
}

// noteGone records "dep #m gone" once on every task whose prerequisite m was hidden.
func (s *Service) noteGone(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT d.n, d.needs FROM task_deps d JOIN tasks td ON td.n = d.needs
		JOIN tasks tn ON tn.n = d.n WHERE td.state = 'hidden' AND NOT d.gone AND tn.state <> 'hidden'`)
	if err != nil {
		return err
	}
	type edge struct{ n, m int64 }
	var es []edge
	for rows.Next() {
		var e edge
		if err := rows.Scan(&e.n, &e.m); err != nil {
			rows.Close()
			return err
		}
		es = append(es, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, e := range es {
		tag, err := s.d.DB.Exec(ctx, `UPDATE task_deps SET gone = true WHERE n = $1 AND needs = $2 AND NOT gone`, e.n, e.m)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		if err := s.sysNote(ctx, e.n, fmt.Sprintf("dep #%d gone", e.m)); err != nil {
			return err
		}
	}
	return nil
}

// announceUnblocked emits the unblock event/wake (and a sys mail when a join rule is set) for every
// dependent that just became unblocked, exactly once.
func (s *Service) announceUnblocked(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT g.n, g.join_rule FROM task_dag g JOIN tasks t ON t.n = g.n
		WHERE g.unblocked_at IS NULL AND t.state = 'open'
		AND EXISTS (SELECT 1 FROM task_deps d WHERE d.n = g.n)
		AND NOT EXISTS (SELECT 1 FROM task_deps d JOIN tasks td ON td.n = d.needs WHERE d.n = g.n AND td.state <> 'done')`)
	if err != nil {
		return err
	}
	type cand struct {
		n    int64
		rule string
	}
	var cs []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.n, &c.rule); err != nil {
			rows.Close()
			return err
		}
		cs = append(cs, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range cs {
		tag, err := s.d.DB.Exec(ctx, `UPDATE task_dag SET unblocked_at = now() WHERE n = $1 AND unblocked_at IS NULL`, c.n)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		if err := core.Event(ctx, s.d.DB, "t", itoa(c.n), "", "unblocked"); err != nil {
			return err
		}
		s.d.Notify.Wake(forge.TaskTopic(c.n))
		if c.rule != "" {
			var croot string
			if err := s.d.DB.QueryRow(ctx, `SELECT root FROM tasks WHERE n = $1`, c.n).Scan(&croot); err == nil && croot != "" {
				_ = core.SysMail(ctx, s.d.DB, croot, "task #"+itoa(c.n)+" unblocked",
					fmt.Sprintf("task #%d is ready: every prerequisite of your split is done.", c.n))
			}
		}
	}
	return nil
}

// sysNote writes a system note (sender asystem) on task n and logs the board event. It inserts
// directly rather than through the capped AddNoteAs so janitor notes are never dropped on a quota.
func (s *Service) sysNote(ctx context.Context, n int64, text string) error {
	if _, err := s.d.DB.Exec(ctx, `INSERT INTO task_notes (n, by, root, text, kind) VALUES ($1, $2, $2, $3, 'note')`,
		n, core.SystemID, text); err != nil {
		return err
	}
	return core.Event(ctx, s.d.DB, "t", itoa(n), "", text)
}

// decodeArgs unmarshals MCP op args.
func decodeArgs(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}
