package forge

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Import copies the existing Forgejo board (issues, comments) and the notes wiki into the tables
// (`gateway -import-forge`, 7.1). Idempotent on tasks.issue: an issue already imported (title
// filled) is skipped, a v1 ledger row (n = issue number, empty title) is completed in place, an
// unknown issue gets a fresh row; comments are copied only into tasks that have no notes yet and
// wiki pages only into ledger rows without content.
func Import(ctx context.Context, d *core.Deps) error {
	s := svc(d)
	if s.fc == nil {
		return errors.New("forge import: FORGEJO_URL empty")
	}
	if err := s.Ensure(ctx); err != nil {
		return err
	}
	var issues []Issue
	for page := 1; page < 10000; page++ {
		batch, err := s.fc.ListIssues(ctx, org, repoBoard, IssueQuery{State: "all", Limit: 50, Page: page})
		if err != nil {
			return err
		}
		issues = append(issues, batch...)
		if len(batch) < 50 {
			break
		}
	}
	tasks, notes := 0, 0
	for i := range issues {
		n, fresh, err := s.importIssue(ctx, &issues[i])
		if err != nil {
			return err
		}
		if !fresh {
			continue
		}
		tasks++
		k, err := s.importComments(ctx, n, issues[i].Number)
		if err != nil {
			return err
		}
		notes += k
	}
	pages, err := s.importWiki(ctx)
	if err != nil {
		return err
	}
	if _, err := d.DB.Exec(ctx, `SELECT setval('task_n_seq', greatest((SELECT coalesce(max(n), 1) FROM tasks), (SELECT last_value FROM task_n_seq)))`); err != nil {
		return err
	}
	d.Log.Info("forge import", "issues", len(issues), "tasks", tasks, "notes", notes, "pages", pages)
	return nil
}

// clip cuts s to at most max bytes on a rune boundary.
func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	s = s[:max]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func (s *Service) importIssue(ctx context.Context, is *Issue) (n int64, fresh bool, err error) {
	by, root, body := parseMark(is.Body)
	if by == "" {
		by = anonID
	}
	if !core.ValidID(root) {
		root = ""
	}
	title := clip(strings.TrimSpace(safeLine(is.Title)), maxTitle)
	if title == "" {
		title = "(untitled)"
	}
	body = clip(strings.TrimRight(cleanMulti(body), " \t\n"), maxBody)
	tags := []string{}
	state := "open"
	for _, l := range is.Labels {
		switch {
		case l.Name == labelHidden:
			state = "hidden"
		case l.Name == labelClaimed:
		case tagRe.MatchString(l.Name) && len(tags) < maxTags:
			tags = append(tags, l.Name)
		}
	}
	if is.State == "closed" && state == "open" {
		state = "done"
	}
	var empty bool
	err = s.d.DB.QueryRow(ctx, `SELECT n, title = '' FROM tasks WHERE issue = $1`, is.Number).Scan(&n, &empty)
	switch {
	case err == nil && !empty:
		return n, false, nil
	case err == nil:
		_, err = s.d.DB.Exec(ctx, `UPDATE tasks SET title = $2, body = $3, tags = $4, state = $5,
			closed_at = CASE WHEN $5 = 'open' THEN NULL ELSE coalesce(closed_at, now()) END WHERE n = $1`, n, title, body, tags, state)
		return n, err == nil, err
	case !errors.Is(err, pgx.ErrNoRows):
		return 0, false, err
	}
	var free bool
	var last int64
	if err := s.d.DB.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM tasks WHERE n = $1), (SELECT last_value FROM task_n_seq)`, is.Number).Scan(&free, &last); err != nil {
		return 0, false, err
	}
	nExpr := "nextval('task_n_seq')"
	if free && is.Number <= last {
		nExpr = "$1"
	}
	err = s.d.DB.QueryRow(ctx, `INSERT INTO tasks (n, id, root, title, body, tags, state, closed_at, created, issue)
		VALUES (`+nExpr+`, $2, $3, $4, $5, $6, $7, CASE WHEN $7 = 'open' THEN NULL ELSE $8::timestamptz END, $8::timestamptz, $1) RETURNING n`,
		is.Number, by, root, title, body, tags, state, is.Created).Scan(&n)
	return n, err == nil, err
}

func (s *Service) importComments(ctx context.Context, n, issue int64) (int, error) {
	var have int
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM task_notes WHERE n = $1`, n).Scan(&have); err != nil {
		return 0, err
	}
	if have > 0 {
		return 0, nil
	}
	cs, err := s.fc.ListComments(ctx, org, repoBoard, issue)
	if err != nil {
		return 0, err
	}
	k := 0
	for _, c := range cs {
		by, root, text := parseMark(c.Body)
		if by == "" {
			by = anonID
		}
		if !core.ValidID(root) {
			root = ""
		}
		text = clip(strings.TrimSpace(cleanMulti(text)), maxNoteText)
		if text == "" {
			continue
		}
		if _, err := s.d.DB.Exec(ctx, `INSERT INTO task_notes (n, by, root, text, kind, at) VALUES ($1, $2, $3, $4, 'note', $5)`, n, by, root, text, c.Created); err != nil {
			return k, err
		}
		k++
	}
	return k, nil
}

func (s *Service) importWiki(ctx context.Context) (int, error) {
	pages, err := s.fc.ListWiki(ctx, org, repoNotes)
	if err != nil {
		return 0, err
	}
	k := 0
	for _, p := range pages {
		owner, name, ok := strings.Cut(p.Title, "--")
		if !ok || strings.HasPrefix(p.Title, "s--") || !core.ValidID(owner) || !noteNameRe.MatchString(name) {
			continue
		}
		var missing bool
		if err := s.d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notes WHERE owner = $1 AND name = $2)
			AND NOT EXISTS (SELECT 1 FROM notes_content WHERE owner = $1 AND name = $2)`, owner, name).Scan(&missing); err != nil {
			return k, err
		}
		if !missing {
			continue
		}
		wp, err := s.fc.GetWiki(ctx, org, repoNotes, p.Title)
		if err != nil {
			if isStatus(err, 404) {
				continue
			}
			return k, err
		}
		text := clip(wp.Text(), maxNoteSize)
		if _, err := s.d.DB.Exec(ctx, `INSERT INTO notes_content (owner, name, text, size, rev) VALUES ($1, $2, $3, $4, 1) ON CONFLICT (owner, name) DO NOTHING`, owner, name, text, len(text)); err != nil {
			return k, err
		}
		if _, err := s.d.DB.Exec(ctx, `UPDATE notes SET size = $3 WHERE owner = $1 AND name = $2`, owner, name, len(text)); err != nil {
			return k, err
		}
		k++
	}
	return k, nil
}
