package forge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// The Forgejo mirror (7.3): outbox kinds kb, task, note, claim, digest, gov, space-doc, flushed
// by the janitor; failures back off exponentially (10s * 2^attempts, max 1h). Votes never mirror.

const (
	maxLabels     = 200
	mirrorSizeMax = 2 << 30 // bytes across the notes and kb repos -> freeze:forge-mirror
	sizeEvery     = time.Hour
	markPfx       = "<!-- by:"
)

var errLabelCap = errors.New("label cap reached")

// taskMirror is the outbox payload of kind task: self-contained so purged rows still close.
type taskMirror struct {
	Issue  *int64   `json:"issue,omitempty"`
	Title  string   `json:"title"`
	Body   string   `json:"body"`
	State  string   `json:"state"` // open|closed
	Labels []string `json:"labels"`
}

// mark prefixes text with the hidden first line "<!-- by:<id> root:<root> -->" (stripped on import).
func mark(by, root, text string) string {
	return fmt.Sprintf("<!-- by:%s root:%s -->\n%s", by, root, text)
}

// parseMark removes the hidden first line and returns (by, root, rest).
func parseMark(body string) (by, root, rest string) {
	if !strings.HasPrefix(body, markPfx) {
		return "", "", body
	}
	line, rest, found := strings.Cut(body, "\n")
	if !found {
		rest = ""
	}
	for _, f := range strings.Fields(strings.TrimSuffix(strings.TrimPrefix(line, "<!-- "), " -->")) {
		if v, ok := strings.CutPrefix(f, "by:"); ok {
			by = v
		} else if v, ok := strings.CutPrefix(f, "root:"); ok {
			root = v
		}
	}
	return by, root, rest
}

// taskPayload renders the mirror payload of a loaded task (notes included): the issue body is the
// marked task body followed by a notes section, labels are the tags plus claimed/hidden.
func taskPayload(t *Task) []byte {
	var b strings.Builder
	b.WriteString(mark(t.By, t.Root, t.Body))
	if t.Space != "" || t.Ask != "" || len(t.Notes) > 0 {
		b.WriteString("\n\n---\n")
	}
	if t.Space != "" {
		b.WriteString("space: " + safeLine(t.Space) + "\n")
	}
	if t.Ask != "" {
		b.WriteString("ask: " + indent(t.Ask) + "\n")
	}
	if len(t.Notes) > 0 {
		fmt.Fprintf(&b, "notes: %d\n", t.NoteCount)
		for _, n := range t.Notes {
			fmt.Fprintf(&b, "- %s %s: %s\n", safeLine(n.By), core.Date(n.At), indent(strings.TrimSpace(n.Text)))
		}
	}
	p := taskMirror{Issue: t.Issue, Title: t.Title, Body: b.String(), State: "open", Labels: append([]string{}, t.Tags...)}
	if t.raw != "open" {
		p.State = "closed"
	}
	if t.raw == "hidden" {
		p.Labels = append(p.Labels, labelHidden)
	}
	if t.claimed() {
		p.Labels = append(p.Labels, labelClaimed)
	}
	out, _ := json.Marshal(p)
	return out
}

// mirrorTask enqueues the current state of task n (a no-op without a mirror or for quarantined
// tasks, which never leave the server until promoted).
func (s *Service) mirrorTask(ctx context.Context, q core.Q, n int64) error {
	if s.fc == nil {
		return nil
	}
	t, err := s.loadTask(ctx, q, n)
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if t.Quarantine {
		return nil
	}
	if err := s.loadNotes(ctx, q, t); err != nil {
		return err
	}
	return Enqueue(ctx, q, "task", itoa(n), taskPayload(t))
}

// mirrorTaskAny refreshes the mirror of n through any mirrored service (package-level entry
// points have no Deps); errors are best effort.
func mirrorTaskAny(ctx context.Context, q core.Q, n int64) {
	svcMu.Lock()
	var m *Service
	for _, s := range svcs {
		if s.fc != nil {
			m = s
			break
		}
	}
	svcMu.Unlock()
	if m != nil {
		if err := m.mirrorTask(ctx, q, n); err != nil {
			m.d.Log.Warn("mirror task", "n", n, "err", err)
		}
	}
}

// wakeAll wakes a topic on every known Deps (package-level entry points).
func wakeAll(topic string) {
	svcMu.Lock()
	defer svcMu.Unlock()
	for _, s := range svcs {
		s.d.Notify.Wake(topic)
	}
}

// --- labels ---

// refreshLabels reloads the board label cache; ensure creates the system labels.
func (s *Service) refreshLabels(ctx context.Context, ensure bool) error {
	ls, err := s.fc.ListLabels(ctx, org, repoBoard)
	if err != nil {
		return err
	}
	m := map[string]int64{}
	for _, l := range ls {
		m[l.Name] = l.ID
	}
	if ensure {
		for name, color := range map[string]string{labelClaimed: "#1d76db", labelHidden: "#e11d21"} {
			if _, ok := m[name]; ok {
				continue
			}
			l, err := s.fc.CreateLabel(ctx, org, repoBoard, name, color)
			if err != nil {
				return err
			}
			m[name] = l.ID
		}
	}
	s.mu.Lock()
	s.labels = m
	s.mu.Unlock()
	return nil
}

// labelID returns the board label id, creating the label on demand while the repo holds fewer
// than maxLabels labels (tags are user input: unbounded label creation would grow Forgejo forever).
func (s *Service) labelID(ctx context.Context, name string) (int64, error) {
	s.mu.Lock()
	id, ok := s.labels[name]
	n := len(s.labels)
	s.mu.Unlock()
	if ok {
		return id, nil
	}
	if n >= maxLabels {
		return 0, errLabelCap
	}
	l, err := s.fc.CreateLabel(ctx, org, repoBoard, name, "#ededed")
	if err != nil {
		if rerr := s.refreshLabels(ctx, false); rerr == nil {
			s.mu.Lock()
			id, ok = s.labels[name]
			s.mu.Unlock()
			if ok {
				return id, nil
			}
		}
		return 0, err
	}
	s.mu.Lock()
	s.labels[name] = l.ID
	s.mu.Unlock()
	return l.ID, nil
}

// labelIDs maps names to ids, dropping names past the label cap.
func (s *Service) labelIDs(ctx context.Context, names []string) ([]int64, error) {
	var ids []int64
	for _, name := range names {
		id, err := s.labelID(ctx, name)
		if errors.Is(err, errLabelCap) {
			continue
		}
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// syncLabels makes the issue's labels equal to want (minus names past the cap).
func (s *Service) syncLabels(ctx context.Context, issue int64, want []string) error {
	is, err := s.fc.GetIssue(ctx, org, repoBoard, issue)
	if err != nil {
		return err
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	var add []int64
	for _, w := range want {
		if is.HasLabel(w) {
			continue
		}
		id, err := s.labelID(ctx, w)
		if errors.Is(err, errLabelCap) {
			continue
		}
		if err != nil {
			return err
		}
		add = append(add, id)
	}
	if len(add) > 0 {
		if err := s.fc.AddIssueLabels(ctx, org, repoBoard, issue, add); err != nil {
			return err
		}
	}
	for _, l := range is.Labels {
		if wantSet[l.Name] {
			continue
		}
		if err := s.fc.RemoveIssueLabel(ctx, org, repoBoard, issue, l.ID); err != nil && !isStatus(err, 404) {
			return err
		}
	}
	return nil
}

// --- flush ---

// flushOutbox processes due outbox rows in batches of 50 (at most 20 batches per tick).
func (s *Service) flushOutbox(ctx context.Context) error {
	if s.fc == nil || !s.ready.Load() {
		return nil
	}
	for i := 0; i < 20; i++ {
		n, err := s.flushBatch(ctx)
		if err != nil || n < 50 {
			return err
		}
	}
	return nil
}

func (s *Service) flushBatch(ctx context.Context) (int, error) {
	type row struct {
		id       int64
		kind     string
		ref      string
		payload  []byte
		attempts int
	}
	rows, err := s.d.DB.Query(ctx, `SELECT id, kind, ref, payload, attempts FROM forge_outbox WHERE next_at <= now() ORDER BY id LIMIT 50`)
	if err != nil {
		return 0, err
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.kind, &r.ref, &r.payload, &r.attempts); err != nil {
			rows.Close()
			return 0, err
		}
		todo = append(todo, r)
	}
	rows.Close()
	frozen := s.d.Frozen("forge-mirror")
	for _, r := range todo {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		var perr error
		switch {
		case frozen && r.kind != "kb":
			// Over the size budget only kb entries keep mirroring (7.3); other rows are dropped.
		case r.kind == "kb":
			perr = s.flushFile(ctx, repoKB, "entries/"+r.ref+".md", r.payload, "kb "+r.ref, kbMarkdown)
		case r.kind == "claim":
			perr = s.flushFile(ctx, repoKB, "changes/"+r.ref+".md", r.payload, "claim "+r.ref, nil)
		case r.kind == "digest":
			perr = s.flushFile(ctx, repoKB, "digests/"+r.ref+".md", r.payload, "digest "+r.ref, nil)
		case r.kind == "task":
			perr = s.flushTask(ctx, r.ref, r.payload)
		case r.kind == "note":
			perr = s.flushWiki(ctx, strings.Replace(r.ref, "/", "--", 1), r.payload)
		case r.kind == "space-doc":
			perr = s.flushWiki(ctx, "s--"+strings.Replace(r.ref, "/", "--", 1), r.payload)
		case r.kind == "gov":
			perr = s.flushGov(ctx, r.ref, r.payload)
		default:
			perr = fmt.Errorf("unknown outbox kind %q", r.kind)
		}
		if perr == nil {
			_, err = s.d.DB.Exec(ctx, `DELETE FROM forge_outbox WHERE id = $1`, r.id)
		} else {
			back := 10 * time.Second << uint(min(r.attempts, 9))
			if back > time.Hour {
				back = time.Hour
			}
			msg := perr.Error()
			if len(msg) > 200 {
				msg = msg[:200]
			}
			_, err = s.d.DB.Exec(ctx, `UPDATE forge_outbox SET attempts = attempts + 1, next_at = now() + $2, last_err = $3 WHERE id = $1`, r.id, back, msg)
		}
		if err != nil {
			return 0, err
		}
	}
	return len(todo), nil
}

// flushFile puts (or, for an empty payload, deletes) a file of the kb repo; wrap renders the payload.
func (s *Service) flushFile(ctx context.Context, repo, path string, payload []byte, msg string, wrap func(ref string, payload []byte) []byte) error {
	if len(payload) == 0 {
		return s.fc.DeleteFile(ctx, org, repo, path, "rm "+msg)
	}
	data := payload
	if wrap != nil {
		ref := strings.TrimSuffix(path[strings.LastIndexByte(path, '/')+1:], ".md")
		data = wrap(ref, payload)
	}
	return s.fc.PutFile(ctx, org, repo, path, data, msg)
}

// flushWiki puts or deletes a page of the notes repo.
func (s *Service) flushWiki(ctx context.Context, page string, payload []byte) error {
	if len(payload) == 0 {
		err := s.fc.DeleteWiki(ctx, org, repoNotes, page)
		if isStatus(err, 404) {
			return nil
		}
		return err
	}
	return s.fc.PutWiki(ctx, org, repoNotes, page, string(payload))
}

// flushTask creates or updates the board issue of task ref from its payload.
func (s *Service) flushTask(ctx context.Context, ref string, payload []byte) error {
	var p taskMirror
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	n, err := parseN(ref)
	if err != nil {
		return err
	}
	issue := p.Issue
	var dbIssue *int64
	if err := s.d.DB.QueryRow(ctx, `SELECT issue FROM tasks WHERE n = $1`, n).Scan(&dbIssue); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if dbIssue != nil {
		issue = dbIssue
	}
	if issue == nil {
		if p.State == "closed" {
			return nil // never mirrored and already closed: nothing to show
		}
		lids, err := s.labelIDs(ctx, p.Labels)
		if err != nil {
			return err
		}
		is, err := s.fc.CreateIssue(ctx, org, repoBoard, p.Title, p.Body, lids)
		if err != nil {
			return err
		}
		_, err = s.d.DB.Exec(ctx, `UPDATE tasks SET issue = $2 WHERE n = $1 AND issue IS NULL`, n, is.Number)
		return err
	}
	if err := s.fc.EditIssueFull(ctx, org, repoBoard, *issue, p.Title, p.State, p.Body); err != nil {
		if isStatus(err, 404) {
			return nil // the mirror lost the issue: a later change recreates nothing (number is taken)
		}
		return err
	}
	return s.syncLabels(ctx, *issue, p.Labels)
}

// govMirror is the payload of kind gov: an issue per proposal in repo gov plus one comment per event.
type govMirror struct {
	Title   string `json:"title"`
	Body    string `json:"body"`
	Comment string `json:"comment"`
}

func (s *Service) flushGov(ctx context.Context, ref string, payload []byte) error {
	var p govMirror
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	prefix := "[" + ref + "]"
	found, err := s.fc.ListIssues(ctx, org, repoGov, IssueQuery{State: "all", Q: ref, Limit: 20})
	if err != nil {
		return err
	}
	var num int64
	for _, is := range found {
		if strings.HasPrefix(is.Title, prefix) {
			num = is.Number
			break
		}
	}
	if num == 0 {
		title := prefix
		if p.Title != "" {
			title += " " + safeLine(p.Title)
		}
		is, err := s.fc.CreateIssue(ctx, org, repoGov, title, p.Body, nil)
		if err != nil {
			return err
		}
		num = is.Number
	} else if p.Body != "" {
		if err := s.fc.EditIssue(ctx, org, repoGov, num, "", p.Body); err != nil {
			return err
		}
	}
	if p.Comment != "" {
		_, err = s.fc.CreateComment(ctx, org, repoGov, num, p.Comment)
	}
	return err
}

// kbMarkdown wraps the compact KB text (kb.Entry.Text) into a markdown page: "# <title>" + fenced text.
func kbMarkdown(ref string, payload []byte) []byte {
	title := ref
	for _, l := range strings.Split(string(payload), "\n") {
		if t, ok := strings.CutPrefix(l, "title: "); ok {
			title = strings.TrimSpace(t)
			break
		}
	}
	fence := "```"
	for bytes.Contains(payload, []byte(fence)) {
		fence += "`"
	}
	var b bytes.Buffer
	b.WriteString("# " + title + "\n\n" + fence + "text\n")
	b.Write(bytes.TrimRight(payload, "\n"))
	b.WriteString("\n" + fence + "\n")
	return b.Bytes()
}

// checkMirrorSize flips freeze:forge-mirror when the notes + kb repos exceed 2 GiB (hourly).
func (s *Service) checkMirrorSize(ctx context.Context) error {
	if s.fc == nil || !s.ready.Load() {
		return nil
	}
	s.mu.Lock()
	due := time.Since(s.sizeCheck) >= sizeEvery
	if due {
		s.sizeCheck = time.Now()
	}
	s.mu.Unlock()
	if !due {
		return nil
	}
	var total int64
	for _, repo := range []string{repoNotes, repoKB} {
		r, err := s.fc.GetRepo(ctx, org, repo)
		if err != nil {
			return err
		}
		total += r.Size << 10 // Forgejo reports KiB
	}
	over := total > mirrorSizeMax
	if over != s.d.Frozen("forge-mirror") {
		return s.d.SetFreeze(ctx, "freeze:forge-mirror", over)
	}
	return nil
}
