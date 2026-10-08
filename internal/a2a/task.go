package a2a

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
)

// A2A task states (0.3) the board maps onto (19.2).
const (
	StSubmitted     = "submitted"
	StWorking       = "working"
	StInputRequired = "input-required"
	StCompleted     = "completed"
	StCanceled      = "canceled"
)

const (
	// MaxHistory bounds historyLength (27.7); DefHistory applies when the client sets none.
	MaxHistory = 100
	DefHistory = 20
	noteWindow = 100 // newest notes loaded per task (history and artifacts are built from them)
)

type note struct {
	ID             int64
	By, Root, Text string
	Kind           string
	At             time.Time
}

// task is the board row plus what the A2A rendering needs (claim, notes, message ids).
type task struct {
	N                    int64
	By, Root             string
	Title, Body          string
	Tags                 []string
	Raw                  string // tasks.state: open|done|hidden
	ContextID, Ask       string
	Quarantine           bool
	Created              time.Time
	Closed               *time.Time
	HolderID, HolderRoot string // the task's last claim row
	Until                time.Time
	Fence                int64
	Live                 bool // claim live and task open
	Blocked              bool
	Needs                string
	Notes                []note           // ascending, at most noteWindow
	MsgIDs               map[int64]string // note id -> client messageId
	First                *firstMsg        // the creation message when the task came through A2A
}

type firstMsg struct {
	ID, Text string
	At       time.Time
}

func taskID(n int64) string { return "t" + strconv.FormatInt(n, 10) }

// parseTaskID accepts "t<n>" (and a bare number) for n >= 1.
func parseTaskID(s string) (int64, bool) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "t")
	if s == "" || len(s) > 18 {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n > 0
}

// loadTask reads one task (any state) with its last claim, newest notes and message ids.
func loadTask(ctx context.Context, q core.Q, n int64) (*task, error) {
	t := &task{N: n}
	err := q.QueryRow(ctx, `SELECT id, root, title, body, tags, state, context_id, ask, quarantine, created, closed_at FROM tasks WHERE n = $1`, n).
		Scan(&t.By, &t.Root, &t.Title, &t.Body, &t.Tags, &t.Raw, &t.ContextID, &t.Ask, &t.Quarantine, &t.Created, &t.Closed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	err = q.QueryRow(ctx, `SELECT id, root, until, fence FROM task_claims WHERE n = $1`, n).Scan(&t.HolderID, &t.HolderRoot, &t.Until, &t.Fence)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	t.Live = err == nil && t.Until.After(time.Now()) && t.Raw == "open"
	if t.Raw == "hidden" { // moderation or cancel: nothing but the state is shown
		return t, nil
	}
	rows, err := q.Query(ctx, `SELECT id, by, root, text, kind, at FROM task_notes WHERE n = $1 ORDER BY id DESC LIMIT $2`, n, noteWindow)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var nt note
		if err := rows.Scan(&nt.ID, &nt.By, &nt.Root, &nt.Text, &nt.Kind, &nt.At); err != nil {
			rows.Close()
			return nil, err
		}
		t.Notes = append(t.Notes, nt)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(t.Notes)-1; i < j; i, j = i+1, j-1 {
		t.Notes[i], t.Notes[j] = t.Notes[j], t.Notes[i]
	}
	mrows, err := q.Query(ctx, `SELECT message_id, note_id, text, at FROM a2a_msgs WHERE n = $1 ORDER BY at`, n)
	if err != nil {
		return nil, err
	}
	t.MsgIDs = map[int64]string{}
	for mrows.Next() {
		var id, text string
		var noteID *int64
		var at time.Time
		if err := mrows.Scan(&id, &noteID, &text, &at); err != nil {
			mrows.Close()
			return nil, err
		}
		switch {
		case noteID != nil:
			t.MsgIDs[*noteID] = id
		case t.First == nil:
			t.First = &firstMsg{id, text, at}
		}
	}
	mrows.Close()
	if err := mrows.Err(); err != nil {
		return nil, err
	}
	t.Blocked, t.Needs = blockedFrom(extraLines(ctx, q, n))
	return t, nil
}

// extraLines runs forge's detail-line chain (bounty, DAG needs, ...).
func extraLines(ctx context.Context, q core.Q, n int64) []string {
	var out []string
	fns := forge.TaskExtras
	if forge.TaskExtra != nil {
		fns = append([]func(context.Context, core.Q, int64) []string{forge.TaskExtra}, fns...)
	}
	for _, fn := range fns {
		for _, l := range fn(ctx, q, n) {
			if l = strings.TrimSpace(doc.SafeLine(l)); l != "" {
				out = append(out, l)
			}
		}
	}
	return out
}

// blockedFrom reads the DAG state out of the detail lines (27.4): `blocked …` or a `needs:` line
// naming a prerequisite that is not done.
func blockedFrom(lines []string) (bool, string) {
	for _, l := range lines {
		if strings.HasPrefix(l, "blocked") {
			return true, l
		}
		if strings.HasPrefix(l, "needs:") && (strings.Contains(l, " open") || strings.Contains(l, " claimed")) {
			return true, l
		}
	}
	return false, ""
}

// state is the 19.2 map: done -> completed, hidden -> canceled, ask -> input-required, live claim
// -> working, else submitted (claim expiry and blocked tasks included).
func (t *task) state() string {
	switch {
	case t.Raw == "done":
		return StCompleted
	case t.Raw == "hidden":
		return StCanceled
	case t.Ask != "":
		return StInputRequired
	case t.Live:
		return StWorking
	}
	return StSubmitted
}

func terminal(state string) bool { return state == StCompleted || state == StCanceled }

// stateOf is the cheap re-read used by long-polls.
func stateOf(ctx context.Context, q core.Q, n int64) (string, error) {
	var raw, ask string
	var until *time.Time
	err := q.QueryRow(ctx, `SELECT t.state, t.ask, c.until FROM tasks t LEFT JOIN task_claims c ON c.n = t.n WHERE t.n = $1`, n).Scan(&raw, &ask, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", core.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	t := task{Raw: raw, Ask: ask, Live: until != nil && until.After(time.Now()) && raw == "open"}
	return t.state(), nil
}

// updated is the status timestamp: the latest of creation, close and last note.
func (t *task) updated() time.Time {
	at := t.Created
	if t.Closed != nil && t.Closed.After(at) {
		at = *t.Closed
	}
	if len(t.Notes) > 0 && t.Notes[len(t.Notes)-1].At.After(at) {
		at = t.Notes[len(t.Notes)-1].At
	}
	if t.Live && t.Until.Add(-24*time.Hour).After(at) {
		at = t.Until.Add(-24 * time.Hour)
	}
	return at
}

func (t *task) contextID() string {
	if t.ContextID != "" {
		return t.ContextID
	}
	return taskID(t.N)
}

func (t *task) creator(nt note) bool { return t.Root != "" && nt.Root == t.Root }

// isResult flags holder notes (the worker's outputs) as artifacts next to done notes.
func (t *task) isResult(nt note) bool {
	return nt.Kind == "note" && t.HolderRoot != "" && nt.Root == t.HolderRoot && !t.creator(nt)
}

// sourceHost is the metadata.source prefix of outbound parts: the public host.
func sourceHost() string {
	if u, err := url.Parse(doc.Base()); err == nil && u.Host != "" {
		return u.Host
	}
	return "agents.ekaii.fr"
}

// textPart is one outbound text part; every one is flagged untrusted with its author (27.8).
func textPart(text, author string) map[string]any {
	src := sourceHost()
	if author != "" {
		src += "/" + doc.SafeLine(author)
	}
	return map[string]any{"kind": "text", "text": doc.CleanMulti(text), "metadata": map[string]any{"untrusted": true, "source": src}}
}

func message(role, id, text, author, tid, cid string, meta map[string]any) map[string]any {
	m := map[string]any{"role": role, "parts": []any{textPart(text, author)}, "messageId": id, "taskId": tid, "contextId": cid, "kind": "message"}
	if len(meta) > 0 {
		m["metadata"] = meta
	}
	return m
}

// a2a renders the Task object: status (with the open ask as its message), history (the creation
// message then the notes, newest historyLen), artifacts (done notes and holder results) and the
// metadata block. Hidden tasks show only id, contextId and status.
func (t *task) a2a(historyLen int) map[string]any {
	tid, cid := taskID(t.N), t.contextID()
	st := t.state()
	status := map[string]any{"state": st, "timestamp": t.updated().UTC().Format(time.RFC3339)}
	out := map[string]any{"id": tid, "contextId": cid, "status": status, "kind": "task"}
	if t.Raw == "hidden" {
		return out
	}
	if historyLen <= 0 {
		historyLen = DefHistory
	}
	if historyLen > MaxHistory {
		historyLen = MaxHistory
	}
	meta := map[string]any{"url": doc.Base() + "/t/" + strconv.FormatInt(t.N, 10), "title": doc.SafeLine(t.Title), "tags": t.Tags, "by": t.By}
	if t.Live {
		meta["claim"] = map[string]any{"id": t.HolderID, "until": t.Until.UTC().Format(time.RFC3339), "fence": t.Fence}
	}
	if t.Quarantine {
		meta["quarantine"] = true
	}
	if t.Blocked {
		meta["blocked"] = true
		meta["needs"] = t.Needs
	}
	out["metadata"] = meta

	var hist []any
	first := strings.TrimRight(t.Title+"\n"+t.Body, "\n")
	fid, fat := tid+"-0", t.Created
	if t.First != nil {
		fid, fat = t.First.ID, t.First.At
	}
	hist = append(hist, message("user", fid, first, t.By, tid, cid, map[string]any{"at": fat.UTC().Format(time.RFC3339)}))
	var artifacts []any
	for _, nt := range t.Notes {
		role := "agent"
		if t.creator(nt) {
			role = "user"
		}
		mid, ok := t.MsgIDs[nt.ID]
		if !ok {
			mid = "n" + strconv.FormatInt(nt.ID, 10)
		}
		m := map[string]any{"at": nt.At.UTC().Format(time.RFC3339)}
		if nt.Kind != "note" {
			m["kind"] = nt.Kind
		}
		msg := message(role, mid, nt.Text, nt.By, tid, cid, m)
		hist = append(hist, msg)
		if nt.Kind == "ask" && st == StInputRequired && nt.Text == t.Ask {
			status["message"] = msg
		}
		switch {
		case nt.Kind == "done":
			artifacts = append(artifacts, artifact("n"+strconv.FormatInt(nt.ID, 10), "done", nt.Text, nt.By))
		case t.isResult(nt):
			artifacts = append(artifacts, artifact("n"+strconv.FormatInt(nt.ID, 10), "result", nt.Text, nt.By))
		}
	}
	if st == StInputRequired && status["message"] == nil {
		status["message"] = message("agent", tid+"-ask", t.Ask, t.HolderID, tid, cid, map[string]any{"kind": "ask"})
	}
	if len(hist) > historyLen {
		hist = hist[len(hist)-historyLen:]
	}
	out["history"] = hist
	if artifacts == nil {
		artifacts = []any{}
	}
	out["artifacts"] = artifacts
	return out
}

func artifact(id, name, text, author string) map[string]any {
	return map[string]any{"artifactId": id, "name": name, "parts": []any{textPart(text, author)}}
}

// text is the compact board rendering used by the `/t <n>` read (7.2 shape, no tail).
func (t *task) text() string {
	var b strings.Builder
	b.WriteString("#" + strconv.FormatInt(t.N, 10) + " ")
	switch {
	case t.Raw == "done":
		b.WriteString("done by " + doc.SafeLine(t.By))
	case t.Raw == "hidden":
		b.WriteString("hidden")
		return b.String() + "\n"
	case t.Live:
		b.WriteString("claimed:" + doc.SafeLine(t.HolderID))
		if t.Ask != "" {
			b.WriteString(" ask")
		}
	default:
		b.WriteString("open")
	}
	b.WriteString(" " + doc.SafeLine(t.Title) + "\n")
	if t.Body != "" {
		b.WriteString("body: " + doc.Indent(t.Body) + "\n")
	}
	if len(t.Tags) > 0 {
		b.WriteString("tags: " + doc.SafeLine(strings.Join(t.Tags, ",")) + "\n")
	}
	if t.Ask != "" {
		b.WriteString("ask: " + doc.Indent(t.Ask) + "\n")
	}
	if t.Needs != "" {
		b.WriteString(t.Needs + "\n")
	}
	b.WriteString("notes: " + strconv.Itoa(len(t.Notes)) + "\n")
	start := 0
	if len(t.Notes) > 5 {
		start = len(t.Notes) - 5
	}
	for _, nt := range t.Notes[start:] {
		kind := ""
		if nt.Kind != "note" {
			kind = " " + nt.Kind
		}
		b.WriteString("- " + doc.SafeLine(nt.By) + " " + core.Date(nt.At) + kind + ": " + doc.Indent(nt.Text) + "\n")
	}
	b.WriteString("url: " + doc.Base() + "/t/" + strconv.FormatInt(t.N, 10) + "\n")
	return b.String()
}

// safe is a one-line, length-capped rendering of client text for error messages.
func safe(s string, n int) string {
	s = doc.SafeLine(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}
