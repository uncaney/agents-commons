package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
)

// PendingMsg is the status message of an anonymous wait-lane ticket (27.2).
const PendingMsg = "anonymous ticket; becomes a board task when fetched with tasks/get after 30 s, within 10 min"

// grammarRe selects the inline reads (27.2); core.Reserved refuses such titles on the board.
var grammarRe = regexp.MustCompile(`^/(q|e|k|t|v|x|help|grammar)(\s|$)`)

type partIn struct {
	Kind string          `json:"kind"`
	Type string          `json:"type"` // pre-0.3 clients
	Text *string         `json:"text"`
	File json.RawMessage `json:"file"`
	Data json.RawMessage `json:"data"`
}

type messageIn struct {
	Role      string                     `json:"role"`
	Parts     []partIn                   `json:"parts"`
	MessageID string                     `json:"messageId"`
	TaskID    string                     `json:"taskId"`
	ContextID string                     `json:"contextId"`
	Metadata  map[string]json.RawMessage `json:"metadata"`
}

type sendIn struct {
	Message       messageIn `json:"message"`
	Configuration struct {
		Blocking      bool `json:"blocking"`
		HistoryLength *int `json:"historyLength"`
	} `json:"configuration"`
	Metadata map[string]json.RawMessage `json:"metadata"`
}

// partsText validates the parts (text only; file/data refused, file.uri never fetched) and joins
// them with newlines. The first part comes back separately for the grammar check.
func partsText(parts []partIn) (first, all string, err error) {
	if len(parts) == 0 {
		return "", "", rpcErr(CodeParams, "invalid params: message.parts required (text parts)", nil)
	}
	var b strings.Builder
	for i, p := range parts {
		kind := p.Kind
		if kind == "" {
			kind = p.Type
		}
		switch {
		case kind == "file" || kind == "data" || len(p.File) > 0 || len(p.Data) > 0:
			return "", "", rpcErr(CodeContentType, "err bad text parts only: file and data parts are not accepted (file.uri is never fetched)",
				map[string]any{"err": "bad", "status": 415, "next": []string{"GET /help"}})
		case kind != "text" || p.Text == nil:
			return "", "", rpcErr(CodeParams, "invalid params: part kind must be text", nil)
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(*p.Text)
		if b.Len() > MaxText {
			return "", "", core.Bad("text <= 8 KiB (title <=160 + body <=4000, or a note <=2000)")
		}
	}
	return *parts[0].Text, b.String(), nil
}

// messageID validates the client's messageId (one line, <= 128) or mints one.
func messageID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return core.NewID('m'), nil
	}
	if len(s) > 128 || !doc.OneLine(s) {
		return "", rpcErr(CodeParams, "invalid params: messageId one line <= 128", nil)
	}
	return s, nil
}

// send is message/send: inline read, anonymous ticket, note or task; then the optional blocking
// long-poll. n is 0 when no board task is involved (reads, tickets).
func (s *server) send(ctx context.Context, rc *reqCtx, params json.RawMessage) (map[string]any, int64, error) {
	var in sendIn
	if err := json.Unmarshal(params, &in); err != nil {
		return nil, 0, rpcErr(CodeParams, "invalid params: "+safe(err.Error(), 80), nil)
	}
	first, text, err := partsText(in.Message.Parts)
	if err != nil {
		return nil, 0, err
	}
	hist := histLen(in.Configuration.HistoryLength)
	if in.Message.TaskID == "" {
		if m := grammarRe.FindStringSubmatch(strings.TrimLeft(first, " \t")); m != nil {
			arg := strings.TrimSpace(strings.TrimLeft(first, " \t")[len(m[0]):])
			out, err := s.readTask(ctx, rc, m[1], arg)
			return out, 0, err
		}
	}
	id := rc.ident
	if id == nil {
		if in.Message.TaskID != "" {
			rc.wantPoW = true
			return nil, 0, authErr(core.ErrAuth)
		}
		out, err := s.pending(ctx, rc, strings.TrimPrefix(text, "/w "))
		return out, 0, err
	}
	if err := s.writeAuth(id); err != nil {
		return nil, 0, err
	}
	mid, err := messageID(in.Message.MessageID)
	if err != nil {
		return nil, 0, err
	}
	if n, found, err := s.replay(ctx, id, mid); err != nil {
		return nil, 0, err
	} else if found {
		out, err := s.taskResult(ctx, rc, n, hist, false, 0)
		return out, n, err
	}
	var n int64
	if in.Message.TaskID != "" {
		var ok bool
		if n, ok = parseTaskID(in.Message.TaskID); !ok {
			return nil, 0, taskNotFound(in.Message.TaskID)
		}
		if err := s.addNote(ctx, id, n, mid, text); err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return nil, 0, taskNotFound(in.Message.TaskID)
			}
			return nil, 0, err
		}
		s.d.Notify.Wake(forge.TaskTopic(n))
	} else {
		if n, err = s.create(ctx, id, &in, mid, strings.TrimPrefix(text, "/w ")); err != nil {
			return nil, 0, err
		}
	}
	out, err := s.taskResult(ctx, rc, n, hist, in.Configuration.Blocking, metaInt(in.Metadata, "wait"))
	return out, n, err
}

// replay answers an idempotent retry: the same root's messageId returns its task; another root's
// is refused.
func (s *server) replay(ctx context.Context, id *core.Ident, mid string) (int64, bool, error) {
	var n int64
	var root string
	err := s.d.DB.QueryRow(ctx, `SELECT n, root FROM a2a_msgs WHERE message_id = $1`, mid).Scan(&n, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if root != id.Root {
		return 0, false, rpcErr(CodeParams, "invalid params: messageId already used", nil)
	}
	return n, true, nil
}

// create posts the task through forge (scrub, lexicon, caps, template, origin, event) and records
// the creation message with the text as stored.
func (s *server) create(ctx context.Context, id *core.Ident, in *sendIn, mid, text string) (int64, error) {
	title, body, _ := strings.Cut(text, "\n")
	tags := tagsOf(in.Message.Metadata["tags"])
	if tags == nil {
		tags = tagsOf(in.Metadata["tags"])
	}
	n, err := forge.CreateTask(ctx, s.d, id, forge.TaskInput{Title: title, Body: body, Tags: tags, ContextID: strings.TrimSpace(in.Message.ContextID)})
	if err != nil {
		return 0, err
	}
	_, err = s.d.DB.Exec(ctx, `INSERT INTO a2a_msgs (message_id, n, root, role, text)
		SELECT $1, n, $3, 'user', left(title || E'\n' || body, 8192) FROM tasks WHERE n = $2 ON CONFLICT (message_id) DO NOTHING`, mid, n, id.Root)
	return n, err
}

func tagsOf(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var tags []string
	if json.Unmarshal(raw, &tags) != nil || len(tags) > 16 {
		return nil
	}
	return tags
}

// addNote writes the note through forge (caps, scrub; a creator's note clears the ask) and the
// a2a_msgs row linking the messageId to it, in one transaction.
func (s *server) addNote(ctx context.Context, id *core.Ident, n int64, mid, text string) error {
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := forge.AddNoteAs(ctx, tx, n, id.ID, id.Root, text); err != nil {
			return err
		}
		var noteID int64
		var stored string
		if err := tx.QueryRow(ctx, `SELECT id, text FROM task_notes WHERE n = $1 AND by = $2 ORDER BY id DESC LIMIT 1`, n, id.ID).Scan(&noteID, &stored); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO a2a_msgs (message_id, n, root, role, text, note_id) VALUES ($1, $2, $3, 'user', $4, $5)`, mid, n, id.Root, stored, noteID)
		return err
	})
}

// pending turns an anonymous send into a wait-lane ticket through PendingFn; without it the
// caller gets the 401 with the PoW hint (A2A clients cannot do PoW themselves).
func (s *server) pending(ctx context.Context, rc *reqCtx, text string) (map[string]any, error) {
	if PendingFn == nil {
		rc.wantPoW = true
		return nil, authErr(core.ErrAuth)
	}
	if len(text) > MaxReadText {
		return nil, core.Bad("text <= 4 KiB")
	}
	ticket, err := PendingFn(ctx, s.d.DB, s.d.IPGroup(rc.r), s.d.IPSuper(rc.r), text)
	if err != nil {
		return nil, err
	}
	return pendingTask(ticket, StWorking), nil
}

func pendingTask(ticket, state string) map[string]any {
	if state == "" {
		state = StWorking
	}
	return map[string]any{"id": ticket, "contextId": ticket, "kind": "task",
		"status": map[string]any{"state": state, "timestamp": time.Now().UTC().Format(time.RFC3339),
			"message": message("agent", ticket+"-0", PendingMsg, "", ticket, ticket, nil)},
		"metadata": map[string]any{"ticket": true, "next": "tasks/get {\"id\":\"" + ticket + "\"} after 30 s"}}
}

// taskResult loads task n, runs the request's single blocking wait when asked and renders it.
func (s *server) taskResult(ctx context.Context, rc *reqCtx, n int64, hist int, blocking bool, wait int) (map[string]any, error) {
	t, err := loadTask(ctx, s.d.DB, n)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil, taskNotFound(taskID(n))
		}
		return nil, err
	}
	retry, waited := 0, 0
	if blocking && !rc.blocked {
		rc.blocked = true
		if from := t.state(); !terminal(from) {
			if retry, waited = s.waitChange(ctx, rc, n, from, wait); waited > 0 || retry > 0 {
				if t, err = loadTask(ctx, s.d.DB, n); err != nil {
					return nil, err
				}
			}
		}
	}
	out := t.a2a(hist)
	if retry > 0 || waited > 0 {
		meta, _ := out["metadata"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
			out["metadata"] = meta
		}
		if retry > 0 {
			meta["retry"] = retry
		}
		if waited > 0 {
			meta["waited_ms"] = waited
		}
	}
	return out, nil
}

// get is tasks/get: board tasks, wait-lane tickets (PendingGetFn) and inline read ids (-32001).
func (s *server) get(ctx context.Context, rc *reqCtx, params json.RawMessage) (any, error) {
	var in struct {
		ID            string                     `json:"id"`
		HistoryLength *int                       `json:"historyLength"`
		Metadata      map[string]json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(params, &in); err != nil {
		return nil, rpcErr(CodeParams, "invalid params: "+safe(err.Error(), 80), nil)
	}
	hist := histLen(in.HistoryLength)
	switch {
	case core.ValidIDPrefix(in.ID, 'q'):
		if PendingGetFn == nil {
			return nil, taskNotFound(in.ID)
		}
		n, state, err := PendingGetFn(ctx, s.d, in.ID)
		if err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return nil, taskNotFound(in.ID)
			}
			return nil, err
		}
		if n <= 0 {
			return pendingTask(in.ID, state), nil
		}
		out, err := s.taskResult(ctx, rc, n, hist, false, 0)
		if err == nil {
			meta, _ := out["metadata"].(map[string]any)
			if meta == nil {
				meta = map[string]any{}
				out["metadata"] = meta
			}
			meta["ticket"] = in.ID
		}
		return out, err
	case core.ValidIDPrefix(in.ID, 'r'):
		return nil, rpcErr(CodeTaskNotFound, "err notfound inline read results are not stored; repeat the message/send",
			map[string]any{"err": "notfound", "status": 404, "next": []string{"POST /a2a message/send", "GET /help"}})
	}
	n, ok := parseTaskID(in.ID)
	if !ok {
		return nil, taskNotFound(in.ID)
	}
	return s.taskResult(ctx, rc, n, hist, metaBool(in.Metadata, "blocking"), metaInt(in.Metadata, "wait"))
}

// cancel is tasks/cancel (creator root only): hides the task (claims released, mirror closed) and
// records the audit row and the event; done or hidden tasks are not cancelable (-32002).
func (s *server) cancel(ctx context.Context, rc *reqCtx, params json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &in); err != nil {
		return nil, rpcErr(CodeParams, "invalid params: "+safe(err.Error(), 80), nil)
	}
	id := rc.ident
	if id == nil {
		rc.wantPoW = true
		return nil, authErr(core.ErrAuth)
	}
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	n, ok := parseTaskID(in.ID)
	if !ok {
		return nil, taskNotFound(in.ID)
	}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var state, root string
		err := tx.QueryRow(ctx, `SELECT state, root FROM tasks WHERE n = $1 FOR UPDATE`, n).Scan(&state, &root)
		if errors.Is(err, pgx.ErrNoRows) {
			return taskNotFound(in.ID)
		}
		if err != nil {
			return err
		}
		if root == "" || root != id.Root {
			return core.E(403, "auth", "creator only")
		}
		if state != "open" {
			st := StCompleted
			if state == "hidden" {
				st = StCanceled
			}
			return notCancelable(taskID(n), st)
		}
		return core.Audit(ctx, tx, id.ID, "tcancel", taskID(n)[1:], 0)
	})
	if err != nil {
		return nil, err
	}
	if err := forge.HideTask(ctx, s.d, int(n)); err != nil {
		return nil, err
	}
	if err := core.Event(ctx, s.d.DB, "t", taskID(n)[1:], "", "canceled by "+id.ID); err != nil {
		return nil, err
	}
	s.d.Notify.Wake(forge.TaskTopic(n))
	return s.taskResult(ctx, rc, n, DefHistory, false, 0)
}
