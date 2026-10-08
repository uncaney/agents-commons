package a2ahost

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/a2a"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/mail"
)

// hosted serves POST /a2a/{id}: A2A 0.3 JSON-RPC to one hosted agent. Reads are anonymous; writes
// (message/send, tasks/cancel) need a cx_ bearer. Streaming methods take one request per HTTP call.
func (h *handlers) hosted(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		core.Err(w, r, http.StatusMethodNotAllowed, "bad", "a2a: POST /a2a/<id> JSON-RPC 2.0 (A2A 0.3): message/send | message/stream | tasks/get | tasks/resubscribe | tasks/cancel; card GET /a/<id>/agent.json")
		return
	}
	ownerID := r.PathValue("id")
	body, err := core.ReadAll(w, r, a2a.MaxBody)
	if err != nil {
		writeRPC(w, 400, errResp(nil, rpcErr(a2a.CodeInvalid, safe(err.Error(), 120), nil)))
		return
	}
	reqs, perr := a2a.Parse(body)
	if perr != nil {
		var e *a2a.Error
		if errors.As(perr, &e) {
			writeRPC(w, 400, errResp(nil, e))
			return
		}
		writeRPC(w, 400, errResp(nil, rpcErr(a2a.CodeParse, "parse error", nil)))
		return
	}
	batch := a2a.IsBatch(body)
	id, _ := h.d.AuthOpt(r)
	ctx, cancel := context.WithTimeout(r.Context(), (maxWait+5)*time.Second)
	defer cancel()

	if !batch && streamMethod(reqs[0].Method) && !reqs[0].Notification() {
		h.stream(ctx, w, r, ownerID, id, &reqs[0])
		return
	}
	var out []rpcResponse
	for i := range reqs {
		if resp, ok := h.dispatch(ctx, r, ownerID, id, &reqs[i]); ok {
			out = append(out, resp)
		}
	}
	if len(out) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if batch {
		writeRPC(w, 200, out)
		return
	}
	writeRPC(w, 200, out[0])
}

func streamMethod(m string) bool { return m == "message/stream" || m == "tasks/resubscribe" }

// dispatch handles one JSON-RPC call; ok=false for notifications.
func (h *handlers) dispatch(ctx context.Context, r *http.Request, ownerID string, id *core.Ident, rq *a2a.Request) (rpcResponse, bool) {
	if rq.Notification() {
		return rpcResponse{}, false
	}
	if rq.Method == "" {
		return errResp(rq.ID, rpcErr(a2a.CodeInvalid, "invalid request: method required", nil)), true
	}
	var res any
	var err error
	switch rq.Method {
	case "message/send":
		res, _, err = h.send(ctx, r, ownerID, id, rq.Params)
	case "message/stream", "tasks/resubscribe":
		err = rpcErr(a2a.CodeInvalid, "invalid request: streaming methods take one request per HTTP call", nil)
	case "tasks/get":
		res, err = h.get(ctx, id, rq.Params)
	case "tasks/cancel":
		res, err = h.cancel(ctx, id, rq.Params)
	default:
		err = rpcErr(a2a.CodeMethod, "method not found: "+safe(rq.Method, 60), nil)
	}
	if err != nil {
		return errResp(rq.ID, apiToRPC(err)), true
	}
	return okResp(rq.ID, res), true
}

// writeAuth is the hosted write gate: a non-banned bearer and no write freeze.
func (h *handlers) writeAuth(id *core.Ident) error {
	switch {
	case id == nil:
		return core.ErrAuth
	case id.Banned:
		return core.ErrBanned
	case h.d.Frozen("write"):
		return core.Frozen("write")
	case id.Scopes != nil && !core.ScopeAllowed(id.Scopes, "mb:w"):
		return core.E(403, "scope", "mb:w required")
	}
	return nil
}

type partIn struct {
	Kind string          `json:"kind"`
	Type string          `json:"type"`
	Text *string         `json:"text"`
	File json.RawMessage `json:"file"`
	Data json.RawMessage `json:"data"`
}

type messageIn struct {
	Role      string   `json:"role"`
	Parts     []partIn `json:"parts"`
	MessageID string   `json:"messageId"`
	TaskID    string   `json:"taskId"`
	ContextID string   `json:"contextId"`
}

type sendIn struct {
	Message       messageIn `json:"message"`
	Configuration struct {
		HistoryLength *int `json:"historyLength"`
	} `json:"configuration"`
}

// partsText joins the text parts (file/data refused, file.uri never fetched).
func partsText(parts []partIn) (string, error) {
	if len(parts) == 0 {
		return "", rpcErr(a2a.CodeParams, "invalid params: message.parts required (text parts)", nil)
	}
	var b strings.Builder
	for i, p := range parts {
		kind := p.Kind
		if kind == "" {
			kind = p.Type
		}
		switch {
		case kind == "file" || kind == "data" || len(p.File) > 0 || len(p.Data) > 0:
			return "", rpcErr(a2a.CodeContentType, "err bad text parts only: file and data parts are not accepted (file.uri is never fetched)",
				map[string]any{"err": "bad", "status": 415})
		case kind != "text" || p.Text == nil:
			return "", rpcErr(a2a.CodeParams, "invalid params: part kind must be text", nil)
		}
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(*p.Text)
		if b.Len() > MaxText {
			return "", core.Bad("text <= 8 KiB")
		}
	}
	return b.String(), nil
}

func messageID(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return core.NewID('m'), nil
	}
	if len(s) > 128 || !doc.OneLine(s) {
		return "", rpcErr(a2a.CodeParams, "invalid params: messageId one line <= 128", nil)
	}
	return s, nil
}

func histLen(p *int) int {
	if p == nil || *p <= 0 {
		return defHistory
	}
	if *p > maxHistory {
		return maxHistory
	}
	return *p
}

// send is message/send: open a hosted task (or append to one) and relay the text to the owner's
// mailbox through the normal mail gates. n is unused (A2A shape parity); returns the Task map.
func (h *handlers) send(ctx context.Context, r *http.Request, ownerID string, id *core.Ident, params json.RawMessage) (map[string]any, int64, error) {
	var in sendIn
	if err := json.Unmarshal(params, &in); err != nil {
		return nil, 0, rpcErr(a2a.CodeParams, "invalid params: "+safe(err.Error(), 80), nil)
	}
	text, err := partsText(in.Message.Parts)
	if err != nil {
		return nil, 0, err
	}
	if strings.TrimSpace(text) == "" {
		return nil, 0, core.Bad("text required")
	}
	if err := h.writeAuth(id); err != nil {
		return nil, 0, err
	}
	mid, err := messageID(in.Message.MessageID)
	if err != nil {
		return nil, 0, err
	}
	hist := histLen(in.Configuration.HistoryLength)
	// Idempotent retry: the same messageId returns its task to its requester.
	if task, rroot, found, err := h.replay(ctx, mid); err != nil {
		return nil, 0, err
	} else if found {
		if rroot != id.Root {
			return nil, 0, rpcErr(a2a.CodeParams, "invalid params: messageId already used", nil)
		}
		t, err := loadHosted(ctx, h.d.DB, task)
		if err != nil {
			return nil, 0, err
		}
		return t.a2a(id.Root, hist), 0, nil
	}
	if in.Message.TaskID == "" {
		return h.openTask(ctx, ownerID, id, mid, text, strings.TrimSpace(in.Message.ContextID), hist)
	}
	return h.continueTask(ctx, ownerID, id, in.Message.TaskID, mid, text, hist)
}

// replay reports whether a messageId was already stored and the task/requester it belongs to.
func (h *handlers) replay(ctx context.Context, mid string) (task, rroot string, found bool, err error) {
	err = h.d.DB.QueryRow(ctx, `SELECT m.task, t.requester_root FROM a2a_hmsgs m JOIN a2a_hosted t ON t.task = m.task WHERE m.message_id = $1`, mid).Scan(&task, &rroot)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return task, rroot, true, nil
}

// openTask creates a hosted task for owner ownerID and relays the first message.
func (h *handlers) openTask(ctx context.Context, ownerID string, id *core.Ident, mid, text, contextID string, hist int) (map[string]any, int64, error) {
	cr, err := loadCardByID(ctx, h.d.DB, ownerID)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil, 0, rpcErr(a2a.CodeTaskNotFound, "err notfound no hosted agent "+safe(ownerID, 40), map[string]any{"err": "notfound", "status": 404})
		}
		return nil, 0, err
	}
	if cr.Inbound != "open" {
		return nil, 0, rpcErr(a2a.CodeUnsupported, "err closed this agent's inbound is closed", map[string]any{"err": "closed", "status": 403})
	}
	task := core.NewID('x')
	if contextID != "" && (len(contextID) > 64 || !doc.OneLine(contextID)) {
		return nil, 0, core.Bad("contextId one line <= 64")
	}
	err = core.Tx(ctx, h.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO a2a_hosted (task, owner_root, context_id, requester_root, state) VALUES ($1, $2, $3, $4, $5)`,
			task, cr.Root, contextID, id.Root, StSubmitted); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO a2a_hmsgs (task, message_id, role, text, state) VALUES ($1, $2, 'user', $3, '')`, task, mid, cutText(text)); err != nil {
			return err
		}
		// Relay to the owner's mailbox through the normal mail gates (a refused send rolls back).
		if _, _, err := mail.Send(ctx, tx, id, ownerID, "a2a", task, text); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	h.d.Notify.Wake(inboxTopic(cr.Root))
	t, err := loadHosted(ctx, h.d.DB, task)
	if err != nil {
		return nil, 0, err
	}
	return t.a2a(id.Root, hist), 0, nil
}

// continueTask appends a requester message to an existing hosted task and relays it.
func (h *handlers) continueTask(ctx context.Context, ownerID string, id *core.Ident, task, mid, text string, hist int) (map[string]any, int64, error) {
	if !core.ValidIDPrefix(task, 'x') {
		return nil, 0, taskNotFound(task)
	}
	var ownerRoot string
	err := core.Tx(ctx, h.d.DB, func(tx pgx.Tx) error {
		var rroot, state string
		err := tx.QueryRow(ctx, `SELECT owner_root, requester_root, state FROM a2a_hosted WHERE task = $1 FOR UPDATE`, task).Scan(&ownerRoot, &rroot, &state)
		if errors.Is(err, pgx.ErrNoRows) {
			return taskNotFound(task)
		}
		if err != nil {
			return err
		}
		if rroot != id.Root {
			return taskNotFound(task) // only the requester continues; the owner uses the reply API
		}
		if terminal(state) {
			return rpcErr(a2a.CodeNotCancel, "err bad task "+safe(task, 40)+" is "+state, map[string]any{"err": "bad", "status": 409})
		}
		if _, err := tx.Exec(ctx, `INSERT INTO a2a_hmsgs (task, message_id, role, text, state) VALUES ($1, $2, 'user', $3, '')`, task, mid, cutText(text)); err != nil {
			return err
		}
		// A requester message answers an input-required ask, moving the task back to working.
		next := state
		if state == StInputRequired {
			next = StWorking
		}
		if _, err := tx.Exec(ctx, `UPDATE a2a_hosted SET state = $2, updated = now() WHERE task = $1`, task, next); err != nil {
			return err
		}
		if _, _, err := mail.Send(ctx, tx, id, ownerID, "a2a", task, text); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	h.d.Notify.Wake(inboxTopic(ownerRoot))
	h.d.Notify.Wake(taskTopic(task))
	t, err := loadHosted(ctx, h.d.DB, task)
	if err != nil {
		return nil, 0, err
	}
	return t.a2a(id.Root, hist), 0, nil
}

// get is tasks/get: the requester or owner reads the task.
func (h *handlers) get(ctx context.Context, id *core.Ident, params json.RawMessage) (any, error) {
	var in struct {
		ID            string `json:"id"`
		HistoryLength *int   `json:"historyLength"`
	}
	if err := json.Unmarshal(params, &in); err != nil {
		return nil, rpcErr(a2a.CodeParams, "invalid params: "+safe(err.Error(), 80), nil)
	}
	if !core.ValidIDPrefix(in.ID, 'x') {
		return nil, taskNotFound(in.ID)
	}
	t, err := loadHosted(ctx, h.d.DB, in.ID)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil, taskNotFound(in.ID)
		}
		return nil, err
	}
	viewer := ""
	if id != nil {
		viewer = id.Root
	}
	// Only a participant (requester or owner) may read the task; everyone else gets the
	// identical task-not-found, so a hosted conversation never leaks to a third party.
	if viewer == "" || (viewer != t.RequesterRoot && viewer != t.OwnerRoot) {
		return nil, taskNotFound(in.ID)
	}
	return t.a2a(viewer, histLen(in.HistoryLength)), nil
}

// cancel is tasks/cancel (requester root only): moves the task to canceled.
func (h *handlers) cancel(ctx context.Context, id *core.Ident, params json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &in); err != nil {
		return nil, rpcErr(a2a.CodeParams, "invalid params: "+safe(err.Error(), 80), nil)
	}
	if err := h.writeAuth(id); err != nil {
		return nil, err
	}
	if !core.ValidIDPrefix(in.ID, 'x') {
		return nil, taskNotFound(in.ID)
	}
	err := core.Tx(ctx, h.d.DB, func(tx pgx.Tx) error {
		var rroot, state string
		err := tx.QueryRow(ctx, `SELECT requester_root, state FROM a2a_hosted WHERE task = $1 FOR UPDATE`, in.ID).Scan(&rroot, &state)
		if errors.Is(err, pgx.ErrNoRows) {
			return taskNotFound(in.ID)
		}
		if err != nil {
			return err
		}
		if rroot != id.Root {
			return rpcErr(a2a.CodeTaskNotFound, "err notfound task "+safe(in.ID, 40), map[string]any{"err": "notfound", "status": 404})
		}
		if terminal(state) {
			return rpcErr(a2a.CodeNotCancel, "err bad task "+safe(in.ID, 40)+" is "+state, map[string]any{"err": "bad", "status": 409})
		}
		_, err = tx.Exec(ctx, `UPDATE a2a_hosted SET state = $2, updated = now() WHERE task = $1`, in.ID, StCanceled)
		return err
	})
	if err != nil {
		return nil, err
	}
	h.d.Notify.Wake(taskTopic(in.ID))
	t, err := loadHosted(ctx, h.d.DB, in.ID)
	if err != nil {
		return nil, err
	}
	return t.a2a(id.Root, defHistory), nil
}

// cutText bounds the stored copy of a relayed message to the a2a_hmsgs column cap.
func cutText(s string) string {
	if len(s) <= MaxText {
		return s
	}
	return strings.ToValidUTF8(s[:MaxText], "")
}

func inboxTopic(ownerRoot string) string { return "a2ain:" + ownerRoot }
func taskTopic(task string) string       { return "a2a:" + task }
