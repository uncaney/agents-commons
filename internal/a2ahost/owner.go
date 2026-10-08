package a2ahost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

// inMsg is one inbound hosted-A2A message as the owner reads it.
type inMsg struct {
	Seq           int64
	Task          string
	RequesterRoot string
	State         string
	Text          string
	At            time.Time
}

// loadInbound reads the owner's inbound requester messages after a cursor (ascending by seq).
func loadInbound(ctx context.Context, q core.Q, ownerRoot string, after int64, k int) ([]inMsg, error) {
	rows, err := q.Query(ctx, `SELECT m.seq, m.task, t.requester_root, t.state, m.text, m.at
		FROM a2a_hmsgs m JOIN a2a_hosted t ON t.task = m.task
		WHERE t.owner_root = $1 AND m.role = 'user' AND m.seq > $2
		ORDER BY m.seq LIMIT $3`, ownerRoot, after, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []inMsg
	for rows.Next() {
		var m inMsg
		if err := rows.Scan(&m.Seq, &m.Task, &m.RequesterRoot, &m.State, &m.Text, &m.At); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// inbound serves GET /v1/a2a/in?after=&wait<=85: the owner's new inbound hosted-A2A messages, with
// an optional long-poll that wakes when a requester sends.
func (h *handlers) inbound(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	if after < 0 {
		after = 0
	}
	k := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("k")); err == nil && v > 0 && v <= 200 {
		k = v
	}
	wait := clampWait(r.URL.Query().Get("wait"))
	msgs, err := loadInbound(r.Context(), h.d.DB, id.Root, after, k)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if len(msgs) == 0 && wait > 0 {
		if rel, ok := h.d.Waiters.Acquire(id.Root, h.d.IPGroup(r)); ok {
			msgs = h.waitInbound(r.Context(), id.Root, after, k, wait)
			rel()
		}
	}
	h.replyInbound(w, r, msgs, after)
}

// waitInbound blocks up to wait seconds for new inbound, re-reading on each wake.
func (h *handlers) waitInbound(ctx context.Context, ownerRoot string, after int64, k, wait int) []inMsg {
	c, cancel := h.d.Notify.Subscribe(inboxTopic(ownerRoot))
	defer cancel()
	deadline := time.NewTimer(time.Duration(wait) * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-c:
			time.Sleep(20 * time.Millisecond)
			if msgs, err := loadInbound(ctx, h.d.DB, ownerRoot, after, k); err == nil && len(msgs) > 0 {
				return msgs
			}
		case <-deadline.C:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

func (h *handlers) replyInbound(w http.ResponseWriter, r *http.Request, msgs []inMsg, after int64) {
	d := &doc.Doc{Head: fmt.Sprintf("a2a inbound: %d", len(msgs)), Budget: 400, MaxAge: -1,
		Cols: []string{"seq", "task", "from", "state", "text"}}
	cur := after
	for _, m := range msgs {
		if m.Seq > cur {
			cur = m.Seq
		}
		d.Rows = append(d.Rows, []string{strconv.FormatInt(m.Seq, 10), m.Task, m.RequesterRoot, m.State, doc.SafeLine(m.Text)})
	}
	d.Fields = []doc.F{{Name: "after", Val: strconv.FormatInt(cur, 10)}}
	d.Next = []doc.Action{doc.GET("/v1/a2a/in?after="+strconv.FormatInt(cur, 10), "next inbound")}
	doc.Reply(w, r, 200, d)
}

// clampWait parses and bounds a wait parameter to [0, maxWait].
func clampWait(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return 0
	}
	if v > maxWait {
		return maxWait
	}
	return v
}

type replyIn struct {
	Text  string `json:"text"`
	State string `json:"state"`
}

// reply serves POST /v1/a2a/{task}/reply {text, state}: the owner appends a message and moves the
// task state, waking the requester's stream and writing a root-scoped event for the requester.
func (h *handlers) reply(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in replyIn
	if err := core.Decode(w, r, replyBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	task := r.PathValue("task")
	state, err := h.doReply(r.Context(), id, task, in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: "ok reply " + task + " state=" + state, MaxAge: -1,
		Next: []doc.Action{doc.GET("/v1/a2a/in", "inbound")}}
	doc.Reply(w, r, 200, d)
}

// doReply is the shared reply logic for the HTTP route and the MCP op.
func (h *handlers) doReply(ctx context.Context, id *core.Ident, task string, in replyIn) (string, error) {
	if !core.ValidIDPrefix(task, 'x') {
		return "", core.ErrNotFound
	}
	text := strings.TrimRight(doc.CleanMulti(scrub.Normalize(in.Text)), "\n")
	if strings.TrimSpace(text) == "" {
		return "", core.Bad("text required")
	}
	if len(text) > MaxText {
		return "", core.ErrSize
	}
	fields := map[string]*string{"text": &text}
	if _, aerr := scrub.RejectOrMask(fields); aerr != nil {
		return "", aerr
	}
	state := strings.TrimSpace(in.State)
	if state == "" {
		state = StWorking
	}
	if !validReplyState(state) {
		return "", core.Bad("state must be working, input-required, completed or failed")
	}
	var requester string
	err := core.Tx(ctx, h.d.DB, func(tx pgx.Tx) error {
		var ownerRoot, cur string
		err := tx.QueryRow(ctx, `SELECT owner_root, requester_root, state FROM a2a_hosted WHERE task = $1 FOR UPDATE`, task).Scan(&ownerRoot, &requester, &cur)
		if errors.Is(err, pgx.ErrNoRows) {
			return core.ErrNotFound
		}
		if err != nil {
			return err
		}
		if ownerRoot != id.Root {
			return core.E(403, "auth", "owner only")
		}
		if terminal(cur) {
			return core.E(409, "dup", "task is "+cur)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO a2a_hmsgs (task, message_id, role, text, state) VALUES ($1, $2, 'agent', $3, $4)`, task, core.NewID('m'), cutText(text), state); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE a2a_hosted SET state = $2, updated = now() WHERE task = $1`, task, state); err != nil {
			return err
		}
		// Root-scoped event so the requester's /v1/events stream learns of the reply.
		return core.Event(ctx, tx, "a2a", task, requester, "a2a reply "+state)
	})
	if err != nil {
		return "", err
	}
	h.d.Notify.Wake(taskTopic(task))
	return state, nil
}

// opInbound is the MCP a2ain op: the owner's new inbound messages (no long-poll).
func (h *handlers) opInbound(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if id == nil {
		return "", core.ErrAuth
	}
	var in struct {
		After int64 `json:"after"`
		K     int   `json:"k"`
	}
	if len(a) > 0 && string(a) != "null" {
		if err := json.Unmarshal(a, &in); err != nil {
			return "", core.Bad("a: " + err.Error())
		}
	}
	k := 50
	if in.K > 0 && in.K <= 200 {
		k = in.K
	}
	msgs, err := loadInbound(ctx, h.d.DB, id.Root, in.After, k)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	cur := in.After
	fmt.Fprintf(&b, "a2a inbound: %d", len(msgs))
	for _, m := range msgs {
		if m.Seq > cur {
			cur = m.Seq
		}
		fmt.Fprintf(&b, "\n%d %s from=%s %s: %s", m.Seq, m.Task, m.RequesterRoot, m.State, doc.SafeLine(m.Text))
	}
	fmt.Fprintf(&b, "\nafter=%d", cur)
	return b.String(), nil
}

// opReply is the MCP a2ar op: owner reply to a hosted task.
func (h *handlers) opReply(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if id == nil {
		return "", core.ErrAuth
	}
	var in struct {
		Task  string `json:"task"`
		Text  string `json:"text"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(a, &in); err != nil {
		return "", core.Bad("a: " + err.Error())
	}
	state, err := h.doReply(ctx, id, in.Task, replyIn{Text: in.Text, State: in.State})
	if err != nil {
		return "", err
	}
	return "ok reply " + in.Task + " state=" + state, nil
}
