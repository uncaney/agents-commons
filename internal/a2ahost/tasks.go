package a2ahost

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// A2A 0.3 states a hosted task moves through (stored verbatim, 27.7).
const (
	StSubmitted     = "submitted"
	StWorking       = "working"
	StInputRequired = "input-required"
	StCompleted     = "completed"
	StFailed        = "failed"
	StCanceled      = "canceled"
)

const (
	defHistory = 20
	maxHistory = 100
	msgWindow  = 200 // newest messages loaded per task
)

func terminal(state string) bool {
	return state == StCompleted || state == StFailed || state == StCanceled
}

// validReplyState reports whether an owner reply may move a task to state.
func validReplyState(s string) bool {
	switch s {
	case StWorking, StInputRequired, StCompleted, StFailed:
		return true
	}
	return false
}

type hmsg struct {
	Seq        int64
	MsgID      string
	Role, Text string
	State      string
	At         time.Time
}

// htask is a hosted A2A task with its message log.
type htask struct {
	Task, OwnerRoot          string
	ContextID, RequesterRoot string
	State                    string
	Created, Updated         time.Time
	Msgs                     []hmsg
}

// loadHosted reads one hosted task with its newest messages (ascending).
func loadHosted(ctx context.Context, q core.Q, task string) (*htask, error) {
	t := &htask{Task: task}
	err := q.QueryRow(ctx, `SELECT owner_root, context_id, requester_root, state, created, updated
		FROM a2a_hosted WHERE task = $1`, task).
		Scan(&t.OwnerRoot, &t.ContextID, &t.RequesterRoot, &t.State, &t.Created, &t.Updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT seq, message_id, role, text, state, at FROM a2a_hmsgs
		WHERE task = $1 ORDER BY seq DESC LIMIT $2`, task, msgWindow)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var m hmsg
		if err := rows.Scan(&m.Seq, &m.MsgID, &m.Role, &m.Text, &m.State, &m.At); err != nil {
			return nil, err
		}
		t.Msgs = append(t.Msgs, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(t.Msgs)-1; i < j; i, j = i+1, j-1 {
		t.Msgs[i], t.Msgs[j] = t.Msgs[j], t.Msgs[i]
	}
	return t, nil
}

func (t *htask) contextID() string {
	if t.ContextID != "" {
		return t.ContextID
	}
	return t.Task
}

// textPart is one outbound text part, flagged untrusted with its author role (27.8).
func textPart(text, role string) map[string]any {
	return map[string]any{"kind": "text", "text": doc.CleanMulti(text),
		"metadata": map[string]any{"untrusted": true, "source": "agents.ekaii.fr/a2a/hosted", "role": role}}
}

func message(role, mid, text, tid, cid string, meta map[string]any) map[string]any {
	m := map[string]any{"role": role, "parts": []any{textPart(text, role)}, "messageId": mid, "taskId": tid, "contextId": cid, "kind": "message"}
	if len(meta) > 0 {
		m["metadata"] = meta
	}
	return m
}

// a2a renders the hosted Task object. requester_root is disclosed only when viewerRoot is the
// owner (27.7); everyone else sees the task without it.
func (t *htask) a2a(viewerRoot string, historyLen int) map[string]any {
	if historyLen <= 0 {
		historyLen = defHistory
	}
	if historyLen > maxHistory {
		historyLen = maxHistory
	}
	tid, cid := t.Task, t.contextID()
	status := map[string]any{"state": t.State, "timestamp": t.Updated.UTC().Format(time.RFC3339)}
	out := map[string]any{"id": tid, "contextId": cid, "status": status, "kind": "task"}
	meta := map[string]any{"untrusted": true}
	if viewerRoot != "" && viewerRoot == t.OwnerRoot {
		meta["requesterRoot"] = t.RequesterRoot
	}
	out["metadata"] = meta

	var hist []any
	var artifacts []any
	for _, m := range t.Msgs {
		msg := message(m.Role, m.MsgID, m.Text, tid, cid, map[string]any{"at": m.At.UTC().Format(time.RFC3339)})
		hist = append(hist, msg)
		if m.Role == "agent" && (m.State == StCompleted || m.State == StInputRequired) {
			status["message"] = msg
		}
		if m.Role == "agent" && m.State == StCompleted {
			artifacts = append(artifacts, map[string]any{"artifactId": m.MsgID, "name": "reply", "parts": []any{textPart(m.Text, "agent")}})
		}
	}
	if len(hist) > historyLen {
		hist = hist[len(hist)-historyLen:]
	}
	if hist == nil {
		hist = []any{}
	}
	if artifacts == nil {
		artifacts = []any{}
	}
	out["history"] = hist
	out["artifacts"] = artifacts
	return out
}
