package a2ahost

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"ekaii.fr/commons/internal/a2a"
	"ekaii.fr/commons/internal/core"
)

const keepalive = 15 * time.Second

// stream serves message/stream and tasks/resubscribe as a bounded text/event-stream (27.7, P37):
// the Task first, then one status-update per change until a terminal state (final:true) or the wait
// budget (<= 85 s) expires. The stream is the request's single long-poll.
func (h *handlers) stream(ctx context.Context, w http.ResponseWriter, r *http.Request, ownerID string, id *core.Ident, rq *a2a.Request) {
	var task string
	if rq.Method == "tasks/resubscribe" {
		var in struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rq.Params, &in); err != nil || !core.ValidIDPrefix(in.ID, 'x') {
			writeRPC(w, 200, errResp(rq.ID, taskNotFound(in.ID)))
			return
		}
		task = in.ID
	} else { // message/stream: send first, then stream the resulting task
		out, _, err := h.send(ctx, r, ownerID, id, rq.Params)
		if err != nil {
			writeRPC(w, 200, errResp(rq.ID, apiToRPC(err)))
			return
		}
		tid, _ := out["id"].(string)
		if !core.ValidIDPrefix(tid, 'x') { // nothing to stream
			newSSE(w).send(okResp(rq.ID, out))
			return
		}
		task = tid
	}
	viewer := ""
	if id != nil {
		viewer = id.Root
	}
	t, err := loadHosted(ctx, h.d.DB, task)
	if err != nil {
		writeRPC(w, 200, errResp(rq.ID, taskNotFound(task)))
		return
	}
	es := newSSE(w)
	es.send(okResp(rq.ID, t.a2a(viewer, defHistory)))
	if terminal(t.State) {
		es.send(okResp(rq.ID, statusEvent(t, true)))
		return
	}
	var release func()
	if id != nil {
		rel, ok := h.d.Waiters.Acquire(id.Root, h.d.IPGroup(r))
		if !ok {
			es.send(okResp(rq.ID, statusEvent(t, false)))
			return
		}
		release = rel
	} else { // anonymous callers get the snapshot and no wait
		es.send(okResp(rq.ID, statusEvent(t, false)))
		return
	}
	defer release()
	c, cancelSub := h.d.Notify.Subscribe(taskTopic(task))
	defer cancelSub()
	deadline := time.NewTimer(maxWait * time.Second)
	defer deadline.Stop()
	ka := time.NewTicker(keepalive)
	defer ka.Stop()
	last := t.State
	for {
		select {
		case <-c:
			time.Sleep(20 * time.Millisecond)
			nt, err := loadHosted(ctx, h.d.DB, task)
			if err != nil {
				return
			}
			if nt.State != last || nt.Updated.After(t.Updated) {
				t = nt
				last = nt.State
				es.send(okResp(rq.ID, statusEvent(t, terminal(t.State))))
				if terminal(t.State) {
					return
				}
			}
		case <-ka.C:
			es.comment("keepalive")
		case <-deadline.C:
			es.send(okResp(rq.ID, statusEvent(t, false)))
			return
		case <-ctx.Done():
			return
		}
	}
}

func statusEvent(t *htask, final bool) map[string]any {
	return map[string]any{"kind": "status-update", "taskId": t.Task, "contextId": t.contextID(),
		"status": map[string]any{"state": t.State, "timestamp": t.Updated.UTC().Format(time.RFC3339)}, "final": final}
}

type sse struct {
	w http.ResponseWriter
	f http.Flusher
}

func newSSE(w http.ResponseWriter) *sse {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	h.Set("X-Robots-Tag", "noindex")
	w.WriteHeader(200)
	f, _ := w.(http.Flusher)
	e := &sse{w, f}
	e.flush()
	return e
}

func (e *sse) flush() {
	if e.f != nil {
		e.f.Flush()
	}
}

func (e *sse) send(v any) {
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	var b bytes.Buffer
	b.WriteString("data: ")
	b.Write(bytes.TrimRight(body.Bytes(), "\n"))
	b.WriteString("\n\n")
	e.w.Write(b.Bytes())
	e.flush()
}

func (e *sse) comment(s string) {
	e.w.Write([]byte(": " + s + "\n\n"))
	e.flush()
}
