package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/forge"
)

const keepalive = 15 * time.Second

// stream serves message/stream and tasks/resubscribe as text/event-stream (27.7): the Task first
// (SSE id = the resume cursor), then one TaskStatusUpdateEvent per board event (id = events.seq)
// with TaskArtifactUpdateEvents for new done/result notes, until a terminal state (final:true) or
// the wait budget runs out (status event carrying metadata.resume). Last-Event-ID or
// params.metadata.after resume after a seq: the missed events replay first. The stream is the
// request's single long-poll; anonymous callers get the snapshot and the cursor only.
func (s *server) stream(ctx context.Context, w http.ResponseWriter, rq *Request, rc *reqCtx) {
	rc.calls++
	if rc.authErr != nil {
		writeJSON(w, 200, errResp(rq.ID, authErr(core.ErrBadToken)))
		return
	}
	var in struct {
		ID       string                     `json:"id"`
		Metadata map[string]json.RawMessage `json:"metadata"`
	}
	if err := json.Unmarshal(rq.Params, &in); err != nil {
		writeJSON(w, 200, errResp(rq.ID, rpcErr(CodeParams, "invalid params: "+safe(err.Error(), 80), nil)))
		return
	}
	var n int64
	if rq.Method == "tasks/resubscribe" {
		var ok bool
		if n, ok = parseTaskID(in.ID); !ok || core.ValidIDPrefix(in.ID, 'q') || core.ValidIDPrefix(in.ID, 'r') {
			writeJSON(w, 200, errResp(rq.ID, taskNotFound(in.ID)))
			return
		}
	} else {
		out, sn, err := s.send(ctx, rc, rq.Params)
		if err != nil {
			status := 200
			if rc.wantPoW {
				s.d.PoWAuthenticate(w, rc.r)
				status = 401
			}
			writeJSON(w, status, errResp(rq.ID, s.toRPC(err, rq.Method)))
			return
		}
		if sn == 0 { // inline read or ticket: one event, done
			newSSE(w).send(0, okResp(rq.ID, out))
			return
		}
		n = sn
	}
	after, ok := s.cursor(ctx, rc.r, in.Metadata, n)
	if !ok {
		writeJSON(w, 200, errResp(rq.ID, rpcErr(CodeParams, "invalid params: metadata.after must be an event sequence number", nil)))
		return
	}
	t, err := loadTask(ctx, s.d.DB, n)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			err = taskNotFound(taskID(n))
		}
		writeJSON(w, 200, errResp(rq.ID, s.toRPC(err, rq.Method)))
		return
	}
	hist := DefHistory
	if v := metaInt(in.Metadata, "historyLength"); v > 0 {
		hist = min(v, MaxHistory)
	}
	es := newSSE(w)
	es.send(after, okResp(rq.ID, t.a2a(hist)))
	tid, cid := taskID(n), t.contextID()
	rc.blocked = true
	wait := s.waitLimit(rc, metaInt(in.Metadata, "wait"))
	lastNote := int64(0)
	if len(t.Notes) > 0 {
		lastNote = t.Notes[len(t.Notes)-1].ID
	}
	var release func()
	var deadline <-chan time.Time
	var ka *time.Ticker
	defer func() {
		if release != nil {
			release()
		}
		if ka != nil {
			ka.Stop()
		}
	}()
	resume := func(extra map[string]any) {
		meta := map[string]any{"resume": after}
		for k, v := range extra {
			meta[k] = v
		}
		es.send(after, okResp(rq.ID, statusEvent(t, tid, cid, false, meta)))
	}
	for {
		// Subscribe before reading so a wake between the two is never lost.
		c, cancel := s.d.Notify.Subscribe(forge.TaskTopic(n))
		seqs, err := s.events(ctx, n, after)
		if err != nil {
			cancel()
			return
		}
		if len(seqs) > 0 {
			if t, err = loadTask(ctx, s.d.DB, n); err != nil {
				cancel()
				return
			}
			for _, nt := range t.Notes {
				if nt.ID <= lastNote {
					continue
				}
				lastNote = nt.ID
				switch {
				case nt.Kind == "done":
					es.send(seqs[0], okResp(rq.ID, artifactEvent(tid, cid, artifact("n"+strconv.FormatInt(nt.ID, 10), "done", nt.Text, nt.By))))
				case t.isResult(nt):
					es.send(seqs[0], okResp(rq.ID, artifactEvent(tid, cid, artifact("n"+strconv.FormatInt(nt.ID, 10), "result", nt.Text, nt.By))))
				}
			}
			fin := terminal(t.state())
			for i, seq := range seqs {
				after = seq
				es.send(seq, okResp(rq.ID, statusEvent(t, tid, cid, fin && i == len(seqs)-1, nil)))
			}
			if fin {
				cancel()
				return
			}
		} else if terminal(t.state()) {
			cancel()
			es.send(after, okResp(rq.ID, statusEvent(t, tid, cid, true, nil)))
			return
		}
		if wait <= 0 {
			cancel()
			resume(nil)
			return
		}
		if release == nil {
			rel, ok := s.d.Waiters.Acquire(rc.ident.Root, s.d.IPGroup(rc.r))
			if !ok {
				cancel()
				resume(map[string]any{"retry": 5})
				return
			}
			release = rel
			tm := time.NewTimer(time.Duration(wait) * time.Second)
			defer tm.Stop()
			deadline = tm.C
			ka = time.NewTicker(keepalive)
		}
		select {
		case <-c:
			cancel()
			time.Sleep(20 * time.Millisecond)
		case <-ka.C:
			cancel()
			es.comment("keepalive")
		case <-deadline:
			cancel()
			resume(nil)
			return
		case <-ctx.Done():
			cancel()
			return
		}
	}
}

// cursor is the resume point: Last-Event-ID, then metadata.after, else the task's latest event.
func (s *server) cursor(ctx context.Context, r *http.Request, meta map[string]json.RawMessage, n int64) (int64, bool) {
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		if seq, err := strconv.ParseInt(v, 10, 64); err == nil && seq >= 0 {
			return seq, true
		}
	}
	if raw, ok := meta["after"]; ok {
		var f float64
		if json.Unmarshal(raw, &f) != nil || f < 0 {
			return 0, false
		}
		return int64(f), true
	}
	var seq *int64
	if err := s.d.DB.QueryRow(ctx, `SELECT max(seq) FROM events WHERE kind = 't' AND ref = $1`, strconv.FormatInt(n, 10)).Scan(&seq); err != nil || seq == nil {
		return 0, true
	}
	return *seq, true
}

// events lists the public board events of task n after seq (at most 50).
func (s *server) events(ctx context.Context, n, after int64) ([]int64, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT seq FROM events WHERE kind = 't' AND ref = $1 AND seq > $2 AND root_scope IS NULL ORDER BY seq LIMIT 50`, strconv.FormatInt(n, 10), after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var seq int64
		if err := rows.Scan(&seq); err != nil {
			return nil, err
		}
		out = append(out, seq)
	}
	return out, rows.Err()
}

func statusEvent(t *task, tid, cid string, final bool, meta map[string]any) map[string]any {
	full := t.a2a(1)
	ev := map[string]any{"kind": "status-update", "taskId": tid, "contextId": cid, "status": full["status"], "final": final}
	if meta != nil {
		ev["metadata"] = meta
	}
	return ev
}

func artifactEvent(tid, cid string, art map[string]any) map[string]any {
	return map[string]any{"kind": "artifact-update", "taskId": tid, "contextId": cid, "artifact": art, "append": false, "lastChunk": true}
}

// sse writes server-sent events, flushing after each.
type sse struct {
	w http.ResponseWriter
	f http.Flusher
}

func newSSE(w http.ResponseWriter) *sse {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
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

func (e *sse) send(id int64, v any) {
	var b bytes.Buffer
	b.WriteString("id: " + strconv.FormatInt(id, 10) + "\n")
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
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
