package subs

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/swarm"
)

var hooked sync.Once

// Register mounts the subscription routes, their scopes and OpenAPI, and wires the swarm topic-head
// extra (subs=<k>) and the report target for sub ids.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := svc(d)
	for pat, h := range map[string]http.HandlerFunc{
		"POST /v1/sub":             s.hCreate,
		"GET /v1/sub":              s.hList,
		"DELETE /v1/sub/{id}":      s.hDelete,
		"POST /v1/sub/{id}/resume": s.hResume,
	} {
		mux.HandleFunc(pat, h)
		scope := "ps:w"
		if strings.HasPrefix(pat, "GET ") {
			scope = "ps:r"
		}
		d.RegisterScope(pat, scope)
	}
	d.RegisterOpenAPI(json.RawMessage(openAPI))
	d.RegisterTarget("u", core.Target{Exists: s.tgtExists, Hide: s.tgtHide, Restore: s.tgtRestore})
	hooked.Do(func() {
		swarm.TopicExtraFn = TopicExtra
	})
}

// TopicExtra renders subs=<k> on a topic head line (swarm.TopicExtraFn).
func TopicExtra(ctx context.Context, q core.Q, topic string) []string {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM subs WHERE topic = $1 AND NOT paused`, topic).Scan(&n); err != nil || n == 0 {
		return nil
	}
	return []string{"subs=" + itoa(int64(n))}
}

func (s *Service) hCreate(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in CreateIn
	if err := core.Decode(w, r, 4096, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	sub, err := s.Create(r.Context(), id, in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusOK, "ok "+sub.ID+" lag=0",
		doc.GET("/v1/sub", "list"), doc.Action{Method: "DELETE", Path: "/v1/sub/" + sub.ID, Hint: "unsub"})
}

func (s *Service) hList(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	subs, err := s.List(r.Context(), id.Root)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var b strings.Builder
	b.WriteString("subs=" + itoa(int64(len(subs))))
	for _, sub := range subs {
		b.WriteString("\n" + sub.line())
	}
	doc.Tail(w, r, b.String(), doc.POST("/v1/sub", "subscribe"))
}

func (s *Service) hDelete(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := s.Delete(r.Context(), id, r.PathValue("id")); err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, "ok", doc.GET("/v1/sub", "list"))
}

func (s *Service) hResume(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	sub, err := s.Resume(r.Context(), id, r.PathValue("id"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, "ok "+sub.ID+" resumed", doc.GET("/v1/sub", "list"))
}

// --- report target (4.7): a sub id 'u…' ---

func (s *Service) tgtExists(ctx context.Context, q core.Q, ref string) error {
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM subs WHERE id = $1)`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func (s *Service) tgtHide(ctx context.Context, q core.Q, ref string) error {
	return s.setPaused(ctx, q, ref, true)
}

func (s *Service) tgtRestore(ctx context.Context, q core.Q, ref string) error {
	return s.setPaused(ctx, q, ref, false)
}

func (s *Service) setPaused(ctx context.Context, q core.Q, ref string, paused bool) error {
	tag, err := q.Exec(ctx, `UPDATE subs SET paused = $2 WHERE id = $1`, ref, paused)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return nil
}

const openAPI = `{
  "paths": {
    "/v1/sub": {
      "post": {
        "summary": "create a subscription",
        "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/SubCreate"}}}},
        "responses": {"200": {"description": "ok u… lag=0"}}
      },
      "get": {"summary": "list subscriptions", "responses": {"200": {"description": "subs=<k>"}}}
    },
    "/v1/sub/{id}": {
      "delete": {"summary": "remove a subscription", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}}
    },
    "/v1/sub/{id}/resume": {
      "post": {"summary": "resume a paused subscription", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}], "responses": {"200": {"description": "ok"}}}
    }
  },
  "components": {"schemas": {"SubCreate": {"type": "object", "required": ["topic", "sink"], "properties": {
    "topic": {"type": "string", "description": "topic name g:<n> | ~<n> | s:<slug>.<n> | r:<room>.<n>"},
    "sink": {"type": "string", "description": "wq:<name> | mb:me | kv:<ns>/<k> | fn:<svc>@<ver>"},
    "to": {"type": "string", "description": "fn output target: topic:<name> | mail:me | kv:<ns>/<k>"},
    "filter": {"type": "string", "description": "prefix:<text> | re:<RE2 <= 64>"},
    "mode": {"type": "string", "enum": ["each", "digest"]},
    "hop_max": {"type": "integer"},
    "ttl_h": {"type": "integer"},
    "max_credits_day": {"type": "integer"}
  }}}}
}`
