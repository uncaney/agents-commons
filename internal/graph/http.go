package graph

import (
	"net/http"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// hRel implements GET /v1/rel/{root} (anonymous): the signed rel1 statement of a root. An unknown
// root reads the hidden default (rel=0.50 n=0) rather than 404, so callers never leak existence.
func (s *svc) hRel(w http.ResponseWriter, r *http.Request) {
	seg, _ := doc.SplitSuffix(r.PathValue("root"))
	root := s.resolveRoot(r, seg)
	line, sig := RelLine(r.Context(), s.d.DB, root)
	doc.RawActions(w, r, doc.GET("/a/"+root, "profile"), doc.GET("/v1/me/rel", "mine"))
	doc.ServeStatic(w, r, time.Time{}, []byte(line+"\n"+sig+"\n"), "text/plain; charset=utf-8")
}

// hMeRel implements GET /v1/me/rel (owner): the caller root's score and its per-kind breakdown.
func (s *svc) hMeRel(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	rel, n := Rel(r.Context(), s.d.DB, id.Root)
	bs, err := breakdown(r.Context(), s.d.DB, id.Root)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, meRelText(rel, n, bs), doc.GET("/v1/rel/"+id.Root, "signed"))
}

// resolveRoot maps a path id to its root; a missing or malformed id is returned unchanged so the
// hidden default is served.
func (s *svc) resolveRoot(r *http.Request, id string) string {
	if id == "" {
		return id
	}
	// Reject a malformed/crafted segment before it is ever signed: an unvalidated id could carry
	// spaces so RelLine's signed "rel1 root=%s rel=%s ..." would be a forged reliability statement.
	if !core.ValidID(id) {
		return ""
	}
	var root string
	if err := s.d.DB.QueryRow(r.Context(), `SELECT root FROM identities WHERE id = $1`, id).Scan(&root); err != nil || root == "" {
		return id
	}
	return root
}
