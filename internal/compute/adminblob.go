package compute

// PUT /admin/blob (SPEC-v2 14.4): the operator's only way to bring a module above the 16 MiB public
// cap into the store. Raw body <= ADMIN_BLOB_MAX (64 MiB default), admin token only, owner asystem,
// pinned_by admin (so donors may fetch it and GC never touches it), wasmscan recorded like any
// upload; ?name=&ver=&note= also writes the pins row in the same call.

import (
	"fmt"
	"net/http"

	"ekaii.fr/commons/internal/core"
)

const defAdminBlobMax = 64 << 20

func (s *svc) adminBlobMax() int64 {
	if m := s.d.Cfg.AdminBlobMax; m > 0 {
		return m
	}
	return defAdminBlobMax
}

func (s *svc) hAdminBlob(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	name, ver, note := q.Get("name"), q.Get("ver"), q.Get("note")
	if name != "" && !core.ValidName(name) {
		core.Fail(w, r, core.Bad("name must match [a-zA-Z0-9._-]{1,32}"))
		return
	}
	if !verRe.MatchString(ver) {
		core.Fail(w, r, core.Bad("ver must match [A-Za-z0-9._-]{0,32}"))
		return
	}
	max := s.adminBlobMax()
	core.MaxBytes(w, r, max)
	b, _, err := s.putBlob(r.Context(), core.SystemID, r.Body, putOpts{exempt: true, pinnedBy: "admin", max: max})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.AdminArg(r, b.hash)
	text := fmt.Sprintf("ok blob %s size=%d kind=%s owner=%s pinned_by=%s", b.hash, b.size, b.kind, b.owner, b.pinnedBy)
	j := map[string]any{"ok": true, "hash": b.hash, "size": b.size, "kind": b.kind, "owner": b.owner, "pinned_by": b.pinnedBy}
	if name != "" {
		if _, err := s.pin(r.Context(), pinIn{Hash: b.hash, Name: name, Ver: ver, Note: note}); err != nil {
			core.Fail(w, r, err)
			return
		}
		text += " pin=" + name + "@" + ver
		j["pin"] = name + "@" + ver
	}
	core.OK(w, r, text, j)
}
