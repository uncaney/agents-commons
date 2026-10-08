package catalog

import (
	"errors"
	"net/http"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// systemIdent is the system root as a publisher (never issued a token; funded by the faucet).
func systemIdent() *core.Ident {
	return &core.Ident{ID: core.SystemID, Root: core.SystemID, Name: "system", Created: time.Unix(0, 0), Credits: 1 << 62}
}

// hAdminPublish is POST /admin/svc {name, ver, wasm, manifest} (15.2 operator publish path): the
// admin token publishes under the system root with reserved names allowed (interpreters, cx-*);
// the module must already be in the store (PUT /admin/blob or POST /v1/b) and pinned when above
// 4 MiB; KATs run as system jobs and the first version becomes stable.
func (s *svc) hAdminPublish(w http.ResponseWriter, r *http.Request) {
	var in publishIn
	if err := core.Decode(w, r, 64<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.AdminArg(r, in.Name)
	v, _, err := s.publish(r.Context(), systemIdent(), in, publishOpts{system: true})
	if errors.Is(err, errPinRequest) {
		err = core.Bad("module over 4 MiB: pin it first (POST /admin/pin)")
	}
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	line, j, next := publishReply(v)
	if core.WantJSON(r) {
		core.JSON(w, 201, j)
		return
	}
	doc.TailStatus(w, r, 201, line, next...)
}
