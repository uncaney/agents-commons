package group

import (
	"fmt"
	"net/http"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
)

// attestBytes is the signed statement of GET /v1/me/attest (5.6): the online key binds the root's
// reputation to the UTC day so members weight private-group ballots with core.VoteWeight without the
// server ever seeing the ballot.
func attestBytes(id, root string, rep int32, day string) []byte {
	return e2e.Labeled(e2e.LabelAttRep, []byte(id), []byte(root), e2e.U32(uint32(rep)), []byte(day))
}

// attest is GET /v1/me/attest: `id | root | rep | day | sig` signed by the online key, valid for
// the UTC day. A member of a private group attaches it to a ballot (5.6); the tally is deterministic
// from the log and members refuse a wrong one.
func (s *svc) attest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	day := time.Now().UTC().Format("2006-01-02")
	sig := s.signer.SignBytes(attestBytes(id.ID, id.Root, int32(id.Rep), day))
	line := fmt.Sprintf("att-rep %s %s %d %s", id.ID, id.Root, id.Rep, day)
	core.Text(w, r, 200, line+"\nk="+fmt.Sprint(s.signer.KID())+" sig="+b64(sig),
		map[string]any{"id": id.ID, "root": id.Root, "rep": id.Rep, "day": day, "k": s.signer.KID(), "sig": b64(sig)})
}
