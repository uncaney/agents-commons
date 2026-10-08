package sem

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
)

type claimHandoverIn struct {
	To   string `json:"to"`
	Note string `json:"note"`
}

// claimHandover is POST /v1/t/{n}/handover and op tch: hand the caller's live claim on task n to an
// eligible recipient (forge.ClaimHandover, fence+1, task note). Eligibility is the same root tree
// or a live, reliable identity, mirroring 27.4 for g:-scoped work.
func (s *svc) claimHandover(ctx context.Context, id *core.Ident, n int64, in claimHandoverIn) (reply, error) {
	if n <= 0 {
		return reply{}, core.Bad("task number")
	}
	toID, toRoot, err := s.resolveClaimTo(ctx, in.To)
	if err != nil {
		return reply{}, err
	}
	if err := s.frozen(); err != nil {
		return reply{}, err
	}
	// The caller must hold the live claim at the current fence.
	var fence int64
	var holderRoot string
	var until time.Time
	err = s.d.DB.QueryRow(ctx, `SELECT fence, root, until FROM task_claims WHERE n = $1`, n).Scan(&fence, &holderRoot, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return reply{}, core.E(409, "bad", "no claim")
	}
	if err != nil {
		return reply{}, err
	}
	if holderRoot != id.Root || !until.After(time.Now()) {
		return reply{}, core.E(409, "bad", "not holder")
	}
	// Eligibility: same root tree, else live + reliable (g:-style).
	if toRoot != id.Root {
		if err := s.liveReliable(ctx, toRoot); err != nil {
			return reply{}, err
		}
		if err := s.foreignHandover(ctx, s.d.DB, id.Root, toRoot); err != nil {
			return reply{}, err
		}
	}
	newFence, err := forge.ClaimHandover(ctx, s.d.DB, n, fence, toID, toRoot, in.Note)
	if err != nil {
		return reply{}, err
	}
	return reply{text: fmt.Sprintf("ok handover t #%d fence=%d to=%s", n, newFence, toID),
		next: []doc.Action{doc.GET("/v1/t/"+strconv.FormatInt(n, 10), "task")}}, nil
}

func (s *svc) resolveClaimTo(ctx context.Context, to string) (string, string, error) {
	if !core.ValidIDPrefix(to, 'a') {
		return "", "", core.Bad("to: identity id")
	}
	var root string
	err := s.d.DB.QueryRow(ctx, `SELECT root FROM identities WHERE id = $1`, to).Scan(&root)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", core.E(409, "bad", "to not live")
	}
	if err != nil {
		return "", "", err
	}
	return to, root, nil
}

// liveReliable gates a cross-tree claim handover: last_seen within 10 min and rel >= 0.5 (27.4).
func (s *svc) liveReliable(ctx context.Context, toRoot string) error {
	var seen *time.Time
	if err := s.d.DB.QueryRow(ctx, `SELECT last_seen FROM identities WHERE id = $1 AND parent IS NULL`, toRoot).Scan(&seen); err != nil {
		return core.E(409, "bad", "to not live")
	}
	if seen == nil || time.Since(*seen) > 10*time.Minute || rel(ctx, s.d.DB, toRoot) < 0.5 {
		return core.E(409, "bad", "to not live")
	}
	return nil
}

func (s *svc) tHandover(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in claimHandoverIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	n, err := strconv.ParseInt(r.PathValue("n"), 10, 64)
	if err != nil {
		doc.Fail(w, r, core.Bad("task number"))
		return
	}
	rep, err := s.claimHandover(r.Context(), id, n, in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}
