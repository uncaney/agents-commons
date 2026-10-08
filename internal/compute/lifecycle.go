package compute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Job is the settled job handed to OnDone (pipes, catalog fees, bounties).
type Job struct {
	ID, Submitter, Root, Wasm, Input, FS, Out, Status, Reason string
	Svc, Kind, Lane, Pipe, Bounty, Sub                        string
	Ms, Mb, UsedMs, Code                                      int
	Reserved, Charged                                         int64
	AttD                                                      bool
	CacheScope                                                string
}

// cancel fails the caller's queued/running job with a full refund (14.3). Leased replicas are
// marked cancelled so the donor's done answers 410 and stops early.
func (s *svc) cancel(ctx context.Context, id *core.Ident, jid string) (int64, error) {
	if !core.ValidID(jid) || jid[0] != 'j' {
		return 0, core.Bad("bad job id")
	}
	var refund int64
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var status string
		err := tx.QueryRow(ctx, `SELECT status, reserved FROM jobs WHERE id = $1 AND root = $2 FOR UPDATE`, jid, id.Root).Scan(&status, &refund)
		if errors.Is(err, pgx.ErrNoRows) {
			return core.ErrNotFound
		}
		if err != nil {
			return err
		}
		if status != "queued" && status != "running" {
			return core.E(409, "taken", "job already "+status)
		}
		_, err = cancelJobs(ctx, tx, `id = $2`, "cancelled", true, jid)
		return err
	})
	if err != nil {
		return 0, err
	}
	s.d.Notify.Wake("job:" + jid)
	return refund, nil
}

func (s *svc) hCancel(w http.ResponseWriter, r *http.Request) {
	id, err := s.authCompute(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	jid := r.PathValue("id")
	refund, err := s.cancel(r.Context(), id, jid)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, fmt.Sprintf("%s cancelled refund=%d", jid, refund), map[string]any{"id": jid, "status": "failed", "reason": "cancelled", "refund": refund})
}

func (s *svc) opJC(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if err := s.checkIdent(id); err != nil {
		return "", err
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	refund, err := s.cancel(ctx, id, in.ID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s cancelled refund=%d", in.ID, refund), nil
}

func (s *svc) opBD(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if err := s.checkIdent(id); err != nil {
		return "", err
	}
	var in struct {
		Hash string `json:"hash"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	if err := s.deleteBlob(ctx, id, in.Hash); err != nil {
		return "", err
	}
	return "ok deleted " + in.Hash, nil
}

func (s *svc) opBInfo(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if id == nil {
		return "", core.ErrAuth
	}
	var in struct {
		Hash string `json:"hash"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	b, err := s.blobForInfo(ctx, id, in.Hash, "")
	if err != nil {
		return "", err
	}
	lines, _, err := s.infoLines(ctx, b)
	if err != nil {
		return "", err
	}
	return strings.Join(lines, "\n"), nil
}

// SystemSubmit queues jobs for the system root (audits, KATs, precomputes): reserved from
// core.SystemID's faucet balance; ErrUnfunded plus an ops event when it runs short (16.1).
func SystemSubmit(ctx context.Context, d *core.Deps, specs []Spec, kind string) ([]string, error) {
	if kind == "" {
		kind = "job"
	}
	for i := range specs {
		specs[i].Kind = kind
	}
	sys := &core.Ident{ID: core.SystemID, Root: core.SystemID, Name: "system", Created: time.Unix(0, 0)}
	res, err := svcFor(d).submit(ctx, sys, specs)
	if err != nil {
		if errors.Is(err, ErrUnfunded) || errors.Is(err, core.ErrCredits) {
			if eerr := core.Event(ctx, d.DB, "ops", "unfunded", "", fmt.Sprintf("compute: system root unfunded for %d %s job(s)", len(specs), kind)); eerr != nil {
				return nil, eerr
			}
			return nil, ErrUnfunded
		}
		return nil, err
	}
	return res.ids, nil
}

// export writes the root's jobs and blobs as JSON lines (3.4 export-me).
func (s *svc) export(ctx context.Context, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	rows, err := s.d.DB.Query(ctx, `SELECT id, status, reason, wasm, input, fs, out, ms, mb, used_ms, code, lane, cached_from, created, finished_at, att, att_sig
		FROM jobs WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id, status, reason, wasm, input, fs, out, lane, cachedFrom, att, sig string
		var ms, mb, usedMs, code int
		var created time.Time
		var finished *time.Time
		if err := rows.Scan(&id, &status, &reason, &wasm, &input, &fs, &out, &ms, &mb, &usedMs, &code, &lane, &cachedFrom, &created, &finished, &att, &sig); err != nil {
			return err
		}
		row := map[string]any{"kind": "job", "id": id, "status": status, "wasm": wasm, "in": input, "ms": ms, "mb": mb, "created": created.UTC().Format(time.RFC3339)}
		if reason != "" {
			row["reason"] = reason
		}
		if fs != "" {
			row["fs"] = fs
		}
		if out != "" {
			row["out"], row["used_ms"], row["code"] = out, usedMs, code
		}
		if lane != "public" {
			row["lane"] = lane
		}
		if cachedFrom != "" {
			row["cached_from"] = cachedFrom
		}
		if finished != nil {
			row["finished_at"] = finished.UTC().Format(time.RFC3339)
		}
		if att != "" {
			row["att"], row["sig"] = att, sig
		}
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	brows, err := s.d.DB.Query(ctx, `SELECT hash, size, kind, public, private, created FROM blobs WHERE owner_root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer brows.Close()
	for brows.Next() {
		var hash, kind string
		var size int64
		var public, private bool
		var created time.Time
		if err := brows.Scan(&hash, &size, &kind, &public, &private, &created); err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "blob", "hash": hash, "size": size, "type": kind, "public": public, "private": private,
			"created": created.UTC().Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	return brows.Err()
}

// resolve maps a job id to its public receipt page (8.3 /x/): published jobs only, so an id
// never confirms the existence of a private job.
func (s *svc) resolve(ctx context.Context, id string) (typ, title, url string, ok bool) {
	if !core.ValidID(id) || id[0] != 'j' {
		return "", "", "", false
	}
	var published bool
	var status string
	if err := s.d.DB.QueryRow(ctx, `SELECT published, status FROM jobs WHERE id = $1`, id).Scan(&published, &status); err != nil || !published {
		return "", "", "", false
	}
	return "job", "compute receipt " + id + " (" + status + ")", "/att/" + id, true
}
