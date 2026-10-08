package gov

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

// Check queue (SPEC-v2 18.5): code proposals are advisory and never auto-merged. The operator
// asks for a check (POST /v1/p/{id}/checkreq, ops token); a disposable runner holding only the
// check token polls GET /admin/checkq, fetches GET /v1/p/{id}/patch, runs the checks in a
// throwaway container and posts POST /admin/proposal/{id}/check. Nothing from a proposal ever
// runs on the gateway: this file moves two columns and emits events.

// MaxCheckLog caps the runner's log (18.1 check_log).
const MaxCheckLog = 16 << 10

// CodeEligibleFn gates check requests (27.5: a code proposal must reference an accepted platform
// task); nil = every code proposal is eligible. The roadmap package sets it.
var CodeEligibleFn func(ctx context.Context, q core.Q, p *Proposal) error

// RequestCheck marks a code proposal check_status = requested (state check_requested once it has
// passed its advisory vote; an open vote keeps running).
func RequestCheck(ctx context.Context, d *core.Deps, id string) (*Proposal, error) {
	var out *Proposal
	err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		p, err := lock(ctx, tx, id)
		if err != nil {
			return err
		}
		if p.Kind != "code" {
			return core.Bad("checks are for code proposals")
		}
		if p.Hidden {
			return core.E(410, "gone", "proposal hidden")
		}
		if p.Terminal() {
			return core.E(409, "dup", "proposal "+p.State)
		}
		if p.CheckStatus == "requested" {
			return core.E(409, "dup", "check already requested")
		}
		if CodeEligibleFn != nil {
			if err := CodeEligibleFn(ctx, tx, p); err != nil {
				return err
			}
		}
		state := p.State
		if state == "passed" {
			state = "check_requested"
		}
		if _, err := tx.Exec(ctx, `UPDATE proposals SET check_status = 'requested', check_log = '', state = $2 WHERE id = $1`, id, state); err != nil {
			return err
		}
		p.State, p.CheckStatus, p.CheckLog = state, "requested", ""
		if err := core.Event(ctx, tx, "p", id, "", "check requested code "+scopeName(p.Scope)); err != nil {
			return err
		}
		out = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	notifier.Store(d.Notify)
	wake(id)
	return out, nil
}

// CheckQueue lists the code proposals whose check is requested, oldest first.
func CheckQueue(ctx context.Context, q core.Q, n int) ([]Proposal, error) {
	if n <= 0 || n > 100 {
		n = 50
	}
	rows, err := q.Query(ctx, `SELECT `+cols+` FROM proposals WHERE kind = 'code' AND check_status = 'requested' AND NOT hidden ORDER BY created, id LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proposal
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// SetCheckResult records the runner's verdict: check_status pass|fail, the log (<= 16 KiB,
// control characters dropped, secrets masked), state back to passed after check_requested.
func SetCheckResult(ctx context.Context, d *core.Deps, id, status, log string) (*Proposal, error) {
	if status != "pass" && status != "fail" {
		return nil, core.Bad("status must be pass|fail")
	}
	if len(log) > MaxCheckLog {
		return nil, core.E(413, "size", "log > 16 KiB")
	}
	if !utf8.ValidString(log) {
		log = strings.ToValidUTF8(log, "")
	}
	log, _ = scrub.Mask(doc.CleanMulti(log))
	var out *Proposal
	err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		p, err := lock(ctx, tx, id)
		if err != nil {
			return err
		}
		if p.Kind != "code" {
			return core.Bad("checks are for code proposals")
		}
		if p.CheckStatus != "requested" {
			return core.E(409, "dup", "no check requested")
		}
		state := p.State
		if state == "check_requested" {
			state = "passed"
		}
		if _, err := tx.Exec(ctx, `UPDATE proposals SET check_status = $2, check_log = $3, state = $4 WHERE id = $1`, id, status, log, state); err != nil {
			return err
		}
		p.State, p.CheckStatus, p.CheckLog = state, status, log
		if err := core.Event(ctx, tx, "p", id, "", "check "+status+" code "+scopeName(p.Scope)); err != nil {
			return err
		}
		out = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	notifier.Store(d.Notify)
	wake(id)
	return out, nil
}

// --- handlers --------------------------------------------------------------------------------------

// hCheckReq is POST /v1/p/{id}/checkreq (ops token): the cxa check path.
func (s *psvc) hCheckReq(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, err := RequestCheck(r.Context(), s.d, id)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	core.AdminArg(r, id)
	doc.Tail(w, r, "ok check requested "+p.ID+" state="+p.State, doc.GET("/v1/p/"+p.ID, ""), doc.GET("/v1/p/"+p.ID+"/patch", "diff"))
}

type checkRow struct {
	ID      string    `json:"id"`
	Blob    string    `json:"blob"`
	Created time.Time `json:"created"`
	Patch   string    `json:"patch"`
	Title   string    `json:"title"`
}

// hCheckQ is GET /admin/checkq (check token): one line per requested check,
// `<id> <blob> <date> GET /v1/p/<id>/patch`, or JSON rows.
func (s *psvc) hCheckQ(w http.ResponseWriter, r *http.Request) {
	ps, err := CheckQueue(r.Context(), s.d.DB, 0)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	rows := make([]checkRow, 0, len(ps))
	var b strings.Builder
	for i := range ps {
		p := &ps[i]
		var cp codePatch
		json.Unmarshal(p.Patch, &cp)
		rows = append(rows, checkRow{ID: p.ID, Blob: cp.Blob, Created: p.Created, Patch: "/v1/p/" + p.ID + "/patch", Title: p.title()})
		b.WriteString(p.ID + " " + cp.Blob + " " + core.Date(p.Created) + " GET /v1/p/" + p.ID + "/patch\n")
	}
	core.AdminArg(r, "n="+itoa(len(rows)))
	w.Header().Set("Cache-Control", "private, no-store")
	core.OK(w, r, "checkq "+itoa(len(rows))+"\n"+b.String(), rows)
}

type checkIn struct {
	Status string `json:"status"`
	Log    string `json:"log"`
}

// hCheckResult is POST /admin/proposal/{id}/check {status, log} (check token or admin).
func (s *psvc) hCheckResult(w http.ResponseWriter, r *http.Request) {
	var in checkIn
	if err := core.Decode(w, r, MaxCheckLog+4096, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	id := r.PathValue("id")
	p, err := SetCheckResult(r.Context(), s.d, id, in.Status, in.Log)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.AdminArg(r, id+" "+in.Status)
	core.OK(w, r, "ok check "+p.CheckStatus+" recorded "+p.ID+" state="+p.State, map[string]any{"id": p.ID, "check_status": p.CheckStatus, "state": p.State})
}
