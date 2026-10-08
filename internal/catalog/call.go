package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// callIn is the body of POST /v1/svc/{nameAtVer} and op svc (name/ver only for the op).
type callIn struct {
	Name   string `json:"name,omitempty"`
	Ver    int    `json:"ver,omitempty"`
	In     string `json:"in,omitempty"`
	InText string `json:"in_text,omitempty"`
	FS     string `json:"fs,omitempty"`
	Ms     int    `json:"ms,omitempty"`
	Mb     int    `json:"mb,omitempty"`
	Wait   int    `json:"wait,omitempty"`
	Fresh  bool   `json:"fresh,omitempty"`
}

// runIn is the body of POST /v1/run and ops run/py/js/lua: in_text, or the interpreter framing
// built from code + stdin (15.4).
type runIn struct {
	Svc    string `json:"svc,omitempty"`
	InText string `json:"in_text,omitempty"`
	Code   string `json:"code,omitempty"`
	Stdin  string `json:"stdin,omitempty"`
	FS     string `json:"fs,omitempty"`
	Ms     int    `json:"ms,omitempty"`
	Mb     int    `json:"mb,omitempty"`
	Wait   int    `json:"wait,omitempty"`
}

// callResult is one call as the reply renders it.
type callResult struct {
	View    *compute.JobView
	Version *Version
	Pinned  bool   // resolved through the stable pointer: print pinned=<hash12> (27.6)
	Out     []byte // stdout when done and small enough to show
	Text    bool   // Out is valid UTF-8 <= 16 KiB
	OutSize int64
}

// Call resolves name@ver (or the stable version), submits the job with the fee, waits up to wait
// seconds and returns the view plus the inline stdout text ("" when not done, binary or large).
func Call(ctx context.Context, d *core.Deps, id *core.Ident, nameAtVer, in, inText, fs string, wait int) (*compute.JobView, string, error) {
	s := &svc{d}
	res, err := s.call(ctx, id, nameAtVer, callIn{In: in, InText: inText, FS: fs, Wait: wait})
	if err != nil {
		return nil, "", err
	}
	out := ""
	if res.Text {
		out = string(res.Out)
	}
	return res.View, out, nil
}

// call is the 15.2 call path: resolve, hints, fee, compute.Submit with Svc set, the calls row,
// then status (long-poll) and the output when done.
func (s *svc) call(ctx context.Context, id *core.Ident, nameAtVer string, in callIn) (*callResult, error) {
	if err := s.checkIdent(id); err != nil {
		return nil, err
	}
	v, err := Resolve(ctx, s.d.DB, nameAtVer)
	if err != nil {
		return nil, err
	}
	if v.State == "rejected" {
		return nil, core.E(410, "gone", v.Ref()+" rejected: "+doc.SafeLine(v.Tested))
	}
	pinned := !strings.Contains(nameAtVer, "@")
	fs := v.FS
	if in.FS != "" {
		if !v.Manifest.FSOverride {
			return nil, core.Bad(v.Ref() + " does not allow an fs override")
		}
		if !hashRe.MatchString(in.FS) {
			return nil, core.Bad("fs must be a sha256 hex")
		}
		fs = in.FS
	}
	ms, mb := in.Ms, in.Mb
	if ms == 0 {
		ms = v.Manifest.MsHint
	}
	if mb == 0 {
		mb = v.Manifest.MbHint
	}
	if ms == 0 {
		ms = defMs
	}
	if mb == 0 {
		mb = defMb
	}
	if ms < 1 || ms > maxMs || mb < 1 || mb > maxMb {
		return nil, core.Bad(fmt.Sprintf("ms must be 1..%d, mb 1..%d", maxMs, maxMb))
	}
	if (in.In == "") == (in.InText == "") {
		return nil, core.Bad("give in or in_text")
	}
	if len(in.InText) > maxInText {
		return nil, core.E(413, "size", "in_text over 64 KiB: upload a blob")
	}
	fee := int64(v.Manifest.Fee)
	if id.Root == v.OwnerRoot {
		fee = 0
	}
	if id.Credits < int64((ms+999)/1000)*3+fee {
		return nil, core.ErrCredits
	}
	ids, err := compute.Submit(ctx, s.d, id, []compute.Spec{{Wasm: v.Wasm, In: in.In, InText: in.InText, FS: fs, Ms: ms, Mb: mb, Fresh: in.Fresh, Svc: v.Ref()}})
	if err != nil {
		return nil, err
	}
	jid := ids[0]
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if fee > 0 {
			if err := core.Reserve(ctx, tx, id.ID, fee); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO service_calls (job, name, ver, caller, root, fee) VALUES ($1, $2, $3, $4, $5, $6)`, jid, v.Name, v.Ver, id.ID, id.Root, fee); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE service_versions SET calls = calls + 1 WHERE name = $1 AND ver = $2`, v.Name, v.Ver); err != nil {
			return err
		}
		other := id.Root != v.OwnerRoot
		_, err := tx.Exec(ctx, `UPDATE services SET calls = calls + 1, other_calls = other_calls + CASE WHEN $2 THEN 1 ELSE 0 END,
			last_other_call = CASE WHEN $2 THEN now() ELSE last_other_call END WHERE name = $1`, v.Name, other)
		return err
	})
	if err != nil {
		return nil, err
	}
	view, err := compute.Status(ctx, s.d, id, jid, in.Wait)
	if err != nil {
		return nil, err
	}
	res := &callResult{View: view, Version: v, Pinned: pinned}
	if view.Status == "done" || view.Status == "failed" {
		if err := settle(ctx, s.d.DB, jid, view.Status); err != nil {
			return nil, err
		}
	}
	if view.Status == "done" {
		b, ok, err := compute.Output(ctx, s.d, id, jid)
		if err != nil {
			return nil, err
		}
		if ok {
			res.OutSize = int64(len(b))
			if len(b) <= inlineOut && utf8.Valid(b) {
				res.Out, res.Text = b, true
			}
		}
	}
	return res, nil
}

// settle releases the fee held by a call once its job is final: earned by the owner when the
// job is done and the caller is another root (15.2), refunded to the caller otherwise.
// Idempotent through service_calls.settled.
func settle(ctx context.Context, q core.Q, jid, status string) error {
	var name, caller, root string
	var ver int
	var fee int64
	err := q.QueryRow(ctx, `UPDATE service_calls SET settled = true WHERE job = $1 AND NOT settled RETURNING name, ver, caller, root, fee`, jid).
		Scan(&name, &ver, &caller, &root, &fee)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil || fee == 0 {
		return err
	}
	var owner string
	if err := q.QueryRow(ctx, `SELECT owner_root FROM services WHERE name = $1`, name).Scan(&owner); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if status == "done" && owner != "" && owner != root {
		return core.Earn(ctx, q, owner, fee)
	}
	return core.Refund(ctx, q, caller, fee)
}

// OnDone is the compute done hook (15.2): settles the fee and updates the version's stats
// (fails, nocons, ms_p50, the nondeterministic flag) and the auto-hide after 10 consecutive
// failed consensus. KATs and plain jobs are ignored. Exported for P60a's chain.
func OnDone(ctx context.Context, q core.Q, j *compute.Job) error {
	if j == nil || j.Svc == "" || j.Kind != "job" {
		return nil
	}
	if err := settle(ctx, q, j.ID, j.Status); err != nil {
		return err
	}
	name, ver, _, err := parseRef(j.Svc)
	if err != nil || ver == 0 {
		return nil
	}
	nocons := j.Status == "failed" && j.Reason == "noconsensus"
	var calls, nc int64
	var samples []int32
	var nondet bool
	err = q.QueryRow(ctx, `UPDATE service_versions SET fails = fails + CASE WHEN $3 THEN 1 ELSE 0 END, nocons = nocons + CASE WHEN $4 THEN 1 ELSE 0 END
		WHERE name = $1 AND ver = $2 RETURNING calls, nocons, ms_samples, nondeterministic`, name, ver, j.Status == "failed", nocons).Scan(&calls, &nc, &samples, &nondet)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if j.Status == "done" {
		samples = append(samples, int32(j.UsedMs))
		if len(samples) > msSamples {
			samples = samples[len(samples)-msSamples:]
		}
	}
	sorted := append([]int32(nil), samples...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
	p50 := 0
	if len(sorted) > 0 {
		p50 = int(sorted[len(sorted)/2])
	}
	flag := nondet || (calls >= nondetMin && nc*100 >= calls*nondetPct)
	if _, err := q.Exec(ctx, `UPDATE service_versions SET ms_samples = $3, ms_p50 = $4, nondeterministic = $5 WHERE name = $1 AND ver = $2`, name, ver, samples, p50, flag); err != nil {
		return err
	}
	if flag && !nondet {
		if err := core.Event(ctx, q, "svc", j.Svc, "", "service "+j.Svc+" flagged nondeterministic (results differ between donors: clocks, randomness, map order, uninitialised memory)"); err != nil {
			return err
		}
	}
	var run int
	var hidden bool
	if err := q.QueryRow(ctx, `UPDATE services SET nocons_run = CASE WHEN $2 THEN nocons_run + 1 ELSE 0 END WHERE name = $1 RETURNING nocons_run, hidden`, name, nocons).Scan(&run, &hidden); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}
	if run >= hideNocons && !hidden {
		if _, err := q.Exec(ctx, `UPDATE services SET hidden = true, hidden_at = now() WHERE name = $1`, name); err != nil {
			return err
		}
		return core.Event(ctx, q, "svc", name, "", fmt.Sprintf("service %s hidden after %d consecutive failed consensus", name, run))
	}
	return nil
}

// --- rendering ----------------------------------------------------------------------------------

// text renders a call result (15.2): `done ms=312 out=<hash> [code=N] [cached] [pinned=<h12>]
// job=<id>` then the stdout indented by two spaces (<= 16 KiB UTF-8; else out= only), or the
// compute status line while the job runs.
func (r *callResult) text() string {
	v := r.View
	switch v.Status {
	case "done":
		var b strings.Builder
		fmt.Fprintf(&b, "done ms=%d out=%s", v.Ms, v.Out)
		if v.Code != 0 {
			fmt.Fprintf(&b, " code=%d", v.Code)
		}
		if v.Cached {
			b.WriteString(" cached")
		}
		if r.Pinned {
			b.WriteString(" pinned=" + r.Version.Hash12())
		}
		b.WriteString(" job=" + v.ID)
		if r.Text && len(r.Out) > 0 {
			b.WriteString("\n  " + doc.Indent(string(r.Out)))
		}
		return b.String()
	case "failed":
		return v.ID + " failed " + doc.SafeLine(v.Reason)
	}
	return v.ID + " " + v.Status
}

func (r *callResult) json() map[string]any {
	v := r.View
	j := map[string]any{"id": v.ID, "status": v.Status, "svc": r.Version.Ref()}
	switch v.Status {
	case "done":
		j["ms"], j["out"], j["code"] = v.Ms, v.Out, v.Code
		if v.Cached {
			j["cached"] = true
		}
		if r.Text {
			j["out_text"] = string(r.Out)
		} else if r.OutSize > 0 {
			j["out_size"] = r.OutSize
		}
	case "failed":
		j["reason"] = v.Reason
	}
	if r.Pinned {
		j["pinned"] = r.Version.Hash12()
	}
	return j
}

func (r *callResult) status() int {
	if r.View.Status == "done" || r.View.Status == "failed" {
		return 200
	}
	return 202
}

func (r *callResult) next() []doc.Action {
	v := r.View
	if v.Status == "done" || v.Status == "failed" {
		return doc.Next(doc.GET("/v1/j/"+v.ID, "status"), doc.POST("/v1/svc/"+r.Version.Ref()+"/ok", "worked"), doc.POST("/v1/svc/"+r.Version.Ref()+"/bad", "failed"))
	}
	return doc.Next(doc.GET("/v1/j/"+v.ID+"?wait=30", "poll"), doc.GET("/v1/svc/"+r.Version.Ref(), ""))
}

// reply writes a call result; ?raw=1 answers the stdout bytes alone (text/plain, no head line,
// no tail) once the job is done.
func (s *svc) reply(w http.ResponseWriter, r *http.Request, res *callResult) {
	if r.URL.Query().Get("raw") == "1" && res.View.Status == "done" {
		id, _ := s.d.Auth(r)
		b, ok, err := compute.Output(r.Context(), s.d, id, res.View.ID)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		if !ok {
			b = nil
		}
		ct := "application/octet-stream"
		if utf8.Valid(b) {
			ct = "text/plain; charset=utf-8"
		}
		doc.RawActions(w, r, doc.GET("/v1/j/"+res.View.ID, ""))
		h := w.Header()
		h.Set("Content-Type", ct)
		h.Set("Cache-Control", "private, no-store")
		h.Set("X-Job", res.View.ID)
		h.Set("X-Out", res.View.Out)
		w.WriteHeader(200)
		w.Write(b)
		return
	}
	if core.WantJSON(r) {
		j := res.json()
		j["next"] = nextJSON(res.next())
		core.JSON(w, res.status(), j)
		return
	}
	doc.TailStatus(w, r, res.status(), res.text(), res.next()...)
}

func (s *svc) hCall(w http.ResponseWriter, r *http.Request) {
	id, err := s.authWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in callIn
	if err := core.Decode(w, r, 1<<20, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if wq := r.URL.Query().Get("wait"); wq != "" {
		if in.Wait, err = strconv.Atoi(wq); err != nil || in.Wait < 0 {
			doc.Fail(w, r, core.Bad("wait must be 0.."+strconv.Itoa(maxWait)))
			return
		}
	}
	in.Wait = min(in.Wait, maxWait)
	res, err := s.call(r.Context(), id, r.PathValue("nameAtVer"), in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.reply(w, r, res)
}

func (s *svc) opCall(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	var in callIn
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	ref := in.Name
	if in.Ver > 0 {
		ref += "@" + strconv.Itoa(in.Ver)
	}
	in.Wait = min(in.Wait, maxWait)
	res, err := s.call(ctx, id, ref, in)
	if err != nil {
		return "", err
	}
	return res.text(), nil
}

// --- run / interpreters -------------------------------------------------------------------------

// framing builds the 15.4 launcher input: in_text as-is, or {"code","stdin"} JSON.
func framing(in *runIn) (string, error) {
	switch {
	case in.Code != "" && in.InText != "":
		return "", core.Bad("give code or in_text, not both")
	case in.Code == "" && in.InText == "":
		return "", core.Bad("code or in_text required")
	case in.Code != "":
		if len(in.Code) > maxCode || len(in.Stdin) > maxInText {
			return "", core.E(413, "size", "code over 64 KiB")
		}
		b, err := json.Marshal(map[string]string{"code": in.Code, "stdin": in.Stdin})
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	if in.Stdin != "" {
		return "", core.Bad("stdin goes with code")
	}
	return in.InText, nil
}

func (s *svc) run(ctx context.Context, id *core.Ident, in runIn) (*callResult, error) {
	if err := s.checkIdent(id); err != nil {
		return nil, err
	}
	if in.Svc == "" {
		return nil, core.Bad("svc required")
	}
	text, err := framing(&in)
	if err != nil {
		return nil, err
	}
	return s.call(ctx, id, in.Svc, callIn{InText: text, FS: in.FS, Ms: in.Ms, Mb: in.Mb, Wait: min(in.Wait, maxWait)})
}

func (s *svc) hRun(w http.ResponseWriter, r *http.Request) {
	id, err := s.authWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in runIn
	if err := core.Decode(w, r, 1<<20, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	res, err := s.run(r.Context(), id, in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.reply(w, r, res)
}

func (s *svc) opRun(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	var in runIn
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	res, err := s.run(ctx, id, in)
	if err != nil {
		return "", err
	}
	return res.text(), nil
}

// opInterp is py{}, js{}, lua{}: run{svc:<interpreter>} with the code/stdin framing.
func (s *svc) opInterp(name string) Op {
	return func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			Code  string `json:"code"`
			Stdin string `json:"stdin,omitempty"`
			FS    string `json:"fs,omitempty"`
			Ms    int    `json:"ms,omitempty"`
			Mb    int    `json:"mb,omitempty"`
			Wait  int    `json:"wait,omitempty"`
		}
		if err := decodeOp(a, &in); err != nil {
			return "", err
		}
		res, err := s.run(ctx, id, runIn{Svc: name, Code: in.Code, Stdin: in.Stdin, FS: in.FS, Ms: in.Ms, Mb: in.Mb, Wait: in.Wait})
		if err != nil {
			return "", err
		}
		return res.text(), nil
	}
}

// --- votes --------------------------------------------------------------------------------------

type voteResult struct {
	Ref       string
	Up        bool
	OkW, BadW float64
}

func (r voteResult) text() string {
	return fmt.Sprintf("ok %s ok%s bad%s", r.Ref, strconv.FormatFloat(r.OkW, 'g', -1, 32), strconv.FormatFloat(r.BadW, 'g', -1, 32))
}

// vote records svok/svbad (15.2): one per root per version, by roots with a finalised job on
// that module within 30 d, weighted by trust.Weight, no self-vote; the version's collapsed sums
// (one voter per super-group, 4.1) are recomputed in the tx.
func (s *svc) vote(ctx context.Context, id *core.Ident, nameAtVer string, up bool, note string) (*voteResult, error) {
	if err := s.checkIdent(id); err != nil {
		return nil, err
	}
	v, err := Resolve(ctx, s.d.DB, nameAtVer)
	if err != nil {
		return nil, err
	}
	note = doc.SafeLine(strings.TrimSpace(doc.CleanMulti(note)))
	if len(note) > 200 {
		return nil, core.Bad("note <= 200 bytes")
	}
	if v.OwnerRoot == id.Root {
		return nil, core.E(403, "auth", "no self vote")
	}
	st, err := trust.Load(ctx, s.d.DB, id.Root)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return nil, core.ErrBadToken
		}
		return nil, err
	}
	var ran bool
	if err := s.d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM jobs WHERE root = $1 AND wasm = $2 AND status IN ('done', 'failed')
		AND finished_at > now() - make_interval(days => $3))`, id.Root, v.Wasm, voteWindowD).Scan(&ran); err != nil {
		return nil, err
	}
	if !ran {
		return nil, core.E(403, "auth", fmt.Sprintf("vote needs a finalised job on %s within %d d", v.Ref(), voteWindowD))
	}
	w := trust.Weight(st)
	grp, super := st.Group, st.Super
	if super == "" {
		_, grp, super = core.ClientFrom(ctx)
	}
	res := &voteResult{Ref: v.Ref(), Up: up}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO service_votes (name, ver, root, ip_group, ip_super, up, w, lvl, note) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			v.Name, v.Ver, id.Root, grp, super, up, float32(w), st.Level(), note); err != nil {
			if core.IsUniqueViolation(err) {
				return core.E(409, "dup", "already voted on "+v.Ref())
			}
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT (SELECT coalesce(sum(w), 0)::float8 FROM (`+trust.CollapseSQLWhere("service_votes", "up", "name = $1 AND ver = $2")+`) c),
			(SELECT coalesce(sum(w), 0)::float8 FROM (`+trust.CollapseSQLWhere("service_votes", "down", "name = $1 AND ver = $2")+`) c)`, v.Name, v.Ver).
			Scan(&res.OkW, &res.BadW); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE service_versions SET ok_w = $3, bad_w = $4 WHERE name = $1 AND ver = $2`, v.Name, v.Ver, float32(res.OkW), float32(res.BadW)); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, map[bool]string{true: "svok", false: "svbad"}[up], v.Ref(), 0)
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *svc) hVote(up bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.authWrite(r)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		var in struct {
			Note string `json:"note,omitempty"`
			V    string `json:"v,omitempty"`
			Why  string `json:"why,omitempty"`
		}
		if err := core.Decode(w, r, 4<<10, &in); err != nil {
			doc.Fail(w, r, err)
			return
		}
		note := in.Note
		if note == "" {
			note = in.V + in.Why
		}
		res, err := s.vote(r.Context(), id, r.PathValue("nameAtVer"), up, note)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		if core.WantJSON(r) {
			core.JSON(w, 200, map[string]any{"ok": true, "svc": res.Ref, "ok_w": res.OkW, "bad_w": res.BadW})
			return
		}
		doc.Tail(w, r, res.text(), doc.GET("/v1/svc/"+res.Ref, ""), doc.GET("/svc/"+strings.SplitN(res.Ref, "@", 2)[0], ""))
	}
}

func (s *svc) opVote(up bool) Op {
	return func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			Name string `json:"name"`
			Ver  int    `json:"ver,omitempty"`
			Note string `json:"note,omitempty"`
		}
		if err := decodeOp(a, &in); err != nil {
			return "", err
		}
		ref := in.Name
		if in.Ver > 0 {
			ref += "@" + strconv.Itoa(in.Ver)
		}
		res, err := s.vote(ctx, id, ref, up, in.Note)
		if err != nil {
			return "", err
		}
		return res.text(), nil
	}
}
