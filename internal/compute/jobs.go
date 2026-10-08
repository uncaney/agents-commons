package compute

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/wasmscan"
)

// Spec is one job request (SPEC-v2 14.1, 14.3, 27.6). Svc, Kind, Pipe, Bounty and Sub are set by
// server packages (catalog, pipes, bounties), never by clients.
type Spec struct {
	Wasm     string `json:"wasm"`
	In       string `json:"in"`
	InText   string `json:"in_text,omitempty"` // alternative to "in": inline input stored as a blob
	FS       string `json:"fs,omitempty"`      // zip blob mounted read-only at / (27.6)
	Ms       int    `json:"ms"`
	Mb       int    `json:"mb"`
	Fresh    bool   `json:"fresh,omitempty"`      // bypass the result cache (14.1)
	MaxWaitS int    `json:"max_wait_s,omitempty"` // auto-cancel with full refund (14.3)
	Lane     string `json:"lane,omitempty"`       // public (default) | own | trusted (27.6)
	Svc      string `json:"-"`
	Kind     string `json:"-"` // job (default) | audit | kat
	Pipe     string `json:"-"`
	Bounty   string `json:"-"`
	Sub      string `json:"-"`
}

type submitIn struct {
	Spec
	Jobs []Spec `json:"jobs"`
}

func (in *submitIn) specs() []Spec {
	if in.Jobs != nil {
		return in.Jobs
	}
	return []Spec{in.Spec}
}

func costOf(ms int) int64 { return int64((ms+999)/1000) * 3 }

// submitResult is what submit learned for the reply: ids (cache hits carry their view), the
// warnings and whether any job actually queued.
type submitResult struct {
	ids    []string
	views  map[string]*JobView // cache hits
	warn   map[string][]string // scrub kinds per id
	queued bool
	probe  bool // a module under probation
	hint   string
}

func (r *submitResult) lines() []string {
	out := make([]string, 0, len(r.ids))
	for _, id := range r.ids {
		switch {
		case r.views[id] != nil:
			out = append(out, r.views[id].text())
		case len(r.warn[id]) > 0:
			out = append(out, id+" warn scrub "+strings.Join(r.warn[id], ",")+": donors are strangers")
		default:
			out = append(out, id)
		}
	}
	return out
}

// submit validates specs, stores inline inputs, serves cache hits and creates the other jobs
// with their replicas (2 public, 1 for own/trusted lanes and audits).
func (s *svc) submit(ctx context.Context, id *core.Ident, specs []Spec) (*submitResult, error) {
	if len(specs) == 0 || len(specs) > maxBatch {
		return nil, core.Bad(fmt.Sprintf("1..%d jobs per request", maxBatch))
	}
	for i := range specs {
		sp := &specs[i]
		if sp.Ms == 0 {
			sp.Ms = defMs
		}
		if sp.Mb == 0 {
			sp.Mb = defMb
		}
		if sp.Ms < 1 || sp.Ms > maxMs || sp.Mb < 1 || sp.Mb > maxMb {
			return nil, core.Bad(fmt.Sprintf("ms must be 1..%d, mb 1..%d", maxMs, maxMb))
		}
		if sp.MaxWaitS < 0 || sp.MaxWaitS > maxWaitS {
			return nil, core.Bad(fmt.Sprintf("max_wait_s must be 0..%d", maxWaitS))
		}
		if sp.Lane == "" {
			sp.Lane = "public"
		}
		if sp.Lane != "public" && sp.Lane != "own" && sp.Lane != "trusted" {
			return nil, core.Bad("lane must be public, own or trusted")
		}
		if sp.Kind == "" {
			sp.Kind = "job"
		}
		if sp.Kind != "job" && sp.Kind != "audit" && sp.Kind != "kat" {
			return nil, core.Bad("kind must be job, audit or kat")
		}
		if !hashRe.MatchString(sp.Wasm) {
			return nil, core.Bad("wasm must be a sha256 hex")
		}
		if sp.FS != "" && !hashRe.MatchString(sp.FS) {
			return nil, core.Bad("fs must be a sha256 hex")
		}
		if sp.InText != "" {
			if sp.In != "" {
				return nil, core.Bad("give in or in_text, not both")
			}
			if len(sp.InText) > maxInText {
				return nil, core.E(413, "size", "in_text over 64 KiB: upload a blob")
			}
			b, _, err := s.putBlob(ctx, id.Root, strings.NewReader(sp.InText), putOpts{private: sp.Lane == "own"})
			if err != nil {
				return nil, err
			}
			sp.In, sp.InText = b.hash, ""
		}
		if !hashRe.MatchString(sp.In) {
			return nil, core.Bad("in must be a sha256 hex (or in_text)")
		}
	}
	res := &submitResult{views: map[string]*JobView{}, warn: map[string][]string{}}
	subLvl := core.Level(ctx, s.d.DB, id.Root)
	if id.Root == core.SystemID {
		subLvl = 3
	}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		res.ids, res.queued, res.probe, res.hint = nil, false, false, ""
		for _, sp := range specs {
			if err := s.submitOne(ctx, tx, id, sp, subLvl, res); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if res.queued {
		s.d.Notify.Wake("lease")
	}
	return res, nil
}

// submitOne checks one spec's blobs (14.3 precise errors, 27.6 lanes, fs, private, probation),
// serves it from the cache or reserves and queues it.
func (s *svc) submitOne(ctx context.Context, tx pgx.Tx, id *core.Ident, sp Spec, subLvl int, res *submitResult) error {
	wasm, err := s.refBlob(ctx, tx, id.Root, sp.Wasm, "wasm")
	if err != nil {
		return err
	}
	in, err := s.refBlob(ctx, tx, id.Root, sp.In, "in")
	if err != nil {
		return err
	}
	var fs *blobRow
	if sp.FS != "" {
		if fs, err = s.refBlob(ctx, tx, id.Root, sp.FS, "fs"); err != nil {
			return err
		}
		fm, err := s.ensureMeta(ctx, tx, fs)
		if err != nil {
			return err
		}
		switch {
		case fm == nil || fm.kind != "zip":
			return core.Bad("fs must be a zip blob")
		case fm.fsUnusable != "":
			return core.Bad("fs " + fm.fsUnusable)
		}
	}
	if (wasm.private || in.private || (fs != nil && fs.private)) && sp.Lane != "own" {
		return core.Bad("private blobs run on lane own only")
	}
	if wasm.size > maxWasm {
		if ok, err := pinned(ctx, tx, wasm.hash); err != nil {
			return err
		} else if !ok {
			return core.E(413, "size", "wasm over 4 MiB (only pinned modules may be larger)")
		}
	}
	wm, err := s.ensureMeta(ctx, tx, wasm)
	if err != nil {
		return err
	}
	switch {
	case wm == nil || wm.kind != "wasm":
		return core.Bad("not a wasm module (no \\0asm magic)")
	case wm.banned != "":
		return core.Bad("module " + wm.banned)
	case wm.parseErr != "":
		return core.Bad("module " + strings.TrimPrefix(wm.parseErr, "wasm: "))
	}
	if err := wm.info().Check(sp.Mb); err != nil {
		var we *wasmscan.Error
		if errors.As(err, &we) {
			return core.E(we.Status, we.Code, we.Msg)
		}
		return core.Bad(err.Error())
	}
	if sp.Lane == "trusted" {
		n, err := bumpDaily(ctx, tx, id.Root, "j:trusted", 1)
		if err != nil {
			return err
		}
		if n > trustedDaily {
			return core.ErrQuota
		}
	}
	var warn []string
	if len(wm.secretKinds) > 0 {
		warn = append(warn, wm.secretKinds...)
	}
	if im, err := loadMeta(ctx, tx, in.hash); err != nil {
		return err
	} else if im != nil && im.kind == "text" {
		warn = append(warn, im.secretKinds...)
	}
	if sp.Lane != "own" && !sp.Fresh {
		v, hit, err := s.cacheServe(ctx, tx, id, sp, wasm, in)
		if err != nil {
			return err
		}
		if hit {
			res.ids = append(res.ids, v.ID)
			res.views[v.ID] = v
			return nil
		}
	}
	cost := costOf(sp.Ms)
	if sp.Lane == "trusted" {
		cost *= 2
	}
	if err := core.Reserve(ctx, tx, id.ID, cost); err != nil {
		if errors.Is(err, core.ErrCredits) && id.Root == core.SystemID {
			return ErrUnfunded
		}
		return err
	}
	jid := core.NewID('j')
	var maxWait any
	if sp.MaxWaitS > 0 {
		maxWait = time.Now().Add(time.Duration(sp.MaxWaitS) * time.Second)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO jobs (id, submitter, root, wasm, input, fs, ms, mb, reserved, wasm_size, svc, kind, lane, sub_lvl, pipe, bounty, sub, max_wait_until)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
		jid, id.ID, id.Root, sp.Wasm, sp.In, sp.FS, sp.Ms, sp.Mb, cost, wasm.size, sp.Svc, sp.Kind, sp.Lane, subLvl, sp.Pipe, sp.Bounty, sp.Sub, maxWait); err != nil {
		return err
	}
	replicas := `INSERT INTO replicas (job) VALUES ($1), ($1)`
	if sp.Lane != "public" || sp.Kind == "audit" {
		replicas = `INSERT INTO replicas (job) VALUES ($1)`
	}
	if _, err := tx.Exec(ctx, replicas, jid); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE blobs SET last_ref = now(), used_at = now() WHERE hash IN ($1, $2, $3)`, sp.Wasm, sp.In, sp.FS); err != nil {
		return err
	}
	res.ids = append(res.ids, jid)
	res.queued = true
	if len(warn) > 0 {
		res.warn[jid] = warn
	}
	if sp.Lane == "public" && wm.runsOK < probationOK {
		res.probe = true
	}
	if h := compileHint(wm.compileMs); h != "" && res.hint == "" {
		res.hint = h
	}
	return nil
}

// refBlob loads a blob a submit references; a missing hash and a private blob of another root
// are the same 404.
func (s *svc) refBlob(ctx context.Context, q core.Q, root, hash, what string) (*blobRow, error) {
	b, err := loadBlob(ctx, q, hash)
	if err != nil {
		return nil, err
	}
	if b == nil || (b.private && b.owner != root) {
		return nil, core.E(404, "notfound", what+" blob "+hash[:12])
	}
	return b, nil
}

// JobView is the status of one job as the submitter sees it.
type JobView struct {
	ID, Status, Out, Reason string
	Ms, Code                int
	Cached                  bool
	Lane                    string
	Att, AttSig             string
}

func (v *JobView) final() bool { return v.Status == "done" || v.Status == "failed" }

func (v *JobView) text() string {
	switch v.Status {
	case "done":
		t := fmt.Sprintf("%s done out=%s ms=%d", v.ID, v.Out, v.Ms)
		if v.Code != 0 {
			t += fmt.Sprintf(" code=%d", v.Code)
		}
		if v.Cached {
			t += " cached"
		}
		return t
	case "failed":
		return v.ID + " failed " + v.Reason
	}
	return v.ID + " " + v.Status
}

func (v *JobView) json() map[string]any {
	j := map[string]any{"id": v.ID, "status": v.Status}
	switch v.Status {
	case "done":
		j["out"], j["ms"], j["code"] = v.Out, v.Ms, v.Code
		if v.Cached {
			j["cached"] = true
		}
	case "failed":
		j["reason"] = v.Reason
	}
	if v.Att != "" {
		j["att"], j["sig"] = v.Att, v.AttSig
	}
	return j
}

// attText appends the signed att1 statement and its signature as lines (14.2).
func (v *JobView) attText() string {
	t := v.text()
	if v.Att != "" {
		t += "\n" + v.Att + "\n" + v.AttSig
	}
	return t
}

func (s *svc) loadJob(ctx context.Context, root, jid string) (*JobView, error) {
	v := &JobView{}
	err := s.d.DB.QueryRow(ctx, `SELECT id, status, out, used_ms, code, reason, cached_from <> '', lane, att, att_sig FROM jobs WHERE id = $1 AND root = $2`, jid, root).
		Scan(&v.ID, &v.Status, &v.Out, &v.Ms, &v.Code, &v.Reason, &v.Cached, &v.Lane, &v.Att, &v.AttSig)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return v, err
}

// status returns the job view, long-polling up to wait seconds for a final state.
// The notifier topic is only subscribed once the job is known to exist, belong to the
// caller and be unfinished (review #5): polls of foreign/unknown/finished ids never
// create a topic entry.
func (s *svc) status(ctx context.Context, id *core.Ident, jid string, wait int) (*JobView, error) {
	if id == nil {
		return nil, core.ErrAuth
	}
	if !core.ValidID(jid) || jid[0] != 'j' {
		return nil, core.Bad("bad job id")
	}
	v, err := s.loadJob(ctx, id.Root, jid)
	if err != nil || v.final() || wait <= 0 {
		return v, err
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	topic := "job:" + jid
	for {
		c, cancel := s.d.Notify.Subscribe(topic) // subscribe, then re-read so a wake in between is not missed
		v, err = s.loadJob(ctx, id.Root, jid)
		rem := time.Until(deadline)
		if err != nil || v.final() || rem <= 0 {
			cancel()
			return v, err
		}
		t := time.NewTimer(rem)
		select {
		case <-c:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return v, nil
		case <-t.C:
		}
		t.Stop()
		cancel()
	}
}

// output returns the bytes of a done job's output; done=false while the job is unfinished.
func (s *svc) output(ctx context.Context, id *core.Ident, jid string) ([]byte, bool, error) {
	v, err := s.status(ctx, id, jid, 0)
	if err != nil {
		return nil, false, err
	}
	if v.Status != "done" {
		return nil, false, nil
	}
	b, err := os.ReadFile(s.blobPath(v.Out))
	if err != nil {
		return nil, true, core.E(404, "notfound", "output blob gone")
	}
	return b, true, nil
}

// reply renders a submit result: one line per job (ids, cache hits as done lines, scrub warnings),
// then the eta line, probation and compile hints (14.3, 27.6). Status 202 when nothing can run
// yet (no donors online) or an input was flagged.
func (s *svc) reply(res *submitResult) (int, string, map[string]any) {
	lines := res.lines()
	j := map[string]any{"id": res.ids[0], "ids": res.ids}
	status := 200
	if res.queued {
		eta, donors := s.stats.eta(res)
		if donors {
			lines = append(lines, fmt.Sprintf("eta_s=~%d", eta))
			j["eta_s"] = eta
		} else {
			lines = append(lines, "queued eta=unknown (no donors online; DELETE /v1/j/"+res.ids[0]+" cancels)")
			status = 202
		}
		if res.probe {
			lines = append(lines, "probation (opt-in donors only, eta may be longer)")
			j["probation"] = true
		}
		if res.hint != "" {
			lines = append(lines, res.hint)
			j["hint"] = res.hint
		}
	}
	if len(res.warn) > 0 {
		status = 202
		var kinds []string
		for _, id := range res.ids {
			kinds = append(kinds, res.warn[id]...)
		}
		j["warn"] = "scrub " + strings.Join(kinds, ",") + ": donors are strangers"
	}
	if len(res.views) > 0 {
		var cached []map[string]any
		for _, id := range res.ids {
			if v := res.views[id]; v != nil {
				cached = append(cached, v.json())
			}
		}
		j["cached"] = cached
	}
	return status, strings.Join(lines, "\n"), j
}

func (s *svc) hSubmit(w http.ResponseWriter, r *http.Request) {
	id, err := s.authCompute(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in submitIn
	if err := core.Decode(w, r, 1<<20, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	res, err := s.submit(r.Context(), id, in.specs())
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	st, text, j := s.reply(res)
	core.Text(w, r, st, text, j)
}

func (s *svc) hJob(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	wait, err := waitParam(r, maxJobWait)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	v, err := s.status(r.Context(), id, r.PathValue("id"), wait)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if r.URL.Query().Get("att") == "1" {
		core.OK(w, r, v.attText(), v.json())
		return
	}
	v.Att, v.AttSig = "", ""
	core.OK(w, r, v.text(), v.json())
}

// MCP ops ------------------------------------------------------------------

func (s *svc) opJ(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if err := s.checkIdent(id); err != nil {
		return "", err
	}
	var in submitIn
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	res, err := s.submit(ctx, id, in.specs())
	if err != nil {
		return "", err
	}
	_, text, _ := s.reply(res)
	return text, nil
}

func (s *svc) opJW(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if id == nil {
		return "", core.ErrAuth
	}
	var in struct {
		ID   string `json:"id"`
		Wait int    `json:"wait"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	v, err := s.status(ctx, id, in.ID, clampWait(in.Wait, maxJobWait))
	if err != nil {
		return "", err
	}
	return v.text(), nil
}

func (s *svc) opJAtt(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if id == nil {
		return "", core.ErrAuth
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	v, err := s.status(ctx, id, in.ID, 0)
	if err != nil {
		return "", err
	}
	if v.Att == "" {
		return "", core.E(409, "bad", v.text()+" (no attestation yet)")
	}
	return v.attText(), nil
}

// opJO returns a done job's output inline when it is small UTF-8 text.
func (s *svc) opJO(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if id == nil {
		return "", core.ErrAuth
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	v, err := s.status(ctx, id, in.ID, 0)
	if err != nil {
		return "", err
	}
	if v.Status != "done" {
		return "", core.E(409, "bad", v.text())
	}
	b, size, text, err := s.readOutput(v.Out)
	if err != nil {
		return "", err
	}
	if b == nil || !text {
		return fmt.Sprintf("out=%s size=%d (binary or too large: use GET /v1/b/%s)", v.Out, size, v.Out), nil
	}
	return string(b), nil
}
