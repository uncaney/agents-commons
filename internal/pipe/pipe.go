// Package pipe implements service pipelines (SPEC-v2 27.6, P107): stdout-to-stdin chaining of
// catalog services / raw modules in one submission. One submission (POST /v1/pipe) runs 2..8
// steps sequentially through compute's job queue — each step's output blob is the next step's
// input (interpreter steps get the {code, stdin} framing) — with per-step result-cache hits,
// per-step fees and refunds, partial outputs on failure, and a signed pipe1 attestation binding
// the per-step att1 receipts at the end.
//
// The steps are ordinary compute jobs carrying jobs.pipe = <pipe id>; compute.OnDone (chained by
// P60a through this package's OnDone) records a settled step and the advancer submits the next one
// OUTSIDE compute's finalize transaction, so the per-step ledger holds never deadlock. Nothing in
// this package runs wasm: execution stays on donated compute.
package pipe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/sign"
)

// Op is an MCP operation (same text as the HTTP handler; errors are *core.APIError).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

const (
	minSteps     = 2
	maxSteps     = 8
	pipeJobs     = 8        // a pipe counts as 8 jobs against the daily compute cap (27.6)
	maxPipeJobs  = 400      // daily pipe-job budget per root (50 pipes), counter "pipe_jobs"
	maxMs        = 30000    // mirrors compute's per-job ceiling (14.1)
	defMs        = 10000    // mirrors compute's default
	maxMb        = 256      // mirrors compute's per-job ceiling
	defMb        = 64       // mirrors compute's default
	maxWait      = 85       // long-poll ceiling, seconds (14.3)
	frameInline  = 16 << 10 // {code, stdin} JSON below this; NUL-split above (27.6 framing)
	maxStdout    = 16 << 10 // inline final stdout shown in the reply (27.6)
	maxCodeBytes = 64 << 10 // interpreter source per step
	maxReadBlob  = 64 << 20 // cap on a chained output we read to re-frame (matches blob mb cap)
)

var hashRe = compileHashRe()

func compileHashRe() func(string) bool {
	return func(s string) bool {
		if len(s) != 64 {
			return false
		}
		for i := 0; i < 64; i++ {
			c := s[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
}

type svc struct {
	d      *core.Deps
	signer *sign.Signer
}

var (
	svcMu sync.Mutex
	svcs  = map[*core.Deps]*svc{}
	// hookOnce installs the compute.OnDone chain once per process (tests build several Deps).
	hookOnce sync.Once
)

func svcFor(d *core.Deps) *svc {
	svcMu.Lock()
	defer svcMu.Unlock()
	if s, ok := svcs[d]; ok {
		return s
	}
	s := &svc{d: d}
	s.signer, _ = sign.New(d.Cfg)
	svcs[d] = s
	return s
}

// step is one resolved pipeline stage stored in pipes.steps (jsonb).
type step struct {
	Wasm   string `json:"wasm"`           // module hash to run
	Ms     int    `json:"ms"`             // per-step time cap
	Mb     int    `json:"mb"`             // per-step memory cap
	Interp bool   `json:"interp"`         // frame the input as {code, stdin}
	Code   string `json:"code,omitempty"` // interpreter source (when Interp)
	Lit    string `json:"lit,omitempty"`  // literal input override for this step (ignores the chain)
	Ref    string `json:"ref,omitempty"`  // service name@ver resolved for this step (display only)
}

// --- creation ---------------------------------------------------------------------------------

// stepIn is one step of the POST /v1/pipe body.
type stepIn struct {
	Svc    string `json:"svc,omitempty"`     // catalog service name (resolved to a module hash)
	Wasm   string `json:"wasm,omitempty"`    // raw module hash (alternative to svc)
	Code   string `json:"code,omitempty"`    // interpreter source -> {code, stdin} framing
	InText string `json:"in_text,omitempty"` // literal input for THIS step (overrides the chain)
	Ms     int    `json:"ms,omitempty"`
	Mb     int    `json:"mb,omitempty"`
}

// pipeIn is the POST /v1/pipe body / pipe op argument.
type pipeIn struct {
	Steps  []stepIn `json:"steps"`
	In     string   `json:"in,omitempty"`      // step-0 input blob hash
	InText string   `json:"in_text,omitempty"` // step-0 literal input
	Wait   int      `json:"wait,omitempty"`
	Ms     int      `json:"ms,omitempty"` // default per-step time cap
	Mb     int      `json:"mb,omitempty"` // memory cap for every step
}

// create validates the steps, reserves the whole budget upfront as an affordability gate (the
// real per-step fees and refunds are compute's), charges the 8-job daily cap, inserts the pipe and
// submits step 0. It returns the pipe id; the caller long-polls (wait) for the final state.
func (s *svc) create(ctx context.Context, id *core.Ident, in pipeIn) (string, error) {
	if id == nil {
		return "", core.ErrAuth
	}
	if id.Banned {
		return "", core.ErrBanned
	}
	if s.d.Frozen("write") {
		return "", core.Frozen("write")
	}
	if s.d.Frozen("compute") {
		return "", core.Frozen("compute")
	}
	if core.Level(ctx, s.d.DB, id.Root) < 1 {
		return "", core.E(403, "level", "pipelines need L1+")
	}
	if len(in.Steps) < minSteps || len(in.Steps) > maxSteps {
		return "", core.Bad(fmt.Sprintf("a pipe runs %d..%d steps", minSteps, maxSteps))
	}
	if in.In != "" && in.InText != "" {
		return "", core.Bad("give in or in_text, not both")
	}
	if in.In != "" && !hashRe(in.In) {
		return "", core.Bad("in must be a sha256 hex")
	}
	if in.Mb != 0 && (in.Mb < 1 || in.Mb > maxMb) {
		return "", core.Bad(fmt.Sprintf("mb must be 1..%d", maxMb))
	}
	mb := in.Mb
	if mb == 0 {
		mb = defMb
	}
	steps := make([]step, len(in.Steps))
	for i, si := range in.Steps {
		st, err := s.resolveStep(ctx, si, in.Ms, mb)
		if err != nil {
			return "", core.E(apiStatus(err), "bad", fmt.Sprintf("step %d: %s", i+1, apiMsg(err)))
		}
		steps[i] = st
	}
	// Step-0 input: a literal seeds in0 as a blob; a hash is used directly.
	in0 := in.In
	if in.InText != "" {
		h, err := compute.PutBlobBytes(ctx, s.d, id.Root, []byte(in.InText), "")
		if err != nil {
			return "", err
		}
		in0 = h
	}
	pid := core.NewID('q')
	stepsJSON, err := json.Marshal(steps)
	if err != nil {
		return "", err
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		// 8-job daily cap (27.6): a pipe counts as 8 jobs regardless of its step count.
		var n int
		if err := tx.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, 'pipe_jobs', current_date, $2)
			ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, id.Root, pipeJobs).Scan(&n); err != nil {
			return err
		}
		if n > maxPipeJobs {
			return core.ErrQuota
		}
		// Fail fast only when the submitter cannot afford even the first step: reserve its nominal
		// cost and release it at once (per-step fees and refunds are compute's, and cache hits cost
		// nothing, so the whole budget is never pre-held — that would reject an affordable cached
		// pipe). Credits are therefore never double-charged.
		if err := core.Reserve(ctx, tx, id.ID, costOf(steps[0].Ms)); err != nil {
			return err
		}
		if err := core.Refund(ctx, tx, id.ID, costOf(steps[0].Ms)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO pipes (id, root, submitter, steps, nsteps, in0, pending, mb, wait)
			VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8)`, pid, id.Root, id.ID, stepsJSON, len(steps), in0, mb, clampWait(in.Wait))
		return err
	})
	if err != nil {
		return "", err
	}
	// Submit step 0 (and drain any immediate cache hits) before returning.
	s.advanceOne(ctx, pid)
	return pid, nil
}

// resolveStep turns a request step into a stored step: resolves a service name to its module hash,
// validates a raw hash, applies the ms/mb caps and the interpreter framing choice.
func (s *svc) resolveStep(ctx context.Context, si stepIn, defMsVal, mb int) (step, error) {
	if (si.Svc == "") == (si.Wasm == "") {
		return step{}, core.Bad("give svc or wasm")
	}
	if si.Code != "" && si.InText != "" {
		return step{}, core.Bad("give code or in_text, not both")
	}
	if len(si.Code) > maxCodeBytes {
		return step{}, core.E(413, "size", "code over 64 KiB")
	}
	st := step{Code: si.Code, Lit: si.InText, Interp: si.Code != ""}
	if si.Wasm != "" {
		if !hashRe(si.Wasm) {
			return step{}, core.Bad("wasm must be a sha256 hex")
		}
		st.Wasm = si.Wasm
	} else {
		v, err := catalog.Resolve(ctx, s.d.DB, si.Svc)
		if err != nil {
			return step{}, err
		}
		if v.State == "rejected" || v.Hidden {
			return step{}, core.E(410, "gone", si.Svc+" not available")
		}
		st.Wasm, st.Ref = v.Wasm, v.Ref()
		if st.Ms == 0 {
			st.Ms = v.Manifest.MsHint
		}
		if st.Mb == 0 {
			st.Mb = v.Manifest.MbHint
		}
	}
	st.Ms = si.Ms
	if st.Ms == 0 {
		st.Ms = defMsVal
	}
	if st.Ms == 0 {
		st.Ms = defMs
	}
	if st.Ms < 1 || st.Ms > maxMs {
		return step{}, core.Bad(fmt.Sprintf("ms must be 1..%d", maxMs))
	}
	st.Mb = mb
	return st, nil
}

// --- advancing --------------------------------------------------------------------------------

// advanceOne submits the next step of pipe pid (or finishes it) whenever a step has settled and
// none is in flight. It runs OUTSIDE compute's finalize transaction (OnDone only records a step),
// so the per-step credit holds can never deadlock. It holds the pipe row FOR UPDATE across the
// submit — safe, because a step is in flight (cur_job set) exactly when no advance is due, so
// OnDone and advanceOne never touch the same pipe row at once. Immediate cache hits are drained in
// the loop (repeated prefixes are free). Idempotent and safe to call from several readers at once.
func (s *svc) advanceOne(ctx context.Context, pid string) {
	for i := 0; i <= maxSteps; i++ {
		again, err := s.advanceStep(ctx, pid)
		if err != nil {
			s.d.Log.Warn("pipe advance", "pipe", pid, "err", err)
			return
		}
		if !again {
			return
		}
	}
}

func (s *svc) advanceStep(ctx context.Context, pid string) (again bool, err error) {
	tx, err := s.d.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var (
		root, submitter, in0 string
		stepsJSON            []byte
		nsteps, cur, mb      int
		outs                 []string
	)
	err = tx.QueryRow(ctx, `SELECT root, submitter, steps, nsteps, cur, outs, in0, mb FROM pipes
		WHERE id = $1 AND state = 'running' AND pending AND cur_job = '' FOR UPDATE`, pid).
		Scan(&root, &submitter, &stepsJSON, &nsteps, &cur, &outs, &in0, &mb)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // nothing to advance
	}
	if err != nil {
		return false, err
	}
	var steps []step
	if err := json.Unmarshal(stepsJSON, &steps); err != nil {
		return false, err
	}
	ident := &core.Ident{ID: submitter, Root: root}
	// All steps done: sign the pipe1 statement and finish.
	if cur >= nsteps {
		att, sig := s.attest(pid, steps, outs)
		if _, err := tx.Exec(ctx, `UPDATE pipes SET state = 'done', pending = false, att = $2, att_sig = $3 WHERE id = $1`, pid, att, sig); err != nil {
			return false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		s.d.Notify.Wake("pipe:" + pid)
		return false, nil
	}
	// Build step `cur`'s input (chained from the previous output, or the seed / a literal).
	inHash, err := s.stepInput(ctx, root, steps[cur], cur, in0, outs)
	if err != nil {
		return false, s.failPipe(ctx, tx, pid, cur, "input: "+apiMsg(err))
	}
	ids, err := compute.Submit(ctx, s.d, ident, []compute.Spec{{
		Wasm: steps[cur].Wasm, In: inHash, Ms: steps[cur].Ms, Mb: steps[cur].Mb, Pipe: pid}})
	if err != nil {
		return false, s.failPipe(ctx, tx, pid, cur, "submit: "+apiMsg(err))
	}
	if len(ids) == 0 {
		return false, s.failPipe(ctx, tx, pid, cur, "submit: no job")
	}
	jid := ids[0]
	// A cached step answers done immediately (no finalize, no OnDone): record it here and drain.
	v, err := compute.Status(ctx, s.d, ident, jid, 0)
	if err != nil {
		return false, err
	}
	switch v.Status {
	case "done":
		if _, err := tx.Exec(ctx, `UPDATE pipes SET outs = array_append(outs, $2), cur = cur + 1, ms_total = ms_total + $3, pending = true, cur_job = '' WHERE id = $1`,
			pid, v.Out, v.Ms); err != nil {
			return false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		s.d.Notify.Wake("pipe:" + pid)
		return true, nil // drain the next step
	case "failed":
		return false, s.failPipe(ctx, tx, pid, cur, doc.SafeLine(v.Reason))
	default:
		if _, err := tx.Exec(ctx, `UPDATE pipes SET cur_job = $2, pending = false WHERE id = $1`, pid, jid); err != nil {
			return false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return false, err
		}
		s.d.Notify.Wake("pipe:" + pid)
		return false, nil // OnDone re-pends when the step settles
	}
}

// failPipe marks the pipe failed at step idx (0-based) with partial outs and commits tx.
func (s *svc) failPipe(ctx context.Context, tx pgx.Tx, pid string, idx int, reason string) error {
	if _, err := tx.Exec(ctx, `UPDATE pipes SET state = 'failed', fail_idx = $2, reason = $3, pending = false, cur_job = '' WHERE id = $1 AND state = 'running'`,
		pid, idx, trunc(reason, 300)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.d.Notify.Wake("pipe:" + pid)
	return nil
}

// stepInput materialises the input blob for step idx: a per-step literal, the interpreter framing
// of the chained data, or the chained data / seed hash passed straight through for a tool step.
func (s *svc) stepInput(ctx context.Context, root string, st step, idx int, in0 string, outs []string) (string, error) {
	prevHash := in0
	if idx > 0 {
		prevHash = outs[idx-1]
	}
	switch {
	case st.Lit != "" && !st.Interp:
		return compute.PutBlobBytes(ctx, s.d, root, []byte(st.Lit), "")
	case st.Interp:
		var stdin []byte
		if st.Lit != "" {
			stdin = []byte(st.Lit)
		} else if prevHash != "" {
			b, err := s.readBlob(prevHash)
			if err != nil {
				return "", err
			}
			stdin = b
		}
		return compute.PutBlobBytes(ctx, s.d, root, frame(st.Code, stdin), "")
	default: // tool step: chained data / seed passed straight through
		if prevHash == "" {
			return compute.PutBlobBytes(ctx, s.d, root, nil, "")
		}
		return prevHash, nil
	}
}

// frame builds the 15.4 launcher input: {"code","stdin"} JSON when small (and whenever the code
// would collide with the NUL-split sniff), else `code\0stdin` (the launcher splits at the first
// NUL when the input does not start with '{').
func frame(code string, stdin []byte) []byte {
	if len(code)+len(stdin) <= frameInline || strings.HasPrefix(code, "{") {
		b, _ := json.Marshal(map[string]string{"code": code, "stdin": string(stdin)})
		return b
	}
	out := make([]byte, 0, len(code)+1+len(stdin))
	out = append(out, code...)
	out = append(out, 0)
	return append(out, stdin...)
}

// readBlob reads an owned blob's bytes straight from the data dir (sha256 layout).
func (s *svc) readBlob(hash string) ([]byte, error) {
	if !hashRe(hash) {
		return nil, core.Bad("bad blob hash")
	}
	f, err := os.Open(filepath.Join(s.d.Cfg.DataDir, "blobs", hash[:2], hash))
	if err != nil {
		return nil, core.E(404, "notfound", "chained blob gone")
	}
	defer f.Close()
	b := make([]byte, maxReadBlob+1)
	n, _ := f.Read(b)
	if n > maxReadBlob {
		return nil, core.E(413, "size", "chained output too large to re-frame")
	}
	return b[:n], nil
}

// --- OnDone (compute chain) -------------------------------------------------------------------

// OnDone records a settled pipe step inside compute's finalize transaction (P60a chains it):
// append the output and re-pend on success, fail the pipe with the step index on failure. It only
// records — the advancer submits the next step out of band — so the per-step credit holds (which
// finalize is in the middle of refunding) can never deadlock against a nested submit. Exported for
// the compute.OnDone chain.
func OnDone(ctx context.Context, q core.Q, j *compute.Job) error {
	if j == nil || j.Pipe == "" {
		return nil
	}
	if j.Status == "done" {
		_, err := q.Exec(ctx, `UPDATE pipes SET outs = array_append(outs, $2), cur = cur + 1, ms_total = ms_total + $3, pending = true, cur_job = ''
			WHERE id = $1 AND cur_job = $4 AND state = 'running'`, j.Pipe, j.Out, j.UsedMs, j.ID)
		return err
	}
	_, err := q.Exec(ctx, `UPDATE pipes SET state = 'failed', fail_idx = cur, reason = $2, pending = false, cur_job = ''
		WHERE id = $1 AND cur_job = $3 AND state = 'running'`, j.Pipe, trunc(doc.SafeLine(j.Reason), 300), j.ID)
	return err
}

// advanceAll is the janitor safety net: advance every pipe with a settled, unadvanced step (for
// pipes whose submitter never long-polls) and time out pipes stuck with a dead in-flight job.
func (s *svc) advanceAll(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT id FROM pipes WHERE state = 'running' AND pending AND cur_job = '' ORDER BY created LIMIT 200`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		s.advanceOne(ctx, id)
	}
	// A pipe whose in-flight step vanished (cancelled job, lost worker) is re-pended so it either
	// re-submits (cache) or fails cleanly rather than hanging forever.
	_, err = s.d.DB.Exec(ctx, `UPDATE pipes p SET pending = true, cur_job = ''
		WHERE p.state = 'running' AND p.cur_job <> '' AND p.created < now() - interval '2 minutes'
		AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = p.cur_job AND j.status IN ('queued', 'running'))`)
	return err
}

// --- attestation ------------------------------------------------------------------------------

// attest signs the pipe1 statement binding the pipeline shape and its outputs (27.6): the per-step
// att1 receipts stay on each job; pipe1 is `pipe1 q=<id> steps=<digest> outs=<digest> t= k=1`.
func (s *svc) attest(pid string, steps []step, outs []string) (line, sig string) {
	if s.signer == nil {
		return "", ""
	}
	wasms := make([]string, len(steps))
	for i, st := range steps {
		wasms[i] = st.Wasm
	}
	kv := []sign.KV{
		{K: "q", V: pid},
		{K: "steps", V: digest(wasms)},
		{K: "outs", V: digest(outs)},
		{K: "t", V: strconv.FormatInt(time.Now().Unix(), 10)},
		{K: "k", V: strconv.Itoa(s.signer.KID())},
	}
	line = sign.Canonical("pipe1", kv...)
	return line, s.signer.Sign("pipe1", line)
}

// digest is the hex sha256 over the newline-joined hashes (compact, reproducible from the chain).
func digest(hs []string) string {
	h := sha256.Sum256([]byte(strings.Join(hs, "\n")))
	return hex.EncodeToString(h[:])
}

// --- view / helpers ---------------------------------------------------------------------------

type pipeView struct {
	ID, State, Reason, Att, AttSig string
	Cur, N, MsTotal, FailIdx       int
	Outs                           []string
}

func (v *pipeView) final() bool { return v.State == "done" || v.State == "failed" }

func (v *pipeView) out() string {
	if v.State == "done" && len(v.Outs) > 0 {
		return v.Outs[len(v.Outs)-1]
	}
	return ""
}

// text is the reply head (27.6): `q… done 3/3 ms=812 out=<hash>` | `q… failed step 2/3 <reason>` |
// `q… running 1/3`.
func (v *pipeView) text() string {
	switch v.State {
	case "done":
		return fmt.Sprintf("%s done %d/%d ms=%d out=%s", v.ID, v.Cur, v.N, v.MsTotal, v.out())
	case "failed":
		return fmt.Sprintf("%s failed step %d/%d %s", v.ID, v.FailIdx+1, v.N, doc.SafeLine(v.Reason))
	default:
		return fmt.Sprintf("%s running %d/%d", v.ID, v.Cur, v.N)
	}
}

func (v *pipeView) json() map[string]any {
	j := map[string]any{"id": v.ID, "state": v.State, "cur": v.Cur, "n": v.N}
	switch v.State {
	case "done":
		j["ms"], j["out"], j["outs"] = v.MsTotal, v.out(), v.Outs
	case "failed":
		j["reason"], j["fail_step"], j["outs"] = v.Reason, v.FailIdx+1, v.Outs
	}
	if v.Att != "" {
		j["att"], j["sig"] = v.Att, v.AttSig
	}
	return j
}

func (s *svc) load(ctx context.Context, root, pid string) (*pipeView, error) {
	if !core.ValidID(pid) || pid[0] != 'q' {
		return nil, core.Bad("bad pipe id")
	}
	v := &pipeView{}
	err := s.d.DB.QueryRow(ctx, `SELECT id, state, cur, nsteps, ms_total, fail_idx, reason, outs, att, att_sig
		FROM pipes WHERE id = $1 AND root = $2`, pid, root).
		Scan(&v.ID, &v.State, &v.Cur, &v.N, &v.MsTotal, &v.FailIdx, &v.Reason, &v.Outs, &v.Att, &v.AttSig)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return v, err
}

// status advances pid, then long-polls up to wait seconds for the final state (or step `until`
// completed, 1-based; 0 = final). It wakes on this pipe's topic and on the in-flight step's job
// topic (compute wakes that after it commits, so advancement stays reliable without a janitor).
func (s *svc) status(ctx context.Context, id *core.Ident, pid string, wait, until int) (*pipeView, error) {
	if id == nil {
		return nil, core.ErrAuth
	}
	deadline := time.Now().Add(time.Duration(clampWait(wait)) * time.Second)
	for {
		s.advanceOne(ctx, pid)
		v, err := s.load(ctx, id.Root, pid)
		if err != nil {
			return nil, err
		}
		if v.final() || (until > 0 && v.Cur >= until) || time.Now().After(deadline) {
			return v, nil
		}
		var curJob string
		if err := s.d.DB.QueryRow(ctx, `SELECT cur_job FROM pipes WHERE id = $1`, pid).Scan(&curJob); err != nil {
			return v, nil
		}
		cp, cancelP := s.d.Notify.Subscribe("pipe:" + pid)
		cj, cancelJ := subscribeJob(s.d, curJob)
		rem := time.Until(deadline)
		if rem <= 0 {
			cancelP()
			cancelJ()
			return v, nil
		}
		t := time.NewTimer(rem)
		select {
		case <-cp:
		case <-cj:
		case <-ctx.Done():
		case <-t.C:
		}
		t.Stop()
		cancelP()
		cancelJ()
		if ctx.Err() != nil {
			return v, nil
		}
	}
}

func subscribeJob(d *core.Deps, jid string) (<-chan struct{}, func()) {
	if jid == "" {
		return nil, func() {}
	}
	return d.Notify.Subscribe("job:" + jid)
}

// stdout reads the final (or a chosen step's) output as inline text when small UTF-8 (27.6).
func (s *svc) stdout(ctx context.Context, id *core.Ident, hash string) (body []byte, text bool, err error) {
	if hash == "" {
		return nil, false, nil
	}
	b, err := s.readBlob(hash)
	if err != nil {
		return nil, false, err
	}
	_ = ctx
	_ = id
	if len(b) > maxStdout || !utf8.Valid(b) {
		return b, false, nil
	}
	return b, true, nil
}

func (s *svc) purge(ctx context.Context, root string) error {
	// Running pipes of a purged root are abandoned (their jobs are cancelled by compute's purge);
	// delete the pipe rows.
	_, err := s.d.DB.Exec(ctx, `DELETE FROM pipes WHERE root = $1`, root)
	return err
}

func (s *svc) meLine(ctx context.Context, id *core.Ident) []string {
	if id == nil {
		return nil
	}
	var n int
	if err := s.d.DB.QueryRow(ctx, `SELECT coalesce((SELECT n FROM counters WHERE scope = $1 AND kind = 'pipe_jobs' AND day = current_date), 0)`, id.Root).Scan(&n); err != nil || n == 0 {
		return nil
	}
	return []string{fmt.Sprintf("pipe_jobs %d/%d", n, maxPipeJobs)}
}

func costOf(ms int) int64 { return int64((ms+999)/1000) * 3 }

func clampWait(n int) int {
	if n < 0 {
		return 0
	}
	if n > maxWait {
		return maxWait
	}
	return n
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func apiStatus(err error) int {
	if ae, ok := err.(*core.APIError); ok {
		return ae.Status
	}
	return 400
}

func apiMsg(err error) string {
	if ae, ok := err.(*core.APIError); ok {
		return ae.Msg
	}
	return err.Error()
}

// Help is the help{t:pipe} text (<= 200 tokens).
const Help = `pipe (chain catalog services/modules stdout->stdin in one submission; 2..8 steps, per-step cache hits, fees and refunds):
POST /v1/pipe {steps:[{svc|wasm, code|in_text, ms, mb}…], in|in_text, wait, mb} / pipe{} -> q… running|done N/N ms= out=<hash> + final stdout indented
Each step's output is the next step's input; a step with code gets the {code,stdin} interpreter framing. GET /v1/pipe/{id}?wait=&step=&raw=1&att=1 / pipeg{id,wait,step} status, a step output, raw bytes, or the signed pipe1 line.
A failed step fails the pipe with its index and keeps partial outs. The pipe counts as 8 jobs/day against caps; donors see every step's input, so never pipe secrets.`
