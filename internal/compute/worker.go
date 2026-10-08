package compute

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/trust"
)

// leaseIn is the donor's offer (14.4, 27.6). A v1 donor (ver < 2, no caps) keeps the v1 contract:
// it runs every public module up to 4 MiB, including modules under probation and L0 submitters,
// and never receives a pinned module. A ver 2 donor negotiates: pin (its pins list), new (modules
// with runs_ok < 3), l0 (L0 submitters).
type leaseIn struct {
	MaxMs int      `json:"max_ms"`
	MaxMb int      `json:"max_mb"`
	Ver   int      `json:"ver"`
	Caps  []string `json:"caps"`
	Pins  []string `json:"pins"`
	// Lanes the donor offers to serve (e.g. public, own). Lane routing is enforced server-side by
	// the root/lane rules in tryLease, so this is accepted (a ver-2 donor sends it) but advisory;
	// without this field the strict JSON decoder rejects the donor's offer with 400.
	Lanes []string `json:"lanes,omitempty"`
}

func (in leaseIn) has(c string) bool {
	for _, x := range in.Caps {
		if x == c {
			return true
		}
	}
	return false
}

type leaseOut struct {
	Lease    string `json:"lease"`
	Job      string `json:"job"`
	Wasm     string `json:"wasm"`
	In       string `json:"in"`
	FS       string `json:"fs,omitempty"`
	Ms       int    `json:"ms"`
	Mb       int    `json:"mb"`
	Lane     string `json:"lane,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Deadline int64  `json:"deadline"`
	Upgrade  string `json:"upgrade,omitempty"`
	Sunset   string `json:"sunset,omitempty"`
}

// codeVal accepts the v1 integer exit code or, with status error, a short code word such as
// "compile-timeout" (27.6).
type codeVal struct {
	n int
	s string
}

func (c *codeVal) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if len(s) > 32 || !sign.OneLine(s) {
			return errors.New("code word too long")
		}
		c.s = s
		return nil
	}
	return json.Unmarshal(b, &c.n)
}

// diagIn is the donor's failure diagnostics (27.6), stored in replicas.diag, never fingerprinted.
type diagIn struct {
	Stderr    string `json:"stderr,omitempty"` // base64 of the stderr tail (<= 4 KiB decoded)
	Trace     string `json:"trace,omitempty"`  // <= 2 KiB
	CompileMs int    `json:"compile_ms,omitempty"`
	MemPages  int    `json:"mem_pages,omitempty"`
}

type doneIn struct {
	Lease  string  `json:"lease"`
	Status string  `json:"status"`
	Out    string  `json:"out"`
	Code   codeVal `json:"code"`
	Ms     int     `json:"ms"`
	Diag   *diagIn `json:"diag"`
	Dsig   string  `json:"dsig"` // base64url ed25519 over dsigMessage (27.6)
}

var statuses = map[string]bool{"ok": true, "exit": true, "timeout": true, "oom": true, "error": true}

const (
	maxStderr = 4 << 10
	maxTrace  = 2 << 10
	// dsigDomain prefixes the donor-signed message: "cx-dsig-v1\0" || job || "\0" || lease || "\0" || fingerprint.
	dsigDomain = "cx-dsig-v1\x00"
)

func dsigMessage(job, lease, fp string) []byte {
	return []byte(dsigDomain + job + "\x00" + lease + "\x00" + fp)
}

func newLease() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "l" + base64.RawURLEncoding.EncodeToString(b[:])
}

// elig is the eligibility of a queued replica for a donor (14.4, 27.6): $1 max_ms, $2 max_mb,
// $3 donor root, $4 ALLOW_SAME_ROOT, $5 pins, $6 donor trusted, $7 accepts new modules, $8 accepts
// L0 submitters. Lane own inverts the root rule; lane trusted and audit jobs go to trusted donors.
const elig = ` FROM replicas r JOIN jobs j ON j.id = r.job LEFT JOIN blob_meta bm ON bm.hash = j.wasm
	WHERE r.state = 'queued' AND j.status IN ('queued','running')
	  AND j.ms <= $1 AND j.mb <= $2
	  AND (j.wasm_size <= 4194304 OR j.wasm = ANY($5::text[]))
	  AND (j.kind <> 'audit' OR $6::bool)
	  AND CASE j.lane
	        WHEN 'own' THEN j.root = $3
	        WHEN 'trusted' THEN $6::bool AND j.root <> $3
	        ELSE j.root <> $3 AND NOT ($3 = ANY(r.excluded_roots))
	          AND ($4::bool OR NOT EXISTS (SELECT 1 FROM replicas o WHERE o.job = r.job AND o.id <> r.id AND o.worker_root = $3))
	          AND (coalesce(bm.runs_ok, 0) >= 3 OR $7::bool) AND (j.sub_lvl >= 1 OR $8::bool)
	      END`

// tryLease hands one eligible queued replica to the worker, or nil. Candidates are the
// oldest leaseWindow queued replicas (own-lane first: a separate queue); one is picked at random
// and locked (SKIP LOCKED), so a colluding pair cannot predictably take both replicas of a job
// (review #1). A root holding maxLeases live leases gets nothing (review #7).
func (s *svc) tryLease(ctx context.Context, id *core.Ident, in leaseIn) (*leaseOut, error) {
	var live int
	var trusted bool
	if err := s.d.DB.QueryRow(ctx, `SELECT (SELECT count(*) FROM replicas WHERE worker_root = $1 AND state = 'leased' AND deadline > now()),
		coalesce((SELECT trusted FROM identities WHERE id = $1), false)`, id.Root).Scan(&live, &trusted); err != nil {
		return nil, err
	}
	s.stats.seen(id.Root, in, maxLeases-live)
	if live >= maxLeases {
		return nil, nil
	}
	legacy := in.Ver < leaseVer
	pins := []string{}
	if !legacy && in.has("pin") {
		pins = in.Pins
	}
	args := []any{in.MaxMs, in.MaxMb, id.Root, s.d.Cfg.AllowSameRoot, pins, trusted, legacy || in.has("new"), legacy || in.has("l0")}
	own, pub, err := scanCandidates(s.d.DB.Query(ctx, `SELECT r.id, j.lane = 'own'`+elig+` ORDER BY (j.lane <> 'own'), r.created, r.id LIMIT `+strconv.Itoa(leaseWindow), args...))
	if err != nil || len(own)+len(pub) == 0 {
		return nil, err
	}
	// Own-lane replicas (the submitter's own donor) are served first; the public window is shuffled.
	mrand.Shuffle(len(pub), func(i, j int) { pub[i], pub[j] = pub[j], pub[i] })
	for _, rid := range append(own, pub...) {
		var out *leaseOut
		err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			var o leaseOut
			err := tx.QueryRow(ctx, `SELECT r.job, j.wasm, j.input, j.fs, j.ms, j.mb, j.lane, j.kind`+elig+` AND r.id = $9 FOR UPDATE OF r SKIP LOCKED`,
				append(args, rid)...).Scan(&o.Job, &o.Wasm, &o.In, &o.FS, &o.Ms, &o.Mb, &o.Lane, &o.Kind)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // taken meanwhile
			}
			if err != nil {
				return err
			}
			o.Lease = newLease()
			dl := time.Now().Add(time.Duration(2*o.Ms)*time.Millisecond + 60*time.Second)
			o.Deadline = dl.Unix()
			if _, err := tx.Exec(ctx, `UPDATE replicas SET state = 'leased', lease = $2, worker = $3, worker_root = $4, deadline = $5, leased_at = now() WHERE id = $1`,
				rid, o.Lease, id.ID, id.Root, dl); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE jobs SET status = 'running' WHERE id = $1 AND status = 'queued'`, o.Job); err != nil {
				return err
			}
			if o.Lane == "public" {
				o.Lane = ""
			}
			if o.Kind == "job" {
				o.Kind = ""
			}
			if legacy {
				o.Upgrade, o.Sunset = s.d.Cfg.PublicURL+"/wasm#cxw", leaseSunset
			}
			out = &o
			return nil
		})
		if err != nil || out != nil {
			return out, err
		}
	}
	return nil, nil
}

// scanCandidates splits the candidate replicas into own-lane and public ids.
func scanCandidates(rows pgx.Rows, err error) (own, pub []int64, _ error) {
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var isOwn bool
		if err := rows.Scan(&id, &isOwn); err != nil {
			return nil, nil, err
		}
		if isOwn {
			own = append(own, id)
		} else {
			pub = append(pub, id)
		}
	}
	return own, pub, rows.Err()
}

func scanInts(rows pgx.Rows, err error) ([]int64, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// lease long-polls up to wait seconds for an eligible replica; (nil, nil) when none.
func (s *svc) lease(ctx context.Context, id *core.Ident, in leaseIn, wait int) (*leaseOut, error) {
	if in.MaxMs <= 0 || in.MaxMs > maxMs {
		in.MaxMs = maxMs
	}
	if in.MaxMb <= 0 || in.MaxMb > maxMb {
		in.MaxMb = maxMb
	}
	if len(in.Pins) > maxPins {
		return nil, core.Bad(fmt.Sprintf("pins: at most %d hashes", maxPins))
	}
	for _, p := range in.Pins {
		if !hashRe.MatchString(p) {
			return nil, core.Bad("pins must be sha256 hex")
		}
	}
	if len(in.Caps) > 16 {
		return nil, core.Bad("caps: too many")
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		c, cancel := s.d.Notify.Subscribe("lease")
		o, err := s.tryLease(ctx, id, in)
		rem := time.Until(deadline)
		if err != nil || o != nil || rem <= 0 {
			cancel()
			return o, err
		}
		t := time.NewTimer(rem)
		select {
		case <-c:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return nil, nil
		case <-t.C:
		}
		t.Stop()
		cancel()
	}
}

type jobRow struct {
	id, submitter, root, wasm, input, fs string
	lane, kind, svc, pipe, bounty, sub   string
	ms, mb                               int
	reserved                             int64
	status                               string
}

var errBadSig = errors.New("bad donor signature")

// done records a worker's report and runs consensus when enough replicas reported. A cancelled
// lease answers 410 (14.3); a bad donor signature is not a report: the lease goes back to the
// queue, excluded for that root (27.6).
func (s *svc) done(ctx context.Context, id *core.Ident, in doneIn) error {
	if in.Lease == "" || len(in.Lease) > 64 {
		return core.Bad("lease required")
	}
	if !statuses[in.Status] {
		return core.Bad("status must be ok|exit|timeout|oom|error")
	}
	if in.Status == "ok" || in.Status == "exit" {
		if !hashRe.MatchString(in.Out) {
			return core.Bad("out must be a sha256 hex for ok/exit")
		}
	} else {
		in.Out = ""
	}
	ecode := ""
	if in.Code.s != "" {
		if in.Status != "error" {
			return core.Bad("a code word needs status error")
		}
		ecode = in.Code.s
	}
	code := in.Code.n
	if in.Status != "exit" {
		code = 0 // code is only meaningful for exit; keeps fingerprints comparable
	}
	if in.Ms < 0 {
		in.Ms = 0
	}
	diag, err := cleanDiag(in.Diag, ecode)
	if err != nil {
		return err
	}
	var dsig []byte
	if in.Dsig != "" {
		if dsig, err = decodeB64(in.Dsig); err != nil || len(dsig) != ed25519.SignatureSize {
			return core.E(400, "badsig", "dsig must be a base64url ed25519 signature")
		}
	}
	fp := report{status: in.Status, code: code, out: in.Out}.fp()
	var j jobRow
	var finalized, tieBreak bool
	var woken []string
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var rid int64
		var dl *time.Time
		var state string
		var pub []byte
		err := tx.QueryRow(ctx, `SELECT r.id, r.state, r.deadline, j.id, j.status, j.ms, j.mb, j.reserved, j.submitter, j.root, j.wasm, j.input, j.fs, j.lane, j.kind, j.svc, j.pipe, j.bounty, j.sub,
				(SELECT pub FROM identities WHERE id = $3)
			FROM replicas r JOIN jobs j ON j.id = r.job
			WHERE r.lease = $1 AND r.worker = $2 AND r.state IN ('leased', 'cancelled') FOR UPDATE OF r, j`, in.Lease, id.ID, id.Root).
			Scan(&rid, &state, &dl, &j.id, &j.status, &j.ms, &j.mb, &j.reserved, &j.submitter, &j.root, &j.wasm, &j.input, &j.fs, &j.lane, &j.kind, &j.svc, &j.pipe, &j.bounty, &j.sub, &pub)
		if errors.Is(err, pgx.ErrNoRows) {
			return core.E(404, "notfound", "lease")
		}
		if err != nil {
			return err
		}
		if state == "cancelled" {
			return core.E(410, "gone", "job cancelled")
		}
		if dl == nil || dl.Before(time.Now()) {
			return core.E(409, "taken", "lease expired")
		}
		if dsig != nil && (len(pub) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(pub), dsigMessage(j.id, in.Lease, fp), dsig)) {
			return errBadSig
		}
		if in.Out != "" {
			if _, ok, err := blobSize(ctx, tx, in.Out); err != nil {
				return err
			} else if !ok {
				return core.E(404, "notfound", "out blob not uploaded")
			}
			// Outputs never count against the worker's quota: hand them to the submitter root (review #4a).
			if _, err := tx.Exec(ctx, `UPDATE blobs SET owner_root = $2 WHERE hash = $1 AND owner_root = $3`, in.Out, j.root, id.Root); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE blobs SET used_at = coalesce(used_at, now()) WHERE hash = $1`, in.Out); err != nil {
				return err
			}
		}
		if in.Ms > j.ms {
			in.Ms = j.ms
		}
		if _, err := tx.Exec(ctx, `UPDATE replicas SET state = 'reported', status = $2, code = $3, out = $4, ms = $5, reported_at = now(), deadline = NULL, diag = $6, dsig = $7 WHERE id = $1`,
			rid, in.Status, code, in.Out, in.Ms, diag, dsig); err != nil {
			return err
		}
		if err := s.recordDiag(ctx, tx, &j, id.Root, in.Diag, ecode, &woken); err != nil {
			return err
		}
		if j.status != "queued" && j.status != "running" || slices.Contains(woken, j.id) {
			return nil // late report on a finished job (or one this report just banned): recorded, not paid
		}
		finalized, tieBreak, err = s.consensus(ctx, tx, &j)
		return err
	})
	if errors.Is(err, errBadSig) {
		if rerr := s.requeueLease(ctx, in.Lease, id.ID, id.Root); rerr != nil {
			return rerr
		}
		return core.E(400, "badsig", "dsig does not verify against the root's registered pub (lease requeued)")
	}
	if err != nil {
		return err
	}
	for _, w := range woken {
		s.d.Notify.Wake("job:" + w)
	}
	if finalized {
		s.d.Notify.Wake("job:" + j.id)
	}
	if tieBreak || len(woken) > 0 {
		s.d.Notify.Wake("lease")
	}
	return nil
}

// requeueLease puts a leased replica back in the queue, never again for that root.
func (s *svc) requeueLease(ctx context.Context, lease, worker, root string) error {
	_, err := s.d.DB.Exec(ctx, `UPDATE replicas SET state = 'queued', lease = NULL, worker = NULL, worker_root = NULL, deadline = NULL, leased_at = NULL,
		excluded_roots = array_append(excluded_roots, $3) WHERE lease = $1 AND worker = $2 AND state = 'leased'`, lease, worker, root)
	if err == nil {
		s.d.Notify.Wake("lease")
	}
	return err
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	if len(s) > 2048 {
		return nil, errors.New("too long")
	}
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// cleanDiag bounds the diagnostics and renders the stored JSON (nil when nothing to store).
func cleanDiag(d *diagIn, ecode string) ([]byte, error) {
	if d == nil && ecode == "" {
		return nil, nil
	}
	out := map[string]any{}
	if ecode != "" {
		out["code"] = ecode
	}
	if d != nil {
		if d.Stderr != "" {
			raw, err := decodeB64(d.Stderr)
			if err != nil || len(raw) > maxStderr {
				return nil, core.Bad("diag.stderr must be base64 of at most 4 KiB")
			}
			out["stderr"] = base64.RawURLEncoding.EncodeToString(raw)
		}
		if d.Trace != "" {
			if len(d.Trace) > maxTrace {
				return nil, core.Bad("diag.trace over 2 KiB")
			}
			out["trace"] = strings.ToValidUTF8(d.Trace, "?")
		}
		if d.CompileMs < 0 || d.CompileMs > 600_000 || d.MemPages < 0 || d.MemPages > 65536 {
			return nil, core.Bad("diag.compile_ms / mem_pages out of range")
		}
		if d.CompileMs > 0 {
			out["compile_ms"] = d.CompileMs
		}
		if d.MemPages > 0 {
			out["mem_pages"] = d.MemPages
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return json.Marshal(out)
}

// recordDiag feeds the module's compile/memory samples and the compile-timeout counter (27.6):
// bombDonors distinct donor roots reporting compile-timeout ban the module (compile-bomb), cancel
// its queued jobs with refund and leave a revocation line.
func (s *svc) recordDiag(ctx context.Context, tx pgx.Tx, j *jobRow, root string, d *diagIn, ecode string, woken *[]string) error {
	if d != nil && (d.CompileMs > 0 || d.MemPages > 0) {
		if _, err := tx.Exec(ctx, `UPDATE blob_meta SET
			compile_ms = CASE WHEN $2 > 0 THEN (array_append(compile_ms, $2::int))[GREATEST(1, cardinality(compile_ms) - 14):cardinality(compile_ms) + 1] ELSE compile_ms END,
			mem_pages = CASE WHEN $3 > 0 THEN (array_append(mem_pages, $3::int))[GREATEST(1, cardinality(mem_pages) - 14):cardinality(mem_pages) + 1] ELSE mem_pages END
			WHERE hash = $1`, j.wasm, d.CompileMs, d.MemPages); err != nil {
			return err
		}
	}
	if ecode != "compile-timeout" {
		return nil
	}
	var donors int
	var banned string
	err := tx.QueryRow(ctx, `UPDATE blob_meta SET compile_timeouts = compile_timeouts + 1,
			ct_roots = CASE WHEN $2 = ANY(ct_roots) OR cardinality(ct_roots) >= 64 THEN ct_roots ELSE array_append(ct_roots, $2) END
		WHERE hash = $1 RETURNING cardinality(ct_roots), banned`, j.wasm, root).Scan(&donors, &banned)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil || donors < bombDonors || banned != "" {
		return err
	}
	ids, err := s.banModule(ctx, tx, j.wasm, "compile-bomb")
	*woken = append(*woken, ids...)
	return err
}

// banModule marks a module banned, cancels its active jobs with refund and records the
// revocation (RevokeFn, else an ops event).
func (s *svc) banModule(ctx context.Context, tx pgx.Tx, wasm, reason string) ([]string, error) {
	if _, err := tx.Exec(ctx, `UPDATE blob_meta SET banned = $2 WHERE hash = $1`, wasm, reason); err != nil {
		return nil, err
	}
	ids, err := cancelJobs(ctx, tx, `wasm = $2`, reason, true, wasm)
	if err != nil {
		return nil, err
	}
	if RevokeFn != nil {
		return ids, RevokeFn(ctx, tx, wasm, "", reason)
	}
	return ids, core.Event(ctx, tx, "ops", wasm, "", "compute: module "+wasm[:12]+" banned "+reason)
}

type report struct {
	root, status, out string
	code, ms          int
	signed            bool
}

func (r report) fp() string { return r.status + ":" + strconv.Itoa(r.code) + ":" + r.out }

func (r report) completed() bool { return r.status == "ok" || r.status == "exit" }

// consensus applies the SPEC rules over the job's reported replicas: 2 agreeing fingerprints
// (1 for single-replica lanes and audits), a third replica on a 2-way split, noconsensus at 3.
func (s *svc) consensus(ctx context.Context, tx pgx.Tx, j *jobRow) (finalized, tieBreak bool, err error) {
	rows, err := tx.Query(ctx, `SELECT worker_root, status, code, coalesce(out, ''), coalesce(ms, 0), dsig IS NOT NULL
		FROM replicas WHERE job = $1 AND state = 'reported' ORDER BY reported_at, id`, j.id)
	if err != nil {
		return false, false, err
	}
	var reps []report
	for rows.Next() {
		var r report
		if err := rows.Scan(&r.root, &r.status, &r.code, &r.out, &r.ms, &r.signed); err != nil {
			rows.Close()
			return false, false, err
		}
		reps = append(reps, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, false, err
	}
	var total int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM replicas WHERE job = $1`, j.id).Scan(&total); err != nil {
		return false, false, err
	}
	need := 2
	if total == 1 {
		need = 1
	}
	if len(reps) < need {
		return false, false, nil
	}
	groups := map[string][]int{}
	for i, r := range reps {
		groups[r.fp()] = append(groups[r.fp()], i)
	}
	for fp, idx := range groups {
		if len(idx) >= need {
			return true, false, s.finalize(ctx, tx, j, reps, fp)
		}
	}
	if len(reps) == 2 && total == 2 {
		_, err := tx.Exec(ctx, `INSERT INTO replicas (job) VALUES ($1)`, j.id)
		return false, true, err
	}
	if len(reps) >= 3 {
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status = 'failed', reason = 'noconsensus', finished_at = now() WHERE id = $1`, j.id); err != nil {
			return false, false, err
		}
		return true, false, core.Refund(ctx, tx, j.submitter, j.reserved)
	}
	return false, false, nil
}

// finalize settles a job on the majority fingerprint: job state, worker credits/rep, submitter
// charge, the signed att1 receipt, the cache scope and the hooks.
//
// Economics (review #1): the submitter pays max(used_s, 1) per replica run (capped by the
// reservation); agreeing workers are paid out of that charge only (never minted):
// min(used_s+1, charge/agreeing) each. Agreed `error` earns nothing (cheap to fake), and so
// does an agreed timeout/oom reported under minPaidMs. Lane own charges nothing and pays nothing
// (the donor is the submitter); lane trusted charges 2x one replica to its single trusted donor.
//
// Rep (4.2): +1 per agreeing worker only for a distinct replication (trust.Distinct over the
// submitter and the agreeing roots) whose submitter root is L2+, once per (worker, submitter)
// pair per day, cap workRepCap/day. Penalty (review #4b): rep -5 only for a completed (ok/exit)
// minority outvoted by a completed majority with a different out/code; timeout-vs-completed and
// timeout-vs-oom splits are wall-clock dependent and never penalised.
func (s *svc) finalize(ctx context.Context, tx pgx.Tx, j *jobRow, reps []report, winFP string) error {
	var win report
	var agree []report
	usedMs := 0
	for _, r := range reps {
		if r.fp() == winFP {
			win = r
			agree = append(agree, r)
			if r.ms > usedMs {
				usedMs = r.ms
			}
		}
	}
	if usedMs > j.ms {
		usedMs = j.ms
	}
	usedS := int64((usedMs + 999) / 1000)
	charge := max(usedS, 1) * int64(len(reps))
	switch j.lane {
	case "own":
		charge = 0
	case "trusted":
		charge = max(usedS, 1) * 2
	}
	if charge > j.reserved {
		charge = j.reserved
	}
	var pay int64
	if charge > 0 {
		pay = min(usedS+1, charge/int64(len(agree)))
	}
	paid := win.status != "error" && j.lane != "own"
	roots := make([]string, 0, len(agree))
	for _, r := range agree {
		roots = append(roots, r.root)
	}
	trustedRoots, err := trustedOf(ctx, tx, roots)
	if err != nil {
		return err
	}
	distinct := false
	switch j.lane {
	case "own":
	case "trusted":
		distinct = true
	default:
		if distinct, err = trust.Distinct(ctx, tx, append([]string{j.root}, roots...)...); err != nil {
			return err
		}
		if !distinct && j.root == core.SystemID && j.kind == "kat" && len(trustedRoots) > 0 {
			distinct = true // 14.5: a trusted donor counts as d=1 for the system root's KATs
		}
		// 27.6: svcget's janitor orders a service precompute as the system root (kind "job", with the
		// service ref in svc) precisely so svcget can serve it, and svcget serves only global att_d
		// cache hits. The system root has no super-group, so the submitter-inclusive Distinct above is
		// always false; the consensus that matters here is a 2-replica agreement across distinct donor
		// super-groups. Count that as d=1 (and globalise it below), else the precompute is wasted.
		if !distinct && j.root == core.SystemID && j.kind == "job" && j.svc != "" && len(roots) >= 2 {
			if distinct, err = trust.Distinct(ctx, tx, roots...); err != nil {
				return err
			}
		}
	}
	scope := "root"
	if j.lane != "trusted" && distinct {
		for _, r := range roots {
			if trustedRoots[r] || core.Level(ctx, tx, r) >= 3 {
				scope = "global"
				break
			}
		}
		if scope == "root" && j.root == core.SystemID && j.kind == "job" && j.svc != "" {
			scope = "global" // 27.6: a distinct system service-precompute is served to everyone
		}
	}
	status, reason, out := "failed", win.status, ""
	if win.completed() {
		status, reason, out = "done", "", win.out
		if _, err := tx.Exec(ctx, `UPDATE blobs SET last_ref = now() WHERE hash = $1`, win.out); err != nil {
			return err
		}
	}
	att, sig := s.attest(j, win, len(agree), len(reps), distinct, signedCount(agree))
	if _, err := tx.Exec(ctx, `UPDATE jobs SET status = $2, reason = $3, out = $4, used_ms = $5, code = $6, finished_at = now(),
			att = $7, att_sig = $8, att_d = $9, cache_scope = $10, charged = $11 WHERE id = $1`,
		j.id, status, reason, out, usedMs, win.code, att, sig, distinct, scope, charge); err != nil {
		return err
	}
	subLvl := -1
	var totalPaid int64
	for _, r := range reps {
		if r.fp() != winFP {
			if win.completed() && r.completed() {
				if _, err := core.AddRep(ctx, tx, r.root, -5, "", 0); err != nil {
					return err
				}
			}
			continue
		}
		if win.completed() && j.lane != "own" {
			if _, err := tx.Exec(ctx, `UPDATE blob_meta SET runs_ok = runs_ok + 1, ok_roots = array_append(ok_roots, $2)
				WHERE hash = $1 AND NOT ($2 = ANY(ok_roots)) AND cardinality(ok_roots) < 64`, j.wasm, r.root); err != nil {
				return err
			}
		}
		if !paid || (!r.completed() && r.ms < minPaidMs) {
			continue
		}
		if err := core.Earn(ctx, tx, r.root, pay); err != nil {
			return err
		}
		totalPaid += pay
		if !distinct || j.lane != "public" {
			continue
		}
		if subLvl < 0 {
			subLvl = core.Level(ctx, tx, j.root)
		}
		if subLvl < 2 {
			continue
		}
		n, err := bumpDaily(ctx, tx, r.root, "rep:pair:"+j.root, 1)
		if err != nil {
			return err
		}
		if n > 1 {
			continue // one rep per (worker, submitter) pair per day
		}
		if _, err := core.AddRep(ctx, tx, r.root, 1, "rep:work", workRepCap); err != nil {
			return err
		}
	}
	// The charge is held credits that must fully leave the system: workers were paid totalPaid out
	// of it (all-agree public), but the agreed-error charge (totalPaid=0), the 3-replica rounding
	// dust and the trusted-lane usedS-1 remainder are never paid out. Burn that remainder so Delta
	// stays zero and the hold pseudo-id does not accrue a permanent, economy-freezing leak.
	if rem := charge - totalPaid; rem > 0 {
		if err := core.BurnHeld(ctx, tx, rem, "compute", j.id); err != nil {
			return err
		}
	}
	if err := core.Refund(ctx, tx, j.submitter, j.reserved-charge); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM replicas WHERE job = $1 AND state = 'queued'`, j.id); err != nil {
		return err
	}
	if status == "done" && distinct && j.lane != "own" && CacheJobFn != nil {
		if err := CacheJobFn(ctx, tx, cacheKey(j.wasm, j.input, j.fs), j.id, out, int(charge)); err != nil {
			s.d.Log.Warn("compute cache hook", "job", j.id, "err", err)
		}
	}
	if OnDone != nil {
		job := &Job{ID: j.id, Submitter: j.submitter, Root: j.root, Wasm: j.wasm, Input: j.input, FS: j.fs, Out: out, Status: status, Reason: reason,
			Svc: j.svc, Kind: j.kind, Lane: j.lane, Pipe: j.pipe, Bounty: j.bounty, Sub: j.sub, Ms: j.ms, Mb: j.mb, UsedMs: usedMs, Code: win.code,
			Reserved: j.reserved, Charged: charge, AttD: distinct, CacheScope: scope}
		if err := OnDone(ctx, tx, job); err != nil {
			s.d.Log.Warn("compute done hook", "job", j.id, "err", err)
		}
	}
	return nil
}

func signedCount(agree []report) int {
	n := 0
	for _, r := range agree {
		if r.signed {
			n++
		}
	}
	return n
}

// attest builds and signs the att1 receipt line (14.2, 27.6): a replication receipt observed by
// the gateway, not a cryptographic proof of execution. Timing splits are never attested as
// disagreement (n counts agreeing fingerprints only).
func (s *svc) attest(j *jobRow, win report, agree, reported int, distinct bool, ds int) (line, sig string) {
	if s.signer == nil {
		return "", ""
	}
	out := win.out
	if out == "" {
		out = "-"
	}
	kv := []sign.KV{{K: "j", V: j.id}, {K: "w", V: j.wasm}, {K: "i", V: j.input}, {K: "o", V: out}, {K: "s", V: win.status},
		{K: "c", V: strconv.Itoa(win.code)}, {K: "n", V: fmt.Sprintf("%d/%d", agree, reported)}, {K: "d", V: strconv.Itoa(b2i(distinct))},
		{K: "t", V: strconv.FormatInt(time.Now().Unix(), 10)}, {K: "k", V: strconv.Itoa(s.signer.KID())}}
	if j.lane != "public" {
		kv = append(kv, sign.KV{K: "lane", V: j.lane})
	}
	if ds > 0 {
		kv = append(kv, sign.KV{K: "ds", V: strconv.Itoa(ds)})
	}
	if j.fs != "" {
		kv = append(kv, sign.KV{K: "f", V: j.fs})
	}
	line = sign.Canonical("att1", kv...)
	return line, s.signer.Sign("att1", line)
}

func b2i(v bool) int {
	if v {
		return 1
	}
	return 0
}

// trustedOf returns the operator-trusted roots among roots (identities.trusted, 14.5).
func trustedOf(ctx context.Context, q core.Q, roots []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(roots) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT id FROM identities WHERE id = ANY($1) AND trusted`, roots)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func (s *svc) hLease(w http.ResponseWriter, r *http.Request) {
	id, err := s.authCompute(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	wait, err := waitParam(r, maxLeaseAit)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in leaseIn
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	o, err := s.lease(r.Context(), id, in, wait)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if o == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	core.JSON(w, 200, o)
}

func (s *svc) hDone(w http.ResponseWriter, r *http.Request) {
	id, err := s.authCompute(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in doneIn
	if err := core.Decode(w, r, 16<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	if err := s.done(r.Context(), id, in); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.JSON(w, 200, map[string]bool{"ok": true})
}
