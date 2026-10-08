package compute

// Audits by an operator-trusted donor (SPEC-v2 14.5). The compute_audit janitor re-runs, as
// kind='audit' jobs of the system root that only trusted donors may lease, every priority audit a
// cross-root cache hit asked for (14.1, audit_queue) and an hourly 1 % sample of the day's
// finalised public jobs (10x for jobs whose donors the collusion query flags). A match records
// the audit and makes the result global (14.1 b); a mismatch revokes the (wasm, input) pair:
// rep -10 for the donors that agreed (unless the module is flagged nondeterministic), a line in
// /att/revoked.txt, cache rows purged, a sys mail to the submitter and an ops event. The collusion
// graph is listed in /admin/stats; nothing here bans anyone.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/mail"
)

const (
	auditRate        = 0.01 // share of the window's finalised jobs re-run per hourly pass
	auditOversample  = 10   // factor for jobs whose agreeing donors form a flagged pair
	auditMaxPerHour  = 50   // sampled audits per pass; the priority queue is served first
	auditQueueMax    = 200  // priority audits per pass (the system budget bounds the rest)
	auditRetries     = 3    // audits of one job (inconclusive runs may be retried, settled ones never)
	auditEvery       = time.Hour
	auditWindow      = 24 * time.Hour // jobs finalised earlier are never sampled
	auditSettleBatch = 100
	auditKeepDays    = 365 // audits and revoked rows (14.6: revoked.txt entries kept 1 y)
	auditRepPenalty  = -10
	auditNotifyMax   = 20 // roots served from the revoked cache that get the sys mail
	revokedListMax   = 10000
	maxReason        = 64
	collusionMinJobs = 50
	collusionShare   = 0.8
	collusionMax     = 100 // pairs listed in /admin/stats
	reasonMismatch   = "audit-mismatch"
)

// RegisterAudit installs the audit seams (RevokedFn, RevokedListFn, PriorityAuditFn, RevokeFn,
// core.CollusionFn) and the compute_audit janitor task. Register (P13) runs on the same Deps first.
func RegisterAudit(d *core.Deps) { svcFor(d).registerAudit() }

func (s *svc) registerAudit() {
	RevokedFn = revokedPair
	RevokedListFn = revokedLines
	PriorityAuditFn = enqueuePriorityAudit
	RevokeFn = recordRevocation
	core.CollusionFn = collusionLines
	s.d.Janitor.Add("compute_audit", s.auditTick)
}

// cleanReason bounds a revocation/queue reason to one short line (it lands in revoked.txt).
func cleanReason(r string) string {
	r = strings.TrimSpace(doc.SafeLine(r))
	if len(r) > maxReason {
		r = strings.ToValidUTF8(r[:maxReason], "")
	}
	if r == "" {
		return "revoked"
	}
	return r
}

// --- seams ------------------------------------------------------------------------------------------

// revokedPair is RevokedFn: the pair, or its whole module, is on the revoked list.
func revokedPair(ctx context.Context, q core.Q, wasm, input string) (bool, error) {
	var v bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM revoked WHERE wasm = $1 AND input IN ($2, ''))`, wasm, input).Scan(&v)
	return v, err
}

// enqueuePriorityAudit is PriorityAuditFn: a cross-root hit on a root-scoped result asks for a
// trusted re-run (14.1). One queue row per job; none while an audit is pending or settled.
func enqueuePriorityAudit(ctx context.Context, q core.Q, jobID, reason string) error {
	_, err := q.Exec(ctx, `INSERT INTO audit_queue (job, reason) SELECT $1, $2
		WHERE NOT EXISTS (SELECT 1 FROM audits WHERE job = $1 AND result <> 'inconclusive')
		ON CONFLICT (job) DO NOTHING`, jobID, cleanReason(reason))
	return err
}

// recordRevocation is RevokeFn: a module ban (input "") or a pair revocation decided elsewhere
// lands on the revoked list with an ops event (the same event banModule writes on its own).
func recordRevocation(ctx context.Context, q core.Q, wasm, input, reason string) error {
	reason = cleanReason(reason)
	if _, err := q.Exec(ctx, `INSERT INTO revoked (wasm, input, reason) VALUES ($1, $2, $3) ON CONFLICT (wasm, input) DO NOTHING`, wasm, input, reason); err != nil {
		return err
	}
	if input == "" {
		return core.Event(ctx, q, "ops", wasm, "", "compute: module "+short(wasm)+" banned "+reason)
	}
	return core.Event(ctx, q, "ops", wasm, "", "compute: result "+short(wasm)+"/"+short(input)+" revoked "+reason)
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// revokedLines is RevokedListFn: newest first, one line per revoked result or module.
func revokedLines(ctx context.Context, q core.Q) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT wasm, input, line, reason, job, at FROM revoked ORDER BY at DESC, wasm, input LIMIT $1`, revokedListMax)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var wasm, input, line, reason, job string
		var at time.Time
		if err := rows.Scan(&wasm, &input, &line, &reason, &job, &at); err != nil {
			return nil, err
		}
		out = append(out, revokedLine(wasm, input, line, reason, job, at))
	}
	return out, rows.Err()
}

// revokedLine renders one entry: the att1 receipt of the revoked job when it has one (14.5), else
// the pair (i=* for a whole module), then reason= and the revocation time.
func revokedLine(wasm, input, line, reason, job string, at time.Time) string {
	if line == "" {
		in := "*"
		if input != "" {
			in = input
		}
		line = "w=" + wasm + " i=" + in
		if job != "" {
			line += " j=" + job
		}
	}
	return line + " reason=" + reason + " at=" + at.UTC().Format(time.RFC3339)
}

// --- janitor ---------------------------------------------------------------------------------------

// auditTick settles the audits whose copies finished (every tick), then once per auditEvery
// serves the priority queue, samples the window and sweeps rows past auditKeepDays.
func (s *svc) auditTick(ctx context.Context) error {
	if err := s.settleAudits(ctx); err != nil {
		return err
	}
	since, due, err := auditDue(ctx, s.d.DB)
	if err != nil || !due {
		return err
	}
	if _, err := s.auditPass(ctx, since, auditRate, auditMaxPerHour); err != nil {
		return err
	}
	return auditSweep(ctx, s.d.DB)
}

// auditDue reports whether an hourly pass is due and moves the marker when it is. since is the
// window start: the previous pass, clipped to auditWindow (a first pass covers one hour).
func auditDue(ctx context.Context, q core.Q) (since time.Time, due bool, err error) {
	now := time.Now()
	var prev time.Time
	err = q.QueryRow(ctx, `SELECT last_at FROM audit_runs WHERE k = 'sample'`).Scan(&prev)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		since = now.Add(-auditEvery)
	case err != nil:
		return since, false, err
	case now.Sub(prev) < auditEvery:
		return since, false, nil
	default:
		since = prev
		if since.Before(now.Add(-auditWindow)) {
			since = now.Add(-auditWindow)
		}
	}
	_, err = q.Exec(ctx, `INSERT INTO audit_runs (k, last_at) VALUES ('sample', $1) ON CONFLICT (k) DO UPDATE SET last_at = EXCLUDED.last_at`, now)
	return since, true, err
}

// auditSweep drops audits and revoked rows past one year and queue rows whose job is gone.
func auditSweep(ctx context.Context, q core.Q) error {
	for _, tbl := range []string{"revoked", "audits"} {
		if _, err := q.Exec(ctx, `DELETE FROM `+tbl+` WHERE at < now() - make_interval(days => $1)`, auditKeepDays); err != nil {
			return err
		}
	}
	_, err := q.Exec(ctx, `DELETE FROM audit_queue WHERE NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = audit_queue.job)`)
	return err
}

// auditTarget is a finalised job an audit re-runs.
type auditTarget struct {
	id, wasm, input, fs string
	ms, mb              int
}

// auditPass submits the audits of one pass: the priority queue first (oldest first, up to
// auditQueueMax), then a random rate share of the public jobs finalised since the window start
// (auditOversample x for flagged donor pairs), at most limit. Nothing runs without a trusted donor
// registered, and an unfunded system root ends the pass (SystemSubmit left the ops event).
// Returns the number of audits submitted.
func (s *svc) auditPass(ctx context.Context, since time.Time, rate float64, limit int) (int, error) {
	var trusted bool
	if err := s.d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM identities WHERE trusted AND parent IS NULL AND revoked_at IS NULL)`).Scan(&trusted); err != nil || !trusted {
		return 0, err
	}
	n, err := s.auditQueue(ctx)
	if errors.Is(err, ErrUnfunded) {
		return n, nil
	}
	if err != nil {
		return n, err
	}
	pairs, err := CollusionPairs(ctx, s.d.DB)
	if err != nil {
		return n, err
	}
	pa, pb := make([]string, len(pairs)), make([]string, len(pairs))
	for i, p := range pairs {
		pa[i], pb[i] = p.A, p.B
	}
	rows, err := s.d.DB.Query(ctx, `WITH cand AS (
			SELECT j.id, j.wasm, j.input, j.fs, j.ms, j.mb, array_agg(r.worker_root) AS roots
			FROM jobs j JOIN replicas r ON r.job = j.id AND r.state = 'reported' AND coalesce(r.out, '') = j.out AND coalesce(r.code, 0) = j.code
			WHERE j.status = 'done' AND j.reason = '' AND j.cached_from = '' AND j.kind = 'job' AND j.lane = 'public'
			  AND j.finished_at >= $1 AND NOT (j.root = $2 AND j.svc = '')
			  AND NOT EXISTS (SELECT 1 FROM audits a WHERE a.job = j.id AND a.result <> 'inconclusive')
			  AND (SELECT count(*) FROM audits a WHERE a.job = j.id) < $3
			  AND NOT EXISTS (SELECT 1 FROM revoked v WHERE v.wasm = j.wasm AND v.input IN (j.input, ''))
			  AND EXISTS (SELECT 1 FROM blobs b WHERE b.hash = j.wasm) AND EXISTS (SELECT 1 FROM blobs b WHERE b.hash = j.input)
			GROUP BY j.id),
		scored AS (
			SELECT c.*, EXISTS (SELECT 1 FROM unnest($4::text[], $5::text[]) p(a, b) WHERE p.a = ANY(c.roots) AND p.b = ANY(c.roots)) AS flagged
			FROM cand c)
		SELECT id, wasm, input, fs, ms, mb FROM scored
		WHERE random() < $6::float8 * CASE WHEN flagged THEN $7::float8 ELSE 1 END
		ORDER BY flagged DESC, random() LIMIT $8`,
		since, core.SystemID, auditRetries, pa, pb, rate, float64(auditOversample), limit)
	if err != nil {
		return n, err
	}
	var targets []auditTarget
	for rows.Next() {
		var t auditTarget
		if err := rows.Scan(&t.id, &t.wasm, &t.input, &t.fs, &t.ms, &t.mb); err != nil {
			rows.Close()
			return n, err
		}
		targets = append(targets, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return n, err
	}
	for _, t := range targets {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		ok, err := s.auditOf(ctx, t, false, "sample")
		if errors.Is(err, ErrUnfunded) {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
}

// auditQueue serves the priority queue: every row whose job still exists and has no pending or
// settled audit gets a priority audit; the others are dropped. ErrUnfunded stops the pass with the
// remaining rows kept for the next one.
func (s *svc) auditQueue(ctx context.Context) (int, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT q.job, q.reason, coalesce(j.wasm, ''), coalesce(j.input, ''), coalesce(j.fs, ''), coalesce(j.ms, 0), coalesce(j.mb, 0),
			j.id IS NOT NULL AND j.status = 'done' AND j.reason = '' AND j.cached_from = '',
			EXISTS (SELECT 1 FROM audits a WHERE a.job = q.job AND a.result <> 'inconclusive') OR (SELECT count(*) FROM audits a WHERE a.job = q.job) >= $2
		FROM audit_queue q LEFT JOIN jobs j ON j.id = q.job ORDER BY q.at, q.job LIMIT $1`, auditQueueMax, auditRetries)
	if err != nil {
		return 0, err
	}
	type qrow struct {
		t             auditTarget
		reason        string
		live, settled bool
	}
	var qs []qrow
	for rows.Next() {
		var r qrow
		if err := rows.Scan(&r.t.id, &r.reason, &r.t.wasm, &r.t.input, &r.t.fs, &r.t.ms, &r.t.mb, &r.live, &r.settled); err != nil {
			rows.Close()
			return 0, err
		}
		qs = append(qs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, r := range qs {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		if r.live && !r.settled {
			ok, err := s.auditOf(ctx, r.t, true, r.reason)
			if err != nil {
				return n, err
			}
			if ok {
				n++
			}
		}
		if _, err := s.d.DB.Exec(ctx, `DELETE FROM audit_queue WHERE job = $1`, r.t.id); err != nil {
			return n, err
		}
	}
	return n, nil
}

// auditOf submits the kind='audit' copy of t (one replica, trusted donors only, never the donors
// that agreed on the result under audit, fresh: the cache would answer with that very result) and
// records the pending audits row. ErrUnfunded is returned as is (the row is dropped, the queue row
// kept by the caller); any other submit error (blobs gone, module banned) settles the audit as
// inconclusive so the job is not retried forever. ok reports a submitted audit.
func (s *svc) auditOf(ctx context.Context, t auditTarget, priority bool, reason string) (ok bool, err error) {
	var aid int64
	if err := s.d.DB.QueryRow(ctx, `INSERT INTO audits (job, priority, reason) VALUES ($1, $2, $3) RETURNING id`, t.id, priority, cleanReason(reason)).Scan(&aid); err != nil {
		return false, err
	}
	ids, err := SystemSubmit(ctx, s.d, []Spec{{Wasm: t.wasm, In: t.input, FS: t.fs, Ms: t.ms, Mb: t.mb, Fresh: true}}, "audit")
	if errors.Is(err, ErrUnfunded) {
		s.d.DB.Exec(ctx, `DELETE FROM audits WHERE id = $1`, aid)
		return false, err
	}
	if err != nil {
		var ae *core.APIError
		if !errors.As(err, &ae) {
			s.d.DB.Exec(ctx, `DELETE FROM audits WHERE id = $1`, aid)
			return false, err
		}
		_, err = s.d.DB.Exec(ctx, `UPDATE audits SET result = 'inconclusive', reason = $2, settled_at = now() WHERE id = $1`, aid, cleanReason("submit: "+ae.Error()))
		return false, err
	}
	return true, core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE audits SET audit = $2 WHERE id = $1`, aid, ids[0]); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE replicas SET excluded_roots = (SELECT coalesce(array_agg(DISTINCT r.worker_root), '{}') FROM replicas r JOIN jobs j ON j.id = r.job
				WHERE j.id = $2 AND r.state = 'reported' AND r.worker_root IS NOT NULL AND coalesce(r.out, '') = j.out AND coalesce(r.code, 0) = j.code)
			WHERE job = $1`, ids[0], t.id)
		return err
	})
}

// --- settlement -------------------------------------------------------------------------------------

type pendingAudit struct {
	id                  int64
	job, audit          string
	priority            bool
	status, reason, out string
	code                int
}

// settleAudits compares every finished audit copy with its job (batches of auditSettleBatch) and
// closes the audits left without a copy (a crash between the row and the submit, or a copy the
// 30-day retention removed) as inconclusive.
func (s *svc) settleAudits(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT a.id, a.job, a.audit, a.priority, x.status, x.reason, x.out, x.code
		FROM audits a JOIN jobs x ON x.id = a.audit
		WHERE a.result = 'pending' AND x.status IN ('done', 'failed') ORDER BY a.at, a.id LIMIT $1`, auditSettleBatch)
	if err != nil {
		return err
	}
	var ps []pendingAudit
	for rows.Next() {
		var p pendingAudit
		if err := rows.Scan(&p.id, &p.job, &p.audit, &p.priority, &p.status, &p.reason, &p.out, &p.code); err != nil {
			rows.Close()
			return err
		}
		ps = append(ps, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range ps {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error { return s.settleOne(ctx, tx, p) }); err != nil {
			return err
		}
	}
	_, err = s.d.DB.Exec(ctx, `UPDATE audits SET result = 'inconclusive', reason = 'lost', settled_at = now()
		WHERE result = 'pending' AND ((audit = '' AND at < now() - interval '1 hour') OR (audit <> '' AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id = audits.audit)))`)
	return err
}

// auditedJob is the job under audit as settlement reads it (locked for the transaction).
type auditedJob struct {
	id, submitter, root, status, wasm, input, out, att, scope string
	code                                                      int
}

// settleOne records one audit's result: inconclusive when the copy did not complete (a trusted
// donor's timeout, oom or error is never a disagreement, 14.2) or the job is gone; match when out
// and exit code agree (a root-scoped result becomes global, 14.1 b); else a mismatch revokes it.
func (s *svc) settleOne(ctx context.Context, tx pgx.Tx, p pendingAudit) error {
	var o auditedJob
	o.id = p.job
	err := tx.QueryRow(ctx, `SELECT submitter, root, status, wasm, input, out, code, att, cache_scope FROM jobs WHERE id = $1 FOR UPDATE`, p.job).
		Scan(&o.submitter, &o.root, &o.status, &o.wasm, &o.input, &o.out, &o.code, &o.att, &o.scope)
	result, detail := "inconclusive", ""
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		detail = "job gone"
	case err != nil:
		return err
	case p.status != "done":
		detail = "audit " + p.reason
	case o.status != "done" || o.scope == "revoked":
		detail = "job " + o.status + " " + o.scope
	case p.out == o.out && p.code == o.code:
		result = "match"
		if _, err := tx.Exec(ctx, `UPDATE jobs SET cache_scope = 'global' WHERE id = $1 AND cache_scope = 'root'`, o.id); err != nil {
			return err
		}
	default:
		result = "mismatch"
		if detail, err = s.revokeResult(ctx, tx, &o, p); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE audits SET result = $2, reason = $3, settled_at = now() WHERE id = $1 AND result = 'pending'`, p.id, result, cleanReason(detail))
	return err
}

// revokeResult applies the mismatch rules (14.5) to o inside the settlement transaction: rep -10
// for every donor that agreed on the revoked result (unless NondeterministicFn flags the module),
// the revoked row (the job's att1 line + reason), the job rows served from it deleted and their
// roots told, the job's cache_scope set to revoked, the 16.4 cache rows of the pair deleted, a
// sys mail to the submitter and an ops event. Mail failures are logged, never block a revocation.
func (s *svc) revokeResult(ctx context.Context, tx pgx.Tx, o *auditedJob, p pendingAudit) (string, error) {
	nondet := NondeterministicFn != nil && NondeterministicFn(ctx, tx, o.wasm)
	roots, err := scanStrings(tx.Query(ctx, `SELECT DISTINCT worker_root FROM replicas WHERE job = $1 AND state = 'reported' AND worker_root IS NOT NULL
		AND coalesce(out, '') = $2 AND coalesce(code, 0) = $3 ORDER BY worker_root`, o.id, o.out, o.code))
	if err != nil {
		return "", err
	}
	if !nondet {
		for _, r := range roots {
			if _, err := core.AddRep(ctx, tx, r, auditRepPenalty, "", 0); err != nil {
				return "", err
			}
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO revoked (wasm, input, line, reason, job) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (wasm, input) DO NOTHING`,
		o.wasm, o.input, o.att, reasonMismatch, o.id); err != nil {
		return "", err
	}
	// Roots served from the revoked result (14.1 hits) lose those rows and hear about it.
	served, err := tx.Query(ctx, `SELECT DISTINCT ON (root) id, root FROM jobs WHERE wasm = $1 AND input = $2 AND cached_from <> '' AND root <> $3 ORDER BY root, created LIMIT $4`,
		o.wasm, o.input, o.root, auditNotifyMax)
	if err != nil {
		return "", err
	}
	var notify [][2]string
	for served.Next() {
		var id, root string
		if err := served.Scan(&id, &root); err != nil {
			served.Close()
			return "", err
		}
		notify = append(notify, [2]string{id, root})
	}
	served.Close()
	if err := served.Err(); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM jobs WHERE wasm = $1 AND input = $2 AND cached_from <> ''`, o.wasm, o.input); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE jobs SET cache_scope = 'revoked' WHERE wasm = $1 AND input = $2 AND status = 'done' AND out = $3`, o.wasm, o.input, o.out); err != nil {
		return "", err
	}
	fss, err := scanStrings(tx.Query(ctx, `SELECT DISTINCT fs FROM jobs WHERE wasm = $1 AND input = $2`, o.wasm, o.input))
	if err != nil {
		return "", err
	}
	keys := []string{cacheKey(o.wasm, o.input, "")}
	for _, fs := range fss {
		if fs != "" {
			keys = append(keys, cacheKey(o.wasm, o.input, fs))
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM cache WHERE key = ANY($1)`, keys); err != nil {
		return "", err
	}
	detail := fmt.Sprintf("out %s vs %s donors %s", short(o.out), short(p.out), strings.Join(roots, ","))
	if nondet {
		detail += " nondeterministic"
	}
	text := fmt.Sprintf("A trusted re-execution (audit %s) of job %s (wasm %s, input %s) produced a different result. The result out=%s is revoked: it is no longer served from the cache and is listed on /att/revoked.txt. Resubmit the job for a fresh run.",
		p.audit, o.id, short(o.wasm), short(o.input), o.out)
	s.sysMail(ctx, tx, o.root, "job "+o.id+" result revoked by audit", text)
	for _, n := range notify {
		s.sysMail(ctx, tx, n[1], "job "+n[0]+" result revoked by audit", text+" Your job "+n[0]+" was served that result from the cache; its row was removed.")
	}
	return detail, core.Event(ctx, tx, "ops", "audit_mismatch", "", fmt.Sprintf("compute: audit %s of %s mismatch wasm=%s %s", p.audit, o.id, short(o.wasm), detail))
}

// sysMail delivers a system notice inside the transaction; a missing or revoked box is logged.
func (s *svc) sysMail(ctx context.Context, q core.Q, root, subject, text string) {
	if root == core.SystemID {
		return
	}
	if err := mail.SendSys(ctx, q, root, subject, text); err != nil {
		s.d.Log.Warn("compute audit mail", "root", root, "err", err)
	}
}

// --- collusion graph ------------------------------------------------------------------------------

// CollusionPair is an edge of the collusion graph (14.5): two donor roots that agreed on more
// than collusionMinJobs retained public jobs and either cover more than collusionShare of the
// smaller one's agreed jobs or registered from one super-group. Listed in /admin/stats, never
// acted on automatically; the sampler audits their jobs auditOversample times more often.
type CollusionPair struct {
	A, B               string
	Jobs, JobsA, JobsB int
	Share              float64
	SameNet            bool
}

// Line renders the pair for /admin/stats.
func (p CollusionPair) Line() string {
	l := fmt.Sprintf("%s %s jobs=%d share=%s", p.A, p.B, p.Jobs, strconv.FormatFloat(math.Round(p.Share*100)/100, 'f', -1, 64))
	if p.SameNet {
		l += " net=same"
	}
	return l
}

// CollusionPairs runs the collusion query over the retained jobs (30 d, 14.6): co-agreeing donor
// pairs above the job threshold that take over collusionShare of each other's agreed jobs or share
// a registration super-group, strongest first, at most collusionMax.
func CollusionPairs(ctx context.Context, q core.Q) ([]CollusionPair, error) {
	rows, err := q.Query(ctx, `WITH ag AS (
			SELECT r.job, r.worker_root AS root FROM replicas r JOIN jobs j ON j.id = r.job
			WHERE r.state = 'reported' AND r.worker_root IS NOT NULL AND j.status = 'done' AND j.kind = 'job' AND j.lane = 'public'
			  AND j.cached_from = '' AND coalesce(r.out, '') = j.out AND coalesce(r.code, 0) = j.code),
		pairs AS (
			SELECT a.root AS ra, b.root AS rb, count(*) AS n FROM ag a JOIN ag b ON b.job = a.job AND b.root > a.root
			GROUP BY a.root, b.root HAVING count(*) > $1),
		per AS (SELECT root, count(*) AS n FROM ag WHERE root IN (SELECT ra FROM pairs UNION SELECT rb FROM pairs) GROUP BY root)
		SELECT p.ra, p.rb, p.n, pa.n, pb.n, coalesce(ia.reg_ip, ''), coalesce(ib.reg_ip, '')
		FROM pairs p JOIN per pa ON pa.root = p.ra JOIN per pb ON pb.root = p.rb
		LEFT JOIN identities ia ON ia.id = p.ra LEFT JOIN identities ib ON ib.id = p.rb
		ORDER BY p.n DESC, p.ra, p.rb LIMIT $2`, collusionMinJobs, collusionMax)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CollusionPair
	for rows.Next() {
		var p CollusionPair
		var ipA, ipB string
		if err := rows.Scan(&p.A, &p.B, &p.Jobs, &p.JobsA, &p.JobsB, &ipA, &ipB); err != nil {
			return nil, err
		}
		p.Share = float64(p.Jobs) / float64(max(min(p.JobsA, p.JobsB), 1))
		p.SameNet = ipA != "" && ipB != "" && core.IPSuper(ipA) == core.IPSuper(ipB)
		if p.Share > collusionShare || p.SameNet {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

// collusionLines is core.CollusionFn: the flagged pairs as lines of /admin/stats.
func collusionLines(ctx context.Context, q core.Q) []string {
	pairs, err := CollusionPairs(ctx, q)
	if err != nil {
		return []string{"error " + doc.SafeLine(err.Error())}
	}
	lines := make([]string, 0, len(pairs))
	for _, p := range pairs {
		lines = append(lines, p.Line())
	}
	return lines
}
