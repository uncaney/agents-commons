package compute

// Acceptance tests of P45-compute-audit (SPEC-v2 14.5): trusted-only audit copies, priority
// audits that globalise the cache, mismatch handling and the collusion query.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
)

// newAuditEnv is newAttEnv plus the audit seams and janitor task, a funded system root and the
// seams restored afterwards (other tests of this package set and clear them on their own).
func newAuditEnv(t *testing.T) *env {
	t.Helper()
	e := newAttEnv(t)
	prevRevoked, prevList, prevPrio, prevRevoke, prevColl, prevNondet := RevokedFn, RevokedListFn, PriorityAuditFn, RevokeFn, core.CollusionFn, NondeterministicFn
	t.Cleanup(func() {
		RevokedFn, RevokedListFn, PriorityAuditFn, RevokeFn, core.CollusionFn, NondeterministicFn = prevRevoked, prevList, prevPrio, prevRevoke, prevColl, prevNondet
	})
	e.s.registerAudit()
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET credits = 100000 WHERE id = $1`, core.SystemID); err != nil {
		t.Fatal(err)
	}
	return e
}

// trustedDonor registers a donor root the operator trusts (POST /admin/trusted in production).
func (e *env) trustedDonor(name string) (id, tok string) {
	e.t.Helper()
	id, tok = e.register(name)
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET trusted = true WHERE id = $1`, id); err != nil {
		e.t.Fatal(err)
	}
	return id, tok
}

// auditRow is the audits row of a job: the audit copy's id and the result.
func (e *env) auditRow(job string) (audit, result string, priority bool) {
	e.t.Helper()
	err := testPool.QueryRow(context.Background(), `SELECT audit, result, priority FROM audits WHERE job = $1 ORDER BY id DESC LIMIT 1`, job).Scan(&audit, &result, &priority)
	if err != nil {
		e.t.Fatalf("audits row of %s: %v", job, err)
	}
	return
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

// runAudit submits this hour's audits: the priority queue, then every job of the last hour when
// rate is 1 (the janitor uses auditRate).
func (e *env) runAudit(rate float64) int {
	e.t.Helper()
	n, err := e.s.auditPass(context.Background(), time.Now().Add(-time.Hour), rate, auditMaxPerHour)
	if err != nil {
		e.t.Fatalf("auditPass: %v", err)
	}
	return n
}

func (e *env) settle() {
	e.t.Helper()
	if err := e.s.settleAudits(context.Background()); err != nil {
		e.t.Fatalf("settleAudits: %v", err)
	}
}

func TestAuditSamplingTrustedOnly(t *testing.T) {
	e := newAuditEnv(t)
	ctx := context.Background()
	sid, stok, wasm, in, w, wid := e.setup(2)
	jid, _ := e.agree(stok, w, wasm, in, []byte("sampled "+sid), 2000)
	if scope, _, _, _ := e.jobRow(jid); scope != "root" {
		t.Fatalf("scope before audit: %s", scope)
	}
	// Without a trusted donor registered nothing is sampled (no system credits burnt for a queue
	// nobody can lease).
	testPool.Exec(ctx, `UPDATE identities SET trusted = false WHERE trusted`)
	if n := e.runAudit(1); n != 0 || e.count(`SELECT count(*) FROM audits WHERE job = $1`, jid) != 0 {
		t.Fatalf("sampled without trusted donors: %d", n)
	}
	_, ttok := e.trustedDonor("trusted")
	if n := e.runAudit(1); n < 1 {
		t.Fatalf("sampled: %d", n)
	}
	aid, result, priority := e.auditRow(jid)
	if result != "pending" || priority || !core.ValidID(aid) {
		t.Fatalf("audits row: %s %s %v", aid, result, priority)
	}
	var kind, root, lane string
	var reps, replicasExcluded int
	var fresh bool
	if err := testPool.QueryRow(ctx, `SELECT j.kind, j.root, j.lane, j.cached_from = '', (SELECT count(*) FROM replicas r WHERE r.job = j.id),
		(SELECT count(*) FROM replicas r WHERE r.job = j.id AND r.excluded_roots @> $2::text[]) FROM jobs j WHERE j.id = $1`, aid, wid).
		Scan(&kind, &root, &lane, &fresh, &reps, &replicasExcluded); err != nil {
		t.Fatal(err)
	}
	if kind != "audit" || root != core.SystemID || lane != "public" || !fresh || reps != 1 || replicasExcluded != 1 {
		t.Fatalf("audit copy: kind=%s root=%s lane=%s fresh=%v replicas=%d excluded=%d", kind, root, lane, fresh, reps, replicasExcluded)
	}
	// A second pass never re-audits a job with a pending audit.
	e.runAudit(1)
	if n := e.count(`SELECT count(*) FROM audits WHERE job = $1`, jid); n != 1 {
		t.Fatalf("audits rows after two passes: %d", n)
	}
	// Only a trusted donor may lease it, and never one of the donors that produced the result.
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 204 {
		t.Fatalf("untrusted donor leased an audit: %d", st)
	}
	testPool.Exec(ctx, `UPDATE identities SET trusted = true WHERE id = $1`, wid[0])
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 204 {
		t.Fatalf("an agreeing donor leased its own audit: %d", st)
	}
	l := e.mustLease(ttok)
	if l.Job != aid || l.Kind != "audit" || l.Wasm != wasm || l.In != in {
		t.Fatalf("trusted lease: %+v", l)
	}
	// Unfunded system root: the pass stops with the inbox event and no dangling audits row.
	testPool.Exec(ctx, `UPDATE identities SET trusted = false WHERE id = $1`, wid[0])
	sid2, stok2 := e.register("sub2")
	e.promote(sid2)
	wasm2, in2 := e.put(stok2, minWasm("u"+sid)), e.put(stok2, []byte("unfunded "+sid))
	jid2, _ := e.agree(stok2, w, wasm2, in2, []byte("r2 "+sid), 1000)
	testPool.Exec(ctx, `UPDATE identities SET credits = 0 WHERE id = $1`, core.SystemID)
	if n := e.runAudit(1); n != 0 || e.count(`SELECT count(*) FROM audits WHERE job = $1`, jid2) != 0 {
		t.Fatalf("unfunded pass: n=%d", n)
	}
	if e.count(`SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'unfunded' AND title LIKE 'compute: system root unfunded%audit%'`) == 0 {
		t.Fatal("no unfunded event")
	}
}

// SECURITY-REVIEW-2 #5: system service precomputes (root=SystemID, kind='job', svc<>”) are promoted
// to global cache_scope and served anonymously by svcget, so the hourly sampler must cover them. The
// old blanket `AND j.root <> SystemID` let a forged global precompute escape auditing forever. Only
// system jobs with an empty svc stay excluded (KATs are kind<>'job' and already filtered by j.kind).
func TestAuditSamplesSystemServicePrecompute(t *testing.T) {
	e := newAuditEnv(t)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(2)
	e.trustedDonor("trusted")
	// Same shape svcget's janitor produces: a system-root kind 'job' carrying a service ref.
	jidSvc, _ := e.agree(stok, w, wasm, in, []byte("svc precompute "+sid), 2000)
	if _, err := testPool.Exec(ctx, `UPDATE jobs SET root = $2, svc = 'myservice' WHERE id = $1`, jidSvc, core.SystemID); err != nil {
		t.Fatal(err)
	}
	// A system-root job with no service ref must stay excluded (defence for any non-svc system job).
	wasm2, in2 := e.put(stok, minWasm("sys"+sid)), e.put(stok, []byte("sys plain "+sid))
	jidPlain, _ := e.agree(stok, w, wasm2, in2, []byte("sys plain out "+sid), 2000)
	if _, err := testPool.Exec(ctx, `UPDATE jobs SET root = $2, svc = '' WHERE id = $1`, jidPlain, core.SystemID); err != nil {
		t.Fatal(err)
	}
	if n := e.runAudit(1); n < 1 {
		t.Fatalf("nothing sampled: %d", n)
	}
	if e.count(`SELECT count(*) FROM audits WHERE job = $1`, jidSvc) != 1 {
		t.Fatal("system service precompute was not sampled")
	}
	if e.count(`SELECT count(*) FROM audits WHERE job = $1`, jidPlain) != 0 {
		t.Fatal("empty-svc system job must stay excluded from the sampler")
	}
}

func TestPriorityAuditGlobalisesCache(t *testing.T) {
	e := newAuditEnv(t)
	sid, stok, wasm, in, w, _ := e.setup(2)
	jid, out := e.agree(stok, w, wasm, in, []byte("priority "+sid), 2000)
	// A second root misses the root-scoped result and asks for a priority audit.
	_, btok := e.register("b")
	st, body := e.submitBody(btok, map[string]any{"wasm": wasm, "in": in})
	if (st != 200 && st != 202) || strings.Contains(body, "cached") {
		t.Fatalf("cross-root hit before the audit: %d %s", st, body)
	}
	e.do("DELETE", "/v1/j/"+firstField(body), btok, nil)
	if e.count(`SELECT count(*) FROM audit_queue WHERE job = $1 AND reason = 'cross-root-hit'`, jid) != 1 {
		t.Fatal("no audit_queue row")
	}
	_, ttok := e.trustedDonor("trusted")
	// Rate 0: only the queue is served.
	if n := e.runAudit(0); n < 1 {
		t.Fatalf("priority pass: %d", n)
	}
	aid, result, priority := e.auditRow(jid)
	if result != "pending" || !priority {
		t.Fatalf("priority audits row: %s %v", result, priority)
	}
	if e.count(`SELECT count(*) FROM audit_queue WHERE job = $1`, jid) != 0 {
		t.Fatal("queue row kept after submit")
	}
	// A new cross-root miss while the audit is pending does not queue a second one.
	_, dtok := e.register("d")
	_, body = e.submitBody(dtok, map[string]any{"wasm": wasm, "in": in})
	e.do("DELETE", "/v1/j/"+firstField(body), dtok, nil)
	if e.count(`SELECT count(*) FROM audit_queue WHERE job = $1`, jid) != 0 {
		t.Fatal("re-queued while pending")
	}
	l := e.mustLease(ttok)
	if l.Job != aid || l.Kind != "audit" {
		t.Fatalf("trusted lease: %+v", l)
	}
	// Nothing settles before the copy reports.
	e.settle()
	if _, result, _ := e.auditRow(jid); result != "pending" {
		t.Fatalf("settled early: %s", result)
	}
	e.mustDone(ttok, l.Lease, "ok", out, 0, 500)
	e.settle()
	if _, result, _ := e.auditRow(jid); result != "match" {
		t.Fatalf("result: %s", result)
	}
	if scope, _, _, _ := e.jobRow(jid); scope != "global" {
		t.Fatalf("scope after a matched audit: %s", scope)
	}
	// Any root is now served from the cache.
	_, ctok := e.register("c")
	st, body = e.submitBody(ctok, map[string]any{"wasm": wasm, "in": in})
	cid := firstField(body)
	if st != 200 || firstLine(body) != cid+" done out="+out+" ms=0 cached" {
		t.Fatalf("hit after globalisation: %d %s", st, body)
	}
	if e.count(`SELECT count(*) FROM revoked WHERE wasm = $1`, wasm) != 0 {
		t.Fatal("a match revoked something")
	}
}

// forceMismatch runs job jid's audit with a trusted donor reporting other, then settles.
func (e *env) forceMismatch(jid, wasm, in string, other []byte) (aid string) {
	e.t.Helper()
	_, ttok := e.trustedDonor("auditor")
	if e.count(`SELECT count(*) FROM audits WHERE job = $1`, jid) == 0 {
		if _, err := testPool.Exec(context.Background(), `INSERT INTO audit_queue (job, reason) VALUES ($1, 'test')`, jid); err != nil {
			e.t.Fatal(err)
		}
		e.runAudit(0)
	}
	aid, _, _ = e.auditRow(jid)
	l := e.mustLease(ttok)
	if l.Job != aid {
		e.t.Fatalf("auditor leased %s, want %s", l.Job, aid)
	}
	o := e.put(ttok, other)
	e.mustDone(ttok, l.Lease, "ok", o, 0, 500)
	e.settle()
	return aid
}

func TestAuditMismatchRevokesAndPenalises(t *testing.T) {
	e := newAuditEnv(t)
	ctx := context.Background()
	sid, stok, wasm, in, w, wid := e.setup(2)
	// A trusted agreeing donor makes the result global, so a third root gets a cached row; the
	// 16.4 cache mirror holds the pair under its key.
	testPool.Exec(ctx, `UPDATE identities SET trusted = true WHERE id = $1`, wid[0])
	jid, out := e.agree(stok, w, wasm, in, []byte("wrong "+sid), 2000)
	bid, btok := e.register("b")
	st, body := e.submitBody(btok, map[string]any{"wasm": wasm, "in": in})
	cid := firstField(body)
	if st != 200 || !strings.Contains(body, "cached") {
		t.Fatalf("cached hit: %d %s", st, body)
	}
	key := cacheKey(wasm, in, "")
	if _, err := testPool.Exec(ctx, `INSERT INTO cache (key, out, blob, attest, job, producer, producer_root, expires_at) VALUES ($1, '', $2, 'job', $3, $4, $5, now() + interval '1 day')`,
		key, out, jid, sid, sid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM cache WHERE key = $1`, key) })
	rep0, rep1 := e.rep(wid[0]), e.rep(wid[1])
	// The sampler picks the job (rate 1) and the agreeing trusted donor cannot audit itself.
	e.runAudit(1)
	aid, _, _ := e.auditRow(jid)
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 204 {
		t.Fatalf("agreeing trusted donor leased the audit of its own result: %d", st)
	}
	if got := e.forceMismatch(jid, wasm, in, []byte("right "+sid)); got != aid {
		t.Fatalf("audit ids: %s %s", got, aid)
	}
	if _, result, _ := e.auditRow(jid); result != "mismatch" {
		t.Fatalf("result: %s", result)
	}
	if e.rep(wid[0]) != rep0-10 || e.rep(wid[1]) != rep1-10 {
		t.Fatalf("rep: %d->%d %d->%d", rep0, e.rep(wid[0]), rep1, e.rep(wid[1]))
	}
	var line, reason string
	if err := testPool.QueryRow(ctx, `SELECT line, reason FROM revoked WHERE wasm = $1 AND input = $2`, wasm, in).Scan(&line, &reason); err != nil {
		t.Fatalf("revoked row: %v", err)
	}
	var att string
	testPool.QueryRow(ctx, `SELECT att FROM jobs WHERE id = $1`, jid).Scan(&att)
	if reason != "audit-mismatch" || line == "" || line != att || !strings.Contains(line, " w="+wasm+" ") || !strings.Contains(line, " i="+in+" ") {
		t.Fatalf("revoked line: %q reason=%s", line, reason)
	}
	st, body, hd := e.do("GET", "/att/revoked.txt", "", nil)
	lines := strings.Split(body, "\n")
	if st != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/plain") || !strings.HasPrefix(lines[0], "# ") {
		t.Fatalf("revoked.txt: %d %s", st, body)
	}
	found := false
	for _, l := range lines[1:] {
		if strings.HasPrefix(l, "att1 ") && strings.Contains(l, " w="+wasm+" ") && strings.Contains(l, " i="+in+" ") && strings.Contains(l, " reason=audit-mismatch at=") {
			found = true
		}
	}
	if !found {
		t.Fatalf("revoked.txt misses the pair:\n%s", body)
	}
	if scope, _, _, _ := e.jobRow(jid); scope != "revoked" {
		t.Fatalf("scope: %s", scope)
	}
	if e.count(`SELECT count(*) FROM jobs WHERE id = $1`, cid) != 0 || e.count(`SELECT count(*) FROM jobs WHERE cached_from = $1`, jid) != 0 {
		t.Fatal("cached rows survived")
	}
	if e.count(`SELECT count(*) FROM cache WHERE key = $1`, key) != 0 {
		t.Fatal("16.4 cache row survived")
	}
	for _, root := range []string{sid, bid} {
		if e.count(`SELECT count(*) FROM mail WHERE box = $1 AND from_id = 'sys' AND subject LIKE 'job j% result revoked by audit' AND text LIKE '%'||$2||'%'`, root, jid) != 1 {
			t.Fatalf("sys mail to %s", root)
		}
	}
	if e.count(`SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'audit_mismatch' AND title LIKE '%'||$1||'%'`, jid) != 1 {
		t.Fatal("ops event")
	}
	// No root is served the revoked result again: not the submitter, not a stranger.
	_, dtok := e.register("d")
	for _, tok := range []string{stok, dtok} {
		st, body := e.submitBody(tok, map[string]any{"wasm": wasm, "in": in})
		if (st != 200 && st != 202) || strings.Contains(body, "cached") {
			t.Fatalf("served after revocation: %d %s", st, body)
		}
		e.do("DELETE", "/v1/j/"+firstField(body), tok, nil)
	}
	if _, ok, _ := CacheLookup(ctx, testPool, wasm, in, "", defMb); ok {
		t.Fatal("CacheLookup served a revoked pair")
	}
	// Revoked pairs are never sampled again.
	e.runAudit(1)
	if e.count(`SELECT count(*) FROM audits WHERE job = $1`, jid) != 1 {
		t.Fatal("re-audited a revoked job")
	}
}

func TestNondeterministicOnlyRevokes(t *testing.T) {
	e := newAuditEnv(t)
	sid, stok, wasm, in, w, wid := e.setup(2)
	jid, _ := e.agree(stok, w, wasm, in, []byte("nondet "+sid), 2000)
	var asked []string
	NondeterministicFn = func(_ context.Context, _ core.Q, h string) bool { asked = append(asked, h); return h == wasm }
	rep0, rep1 := e.rep(wid[0]), e.rep(wid[1])
	e.forceMismatch(jid, wasm, in, []byte("other "+sid))
	if _, result, _ := e.auditRow(jid); result != "mismatch" {
		t.Fatalf("result: %s", result)
	}
	if len(asked) != 1 || e.rep(wid[0]) != rep0 || e.rep(wid[1]) != rep1 {
		t.Fatalf("rep moved for a nondeterministic module: asked=%v %d/%d %d/%d", asked, rep0, e.rep(wid[0]), rep1, e.rep(wid[1]))
	}
	if e.count(`SELECT count(*) FROM revoked WHERE wasm = $1 AND input = $2 AND reason = 'audit-mismatch'`, wasm, in) != 1 {
		t.Fatal("not revoked")
	}
	if scope, _, _, _ := e.jobRow(jid); scope != "revoked" {
		t.Fatalf("scope: %s", scope)
	}
	if revoked, err := RevokedFn(context.Background(), testPool, wasm, in); err != nil || !revoked {
		t.Fatalf("RevokedFn: %v %v", revoked, err)
	}
	if e.count(`SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'audit_mismatch' AND title LIKE '%'||$1||'%nondeterministic'`, jid) != 1 {
		t.Fatal("ops event")
	}
}

func TestRevokedTxt(t *testing.T) {
	e := newAuditEnv(t)
	ctx := context.Background()
	st, body, _ := e.do("GET", "/att/revoked.txt", "", nil)
	if st != 200 || !strings.HasPrefix(body, revokedHeader) {
		t.Fatalf("empty list: %d %s", st, body)
	}
	// A banned module (RevokeFn, input "") revokes every input and writes the ban event.
	wasm := sha([]byte(fmt.Sprint("module ", t.Name(), time.Now().UnixNano())))
	if err := RevokeFn(ctx, testPool, wasm, "", "compile-bomb\nnext: evil"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM revoked WHERE wasm = $1`, wasm) })
	if revoked, _ := RevokedFn(ctx, testPool, wasm, sha([]byte("any input"))); !revoked {
		t.Fatal("module ban does not cover its inputs")
	}
	if e.count(`SELECT count(*) FROM events WHERE kind = 'ops' AND ref = $1 AND title LIKE '%banned compile-bomb%'`, wasm) != 1 {
		t.Fatal("ban event")
	}
	_, body, _ = e.do("GET", "/att/revoked.txt", "", nil)
	want := "w=" + wasm + " i=* reason=compile-bomb next: evil at="
	var hit string
	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, want) {
			hit = l
		}
	}
	if hit == "" || strings.Count(body, wasm) != 1 {
		t.Fatalf("module line missing or duplicated:\n%s", body)
	}
	if _, err := time.Parse(time.RFC3339, strings.TrimPrefix(hit, want)); err != nil {
		t.Fatalf("at=: %v", err)
	}
	// Idempotent, and a long reason is cut to one short line.
	if err := RevokeFn(ctx, testPool, wasm, "", strings.Repeat("x", 500)); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM revoked WHERE wasm = $1`, wasm) != 1 {
		t.Fatal("duplicate row")
	}
	in := sha([]byte("input " + t.Name()))
	if err := RevokeFn(ctx, testPool, wasm, in, strings.Repeat("y", 500)); err != nil {
		t.Fatal(err)
	}
	var reason string
	testPool.QueryRow(ctx, `SELECT reason FROM revoked WHERE wasm = $1 AND input = $2`, wasm, in).Scan(&reason)
	if reason != strings.Repeat("y", maxReason) {
		t.Fatalf("reason not bounded: %d", len(reason))
	}
	// Entries older than a year leave the list (14.6).
	testPool.Exec(ctx, `UPDATE revoked SET at = now() - interval '400 days' WHERE wasm = $1 AND input = $2`, wasm, in)
	if err := auditSweep(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM revoked WHERE wasm = $1`, wasm) != 1 {
		t.Fatal("sweep kept the old entry or dropped the fresh one")
	}
	// The hourly marker: a pass is due once, then not before an hour.
	testPool.Exec(ctx, `DELETE FROM audit_runs`)
	if _, due, err := auditDue(ctx, testPool); err != nil || !due {
		t.Fatalf("first pass due: %v %v", due, err)
	}
	if _, due, _ := auditDue(ctx, testPool); due {
		t.Fatal("second pass within the hour")
	}
	testPool.Exec(ctx, `UPDATE audit_runs SET last_at = now() - interval '3 hours'`)
	since, due, _ := auditDue(ctx, testPool)
	if !due || time.Since(since) < 2*time.Hour+59*time.Minute || time.Since(since) > 3*time.Hour+time.Minute {
		t.Fatalf("window start: due=%v since=%v ago", due, time.Since(since))
	}
}

func TestCollusionQuery(t *testing.T) {
	e := newAuditEnv(t)
	ctx := context.Background()
	sid, _ := e.register("sub")
	// Pair a/b: 60 co-agreed jobs, b's only ones (share 1), different networks. Pair c/d: 60
	// co-agreed of d's 100 (share 0.6) but one /24 (same super-group). Pair a/c: 51 co-agreed of
	// many (share 0.46) from different networks: not flagged. Rows go straight into jobs/replicas:
	// the query reads the tables the consensus path writes. The a/b and a/c modules and inputs are
	// real blobs (stored through PutBlobBytes, past the per-root rate limit) so the sampler may
	// draw those jobs below.
	a, _ := e.register("a")
	b, _ := e.register("b")
	cIP := randIP()
	c, _ := e.registerIP("c", cIP)
	d, _ := e.registerIP("d", cIP[:strings.LastIndexByte(cIP, '.')]+".251") // c's /24: one super-group
	store := func(data []byte) string {
		t.Helper()
		h, err := PutBlobBytes(ctx, e.d, sid, data, "")
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	wasmOf := map[string]string{"ab": store(minWasm("ab" + sid)), "ac": store(minWasm("ac" + sid))}
	mk := func(tag string, n int, roots ...string) {
		t.Helper()
		wasm := wasmOf[tag]
		if wasm == "" {
			wasm = sha([]byte("w" + tag + sid))
		}
		for i := 0; i < n; i++ {
			jid := core.NewID('j')
			out := sha([]byte(tag + fmt.Sprint(i)))
			in := sha([]byte("i" + tag + sid + fmt.Sprint(i)))
			if wasmOf[tag] != "" {
				in = store([]byte("i" + tag + sid + fmt.Sprint(i)))
			}
			if _, err := testPool.Exec(ctx, `INSERT INTO jobs (id, submitter, root, wasm, input, ms, mb, status, out, code, finished_at, att_d)
				VALUES ($1, $2, $2, $3, $4, 1000, 64, 'done', $5, 0, now(), true)`, jid, sid, wasm, in, out); err != nil {
				t.Fatal(err)
			}
			for _, r := range roots {
				if _, err := testPool.Exec(ctx, `INSERT INTO replicas (job, state, worker, worker_root, status, code, out, ms, reported_at) VALUES ($1, 'reported', $2, $2, 'ok', 0, $3, 500, now())`, jid, r, out); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	mk("ab", 60, a, b)
	mk("cd", 60, c, d)
	mk("c", 40, c, sid)
	mk("d", 40, d, sid)
	mk("ac", 51, a, c)
	pairs, err := CollusionPairs(ctx, testPool)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]CollusionPair{}
	for _, p := range pairs {
		got[p.A+" "+p.B] = p
	}
	ab, ok := got[minmax(a, b)]
	if !ok || ab.Jobs != 60 {
		t.Fatalf("a/b: %+v %v", ab, ok)
	}
	cd, ok := got[minmax(c, d)]
	if !ok || cd.Jobs != 60 || !cd.SameNet || cd.Share > collusionShare {
		t.Fatalf("c/d: %+v %v", cd, ok)
	}
	if _, ok := got[minmax(a, c)]; ok {
		t.Fatalf("a/c flagged: %+v", pairs)
	}
	for _, p := range pairs {
		if p.A == sid || p.B == sid {
			t.Fatalf("submitter-as-donor pair flagged: %+v", p)
		}
	}
	// a/b: a agreed on 60+51 jobs, b on 60: share = 60/60 = 1.
	if ab.Share != 1 || ab.JobsA+ab.JobsB != 171 || ab.SameNet {
		t.Fatalf("a/b share: %+v", ab)
	}
	lines := core.CollusionFn(ctx, testPool)
	if len(lines) != len(pairs) || !strings.Contains(strings.Join(lines, "\n"), minmax(a, b)+" jobs=60 share=1") || !strings.Contains(strings.Join(lines, "\n"), minmax(c, d)+" jobs=60 share=0.6 net=same") {
		t.Fatalf("stats lines: %v", lines)
	}
	st, body := e.adminDo("GET", "/admin/stats", nil)
	if st != 200 || !strings.Contains(body, "collusion: "+minmax(c, d)+" jobs=60 share=0.6 net=same") {
		t.Fatalf("/admin/stats: %d %s", st, body)
	}
	// The sampler oversamples flagged pairs: with rate 0.1 and 10x every a/b job is drawn, the
	// unflagged a/c jobs rarely all are (the c/d jobs have no blobs and are never candidates).
	e.trustedDonor("trusted")
	n, err := e.s.auditPass(ctx, time.Now().Add(-time.Hour), 0.1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	flagged := e.count(`SELECT count(*) FROM audits a JOIN jobs j ON j.id = a.job WHERE j.wasm = $1 AND a.result = 'pending' AND a.audit <> ''`, wasmOf["ab"])
	plain := e.count(`SELECT count(*) FROM audits a JOIN jobs j ON j.id = a.job WHERE j.wasm = $1`, wasmOf["ac"])
	if n < 60 || flagged != 60 || plain >= 51 {
		t.Fatalf("oversampling: n=%d flagged=%d/60 plain=%d/51", n, flagged, plain)
	}
	if e.count(`SELECT count(*) FROM audits a JOIN jobs j ON j.id = a.job WHERE j.root = $1 AND NOT (j.wasm = ANY($2))`, sid, []string{wasmOf["ab"], wasmOf["ac"]}) != 0 {
		t.Fatal("a job without blobs was sampled")
	}
}

// minmax orders two ids the way the pair query does (a < b).
func minmax(a, b string) string {
	if a < b {
		return a + " " + b
	}
	return b + " " + a
}
