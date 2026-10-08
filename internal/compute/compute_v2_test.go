package compute

// Acceptance tests of P13-compute-core (SPEC-v2 14.1-14.4, 14.6, 4.2, 27.6).

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/sign"
)

const adminTok = "cx-admin-test"

// --- fixtures ---------------------------------------------------------------------------------

type wasmOpts struct {
	imports []string // "module.field" function imports (type 0)
	memMin  int      // > 0 adds a memory section with that minimum
	noStart bool
	tag     string
}

func section(id byte, body []byte) []byte {
	out := append([]byte{id}, uleb(len(body))...)
	return append(out, body...)
}

func vec(s string) []byte { return append(uleb(len(s)), s...) }

// buildWasm assembles a small valid core module per o.
func buildWasm(o wasmOpts) []byte {
	b := []byte{0, 'a', 's', 'm', 1, 0, 0, 0}
	b = append(b, section(1, []byte{1, 0x60, 0, 0})...)
	if len(o.imports) > 0 {
		body := uleb(len(o.imports))
		for _, im := range o.imports {
			mod, name, _ := strings.Cut(im, ".")
			body = append(body, vec(mod)...)
			body = append(body, vec(name)...)
			body = append(body, 0, 0)
		}
		b = append(b, section(2, body)...)
	}
	b = append(b, section(3, []byte{1, 0})...)
	if o.memMin > 0 {
		b = append(b, section(5, append([]byte{1, 0}, uleb(o.memMin)...))...)
	}
	if !o.noStart {
		body := append([]byte{1}, vec("_start")...)
		body = append(body, 0)
		body = append(body, uleb(len(o.imports))...)
		b = append(b, section(7, body)...)
	}
	b = append(b, section(10, []byte{1, 2, 0, 0x0b})...)
	return append(b, customSection("t", o.tag)...)
}

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(files[n]))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// bigWasm is a valid module just over the 4 MiB unpinned cap.
func bigWasm(tag string) []byte {
	return append(minWasm(tag), customSection("pad", strings.Repeat("x", maxWasm))...)
}

const ghpKey = "ghp_Ab9Cd8Ef7Gh6Ij5Kl4Mn3Op2Qr1St0Uv9Wx8Y" // 36 chars after the prefix: tier-1 kind key

func (e *env) adminDo(method, path string, body any) (int, string) {
	e.t.Helper()
	st, b, _ := e.do(method, path, adminTok, body)
	return st, b
}

func (e *env) submitBody(tok string, body any) (int, string) {
	e.t.Helper()
	st, b, _ := e.do("POST", "/v1/j", tok, body)
	return st, b
}

func (e *env) leaseV2(tok string, body map[string]any) (int, *leaseOut, string) {
	e.t.Helper()
	st, raw, _ := e.do("POST", "/v1/w/lease", tok, body)
	if st != 200 {
		return st, nil, raw
	}
	var l leaseOut
	if err := json.Unmarshal([]byte(raw), &l); err != nil || l.Lease == "" {
		e.t.Fatalf("lease body: %s", raw)
	}
	return st, &l, raw
}

// agree runs a fresh job through two agreeing workers (ms/2 used each) and returns (job, out).
func (e *env) agree(stok string, w []string, wasm, in string, outData []byte, ms int) (string, string) {
	e.t.Helper()
	jid := e.submit(stok, wasm, in, ms)
	out := e.put(w[0], outData)
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], l0.Lease, "ok", out, 0, ms/2)
	e.mustDone(w[1], l1.Lease, "ok", out, 0, ms/2)
	if got := e.job(stok, jid, 0); !strings.HasPrefix(got, jid+" done out="+out) {
		e.t.Fatalf("agree: %s", got)
	}
	return jid, out
}

func (e *env) jobRow(jid string) (scope string, attD bool, status, reason string) {
	e.t.Helper()
	if err := testPool.QueryRow(context.Background(), `SELECT cache_scope, att_d, status, reason FROM jobs WHERE id = $1`, jid).Scan(&scope, &attD, &status, &reason); err != nil {
		e.t.Fatal(err)
	}
	return
}

func firstLine(body string) string { return strings.SplitN(body, "\n", 2)[0] }

// --- 14.1 result cache --------------------------------------------------------------------------

func TestResultCacheRootScopedByDefault(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(2)
	var audited []string
	PriorityAuditFn = func(_ context.Context, _ core.Q, jobID, reason string) error {
		audited = append(audited, jobID+" "+reason)
		return nil
	}
	t.Cleanup(func() { PriorityAuditFn = nil })
	jid, out := e.agree(stok, w, wasm, in, []byte("cached result "+sid), 4000)
	if scope, attD, _, _ := e.jobRow(jid); scope != "root" || !attD {
		t.Fatalf("fresh result: scope=%s att_d=%v", scope, attD)
	}
	before := e.credits(sid)
	st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "ms": 9000})
	cid := firstField(body)
	if st != 200 || cid == jid || !core.ValidID(cid) || firstLine(body) != cid+" done out="+out+" ms=0 cached" {
		t.Fatalf("same-root hit: %d %s", st, body)
	}
	if e.credits(sid) != before {
		t.Fatalf("a cache hit must reserve nothing: %d -> %d", before, e.credits(sid))
	}
	if got := e.job(stok, cid, 0); got != cid+" done out="+out+" ms=0 cached" {
		t.Fatalf("cached row status: %s", got)
	}
	var from string
	testPool.QueryRow(ctx, `SELECT cached_from FROM jobs WHERE id = $1`, cid).Scan(&from)
	if from != jid {
		t.Fatalf("cached_from=%q", from)
	}
	st, body, _ = e.do("POST", "/v1/j?f=json", stok, map[string]any{"wasm": wasm, "in": in})
	var j struct {
		ID     string
		Cached []map[string]any
	}
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || len(j.Cached) != 1 || j.Cached[0]["cached"] != true || j.Cached[0]["out"] != out {
		t.Fatalf("json hit: %d %s", st, body)
	}
	var savedMs, savedCr int
	testPool.QueryRow(ctx, `SELECT coalesce((SELECT n FROM counters WHERE scope = $1 AND kind = 'saved:ms' AND day = current_date), 0),
		coalesce((SELECT n FROM counters WHERE scope = $1 AND kind = 'saved:credits' AND day = current_date), 0)`, sid).Scan(&savedMs, &savedCr)
	if savedMs != 4000 || savedCr != 8 {
		t.Fatalf("saved counters ms=%d credits=%d", savedMs, savedCr)
	}
	if st, body, _ := e.do("GET", "/v1/me", stok, nil); st != 200 || !strings.Contains(body, "\ncompute saved=8 saved_ms=4000 cached=2") {
		t.Fatalf("me: %d %s", st, body)
	}
	// A second distinct root misses (root scope) and asks for a priority audit of the original.
	_, btok := e.register("other")
	st, body = e.submitBody(btok, map[string]any{"wasm": wasm, "in": in})
	bj := firstField(body)
	if (st != 200 && st != 202) || !core.ValidID(bj) || strings.Contains(body, "cached") {
		t.Fatalf("second root must miss: %d %s", st, body)
	}
	if got := e.job(btok, bj, 0); got != bj+" queued" {
		t.Fatalf("second root job: %s", got)
	}
	if len(audited) != 1 || audited[0] != jid+" cross-root-hit" {
		t.Fatalf("priority audit hook: %v", audited)
	}
	// Without the hook the request lands in audit_queue.
	PriorityAuditFn = nil
	_, ctok := e.register("third")
	e.submitBody(ctok, map[string]any{"wasm": wasm, "in": in})
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM audit_queue WHERE job = $1 AND reason = 'cross-root-hit'`, jid).Scan(&n)
	if n != 1 {
		t.Fatalf("audit_queue rows: %d", n)
	}
}

func TestResultCacheGlobalAfterTrustedReplica(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, wid := e.setup(2)
	testPool.Exec(ctx, `UPDATE identities SET trusted = true WHERE id = $1`, wid[0])
	jid, out := e.agree(stok, w, wasm, in, []byte("global result "+sid), 2000)
	if scope, _, _, _ := e.jobRow(jid); scope != "global" {
		t.Fatalf("scope with a trusted replica: %s", scope)
	}
	_, btok := e.register("b")
	st, body := e.submitBody(btok, map[string]any{"wasm": wasm, "in": in})
	cid := firstField(body)
	if st != 200 || firstLine(body) != cid+" done out="+out+" ms=0 cached" {
		t.Fatalf("cross-root hit on a global result: %d %s", st, body)
	}
	if got := e.job(btok, cid, 0); got != cid+" done out="+out+" ms=0 cached" {
		t.Fatalf("b's cached row: %s", got)
	}
	v, ok, err := CacheLookup(ctx, testPool, wasm, in, "", defMb)
	if err != nil || !ok || v.Out != out || !v.Cached || v.ID != jid {
		t.Fatalf("CacheLookup: %+v %v %v", v, ok, err)
	}
	if _, ok, _ := CacheLookup(ctx, testPool, wasm, in, "", 32); ok {
		t.Fatal("mb is part of the key")
	}
	RevokedFn = func(context.Context, core.Q, string, string) (bool, error) { return true, nil }
	t.Cleanup(func() { RevokedFn = nil })
	if _, ok, _ := CacheLookup(ctx, testPool, wasm, in, "", defMb); ok {
		t.Fatal("revoked results must not be served")
	}
	st, body = e.submitBody(btok, map[string]any{"wasm": wasm, "in": in})
	if (st != 200 && st != 202) || strings.Contains(body, "cached") {
		t.Fatalf("revoked -> miss: %d %s", st, body)
	}
	RevokedFn = nil
	if st, _, _ := e.do("DELETE", "/v1/j/"+firstField(body), btok, nil); st != 200 {
		t.Fatalf("cancel b's fresh job: %d", st)
	}
	// An L3 agreeing donor also makes the result global.
	sid2, stok2 := e.register("sub2")
	e.promote(sid2)
	wasm2, in2 := e.put(stok2, minWasm(sid2)), e.put(stok2, []byte("in "+sid2))
	testPool.Exec(ctx, `UPDATE identities SET trusted = false WHERE id = $1`, wid[0])
	testPool.Exec(ctx, `UPDATE identities SET rep = 25, created = now() - interval '40 days', verified_noncompute = 1 WHERE id = $1`, wid[1])
	jid2, _ := e.agree(stok2, w, wasm2, in2, []byte("l3 "+sid2), 2000)
	if scope, _, _, _ := e.jobRow(jid2); scope != "global" {
		t.Fatalf("scope with an L3 replica: %s", scope)
	}
}

func TestCacheFreshBypass(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, _ := e.setup(2)
	jid, out := e.agree(stok, w, wasm, in, []byte("fresh "+sid), 2000)
	st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "fresh": true})
	fid := firstField(body)
	if (st != 200 && st != 202) || fid == jid || strings.Contains(body, "cached") {
		t.Fatalf("fresh must bypass the cache: %d %s", st, body)
	}
	if got := e.job(stok, fid, 0); got != fid+" queued" {
		t.Fatalf("fresh job: %s", got)
	}
	// A hit needs the out blob on disk: with the file gone the lookup is a miss.
	os.Remove(e.s.blobPath(out))
	st, body = e.submitBody(stok, map[string]any{"wasm": wasm, "in": in})
	if (st != 200 && st != 202) || strings.Contains(body, "cached") {
		t.Fatalf("missing out blob must miss: %d %s", st, body)
	}
}

// --- 14.2 attestations --------------------------------------------------------------------------

func TestAttestationLineVerifies(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(2)
	jid, out := e.agree(stok, w, wasm, in, []byte("attested "+sid), 2000)
	st, body, _ := e.do("GET", "/v1/j/"+jid+"?att=1", stok, nil)
	lines := strings.Split(body, "\n")
	if st != 200 || len(lines) != 3 {
		t.Fatalf("att reply: %d %q", st, body)
	}
	line, sig := lines[1], lines[2]
	if !strings.HasPrefix(line, "att1 j="+jid+" w="+wasm+" i="+in+" o="+out+" s=ok c=0 n=2/2 d=1 t=") || !strings.HasSuffix(line, " k=1") || !strings.HasPrefix(sig, "sig=") {
		t.Fatalf("att line: %q %q", line, sig)
	}
	signer := sign.MustNew(e.d.Cfg)
	if kid, ok := signer.Verify("att1", line, sig); !ok || kid != 1 {
		t.Fatalf("signature does not verify: kid=%d ok=%v", kid, ok)
	}
	if _, ok := signer.Verify("att1", strings.Replace(line, " d=1 ", " d=0 ", 1), sig); ok {
		t.Fatal("tampered line verified")
	}
	if _, ok := signer.Verify("ts1", line, sig); ok {
		t.Fatal("signature verified under another domain type")
	}
	st, body, _ = e.do("GET", "/v1/j/"+jid+"?att=1&f=json", stok, nil)
	var j map[string]any
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || j["att"] != line || j["sig"] != sig {
		t.Fatalf("json att: %d %s", st, body)
	}
	if got := e.job(stok, jid, 0); strings.Contains(got, "\n") {
		t.Fatalf("without ?att=1 the status is one line: %q", got)
	}
	me, _ := e.d.LookupToken(ctx, stok)
	if got, err := Ops(e.d)["jatt"](ctx, me, json.RawMessage(`{"id":"`+jid+`"}`)); err != nil || got != strings.Join(lines, "\n") {
		t.Fatalf("jatt: %q %v", got, err)
	}
	// Timing splits are never attested as disagreement: n counts agreeing reports only.
	jid2 := e.submit(stok, wasm, in, 2000)
	_, w3 := e.register("w3")
	a, b := e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], a.Lease, "ok", out, 0, 1900)
	e.mustDone(w[1], b.Lease, "timeout", "", 0, 2000)
	c := e.mustLease(w3)
	e.mustDone(w3, c.Lease, "ok", out, 0, 1800)
	var att string
	testPool.QueryRow(ctx, `SELECT att FROM jobs WHERE id = $1`, jid2).Scan(&att)
	if !strings.Contains(att, " n=2/3 d=1 ") {
		t.Fatalf("split att: %q", att)
	}
}

// --- 4.2 compute rep ----------------------------------------------------------------------------

func TestComputeRepNeedsL2SubmitterOtherSuper(t *testing.T) {
	e := newEnv(t, false)
	// (a) L0 submitter: agreeing distinct workers are paid, earn no rep.
	sid, stok := e.register("l0sub")
	wasm, in := e.put(stok, minWasm(sid)), e.put(stok, []byte("in "+sid))
	wa, ta := e.register("wa")
	wb, tb := e.register("wb")
	e.agree(stok, []string{ta, tb}, wasm, in, []byte("o "+sid), 2000)
	if e.rep(wa) != 0 || e.rep(wb) != 0 || e.credits(wa) <= 100 {
		t.Fatalf("L0 submitter: rep %d %d credits %d", e.rep(wa), e.rep(wb), e.credits(wa))
	}
	// (b) L2 submitter sharing a super-group (/24) with one worker: not distinct, no rep for anyone.
	ip := randIP()
	sid2, stok2 := e.registerIP("l2sub", ip)
	e.promote(sid2)
	wasm2, in2 := e.put(stok2, minWasm(sid2)), e.put(stok2, []byte("in "+sid2))
	wc, tc := e.registerIP("wc", ip[:strings.LastIndex(ip, ".")]+".251")
	wd, td := e.register("wd")
	e.agree(stok2, []string{tc, td}, wasm2, in2, []byte("o "+sid2), 2000)
	if e.rep(wc) != 0 || e.rep(wd) != 0 {
		t.Fatalf("same super-group as submitter: rep %d %d", e.rep(wc), e.rep(wd))
	}
	// (c) L2 submitter, every root in its own super-group: +1 each.
	sid3, stok3 := e.register("l2sub3")
	e.promote(sid3)
	wasm3, in3 := e.put(stok3, minWasm(sid3)), e.put(stok3, []byte("in "+sid3))
	e.agree(stok3, []string{ta, td}, wasm3, in3, []byte("o "+sid3), 2000)
	if e.rep(wa) != 1 || e.rep(wd) != 1 {
		t.Fatalf("L2 distinct: rep %d %d", e.rep(wa), e.rep(wd))
	}
}

func TestComputeRepPairDayCap(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, wid := e.setup(2)
	e.agree(stok, w, wasm, in, []byte("one "+sid), 2000)
	in2 := e.put(stok, []byte("second input "+sid))
	e.agree(stok, w, wasm, in2, []byte("two "+sid), 2000)
	if e.rep(wid[0]) != 1 || e.rep(wid[1]) != 1 {
		t.Fatalf("one rep per (worker, submitter) pair per day: %d %d", e.rep(wid[0]), e.rep(wid[1]))
	}
	sid2, stok2 := e.register("sub2")
	e.promote(sid2)
	wasm2, in3 := e.put(stok2, minWasm(sid2)), e.put(stok2, []byte("in "+sid2))
	e.agree(stok2, w, wasm2, in3, []byte("three "+sid2), 2000)
	if e.rep(wid[0]) != 2 || e.rep(wid[1]) != 2 {
		t.Fatalf("another submitter pays again: %d %d", e.rep(wid[0]), e.rep(wid[1]))
	}
}

// --- 14.3 lifecycle -----------------------------------------------------------------------------

func TestCancelRefundAndDonor410(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(1)
	_, otok := e.register("o")
	jid := e.submit(stok, wasm, in, 10000)
	l := e.mustLease(w[0])
	if st, _, _ := e.do("DELETE", "/v1/j/"+jid, otok, nil); st != 404 {
		t.Fatalf("stranger cancel: %d", st)
	}
	st, body, _ := e.do("DELETE", "/v1/j/"+jid, stok, nil)
	if st != 200 || body != jid+" cancelled refund=30" {
		t.Fatalf("cancel: %d %s", st, body)
	}
	if e.credits(sid) != 100 {
		t.Fatalf("refund: %d", e.credits(sid))
	}
	if got := e.job(stok, jid, 0); got != jid+" failed cancelled" {
		t.Fatalf("status: %s", got)
	}
	if st, body := e.done(w[0], l.Lease, "ok", wasm, 0, 1); st != 410 || !strings.HasPrefix(body, "err gone") {
		t.Fatalf("donor done after cancel: %d %s", st, body)
	}
	if st, _, _ := e.do("POST", "/v1/b", w[0], []byte("late"), "X-Lease", l.Lease); st != 404 {
		t.Fatalf("upload under a cancelled lease: %d", st)
	}
	if st, body, _ := e.do("DELETE", "/v1/j/"+jid, stok, nil); st != 409 || !strings.HasPrefix(body, "err taken") {
		t.Fatalf("second cancel: %d %s", st, body)
	}
	var state string
	testPool.QueryRow(ctx, `SELECT state FROM replicas WHERE lease = $1`, l.Lease).Scan(&state)
	if state != "cancelled" {
		t.Fatalf("replica state: %s", state)
	}
	testPool.Exec(ctx, `UPDATE replicas SET deadline = now() - interval '1 second' WHERE lease = $1`, l.Lease)
	e.d.Janitor.RunOnce(ctx)
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM replicas WHERE job = $1`, jid).Scan(&n)
	if n != 0 {
		t.Fatalf("cancelled replica past its deadline kept: %d", n)
	}
	me, _ := e.d.LookupToken(ctx, stok)
	jid2 := e.submit(stok, wasm, in, 1000)
	if got, err := Ops(e.d)["jc"](ctx, me, json.RawMessage(`{"id":"`+jid2+`"}`)); err != nil || got != jid2+" cancelled refund=3" {
		t.Fatalf("jc: %q %v", got, err)
	}
	st, body, _ = e.do("DELETE", "/v1/j/"+e.submit(stok, wasm, in, 1000)+"?f=json", stok, nil)
	if st != 200 || !strings.Contains(body, `"reason":"cancelled"`) || !strings.Contains(body, `"refund":3`) {
		t.Fatalf("json cancel: %d %s", st, body)
	}
}

func TestBlobDeleteRules(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, _, _ := e.setup(0)
	_, otok := e.register("o")
	h := e.put(stok, []byte("deletable "+sid))
	if st, _, _ := e.do("DELETE", "/v1/b/"+h, otok, nil); st != 404 {
		t.Fatalf("stranger delete: %d", st)
	}
	st, body, _ := e.do("DELETE", "/v1/b/"+h, stok, nil)
	if st != 200 || body != "ok deleted "+h {
		t.Fatalf("delete: %d %s", st, body)
	}
	if _, ok, _ := blobSize(ctx, testPool, h); ok {
		t.Fatal("row survived")
	}
	if _, err := os.Stat(e.s.blobPath(h)); err == nil {
		t.Fatal("file survived")
	}
	if st, _, _ := e.do("GET", "/v1/b/"+h, stok, nil); st != 404 {
		t.Fatalf("read after delete: %d", st)
	}
	e.submit(stok, wasm, in, 1000)
	if st, body, _ := e.do("DELETE", "/v1/b/"+in, stok, nil); st != 409 || !strings.HasPrefix(body, "err taken") {
		t.Fatalf("referenced by an active job: %d %s", st, body)
	}
	p := e.put(stok, []byte("pinned "+sid))
	if st, body := e.adminDo("POST", "/admin/pin", map[string]any{"hash": p, "name": "pinned", "ver": "1"}); st != 200 {
		t.Fatalf("pin: %d %s", st, body)
	}
	if st, _, _ := e.do("DELETE", "/v1/b/"+p, stok, nil); st != 409 {
		t.Fatalf("pinned delete: %d", st)
	}
	if st, _, _ := e.do("DELETE", "/v1/b/zz", stok, nil); st != 400 {
		t.Fatalf("bad hash: %d", st)
	}
	me, _ := e.d.LookupToken(ctx, stok)
	h2 := e.put(stok, []byte("deletable 2 "+sid))
	if got, err := Ops(e.d)["bd"](ctx, me, json.RawMessage(`{"hash":"`+h2+`"}`)); err != nil || got != "ok deleted "+h2 {
		t.Fatalf("bd: %q %v", got, err)
	}
}

func TestBlobInfoAndSubmitPreciseErrors(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, _, in, _, _ := e.setup(0)
	_, otok := e.register("o")
	bad := e.put(stok, buildWasm(wasmOpts{imports: []string{"env.emscripten_notify_memory_growth"}, tag: sid}))
	st, body := e.submitBody(stok, map[string]any{"wasm": bad, "in": in})
	if st != 400 || body != "err bad import env.emscripten_notify_memory_growth: only wasi_snapshot_preview1 is available" {
		t.Fatalf("bad import: %d %s", st, body)
	}
	oom := e.put(stok, buildWasm(wasmOpts{memMin: 1024, tag: sid}))
	st, body = e.submitBody(stok, map[string]any{"wasm": oom, "in": in, "mb": 32})
	if st != 400 || body != "err oom declared min memory 1024 pages (64 MiB) > mb=32" {
		t.Fatalf("oom: %d %s", st, body)
	}
	if st, body = e.submitBody(stok, map[string]any{"wasm": oom, "in": in, "mb": 64, "fresh": true}); st != 200 && st != 202 {
		t.Fatalf("64 MiB declared with mb=64: %d %s", st, body)
	}
	nostart := e.put(stok, buildWasm(wasmOpts{noStart: true, tag: sid}))
	st, body = e.submitBody(stok, map[string]any{"wasm": nostart, "in": in})
	if st != 400 || body != "err bad no _start export (component model/preview2 unsupported; build with wasi-sdk preview1, GOOS=wasip1 or --target wasm32-wasip1)" {
		t.Fatalf("no _start: %d %s", st, body)
	}
	st, body = e.submitBody(stok, map[string]any{"wasm": in, "in": in})
	if st != 400 || !strings.HasPrefix(body, "err bad not a wasm module") {
		t.Fatalf("text as wasm: %d %s", st, body)
	}
	junk := e.put(stok, []byte("\x00asm junk module "+sid))
	st, body = e.submitBody(stok, map[string]any{"wasm": junk, "in": in})
	if st != 400 || body != "err bad module unsupported binary version" {
		t.Fatalf("junk module: %d %s", st, body)
	}
	wasi := e.put(stok, buildWasm(wasmOpts{imports: []string{"wasi_snapshot_preview1.fd_write"}, tag: sid}))
	if st, body = e.submitBody(stok, map[string]any{"wasm": wasi, "in": in, "fresh": true}); st != 200 && st != 202 {
		t.Fatalf("wasi import: %d %s", st, body)
	}
	if e.credits(sid) != 100-30-30 {
		t.Fatalf("refused submits charged: %d", e.credits(sid))
	}
	// Info lines.
	st, body, _ = e.do("GET", "/v1/b/"+oom+"/info", stok, nil)
	lines := strings.Split(body, "\n")
	if st != 200 || !strings.HasPrefix(lines[0], fmt.Sprintf("wasm size=%d imports=- memory=min1024 funcs=1 has_start=1 producers=- scrub=clean", len(buildWasm(wasmOpts{memMin: 1024, tag: sid})))) ||
		!strings.Contains(lines[0], " exp=") || len(lines) < 2 || !strings.HasPrefix(lines[1], "runs_ok=0 compile_timeouts=0") {
		t.Fatalf("info: %d %q", st, body)
	}
	if st, body, _ = e.do("GET", "/v1/b/"+bad+"/info", stok, nil); st != 200 || !strings.Contains(body, "imports=env:emscripten_notify_memory_growth memory=-") {
		t.Fatalf("info imports: %d %s", st, body)
	}
	if st, body, _ = e.do("GET", "/v1/b/"+in+"/info", stok, nil); st != 200 || !strings.HasPrefix(body, fmt.Sprintf("text size=%d scrub=clean", len("input "+sid))) {
		t.Fatalf("text info: %d %s", st, body)
	}
	if st, _, _ = e.do("GET", "/v1/b/"+oom+"/info", otok, nil); st != 404 {
		t.Fatalf("stranger info: %d", st)
	}
	st, body, _ = e.do("GET", "/v1/b/"+oom+"/info?f=json", stok, nil)
	var j map[string]any
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || j["has_start"] != true || j["min_pages"] != float64(1024) || j["scrub"] != "clean" {
		t.Fatalf("json info: %s", body)
	}
	me, _ := e.d.LookupToken(ctx, stok)
	if got, err := Ops(e.d)["binfo"](ctx, me, json.RawMessage(`{"hash":"`+junk+`"}`)); err != nil || !strings.Contains(got, "parse_err=unsupported_binary_version") {
		t.Fatalf("binfo: %q %v", got, err)
	}
}

func TestWStatsBuckets(t *testing.T) {
	for n, want := range map[int]string{0: "0", 1: "1-2", 2: "1-2", 3: "3-9", 9: "3-9", 10: "10+", 50: "10+"} {
		if got := bucket(n); got != want {
			t.Fatalf("bucket(%d)=%s", n, got)
		}
	}
	e := newEnv(t, false)
	st, body, hd := e.do("GET", "/v1/w/stats", "", nil)
	if st != 200 || !strings.HasPrefix(body, "donors_online=0 slots=0 queued=") || !strings.Contains(body, " max_ms=30000 max_mb=256 caps=wasm4m donors_new=0 donors_l0=0") ||
		!strings.Contains(hd.Get("Cache-Control"), "max-age=15") {
		t.Fatalf("stats: %d %s %v", st, body, hd)
	}
	_, stok, wasm, in, w, _ := e.setup(3)
	for i := range w {
		if st, _ := e.lease(w[i], 30000, 256, 0); st != 204 {
			t.Fatalf("poll: %d", st)
		}
	}
	e.s.stats.at = time.Time{} // drop the 15 s cache
	st, body, _ = e.do("GET", "/v1/w/stats", "", nil)
	if st != 200 || !strings.HasPrefix(body, "donors_online=3-9 slots=10+ queued=0 leased=0 ") || !strings.Contains(body, "donors_new=3-9 donors_l0=3-9") {
		t.Fatalf("stats with donors: %s", body)
	}
	e.submit(stok, wasm, in, 1000)
	e.s.stats.at = time.Time{}
	st, body, _ = e.do("GET", "/v1/w/stats?f=json", "", nil)
	var j map[string]any
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || j["queued"] != float64(2) || j["donors_online"] != "3-9" {
		t.Fatalf("json stats: %s", body)
	}
	// The submit reply carries an eta once donors are online.
	st, body = e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "fresh": true})
	if st != 200 || !strings.Contains(body, "\neta_s=~") {
		t.Fatalf("eta line: %d %s", st, body)
	}
	if got, err := Ops(e.d)["wstats"](context.Background(), nil, nil); err != nil || !strings.HasPrefix(got, "donors_online=") {
		t.Fatalf("wstats op: %q %v", got, err)
	}
}

func TestMaxWaitAutoCancel(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(1)
	if st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "max_wait_s": maxWaitS + 1}); st != 400 || !strings.HasPrefix(body, "err bad max_wait_s") {
		t.Fatalf("max_wait_s bound: %d %s", st, body)
	}
	st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "ms": 10000, "max_wait_s": 30, "fresh": true})
	jid := firstField(body)
	if (st != 200 && st != 202) || !core.ValidID(jid) {
		t.Fatalf("submit: %d %s", st, body)
	}
	l := e.mustLease(w[0])
	e.d.Janitor.RunOnce(ctx)
	if got := e.job(stok, jid, 0); got != jid+" running" {
		t.Fatalf("before the deadline: %s", got)
	}
	testPool.Exec(ctx, `UPDATE jobs SET max_wait_until = now() - interval '1 second' WHERE id = $1`, jid)
	e.d.Janitor.RunOnce(ctx)
	if got := e.job(stok, jid, 0); got != jid+" failed max_wait" {
		t.Fatalf("after the deadline: %s", got)
	}
	if e.credits(sid) != 100 {
		t.Fatalf("full refund: %d", e.credits(sid))
	}
	if st, body := e.done(w[0], l.Lease, "ok", wasm, 0, 1); st != 410 || !strings.HasPrefix(body, "err gone") {
		t.Fatalf("donor after max_wait: %d %s", st, body)
	}
}

// --- 14.4 caps and pins -------------------------------------------------------------------------

func TestLeaseCapsPinsEligibility(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, wid := e.setup(2) // w[0] a v1 donor, w[1] a ver 2 donor
	big := e.put(stok, bigWasm(sid))
	if st, body := e.submitBody(stok, map[string]any{"wasm": big, "in": in}); st != 413 || !strings.HasPrefix(body, "err size wasm over 4 MiB") {
		t.Fatalf("unpinned big module: %d %s", st, body)
	}
	if st, body := e.adminDo("POST", "/admin/pin", map[string]any{"hash": big, "name": "cx-big", "ver": "2"}); st != 200 {
		t.Fatalf("pin: %d %s", st, body)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM pins WHERE hash = $1`, big) })
	jid := e.submit(stok, big, in, 1000)
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 204 {
		t.Fatalf("a v1 worker must never get a module over 4 MiB: %d", st)
	}
	if st, _, _ := e.leaseV2(w[1], map[string]any{"max_ms": 30000, "max_mb": 256, "ver": 2, "caps": []string{"new", "l0"}}); st != 204 {
		t.Fatalf("ver 2 without the pin cap: %d", st)
	}
	if st, _, _ := e.leaseV2(w[1], map[string]any{"max_ms": 30000, "max_mb": 256, "ver": 2, "caps": []string{"pin", "new", "l0"}, "pins": []string{wasm}}); st != 204 {
		t.Fatalf("pin cap with another pin list: %d", st)
	}
	if st, _, body := e.leaseV2(w[1], map[string]any{"max_ms": 30000, "max_mb": 256, "ver": 2, "caps": []string{"pin"}, "pins": make([]string, maxPins+1)}); st != 400 {
		t.Fatalf("too many pins: %d %s", st, body)
	}
	st, l, raw := e.leaseV2(w[1], map[string]any{"max_ms": 30000, "max_mb": 256, "ver": 2, "caps": []string{"pin", "new", "l0"}, "pins": []string{big}})
	if st != 200 || l.Job != jid || l.Wasm != big || strings.Contains(raw, "upgrade") {
		t.Fatalf("pinned lease: %d %s", st, raw)
	}
	// A v1 donor is told to upgrade.
	small := e.submit(stok, wasm, in, 1000)
	st, l, raw = e.leaseV2(w[0], map[string]any{"max_ms": 30000, "max_mb": 256})
	if st != 200 || l.Job != small || l.Upgrade != "https://t.example/wasm#cxw" || l.Sunset != leaseSunset || !strings.Contains(raw, `"sunset"`) {
		t.Fatalf("legacy lease: %d %s", st, raw)
	}
	if st, _, _ := e.do("DELETE", "/v1/j/"+small, stok, nil); st != 200 {
		t.Fatalf("cancel small: %d", st)
	}
	// kind audit goes to trusted donors only, as one replica.
	testPool.Exec(ctx, `UPDATE identities SET credits = 100 WHERE id = $1`, core.SystemID)
	ids, err := SystemSubmit(ctx, e.d, []Spec{{Wasm: wasm, In: in, Ms: 1000}}, "audit")
	if err != nil || len(ids) != 1 {
		t.Fatalf("audit submit: %v %v", ids, err)
	}
	var reps int
	testPool.QueryRow(ctx, `SELECT count(*) FROM replicas WHERE job = $1`, ids[0]).Scan(&reps)
	if reps != 1 {
		t.Fatalf("audit replicas: %d", reps)
	}
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 204 {
		t.Fatalf("untrusted donor got an audit: %d", st)
	}
	testPool.Exec(ctx, `UPDATE identities SET trusted = true WHERE id = $1`, wid[1])
	st, l, _ = e.leaseV2(w[1], map[string]any{"max_ms": 30000, "max_mb": 256, "ver": 2, "caps": []string{"new", "l0"}})
	if st != 200 || l.Job != ids[0] || l.Kind != "audit" {
		t.Fatalf("trusted audit lease: %d %+v", st, l)
	}
}

func TestPinsAdmin(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, _, in, _, _ := e.setup(0)
	big := e.put(stok, bigWasm(sid))
	if st, body, _ := e.do("POST", "/admin/pin", stok, map[string]any{"hash": big, "name": "x"}); st != 401 || body != "err auth admin" {
		t.Fatalf("user token on /admin/pin: %d %s", st, body)
	}
	st, body := e.adminDo("POST", "/admin/pin", map[string]any{"hash": big, "name": "cx-big", "ver": "1.0", "note": "test\nline"})
	if st != 200 || body != fmt.Sprintf("ok pin %s cx-big@1.0 %d", big, len(bigWasm(sid))) {
		t.Fatalf("pin: %d %s", st, body)
	}
	if st, body := e.adminDo("POST", "/admin/pin", map[string]any{"hash": big, "name": "bad name!"}); st != 400 {
		t.Fatalf("bad name: %d %s", st, body)
	}
	if st, body := e.adminDo("POST", "/admin/pin", map[string]any{"hash": strings.Repeat("0", 64), "name": "ghost"}); st != 404 {
		t.Fatalf("unknown blob: %d %s", st, body)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM pins WHERE hash = $1`, big) })
	st, body, _ = e.do("GET", "/v1/pins", "", nil)
	if st != 200 || !strings.Contains(body, fmt.Sprintf("%s cx-big@1.0 %d", big, len(bigWasm(sid)))) {
		t.Fatalf("pins: %d %s", st, body)
	}
	var by string
	testPool.QueryRow(ctx, `SELECT pinned_by FROM blobs WHERE hash = $1`, big).Scan(&by)
	if by != "admin" {
		t.Fatalf("pinned_by=%s", by)
	}
	jid := e.submit(stok, big, in, 1000)
	st, body = e.adminDo("POST", "/admin/unpin", map[string]any{"hash": big})
	if st != 200 || body != "ok unpin "+big+" cancelled=1" {
		t.Fatalf("unpin: %d %s", st, body)
	}
	if got := e.job(stok, jid, 0); got != jid+" failed unpinned" || e.credits(sid) != 100 {
		t.Fatalf("unpin cancels with refund: %s %d", got, e.credits(sid))
	}
	if st, body, _ = e.do("GET", "/v1/pins", stok, nil); st != 200 || strings.Contains(body, big) {
		t.Fatalf("pins after unpin: %d %q", st, body)
	}
	if st, _ := e.adminDo("POST", "/admin/unpin", map[string]any{"hash": big}); st != 404 {
		t.Fatalf("unpin twice: %d", st)
	}
	// Seeds (catalog) show by=seed.
	testPool.Exec(ctx, `INSERT INTO pins (hash, name, ver, size, note) VALUES ($1, 'cx-seed', '0.1', 5, 'seed')`, big)
	if st, body, _ = e.do("GET", "/v1/pins", "", nil); st != 200 || !strings.Contains(body, big+" cx-seed@0.1 5 by=seed") {
		t.Fatalf("seed pin: %d %s", st, body)
	}
}

// --- 14.6 retention -----------------------------------------------------------------------------

func TestRetentionAggregate(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(2)
	jid, out := e.agree(stok, w, wasm, in, []byte("old "+sid), 4000) // used 2000 ms, charged 2 x 2
	st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in})
	cid := firstField(body)
	if st != 200 || !strings.Contains(body, "cached") {
		t.Fatalf("hit: %d %s", st, body)
	}
	keep := e.submit(stok, wasm, in, 1000)
	testPool.Exec(ctx, `UPDATE jobs SET finished_at = now() - interval '31 days' WHERE id IN ($1, $2)`, jid, cid)
	testPool.Exec(ctx, `DELETE FROM job_stats_daily WHERE day = (now() - interval '31 days')::date`)
	if err := e.s.retention(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE id IN ($1, $2)`, jid, cid).Scan(&n)
	if n != 0 {
		t.Fatalf("old jobs kept: %d", n)
	}
	testPool.QueryRow(ctx, `SELECT count(*) FROM replicas WHERE job = $1`, jid).Scan(&n)
	if n != 0 {
		t.Fatalf("replicas kept: %d", n)
	}
	var jobs, ms, credits, cached, savedMs, savedCr int64
	if err := testPool.QueryRow(ctx, `SELECT jobs, ms, credits, cached, saved_ms, saved_credits FROM job_stats_daily WHERE day = (now() - interval '31 days')::date`).
		Scan(&jobs, &ms, &credits, &cached, &savedMs, &savedCr); err != nil {
		t.Fatal(err)
	}
	if jobs != 2 || ms != 2000 || credits != 4 || cached != 1 || savedMs != 2000 || savedCr != 4 {
		t.Fatalf("aggregate: jobs=%d ms=%d credits=%d cached=%d saved_ms=%d saved_credits=%d", jobs, ms, credits, cached, savedMs, savedCr)
	}
	if got := e.job(stok, keep, 0); got != keep+" queued" {
		t.Fatalf("recent job touched: %s", got)
	}
	_ = out
}

// --- exported API -------------------------------------------------------------------------------

func TestExportedSubmitStatus(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(2)
	me, err := e.d.LookupToken(ctx, stok)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := Submit(ctx, e.d, me, []Spec{{Wasm: wasm, In: in, Ms: 2000, Fresh: true}})
	if err != nil || len(ids) != 1 {
		t.Fatalf("Submit: %v %v", ids, err)
	}
	if v, err := Status(ctx, e.d, me, ids[0], 0); err != nil || v.Status != "queued" {
		t.Fatalf("Status: %+v %v", v, err)
	}
	if _, done, err := Output(ctx, e.d, me, ids[0]); err != nil || done {
		t.Fatalf("Output before done: %v %v", done, err)
	}
	out := e.put(w[0], []byte("exported "+sid))
	go func() {
		time.Sleep(150 * time.Millisecond)
		for i := 0; i < 2; i++ {
			l := e.mustLease(w[i])
			e.mustDone(w[i], l.Lease, "ok", out, 0, 100)
		}
	}()
	v, err := Status(ctx, e.d, me, ids[0], 5)
	if err != nil || v.Status != "done" || v.Out != out || v.Ms != 100 || v.Att == "" {
		t.Fatalf("Status done: %+v %v", v, err)
	}
	if b, done, err := Output(ctx, e.d, me, ids[0]); err != nil || !done || string(b) != "exported "+sid {
		t.Fatalf("Output: %q %v %v", b, done, err)
	}
	other, _ := e.d.LookupToken(ctx, w[0])
	if _, err := Status(ctx, e.d, other, ids[0], 0); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("stranger Status: %v", err)
	}
	if _, err := Status(ctx, e.d, me, "nope", 0); err == nil {
		t.Fatal("bad id accepted")
	}
	if _, err := Submit(ctx, e.d, me, []Spec{{Wasm: wasm, In: in, Lane: "sideways"}}); err == nil || !strings.HasPrefix(err.Error(), "err bad lane") {
		t.Fatalf("bad lane: %v", err)
	}
	var buf bytes.Buffer
	if err := e.d.Export(ctx, sid, &buf); err != nil || !strings.Contains(buf.String(), `"kind":"job"`) || !strings.Contains(buf.String(), ids[0]) || !strings.Contains(buf.String(), `"kind":"blob"`) {
		t.Fatalf("export: %v %s", err, buf.String())
	}
	if _, _, _, ok := e.d.Resolve(ctx, ids[0]); ok {
		t.Fatal("unpublished job resolved")
	}
	testPool.Exec(ctx, `UPDATE jobs SET published = true WHERE id = $1`, ids[0])
	if typ, _, url, ok := e.d.Resolve(ctx, ids[0]); !ok || typ != "job" || url != "/att/"+ids[0] {
		t.Fatalf("resolve: %s %s %v", typ, url, ok)
	}
}

func TestSystemSubmitUnfunded(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, stok, wasm, in, _, _ := e.setup(0)
	testPool.Exec(ctx, `UPDATE identities SET credits = 0 WHERE id = $1`, core.SystemID)
	_, err := SystemSubmit(ctx, e.d, []Spec{{Wasm: wasm, In: in, Ms: 1000}}, "kat")
	if !errors.Is(err, ErrUnfunded) {
		t.Fatalf("unfunded: %v", err)
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'unfunded' AND title LIKE 'compute: system root unfunded%'`).Scan(&n)
	if n < 1 {
		t.Fatal("no ops/unfunded event")
	}
	testPool.Exec(ctx, `UPDATE identities SET credits = 100 WHERE id = $1`, core.SystemID)
	ids, err := SystemSubmit(ctx, e.d, []Spec{{Wasm: wasm, In: in, Ms: 1000}}, "kat")
	if err != nil || len(ids) != 1 {
		t.Fatalf("funded: %v %v", ids, err)
	}
	var root, kind string
	var lvl, reps int
	var reserved int64
	testPool.QueryRow(ctx, `SELECT root, kind, sub_lvl, reserved, (SELECT count(*) FROM replicas WHERE job = $1) FROM jobs WHERE id = $1`, ids[0]).Scan(&root, &kind, &lvl, &reserved, &reps)
	if root != core.SystemID || kind != "kat" || lvl != 3 || reserved != 3 || reps != 2 {
		t.Fatalf("system job: root=%s kind=%s lvl=%d reserved=%d reps=%d", root, kind, lvl, reserved, reps)
	}
	if _, err := SystemSubmit(ctx, e.d, []Spec{{Wasm: wasm, In: in}}, "weird"); err == nil {
		t.Fatal("bad kind accepted")
	}
	_ = stok
}

// A system-root service-precompute job (svcget's janitor: kind "job" with a svc ref) that reaches a
// 2-replica consensus across distinct donor super-groups must finalize cache_scope="global" with
// att_d set, even when neither donor is trusted/L3 (SPEC-v2 27.6). Otherwise it stays root-scoped,
// att_d-false, and svcget (which serves only global att_d cache hits) can never serve the precompute.
func TestSystemPrecomputeGlobalScope(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, wid := e.setup(2) // two donors, distinct random IPs, neither trusted
	_ = stok
	testPool.Exec(ctx, `UPDATE identities SET credits = 100 WHERE id = $1`, core.SystemID)
	ids, err := SystemSubmit(ctx, e.d, []Spec{{Wasm: wasm, In: in, Ms: 2000, Svc: "cx-svc@1"}}, "job")
	if err != nil || len(ids) != 1 {
		t.Fatalf("precompute submit: %v %v", ids, err)
	}
	jid := ids[0]
	// Neither donor is trusted or L3: the system-precompute rule, not a trusted replica, globalises.
	for _, id := range wid {
		if lvl := core.Level(ctx, testPool, id); lvl >= 3 {
			t.Fatalf("donor %s unexpectedly L3", id)
		}
	}
	out := e.put(w[0], []byte("precompute result "+sid))
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], l0.Lease, "ok", out, 0, 1000)
	e.mustDone(w[1], l1.Lease, "ok", out, 0, 1000)
	if scope, attD, status, reason := e.jobRow(jid); status != "done" || scope != "global" || !attD {
		t.Fatalf("system precompute: status=%s reason=%s scope=%s att_d=%v", status, reason, scope, attD)
	}
	// svcget can now serve it: a global att_d cache hit exists for the (wasm, in, mb) key.
	v, ok, err := CacheLookup(ctx, testPool, wasm, in, "", defMb)
	if err != nil || !ok || v.Out != out || v.ID != jid {
		t.Fatalf("global cache hit: %+v ok=%v err=%v", v, ok, err)
	}
}

// --- REV3 (27.6) --------------------------------------------------------------------------------

func TestBlobReadOwnerLeaseOnly(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, _ := e.setup(1)
	_, otok := e.register("stranger")
	missing := strings.Repeat("0", 64)
	st1, b1, _ := e.do("GET", "/v1/b/"+wasm, otok, nil)
	st2, b2, _ := e.do("GET", "/v1/b/"+missing, otok, nil)
	if st1 != 404 || st2 != 404 || b1 != b2 {
		t.Fatalf("stranger must see a missing hash: %d %q vs %d %q", st1, b1, st2, b2)
	}
	if st, body, _ := e.do("GET", "/v1/b/"+wasm, stok, nil); st != 200 || body != string(minWasm(sid)) {
		t.Fatalf("owner: %d", st)
	}
	if st, _, _ := e.do("GET", "/v1/b/"+wasm, w[0], nil); st != 404 {
		t.Fatalf("donor without a lease: %d", st)
	}
	e.submit(stok, wasm, in, 1000)
	l := e.mustLease(w[0])
	for _, h := range []string{wasm, in} {
		if st, _, _ := e.do("GET", "/v1/b/"+h, w[0], nil, "X-Lease", l.Lease); st != 200 {
			t.Fatalf("X-Lease read %s: %d", h[:8], st)
		}
		if st, _, _ := e.do("HEAD", "/v1/b/"+h, w[0], nil, "X-Lease", l.Lease); st != 200 {
			t.Fatalf("X-Lease head %s: %d", h[:8], st)
		}
	}
	if st, _, _ := e.do("GET", "/v1/b/"+wasm, otok, nil, "X-Lease", l.Lease); st != 404 {
		t.Fatalf("a lease is bound to its donor identity: %d", st)
	}
	if st, _, _ := e.do("GET", "/v1/b/"+wasm, w[0], nil, "X-Lease", "lnope"); st != 200 {
		t.Fatalf("a v1 donor holding the lease still reads: %d", st)
	}
	out := e.put(w[0], []byte("out "+sid))
	e.mustDone(w[0], l.Lease, "ok", out, 0, 10)
	if st, _, _ := e.do("GET", "/v1/b/"+wasm, w[0], nil, "X-Lease", l.Lease); st != 404 {
		t.Fatalf("reported lease still reads: %d", st)
	}
	if st, _, _ := e.do("GET", "/v1/b/"+wasm, "", nil); st != 401 {
		t.Fatalf("anonymous private blob: %d", st)
	}
}

func TestPublishTextOrWasmOnly(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, _, _, _, _ := e.setup(0)
	_, otok := e.register("o")
	pub := func(tok, h string) (int, string) {
		st, body, _ := e.do("POST", "/v1/b/"+h+"/publish", tok, nil)
		return st, body
	}
	png := e.put(stok, append([]byte("\x89PNG\r\n\x1a\n"), []byte("fake png "+sid)...))
	if st, body := pub(stok, png); st != 400 || body != "err bad no media or archive hosting" {
		t.Fatalf("png: %d %s", st, body)
	}
	zipb := e.put(stok, buildZip(t, map[string]string{"a.txt": "hello " + sid}))
	if st, body := pub(stok, zipb); st != 400 || body != "err bad no media or archive hosting" {
		t.Fatalf("zip: %d %s", st, body)
	}
	bin := e.put(stok, append([]byte{0xff, 0xfe, 0x00, 0x01}, []byte(sid)...))
	if st, body := pub(stok, bin); st != 400 || body != "err bad no media or archive hosting" {
		t.Fatalf("binary: %d %s", st, body)
	}
	t2 := e.put(stok, []byte("notes live in /home/alice/notes "+sid))
	if st, body := pub(stok, t2); st != 400 || body != "err scrub path" {
		t.Fatalf("tier-2 finding: %d %s", st, body)
	}
	t1 := e.put(stok, []byte("token "+ghpKey+" "+sid))
	if st, body := pub(stok, t1); st != 400 || body != "err scrub key" {
		t.Fatalf("tier-1 finding: %d %s", st, body)
	}
	clean := e.put(stok, []byte("public note "+sid))
	if st, _ := pub(otok, clean); st != 404 {
		t.Fatalf("stranger publish: %d", st)
	}
	if st, body := pub(stok, clean); st != 200 || body != "ok public "+clean+" /v1/b/"+clean {
		t.Fatalf("publish text: %d %s", st, body)
	}
	st, body, hd := e.do("GET", "/v1/b/"+clean, "", nil)
	if st != 200 || body != "public note "+sid || !strings.HasPrefix(hd.Get("Cache-Control"), "public") {
		t.Fatalf("anonymous read of a public blob: %d %s %v", st, body, hd)
	}
	if st, _, _ := e.do("GET", "/v1/b/"+clean, otok, nil); st != 200 {
		t.Fatalf("stranger read of a public blob: %d", st)
	}
	wasm := e.put(stok, minWasm("pub "+sid))
	if st, body := pub(stok, wasm); st != 200 {
		t.Fatalf("publish wasm: %d %s", st, body)
	}
	junk := e.put(stok, []byte("\x00asm junk "+sid))
	if st, body := pub(stok, junk); st != 400 || !strings.HasPrefix(body, "err bad module does not scan") {
		t.Fatalf("publish junk wasm: %d %s", st, body)
	}
	st, body, _ = e.do("POST", "/v1/b?private=1", stok, []byte("private note "+sid))
	priv := firstField(body)
	if st != 200 {
		t.Fatalf("private upload: %d %s", st, body)
	}
	if st, body := pub(stok, priv); st != 400 || body != "err bad private blob cannot be published" {
		t.Fatalf("publish private: %d %s", st, body)
	}
	if st, body, _ := e.do("GET", "/v1/b/"+clean+"/info", otok, nil); st != 200 || !strings.Contains(body, " public=1") {
		t.Fatalf("public info: %d %s", st, body)
	}
}

func TestDataSegmentSecretFlagged(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, _, _ := e.setup(0)
	st, body, _ := e.do("POST", "/v1/b", stok, wasmWithData(sid, "config token "+ghpKey+" end"))
	flagged := firstField(body)
	if st != 200 || !strings.Contains(body, " kind=wasm scrub=key") {
		t.Fatalf("flagged upload: %d %s", st, body)
	}
	if st, body, _ := e.do("GET", "/v1/b/"+flagged+"/info", stok, nil); st != 200 || !strings.Contains(firstLine(body), " scrub=key") {
		t.Fatalf("info: %d %s", st, body)
	}
	st, body = e.submitBody(stok, map[string]any{"wasm": flagged, "in": in, "fresh": true})
	jid := firstField(body)
	if st != 202 || firstLine(body) != jid+" warn scrub key: donors are strangers" {
		t.Fatalf("flagged module submit: %d %s", st, body)
	}
	if got := e.job(stok, jid, 0); got != jid+" queued" {
		t.Fatalf("flagged job still queued: %s", got)
	}
	st, body, _ = e.do("POST", "/v1/j?f=json", stok, map[string]any{"wasm": flagged, "in": in, "fresh": true})
	var j map[string]any
	if st != 202 || json.Unmarshal([]byte(body), &j) != nil || j["warn"] != "scrub key: donors are strangers" {
		t.Fatalf("json warn: %d %s", st, body)
	}
	// A flagged UTF-8 input warns too; a private upload skips the scan.
	st, body, _ = e.do("POST", "/v1/b", stok, []byte("my key "+ghpKey))
	secretIn := firstField(body)
	if st != 200 || !strings.Contains(body, " scrub=key") {
		t.Fatalf("flagged input upload: %d %s", st, body)
	}
	if st, body = e.submitBody(stok, map[string]any{"wasm": wasm, "in": secretIn, "fresh": true}); st != 202 || !strings.Contains(firstLine(body), " warn scrub key: donors are strangers") {
		t.Fatalf("flagged input submit: %d %s", st, body)
	}
	if st, body, _ = e.do("POST", "/v1/b?private=1", stok, []byte("my private key "+ghpKey)); st != 200 || strings.Contains(body, "scrub=") {
		t.Fatalf("private upload scanned: %d %s", st, body)
	}
	if st, body = e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "fresh": true}); st == 202 && strings.Contains(body, "warn scrub") {
		t.Fatalf("clean submit warned: %s", body)
	}
}

func TestOpaqueTenureGC(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, _, _, _ := e.setup(0)
	opaque := append([]byte{0xff, 0xfe, 0x00, 0x80, 0xc3}, []byte("opaque "+sid)...)
	st, body, _ := e.do("POST", "/v1/b", stok, opaque)
	h := firstField(body)
	if st != 200 || !strings.Contains(body, " exp="+core.Date(time.Now().Add(24*time.Hour))+" kind=opaque") {
		t.Fatalf("opaque upload: %d %s", st, body)
	}
	for i := 0; i < 3; i++ {
		e.put(stok, opaque) // touches 1..3
	}
	if st, body, _ := e.do("POST", "/v1/b", stok, opaque); st != 429 || !strings.HasPrefix(body, "err quota blob tenure") {
		t.Fatalf("4th re-upload this week: %d %s", st, body)
	}
	used := append([]byte{0xff, 0xfe, 0x00}, []byte("used opaque "+sid)...)
	hu := e.put(stok, used)
	e.submit(stok, wasm, hu, 1000)
	text := e.put(stok, []byte("old text "+sid))
	st, body, _ = e.do("POST", "/v1/b?private=1", stok, []byte("private "+sid))
	priv := firstField(body)
	if st != 200 || !strings.Contains(body, " exp="+core.Date(time.Now().Add(24*time.Hour))) {
		t.Fatalf("private upload: %d %s", st, body)
	}
	testPool.Exec(ctx, `UPDATE blobs SET created = now() - interval '25 hours' WHERE hash = ANY($1)`, []string{h, hu, text, priv})
	if err := e.s.gcBlobs(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		hash string
		keep bool
	}{{h, false}, {hu, true}, {text, true}, {priv, false}} {
		_, ok, _ := blobSize(ctx, testPool, c.hash)
		_, ferr := os.Stat(e.s.blobPath(c.hash))
		if ok != c.keep || (ferr == nil) != c.keep {
			t.Fatalf("blob %s kept=%v file=%v want %v", c.hash[:8], ok, ferr == nil, c.keep)
		}
	}
	// L0/L1 roots hold at most 64 MiB of live opaque bytes; the L2 submitter above is not capped.
	l0, ltok := e.register("l0")
	testPool.Exec(ctx, `INSERT INTO blobs (hash, size, owner_root, kind, used_at) VALUES ($1, $2, $3, 'opaque', now())`, sha([]byte("fat "+l0)), int64(opaqueQuota), l0)
	if st, body, _ := e.do("POST", "/v1/b", ltok, append([]byte{0xff, 0xfe}, []byte("one more "+l0)...)); st != 429 || !strings.HasPrefix(body, "err quota opaque") {
		t.Fatalf("opaque quota: %d %s", st, body)
	}
	if st, _, _ := e.do("POST", "/v1/b", ltok, []byte("text is fine "+l0)); st != 200 {
		t.Fatalf("text under the opaque cap: %d", st)
	}
	testPool.Exec(ctx, `INSERT INTO blobs (hash, size, owner_root, kind, used_at) VALUES ($1, $2, $3, 'opaque', now())`, sha([]byte("fat "+sid)), int64(opaqueQuota), sid)
	if st, _, _ := e.do("POST", "/v1/b", stok, append([]byte{0xff, 0xfe}, []byte("one more "+sid)...)); st != 200 {
		t.Fatalf("L2 root over the L0 opaque cap: %d", st)
	}
}

func TestLaneOwnInvertsEligibility(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, wid := e.setup(1)
	if st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "lane": "sideways"}); st != 400 || !strings.HasPrefix(body, "err bad lane") {
		t.Fatalf("bad lane: %d %s", st, body)
	}
	st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in_text": "own input " + sid, "lane": "own"})
	jid := firstField(body)
	if (st != 200 && st != 202) || !core.ValidID(jid) {
		t.Fatalf("own submit: %d %s", st, body)
	}
	var reps int
	var private bool
	testPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM replicas WHERE job = $1), b.private FROM jobs j JOIN blobs b ON b.hash = j.input WHERE j.id = $1`, jid).Scan(&reps, &private)
	if reps != 1 || !private {
		t.Fatalf("own lane: replicas=%d private_in=%v", reps, private)
	}
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 204 {
		t.Fatalf("a stranger donor got an own-lane job: %d", st)
	}
	st, l := e.lease(stok, 30000, 256, 0)
	if st != 200 || l.Job != jid || l.Lane != "own" {
		t.Fatalf("own root lease: %d %+v", st, l)
	}
	if st, _, _ := e.do("GET", "/v1/b/"+l.In, w[0], nil, "X-Lease", l.Lease); st != 404 {
		t.Fatalf("private input leaked: %d", st)
	}
	out := e.put(stok, []byte("own out "+sid))
	rep := e.rep(sid)
	e.mustDone(stok, l.Lease, "ok", out, 0, 500)
	if got := e.job(stok, jid, 0); got != jid+" done out="+out+" ms=500" {
		t.Fatalf("own done: %s", got)
	}
	if e.credits(sid) != 100 || e.rep(sid) != rep {
		t.Fatalf("own lane charges and pays nothing: credits %d rep %d -> %d", e.credits(sid), rep, e.rep(sid))
	}
	var att string
	var attD bool
	testPool.QueryRow(ctx, `SELECT att, att_d FROM jobs WHERE id = $1`, jid).Scan(&att, &attD)
	if attD || !strings.Contains(att, " n=1/1 d=0 ") || !strings.HasSuffix(att, " lane=own") {
		t.Fatalf("own att: %q d=%v", att, attD)
	}
	st, body = e.submitBody(stok, map[string]any{"wasm": wasm, "in": l.In, "lane": "own"})
	if (st != 200 && st != 202) || strings.Contains(body, "cached") {
		t.Fatalf("own lane never reads the cache: %d %s", st, body)
	}
	if st, _, _ := e.do("DELETE", "/v1/j/"+firstField(body), stok, nil); st != 200 || e.credits(sid) != 100 {
		t.Fatalf("cancel second own job: %d credits %d", st, e.credits(sid))
	}
	if st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": l.In}); st != 400 || body != "err bad private blobs run on lane own only" {
		t.Fatalf("private blob on the public lane: %d %s", st, body)
	}
	// Lane trusted: one replica for a trusted donor, charged 2x, d=1, root scope.
	st, body = e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "ms": 1000, "lane": "trusted", "fresh": true})
	tj := firstField(body)
	if (st != 200 && st != 202) || !core.ValidID(tj) || e.credits(sid) != 94 {
		t.Fatalf("trusted submit: %d %s credits %d", st, body, e.credits(sid))
	}
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 204 {
		t.Fatalf("untrusted donor got a trusted-lane job: %d", st)
	}
	testPool.Exec(ctx, `UPDATE identities SET trusted = true WHERE id = $1`, wid[0])
	st, l = e.lease(w[0], 30000, 256, 0)
	if st != 200 || l.Job != tj || l.Lane != "trusted" {
		t.Fatalf("trusted lease: %d %+v", st, l)
	}
	e.mustDone(w[0], l.Lease, "ok", out, 0, 500)
	if got := e.job(stok, tj, 0); got != tj+" done out="+out+" ms=500" || e.credits(sid) != 98 || e.credits(wid[0]) != 102 {
		t.Fatalf("trusted done: %s sub %d donor %d", got, e.credits(sid), e.credits(wid[0]))
	}
	if scope, attD, _, _ := e.jobRow(tj); scope != "root" || !attD {
		t.Fatalf("trusted lane: scope=%s att_d=%v", scope, attD)
	}
	if e.rep(wid[0]) != 0 {
		t.Fatalf("single-replica lane earned rep: %d", e.rep(wid[0]))
	}
}

func TestFsInCacheKey(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(2)
	a := "A = 1 # " + sid + "\n" // archive/zip output is deterministic: unique content per root
	z1 := e.put(stok, buildZip(t, map[string]string{"lib/a.py": a}))
	z2 := e.put(stok, buildZip(t, map[string]string{"lib/b.py": "B = 2 # " + sid + "\n"}))
	if st, body, _ := e.do("GET", "/v1/b/"+z1+"/info", stok, nil); st != 200 || !strings.HasPrefix(body, fmt.Sprintf("zip entries=1 unpacked=%dB fs_ok=1 scrub=clean", len(a))) {
		t.Fatalf("zip info: %d %s", st, body)
	}
	if st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "fs": in}); st != 400 || body != "err bad fs must be a zip blob" {
		t.Fatalf("fs not a zip: %d %s", st, body)
	}
	st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "fs": z1, "ms": 2000, "fresh": true})
	jid := firstField(body)
	if (st != 200 && st != 202) || !core.ValidID(jid) {
		t.Fatalf("fs submit: %d %s", st, body)
	}
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	if l0.FS != z1 || l1.FS != z1 {
		t.Fatalf("lease fs: %q %q", l0.FS, l1.FS)
	}
	if st, _, _ := e.do("GET", "/v1/b/"+z1, w[0], nil, "X-Lease", l0.Lease); st != 200 {
		t.Fatalf("donor reads the fs blob under its lease: %d", st)
	}
	out := e.put(w[0], []byte("fs out "+sid))
	e.mustDone(w[0], l0.Lease, "ok", out, 0, 1000)
	e.mustDone(w[1], l1.Lease, "ok", out, 0, 1000)
	if got := e.job(stok, jid, 0); got != jid+" done out="+out+" ms=1000" {
		t.Fatalf("fs done: %s", got)
	}
	var att string
	testPool.QueryRow(ctx, `SELECT att FROM jobs WHERE id = $1`, jid).Scan(&att)
	if !strings.HasSuffix(att, " f="+z1) {
		t.Fatalf("att without fs: %q", att)
	}
	if st, body = e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "fs": z1}); st != 200 || !strings.Contains(firstLine(body), " done out="+out+" ms=0 cached") {
		t.Fatalf("same fs must hit: %d %s", st, body)
	}
	for _, body := range []map[string]any{{"wasm": wasm, "in": in}, {"wasm": wasm, "in": in, "fs": z2}} {
		if st, got := e.submitBody(stok, body); (st != 200 && st != 202) || strings.Contains(got, "cached") {
			t.Fatalf("different fs must miss: %d %s", st, got)
		}
	}
	if v, ok, _ := CacheLookup(ctx, testPool, wasm, in, z1, defMb); ok || v != nil {
		t.Fatal("root-scoped fs result served as global")
	}
}

func TestProbationCapsNewL0(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok := e.register("l0")
	wasm, in := e.put(stok, minWasm(sid)), e.put(stok, []byte("in "+sid))
	_, w2 := e.register("v2donor")
	_, w1 := e.register("v1donor")
	st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "fresh": true})
	j1 := firstField(body)
	if (st != 200 && st != 202) || !strings.Contains(body, "\nprobation (opt-in donors only, eta may be longer)") {
		t.Fatalf("probation line: %d %s", st, body)
	}
	v2 := func(caps ...string) (int, *leaseOut) {
		st, l, _ := e.leaseV2(w2, map[string]any{"max_ms": 30000, "max_mb": 256, "ver": 2, "caps": caps})
		return st, l
	}
	if st, _ := v2(); st != 204 {
		t.Fatalf("ver 2 without caps: %d", st)
	}
	if st, _ := v2("new"); st != 204 {
		t.Fatalf("new without l0 (L0 submitter): %d", st)
	}
	if st, _ := v2("l0"); st != 204 {
		t.Fatalf("l0 without new (module under probation): %d", st)
	}
	if st, l := v2("new", "l0"); st != 200 || l.Job != j1 {
		t.Fatalf("new+l0: %d", st)
	}
	if st, l := e.lease(w1, 30000, 256, 0); st != 200 || l.Job != j1 {
		t.Fatalf("a v1 donor keeps the v1 contract: %d", st)
	}
	testPool.Exec(ctx, `UPDATE blob_meta SET runs_ok = 3 WHERE hash = $1`, wasm)
	st, body = e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "fresh": true})
	j2 := firstField(body)
	if strings.Contains(body, "probation") {
		t.Fatalf("out of probation: %s", body)
	}
	if st, l := v2("l0"); st != 200 || l.Job != j2 {
		t.Fatalf("l0 only after probation: %d", st)
	}
	e.promote(sid)
	st, body = e.submitBody(stok, map[string]any{"wasm": wasm, "in": in, "fresh": true})
	j3 := firstField(body)
	if st, l := v2("new"); st != 200 || l.Job != j3 {
		t.Fatalf("L2 submitter without l0: %d", st)
	}
	var lvl int
	testPool.QueryRow(ctx, `SELECT sub_lvl FROM jobs WHERE id = $1`, j3).Scan(&lvl)
	if lvl != 2 {
		t.Fatalf("sub_lvl=%d", lvl)
	}
}

func TestDsigVerified(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, wid := e.setup(3)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	testPool.Exec(ctx, `UPDATE identities SET pub = $2 WHERE id = $1`, wid[0], []byte(pub))
	jid := e.submit(stok, wasm, in, 1000)
	out := e.put(w[0], []byte("signed "+sid))
	l0 := e.mustLease(w[0])
	fp := "ok:0:" + out
	done := func(tok, lease, dsig string) (int, string) {
		st, body, _ := e.do("POST", "/v1/w/done", tok, map[string]any{"lease": lease, "status": "ok", "out": out, "ms": 100, "dsig": dsig})
		return st, body
	}
	bad := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte("something else")))
	if st, body := done(w[0], l0.Lease, bad); st != 400 || !strings.HasPrefix(body, "err badsig") {
		t.Fatalf("bad dsig: %d %s", st, body)
	}
	var state string
	var excl []string
	testPool.QueryRow(ctx, `SELECT state, excluded_roots FROM replicas WHERE id = (SELECT id FROM replicas WHERE job = $1 ORDER BY id LIMIT 1)`, jid).Scan(&state, &excl)
	var queued int
	testPool.QueryRow(ctx, `SELECT count(*) FROM replicas WHERE job = $1 AND state = 'queued'`, jid).Scan(&queued)
	if queued != 2 {
		t.Fatalf("bad dsig must requeue (not report): queued=%d", queued)
	}
	testPool.QueryRow(ctx, `SELECT count(*) FROM replicas WHERE job = $1 AND $2 = ANY(excluded_roots)`, jid, wid[0]).Scan(&queued)
	if queued != 1 {
		t.Fatalf("requeued replica not excluded for the signer: %d", queued)
	}
	if st, body := done(w[0], "lnope", bad); st != 404 {
		t.Fatalf("unknown lease: %d %s", st, body)
	}
	l0b := e.mustLease(w[0]) // the other replica
	good := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, dsigMessage(jid, l0b.Lease, fp)))
	if st, body := done(w[0], l0b.Lease, good); st != 200 {
		t.Fatalf("good dsig: %d %s", st, body)
	}
	var stored []byte
	testPool.QueryRow(ctx, `SELECT dsig FROM replicas WHERE lease = $1`, l0b.Lease).Scan(&stored)
	if !bytes.Equal(stored, ed25519.Sign(priv, dsigMessage(jid, l0b.Lease, fp))) {
		t.Fatal("dsig not stored")
	}
	// A donor without a registered pub cannot sign; its lease is requeued and excluded for it too.
	l1 := e.mustLease(w[1])
	if st, body := done(w[1], l1.Lease, good); st != 400 || !strings.HasPrefix(body, "err badsig") {
		t.Fatalf("dsig without pub: %d %s", st, body)
	}
	if st, _ := e.lease(w[1], 30000, 256, 0); st != 204 {
		t.Fatalf("excluded donor leased the replica again: %d", st)
	}
	l2 := e.mustLease(w[2])
	e.mustDone(w[2], l2.Lease, "ok", out, 0, 100)
	if got := e.job(stok, jid, 0); got != jid+" done out="+out+" ms=100" {
		t.Fatalf("done: %s", got)
	}
	var att string
	testPool.QueryRow(ctx, `SELECT att FROM jobs WHERE id = $1`, jid).Scan(&att)
	if !strings.Contains(att, " n=2/2 d=1 ") || !strings.HasSuffix(att, " ds=1") {
		t.Fatalf("att ds: %q", att)
	}
	if st, body := done(w[0], l0b.Lease, "not base64!!"); st != 400 || !strings.HasPrefix(body, "err badsig") {
		t.Fatalf("malformed dsig: %d %s", st, body)
	}
}

func TestDiagStored(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(3)
	jid := e.submit(stok, wasm, in, 2000)
	out := e.put(w[0], []byte("diag out "+sid))
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	stderr := base64.StdEncoding.EncodeToString([]byte("panic: boom\n"))
	diag := map[string]any{"stderr": stderr, "trace": "wasm stack trace:\n  main.main", "compile_ms": 3000, "mem_pages": 40}
	st, body, _ := e.do("POST", "/v1/w/done", w[0], map[string]any{"lease": l0.Lease, "status": "exit", "out": out, "code": 1, "ms": 100, "diag": diag})
	if st != 200 {
		t.Fatalf("done with diag: %d %s", st, body)
	}
	var stored map[string]any
	var raw []byte
	testPool.QueryRow(ctx, `SELECT diag FROM replicas WHERE lease = $1`, l0.Lease).Scan(&raw)
	if json.Unmarshal(raw, &stored) != nil || stored["stderr"] != base64.RawURLEncoding.EncodeToString([]byte("panic: boom\n")) || stored["compile_ms"] != float64(3000) || stored["mem_pages"] != float64(40) || stored["trace"] != "wasm stack trace:\n  main.main" {
		t.Fatalf("stored diag: %s", raw)
	}
	var compileMs, memPages []int32
	testPool.QueryRow(ctx, `SELECT compile_ms, mem_pages FROM blob_meta WHERE hash = $1`, wasm).Scan(&compileMs, &memPages)
	if len(compileMs) != 1 || compileMs[0] != 3000 || len(memPages) != 1 || memPages[0] != 40 {
		t.Fatalf("samples: %v %v", compileMs, memPages)
	}
	if st, body, _ := e.do("GET", "/v1/b/"+wasm+"/info", stok, nil); st != 200 || !strings.Contains(body, " compile_ms_p50=3000 mem_p50=3MiB") || !strings.Contains(body, "\nwarn compile uses 30 % of a 10 s budget; set ms>=20000") {
		t.Fatalf("info hints: %d %s", st, body)
	}
	big := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), maxStderr+1))
	if st, body, _ := e.do("POST", "/v1/w/done", w[1], map[string]any{"lease": l1.Lease, "status": "exit", "out": out, "code": 1, "ms": 100, "diag": map[string]any{"stderr": big}}); st != 400 || !strings.HasPrefix(body, "err bad diag.stderr") {
		t.Fatalf("oversize stderr: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/w/done", w[1], map[string]any{"lease": l1.Lease, "status": "ok", "out": out, "code": "compile-timeout", "ms": 1}); st != 400 || !strings.HasPrefix(body, "err bad a code word needs status error") {
		t.Fatalf("code word with status ok: %d %s", st, body)
	}
	e.mustDone(w[1], l1.Lease, "exit", out, 1, 100)
	if got := e.job(stok, jid, 0); got != jid+" done out="+out+" ms=100 code=1" {
		t.Fatalf("done: %s", got)
	}
	// Three distinct donors reporting compile-timeout ban the module.
	ct := func(tok, lease string) {
		t.Helper()
		st, body, _ := e.do("POST", "/v1/w/done", tok, map[string]any{"lease": lease, "status": "error", "code": "compile-timeout", "ms": 10000, "diag": map[string]any{"compile_ms": 10000}})
		if st != 200 {
			t.Fatalf("compile-timeout report: %d %s", st, body)
		}
	}
	jid2 := e.submit(stok, wasm, in, 1000)
	a, b := e.mustLease(w[0]), e.mustLease(w[1])
	ct(w[0], a.Lease)
	ct(w[1], b.Lease)
	if got := e.job(stok, jid2, 0); got != jid2+" failed error" {
		t.Fatalf("agreed compile-timeout: %s", got)
	}
	var timeouts int
	var banned string
	testPool.QueryRow(ctx, `SELECT compile_timeouts, banned FROM blob_meta WHERE hash = $1`, wasm).Scan(&timeouts, &banned)
	if timeouts != 2 || banned != "" {
		t.Fatalf("after two donors: timeouts=%d banned=%q", timeouts, banned)
	}
	jid3 := e.submit(stok, wasm, in, 1000)
	before := e.credits(sid)
	c := e.mustLease(w[2])
	ct(w[2], c.Lease)
	testPool.QueryRow(ctx, `SELECT compile_timeouts, banned FROM blob_meta WHERE hash = $1`, wasm).Scan(&timeouts, &banned)
	if timeouts != 3 || banned != "compile-bomb" {
		t.Fatalf("after three donors: timeouts=%d banned=%q", timeouts, banned)
	}
	if got := e.job(stok, jid3, 0); got != jid3+" failed compile-bomb" || e.credits(sid) != before+3 {
		t.Fatalf("ban cancels with refund: %s credits %d -> %d", got, before, e.credits(sid))
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = $1 AND title LIKE '%banned compile-bomb'`, wasm).Scan(&n)
	if n != 1 {
		t.Fatalf("revocation event: %d", n)
	}
	if st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in}); st != 400 || body != "err bad module compile-bomb" {
		t.Fatalf("banned submit: %d %s", st, body)
	}
	if st, body, _ := e.do("GET", "/v1/b/"+wasm+"/info", stok, nil); st != 200 || !strings.Contains(body, " banned=compile-bomb") {
		t.Fatalf("info banned: %d %s", st, body)
	}
	// The ban survives deletion and re-upload of the module.
	if st, body, _ := e.do("DELETE", "/v1/b/"+wasm, stok, nil); st != 200 {
		t.Fatalf("delete banned module: %d %s", st, body)
	}
	if h := e.put(stok, minWasm(sid)); h != wasm {
		t.Fatal("re-upload hash")
	}
	if st, body := e.submitBody(stok, map[string]any{"wasm": wasm, "in": in}); st != 400 || body != "err bad module compile-bomb" {
		t.Fatalf("ban must survive re-upload: %d %s", st, body)
	}
}
