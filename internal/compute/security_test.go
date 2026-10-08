package compute

// Regression tests for SECURITY-REVIEW-1 findings #1, #4a, #4b, #4c, #5, #7, #8.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
)

// #1: agreed `error` earns no credits and no rep; the submitter still pays 1 per replica.
func TestErrorAgreementEarnsNothing(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, wid := e.setup(2)
	jid := e.submit(stok, wasm, in, 1000) // reserve 3
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], l0.Lease, "error", "", 0, 1000)
	e.mustDone(w[1], l1.Lease, "error", "", 0, 1000)
	if got := e.job(stok, jid, 0); got != jid+" failed error" {
		t.Fatalf("status: %s", got)
	}
	if e.credits(wid[0]) != 100 || e.credits(wid[1]) != 100 || e.rep(wid[0]) != 0 || e.rep(wid[1]) != 0 {
		t.Fatalf("error must not pay: %d %d rep %d %d", e.credits(wid[0]), e.credits(wid[1]), e.rep(wid[0]), e.rep(wid[1]))
	}
	if e.credits(sid) != 98 {
		t.Fatalf("submitter must pay 1 per replica run: %d", e.credits(sid))
	}
}

// #1: agreed timeout/oom reported with ms < 50 earns nothing; total paid never exceeds the charge.
func TestFastTimeoutEarnsNothing(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, wid := e.setup(2)
	jid := e.submit(stok, wasm, in, 1000)
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], l0.Lease, "oom", "", 0, 0)
	e.mustDone(w[1], l1.Lease, "oom", "", 0, 49)
	if got := e.job(stok, jid, 0); got != jid+" failed oom" {
		t.Fatalf("status: %s", got)
	}
	if e.credits(wid[0]) != 100 || e.credits(wid[1]) != 100 || e.rep(wid[0]) != 0 || e.rep(wid[1]) != 0 {
		t.Fatalf("fast oom must not pay: %d %d", e.credits(wid[0]), e.credits(wid[1]))
	}
	if e.credits(sid) != 98 {
		t.Fatalf("submitter: %d", e.credits(sid))
	}
	// Honest short job: used_s = 1, charge 2, pay min(2, 2/2) = 1 each: paid 2 <= charged 2.
	jid2 := e.submit(stok, wasm, in, 1000)
	out := e.put(w[0], []byte("quick"))
	a, b := e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], a.Lease, "ok", out, 0, 60)
	e.mustDone(w[1], b.Lease, "ok", out, 0, 70)
	if got := e.job(stok, jid2, 0); !strings.HasPrefix(got, jid2+" done") {
		t.Fatalf("status: %s", got)
	}
	if e.credits(wid[0]) != 101 || e.credits(wid[1]) != 101 || e.credits(sid) != 96 {
		t.Fatalf("paid %d+%d, submitter %d", e.credits(wid[0])-100, e.credits(wid[1])-100, e.credits(sid))
	}
}

// #1: agreeing roots registered from the same IP (or the submitter's IP) earn credits but no rep.
func TestSameIPAgreementNoRep(t *testing.T) {
	e := newEnv(t, false)
	ip := randIP()
	sid, stok := e.registerIP("sub", randIP())
	e.promote(sid)
	wasm, in := e.put(stok, minWasm(sid)), e.put(stok, []byte("in "+sid))
	wa, ta := e.registerIP("wa", ip)
	wb, tb := e.registerIP("wb", ip)
	jid := e.submit(stok, wasm, in, 2000)
	out := e.put(ta, []byte("same ip out"))
	a, b := e.mustLease(ta), e.mustLease(tb)
	e.mustDone(ta, a.Lease, "ok", out, 0, 1500)
	e.mustDone(tb, b.Lease, "ok", out, 0, 1500)
	if got := e.job(stok, jid, 0); !strings.HasPrefix(got, jid+" done") {
		t.Fatalf("status: %s", got)
	}
	if e.credits(wa) != 102 || e.credits(wb) != 102 {
		t.Fatalf("credits still paid from charge: %d %d", e.credits(wa), e.credits(wb))
	}
	if e.rep(wa) != 0 || e.rep(wb) != 0 {
		t.Fatalf("same-IP agreement must not earn rep: %d %d", e.rep(wa), e.rep(wb))
	}
	// Worker sharing the submitter's IP: no rep either.
	sip := randIP()
	sid2, stok2 := e.registerIP("sub2", sip)
	e.promote(sid2)
	wasm2, in2 := e.put(stok2, minWasm(sid2)), e.put(stok2, []byte("in "+sid2))
	wc, tc := e.registerIP("wc", sip)
	wd, td := e.registerIP("wd", randIP())
	jid2 := e.submit(stok2, wasm2, in2, 2000)
	c, d := e.mustLease(tc), e.mustLease(td)
	e.mustDone(tc, c.Lease, "ok", out, 0, 100)
	e.mustDone(td, d.Lease, "ok", out, 0, 100)
	if got := e.job(stok2, jid2, 0); !strings.HasPrefix(got, jid2+" done") {
		t.Fatalf("status: %s", got)
	}
	if e.rep(wc) != 0 || e.rep(wd) != 0 {
		t.Fatalf("submitter-IP agreement must not earn rep: %d %d", e.rep(wc), e.rep(wd))
	}
}

// #1: replica assignment is random among the oldest window, not strictly FIFO.
func TestLeaseRandomAssignment(t *testing.T) {
	e := newEnv(t, false)
	_, stok, wasm, in, w, _ := e.setup(1)
	var jobs []string
	for i := 0; i < 20; i++ {
		jobs = append(jobs, e.submit(stok, wasm, in, 1000))
	}
	oldest, err := scanInts(testPool.Query(context.Background(), `SELECT id FROM replicas WHERE job = ANY($1) ORDER BY created, id LIMIT 4`, jobs))
	if err != nil || len(oldest) != 4 {
		t.Fatal(err, oldest)
	}
	var got []int64
	for i := 0; i < maxLeases; i++ {
		l := e.mustLease(w[0])
		var rid int64
		testPool.QueryRow(context.Background(), `SELECT id FROM replicas WHERE lease = $1`, l.Lease).Scan(&rid)
		got = append(got, rid)
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	if reflect.DeepEqual(got, oldest) { // P = 1/C(40,4) under random assignment
		t.Fatalf("leases handed out strictly oldest-first: %v", got)
	}
}

// #7: at most maxLeases live leases per worker root; 204 at the cap.
func TestLeaseCap(t *testing.T) {
	e := newEnv(t, false)
	_, stok, wasm, in, w, _ := e.setup(1)
	for i := 0; i < maxLeases+1; i++ {
		e.submit(stok, wasm, in, 1000)
	}
	var leases []*leaseOut
	for i := 0; i < maxLeases; i++ {
		leases = append(leases, e.mustLease(w[0]))
	}
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 204 {
		t.Fatalf("over cap: %d", st)
	}
	e.mustDone(w[0], leases[0].Lease, "error", "", 0, 0)
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 200 {
		t.Fatalf("after report: %d", st)
	}
}

// #7: expiry penalty is capped at expireRepCap per root per day.
func TestExpiryPenaltyCap(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, stok, wasm, in, w, wid := e.setup(1)
	for i := 0; i < 6; i++ {
		e.submit(stok, wasm, in, 1000)
	}
	expire := func(n int) {
		for i := 0; i < n; i++ {
			e.mustLease(w[0])
		}
		testPool.Exec(ctx, `UPDATE replicas SET deadline = now() - interval '1 second' WHERE worker_root = $1 AND state = 'leased'`, wid[0])
		e.d.Janitor.RunOnce(ctx)
	}
	expire(4)
	if e.rep(wid[0]) != -4 {
		t.Fatalf("rep after 4 expiries: %d", e.rep(wid[0]))
	}
	expire(2)
	if e.rep(wid[0]) != -expireRepCap {
		t.Fatalf("rep must be capped at -%d/day: %d", expireRepCap, e.rep(wid[0]))
	}
}

// #4b: timeout-vs-completed and timeout-vs-oom splits are never penalised.
func TestTimingSplitNoPenalty(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, wid := e.setup(3)
	jid := e.submit(stok, wasm, in, 2000)
	out := e.put(w[0], []byte("slow but right"))
	a, b := e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], a.Lease, "ok", out, 0, 1900)
	e.mustDone(w[1], b.Lease, "timeout", "", 0, 2000)
	c := e.mustLease(w[2])
	if c.Job != jid {
		t.Fatalf("tie-break: %+v", c)
	}
	e.mustDone(w[2], c.Lease, "ok", out, 0, 1800)
	if got := e.job(stok, jid, 0); got != fmt.Sprintf("%s done out=%s ms=1900", jid, out) {
		t.Fatalf("status: %s", got)
	}
	if e.rep(wid[1]) != 0 || e.credits(wid[1]) != 100 {
		t.Fatalf("timeout minority penalised: rep %d credits %d", e.rep(wid[1]), e.credits(wid[1]))
	}
	if e.rep(wid[0]) != 1 || e.rep(wid[2]) != 1 {
		t.Fatalf("majority rep: %d %d", e.rep(wid[0]), e.rep(wid[2]))
	}
	// used_s = 2, 3 replicas: charge 6, pay min(3, 6/2) = 3 each.
	if e.credits(wid[0]) != 103 || e.credits(wid[2]) != 103 || e.credits(sid) != 94 {
		t.Fatalf("credits: %d %d sub %d", e.credits(wid[0]), e.credits(wid[2]), e.credits(sid))
	}
	// timeout vs oom, timeout wins: oom minority not penalised.
	jid2 := e.submit(stok, wasm, in, 1000)
	a, b = e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], a.Lease, "timeout", "", 0, 1000)
	e.mustDone(w[1], b.Lease, "oom", "", 0, 900)
	c = e.mustLease(w[2])
	e.mustDone(w[2], c.Lease, "timeout", "", 0, 1000)
	if got := e.job(stok, jid2, 0); got != jid2+" failed timeout" {
		t.Fatalf("status: %s", got)
	}
	if e.rep(wid[1]) != 0 {
		t.Fatalf("oom minority penalised: %d", e.rep(wid[1]))
	}
	// Completed vs completed with different output: the minority is penalised (unchanged).
	jid3 := e.submit(stok, wasm, in, 1000)
	bad := e.put(w[1], []byte("wrong"))
	a, b = e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], a.Lease, "ok", out, 0, 100)
	e.mustDone(w[1], b.Lease, "ok", bad, 0, 100)
	c = e.mustLease(w[2])
	e.mustDone(w[2], c.Lease, "ok", out, 0, 100)
	if got := e.job(stok, jid3, 0); !strings.HasPrefix(got, jid3+" done") || e.rep(wid[1]) != -5 {
		t.Fatalf("cheater: %s rep %d", got, e.rep(wid[1]))
	}
}

// #4a: outputs uploaded under X-Lease bypass the worker quota and belong to the submitter root;
// outputs uploaded plainly are handed to the submitter root on done.
func TestOutputBlobOwnership(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, wid := e.setup(2)
	e.submit(stok, wasm, in, 1000)
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	// Worker 0 is at its quota: plain upload refused, leased upload accepted.
	testPool.Exec(ctx, `INSERT INTO blobs (hash, size, owner_root) VALUES ($1, $2, $3)`, sha([]byte("full "+wid[0])), int64(blobQuota), wid[0])
	out := []byte("output of " + sid)
	if st, body, _ := e.do("POST", "/v1/b", w[0], out); st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("plain upload at quota: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/b", w[0], out, "X-Lease", "lnope"); st != 404 {
		t.Fatalf("unknown lease: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/b", w[1], out, "X-Lease", l0.Lease); st != 404 {
		t.Fatalf("foreign lease: %d %s", st, body)
	}
	st, body, _ := e.do("POST", "/v1/b", w[0], out, "X-Lease", l0.Lease)
	if body = firstField(body); st != 200 || body != sha(out) {
		t.Fatalf("leased upload: %d %s", st, body)
	}
	var owner string
	testPool.QueryRow(ctx, `SELECT owner_root FROM blobs WHERE hash = $1`, body).Scan(&owner)
	if owner != sid {
		t.Fatalf("leased output owner %s, want submitter %s", owner, sid)
	}
	if st, _, _ := e.do("POST", "/v1/b", w[0], bytes.Repeat([]byte("y"), maxBlob+1), "X-Lease", l0.Lease); st != 413 {
		t.Fatalf("leased upload over 16 MiB: %d", st)
	}
	// Plain upload by worker 1, transferred on done.
	out2 := e.put(w[1], []byte("other output "+sid))
	testPool.QueryRow(ctx, `SELECT owner_root FROM blobs WHERE hash = $1`, out2).Scan(&owner)
	if owner != wid[1] {
		t.Fatalf("plain upload owner %s", owner)
	}
	e.mustDone(w[1], l1.Lease, "ok", out2, 0, 10)
	testPool.QueryRow(ctx, `SELECT owner_root FROM blobs WHERE hash = $1`, out2).Scan(&owner)
	if owner != sid {
		t.Fatalf("done must transfer output to submitter: owner %s", owner)
	}
	e.mustDone(w[0], l0.Lease, "ok", body, 0, 10)
}

// SECURITY-REVIEW-2 #6: an X-Lease donor output is attributed to the submitter root and must still
// obey the submitter's per-root 256 MiB cap, else a single leased donor stores unbounded blobs past
// it. A fully exempt system write (admin/seed pin, joblog) keeps its waiver so system-root paths are
// unaffected.
func TestLeaseOutputBoundBySubmitterQuota(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(2)
	e.submit(stok, wasm, in, 1000)
	l0 := e.mustLease(w[0])
	e.mustLease(w[1])
	// Submitter sits at its per-root cap: a leased donor output attributed to it is refused, exactly
	// like one of the submitter's own uploads would be.
	testPool.Exec(ctx, `INSERT INTO blobs (hash, size, owner_root) VALUES ($1, $2, $3)`, sha([]byte("subfull "+sid)), int64(blobQuota), sid)
	out := []byte("leased output over the submitter cap " + sid)
	if st, body, _ := e.do("POST", "/v1/b", w[0], out, "X-Lease", l0.Lease); st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("leased upload past submitter cap: %d %s", st, body)
	}
	// A fully exempt system pin stays waived even with the system root itself at the cap, so the
	// admin/joblog system-root paths are not broken by the new bound.
	sysFull := sha([]byte("sysfull " + sid))
	testPool.Exec(ctx, `INSERT INTO blobs (hash, size, owner_root) VALUES ($1, $2, $3)`, sysFull, int64(blobQuota), core.SystemID)
	pin, _, err := e.s.putBlob(ctx, core.SystemID, bytes.NewReader([]byte("sys pin "+sid)), putOpts{exempt: true, pinnedBy: "admin", max: maxBlob})
	t.Cleanup(func() {
		c := context.Background()
		hashes := []string{sysFull}
		if pin != nil {
			hashes = append(hashes, pin.hash)
		}
		testPool.Exec(c, `DELETE FROM blob_meta WHERE hash = ANY($1)`, hashes)
		testPool.Exec(c, `DELETE FROM blobs WHERE hash = ANY($1)`, hashes)
	})
	if err != nil {
		t.Fatalf("exempt system pin must bypass the per-root cap: %v", err)
	}
}

// #7: blob reads: owner, live lease holder (wasm/in), submitter root (wasm/in/out); else 404.
func TestBlobReadAccess(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, stok, wasm, in, w, _ := e.setup(2)
	_, otok := e.register("stranger")
	for _, h := range []string{wasm, in} {
		if st, _, _ := e.do("GET", "/v1/b/"+h, w[0], nil); st != 404 {
			t.Fatalf("worker without lease read %s: %d", h[:8], st)
		}
	}
	jid := e.submit(stok, wasm, in, 1000)
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	for _, h := range []string{wasm, in} {
		if st, _, _ := e.do("GET", "/v1/b/"+h, w[0], nil); st != 200 {
			t.Fatalf("lease holder read %s: %d", h[:8], st)
		}
		if st, _, _ := e.do("HEAD", "/v1/b/"+h, otok, nil); st != 404 {
			t.Fatalf("stranger read %s: %d", h[:8], st)
		}
	}
	out := []byte("secret output " + jid)
	st, oh, _ := e.do("POST", "/v1/b", w[0], out, "X-Lease", l0.Lease)
	if oh = firstField(oh); st != 200 {
		t.Fatalf("upload: %d", st)
	}
	if st, _, _ := e.do("GET", "/v1/b/"+oh, otok, nil); st != 404 {
		t.Fatalf("stranger read output: %d", st)
	}
	e.mustDone(w[0], l0.Lease, "ok", oh, 0, 10)
	e.mustDone(w[1], l1.Lease, "ok", oh, 0, 10)
	if got := e.job(stok, jid, 0); !strings.HasPrefix(got, jid+" done out="+oh) {
		t.Fatalf("status: %s", got)
	}
	if st, body, _ := e.do("GET", "/v1/b/"+oh, stok, nil); st != 200 || body != string(out) {
		t.Fatalf("submitter read output: %d", st)
	}
	// Lease reported: the worker no longer reads the job's blobs (nor the output it does not own).
	for _, h := range []string{wasm, in, oh} {
		if st, _, _ := e.do("GET", "/v1/b/"+h, w[0], nil); st != 404 {
			t.Fatalf("worker after done read %s: %d", h[:8], st)
		}
	}
	// Expired lease: no access either.
	jid2 := e.submit(stok, wasm, in, 1000)
	l := e.mustLease(w[0])
	testPool.Exec(ctx, `UPDATE replicas SET deadline = now() - interval '1 second' WHERE lease = $1`, l.Lease)
	if st, _, _ := e.do("GET", "/v1/b/"+wasm, w[0], nil); st != 404 {
		t.Fatalf("expired lease read: %d (job %s)", st, jid2)
	}
}

// #8: global disk budget (MAX_BLOB_BYTES) -> 507 err quota disk; tmp sweep after 1 h.
func TestDiskBudgetAndTmpSweep(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	root, tok := e.register("disk")
	data := []byte("disk budget probe " + root)
	var total int64
	testPool.QueryRow(ctx, `SELECT coalesce(sum(size), 0) FROM blobs`).Scan(&total)
	e.s.maxBytes = total + 5
	st, body, _ := e.do("POST", "/v1/b", tok, data)
	if st != 507 || !strings.HasPrefix(body, "err quota disk") {
		t.Fatalf("over budget: %d %s", st, body)
	}
	e.s.maxBytes = defMaxBytes
	e.put(tok, data)
	if ents, _ := os.ReadDir(filepath.Join(e.d.Cfg.DataDir, "blobs", "tmp")); len(ents) != 0 {
		t.Fatalf("refused upload left tmp files: %d", len(ents))
	}
	tmp := filepath.Join(e.d.Cfg.DataDir, "blobs", "tmp")
	stale, fresh := filepath.Join(tmp, "up-stale"), filepath.Join(tmp, "up-fresh")
	os.WriteFile(stale, []byte("x"), 0o600)
	os.WriteFile(fresh, []byte("x"), 0o600)
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(stale, old, old)
	e.d.Janitor.RunOnce(ctx)
	if _, err := os.Stat(stale); err == nil {
		t.Fatal("stale tmp file not swept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("fresh tmp file swept")
	}
}

// #4c: job wasm over 4 MiB is refused at submit.
func TestSubmitWasmSizeCap(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, _, in, _, _ := e.setup(0)
	big := sha([]byte("big wasm " + sid))
	testPool.Exec(ctx, `INSERT INTO blobs (hash, size, owner_root) VALUES ($1, $2, $3)`, big, int64(maxWasm)+1, sid)
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM blobs WHERE hash = $1`, big) })
	st, body, _ := e.do("POST", "/v1/j", stok, map[string]any{"wasm": big, "in": in, "ms": 1000})
	if st != 413 || !strings.HasPrefix(body, "err size") {
		t.Fatalf("big wasm: %d %s", st, body)
	}
	if e.credits(sid) != 100 {
		t.Fatalf("refused submit charged: %d", e.credits(sid))
	}
}

// #5: polling an unknown/foreign/finished job never subscribes a notifier topic.
func TestLongPollNoTopicLeak(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, stok, wasm, in, w, _ := e.setup(2)
	_, otok := e.register("o")
	topics := func() int { // job:* topics currently subscribed
		v := reflect.ValueOf(e.d.Notify).Elem().FieldByName("ch")
		if !v.IsValid() || v.Kind() != reflect.Map || v.Type().Key().Kind() != reflect.String {
			return -1 // notifier internals changed: skip the count
		}
		n := 0
		for it := v.MapRange(); it.Next(); {
			if strings.HasPrefix(it.Key().String(), "job:") {
				n++
			}
		}
		return n
	}
	base := topics()
	jid := e.submit(stok, wasm, in, 1000)
	if st, _, _ := e.do("GET", "/v1/j/jzzzzzz?wait=1", stok, nil); st != 404 {
		t.Fatalf("unknown: %d", st)
	}
	if st, _, _ := e.do("GET", "/v1/j/"+jid+"?wait=1", otok, nil); st != 404 {
		t.Fatalf("foreign: %d", st)
	}
	if n := topics(); base >= 0 && n != base {
		t.Fatalf("unknown/foreign polls created %d topic(s)", n-base)
	}
	out := e.put(w[0], []byte("done"))
	for i := 0; i < 2; i++ {
		l := e.mustLease(w[i])
		e.mustDone(w[i], l.Lease, "ok", out, 0, 1)
	}
	start := time.Now()
	if got := e.job(stok, jid, 5); !strings.HasPrefix(got, jid+" done") || time.Since(start) > time.Second {
		t.Fatalf("finished poll: %s after %v", got, time.Since(start))
	}
	if n := topics(); base >= 0 && n != base {
		t.Fatalf("finished-job poll left %d topic(s)", n-base)
	}
	// A genuine wait does subscribe, and the wake releases it.
	jid2 := e.submit(stok, wasm, in, 1000)
	go func() {
		time.Sleep(200 * time.Millisecond)
		for i := 0; i < 2; i++ {
			l := e.mustLease(w[i])
			e.mustDone(w[i], l.Lease, "ok", out, 0, 1)
		}
	}()
	if got := e.job(stok, jid2, 5); !strings.HasPrefix(got, jid2+" done") {
		t.Fatalf("wait: %s", got)
	}
	if n := topics(); base >= 0 && n != base {
		t.Fatalf("woken poll left %d topic(s)", n-base)
	}
	_ = ctx
}
