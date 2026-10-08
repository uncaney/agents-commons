package compute

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("compute", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping compute DB tests")
		os.Exit(0)
	}
	// Drain stale active jobs from earlier (killed) runs so oldest-first leasing serves this run,
	// and lift storage freezes a killed run's fixtures may have left behind.
	if _, err := testPool.Exec(ctx, cancelSQL(` AND created < now() - interval '5 minutes'`), []string(nil)); err != nil {
		panic(err)
	}
	testPool.Exec(ctx, `DELETE FROM flags WHERE k IN ('freeze:blobs', 'freeze:blobs_opaque')`)
	// Trust's seam: compute rep (4.2) needs the submitter's level.
	core.LevelFn = trust.LevelOf
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// minWasm is a valid core module exporting an empty _start (no imports, no memory); tag lands in
// a custom section so each test gets a distinct hash.
func minWasm(tag string) []byte {
	b := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0, // type 0: () -> ()
		3, 2, 1, 0, // func 0: type 0
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0, // export "_start" = func 0
		10, 4, 1, 2, 0, 0x0b} // code: one body, no locals, end
	return append(b, customSection("t", tag)...)
}

// wasmWithData is minWasm plus one memory page and an active data segment holding data (27.6
// data-segment scrub).
func wasmWithData(tag, data string) []byte {
	b := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0,
		3, 2, 1, 0,
		5, 3, 1, 0, 1, // memory: min 1 page
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0,
		10, 4, 1, 2, 0, 0x0b}
	seg := append([]byte{0, 0x41, 0, 0x0b}, uleb(len(data))...) // active, memory 0, i32.const 0, end, vec len
	seg = append(seg, data...)
	body := append([]byte{1}, seg...)
	b = append(b, 11)
	b = append(b, uleb(len(body))...)
	b = append(b, body...)
	return append(b, customSection("t", tag)...)
}

func customSection(name, payload string) []byte {
	body := append(uleb(len(name)), name...)
	body = append(body, payload...)
	out := append([]byte{0}, uleb(len(body))...)
	return append(out, body...)
}

func uleb(n int) []byte {
	var out []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, c|0x80)
			continue
		}
		return append(out, c)
	}
}

// cancelSQL fails active jobs of the given roots ($1, NULL = all) matching extra, dropping
// their unreported replicas, so later tests' workers never lease this test's leftovers.
func cancelSQL(extra string) string {
	return `WITH j AS (UPDATE jobs SET status = 'failed', reason = 'test-cleanup', finished_at = now()
		WHERE status IN ('queued','running') AND ($1::text[] IS NULL OR root = ANY($1))` + extra + ` RETURNING id)
		DELETE FROM replicas WHERE job IN (SELECT id FROM j) AND state <> 'reported'`
}

type env struct {
	t     *testing.T
	d     *core.Deps
	srv   *httptest.Server
	s     *svc
	roots []string
}

func newEnv(t *testing.T, sameRoot bool) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true, AllowSameRoot: sameRoot, RegPerHour: 1 << 20,
		AdminToken: adminTok, PublicURL: "https://t.example"}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	s := svcFor(d)
	s.register(mux)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	e := &env{t: t, d: d, srv: srv, s: s}
	t.Cleanup(func() {
		// Leftover queued replicas of this test (its roots and the system root's audits/KATs) must
		// never be leased by a later test's donors; the blob rows of this test's roots (files live
		// in the per-test DataDir) must not accumulate across runs of one database.
		ctx := context.Background()
		testPool.Exec(ctx, cancelSQL(""), append(e.roots, core.SystemID))
		testPool.Exec(ctx, `DELETE FROM blob_meta WHERE banned = '' AND hash IN (SELECT hash FROM blobs WHERE owner_root = ANY($1))`, e.roots)
		testPool.Exec(ctx, `DELETE FROM blobs WHERE owner_root = ANY($1)`, e.roots)
	})
	return e
}

var ipSeq = func() *uint32 {
	var b [4]byte
	rand.Read(b[:])
	n := uint32(b[0])<<8 | uint32(b[1])
	return &n
}()

// randIP returns an address in a /24 no earlier call of this run used: trust.Distinct works on
// super-groups, so every registration gets its own network unless a test shares an IP on purpose.
func randIP() string {
	var b [1]byte
	rand.Read(b[:])
	n := atomic.AddUint32(ipSeq, 1)
	return fmt.Sprintf("10.%d.%d.%d", (n>>8)&0xff, n&0xff, 1+int(b[0])%250)
}

func (e *env) do(method, path, token string, body any, hdr ...string) (int, string, http.Header) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", randIP())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

func (e *env) register(name string) (id, tok string) {
	e.t.Helper()
	return e.registerIP(name, randIP())
}

// registerIP registers a root from a given client IP (identities.reg_ip).
func (e *env) registerIP(name, ip string) (id, tok string) {
	e.t.Helper()
	_, body, _ := e.do("POST", "/v1/challenge", "", nil, "CF-Connecting-IP", ip)
	c := strings.TrimPrefix(strings.Fields(body)[0], "c=")
	st, body, _ := e.do("POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, 6), "name": name}, "CF-Connecting-IP", ip)
	if st != 201 {
		e.t.Fatalf("register: %d %s", st, body)
	}
	for _, f := range strings.Fields(body) {
		if v, ok := strings.CutPrefix(f, "id="); ok {
			id = v
		} else if v, ok := strings.CutPrefix(f, "token="); ok {
			tok = v
		}
	}
	e.roots = append(e.roots, id)
	return id, tok
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// firstField is the v1 head token of a reply line (v2 appends k=v fields after it).
func firstField(body string) string {
	if f := strings.Fields(strings.SplitN(body, "\n", 2)[0]); len(f) > 0 {
		return f[0]
	}
	return ""
}

func (e *env) put(tok string, data []byte) string {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/b", tok, data)
	if st != 200 || firstField(body) != sha(data) {
		e.t.Fatalf("put: %d %s", st, body)
	}
	return firstField(body)
}

// submit queues a fresh job (the v1 consensus/economics tests must never be served from the
// result cache) and returns its id; 202 = queued with no donor online yet.
func (e *env) submit(tok, wasm, in string, ms int) string {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/j", tok, map[string]any{"wasm": wasm, "in": in, "ms": ms, "fresh": true})
	id := firstField(body)
	if (st != 200 && st != 202) || !core.ValidID(id) {
		e.t.Fatalf("submit: %d %s", st, body)
	}
	return id
}

func (e *env) lease(tok string, maxMs, maxMb, wait int) (int, *leaseOut) {
	e.t.Helper()
	st, body, _ := e.do("POST", fmt.Sprintf("/v1/w/lease?wait=%d", wait), tok, map[string]int{"max_ms": maxMs, "max_mb": maxMb})
	if st != 200 {
		return st, nil
	}
	var l leaseOut
	if err := json.Unmarshal([]byte(body), &l); err != nil || l.Lease == "" || l.Deadline < time.Now().Unix()+60 {
		e.t.Fatalf("lease body: %s", body)
	}
	return st, &l
}

func (e *env) mustLease(tok string) *leaseOut {
	e.t.Helper()
	st, l := e.lease(tok, 30000, 256, 0)
	if st != 200 {
		e.t.Fatalf("lease: %d", st)
	}
	return l
}

func (e *env) done(tok, lease, status, out string, code, ms int) (int, string) {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/w/done", tok, map[string]any{"lease": lease, "status": status, "out": out, "code": code, "ms": ms})
	return st, body
}

func (e *env) mustDone(tok, lease, status, out string, code, ms int) {
	e.t.Helper()
	if st, body := e.done(tok, lease, status, out, code, ms); st != 200 || body != `{"ok":true}` {
		e.t.Fatalf("done: %d %s", st, body)
	}
}

func (e *env) job(tok, id string, wait int) string {
	e.t.Helper()
	st, body, _ := e.do("GET", fmt.Sprintf("/v1/j/%s?wait=%d", id, wait), tok, nil)
	if st != 200 {
		e.t.Fatalf("job: %d %s", st, body)
	}
	return body
}

func (e *env) credits(id string) int64 {
	var c int64
	if err := testPool.QueryRow(context.Background(), `SELECT credits FROM identities WHERE id = $1`, id).Scan(&c); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) rep(id string) int {
	r, err := core.Rep(context.Background(), testPool, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// ledgerDelta returns the credit-conservation delta across the whole DB (0 when the books balance:
// credits + reserved + escrow == mint - burn). Finalize must not change it (no leak into hold).
func (e *env) ledgerDelta() int64 {
	a, err := core.LedgerAudit(context.Background(), testPool, e.d.EscrowSQL())
	if err != nil {
		e.t.Fatal(err)
	}
	return a.Delta()
}

// promote makes root an L2 submitter (rep 5, 4 days old, one verified non-compute contribution):
// compute rep (4.2) only flows from L2+ submitters.
func (e *env) promote(root string) {
	e.t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET rep = 5, created = now() - interval '4 days', verified_noncompute = 1 WHERE id = $1`, root); err != nil {
		e.t.Fatal(err)
	}
}

// setup registers an L2 submitter with wasm+in blobs and n workers.
func (e *env) setup(workers int) (sid, stok, wasm, in string, wtoks []string, wids []string) {
	e.t.Helper()
	sid, stok = e.register("sub")
	e.promote(sid)
	wasm = e.put(stok, minWasm(sid))
	in = e.put(stok, []byte("input "+sid))
	for i := 0; i < workers; i++ {
		id, tok := e.register(fmt.Sprintf("w%d", i))
		wids, wtoks = append(wids, id), append(wtoks, tok)
	}
	return
}

func TestBlobs(t *testing.T) {
	e := newEnv(t, false)
	root, tok := e.register("b")
	_, otok := e.register("b2")
	data := []byte("hello blobs " + root)
	h := e.put(tok, data)
	if _, err := os.Stat(filepath.Join(e.d.Cfg.DataDir, "blobs", h[:2], h)); err != nil {
		t.Fatal("file not at sha path:", err)
	}
	// Dedup: same hash from another root refreshes only; one row, owner unchanged.
	st, body, _ := e.do("POST", "/v1/b?f=json", otok, data)
	var j map[string]any
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || j["hash"] != h || j["size"] != float64(len(data)) {
		t.Fatalf("json put: %d %s", st, body)
	}
	var n int
	var owner string
	testPool.QueryRow(context.Background(), `SELECT count(*), min(owner_root) FROM blobs WHERE hash = $1`, h).Scan(&n, &owner)
	if n != 1 || owner != root {
		t.Fatalf("dedup rows=%d owner=%s", n, owner)
	}
	if st, body, _ := e.do("GET", "/v1/b/"+h, "", nil); st != 401 || body != "err auth token required" {
		t.Fatalf("anon get: %d %s", st, body)
	}
	if st, _, _ := e.do("POST", "/v1/b", "", data); st != 401 {
		t.Fatalf("anon put: %d", st)
	}
	if st, _, _ := e.do("GET", "/v1/b/"+h, otok, nil); st != 404 {
		t.Fatalf("non-owner read: %d", st)
	}
	st, body, hd := e.do("GET", "/v1/b/"+h, tok, nil)
	if st != 200 || body != string(data) || hd.Get("Content-Type") != "application/octet-stream" ||
		hd.Get("ETag") != `"`+h+`"` || hd.Get("Content-Length") != fmt.Sprint(len(data)) || !strings.Contains(hd.Get("Cache-Control"), "immutable") {
		t.Fatalf("get: %d %q %v", st, body, hd)
	}
	st, body, hd = e.do("HEAD", "/v1/b/"+h, tok, nil)
	if st != 200 || body != "" || hd.Get("Content-Length") != fmt.Sprint(len(data)) {
		t.Fatalf("head: %d %q %v", st, body, hd)
	}
	if st, _, _ := e.do("GET", "/v1/b/"+strings.Repeat("0", 64), tok, nil); st != 404 {
		t.Fatalf("unknown: %d", st)
	}
	if st, _, _ := e.do("GET", "/v1/b/zzz", tok, nil); st != 400 {
		t.Fatalf("bad hash: %d", st)
	}
	// Quota: fake a nearly full root, then a new blob is refused but a re-upload is free.
	testPool.Exec(context.Background(), `INSERT INTO blobs (hash, size, owner_root) VALUES ($1, $2, $3)`, sha([]byte("fake"+root)), int64(blobQuota)-3, root)
	st, body, _ = e.do("POST", "/v1/b", tok, []byte("new blob for "+root))
	if st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("quota: %d %s", st, body)
	}
	e.put(tok, data)
	// Size cap.
	st, body, _ = e.do("POST", "/v1/b", otok, bytes.Repeat([]byte("x"), maxBlob+1))
	if st != 413 || !strings.HasPrefix(body, "err size") {
		t.Fatalf("size: %d %s", st, body)
	}
	if ents, _ := os.ReadDir(filepath.Join(e.d.Cfg.DataDir, "blobs", "tmp")); len(ents) != 0 {
		t.Fatalf("tmp leftovers: %d", len(ents))
	}
}

func TestSubmitAndStatus(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, _, _ := e.setup(0)
	_, otok := e.register("o")
	jid := e.submit(stok, wasm, in, 0)
	if e.credits(sid) != 70 {
		t.Fatalf("reserve: %d", e.credits(sid))
	}
	if got := e.job(stok, jid, 0); got != jid+" queued" {
		t.Fatalf("status: %s", got)
	}
	st, body, _ := e.do("GET", "/v1/j/"+jid+"?f=json", stok, nil)
	if st != 200 || body != fmt.Sprintf(`{"id":"%s","status":"queued"}`, jid) {
		t.Fatalf("json status: %d %s", st, body)
	}
	if st, _, _ := e.do("GET", "/v1/j/"+jid, otok, nil); st != 404 {
		t.Fatalf("stranger: %d", st)
	}
	if st, _, _ := e.do("GET", "/v1/j/"+jid, "", nil); st != 401 {
		t.Fatalf("anon: %d", st)
	}
	if st, _, _ := e.do("GET", "/v1/j/"+jid+"?wait=x", stok, nil); st != 400 {
		t.Fatalf("bad wait: %d", st)
	}
	var ms, mb int
	var reps int
	testPool.QueryRow(context.Background(), `SELECT ms, mb, (SELECT count(*) FROM replicas WHERE job = $1) FROM jobs WHERE id = $1`, jid).Scan(&ms, &mb, &reps)
	if ms != defMs || mb != defMb || reps != 2 {
		t.Fatalf("defaults: ms=%d mb=%d reps=%d", ms, mb, reps)
	}
	// Batch, JSON reply, credits.
	st, body, _ = e.do("POST", "/v1/j?f=json", stok, map[string]any{"jobs": []map[string]any{{"wasm": wasm, "in": in, "ms": 1000}, {"wasm": wasm, "in": in, "ms": 1500, "mb": 8}}})
	var jr struct {
		ID  string
		IDs []string
	}
	if (st != 200 && st != 202) || json.Unmarshal([]byte(body), &jr) != nil || len(jr.IDs) != 2 || jr.ID != jr.IDs[0] {
		t.Fatalf("batch: %d %s", st, body)
	}
	if e.credits(sid) != 70-3-6 {
		t.Fatalf("batch credits: %d", e.credits(sid))
	}
	// Errors.
	for _, c := range []struct {
		body any
		st   int
		code string
	}{
		{map[string]any{"wasm": wasm, "in": in, "ms": 30000}, 402, "err credits"},
		{map[string]any{"wasm": strings.Repeat("1", 64), "in": in}, 404, "err notfound"},
		{map[string]any{"wasm": wasm, "in": "nope"}, 400, "err bad"},
		{map[string]any{"wasm": wasm, "in": in, "ms": 30001}, 400, "err bad"},
		{map[string]any{"wasm": wasm, "in": in, "mb": 257}, 400, "err bad"},
		{map[string]any{"jobs": make([]map[string]any, 101)}, 400, "err bad"},
		{map[string]any{"wasm": wasm, "in": in, "bogus": 1}, 400, "err bad"},
	} {
		if st, body, _ := e.do("POST", "/v1/j", stok, c.body); st != c.st || !strings.HasPrefix(body, c.code) {
			t.Fatalf("%v: %d %s", c.body, st, body)
		}
	}
	if e.credits(sid) != 61 {
		t.Fatalf("failed submit must not charge: %d", e.credits(sid))
	}
}

func TestLeaseRules(t *testing.T) {
	e := newEnv(t, false)
	_, stok, wasm, in, w, _ := e.setup(2)
	jid := e.submit(stok, wasm, in, 1000)
	if st, _ := e.lease(stok, 30000, 256, 0); st != 204 {
		t.Fatalf("submitter root leased its own job: %d", st)
	}
	if st, _ := e.lease(w[0], 500, 256, 0); st != 204 {
		t.Fatalf("max_ms not respected: %d", st)
	}
	if st, _ := e.lease(w[0], 1000, 32, 0); st != 204 {
		t.Fatalf("max_mb not respected: %d", st)
	}
	l := e.mustLease(w[0])
	if l.Job != jid || l.Wasm != wasm || l.In != in || l.Ms != 1000 || l.Mb != 64 || l.Deadline < time.Now().Unix()+61 {
		t.Fatalf("lease: %+v", l)
	}
	if got := e.job(stok, jid, 0); got != jid+" running" {
		t.Fatalf("status: %s", got)
	}
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 204 {
		t.Fatalf("same root got second replica: %d", st)
	}
	l2 := e.mustLease(w[1])
	if l2.Job != jid || l2.Lease == l.Lease {
		t.Fatalf("second replica: %+v", l2)
	}
	if st, _ := e.lease(w[1], 30000, 256, 0); st != 204 {
		t.Fatalf("third lease: %d", st)
	}
	if st, _, _ := e.do("POST", "/v1/w/lease", "", map[string]int{}); st != 401 {
		t.Fatalf("anon lease: %d", st)
	}
	if st, body, _ := e.do("POST", "/v1/w/lease?wait=99", w[0], `{"max_ms":"x"}`); st != 400 || !strings.HasPrefix(body, "err bad") {
		t.Fatalf("bad body: %d %s", st, body)
	}
}

func TestLongPollWake(t *testing.T) {
	e := newEnv(t, false)
	_, stok, wasm, in, w, _ := e.setup(1)
	type res struct {
		st int
		l  *leaseOut
		at time.Duration
	}
	start := time.Now()
	ch := make(chan res, 1)
	go func() {
		st, l := e.lease(w[0], 30000, 256, 5)
		ch <- res{st, l, time.Since(start)}
	}()
	time.Sleep(300 * time.Millisecond)
	jid := e.submit(stok, wasm, in, 1000)
	r := <-ch
	if r.st != 200 || r.l.Job != jid || r.at > 2*time.Second {
		t.Fatalf("wake: st=%d after %v", r.st, r.at)
	}
	// Job long-poll wakes on completion.
	_, w2 := e.register("w2")
	l2 := e.mustLease(w2)
	out := e.put(w2, []byte("out"))
	go func() {
		time.Sleep(300 * time.Millisecond)
		e.mustDone(w[0], r.l.Lease, "ok", out, 0, 100)
		e.mustDone(w2, l2.Lease, "ok", out, 0, 100)
	}()
	start = time.Now()
	if got := e.job(stok, jid, 5); !strings.HasPrefix(got, jid+" done out="+out) || time.Since(start) > 2*time.Second {
		t.Fatalf("job wake: %s after %v", got, time.Since(start))
	}
}

func TestConsensusAgree(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, wid := e.setup(2)
	jid := e.submit(stok, wasm, in, 10000) // reserve 30
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	out := e.put(w[0], []byte("result"))
	if st, body := e.done(w[0], l0.Lease, "ok", strings.Repeat("a", 64), 0, 1); st != 404 || !strings.Contains(body, "out blob") {
		t.Fatalf("missing out blob: %d %s", st, body)
	}
	if st, _ := e.done(w[1], l0.Lease, "ok", out, 0, 1); st != 404 {
		t.Fatalf("foreign lease accepted: %d", st)
	}
	if st, _ := e.done(w[0], l0.Lease, "weird", out, 0, 1); st != 400 {
		t.Fatalf("bad status: %d", st)
	}
	e.mustDone(w[0], l0.Lease, "ok", out, 0, 2500)
	if got := e.job(stok, jid, 0); got != jid+" running" {
		t.Fatalf("after one report: %s", got)
	}
	e.mustDone(w[1], l1.Lease, "ok", out, 0, 1800)
	if got := e.job(stok, jid, 0); got != fmt.Sprintf("%s done out=%s ms=2500", jid, out) {
		t.Fatalf("done: %s", got)
	}
	st, body, _ := e.do("GET", "/v1/j/"+jid, stok, nil, "Accept", "application/json")
	if st != 200 || body != fmt.Sprintf(`{"code":0,"id":"%s","ms":2500,"out":"%s","status":"done"}`, jid, out) {
		t.Fatalf("json done: %s", body)
	}
	// used_s = 3: submitter charged 3*2=6 of 30; workers paid out of it, min(4, 6/2)=3 each, rep +1.
	if e.credits(wid[0]) != 103 || e.credits(wid[1]) != 103 || e.rep(wid[0]) != 1 || e.rep(wid[1]) != 1 {
		t.Fatalf("workers: %d %d rep %d %d", e.credits(wid[0]), e.credits(wid[1]), e.rep(wid[0]), e.rep(wid[1]))
	}
	if e.credits(sid) != 94 {
		t.Fatalf("submitter: %d", e.credits(sid))
	}
	if st, _ := e.done(w[0], l0.Lease, "ok", out, 0, 1); st != 404 {
		t.Fatalf("lease reuse: %d", st)
	}
	var lastRef time.Time
	testPool.QueryRow(context.Background(), `SELECT last_ref FROM blobs WHERE hash = $1`, out).Scan(&lastRef)
	if time.Since(lastRef) > time.Minute {
		t.Fatal("output blob last_ref not refreshed")
	}
	// Exit status with code is "done" too.
	jid2 := e.submit(stok, wasm, in, 1000)
	a, b := e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], a.Lease, "exit", out, 3, 10)
	e.mustDone(w[1], b.Lease, "exit", out, 3, 20)
	if got := e.job(stok, jid2, 0); got != fmt.Sprintf("%s done out=%s ms=20 code=3", jid2, out) {
		t.Fatalf("exit: %s", got)
	}
}

func TestConsensusDisagreeTieBreak(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, wid := e.setup(3)
	jid := e.submit(stok, wasm, in, 10000)
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	good, bad := e.put(w[0], []byte("good")), e.put(w[1], []byte("cheat"))
	e.mustDone(w[0], l0.Lease, "ok", good, 0, 1200)
	e.mustDone(w[1], l1.Lease, "ok", bad, 0, 900)
	if got := e.job(stok, jid, 0); got != jid+" running" {
		t.Fatalf("should await tie-break: %s", got)
	}
	for i := 0; i < 2; i++ {
		if st, _ := e.lease(w[i], 30000, 256, 0); st != 204 {
			t.Fatalf("w%d got the tie-break replica: %d", i, st)
		}
	}
	l2 := e.mustLease(w[2])
	if l2.Job != jid {
		t.Fatalf("tie-break job: %s", l2.Job)
	}
	e.mustDone(w[2], l2.Lease, "ok", good, 0, 2100)
	if got := e.job(stok, jid, 0); got != fmt.Sprintf("%s done out=%s ms=2100", jid, good) {
		t.Fatalf("majority: %s", got)
	}
	// used_s = 3; submitter charged 3*3=9; agreeing roots paid min(4, 9/2)=4, rep +1; cheater rep -5, unpaid.
	if e.credits(wid[0]) != 104 || e.credits(wid[2]) != 104 || e.credits(wid[1]) != 100 {
		t.Fatalf("credits: %d %d %d", e.credits(wid[0]), e.credits(wid[1]), e.credits(wid[2]))
	}
	if e.rep(wid[0]) != 1 || e.rep(wid[2]) != 1 || e.rep(wid[1]) != -5 {
		t.Fatalf("rep: %d %d %d", e.rep(wid[0]), e.rep(wid[1]), e.rep(wid[2]))
	}
	if e.credits(sid) != 91 {
		t.Fatalf("submitter: %d", e.credits(sid))
	}
}

// TestFinalizeConservesRemainder: a majority finalize charges usedS*len(reps) but pays only the
// agreeing roots min(usedS+1, charge/len(agree)) each; the rounding remainder (and the whole charge
// of an agreed-error job, paid=0) must be burnt, not leaked into the hold pseudo-id. Finding #1: a
// leak left the credit ledger unconserved forever, tripping the daily audit and freezing compute.
func TestFinalizeConservesRemainder(t *testing.T) {
	e := newEnv(t, false)
	before := e.ledgerDelta()
	_, stok, wasm, in, w, _ := e.setup(3)
	jid := e.submit(stok, wasm, in, 10000)
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	good, bad := e.put(w[0], []byte("good")), e.put(w[1], []byte("cheat"))
	e.mustDone(w[0], l0.Lease, "ok", good, 0, 1200)
	e.mustDone(w[1], l1.Lease, "ok", bad, 0, 900)
	for i := 0; i < 2; i++ {
		e.lease(w[i], 30000, 256, 0)
	}
	l2 := e.mustLease(w[2])
	e.mustDone(w[2], l2.Lease, "ok", good, 0, 2100)
	if got := e.job(stok, jid, 0); got != fmt.Sprintf("%s done out=%s ms=2100", jid, good) {
		t.Fatalf("majority: %s", got)
	}
	// used_s=3, charge=9, two agreeing roots paid 4 each (totalPaid=8); the remainder of 1 is burnt,
	// so the global conservation delta is unchanged by the finalize.
	if after := e.ledgerDelta(); after != before {
		t.Fatalf("finalize changed ledger delta: before=%d after=%d (remainder leaked into hold)", before, after)
	}
}

func TestNoConsensus(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, wid := e.setup(3)
	jid := e.submit(stok, wasm, in, 10000)
	var leases []*leaseOut
	for i := 0; i < 2; i++ {
		leases = append(leases, e.mustLease(w[i]))
	}
	for i := 0; i < 2; i++ {
		e.mustDone(w[i], leases[i].Lease, "ok", e.put(w[i], []byte(fmt.Sprint("o", i))), 0, 500)
	}
	l := e.mustLease(w[2])
	e.mustDone(w[2], l.Lease, "error", "", 0, 500)
	if got := e.job(stok, jid, 0); got != jid+" failed noconsensus" {
		t.Fatalf("noconsensus: %s", got)
	}
	if e.credits(sid) != 100 {
		t.Fatalf("full refund expected: %d", e.credits(sid))
	}
	for i := 0; i < 3; i++ {
		if e.credits(wid[i]) != 100 || e.rep(wid[i]) != 0 {
			t.Fatalf("w%d touched: %d/%d", i, e.credits(wid[i]), e.rep(wid[i]))
		}
	}
	var reps int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM replicas WHERE job = $1 AND state = 'queued'`, jid).Scan(&reps)
	if reps != 0 {
		t.Fatalf("queued replicas left: %d", reps)
	}
}

func TestTimeoutAgreement(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, wid := e.setup(2)
	jid := e.submit(stok, wasm, in, 10000)
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], l0.Lease, "timeout", "ignored-out", 7, 10000)
	e.mustDone(w[1], l1.Lease, "timeout", "", 0, 99999) // ms clamped to the job limit
	if got := e.job(stok, jid, 0); got != jid+" failed timeout" {
		t.Fatalf("timeout: %s", got)
	}
	// used_s = 10: charge 20, pay min(11, 20/2) = 10 each.
	if e.credits(wid[0]) != 110 || e.credits(wid[1]) != 110 || e.credits(sid) != 80 {
		t.Fatalf("credits: w %d %d s %d", e.credits(wid[0]), e.credits(wid[1]), e.credits(sid))
	}
	st, body, _ := e.do("GET", "/v1/j/"+jid+"?f=json", stok, nil)
	if st != 200 || body != fmt.Sprintf(`{"id":"%s","reason":"timeout","status":"failed"}`, jid) {
		t.Fatalf("json failed: %s", body)
	}
}

func TestExpiredLeaseRequeue(t *testing.T) {
	e := newEnv(t, false)
	_, stok, wasm, in, w, wid := e.setup(3)
	jid := e.submit(stok, wasm, in, 1000)
	l, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	testPool.Exec(context.Background(), `UPDATE replicas SET deadline = now() - interval '1 second' WHERE lease = $1`, l.Lease)
	if st, body := e.done(w[0], l.Lease, "ok", wasm, 0, 1); st != 409 || !strings.HasPrefix(body, "err taken") {
		t.Fatalf("expired done: %d %s", st, body)
	}
	e.d.Janitor.RunOnce(context.Background())
	var state string
	var lease *string
	var excl []string
	testPool.QueryRow(context.Background(), `SELECT state, lease, excluded_roots FROM replicas WHERE job = $1 AND state = 'queued'`, jid).Scan(&state, &lease, &excl)
	if state != "queued" || lease != nil || len(excl) != 1 || excl[0] != wid[0] {
		t.Fatalf("not requeued/excluded: %s %v %v", state, lease, excl)
	}
	if got := e.job(stok, jid, 0); got != jid+" running" {
		t.Fatalf("job status (other replica still leased): %s", got)
	}
	// Letting a lease expire costs rep 1; the replica is never re-leased to that root.
	if e.rep(wid[0]) != -1 || e.rep(wid[1]) != 0 {
		t.Fatalf("rep: %d %d", e.rep(wid[0]), e.rep(wid[1]))
	}
	if st, _ := e.lease(w[0], 30000, 256, 0); st != 204 {
		t.Fatalf("expired worker re-leased the replica: %d", st)
	}
	l2 := e.mustLease(w[2])
	if l2.Job != jid {
		t.Fatalf("release to another root: %+v", l2)
	}
	_ = l1
}

func TestStuckJobCap(t *testing.T) {
	e := newEnv(t, false)
	sid, stok, wasm, in, w, _ := e.setup(1)
	jid := e.submit(stok, wasm, in, 10000)
	l := e.mustLease(w[0])
	testPool.Exec(context.Background(), `UPDATE jobs SET created = now() - interval '25 hours' WHERE id = $1`, jid)
	e.d.Janitor.RunOnce(context.Background())
	if got := e.job(stok, jid, 0); got != jid+" failed timeout-queue" {
		t.Fatalf("stuck: %s", got)
	}
	if e.credits(sid) != 100 {
		t.Fatalf("refund: %d", e.credits(sid))
	}
	if st, _ := e.done(w[0], l.Lease, "ok", wasm, 0, 1); st != 404 {
		t.Fatalf("done on cancelled job: %d", st)
	}
}

func TestAllowSameRoot(t *testing.T) {
	e := newEnv(t, true)
	_, stok, wasm, in, w, _ := e.setup(1)
	jid := e.submit(stok, wasm, in, 1000)
	if st, _ := e.lease(stok, 30000, 256, 0); st != 204 {
		t.Fatalf("submitter must still be excluded: %d", st)
	}
	a, b := e.mustLease(w[0]), e.mustLease(w[0])
	if a.Job != jid || b.Job != jid || a.Lease == b.Lease {
		t.Fatalf("same root leases: %+v %+v", a, b)
	}
	out := e.put(w[0], []byte("same"))
	e.mustDone(w[0], a.Lease, "ok", out, 0, 10)
	e.mustDone(w[0], b.Lease, "ok", out, 0, 10)
	if got := e.job(stok, jid, 0); got != fmt.Sprintf("%s done out=%s ms=10", jid, out) {
		t.Fatalf("same root done: %s", got)
	}
}

func TestFrozenAndBanned(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, stok, wasm, in, w, wid := e.setup(1)
	if err := e.d.SetFreeze(ctx, "compute", true); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ m, p string }{{"POST", "/v1/b"}, {"POST", "/v1/j"}, {"POST", "/v1/w/lease"}, {"POST", "/v1/w/done"}} {
		if st, body, _ := e.do(c.m, c.p, stok, "{}"); st != 503 || body != "err frozen compute" {
			e.d.SetFreeze(ctx, "compute", false)
			t.Fatalf("%s %s frozen: %d %s", c.m, c.p, st, body)
		}
	}
	if st, _, _ := e.do("GET", "/v1/b/"+wasm, stok, nil); st != 200 {
		t.Fatal("reads should work while frozen")
	}
	if _, err := Ops(e.d)["j"](ctx, &core.Ident{ID: "a", Root: "a"}, nil); err == nil || err.Error() != "err frozen compute" {
		t.Fatalf("op frozen: %v", err)
	}
	e.d.SetFreeze(ctx, "compute", false)
	e.submit(stok, wasm, in, 1000)
	testPool.Exec(ctx, `UPDATE identities SET rep = -10 WHERE id = $1`, wid[0])
	if st, body, _ := e.do("POST", "/v1/w/lease", w[0], "{}"); st != 403 || body != "err auth banned" {
		t.Fatalf("banned lease: %d %s", st, body)
	}
}

func TestPurgeHook(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(1)
	jid := e.submit(stok, wasm, in, 1000)
	l := e.mustLease(w[0])
	if n, err := e.d.Purge(ctx, sid); err != nil || n != 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	for _, h := range []string{wasm, in} {
		if _, err := os.Stat(e.s.blobPath(h)); err == nil {
			t.Fatal("blob file survived purge")
		}
	}
	var blobs, reps int
	var status, reason string
	testPool.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE owner_root = $1`, sid).Scan(&blobs)
	testPool.QueryRow(ctx, `SELECT status, reason, (SELECT count(*) FROM replicas WHERE job = $1) FROM jobs WHERE id = $1`, jid).Scan(&status, &reason, &reps)
	if blobs != 0 || status != "failed" || reason != "purged" || reps != 0 {
		t.Fatalf("after purge: blobs=%d %s %s reps=%d", blobs, status, reason, reps)
	}
	if st, _ := e.done(w[0], l.Lease, "ok", wasm, 0, 1); st != 404 {
		t.Fatalf("done after purge: %d", st)
	}
	// Purging a worker releases its lease back to the queue.
	_, stok2, wasm2, in2, w2, wid2 := e.setup(1)
	jid2 := e.submit(stok2, wasm2, in2, 1000)
	e.mustLease(w2[0])
	e.d.Purge(ctx, wid2[0])
	var queued int
	testPool.QueryRow(ctx, `SELECT count(*) FROM replicas WHERE job = $1 AND state = 'queued'`, jid2).Scan(&queued)
	if queued != 2 {
		t.Fatalf("worker purge should requeue: %d", queued)
	}
}

func TestGCBlobs(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, stok, wasm, in, _, _ := e.setup(0)
	old := e.put(stok, []byte("old unreferenced"))
	e.submit(stok, wasm, in, 1000)
	testPool.Exec(ctx, `UPDATE blobs SET last_ref = now() - interval '8 days' WHERE hash IN ($1, $2, $3)`, old, wasm, in)
	if err := e.s.gcBlobs(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE hash IN ($1, $2, $3)`, old, wasm, in).Scan(&n)
	if n != 2 {
		t.Fatalf("expected only active-job blobs kept, have %d", n)
	}
	if _, err := os.Stat(e.s.blobPath(old)); err == nil {
		t.Fatal("gc left file")
	}
	if _, err := os.Stat(e.s.blobPath(wasm)); err != nil {
		t.Fatal("gc removed referenced blob")
	}
}

func TestOps(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	sid, stok, wasm, _, w, _ := e.setup(2)
	ops := Ops(e.d)
	for _, k := range []string{"j", "jw", "jo"} {
		if ops[k] == nil {
			t.Fatalf("op %s missing", k)
		}
	}
	me, err := e.d.LookupToken(ctx, stok)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ops["j"](ctx, nil, json.RawMessage(`{}`)); err == nil || err.Error() != "err auth token required" {
		t.Fatalf("anon j: %v", err)
	}
	if _, err := ops["j"](ctx, me, json.RawMessage(fmt.Sprintf(`{"wasm":%q,"in_text":%q}`, wasm, strings.Repeat("x", maxInText+1)))); err == nil || !strings.HasPrefix(err.Error(), "err size") {
		t.Fatalf("in_text too big: %v", err)
	}
	if _, err := ops["j"](ctx, me, json.RawMessage(fmt.Sprintf(`{"wasm":%q,"in":%q,"in_text":"x"}`, wasm, wasm))); err == nil || !strings.HasPrefix(err.Error(), "err bad") {
		t.Fatalf("in+in_text: %v", err)
	}
	jid, err := ops["j"](ctx, me, json.RawMessage(fmt.Sprintf(`{"wasm":%q,"in_text":%q,"ms":2000}`, wasm, "inline input "+sid)))
	if jid = firstField(jid); err != nil || !core.ValidID(jid) {
		t.Fatalf("op j: %q %v", jid, err)
	}
	var input, owner string
	testPool.QueryRow(ctx, `SELECT j.input, b.owner_root FROM jobs j JOIN blobs b ON b.hash = j.input WHERE j.id = $1`, jid).Scan(&input, &owner)
	if input != sha([]byte("inline input "+sid)) || owner != sid {
		t.Fatalf("in_text blob: %s owner %s", input, owner)
	}
	if got, err := ops["jw"](ctx, me, json.RawMessage(`{"id":"`+jid+`"}`)); err != nil || got != jid+" queued" {
		t.Fatalf("jw: %q %v", got, err)
	}
	if _, err := ops["jo"](ctx, me, json.RawMessage(`{"id":"`+jid+`"}`)); err == nil || !strings.HasPrefix(err.Error(), "err bad "+jid+" queued") {
		t.Fatalf("jo not done: %v", err)
	}
	out := e.put(w[0], []byte("result text\n"))
	go func() {
		time.Sleep(200 * time.Millisecond)
		for i := 0; i < 2; i++ {
			l := e.mustLease(w[i])
			e.mustDone(w[i], l.Lease, "ok", out, 0, 150)
		}
	}()
	start := time.Now()
	got, err := ops["jw"](ctx, me, json.RawMessage(`{"id":"`+jid+`","wait":10}`))
	if err != nil || got != fmt.Sprintf("%s done out=%s ms=150", jid, out) || time.Since(start) > 3*time.Second {
		t.Fatalf("jw wait: %q %v after %v", got, err, time.Since(start))
	}
	if got, err := ops["jo"](ctx, me, json.RawMessage(`{"id":"`+jid+`"}`)); err != nil || got != "result text\n" {
		t.Fatalf("jo: %q %v", got, err)
	}
	other, _ := e.d.LookupToken(ctx, w[0])
	if _, err := ops["jo"](ctx, other, json.RawMessage(`{"id":"`+jid+`"}`)); err == nil || err.Error() != "err notfound not found" {
		t.Fatalf("jo stranger: %v", err)
	}
	// Binary output falls back to a pointer line (unique bytes per run: opaque re-uploads are counted).
	binData := append([]byte{0xff, 0xfe, 0x00}, []byte(sid)...)
	bin := e.put(w[0], binData)
	jid2 := e.submit(stok, wasm, input, 1000)
	for i := 0; i < 2; i++ {
		l := e.mustLease(w[i])
		e.mustDone(w[i], l.Lease, "ok", bin, 0, 1)
	}
	if got, err := ops["jo"](ctx, me, json.RawMessage(`{"id":"`+jid2+`"}`)); err != nil || got != fmt.Sprintf("out=%s size=%d (binary or too large: use GET /v1/b/%s)", bin, len(binData), bin) {
		t.Fatalf("jo binary: %q %v", got, err)
	}
	// Batch via op: one line per job (the first is served from the cache: same wasm/in/mb as jid).
	got, err = ops["j"](ctx, me, json.RawMessage(fmt.Sprintf(`{"jobs":[{"wasm":%q,"in":%q,"ms":1000},{"wasm":%q,"in_text":"b"}]}`, wasm, input, wasm)))
	lines := strings.Split(got, "\n")
	if err != nil || len(lines) < 2 || !core.ValidID(firstField(lines[0])) || !core.ValidID(firstField(lines[1])) {
		t.Fatalf("op j batch: %q %v", got, err)
	}
	if !strings.Contains(lines[0], " done out=") || !strings.HasSuffix(lines[0], " ms=0 cached") {
		t.Fatalf("batch first job should be a cache hit: %q", lines[0])
	}
}
