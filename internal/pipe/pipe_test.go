package pipe

// Acceptance tests of P107-pipe (SPEC-v2 27.6). They drive the real HTTP surface: identities
// register through the PoW challenge, modules are uploaded as blobs, each pipeline step runs
// through compute's lease/done protocol with two donor roots in distinct networks, and the
// advancer chains the steps. No real interpreter runs; step outputs are the (simulated) donor
// bytes, which is enough to exercise chaining, caching, failure, framing, caps and attestation.

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
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/sign"
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
	} else if pool, done := testdb.Open("pipe", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping pipe DB tests")
		os.Exit(0)
	}
	core.LevelFn = trust.LevelOf
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// --- fixtures ---------------------------------------------------------------------------------

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

func customSection(name, payload string) []byte {
	body := append(uleb(len(name)), name...)
	body = append(body, payload...)
	out := append([]byte{0}, uleb(len(body))...)
	return append(out, body...)
}

// minWasm is a valid module exporting an empty _start; tag makes each hash distinct.
func minWasm(tag string) []byte {
	b := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0,
		3, 2, 1, 0,
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0,
		10, 4, 1, 2, 0, 0x0b}
	return append(b, customSection("t", tag)...)
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

var ipSeq = func() *uint32 { var n uint32 = 1; return &n }()

func randIP() string {
	n := atomic.AddUint32(ipSeq, 1)
	var b [1]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", (n>>8)&0xff, n&0xff, 1+int(b[0])%250)
}

// --- env --------------------------------------------------------------------------------------

type env struct {
	t     *testing.T
	d     *core.Deps
	s     *svc
	srv   *httptest.Server
	roots []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true,
		RegPerHour: 1 << 20, AdminToken: "cx-admin-test", PublicURL: "https://t.example", AdminBlobMax: 64 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAdminV2(mux, d)
	sign.Register(mux, d)
	compute.Register(mux, d)
	catalog.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	e := &env{t: t, d: d, s: svcFor(d), srv: srv}
	t.Cleanup(func() {
		srv.Close()
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM pipes WHERE root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM jobs WHERE root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM blobs WHERE owner_root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM counters WHERE scope = ANY($1)`, e.roots)
		d.Close()
	})
	return e
}

func (e *env) do(method, path, token string, body any) (int, string, http.Header) {
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
	ip := randIP()
	_, body, _ := e.do2("POST", "/v1/challenge", "", nil, ip)
	c := strings.TrimPrefix(strings.Fields(body)[0], "c=")
	st, body, _ := e.do2("POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, 6), "name": name}, ip)
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

// do2 pins a fixed client IP (distinct super-groups for consensus).
func (e *env) do2(method, path, token string, body any, ip string) (int, string, http.Header) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", ip)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

func (e *env) l2(root string) {
	e.t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET rep = 5, created = now() - interval '4 days', verified_noncompute = 1 WHERE id = $1`, root); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) put(tok string, data []byte) string {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/b", tok, data)
	if st != 200 || strings.Fields(body)[0] != sha(data) {
		e.t.Fatalf("put: %d %s", st, body)
	}
	return sha(data)
}

type leaseOut struct {
	Lease, Job, Wasm, In string
	Ms, Mb               int
}

func (e *env) lease(tok string) *leaseOut {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/w/lease", tok, map[string]int{"max_ms": 30000, "max_mb": 256})
	if st == 204 {
		return nil
	}
	if st != 200 {
		e.t.Fatalf("lease: %d %s", st, body)
	}
	var l leaseOut
	if err := json.Unmarshal([]byte(body), &l); err != nil || l.Lease == "" {
		e.t.Fatalf("lease body: %s", body)
	}
	return &l
}

func (e *env) done(tok, lease, status, out string, ms int) {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/w/done", tok, map[string]any{"lease": lease, "status": status, "out": out, "code": 0, "ms": ms})
	if st != 200 || body != `{"ok":true}` {
		e.t.Fatalf("done: %d %s", st, body)
	}
}

func (e *env) view(pid string) *pipeView {
	e.t.Helper()
	v, err := e.s.load(context.Background(), e.rootOf(pid), pid)
	if err != nil {
		e.t.Fatalf("view %s: %v", pid, err)
	}
	return v
}

func (e *env) rootOf(pid string) string {
	var root string
	if err := testPool.QueryRow(context.Background(), `SELECT root FROM pipes WHERE id = $1`, pid).Scan(&root); err != nil {
		e.t.Fatalf("rootOf %s: %v", pid, err)
	}
	return root
}

// drive advances the pipe and runs the two donors on each queued step until the pipe settles.
// stepFn maps (step index, input hash) to the donor status and, for "ok", the output bytes.
func (e *env) drive(pid string, wtoks []string, stepFn func(idx int, in string) (string, []byte)) *pipeView {
	ctx := context.Background()
	for round := 0; round < 60; round++ {
		e.s.advanceOne(ctx, pid)
		v := e.view(pid)
		if v.final() {
			return v
		}
		idx := v.Cur
		worked := false
		for i := 0; i < 50; i++ {
			prog := false
			for _, tok := range wtoks {
				l := e.lease(tok)
				if l == nil {
					continue
				}
				prog, worked = true, true
				status, out := stepFn(idx, l.In)
				h := ""
				if status == "ok" {
					h = e.put(tok, out)
				}
				e.done(tok, l.Lease, status, h, l.Ms/2)
			}
			if !prog {
				break
			}
		}
		if !worked {
			// No queued replicas: either a cache-only advance is pending or we are stuck.
			e.s.advanceOne(ctx, pid)
			if e.view(pid).final() {
				return e.view(pid)
			}
		}
	}
	return e.view(pid)
}

func (e *env) workers(n int) []string {
	e.t.Helper()
	var toks []string
	for i := 0; i < n; i++ {
		_, tok := e.register(fmt.Sprintf("w%d", i))
		toks = append(toks, tok)
	}
	return toks
}

// transform is the default donor behaviour: a deterministic, per-input output so both donors agree
// and each distinct step input yields a distinct output hash.
func transform(idx int, in string) (string, []byte) {
	return "ok", []byte(fmt.Sprintf("out-%d-%s", idx, in[:8]))
}

// setup registers an L2 submitter, two distinct-network donors and n distinct wasm modules.
func (e *env) setup(nmods int) (sid, stok string, wtoks, wasms []string) {
	e.t.Helper()
	sid, stok = e.register("sub")
	e.l2(sid)
	wtoks = e.workers(2)
	for i := 0; i < nmods; i++ {
		wasms = append(wasms, e.put(stok, minWasm(fmt.Sprintf("m%d-%s", i, sid))))
	}
	return
}

func (e *env) createPipe(stok string, steps []map[string]any, in map[string]any) string {
	e.t.Helper()
	body := map[string]any{"steps": steps}
	for k, v := range in {
		body[k] = v
	}
	st, resp, _ := e.do("POST", "/v1/pipe", stok, body)
	if st != 200 && st != 202 {
		e.t.Fatalf("create pipe: %d %s", st, resp)
	}
	pid := strings.Fields(resp)[0]
	if !core.ValidID(pid) || pid[0] != 'q' {
		e.t.Fatalf("bad pipe id: %s", resp)
	}
	return pid
}

// --- tests ------------------------------------------------------------------------------------

func TestChainThreeSteps(t *testing.T) {
	e := newEnv(t)
	_, stok, wtoks, wasms := e.setup(3)
	seed := e.put(stok, []byte("the-seed-input"))
	pid := e.createPipe(stok, []map[string]any{
		{"wasm": wasms[0]}, {"wasm": wasms[1]}, {"wasm": wasms[2]},
	}, map[string]any{"in": seed})

	v := e.drive(pid, wtoks, transform)
	if v.State != "done" || v.Cur != 3 || len(v.Outs) != 3 {
		t.Fatalf("pipe not done: state=%s cur=%d outs=%v", v.State, v.Cur, v.Outs)
	}
	// Each step consumed the previous step's output as its input.
	if v.Outs[2] != sha([]byte("out-2-"+v.Outs[1][:8])) {
		t.Fatalf("final out not chained from step 2 input: %v", v.Outs)
	}

	// GET ?att=1 prints a pipe1 line that /verify validates.
	st, body, _ := e.do("GET", "/v1/pipe/"+pid+"?att=1", stok, nil)
	if st != 200 || !strings.Contains(body, "done 3/3") {
		t.Fatalf("att get: %d %s", st, body)
	}
	line, sig := pipe1Of(t, body)
	vst, vbody, _ := e.do("GET", "/verify?s="+url.QueryEscape(line)+"&sig="+url.QueryEscape(sig), "", nil)
	if vst != 200 || !strings.HasPrefix(vbody, "valid ") || !strings.Contains(vbody, "type=pipe1") {
		t.Fatalf("verify: %d %s (line=%q)", vst, vbody, line)
	}
}

func TestInterpreterFraming(t *testing.T) {
	// frame() unit coverage: small -> JSON, large -> NUL split, {-prefixed code stays JSON.
	if got := string(frame("P", []byte("hi"))); got != `{"code":"P","stdin":"hi"}` {
		t.Fatalf("json framing: %s", got)
	}
	big := bytes.Repeat([]byte("x"), frameInline+1)
	nf := frame("PROG", big)
	if !bytes.Equal(nf, append([]byte("PROG\x00"), big...)) {
		t.Fatalf("NUL framing wrong (len=%d)", len(nf))
	}
	if got := string(frame("{jq}", big)); !strings.HasPrefix(got, `{"code":"{jq}"`) {
		t.Fatalf("brace code must stay JSON: %.20s", got)
	}

	// Integration: a tool step feeds an interpreter step; the interpreter job's input is the frame.
	e := newEnv(t)
	_, stok, wtoks, wasms := e.setup(2)
	seed := e.put(stok, []byte("seed"))
	pid := e.createPipe(stok, []map[string]any{
		{"wasm": wasms[0]},                      // tool step: raw stdin
		{"wasm": wasms[1], "code": "PROGRAM()"}, // interpreter step: {code,stdin} framing
	}, map[string]any{"in": seed})

	// Run step 0 only, then advance so step 1 is submitted but not yet run.
	ctx := context.Background()
	e.s.advanceOne(ctx, pid)
	e.runStep(pid, wtoks, transform) // step 0
	e.s.advanceOne(ctx, pid)         // submits step 1

	step0Out := e.view(pid).Outs[0]
	data, _ := e.s.readBlob(step0Out)
	wantIn := sha(frame("PROGRAM()", data))
	var gotIn string
	if err := testPool.QueryRow(ctx, `SELECT input FROM jobs WHERE pipe = $1 AND wasm = $2 ORDER BY created DESC LIMIT 1`, pid, wasms[1]).Scan(&gotIn); err != nil {
		t.Fatalf("load step1 job: %v", err)
	}
	if gotIn != wantIn {
		t.Fatalf("interpreter input not framed: got %s want %s", gotIn, wantIn)
	}
}

// runStep leases+reports exactly the currently queued step once (both donors).
func (e *env) runStep(pid string, wtoks []string, stepFn func(idx int, in string) (string, []byte)) {
	idx := e.view(pid).Cur
	for i := 0; i < 50; i++ {
		prog := false
		for _, tok := range wtoks {
			l := e.lease(tok)
			if l == nil {
				continue
			}
			prog = true
			status, out := stepFn(idx, l.In)
			h := ""
			if status == "ok" {
				h = e.put(tok, out)
			}
			e.done(tok, l.Lease, status, h, l.Ms/2)
		}
		if !prog {
			return
		}
	}
}

func TestFailedStepPartialOutsRefund(t *testing.T) {
	e := newEnv(t)
	sid, stok, wtoks, wasms := e.setup(3)
	before := e.credits(sid)
	seed := e.put(stok, []byte("seed-fail"))
	pid := e.createPipe(stok, []map[string]any{
		{"wasm": wasms[0]}, {"wasm": wasms[1]}, {"wasm": wasms[2]},
	}, map[string]any{"in": seed, "ms": 5000})

	// Step 0 succeeds, step 1 fails (both donors report error -> no consensus output).
	v := e.drive(pid, wtoks, func(idx int, in string) (string, []byte) {
		if idx == 1 {
			return "error", nil
		}
		return transform(idx, in)
	})
	if v.State != "failed" || v.FailIdx != 1 {
		t.Fatalf("expected failure at step 2: state=%s fail_idx=%d", v.State, v.FailIdx)
	}
	if len(v.Outs) != 1 {
		t.Fatalf("partial outs not kept: %v", v.Outs)
	}
	// Step 2 never ran and its reservation was refunded; at most two steps' cost was charged.
	spent := before - e.credits(sid)
	if spent > 2*costOf(5000) {
		t.Fatalf("step 3 not refunded: spent %d", spent)
	}
	// The failed pipe is readable with its partial output via ?step=1.
	st, body, _ := e.do("GET", "/v1/pipe/"+pid, stok, nil)
	if st != 200 || !strings.Contains(body, "failed step 2/3") {
		t.Fatalf("failed status: %d %s", st, body)
	}
}

func (e *env) credits(id string) int64 {
	var c int64
	if err := testPool.QueryRow(context.Background(), `SELECT credits FROM identities WHERE id = $1`, id).Scan(&c); err != nil {
		e.t.Fatal(err)
	}
	return c
}

func TestPerStepCacheHits(t *testing.T) {
	e := newEnv(t)
	_, stok, wtoks, wasms := e.setup(3)
	seed := e.put(stok, []byte("cache-seed"))
	steps := []map[string]any{{"wasm": wasms[0]}, {"wasm": wasms[1]}, {"wasm": wasms[2]}}

	p1 := e.createPipe(stok, steps, map[string]any{"in": seed})
	v1 := e.drive(p1, wtoks, transform)
	if v1.State != "done" {
		t.Fatalf("first run: %s", v1.State)
	}

	// Second identical pipe: every step is a cache hit, so it completes with NO donor activity.
	p2 := e.createPipe(stok, steps, map[string]any{"in": seed})
	ctx := context.Background()
	for i := 0; i < 12; i++ {
		e.s.advanceOne(ctx, p2)
		if e.view(p2).final() {
			break
		}
	}
	v2 := e.view(p2)
	if v2.State != "done" || v2.Cur != 3 {
		t.Fatalf("cached run not done without donors: state=%s cur=%d", v2.State, v2.Cur)
	}
	// The outputs match the first run (same cached results).
	if fmt.Sprint(v2.Outs) != fmt.Sprint(v1.Outs) {
		t.Fatalf("cached outs differ: %v vs %v", v2.Outs, v1.Outs)
	}
	// All of p2's step jobs are cache hits.
	var cached, total int
	testPool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE cached_from <> ''), count(*) FROM jobs WHERE pipe = $1`, p2).Scan(&cached, &total)
	if total == 0 || cached != total {
		t.Fatalf("p2 jobs not all cached: %d/%d", cached, total)
	}
}

func TestPipe1Attestation(t *testing.T) {
	e := newEnv(t)
	_, stok, wtoks, wasms := e.setup(2)
	seed := e.put(stok, []byte("att-seed"))
	pid := e.createPipe(stok, []map[string]any{{"wasm": wasms[0]}, {"wasm": wasms[1]}}, map[string]any{"in": seed})
	v := e.drive(pid, wtoks, transform)
	if v.State != "done" {
		t.Fatalf("not done: %s", v.State)
	}
	if v.Att == "" || !strings.HasPrefix(v.Att, "pipe1 q="+pid+" ") {
		t.Fatalf("no pipe1 line: %q", v.Att)
	}
	// The statement must bind the pipeline's steps and outputs digests and verify under pipe1.
	if !strings.Contains(v.Att, "steps=") || !strings.Contains(v.Att, "outs=") || !strings.Contains(v.Att, "k=") {
		t.Fatalf("pipe1 fields missing: %s", v.Att)
	}
	s := sign.MustNew(e.d.Cfg)
	if _, ok := s.Verify("pipe1", v.Att, v.AttSig); !ok {
		t.Fatalf("pipe1 signature does not verify: %s / %s", v.Att, v.AttSig)
	}
	// A tampered line must not verify.
	if _, ok := s.Verify("pipe1", v.Att+" x=1", v.AttSig); ok {
		t.Fatal("tampered pipe1 verified")
	}
}

func TestCapsCountAsEightJobs(t *testing.T) {
	e := newEnv(t)
	sid, stok, wtoks, wasms := e.setup(2)
	seed := e.put(stok, []byte("caps-seed"))
	steps := []map[string]any{{"wasm": wasms[0]}, {"wasm": wasms[1]}}

	p := e.createPipe(stok, steps, map[string]any{"in": seed})
	e.drive(p, wtoks, transform)
	if n := e.counter(sid, "pipe_jobs"); n != pipeJobs {
		t.Fatalf("one pipe did not count as 8 jobs: %d", n)
	}
	// Push the counter to just under the cap; the next pipe's 8 jobs exceed it -> 429.
	if _, err := testPool.Exec(context.Background(), `UPDATE counters SET n = $2 WHERE scope = $1 AND kind = 'pipe_jobs' AND day = current_date`, sid, maxPipeJobs-4); err != nil {
		t.Fatal(err)
	}
	st, body, _ := e.do("POST", "/v1/pipe", stok, map[string]any{"steps": steps, "in": seed})
	if st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("expected quota refusal: %d %s", st, body)
	}
}

func (e *env) counter(root, kind string) int {
	var n int
	testPool.QueryRow(context.Background(), `SELECT coalesce((SELECT n FROM counters WHERE scope = $1 AND kind = $2 AND day = current_date), 0)`, root, kind).Scan(&n)
	return n
}

func TestLongPollAndStepRead(t *testing.T) {
	e := newEnv(t)
	_, stok, wtoks, wasms := e.setup(3)
	seed := e.put(stok, []byte("poll-seed"))
	pid := e.createPipe(stok, []map[string]any{{"wasm": wasms[0]}, {"wasm": wasms[1]}, {"wasm": wasms[2]}}, map[string]any{"in": seed})
	v := e.drive(pid, wtoks, transform)
	if v.State != "done" {
		t.Fatalf("not done: %s", v.State)
	}

	// Long-poll on a finished pipe returns immediately with the done head and indented stdout.
	st, body, _ := e.do("GET", "/v1/pipe/"+pid+"?wait=2", stok, nil)
	if st != 200 || !strings.HasPrefix(body, pid+" done 3/3") || !strings.Contains(body, "\n  ") {
		t.Fatalf("long-poll done: %d %q", st, body)
	}

	// ?step=2 reports progress reached at least step 2.
	st, body, _ = e.do("GET", "/v1/pipe/"+pid+"?step=2&f=json", stok, nil)
	var j map[string]any
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || int(j["cur"].(float64)) < 2 {
		t.Fatalf("step read: %d %s", st, body)
	}

	// ?raw=1 returns the final output bytes verbatim; ?step=1&raw=1 returns step 1's output.
	st, raw, hd := e.do("GET", "/v1/pipe/"+pid+"?raw=1", stok, nil)
	wantFinal, _ := e.s.readBlob(v.out())
	if st != 200 || raw != string(wantFinal) || hd.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("raw final: %d %q", st, raw)
	}
	st, raw1, _ := e.do("GET", "/v1/pipe/"+pid+"?raw=1&step=1", stok, nil)
	want1, _ := e.s.readBlob(v.Outs[0])
	if st != 200 || raw1 != string(want1) {
		t.Fatalf("raw step1: %d %q", st, raw1)
	}

	// A foreign root cannot read the pipe.
	_, otok := e.register("other")
	if st, _, _ := e.do("GET", "/v1/pipe/"+pid, otok, nil); st != 404 {
		t.Fatalf("foreign read: %d", st)
	}
}

// pipe1Of extracts the pipe1 statement line and its sig= token from an ?att=1 body.
func pipe1Of(t *testing.T, body string) (line, sig string) {
	t.Helper()
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "pipe1 ") {
			line = ln
		} else if strings.HasPrefix(ln, "sig=") {
			sig = ln
		}
	}
	if line == "" || sig == "" {
		t.Fatalf("no pipe1/sig in %q", body)
	}
	return
}
