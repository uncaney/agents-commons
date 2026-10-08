package svcmcp

// Acceptance tests of P112 (SPEC-v2 27.7). They drive the real HTTP surface: identities register
// through the PoW challenge and modules upload as blobs and run through compute's lease/done loop
// with simulated donors. A helper flips a published version to verified+stable and records one L2
// ok vote via SQL so the per-service endpoints treat the service as installable.

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
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/trust"
)

const adminTok = "cx-admin-test"

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		fmt.Println("TEST_DATABASE_URL unset: skipping svcmcp DB tests")
		os.Exit(0)
	}
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
	testPool = pool
	core.LevelFn = trust.LevelOf
	code := m.Run()
	pool.Close()
	os.Exit(code)
}

// --- wasm fixture (a valid module exporting an empty _start; tag makes each hash distinct) -------

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

func minWasm(tag string) []byte {
	b := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0,
		3, 2, 1, 0,
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0,
		10, 4, 1, 2, 0, 0x0b}
	return append(b, customSection("t", tag)...)
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// --- env -----------------------------------------------------------------------------------------

type env struct {
	t     *testing.T
	d     *core.Deps
	srv   *httptest.Server
	roots []string
	names []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true, RegPerHour: 1 << 20,
		AdminToken: adminTok, PublicURL: "https://t.example", AdminBlobMax: 64 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAdminV2(mux, d)
	compute.Register(mux, d)
	catalog.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	e := &env{t: t, d: d, srv: srv}
	t.Cleanup(func() {
		srv.Close()
		ctx := context.Background()
		if len(e.names) > 0 {
			testPool.Exec(ctx, `DELETE FROM services WHERE name = ANY($1)`, e.names)
		}
		d.Close()
	})
	return e
}

var ipSeq = func() *uint32 { var n uint32 = 1000; return &n }()

func randIP() string {
	n := atomic.AddUint32(ipSeq, 1)
	return fmt.Sprintf("10.%d.%d.%d", (n>>8)&0xff, n&0xff, 1+int(n)%250)
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
	ip := randIP()
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

func (e *env) l1(root string) {
	e.t.Helper()
	testPool.Exec(context.Background(), `UPDATE identities SET rep = 1, created = now() - interval '2 days' WHERE id = $1`, root)
}

func (e *env) l2(root string) {
	e.t.Helper()
	testPool.Exec(context.Background(), `UPDATE identities SET rep = 5, created = now() - interval '4 days', verified_noncompute = 1 WHERE id = $1`, root)
}

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

func (e *env) manifest() map[string]any {
	return map[string]any{"desc": "echo the input back", "usage": "send text", "abi": "text", "in": "text", "out": "text",
		"ms_hint": 2000, "mb_hint": 32, "tests": []map[string]any{{"in_text": "a", "out_sha256": sha([]byte("A"))}}}
}

// publishServed publishes a module and SQL-forces it to verified+stable with one L2 ok vote, so
// the per-service endpoints treat it as installable. Returns name and the stable wasm hash.
func (e *env) publishServed(prefix string, extra map[string]any) (name, wasm string) {
	e.t.Helper()
	pid, ptok := e.register("pub")
	e.l1(pid)
	wasm = e.put(ptok, minWasm(pid+prefix))
	name = uname(prefix)
	e.names = append(e.names, name)
	m := e.manifest()
	for k, v := range extra {
		m[k] = v
	}
	st, body, _ := e.do("POST", "/v1/svc", ptok, map[string]any{"name": name, "wasm": wasm, "manifest": m})
	if st != 201 || !strings.HasPrefix(body, "ok "+name+"@") {
		e.t.Fatalf("publish %s: %d %s", name, st, body)
	}
	ctx := context.Background()
	// Kill the scheduled KAT jobs so the worker loop only runs our calls, then force the version.
	testPool.Exec(ctx, `UPDATE jobs SET status='failed', finished_at=now() WHERE svc=$1 AND kind='kat' AND status IN ('queued','running')`, name+"@1")
	testPool.Exec(ctx, `UPDATE service_versions SET state='verified', verified_at=now() WHERE name=$1 AND ver=1`, name)
	testPool.Exec(ctx, `UPDATE services SET stable_ver=1, stable_at=now() WHERE name=$1`, name)
	e.addL2(name, 1)
	return name, wasm
}

// addL2 records one ok vote from a distinct L2 super-group so hasL2 sees the service as confirmed.
func (e *env) addL2(name string, ver int) {
	e.t.Helper()
	vid, _ := e.register("l2voter")
	e.l2(vid)
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO service_votes (name, ver, root, ip_group, ip_super, up, w, lvl) VALUES ($1,$2,$3,'g-l2','svcmcp-test-super',true,1,2)`,
		name, ver, vid); err != nil {
		e.t.Fatalf("addL2: %v", err)
	}
}

type leaseOut struct {
	Lease, Job, Wasm, In, FS, Kind string
	Ms, Mb                         int
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

func (e *env) done(tok, lease, out string, ms int) {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/w/done", tok, map[string]any{"lease": lease, "status": "ok", "out": out, "code": 0, "ms": ms})
	if st != 200 || body != `{"ok":true}` {
		e.t.Fatalf("done: %d %s", st, body)
	}
}

// work makes every worker lease and report until nothing is eligible, producing out for each job.
func (e *env) work(wtoks []string, out string) int {
	e.t.Helper()
	n := 0
	for i := 0; i < 50; i++ {
		progressed := false
		for _, tok := range wtoks {
			l := e.lease(tok)
			if l == nil {
				continue
			}
			progressed = true
			h := e.put(tok, []byte(out))
			e.done(tok, l.Lease, h, l.Ms/2)
			n++
		}
		if !progressed {
			break
		}
	}
	return n
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

// warm runs the stable service once on in_text through two donors so the result is cached; a later
// tools/call on the same input then returns immediately (done) regardless of the long-poll.
func (e *env) warm(caller, name, inText, out string) {
	e.t.Helper()
	if st, _, _ := e.do("POST", "/v1/svc/"+name, caller, map[string]any{"in_text": inText}); st != 202 && st != 200 {
		e.t.Fatalf("warm call: %d", st)
	}
	e.work(e.workers(2), out)
}

func (e *env) credits(id string) int64 {
	e.t.Helper()
	var c int64
	testPool.QueryRow(context.Background(), `SELECT credits FROM identities WHERE id=$1`, id).Scan(&c)
	return c
}

var nameSeq atomic.Uint32

func uname(prefix string) string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("%s-%x%02x", prefix, b, nameSeq.Add(1)%100)
}

// --- MCP JSON-RPC helpers ------------------------------------------------------------------------

func rpcBody(method string, params any) map[string]any {
	m := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		m["params"] = params
	}
	return m
}

func (e *env) rpc(path, token, method string, params any) map[string]any {
	e.t.Helper()
	st, body, _ := e.do("POST", path, token, rpcBody(method, params))
	if st != 200 {
		e.t.Fatalf("rpc %s %s: %d %s", path, method, st, body)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		e.t.Fatalf("rpc decode: %s", body)
	}
	return m
}

// result returns the JSON-RPC result object, failing on a protocol error.
func (e *env) result(m map[string]any) map[string]any {
	e.t.Helper()
	if m["error"] != nil {
		e.t.Fatalf("rpc error: %v", m["error"])
	}
	r, _ := m["result"].(map[string]any)
	if r == nil {
		e.t.Fatalf("no result: %v", m)
	}
	return r
}

// callText returns the tools/call result's text and isError flag.
func toolCall(m map[string]any) (string, bool) {
	r, _ := m["result"].(map[string]any)
	content, _ := r["content"].([]any)
	text := ""
	if len(content) > 0 {
		c, _ := content[0].(map[string]any)
		text, _ = c["text"].(string)
	}
	isErr, _ := r["isError"].(bool)
	return text, isErr
}

// --- tests ---------------------------------------------------------------------------------------

func TestToolsListShapeAndPrefix(t *testing.T) {
	e := newEnv(t)
	name, _ := e.publishServed("echo", nil)

	init := e.result(e.rpc("/mcp/svc/"+name, "", "initialize", map[string]any{"protocolVersion": "2025-06-18"}))
	if init["protocolVersion"] != "2025-06-18" {
		t.Fatalf("protocolVersion not echoed: %v", init["protocolVersion"])
	}
	si, _ := init["serverInfo"].(map[string]any)
	if si["name"] != "agents.ekaii.fr/svc/"+name {
		t.Fatalf("serverInfo name: %v", si["name"])
	}
	if instr, _ := init["instructions"].(string); !strings.Contains(instr, "/svc/"+name) {
		t.Fatalf("instructions missing page URL: %q", instr)
	}

	lst := e.result(e.rpc("/mcp/svc/"+name, "", "tools/list", nil))
	tools, _ := lst["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("want exactly one tool, got %d", len(tools))
	}
	tool, _ := tools[0].(map[string]any)
	if tool["name"] != name {
		t.Fatalf("tool name: %v", tool["name"])
	}
	desc, _ := tool["description"].(string)
	if !strings.HasPrefix(desc, "[agents.ekaii.fr service by ") || !strings.Contains(desc, "untrusted]") {
		t.Fatalf("description prefix wrong: %q", desc)
	}
	sch, _ := tool["inputSchema"].(map[string]any)
	if sch["type"] != "object" {
		t.Fatalf("default inputSchema: %v", sch)
	}
}

func TestToolsCallChargesCaller(t *testing.T) {
	e := newEnv(t)
	name, _ := e.publishServed("echo", map[string]any{"fee": 2})
	cid, caller := e.register("caller")
	e.l1(cid)
	e.warm(caller, name, "hello", "HELLO\n")

	before := e.credits(cid)
	res := e.rpc("/mcp/svc/"+name, caller, "tools/call", map[string]any{"name": name, "arguments": map[string]any{"input": "hello"}})
	text, isErr := toolCall(res)
	if isErr || text != "HELLO" {
		t.Fatalf("tools/call text=%q isError=%v", text, isErr)
	}
	after := e.credits(cid)
	if after >= before {
		t.Fatalf("caller not charged: before=%d after=%d", before, after)
	}
	var n int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM service_calls WHERE name=$1 AND caller=$2`, name, cid).Scan(&n)
	if n == 0 {
		t.Fatal("no service_calls row for the caller")
	}
}

func TestAnonymousCallHint(t *testing.T) {
	e := newEnv(t)
	name, _ := e.publishServed("echo", nil)
	res := e.rpc("/mcp/svc/"+name, "", "tools/call", map[string]any{"name": name, "arguments": map[string]any{"input": "x"}})
	text, isErr := toolCall(res)
	if !isErr {
		t.Fatalf("anonymous call should be isError: %q", text)
	}
	if !strings.Contains(text, "challenge") || !strings.Contains(text, "join") {
		t.Fatalf("missing PoW/join hint: %q", text)
	}
}

func TestUrlTokenPath(t *testing.T) {
	e := newEnv(t)
	name, _ := e.publishServed("echo", nil)
	rid, root := e.register("urlroot")
	e.l1(rid)
	// Mint a url-class subkey, then provision it with credits (url subkeys carry none by default).
	st, body, _ := e.do("POST", "/v1/subkey", root, map[string]any{"name": "share", "class": "url"})
	if st != 201 {
		t.Fatalf("mint url token: %d %s", st, body)
	}
	var subID, urlTok string
	for _, f := range strings.Fields(strings.SplitN(body, "\n", 2)[0]) {
		if v, ok := strings.CutPrefix(f, "id="); ok {
			subID = v
		} else if v, ok := strings.CutPrefix(f, "token="); ok {
			urlTok = v
		}
	}
	testPool.Exec(context.Background(), `UPDATE identities SET credits=500 WHERE id=$1`, subID)

	path := "/mcp/svc/" + name + "/t/" + urlTok
	lst := e.result(e.rpc(path, "", "tools/list", nil))
	if tools, _ := lst["tools"].([]any); len(tools) != 1 {
		t.Fatalf("url-token tools/list: %v", lst)
	}
	e.warm(root, name, "hello", "HELLO\n")
	res := e.rpc(path, "", "tools/call", map[string]any{"name": name, "arguments": map[string]any{"input": "hello"}})
	if text, isErr := toolCall(res); isErr || text != "HELLO" {
		t.Fatalf("url-token tools/call text=%q isError=%v", text, isErr)
	}
	// A non-url token in the path is rejected at tools/call.
	_, bad := e.register("noturl")
	bres := e.rpc("/mcp/svc/"+name+"/t/"+bad, "", "tools/call", map[string]any{"name": name, "arguments": map[string]any{"input": "hello"}})
	if text, isErr := toolCall(bres); !isErr || !strings.Contains(text, "auth") {
		t.Fatalf("non-url token accepted: %q", text)
	}
}

func TestOpenAPIPerService(t *testing.T) {
	e := newEnv(t)
	name, _ := e.publishServed("echo", nil)

	st, body, _ := e.do("GET", "/svc/"+name+"/openapi.json", "", nil)
	if st != 200 {
		t.Fatalf("openapi: %d %s", st, body)
	}
	var oa map[string]any
	if err := json.Unmarshal([]byte(body), &oa); err != nil {
		t.Fatalf("openapi decode: %v", err)
	}
	if oa["openapi"] != "3.1.0" {
		t.Fatalf("openapi version: %v", oa["openapi"])
	}
	paths, _ := oa["paths"].(map[string]any)
	runPath := "/v1/svc/" + name + "/run"
	p, ok := paths[runPath].(map[string]any)
	if !ok {
		t.Fatalf("missing run path: %v", paths)
	}
	post, _ := p["post"].(map[string]any)
	xmcp, _ := post["x-mcp"].(map[string]any)
	if u, _ := xmcp["url"].(string); !strings.HasSuffix(u, "/mcp/svc/"+name) {
		t.Fatalf("x-mcp url: %v", xmcp)
	}
	if post["security"] == nil {
		t.Fatal("run operation has no bearer security")
	}

	st, body, _ = e.do("GET", "/svc/"+name+"/mcp.json", "", nil)
	if st != 200 {
		t.Fatalf("mcp.json: %d %s", st, body)
	}
	var mj map[string]any
	json.Unmarshal([]byte(body), &mj)
	servers, _ := mj["mcpServers"].(map[string]any)
	entry, _ := servers[name].(map[string]any)
	if entry["type"] != "http" || !strings.HasSuffix(entry["url"].(string), "/mcp/svc/"+name) {
		t.Fatalf("mcp.json entry: %v", servers)
	}

	// A name that is not served answers 404.
	if st, _, _ := e.do("GET", "/svc/"+uname("ghost")+"/openapi.json", "", nil); st != 404 {
		t.Fatalf("unknown openapi should 404: %d", st)
	}
}

func TestOnlyStableWithL2Ok(t *testing.T) {
	e := newEnv(t)
	// Verified but no stable pointer: not served.
	pid, ptok := e.register("pub")
	e.l1(pid)
	wasm := e.put(ptok, minWasm(pid+"nostable"))
	name := uname("nostable")
	e.names = append(e.names, name)
	if st, body, _ := e.do("POST", "/v1/svc", ptok, map[string]any{"name": name, "wasm": wasm, "manifest": e.manifest()}); st != 201 {
		t.Fatalf("publish: %d %s", st, body)
	}
	testPool.Exec(context.Background(), `UPDATE service_versions SET state='verified', verified_at=now() WHERE name=$1 AND ver=1`, name)
	if st, _, _ := e.do("POST", "/mcp/svc/"+name, "", rpcBody("tools/list", nil)); st != 404 {
		t.Fatalf("no-stable service served: %d", st)
	}

	// Stable but no L2 ok: not served.
	testPool.Exec(context.Background(), `UPDATE services SET stable_ver=1, stable_at=now() WHERE name=$1`, name)
	if st, _, _ := e.do("POST", "/mcp/svc/"+name, "", rpcBody("tools/list", nil)); st != 404 {
		t.Fatalf("stable-without-L2 served: %d", st)
	}

	// Add one L2 ok: now served.
	e.addL2(name, 1)
	st, body, _ := e.do("POST", "/mcp/svc/"+name, "", rpcBody("tools/list", nil))
	if st != 200 {
		t.Fatalf("stable+L2 not served: %d %s", st, body)
	}
}

func TestBatchCap(t *testing.T) {
	e := newEnv(t)
	name, _ := e.publishServed("echo", nil)

	// A batch of 11 is refused before any dispatch.
	var big []any
	for i := 0; i < 11; i++ {
		big = append(big, rpcBody("ping", nil))
	}
	st, body, _ := e.do("POST", "/mcp/svc/"+name, "", big)
	if st != 400 || !strings.Contains(body, "batch too large") {
		t.Fatalf("batch of 11: %d %s", st, body)
	}

	// A batch of 10 is answered with 10 responses.
	var ok []any
	for i := 0; i < 10; i++ {
		ok = append(ok, map[string]any{"jsonrpc": "2.0", "id": i, "method": "ping"})
	}
	st, body, _ = e.do("POST", "/mcp/svc/"+name, "", ok)
	if st != 200 {
		t.Fatalf("batch of 10: %d %s", st, body)
	}
	var arr []any
	if err := json.Unmarshal([]byte(body), &arr); err != nil || len(arr) != 10 {
		t.Fatalf("batch of 10 responses: %v (%s)", len(arr), body)
	}
}
