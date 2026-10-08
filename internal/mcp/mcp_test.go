package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	// Prefer an explicit TEST_DATABASE_URL (the workflow's scratch DB); otherwise fall back to the
	// per-package isolated database from internal/testdb so parallel builders never race.
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		ctx := context.Background()
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool = pool
		code := m.Run()
		pool.Close()
		os.Exit(code)
	}
	pool, cleanup := testdb.Open("mcp", core.Migrate)
	testPool = pool
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
	ip  string
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true, RegPerHour: 1 << 20,
		ForgejoURL: "http://127.0.0.1:1", ForgejoToken: "x", PublicURL: "https://agents.test"}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	kb.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	var b [2]byte
	rand.Read(b[:])
	return &tenv{d, srv, fmt.Sprintf("10.7.%d.%d", b[0], b[1])}
}

// raw posts body to /mcp and returns status, headers and body.
func (e *tenv) raw(t *testing.T, method, body, token string) (int, http.Header, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("CF-Connecting-IP", e.ip)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, b
}

// rpc sends one request and decodes the response envelope.
func (e *tenv) rpc(t *testing.T, token string, id any, method string, params any) (map[string]any, []byte) {
	t.Helper()
	msg := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		msg["params"] = params
	}
	b, _ := json.Marshal(msg)
	st, h, body := e.raw(t, "POST", string(b), token)
	if st != 200 {
		t.Fatalf("%s: status %d %s", method, st, body)
	}
	if ct := h.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type %q", ct)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("bad json: %v %s", err, body)
	}
	return out, body
}

func (e *tenv) call(t *testing.T, token, op string, a any) (string, bool) {
	t.Helper()
	args := map[string]any{"op": op}
	if a != nil {
		args["a"] = a
	}
	out, body := e.rpc(t, token, 1, "tools/call", map[string]any{"name": "cx", "arguments": args})
	res, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %s", body)
	}
	c := res["content"].([]any)[0].(map[string]any)
	isErr, _ := res["isError"].(bool)
	return c["text"].(string), isErr
}

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

func (e *tenv) register(t *testing.T, name string) (id, tok string) {
	t.Helper()
	do := func(path string, body any) string {
		var rd io.Reader
		if body != nil {
			j, _ := json.Marshal(body)
			rd = bytes.NewReader(j)
		}
		req, _ := http.NewRequest("POST", e.srv.URL+path, rd)
		req.Header.Set("CF-Connecting-IP", e.ip)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode/100 != 2 {
			t.Fatalf("%s: %d %s", path, res.StatusCode, b)
		}
		return string(b)
	}
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(do("/v1/challenge", nil), -1) {
		m[x[1]] = x[2]
	}
	c := m["c"]
	out := do("/v1/register", map[string]string{"c": c, "nonce": pow.Solve(c, 6), "name": name})
	m = map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(out, -1) {
		m[x[1]] = x[2]
	}
	return m["id"], m["token"]
}

// ident looks a token up as an *Ident (for minting scoped subkeys in tests).
func (e *tenv) ident(t *testing.T, tok string) *core.Ident {
	t.Helper()
	id, err := e.d.LookupToken(context.Background(), tok)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	return id
}

func TestInitialize(t *testing.T) {
	e := newEnv(t)
	for _, tc := range [][2]string{{"2025-03-26", "2025-03-26"}, {"2024-11-05", "2024-11-05"}, {"2025-06-18", "2025-06-18"}, {"1999-01-01", "2025-06-18"}, {"", "2025-06-18"}} {
		out, body := e.rpc(t, "", 1, "initialize", map[string]any{"protocolVersion": tc[0], "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "t", "version": "0"}})
		res := out["result"].(map[string]any)
		if res["protocolVersion"] != tc[1] {
			t.Fatalf("proto %q -> %v: %s", tc[0], res["protocolVersion"], body)
		}
		si := res["serverInfo"].(map[string]any)
		if si["name"] != ServerName || si["version"] != Version {
			t.Fatalf("serverInfo: %s", body)
		}
		caps := res["capabilities"].(map[string]any)
		for _, c := range []string{"tools", "resources", "prompts", "completions"} {
			if _, ok := caps[c]; !ok {
				t.Fatalf("capabilities missing %s: %s", c, body)
			}
		}
		if s, _ := res["instructions"].(string); s == "" {
			t.Fatalf("instructions: %q", s)
		}
	}
	if out, _ := e.rpc(t, "", 7, "ping", nil); out["result"] == nil || fmt.Sprint(out["id"]) != "7" {
		t.Fatalf("ping: %v", out)
	}
}

func TestInstructionsBudget(t *testing.T) {
	if n := len(Instructions); n > 400 {
		t.Fatalf("instructions %d bytes > 400", n)
	}
	// The framing must name the reasons to use it (19.6).
	for _, w := range []string{"memory", "swarm", "compute", "untrusted"} {
		if !strings.Contains(Instructions, w) {
			t.Fatalf("instructions missing %q: %q", w, Instructions)
		}
	}
}

func TestToolsList(t *testing.T) {
	e := newEnv(t)
	out, body := e.rpc(t, "", "abc", "tools/list", nil)
	tools := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("tools: %s", body)
	}
	tool := tools[0].(map[string]any)
	if tool["name"] != "cx" || tool["description"] != ToolDesc {
		t.Fatalf("tool: %s", body)
	}
	if n := len(strings.Fields(ToolDesc)); n > 60 {
		t.Fatalf("description %d words > 60", n)
	}
	schema, _ := json.Marshal(tool["inputSchema"])
	if string(schema) != `{"properties":{"a":{"type":"object"},"op":{"type":"string"}},"required":["op"],"type":"object"}` {
		t.Fatalf("schema: %s", schema)
	}
	if len(body) >= 900 {
		t.Fatalf("tools/list response %d bytes >= 900", len(body))
	}
	t.Logf("tools/list response: %d bytes", len(body))
}

func TestHelpBudgets(t *testing.T) {
	if n := len(HelpIndex()); n > indexBudget {
		t.Fatalf("help index %d bytes > %d", n, indexBudget)
	}
	for _, ns := range Namespaces() {
		s, ok := helpFor(ns)
		if !ok {
			t.Fatalf("namespace %q has no page", ns)
		}
		if n := len(s); n > nsBudget {
			t.Fatalf("namespace %q page %d bytes > %d", ns, n, nsBudget)
		}
	}
}

func TestHelpIndexBudgetWithRev3Namespaces(t *testing.T) {
	idx := HelpIndex()
	if n := len(idx); n > indexBudget {
		t.Fatalf("rev3 help index %d bytes > %d", n, indexBudget)
	}
	for _, ns := range []string{"sessions", "graph", "rooms", "pay", "auctions", "treasury", "hooks", "hubs", "clients"} {
		if !strings.Contains(idx, ns) {
			t.Fatalf("help index missing rev3 namespace %q: %s", ns, idx)
		}
	}
	// The index must point agents at a token and mark content untrusted.
	for _, w := range []string{"Bearer", "cx join", "untrusted"} {
		if !strings.Contains(idx, w) {
			t.Fatalf("help index missing %q", w)
		}
	}
}

func TestCallAnonymousAndAuth(t *testing.T) {
	e := newEnv(t)
	// help index: namespaces + token hint + untrusted banner.
	txt, isErr := e.call(t, "", "help", nil)
	if isErr || !strings.Contains(txt, "Bearer") || !strings.Contains(txt, "cx join") || !strings.Contains(txt, "untrusted") {
		t.Fatalf("help: %v %q", isErr, txt)
	}
	for _, ns := range Namespaces() {
		if !strings.Contains(txt, ns) {
			t.Fatalf("help index lacks namespace %s", ns)
		}
	}
	// A namespace page lists its ops.
	board, isErr := e.call(t, "", "help", map[string]any{"t": "board"})
	if isErr || !strings.Contains(board, "t{") || !strings.Contains(board, "tp{") {
		t.Fatalf("help board: %v %q", isErr, board)
	}
	if _, isErr := e.call(t, "", "help", map[string]any{"t": "nope"}); !isErr {
		t.Fatal("help unknown namespace should error")
	}
	// Anonymous search works.
	if _, isErr := e.call(t, "", "s", map[string]any{"q": "nothing-matches-this-zzz"}); isErr {
		t.Fatal("anon search failed")
	}
	// Anonymous write -> isError with the hint (now with a next: tail).
	txt, isErr = e.call(t, "", "p", map[string]any{"kind": "fix", "title": "x", "symptom": "y", "fix": "z"})
	if !isErr || !strings.HasPrefix(txt, "err auth (get a token: op=help)") {
		t.Fatalf("anon write: %v %q", isErr, txt)
	}
	if txt, isErr = e.call(t, "", "me", nil); !isErr || !strings.HasPrefix(txt, "err auth") {
		t.Fatalf("anon me: %q", txt)
	}
	// Unknown op.
	if txt, isErr = e.call(t, "", "nope", nil); !isErr || !strings.HasPrefix(txt, "err bad unknown op") {
		t.Fatalf("unknown op: %q", txt)
	}
	if txt, isErr = e.call(t, "", "", nil); !isErr || !strings.HasPrefix(txt, "err bad") {
		t.Fatalf("missing op: %q", txt)
	}
	// Bad token -> err auth.
	if txt, isErr = e.call(t, "cx_"+strings.Repeat("A", 43), "s", nil); !isErr || !strings.HasPrefix(txt, "err auth invalid token") {
		t.Fatalf("bad token: %v %q", isErr, txt)
	}
	// Real token: me, p, g, sub.
	id, tok := e.register(t, "mcp-user")
	txt, isErr = e.call(t, tok, "me", nil)
	if isErr || !strings.HasPrefix(txt, "id="+id+" name=mcp-user root="+id+" credits=100 rep=0 exp=never") {
		t.Fatalf("me: %q", txt)
	}
	title := "mcp test entry " + id
	txt, isErr = e.call(t, tok, "p", map[string]any{"kind": "fix", "title": title, "symptom": "mcp symptom " + id, "fix": "do it", "force": true})
	if isErr || !strings.HasPrefix(txt, "ok k") {
		t.Fatalf("p: %v %q", isErr, txt)
	}
	kid := strings.Fields(strings.TrimPrefix(txt, "ok "))[0]
	txt, isErr = e.call(t, "", "g", map[string]any{"id": kid})
	if isErr || !strings.Contains(txt, "title: "+title) {
		t.Fatalf("g: %v %q", isErr, txt)
	}
	txt, isErr = e.call(t, tok, "sub", map[string]any{"name": "child", "credits": 10, "ttl_h": 2})
	if isErr || !strings.Contains(txt, " token=cx_") || !strings.Contains(txt, "credits=10") {
		t.Fatalf("sub: %v %q", isErr, txt)
	}
	subTok := kvRe.FindStringSubmatch(txt[strings.Index(txt, "token="):])[2]
	if txt, isErr = e.call(t, subTok, "me", nil); isErr || !strings.Contains(txt, "root="+id) || !strings.Contains(txt, "credits=10") {
		t.Fatalf("sub me: %q", txt)
	}
	if txt, isErr = e.call(t, tok, "me", nil); isErr || !strings.Contains(txt, "credits=90") {
		t.Fatalf("parent after sub: %q", txt)
	}
	// API errors keep the wire format (+ next tail).
	if txt, isErr = e.call(t, tok, "g", map[string]any{"id": "kzzzzzz"}); !isErr || !strings.HasPrefix(txt, "err notfound not found") {
		t.Fatalf("notfound: %q", txt)
	}
	// Unknown tool -> JSON-RPC error.
	out, _ := e.rpc(t, "", 1, "tools/call", map[string]any{"name": "other", "arguments": map[string]any{"op": "help"}})
	if out["error"] == nil {
		t.Fatalf("unknown tool: %v", out)
	}
}

func TestNextOnlyOnErr(t *testing.T) {
	e := newEnv(t)
	// Success: no next: tail.
	if txt, isErr := e.call(t, "", "help", nil); isErr || strings.Contains(txt, "\nnext:") {
		t.Fatalf("success carried next: %q", txt)
	}
	if txt, isErr := e.call(t, "", "s", map[string]any{"q": "zzz-no-match"}); isErr || strings.Contains(txt, "next:") {
		t.Fatalf("search carried next: %q", txt)
	}
	// Error: a next: recovery line is appended.
	txt, isErr := e.call(t, "", "nope", nil)
	if !isErr || !strings.Contains(txt, "next:") {
		t.Fatalf("err lacked next: %q", txt)
	}
	txt, isErr = e.call(t, "", "g", map[string]any{"id": "kzzzzzz"})
	if !isErr || !strings.Contains(txt, "next:") {
		t.Fatalf("notfound lacked next: %q", txt)
	}
}

func TestOpScopeAndCost(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register(t, "scope-root")
	parent := e.ident(t, tok)
	// A scoped token that holds kb:r and t:r but not t:w.
	_, scoped, err := core.CreateSubkeyV2(context.Background(), e.d.DB, parent, core.SubkeyOpts{
		Name: "scoped", Credits: 5, Exp: time.Now().Add(time.Hour), Scopes: []string{"kb:r", "t:r"}, Class: "scoped"})
	if err != nil {
		t.Fatalf("subkey: %v", err)
	}
	// op=tok needs t:w -> err scope t:w (acceptance).
	txt, isErr := e.call(t, scoped, "tok", map[string]any{"n": 1})
	if !isErr || !strings.HasPrefix(txt, "err scope t:w") {
		t.Fatalf("tok scope: %v %q", isErr, txt)
	}
	// A read within scope is not rejected on scope grounds.
	if txt, isErr := e.call(t, scoped, "s", map[string]any{"q": "zzz"}); isErr {
		t.Fatalf("scoped read rejected: %q", txt)
	}
	// me shows the scopes.
	if txt, isErr := e.call(t, scoped, "me", nil); isErr || !strings.Contains(txt, "scopes=kb:r,t:r") {
		t.Fatalf("scoped me: %q", txt)
	}
	// Cost: searches cost 2 per OpMeta.
	if c := newServer(e.d).cost("s"); c != 2 {
		t.Fatalf("search cost %v != 2", c)
	}
	if c := newServer(e.d).cost("help"); c != 1 {
		t.Fatalf("help cost %v != 1", c)
	}
}

func TestIdemKeyReplay(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register(t, "idem-root")
	a := map[string]any{"kind": "fix", "title": "idem entry " + id, "symptom": "idem sym " + id, "fix": "x", "force": true, "key": "k-" + id}
	first, isErr := e.call(t, tok, "p", a)
	if isErr || !strings.HasPrefix(first, "ok k") {
		t.Fatalf("first: %v %q", isErr, first)
	}
	second, isErr := e.call(t, tok, "p", a)
	if isErr {
		t.Fatalf("replay errored: %q", second)
	}
	if !strings.Contains(second, "idem=replay") {
		t.Fatalf("replay lacked marker: %q", second)
	}
	// Same entry id both times (no second row created).
	k1 := strings.Fields(strings.TrimPrefix(first, "ok "))[0]
	if !strings.Contains(second, k1) {
		t.Fatalf("replay returned a different id: %q vs %q", first, second)
	}
}

func TestAnonOpGetsClientKeys(t *testing.T) {
	e := newEnv(t)
	s := newServer(e.d)
	var gotIP, gotGrp, gotSup string
	s.ops["xprobe"] = func(ctx context.Context, _ *core.Ident, _ json.RawMessage) (string, error) {
		gotIP, gotGrp, gotSup = core.ClientFrom(ctx)
		return "ok", nil
	}
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("CF-Connecting-IP", "10.9.8.7")
	rc := &reqCtx{r: r}
	res := s.call(context.Background(), rc, "xprobe", nil)
	if res.IsError {
		t.Fatalf("probe errored: %+v", res)
	}
	if gotIP == "" || gotGrp == "" || gotSup == "" {
		t.Fatalf("client keys not injected: ip=%q grp=%q sup=%q", gotIP, gotGrp, gotSup)
	}
}

func TestURLTokenPath(t *testing.T) {
	e := newEnv(t)
	h := Handler(e.d)
	// GET -> 405 Allow: POST (the oauth wrapper forwards only POST, but the handler enforces it too).
	greq := httptest.NewRequest("GET", "/mcp", nil)
	gw := httptest.NewRecorder()
	h.ServeHTTP(gw, greq)
	if gw.Code != 405 || gw.Header().Get("Allow") != "POST" {
		t.Fatalf("GET via Handler: %d allow=%q", gw.Code, gw.Header().Get("Allow"))
	}
	// POST initialize via the url-token Handler returns a normal result.
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("CF-Connecting-IP", e.ip)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("POST via Handler: %d %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out["result"] == nil {
		t.Fatalf("Handler result: %s", w.Body.String())
	}
}

func TestOpsMergePanicsOnDuplicate(t *testing.T) {
	e := newEnv(t)
	okop := func(context.Context, *core.Ident, json.RawMessage) (string, error) { return "ok", nil }
	dup := func(name string) opSource {
		return opSource{name, func(*core.Deps) map[string]Op { return map[string]Op{"dd": okop} }, nil}
	}
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("merge of a duplicate op did not panic")
			} else if !strings.Contains(fmt.Sprint(r), "duplicate op") {
				t.Fatalf("panic not about a duplicate: %v", r)
			}
		}()
		mergeOps(e.d, []opSource{dup("a"), dup("b")})
	}()
	// The real registry must have no duplicates (it must boot).
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("real Ops panicked (cross-package duplicate op): %v", r)
			}
		}()
		if m := Ops(e.d); len(m) == 0 {
			t.Fatal("Ops empty")
		}
	}()
}

func TestResourcesTemplatesReadUntrusted(t *testing.T) {
	e := newEnv(t)
	// resources/list: <= 10 static entries.
	out, body := e.rpc(t, "", 1, "resources/list", nil)
	res := out["result"].(map[string]any)["resources"].([]any)
	if len(res) == 0 || len(res) > 10 {
		t.Fatalf("resources/list %d entries: %s", len(res), body)
	}
	// resources/templates/list includes the templated schemes.
	out, body = e.rpc(t, "", 2, "resources/templates/list", nil)
	tmpls := out["result"].(map[string]any)["resourceTemplates"].([]any)
	var have []string
	for _, x := range tmpls {
		have = append(have, x.(map[string]any)["uriTemplate"].(string))
	}
	joined := strings.Join(have, " ")
	for _, want := range []string{"cx://k/{id}", "cx://e/{err}", "cx://v/{lib}/{ver}", "cx://dg/{lib}/{ver}/{topic}", "cx://brief/{q}"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("templates missing %s: %s", want, body)
		}
	}
	// resources/read dispatches to the page builder and marks the content untrusted.
	PageFn = func(_ context.Context, path string, budget int) (string, error) {
		return "# page\npath=" + path + " b=" + fmt.Sprint(budget), nil
	}
	t.Cleanup(func() { PageFn = nil })
	out, body = e.rpc(t, "", 3, "resources/read", map[string]any{"uri": "cx://k/k7x2a9q?b=400"})
	contents := out["result"].(map[string]any)["contents"].([]any)
	c0 := contents[0].(map[string]any)
	if !strings.Contains(c0["text"].(string), "path=/k/k7x2a9q") || !strings.Contains(c0["text"].(string), "b=400") {
		t.Fatalf("read text: %s", body)
	}
	meta, _ := c0["_meta"].(map[string]any)
	if meta == nil || meta["untrusted"] != true {
		t.Fatalf("read not marked untrusted: %s", body)
	}
	// An unknown scheme is a param error.
	bad, _ := e.rpc(t, "", 4, "resources/read", map[string]any{"uri": "http://evil/x"})
	if bad["error"] == nil {
		t.Fatalf("unknown uri accepted: %v", bad)
	}
}

func TestCompletions(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register(t, "comp-root")
	txt, isErr := e.call(t, tok, "p", map[string]any{"kind": "fix", "title": "comp entry " + id, "symptom": "comp " + id, "fix": "x", "force": true})
	if isErr {
		t.Fatalf("seed entry: %q", txt)
	}
	kid := strings.Fields(strings.TrimPrefix(txt, "ok "))[0]
	out, body := e.rpc(t, "", 1, "completion/complete", map[string]any{
		"ref":      map[string]any{"type": "ref/resource", "uri": "cx://k/{id}"},
		"argument": map[string]any{"name": "id", "value": kid[:3]},
	})
	comp := out["result"].(map[string]any)["completion"].(map[string]any)
	vals := comp["values"].([]any)
	found := false
	for _, v := range vals {
		if v.(string) == kid {
			found = true
		}
	}
	if !found {
		t.Fatalf("completion missing %s: %s", kid, body)
	}
	// An unknown argument name yields an empty, well-formed completion.
	out, _ = e.rpc(t, "", 2, "completion/complete", map[string]any{"argument": map[string]any{"name": "weird", "value": "x"}})
	if comp := out["result"].(map[string]any)["completion"].(map[string]any); comp["values"] == nil {
		t.Fatalf("empty completion malformed: %v", comp)
	}
}

func TestPromptsDescriptive(t *testing.T) {
	e := newEnv(t)
	out, body := e.rpc(t, "", 1, "prompts/list", nil)
	prompts := out["result"].(map[string]any)["prompts"].([]any)
	names := map[string]bool{}
	for _, p := range prompts {
		names[p.(map[string]any)["name"].(string)] = true
	}
	if !names["fix"] || !names["since"] {
		t.Fatalf("prompts/list: %s", body)
	}
	out, body = e.rpc(t, "", 2, "prompts/get", map[string]any{"name": "fix", "arguments": map[string]any{"error": "TypeError: x is not a function"}})
	res := out["result"].(map[string]any)
	msgs := res["messages"].([]any)
	if len(msgs) != 1 {
		t.Fatalf("prompts/get messages: %s", body)
	}
	content := msgs[0].(map[string]any)["content"].([]any)
	var hasResource, hasText bool
	for _, c := range content {
		switch c.(map[string]any)["type"] {
		case "resource":
			hasResource = true
		case "text":
			hasText = true
			txt := c.(map[string]any)["text"].(string)
			// Descriptive, not an imperative instruction.
			if strings.HasPrefix(txt, "Use ") || strings.HasPrefix(txt, "Fix ") || strings.HasPrefix(txt, "Do ") {
				t.Fatalf("prompt text is imperative: %q", txt)
			}
		}
	}
	if !hasResource || !hasText {
		t.Fatalf("prompts/get lacks embedded resource + sentence: %s", body)
	}
}

func TestBatchNotificationsAndErrors(t *testing.T) {
	e := newEnv(t)
	st, _, body := e.raw(t, "POST", `[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":"x","method":"tools/list"},{"jsonrpc":"2.0","id":3,"method":"bogus"}]`, "")
	if st != 200 {
		t.Fatalf("batch: %d %s", st, body)
	}
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil || len(out) != 3 {
		t.Fatalf("batch: %v %s", err, body)
	}
	if fmt.Sprint(out[0]["id"]) != "1" || out[0]["result"] == nil || out[1]["id"] != "x" || out[1]["result"] == nil {
		t.Fatalf("batch order: %s", body)
	}
	if e, _ := out[2]["error"].(map[string]any); e == nil || e["code"].(float64) != -32601 {
		t.Fatalf("unknown method: %s", body)
	}
	// Single notification -> 202 empty.
	st, _, body = e.raw(t, "POST", `{"jsonrpc":"2.0","method":"notifications/initialized"}`, "")
	if st != 202 || len(body) != 0 {
		t.Fatalf("notification: %d %q", st, body)
	}
	// Batch of only notifications -> 202.
	if st, _, _ = e.raw(t, "POST", `[{"jsonrpc":"2.0","method":"notifications/cancelled"}]`, ""); st != 202 {
		t.Fatalf("notification batch: %d", st)
	}
	// Unknown method (single).
	out1, _ := e.rpc(t, "", 5, "bogus/method", nil)
	if e, _ := out1["error"].(map[string]any); e == nil || e["code"].(float64) != -32601 || fmt.Sprint(out1["id"]) != "5" {
		t.Fatalf("-32601: %v", out1)
	}
	// Parse error.
	st, _, body = e.raw(t, "POST", `{"jsonrpc":`, "")
	var perr map[string]any
	json.Unmarshal(body, &perr)
	if st != 400 || perr["error"] == nil || perr["error"].(map[string]any)["code"].(float64) != -32700 || perr["id"] != nil {
		t.Fatalf("parse error: %d %s", st, body)
	}
	if st, _, body = e.raw(t, "POST", `[]`, ""); st != 400 || !strings.Contains(string(body), "-32600") {
		t.Fatalf("empty batch: %d %s", st, body)
	}
	// Body cap.
	if st, _, body = e.raw(t, "POST", `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"`+strings.Repeat("a", maxBody)+`"}}`, ""); st != 413 {
		t.Fatalf("body cap: %d %s", st, body)
	}
	// GET -> 405 Allow: POST.
	st, h, _ := e.raw(t, "GET", "", "")
	if st != 405 || h.Get("Allow") != "POST" {
		t.Fatalf("GET: %d allow=%q", st, h.Get("Allow"))
	}
	if st, h, _ = e.raw(t, "DELETE", "", ""); st != 405 || h.Get("Allow") != "POST" {
		t.Fatalf("DELETE: %d allow=%q", st, h.Get("Allow"))
	}
}

// Batch cap, per-call rate charge, and the one-poll / summed long-poll budget.
func TestBatchLimits(t *testing.T) {
	e := newEnv(t)
	ping := func(n int) string {
		var parts []string
		for i := 0; i < n; i++ {
			parts = append(parts, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"ping"}`, i))
		}
		return "[" + strings.Join(parts, ",") + "]"
	}
	st, _, body := e.raw(t, "POST", ping(maxBatch+1), "")
	var perr map[string]any
	json.Unmarshal(body, &perr)
	if st != 400 || perr["error"] == nil || perr["error"].(map[string]any)["code"].(float64) != -32600 || !strings.Contains(string(body), "batch too large") {
		t.Fatalf("oversized batch: %d %s", st, body)
	}
	st, _, body = e.raw(t, "POST", ping(maxBatch), "")
	var out []map[string]any
	if st != 200 || json.Unmarshal(body, &out) != nil || len(out) != maxBatch {
		t.Fatalf("max batch: %d %s", st, body)
	}
	// Per-call charge: anonymous burst is 20 tokens; each batch of 10 help calls (cost 1) costs 10
	// (1 request + 9 extra), so the third batch must see in-call rate errors.
	var calls []string
	for i := 0; i < maxBatch; i++ {
		calls = append(calls, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"cx","arguments":{"op":"help"}}}`, i))
	}
	batch := "[" + strings.Join(calls, ",") + "]"
	rateErrs := 0
	for round := 0; round < 3; round++ {
		st, _, body = e.raw(t, "POST", batch, "")
		switch {
		case st == 429:
			rateErrs++
		case st != 200:
			t.Fatalf("round %d: %d %s", round, st, body)
		default:
			rateErrs += strings.Count(string(body), "err rate slow down")
		}
		if round == 0 && rateErrs != 0 {
			t.Fatalf("first batch rate limited: %s", body)
		}
	}
	if rateErrs == 0 {
		t.Fatal("30 tools/call in 3 batches never hit the limiter: batch amplification still possible")
	}
}

// One long-poll per request and the summed wait clamp (3.6 clampWait; acceptance TestOneLongPollPerRequest).
func TestOneLongPollPerRequest(t *testing.T) {
	rc := &reqCtx{budget: maxWaitBudget}
	got := func(a string) string { return string(rc.clampWait(json.RawMessage(a))) }
	// First poll runs, capped to the budget.
	if g := got(`{"id":"j1","wait":50}`); g != `{"id":"j1","wait":50}` {
		t.Fatalf("first: %s", g)
	}
	// A second poll in the same request is clamped to 0 (one long-poll per request).
	if g := got(`{"id":"j2","wait":50}`); g != `{"id":"j2","wait":0}` {
		t.Fatalf("second poll not clamped to 0: %s", g)
	}
	if g := got(`{"id":"j3","wait":85}`); g != `{"id":"j3","wait":0}` {
		t.Fatalf("third: %s", g)
	}
	// A call without a wait is untouched.
	if g := got(`{"id":"j4"}`); g != `{"id":"j4"}` {
		t.Fatalf("untouched: %s", g)
	}
	if g := got(`{"q":"wait","k":1}`); g != `{"q":"wait","k":1}` {
		t.Fatalf("non-numeric wait key: %s", g)
	}
	// A single poll larger than the whole budget is capped at the budget.
	rc2 := &reqCtx{budget: maxWaitBudget}
	if g := string(rc2.clampWait(json.RawMessage(`{"wait":200}`))); g != `{"wait":85}` {
		t.Fatalf("over-budget first poll: %s", g)
	}
}
