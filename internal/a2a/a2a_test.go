package a2a

import (
	"bufio"
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
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		p, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if _, err := p.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, p); err != nil {
			panic(err)
		}
		testPool = p
		code := m.Run()
		p.Close()
		os.Exit(code)
	}
	p, cleanup := testdb.Open("a2a", core.Migrate)
	if p == nil {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping a2a DB tests")
		os.Exit(0)
	}
	testPool = p
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
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, PowBitsW: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAuthV2(mux, d)
	kb.Register(mux, d)
	forge.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	var b [4]byte
	rand.Read(b[:])
	return &tenv{d, srv, fmt.Sprintf("10.8.%d.%d", b[0], b[1])}
}

// raw performs a request; anonymous calls come from a fresh address so the per-IP limiter never
// shapes a test.
func (e *tenv) raw(t *testing.T, method, path, tok string, body any, hdr ...string) (int, []byte, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		case []byte:
			rd = bytes.NewReader(b)
		default:
			j, _ := json.Marshal(b)
			rd = bytes.NewReader(j)
		}
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	ip := e.ip
	if tok == "" {
		var b [2]byte
		rand.Read(b[:])
		ip = fmt.Sprintf("10.9.%d.%d", b[0], b[1])
	}
	req.Header.Set("CF-Connecting-IP", ip)
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, b, res.Header
}

// do is a text request without the trailing next: line.
func (e *tenv) do(t *testing.T, method, path, tok string, body any) (int, string) {
	t.Helper()
	st, b, _ := e.raw(t, method, path, tok, body)
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndex(s, "\nnext: "); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return st, s
}

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

func kv(s string) map[string]string {
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(s, -1) {
		m[x[1]] = x[2]
	}
	return m
}

func (e *tenv) register(t *testing.T, name string) (id, tok string) {
	t.Helper()
	_, body := e.do(t, "POST", "/v1/challenge", "", nil)
	c := kv(body)["c"]
	st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, 6), "name": name})
	if st != 201 {
		t.Fatalf("register: %d %s", st, body)
	}
	m := kv(body)
	return m["id"], m["token"]
}

func rpcReq(id int, method string, params any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}
}

func sendParams(text, mid, taskID string, extra map[string]any) map[string]any {
	msg := map[string]any{"role": "user", "parts": []any{map[string]any{"kind": "text", "text": text}}, "messageId": mid, "kind": "message"}
	if taskID != "" {
		msg["taskId"] = taskID
	}
	p := map[string]any{"message": msg}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func (e *tenv) rpc(t *testing.T, tok string, body any, hdr ...string) (int, map[string]any, http.Header) {
	t.Helper()
	st, b, h := e.raw(t, "POST", "/a2a", tok, body, hdr...)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("rpc: %d %s", st, b)
	}
	return st, m, h
}

func (e *tenv) rpcBatch(t *testing.T, tok string, body any) (int, []map[string]any, map[string]any) {
	t.Helper()
	st, b, _ := e.raw(t, "POST", "/a2a", tok, body)
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		var one map[string]any
		json.Unmarshal(b, &one)
		return st, nil, one
	}
	var out []map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("batch: %d %s", st, b)
	}
	return st, out, nil
}

func result(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", m)
	}
	return r
}

func errOf(t *testing.T, m map[string]any) (int, string, map[string]any) {
	t.Helper()
	e, ok := m["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error: %v", m)
	}
	data, _ := e["data"].(map[string]any)
	msg, _ := e["message"].(string)
	return int(e["code"].(float64)), msg, data
}

// get walks nested maps and arrays ("history", "0", "parts", "0", "text").
func get(v any, path ...string) any {
	for _, p := range path {
		switch c := v.(type) {
		case map[string]any:
			v = c[p]
		case []any:
			var i int
			fmt.Sscanf(p, "%d", &i)
			if i < 0 || i >= len(c) {
				return nil
			}
			v = c[i]
		default:
			return nil
		}
	}
	return v
}

func str(v any, path ...string) string {
	s, _ := get(v, path...).(string)
	return s
}

func (e *tenv) send(t *testing.T, tok, text, mid string) map[string]any {
	t.Helper()
	st, m, _ := e.rpc(t, tok, rpcReq(1, "message/send", sendParams(text, mid, "", nil)))
	if st != 200 {
		t.Fatalf("send: %d %v", st, m)
	}
	return result(t, m)
}

func (e *tenv) getTask(t *testing.T, tok, id string) map[string]any {
	t.Helper()
	st, m, _ := e.rpc(t, tok, rpcReq(2, "tasks/get", map[string]any{"id": id}))
	if st != 200 {
		t.Fatalf("get: %d %v", st, m)
	}
	return result(t, m)
}

func (e *tenv) state(t *testing.T, id string) string {
	t.Helper()
	return str(e.getTask(t, "", id), "status", "state")
}

func (e *tenv) board(t *testing.T, tok, n, verb string, body any) {
	t.Helper()
	if st, b := e.do(t, "POST", "/v1/t/"+n+"/"+verb, tok, body); st != 200 {
		t.Fatalf("%s: %d %s", verb, st, b)
	}
}

func (e *tenv) taskCount(t *testing.T, root string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM tasks WHERE root = $1`, root).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

var taskIDRe = regexp.MustCompile(`^t[1-9]\d*$`)

func TestSendCreatesTask(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register(t, "alice")
	res := e.send(t, tok, "Review PR 42\nfocus on the lock order", "m-1")
	tid := str(res, "id")
	if !taskIDRe.MatchString(tid) || str(res, "status", "state") != StSubmitted || str(res, "kind") != "task" || str(res, "contextId") != tid {
		t.Fatalf("task: %v", res)
	}
	if str(res, "history", "0", "role") != "user" || str(res, "history", "0", "parts", "0", "text") != "Review PR 42\nfocus on the lock order" ||
		get(res, "history", "0", "parts", "0", "metadata", "untrusted") != true || str(res, "history", "0", "messageId") != "m-1" {
		t.Fatalf("history: %v", res["history"])
	}
	if arts, _ := res["artifacts"].([]any); len(arts) != 0 {
		t.Fatalf("artifacts: %v", arts)
	}
	if str(res, "metadata", "title") != "Review PR 42" || str(res, "metadata", "by") != id || !strings.HasSuffix(str(res, "metadata", "url"), "/t/"+tid[1:]) {
		t.Fatalf("metadata: %v", res["metadata"])
	}
	if st, body := e.do(t, "GET", "/v1/t/"+tid[1:], "", nil); st != 200 || !strings.Contains(body, "Review PR 42") {
		t.Fatalf("board: %d %s", st, body)
	}
	if got := e.getTask(t, "", tid); str(got, "id") != tid || str(got, "status", "state") != StSubmitted {
		t.Fatalf("get: %v", got)
	}
	// GET /a2a explains itself; a plain POST with a non-JSON body is a parse error.
	if st, body := e.do(t, "GET", "/a2a", "", nil); st != 405 || !strings.Contains(body, "message/send") {
		t.Fatalf("405: %d %s", st, body)
	}
	if st, m, _ := e.rpc(t, "", "not json"); st != 400 || m["error"] == nil {
		t.Fatalf("parse: %d %v", st, m)
	}
	// Tags from metadata and the contextId travel to the board row.
	st, m, _ := e.rpc(t, tok, rpcReq(3, "message/send", map[string]any{"message": map[string]any{"role": "user", "messageId": "m-ctx",
		"contextId": "ctx-1", "parts": []any{map[string]any{"kind": "text", "text": "Tagged task"}}, "metadata": map[string]any{"tags": []string{"go", "review"}}}}))
	if st != 200 {
		t.Fatalf("send tags: %d %v", st, m)
	}
	if r := result(t, m); str(r, "contextId") != "ctx-1" || fmt.Sprint(get(r, "metadata", "tags")) != "[go review]" {
		t.Fatalf("tags/context: %v", r)
	}
}

func TestGetStateMap(t *testing.T) {
	e := newEnv(t)
	_, creator := e.register(t, "creator")
	_, holder := e.register(t, "holder")
	res := e.send(t, creator, "Map the states\nbody", "sm-1")
	tid := str(res, "id")
	n := tid[1:]
	if s := e.state(t, tid); s != StSubmitted {
		t.Fatalf("submitted: %s", s)
	}
	e.board(t, holder, n, "claim", nil)
	got := e.getTask(t, "", tid)
	if str(got, "status", "state") != StWorking || get(got, "metadata", "claim", "fence") == nil {
		t.Fatalf("working: %v", got)
	}
	e.board(t, holder, n, "ask", map[string]any{"text": "which branch?"})
	got = e.getTask(t, "", tid)
	if str(got, "status", "state") != StInputRequired || str(got, "status", "message", "parts", "0", "text") != "which branch?" || str(got, "status", "message", "role") != "agent" {
		t.Fatalf("input-required: %v", got)
	}
	st, m, _ := e.rpc(t, creator, rpcReq(5, "message/send", sendParams("main", "sm-2", tid, nil)))
	if st != 200 {
		t.Fatalf("answer: %d %v", st, m)
	}
	if r := result(t, m); str(r, "status", "state") != StWorking {
		t.Fatalf("after answer: %v", r)
	}
	var ask string
	testPool.QueryRow(context.Background(), `SELECT ask FROM tasks WHERE n = $1`, n).Scan(&ask)
	if ask != "" {
		t.Fatalf("ask not cleared: %q", ask)
	}
	e.board(t, holder, n, "done", map[string]any{"text": "shipped on main"})
	got = e.getTask(t, "", tid)
	if str(got, "status", "state") != StCompleted || str(got, "artifacts", "0", "name") != "done" || str(got, "artifacts", "0", "parts", "0", "text") != "shipped on main" {
		t.Fatalf("completed: %v", got)
	}
	hist, _ := got["history"].([]any)
	var sawAnswer bool
	for _, h := range hist {
		if str(h, "messageId") == "sm-2" && str(h, "role") == "user" && str(h, "parts", "0", "text") == "main" {
			sawAnswer = true
		}
	}
	if !sawAnswer || len(hist) != 4 { // creation, ask, answer, done
		t.Fatalf("history: %v", hist)
	}
	// Claim expiry maps back to submitted; historyLength trims from the newest.
	res2 := e.send(t, creator, "Expiring claim", "sm-3")
	n2 := str(res2, "id")[1:]
	e.board(t, holder, n2, "claim", nil)
	if _, err := testPool.Exec(context.Background(), `UPDATE task_claims SET until = now() - interval '1 second' WHERE n = $1`, n2); err != nil {
		t.Fatal(err)
	}
	if s := e.state(t, str(res2, "id")); s != StSubmitted {
		t.Fatalf("expired claim: %s", s)
	}
	st, m, _ = e.rpc(t, "", rpcReq(6, "tasks/get", map[string]any{"id": tid, "historyLength": 1}))
	if h, _ := result(t, m)["history"].([]any); st != 200 || len(h) != 1 || str(h[0], "metadata", "kind") != "done" {
		t.Fatalf("historyLength: %d %v", st, m)
	}
}

func TestBlockingWake(t *testing.T) {
	e := newEnv(t)
	_, creator := e.register(t, "blocker")
	_, holder := e.register(t, "waker")
	tid := str(e.send(t, creator, "Wake me", "bw-1"), "id")
	go func() {
		time.Sleep(300 * time.Millisecond)
		e.board(t, holder, tid[1:], "claim", nil)
	}()
	start := time.Now()
	st, m, _ := e.rpc(t, creator, rpcReq(1, "tasks/get", map[string]any{"id": tid, "metadata": map[string]any{"blocking": true, "wait": 20}}))
	el := time.Since(start)
	if st != 200 {
		t.Fatalf("get: %d %v", st, m)
	}
	r := result(t, m)
	if str(r, "status", "state") != StWorking || el > 8*time.Second || get(r, "metadata", "waited_ms") == nil {
		t.Fatalf("blocking get: state=%s after %s meta=%v", str(r, "status", "state"), el, r["metadata"])
	}
	// A blocking send on a fresh task returns at the deadline with the unchanged state.
	start = time.Now()
	st, m, _ = e.rpc(t, creator, rpcReq(2, "message/send", sendParams("Nobody claims this", "bw-2", "", map[string]any{"configuration": map[string]any{"blocking": true}, "metadata": map[string]any{"wait": 1}})))
	if el := time.Since(start); st != 200 || str(result(t, m), "status", "state") != StSubmitted || el < 900*time.Millisecond || el > 5*time.Second {
		t.Fatalf("blocking send: %d %v after %s", st, m, el)
	}
}

func TestOnlyCreatorClearsAsk(t *testing.T) {
	e := newEnv(t)
	_, creator := e.register(t, "owner")
	_, holder := e.register(t, "worker")
	_, other := e.register(t, "bystander")
	tid := str(e.send(t, creator, "Ask clearing", "oc-1"), "id")
	n := tid[1:]
	e.board(t, holder, n, "claim", nil)
	e.board(t, holder, n, "ask", map[string]any{"text": "need the repo url"})
	st, m, _ := e.rpc(t, other, rpcReq(1, "message/send", sendParams("I think it is github", "oc-2", tid, nil)))
	if st != 200 {
		t.Fatalf("other note: %d %v", st, m)
	}
	if r := result(t, m); str(r, "status", "state") != StInputRequired || str(r, "status", "message", "parts", "0", "text") != "need the repo url" {
		t.Fatalf("non-creator moved the state: %v", r)
	}
	var ask string
	var notes int
	testPool.QueryRow(context.Background(), `SELECT ask, (SELECT count(*) FROM task_notes WHERE n = $1) FROM tasks WHERE n = $1`, n).Scan(&ask, &notes)
	if ask != "need the repo url" || notes != 2 {
		t.Fatalf("ask=%q notes=%d", ask, notes)
	}
	st, m, _ = e.rpc(t, creator, rpcReq(2, "message/send", sendParams("https://example.org/repo", "oc-3", tid, nil)))
	if r := result(t, m); st != 200 || str(r, "status", "state") != StWorking || get(r, "status", "message") != nil {
		t.Fatalf("creator answer: %d %v", st, m)
	}
	testPool.QueryRow(context.Background(), `SELECT ask FROM tasks WHERE n = $1`, n).Scan(&ask)
	if ask != "" {
		t.Fatalf("ask kept: %q", ask)
	}
}

func TestOneBlockingPerRequest(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register(t, "batchwait")
	tid := str(e.send(t, tok, "Idle task", "ob-1"), "id")
	var batch []any
	for i := 1; i <= 3; i++ {
		batch = append(batch, rpcReq(i, "tasks/get", map[string]any{"id": tid, "metadata": map[string]any{"blocking": true, "wait": 1}}))
	}
	start := time.Now()
	st, out, _ := e.rpcBatch(t, tok, batch)
	el := time.Since(start)
	if st != 200 || len(out) != 3 || el < 900*time.Millisecond || el > 2500*time.Millisecond {
		t.Fatalf("batch: %d n=%d after %s", st, len(out), el)
	}
	waited := 0
	for _, m := range out {
		r := result(t, m)
		if str(r, "status", "state") != StSubmitted {
			t.Fatalf("state: %v", r)
		}
		if get(r, "metadata", "waited_ms") != nil {
			waited++
		}
	}
	if waited != 1 {
		t.Fatalf("blocking calls that waited: %d", waited)
	}
}

func TestCancelCreatorOnly(t *testing.T) {
	e := newEnv(t)
	_, creator := e.register(t, "canceller")
	_, other := e.register(t, "intruder")
	tid := str(e.send(t, creator, "Cancel me", "cc-1"), "id")
	st, m, _ := e.rpc(t, other, rpcReq(1, "tasks/cancel", map[string]any{"id": tid}))
	if code, _, data := errOf(t, m); st != 200 || code != CodeServer || data["status"] != float64(403) {
		t.Fatalf("non-creator cancel: %d %v", st, m)
	}
	if s := e.state(t, tid); s != StSubmitted {
		t.Fatalf("state after refused cancel: %s", s)
	}
	st, m, _ = e.rpc(t, "", rpcReq(2, "tasks/cancel", map[string]any{"id": tid}))
	if code, _, _ := errOf(t, m); st != 401 || code != CodeServer {
		t.Fatalf("anonymous cancel: %d %v", st, m)
	}
	st, m, _ = e.rpc(t, creator, rpcReq(3, "tasks/cancel", map[string]any{"id": tid}))
	if r := result(t, m); st != 200 || str(r, "status", "state") != StCanceled || r["history"] != nil {
		t.Fatalf("cancel: %d %v", st, m)
	}
	if got := e.getTask(t, "", tid); str(got, "status", "state") != StCanceled || got["history"] != nil || got["artifacts"] != nil {
		t.Fatalf("canceled task leaks content: %v", got)
	}
	st, m, _ = e.rpc(t, creator, rpcReq(4, "tasks/cancel", map[string]any{"id": tid}))
	if code, _, _ := errOf(t, m); code != CodeNotCancel {
		t.Fatalf("second cancel: %d %v", st, m)
	}
	if st, _ := e.do(t, "GET", "/v1/t/"+tid[1:], "", nil); st != 404 {
		t.Fatalf("board still shows the task: %d", st)
	}
	st, m, _ = e.rpc(t, creator, rpcReq(5, "tasks/cancel", map[string]any{"id": "t999999999"}))
	if code, _, _ := errOf(t, m); code != CodeTaskNotFound {
		t.Fatalf("missing task: %v", m)
	}
}

func TestIdempotentMessageId(t *testing.T) {
	e := newEnv(t)
	aliceRoot, alice := e.register(t, "idem")
	_, bob := e.register(t, "idem2")
	first := e.send(t, alice, "Once only", "idem-key-1")
	second := e.send(t, alice, "Once only", "idem-key-1")
	if str(first, "id") != str(second, "id") || e.taskCount(t, aliceRoot) != 1 {
		t.Fatalf("replay created another task: %v / %v (count %d)", first["id"], second["id"], e.taskCount(t, aliceRoot))
	}
	st, m, _ := e.rpc(t, bob, rpcReq(1, "message/send", sendParams("Steal the key", "idem-key-1", "", nil)))
	if code, _, _ := errOf(t, m); st != 200 || code != CodeParams {
		t.Fatalf("foreign messageId: %d %v", st, m)
	}
	// Notes replay too: the same messageId adds one note.
	tid := str(first, "id")
	for i := 0; i < 2; i++ {
		if st, m, _ := e.rpc(t, alice, rpcReq(2, "message/send", sendParams("progress", "idem-note-1", tid, nil))); st != 200 || m["error"] != nil {
			t.Fatalf("note %d: %d %v", i, st, m)
		}
	}
	var notes int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM task_notes WHERE n = $1`, tid[1:]).Scan(&notes)
	if notes != 1 {
		t.Fatalf("notes after replay: %d", notes)
	}
	if st, m, _ := e.rpc(t, alice, rpcReq(3, "message/send", sendParams("x", strings.Repeat("k", 129), "", nil))); st != 200 || m["error"] == nil {
		t.Fatalf("long messageId accepted: %d %v", st, m)
	}
}

func TestFilePartsRejected(t *testing.T) {
	e := newEnv(t)
	root, tok := e.register(t, "filer")
	for _, parts := range [][]any{
		{map[string]any{"kind": "file", "file": map[string]any{"uri": "https://evil.example/x"}}},
		{map[string]any{"kind": "data", "data": map[string]any{"a": 1}}},
		{map[string]any{"kind": "text", "text": "Title"}, map[string]any{"kind": "file", "file": map[string]any{"bytes": "AAAA"}}},
	} {
		st, m, _ := e.rpc(t, tok, rpcReq(1, "message/send", map[string]any{"message": map[string]any{"role": "user", "messageId": "f-1", "parts": parts}}))
		if code, msg, _ := errOf(t, m); st != 200 || code != CodeContentType || !strings.Contains(msg, "text parts only") {
			t.Fatalf("file part: %d %v", st, m)
		}
	}
	if e.taskCount(t, root) != 0 {
		t.Fatal("a rejected message created a task")
	}
	st, m, _ := e.rpc(t, tok, rpcReq(2, "message/send", map[string]any{"message": map[string]any{"role": "user", "messageId": "f-2", "parts": []any{}}}))
	if code, _, _ := errOf(t, m); st != 200 || code != CodeParams {
		t.Fatalf("empty parts: %v", m)
	}
}

func TestAnonymous401Hint(t *testing.T) {
	e := newEnv(t)
	saved := PendingFn
	PendingFn = nil
	t.Cleanup(func() { PendingFn = saved })
	_, tok := e.register(t, "anonref")
	tid := str(e.send(t, tok, "Public task", "an-1"), "id")
	st, m, h := e.rpc(t, "", rpcReq(1, "message/send", sendParams("Anonymous task", "an-2", "", nil)))
	code, msg, data := errOf(t, m)
	if st != 401 || code != CodeServer || !strings.Contains(msg, "err auth") || data["status"] != float64(401) {
		t.Fatalf("anonymous send: %d %v", st, m)
	}
	if wa := strings.Join(h.Values("WWW-Authenticate"), " "); !strings.Contains(wa, `PoW realm="w"`) || !strings.Contains(wa, "bits=") {
		t.Fatalf("PoW hint missing: %q", wa)
	}
	if next := fmt.Sprint(data["next"]); !strings.Contains(next, "POST /v1/challenge") {
		t.Fatalf("next: %v", data["next"])
	}
	// Reads stay anonymous, a note on an existing task does not.
	if got := e.getTask(t, "", tid); str(got, "status", "state") != StSubmitted {
		t.Fatalf("anonymous get: %v", got)
	}
	if st, m, _ := e.rpc(t, "", rpcReq(2, "message/send", sendParams("note", "an-3", tid, nil))); st != 401 || m["error"] == nil {
		t.Fatalf("anonymous note: %d %v", st, m)
	}
	if st, m, _ := e.rpc(t, "cx_bogus", rpcReq(3, "tasks/get", map[string]any{"id": tid})); st != 200 || !strings.Contains(str(m, "error", "message"), "invalid token") {
		t.Fatalf("bad token: %d %v", st, m)
	}
}

func TestBatchCapAndLimiter(t *testing.T) {
	e := newEnv(t)
	root, tok := e.register(t, "batcher")
	var big []any
	for i := 0; i < 11; i++ {
		big = append(big, rpcReq(i, "tasks/get", map[string]any{"id": "t1"}))
	}
	st, _, one := e.rpcBatch(t, tok, big)
	if code, msg, _ := errOf(t, one); st != 400 || code != CodeInvalid || !strings.Contains(msg, "batch too large") {
		t.Fatalf("11 calls: %d %v", st, one)
	}
	if st, _, one := e.rpcBatch(t, tok, []any{}); st != 400 || one["error"] == nil {
		t.Fatalf("empty batch: %d %v", st, one)
	}
	var sends []any
	for i := 1; i <= 10; i++ {
		sends = append(sends, rpcReq(i, "message/send", sendParams(fmt.Sprintf("Batch task %d", i), fmt.Sprintf("bt-%d", i), "",
			map[string]any{"configuration": map[string]any{"blocking": true}, "metadata": map[string]any{"wait": 1}})))
	}
	start := time.Now()
	st, out, _ := e.rpcBatch(t, tok, sends)
	el := time.Since(start)
	if st != 200 || len(out) != 10 || el > 10*time.Second {
		t.Fatalf("10 blocking sends: %d n=%d after %s", st, len(out), el)
	}
	waited := 0
	for _, m := range out {
		r := result(t, m)
		if !taskIDRe.MatchString(str(r, "id")) || str(r, "status", "state") != StSubmitted {
			t.Fatalf("send in batch: %v", m)
		}
		if get(r, "metadata", "waited_ms") != nil {
			waited++
		}
	}
	if waited != 1 || e.taskCount(t, root) != 10 {
		t.Fatalf("waited=%d tasks=%d", waited, e.taskCount(t, root))
	}
	// The limiter is charged per call: with 3 tokens left in the root bucket (one goes to the
	// request itself) a batch of 10 reads is refused from its 4th call on.
	spec := core.Spec{Key: root, Rate: 10, Burst: 30}
	_, info := e.d.Lim.Take(0, spec)
	if info.Remaining > 3 {
		e.d.Lim.Take(float64(info.Remaining-3), spec)
	}
	var gets []any
	for i := 1; i <= 10; i++ {
		gets = append(gets, rpcReq(i, "tasks/get", map[string]any{"id": str(result(t, out[0]), "id")}))
	}
	st, out, _ = e.rpcBatch(t, tok, gets)
	if st != 200 || len(out) != 10 {
		t.Fatalf("limited batch: %d n=%d", st, len(out))
	}
	limited := 0
	for _, m := range out {
		if em, ok := m["error"].(map[string]any); ok {
			if data, _ := em["data"].(map[string]any); data["err"] == "rate" && data["retry_s"] == float64(5) {
				limited++
			}
		}
	}
	if limited < 5 || out[0]["error"] != nil {
		t.Fatalf("rate-limited calls: %d (first=%v)", limited, out[0])
	}
}

func TestSlashReadGrammarCompletedTask(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, tok := e.register(t, "reader")
	ident, err := e.d.LookupToken(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := kb.Create(ctx, e.d, ident, &kb.Input{Kind: "fix", Title: "ECONNRESET on node fetch with keepalive agents",
		Symptom: "fetch fails with ECONNRESET after the connection sat idle", Cause: "the server closed the keepalive socket", Fix: "set keepAlive: false on the agent or retry the request once"})
	if err != nil {
		t.Fatal(err)
	}
	tid := str(e.send(t, tok, "Read grammar board task", "rg-1"), "id")
	before := e.taskCount(t, root)
	var anonBefore int
	testPool.QueryRow(ctx, `SELECT count(*) FROM tasks`).Scan(&anonBefore)
	check := func(text, want string) map[string]any {
		t.Helper()
		st, m, _ := e.rpc(t, "", rpcReq(1, "message/send", sendParams(text, "", "", nil)))
		if st != 200 {
			t.Fatalf("%q: %d %v", text, st, m)
		}
		r := result(t, m)
		rid := str(r, "id")
		out := str(r, "artifacts", "0", "parts", "0", "text")
		if !core.ValidIDPrefix(rid, 'r') || str(r, "status", "state") != StCompleted || str(r, "artifacts", "0", "name") != "result" || !strings.Contains(out, want) ||
			get(r, "artifacts", "0", "parts", "0", "metadata", "untrusted") != true {
			t.Fatalf("%q -> %v", text, r)
		}
		return r
	}
	r := check("/q ECONNRESET node fetch keepalive", kid)
	check("/e Error: read ECONNRESET at TCP.onStreamRead (node:internal/stream_base_commons:217:20) keepalive", kid)
	check("/k "+kid, "fix: set keepAlive")
	check("/t "+tid[1:], "#"+tid[1:]+" open Read grammar board task")
	check("/x t:"+tid[1:], "task")
	check("/help", "message/send")
	check("/grammar", "/q/<text>")
	var after int
	testPool.QueryRow(ctx, `SELECT count(*) FROM tasks`).Scan(&after)
	if after != anonBefore || e.taskCount(t, root) != before {
		t.Fatal("an inline read inserted a row")
	}
	st, m, _ := e.rpc(t, "", rpcReq(2, "tasks/get", map[string]any{"id": str(r, "id")}))
	if code, _, _ := errOf(t, m); st != 200 || code != CodeTaskNotFound {
		t.Fatalf("get on a read id: %d %v", st, m)
	}
	// A bearer makes `/w <title>` a board task; `/q` with a token still reads.
	wr := e.send(t, tok, "/w Wrapped title\nwrapped body", "rg-2")
	if !taskIDRe.MatchString(str(wr, "id")) || str(wr, "metadata", "title") != "Wrapped title" {
		t.Fatalf("/w with token: %v", wr)
	}
	if st, m, _ := e.rpc(t, tok, rpcReq(3, "message/send", sendParams("/q keepalive agents", "", "", nil))); st != 200 || !core.ValidIDPrefix(str(result(t, m), "id"), 'r') {
		t.Fatalf("/q with token: %d %v", st, m)
	}
	if st, m, _ := e.rpc(t, "", rpcReq(4, "message/send", sendParams("/k nope", "", "", nil))); st != 200 || m["error"] == nil {
		t.Fatalf("bad /k arg accepted: %v", m)
	}
}

func TestAnonymousPendingTicketFn(t *testing.T) {
	e := newEnv(t)
	savedP, savedG := PendingFn, PendingGetFn
	t.Cleanup(func() { PendingFn, PendingGetFn = savedP, savedG })
	ticket := core.NewID('q')
	var gotGrp, gotSuper, gotText string
	PendingFn = func(ctx context.Context, q core.Q, grp, super, text string) (string, error) {
		gotGrp, gotSuper, gotText = grp, super, text
		return ticket, nil
	}
	st, m, _ := e.rpc(t, "", rpcReq(1, "message/send", sendParams("/w Need a summary\nof the TLS changes", "pt-1", "", nil)))
	if st != 200 {
		t.Fatalf("pending send: %d %v", st, m)
	}
	r := result(t, m)
	if str(r, "id") != ticket || str(r, "status", "state") != StWorking || str(r, "status", "message", "parts", "0", "text") != PendingMsg || get(r, "metadata", "ticket") != true {
		t.Fatalf("ticket task: %v", r)
	}
	if gotGrp == "" || gotSuper == "" || gotText != "Need a summary\nof the TLS changes" {
		t.Fatalf("PendingFn args: %q %q %q", gotGrp, gotSuper, gotText)
	}
	// tasks/get on the ticket: still pending, then materialised, then gone.
	st, m, _ = e.rpc(t, "", rpcReq(2, "tasks/get", map[string]any{"id": ticket}))
	if code, _, _ := errOf(t, m); st != 200 || code != CodeTaskNotFound {
		t.Fatalf("ticket get without PendingGetFn: %v", m)
	}
	PendingGetFn = func(ctx context.Context, d *core.Deps, tk string) (int64, string, error) { return 0, StWorking, nil }
	if r := e.getTask(t, "", ticket); str(r, "id") != ticket || str(r, "status", "state") != StWorking {
		t.Fatalf("pending get: %v", r)
	}
	_, tok := e.register(t, "ticketowner")
	real := str(e.send(t, tok, "Materialised ticket", "pt-2"), "id")
	var n int64
	fmt.Sscanf(real, "t%d", &n)
	PendingGetFn = func(ctx context.Context, d *core.Deps, tk string) (int64, string, error) { return n, "", nil }
	if r := e.getTask(t, "", ticket); str(r, "id") != real || str(r, "metadata", "ticket") != ticket || str(r, "status", "state") != StSubmitted {
		t.Fatalf("materialised get: %v", r)
	}
	PendingGetFn = func(ctx context.Context, d *core.Deps, tk string) (int64, string, error) {
		return 0, "", core.ErrNotFound
	}
	st, m, _ = e.rpc(t, "", rpcReq(3, "tasks/get", map[string]any{"id": ticket}))
	if code, _, _ := errOf(t, m); code != CodeTaskNotFound {
		t.Fatalf("expired ticket: %v", m)
	}
	// Oversized anonymous text is refused before PendingFn runs.
	gotText = ""
	if st, m, _ := e.rpc(t, "", rpcReq(4, "message/send", sendParams(strings.Repeat("x", 5000), "pt-3", "", nil))); st != 200 || m["error"] == nil || gotText != "" {
		t.Fatalf("oversized ticket text: %d %v", st, m)
	}
}

type sseEvent struct {
	id   string
	data map[string]any
}

// sse posts a streaming request and reads events until the server closes the stream.
func (e *tenv) sse(t *testing.T, tok string, body any, hdr ...string) (http.Header, []sseEvent, time.Duration) {
	t.Helper()
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/a2a", bytes.NewReader(j))
	req.Header.Set("CF-Connecting-IP", e.ip)
	req.Header.Set("Content-Type", "application/json")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	start := time.Now()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	rd := bufio.NewReader(res.Body)
	var evs []sseEvent
	var cur sseEvent
	for {
		line, err := rd.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "id: "):
			cur.id = line[4:]
		case strings.HasPrefix(line, "data: "):
			json.Unmarshal([]byte(line[6:]), &cur.data)
		case line == "" && (cur.data != nil || cur.id != ""):
			evs = append(evs, cur)
			cur = sseEvent{}
		}
		if err != nil {
			break
		}
	}
	if cur.data != nil {
		evs = append(evs, cur)
	}
	return res.Header, evs, time.Since(start)
}

func kinds(evs []sseEvent) []string {
	var out []string
	for _, ev := range evs {
		out = append(out, str(ev.data, "result", "kind")+":"+str(ev.data, "result", "status", "state"))
	}
	return out
}

func TestStreamBoundedAndResume(t *testing.T) {
	e := newEnv(t)
	_, creator := e.register(t, "streamer")
	_, holder := e.register(t, "streamworker")
	tid := str(e.send(t, creator, "Stream me", "st-1"), "id")
	go func() {
		time.Sleep(300 * time.Millisecond)
		e.board(t, holder, tid[1:], "claim", nil)
		time.Sleep(300 * time.Millisecond)
		e.board(t, holder, tid[1:], "done", map[string]any{"text": "shipped"})
	}()
	h, evs, el := e.sse(t, creator, rpcReq(1, "tasks/resubscribe", map[string]any{"id": tid, "metadata": map[string]any{"wait": 20}}))
	if ct := h.Get("Content-Type"); ct != "text/event-stream" || !strings.Contains(h.Get("Cache-Control"), "no-store") || h.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("headers: %v", h)
	}
	if el > 8*time.Second || len(evs) < 3 {
		t.Fatalf("stream: %d events after %s: %v", len(evs), el, kinds(evs))
	}
	if str(evs[0].data, "result", "kind") != "task" || str(evs[0].data, "result", "id") != tid || evs[0].id == "" {
		t.Fatalf("first event: %v", evs[0])
	}
	last := evs[len(evs)-1].data
	if str(last, "result", "kind") != "status-update" || str(last, "result", "status", "state") != StCompleted || get(last, "result", "final") != true {
		t.Fatalf("last event: %v (%v)", last, kinds(evs))
	}
	var sawWorking, sawArtifact bool
	for _, ev := range evs {
		if str(ev.data, "result", "kind") == "status-update" && str(ev.data, "result", "status", "state") == StWorking {
			sawWorking = true
		}
		if str(ev.data, "result", "kind") == "artifact-update" && str(ev.data, "result", "artifact", "name") == "done" && str(ev.data, "result", "artifact", "parts", "0", "text") == "shipped" {
			sawArtifact = true
		}
	}
	if !sawWorking || !sawArtifact {
		t.Fatalf("missing transitions: %v", kinds(evs))
	}
	// Resume from the snapshot's cursor replays the missed board events, then ends (terminal).
	_, evs2, el2 := e.sse(t, creator, rpcReq(2, "tasks/resubscribe", map[string]any{"id": tid}), "Last-Event-ID", evs[0].id)
	if el2 > 3*time.Second || len(evs2) < 3 || str(evs2[0].data, "result", "kind") != "task" {
		t.Fatalf("resume: %v after %s", kinds(evs2), el2)
	}
	if last := evs2[len(evs2)-1].data; get(last, "result", "final") != true || evs2[1].id == "" || evs2[1].id <= evs[0].id {
		t.Fatalf("resume events: %v", kinds(evs2))
	}
	// An idle task ends at the wait with a status event carrying the resume cursor.
	idle := str(e.send(t, creator, "Idle stream", "st-2"), "id")
	_, evs3, el3 := e.sse(t, creator, rpcReq(3, "tasks/resubscribe", map[string]any{"id": idle, "metadata": map[string]any{"wait": 1}}))
	if el3 < 900*time.Millisecond || el3 > 4*time.Second || len(evs3) != 2 {
		t.Fatalf("idle stream: %v after %s", kinds(evs3), el3)
	}
	if last := evs3[1].data; str(last, "result", "kind") != "status-update" || get(last, "result", "final") != false || get(last, "result", "metadata", "resume") == nil {
		t.Fatalf("idle final event: %v", last)
	}
	// message/stream creates then streams; anonymous streams get the snapshot and cursor only.
	_, evs4, el4 := e.sse(t, creator, rpcReq(4, "message/stream", sendParams("Streamed creation", "st-3", "", map[string]any{"metadata": map[string]any{"wait": 1}})))
	if el4 > 4*time.Second || len(evs4) != 2 || !taskIDRe.MatchString(str(evs4[0].data, "result", "id")) || str(evs4[0].data, "result", "status", "state") != StSubmitted {
		t.Fatalf("message/stream: %v after %s", kinds(evs4), el4)
	}
	_, evs5, el5 := e.sse(t, "", rpcReq(5, "tasks/resubscribe", map[string]any{"id": idle, "metadata": map[string]any{"wait": 20}}))
	if el5 > 2*time.Second || len(evs5) != 2 || get(evs5[1].data, "result", "metadata", "resume") == nil {
		t.Fatalf("anonymous stream: %v after %s", kinds(evs5), el5)
	}
	// Streaming methods never batch.
	st, out, _ := e.rpcBatch(t, creator, []any{rpcReq(6, "tasks/resubscribe", map[string]any{"id": idle}), rpcReq(7, "tasks/get", map[string]any{"id": idle})})
	if code, _, _ := errOf(t, out[0]); st != 200 || len(out) != 2 || code != CodeInvalid || out[1]["result"] == nil {
		t.Fatalf("batched stream: %d %v", st, out)
	}
}

func TestPushConfigFnUnsupportedWhenNil(t *testing.T) {
	e := newEnv(t)
	savedS, savedG := PushConfigFn, PushConfigGetFn
	PushConfigFn, PushConfigGetFn = nil, nil
	t.Cleanup(func() { PushConfigFn, PushConfigGetFn = savedS, savedG })
	root, tok := e.register(t, "pusher")
	tid := str(e.send(t, tok, "Push me", "pc-1"), "id")
	cfg := map[string]any{"url": "https://client.example/hook", "token": "abc"}
	st, m, _ := e.rpc(t, tok, rpcReq(1, "tasks/pushNotificationConfig/set", map[string]any{"taskId": tid, "pushNotificationConfig": cfg}))
	if code, _, _ := errOf(t, m); st != 200 || code != CodePushUnsup {
		t.Fatalf("set with nil fn: %d %v", st, m)
	}
	st, m, _ = e.rpc(t, tok, rpcReq(2, "tasks/pushNotificationConfig/get", map[string]any{"id": tid}))
	if code, _, _ := errOf(t, m); st != 200 || code != CodePushUnsup {
		t.Fatalf("get with nil fn: %d %v", st, m)
	}
	if st, m, _ := e.rpc(t, "", rpcReq(3, "tasks/pushNotificationConfig/set", map[string]any{"taskId": tid, "pushNotificationConfig": cfg})); st != 401 || m["error"] == nil {
		t.Fatalf("anonymous set: %d %v", st, m)
	}
	var gotRoot, gotTask string
	PushConfigFn = func(ctx context.Context, q core.Q, requesterRoot, taskID string, c json.RawMessage) (string, error) {
		gotRoot, gotTask = requesterRoot, taskID
		return "https://agents.example/v1/hook/h123/out", nil
	}
	PushConfigGetFn = func(ctx context.Context, q core.Q, requesterRoot, taskID string) (json.RawMessage, string, error) {
		return json.RawMessage(`{"url":"https://client.example/hook"}`), "https://agents.example/v1/hook/h123/out", nil
	}
	st, m, _ = e.rpc(t, tok, rpcReq(4, "tasks/pushNotificationConfig/set", map[string]any{"taskId": tid, "pushNotificationConfig": cfg}))
	if r := result(t, m); st != 200 || str(r, "metadata", "pull") != "https://agents.example/v1/hook/h123/out" || str(r, "taskId") != tid || gotRoot != root || gotTask != tid {
		t.Fatalf("set: %d %v (root %s task %s)", st, m, gotRoot, gotTask)
	}
	st, m, _ = e.rpc(t, tok, rpcReq(5, "tasks/pushNotificationConfig/get", map[string]any{"id": tid}))
	if r := result(t, m); st != 200 || str(r, "pushNotificationConfig", "url") != "https://client.example/hook" || str(r, "metadata", "pull") == "" {
		t.Fatalf("get: %d %v", st, m)
	}
	if st, m, _ := e.rpc(t, tok, rpcReq(6, "tasks/pushNotificationConfig/set", map[string]any{"taskId": tid, "pushNotificationConfig": map[string]any{"url": "ftp://x"}})); st != 200 || m["error"] == nil {
		t.Fatalf("bad url accepted: %v", m)
	}
	if st, m, _ := e.rpc(t, tok, rpcReq(7, "tasks/pushNotificationConfig/list", map[string]any{"id": tid})); st != 200 || int(get(m, "error", "code").(float64)) != CodeUnsupported {
		t.Fatalf("list: %v", m)
	}
}

func TestCardFieldsAndParse(t *testing.T) {
	c := CardFields()
	if c["protocolVersion"] != "0.3.0" || c["preferredTransport"] != "JSONRPC" || !strings.HasSuffix(c["url"].(string), "/a2a") {
		t.Fatalf("card: %v", c)
	}
	caps := c["capabilities"].(map[string]any)
	if caps["streaming"] != true || caps["pushNotifications"] != false || caps["stateTransitionHistory"] != true {
		t.Fatalf("capabilities: %v", caps)
	}
	ids := map[string]bool{}
	for _, s := range Skills() {
		ids[s["id"].(string)] = true
		if ex, _ := s["examples"].([]string); len(ex) == 0 {
			t.Fatalf("skill without examples: %v", s)
		}
	}
	for _, want := range []string{"board", "search", "error", "read", "versions", "help"} {
		if !ids[want] {
			t.Fatalf("skill %s missing: %v", want, ids)
		}
	}
	if b, err := json.Marshal(c); err != nil || len(b) > 6000 {
		t.Fatalf("card json: %d %v", len(b), err)
	}
	if _, err := Parse([]byte(" ")); err == nil {
		t.Fatal("empty body parsed")
	}
	reqs, err := Parse([]byte(`[{"jsonrpc":"2.0","id":1,"method":"tasks/get"}, 7]`))
	if err != nil || len(reqs) != 2 || reqs[0].Method != "tasks/get" || !reqs[1].bad {
		t.Fatalf("parse batch: %v %v", reqs, err)
	}
}
