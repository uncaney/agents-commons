package a2ahost

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/mail"
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
	p, cleanup := testdb.Open("a2ahost", core.Migrate)
	if p == nil {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping a2ahost DB tests")
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
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, PowBitsW: 6,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAuthV2(mux, d)
	mail.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	var b [2]byte
	rand.Read(b[:])
	return &tenv{d, srv, fmt.Sprintf("10.8.%d.%d", b[0], b[1])}
}

func (e *tenv) raw(t *testing.T, method, path, tok string, body any, hdr ...string) (int, []byte, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		default:
			j, _ := json.Marshal(b)
			rd = strings.NewReader(string(j))
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

func (e *tenv) register(t *testing.T, name string) (id, tok string) {
	t.Helper()
	_, b, _ := e.raw(t, "POST", "/v1/challenge", "", nil)
	c := kv(string(b))["c"]
	st, rb, _ := e.raw(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, 6), "name": name})
	if st != 201 {
		t.Fatalf("register: %d %s", st, rb)
	}
	m := kv(string(rb))
	return m["id"], m["token"]
}

func (e *tenv) setLevel(t *testing.T, id string, lvl int) {
	t.Helper()
	var q string
	switch lvl {
	case 1:
		q = `UPDATE identities SET rep = 1, created = now() - interval '2 days' WHERE id = $1`
	case 2:
		q = `UPDATE identities SET rep = 5, created = now() - interval '5 days', verified_noncompute = 1 WHERE id = $1`
	case 3:
		q = `UPDATE identities SET rep = 25, created = now() - interval '40 days', verified_noncompute = 1 WHERE id = $1`
	default:
		return
	}
	if _, err := testPool.Exec(context.Background(), q, id); err != nil {
		t.Fatal(err)
	}
}

func kv(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Fields(s) {
		if i := strings.IndexByte(line, '='); i > 0 {
			m[line[:i]] = strings.Trim(line[i+1:], `",`)
		}
	}
	return m
}

// --- card helpers ---

func putCard(t *testing.T, e *tenv, tok, desc, inbound string, skills []map[string]any) (int, string) {
	t.Helper()
	body := map[string]any{"description": desc, "inbound": inbound}
	if skills != nil {
		body["skills"] = skills
	}
	st, b, _ := e.raw(t, "PUT", "/v1/me/card", tok, body)
	return st, string(b)
}

func skill(id, name string, tags ...string) map[string]any {
	return map[string]any{"id": id, "name": name, "description": "does " + name, "tags": tags}
}

// --- JSON-RPC helpers ---

func sendBody(id int, text, mid, taskID string) map[string]any {
	msg := map[string]any{"role": "user", "parts": []any{map[string]any{"kind": "text", "text": text}}, "messageId": mid, "kind": "message"}
	if taskID != "" {
		msg["taskId"] = taskID
	}
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "message/send", "params": map[string]any{"message": msg}}
}

func (e *tenv) rpc(t *testing.T, ownerID, tok string, body any) (int, map[string]any) {
	t.Helper()
	st, b, _ := e.raw(t, "POST", "/a2a/"+ownerID, tok, body)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("rpc: %d %s", st, b)
	}
	return st, m
}

func result(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", m)
	}
	return r
}

func rpcError(m map[string]any) (float64, string, bool) {
	e, ok := m["error"].(map[string]any)
	if !ok {
		return 0, "", false
	}
	code, _ := e["code"].(float64)
	msg, _ := e["message"].(string)
	return code, msg, true
}

// --- tests ---

func TestCardValidationReserved(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register(t, "owner")
	st, body := putCard(t, e, tok, "a helpful agent", "open", []map[string]any{skill("s1", "admin")})
	if st != 400 || !strings.Contains(body, "reserved") {
		t.Fatalf("reserved skill name must be refused: %d %s", st, body)
	}
	// a clean card is accepted
	st, body = putCard(t, e, tok, "a helpful agent", "open", []map[string]any{skill("s1", "summarise")})
	if st != 200 {
		t.Fatalf("clean card: %d %s", st, body)
	}
}

func TestAgentJsonShape(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register(t, "scribe")
	if st, b := putCard(t, e, tok, "summarises text", "open", []map[string]any{skill("sum", "summarise", "text", "nlp")}); st != 200 {
		t.Fatalf("card: %d %s", st, b)
	}
	st, b, _ := e.raw(t, "GET", "/a/"+id+"/agent.json", "", nil)
	if st != 200 {
		t.Fatalf("agent.json: %d %s", st, b)
	}
	var card map[string]any
	if err := json.Unmarshal(b, &card); err != nil {
		t.Fatal(err)
	}
	if name, _ := card["name"].(string); name != "scribe ("+id+")" {
		t.Fatalf("name = %q", name)
	}
	if url, _ := card["url"].(string); !strings.HasSuffix(url, "/a2a/"+id) {
		t.Fatalf("url = %q", url)
	}
	prov, _ := card["provider"].(map[string]any)
	if org, _ := prov["organization"].(string); org != "agents.ekaii.fr (hosted)" {
		t.Fatalf("provider = %v", prov)
	}
	caps, _ := card["capabilities"].(map[string]any)
	if s, _ := caps["streaming"].(bool); !s {
		t.Fatalf("capabilities = %v", caps)
	}
	sec, _ := card["securitySchemes"].(map[string]any)
	bearer, _ := sec["bearer"].(map[string]any)
	if sch, _ := bearer["scheme"].(string); sch != "bearer" {
		t.Fatalf("securitySchemes = %v", sec)
	}
	if skills, _ := card["skills"].([]any); len(skills) != 1 {
		t.Fatalf("skills = %v", card["skills"])
	}
}

func TestClosedInboundRefused(t *testing.T) {
	e := newEnv(t)
	owner, otok := e.register(t, "owner")
	if st, b := putCard(t, e, otok, "closed agent", "closed", nil); st != 200 {
		t.Fatalf("card: %d %s", st, b)
	}
	_, rtok := e.register(t, "req")
	e.setLevel(t, mustID(t, e, rtok), 2)
	st, m := e.rpc(t, owner, rtok, sendBody(1, "hello", "", ""))
	if st != 200 {
		t.Fatalf("http %d", st)
	}
	code, msg, ok := rpcError(m)
	if !ok || code != -32004 {
		t.Fatalf("closed inbound must be -32004: %v (%s)", m, msg)
	}
}

func TestSendRelaysThroughMailGates(t *testing.T) {
	e := newEnv(t)
	owner, otok := e.register(t, "owner")
	if st, b := putCard(t, e, otok, "open agent", "open", nil); st != 200 {
		t.Fatalf("card: %d %s", st, b)
	}
	// an L2 requester passes the mail context gate and the message lands in the owner's mailbox.
	req, rtok := e.register(t, "req")
	e.setLevel(t, req, 2)
	st, m := e.rpc(t, owner, rtok, sendBody(1, "please summarise", "", ""))
	if st != 200 {
		t.Fatalf("http %d %v", st, m)
	}
	task, _ := result(t, m)["id"].(string)
	if !core.ValidIDPrefix(task, 'x') {
		t.Fatalf("no hosted task id: %v", m)
	}
	// the owner's mailbox carries the relayed message keyed re=<task>.
	_, inbox, _ := e.raw(t, "GET", "/v1/mb", otok, nil)
	if !strings.Contains(string(inbox), task) {
		t.Fatalf("relayed mail not in owner mailbox: %s", inbox)
	}

	// a fresh (age < 1 h) requester is stopped by the mail gate: nothing is stored.
	_, ftok := e.register(t, "fresh")
	st, m = e.rpc(t, owner, ftok, sendBody(1, "hi", "", ""))
	if _, _, ok := rpcError(m); !ok {
		t.Fatalf("fresh requester should hit a mail gate: %v", m)
	}
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM a2a_hosted WHERE owner_root = $1`, owner).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("gate-refused send must store nothing (tasks=%d)", n)
	}
}

func TestOwnerReplyAndRequesterGet(t *testing.T) {
	e := newEnv(t)
	owner, otok := e.register(t, "owner")
	if st, b := putCard(t, e, otok, "open agent", "open", nil); st != 200 {
		t.Fatalf("card: %d %s", st, b)
	}
	req, rtok := e.register(t, "req")
	e.setLevel(t, req, 2)
	_, m := e.rpc(t, owner, rtok, sendBody(1, "do the thing", "", ""))
	task, _ := result(t, m)["id"].(string)

	// the owner sees the inbound message.
	_, in, _ := e.raw(t, "GET", "/v1/a2a/in", otok, nil)
	if !strings.Contains(string(in), task) {
		t.Fatalf("owner inbound missing task: %s", in)
	}
	// the owner replies completed.
	st, rb, _ := e.raw(t, "POST", "/v1/a2a/"+task+"/reply", otok, map[string]any{"text": "done", "state": "completed"})
	if st != 200 {
		t.Fatalf("reply: %d %s", st, rb)
	}
	// the requester sees the task completed.
	_, m = e.rpc(t, owner, rtok, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tasks/get", "params": map[string]any{"id": task}})
	status, _ := result(t, m)["status"].(map[string]any)
	if state, _ := status["state"].(string); state != "completed" {
		t.Fatalf("task state = %v", status)
	}
}

func TestRequesterRootHiddenFromOthers(t *testing.T) {
	e := newEnv(t)
	owner, otok := e.register(t, "owner")
	putCard(t, e, otok, "open agent", "open", nil)
	req, rtok := e.register(t, "req")
	e.setLevel(t, req, 2)
	_, m := e.rpc(t, owner, rtok, sendBody(1, "hello", "", ""))
	task, _ := result(t, m)["id"].(string)

	// a third agent reads the task: it is not a participant, so it gets the identical
	// task-not-found and no history (nor requesterRoot) is disclosed.
	_, ctok := e.register(t, "other")
	e.setLevel(t, mustID(t, e, ctok), 2)
	_, m = e.rpc(t, owner, ctok, map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tasks/get", "params": map[string]any{"id": task}})
	if code, msg, ok := rpcError(m); !ok || code != -32001 {
		t.Fatalf("non-participant tasks/get must be task-not-found (-32001): %v (%s)", m, msg)
	}
	if _, leaked := m["result"]; leaked {
		t.Fatalf("non-participant must get no result: %v", m)
	}
	// the owner reads it: requesterRoot is present and equals the requester.
	_, m = e.rpc(t, owner, otok, map[string]any{"jsonrpc": "2.0", "id": 4, "method": "tasks/get", "params": map[string]any{"id": task}})
	meta, _ := result(t, m)["metadata"].(map[string]any)
	if rr, _ := meta["requesterRoot"].(string); rr != req {
		t.Fatalf("owner should see requesterRoot=%s, got %v", req, meta)
	}
}

// TestGetRequiresParticipant asserts tasks/get discloses history only to the requester
// and the owner; an anonymous caller and an unrelated third agent both get task-not-found.
func TestGetRequiresParticipant(t *testing.T) {
	e := newEnv(t)
	owner, otok := e.register(t, "owner")
	putCard(t, e, otok, "open agent", "open", nil)
	req, rtok := e.register(t, "req")
	e.setLevel(t, req, 2)
	_, m := e.rpc(t, owner, rtok, sendBody(1, "secret ask", "", ""))
	task, _ := result(t, m)["id"].(string)

	getBody := func(rid int) map[string]any {
		return map[string]any{"jsonrpc": "2.0", "id": rid, "method": "tasks/get", "params": map[string]any{"id": task}}
	}

	// the requester reads its own task: full history is returned.
	_, m = e.rpc(t, owner, rtok, getBody(2))
	if hist, _ := result(t, m)["history"].([]any); len(hist) == 0 {
		t.Fatalf("requester must see history: %v", m)
	}
	// the owner reads it too.
	_, m = e.rpc(t, owner, otok, getBody(3))
	if hist, _ := result(t, m)["history"].([]any); len(hist) == 0 {
		t.Fatalf("owner must see history: %v", m)
	}
	// an anonymous caller gets task-not-found with no result.
	_, m = e.rpc(t, owner, "", getBody(4))
	if code, msg, ok := rpcError(m); !ok || code != -32001 {
		t.Fatalf("anonymous tasks/get must be task-not-found (-32001): %v (%s)", m, msg)
	}
	if _, leaked := m["result"]; leaked {
		t.Fatalf("anonymous caller must get no result: %v", m)
	}
}

func TestDirectoryL1OpenOnly(t *testing.T) {
	e := newEnv(t)
	l1, l1tok := e.register(t, "liste")
	e.setLevel(t, l1, 1)
	putCard(t, e, l1tok, "listed L1 open", "open", nil)

	_, l0tok := e.register(t, "fresh")
	putCard(t, e, l0tok, "L0 open", "open", nil) // L0 never listed

	l1c, l1ctok := e.register(t, "closed")
	e.setLevel(t, l1c, 1)
	putCard(t, e, l1ctok, "L1 closed", "closed", nil) // inbound closed never listed

	_, b, _ := e.raw(t, "GET", "/agents", "", nil)
	body := string(b)
	if !strings.Contains(body, l1) {
		t.Fatalf("L1 open card not listed: %s", body)
	}
	if strings.Contains(body, "L0 open") || strings.Contains(body, "L1 closed") {
		t.Fatalf("L0 or closed card listed: %s", body)
	}
}

func TestSitemapL2Only(t *testing.T) {
	e := newEnv(t)
	l1, l1tok := e.register(t, "one")
	e.setLevel(t, l1, 1)
	putCard(t, e, l1tok, "L1 open", "open", nil)
	l2, l2tok := e.register(t, "two")
	e.setLevel(t, l2, 2)
	putCard(t, e, l2tok, "L2 open", "open", nil)

	urls, err := agentsSitemap(context.Background(), e.d)
	if err != nil {
		t.Fatal(err)
	}
	var sawL2, sawL1 bool
	for _, u := range urls {
		if strings.Contains(u.Loc, l2) {
			sawL2 = true
		}
		if strings.Contains(u.Loc, l1) {
			sawL1 = true
		}
	}
	if !sawL2 || sawL1 {
		t.Fatalf("sitemap must list L2 only: l2=%v l1=%v (%v)", sawL2, sawL1, urls)
	}
}

// mustID returns the identity id for a token via GET /v1/me.
func mustID(t *testing.T, e *tenv, tok string) string {
	t.Helper()
	_, b, _ := e.raw(t, "GET", "/v1/me", tok, nil)
	id := kv(string(b))["id"]
	if id == "" {
		t.Fatalf("no id in /v1/me: %s", b)
	}
	return id
}
