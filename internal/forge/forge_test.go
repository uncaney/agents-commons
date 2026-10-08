package forge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

// TestMain opens the package database through internal/testdb (TEST_PG_ADMIN_URL); a builder may
// still point TEST_DATABASE_URL at a scratch database of its own.
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
	p, cleanup := testdb.Open("forge", core.Migrate)
	if p == nil {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping forge DB tests")
		os.Exit(0)
	}
	testPool = p
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d     *core.Deps
	s     *Service
	fake  *fakeForge // nil without a mirror
	srv   *httptest.Server
	ip    string
	space string // per-env space: the database is shared by every test, lists filter on it
}

type envOpts struct {
	down     bool // the fake Forgejo answers 503 until flipped
	noMirror bool // FORGEJO_URL="" (Postgres only)
}

func newEnv(t *testing.T, down bool) *tenv { return newEnvOpts(t, envOpts{down: down}) }

func newEnvOpts(t *testing.T, o envOpts) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, PowBitsW: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20} // hourly registration counter is shared across packages' tests
	var f *fakeForge
	if !o.noMirror {
		f = newFake()
		t.Cleanup(f.srv.Close)
		f.down.Store(o.down)
		cfg.ForgejoURL, cfg.ForgejoToken = f.srv.URL, "fake-token"
	}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAuthV2(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	var b [4]byte
	rand.Read(b[:])
	e := &tenv{d, svc(d), f, srv, fmt.Sprintf("10.8.%d.%d", b[0], b[1]), fmt.Sprintf("sp-%x", b)}
	if f != nil && !o.down {
		e.waitReady(t)
	}
	return e
}

func (e *tenv) waitReady(t *testing.T) {
	t.Helper()
	for i := 0; i < 200 && !e.s.Ready(); i++ {
		time.Sleep(25 * time.Millisecond)
	}
	if !e.s.Ready() {
		t.Fatal("forge mirror never ready")
	}
}

// doRaw performs a request and returns status, trimmed body and headers.
func (e *tenv) doRaw(t *testing.T, method, path, token string, body any, hdr ...string) (int, string, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		default:
			j, _ := json.Marshal(b)
			rd = bytes.NewReader(j)
		}
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	// Anonymous reads and challenges come from a fresh address so the per-IP limiter (burst 20)
	// never shapes a test; /w/t keeps the env address (its quotas are keyed by IP group).
	ip := e.ip
	if token == "" && !strings.HasPrefix(path, "/w/") {
		var b [2]byte
		rand.Read(b[:])
		ip = fmt.Sprintf("10.9.%d.%d", b[0], b[1])
	}
	req.Header.Set("CF-Connecting-IP", ip)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
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
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

// do is doRaw without the trailing next: line (v2 tails on v1 documents).
func (e *tenv) do(t *testing.T, method, path, token string, body any, hdr ...string) (int, string) {
	t.Helper()
	st, b, _ := e.doRaw(t, method, path, token, body, hdr...)
	return st, stripTail(b)
}

func stripTail(b string) string {
	if i := strings.LastIndex(b, "\nnext: "); i >= 0 {
		return strings.TrimSpace(b[:i])
	}
	if strings.HasPrefix(b, "next: ") {
		return ""
	}
	return b
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

// powHeader solves a for=w challenge and returns the X-PoW header value.
func (e *tenv) powHeader(t *testing.T) string {
	t.Helper()
	_, body := e.do(t, "POST", "/v1/challenge?for=w", "", nil)
	m := kv(body)
	bits, _ := strconv.Atoi(m["bits"])
	return m["c"] + ":" + pow.Solve(m["c"], bits)
}

// taskBody is a create payload in this env's space.
func (e *tenv) taskBody(title string, extra map[string]any) map[string]any {
	m := map[string]any{"title": title, "space": e.space}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// create posts a task in the env's space and returns its number.
func (e *tenv) create(t *testing.T, tok, title string) int64 {
	t.Helper()
	st, body := e.do(t, "POST", "/v1/t", tok, e.taskBody(title, nil))
	if st != 201 || !strings.HasPrefix(body, "#") {
		t.Fatalf("create %q: %d %s", title, st, body)
	}
	return parseHash(t, body)
}

func parseHash(t *testing.T, body string) int64 {
	t.Helper()
	var n int64
	if _, err := fmt.Sscanf(body, "#%d", &n); err != nil {
		t.Fatalf("no task number in %q", body)
	}
	return n
}

// list is GET /v1/t restricted to the env's space.
func (e *tenv) list(t *testing.T, params string) string {
	t.Helper()
	p := "/v1/t?space=" + e.space
	if params != "" {
		p += "&" + params
	}
	st, body := e.do(t, "GET", p, "", nil)
	if st != 200 {
		t.Fatalf("list %s: %d %s", params, st, body)
	}
	return body
}

func (e *tenv) ident(t *testing.T, tok string) *core.Ident {
	t.Helper()
	id, err := e.d.LookupToken(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// flush pushes every pending outbox row (debounced ones included) through the mirror.
func (e *tenv) flush(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE forge_outbox SET next_at = now() WHERE attempts = 0 AND next_at > now()`); err != nil {
		t.Fatal(err)
	}
	if err := FlushOutbox(ctx, e.d); err != nil {
		t.Fatal(err)
	}
}

// issueOf returns the mirrored issue of task n (after flush).
func (e *tenv) issueOf(t *testing.T, n int64) Issue {
	t.Helper()
	var issue *int64
	if err := testPool.QueryRow(context.Background(), `SELECT issue FROM tasks WHERE n = $1`, n).Scan(&issue); err != nil || issue == nil {
		t.Fatalf("task %d has no mirror issue (%v)", n, err)
	}
	return e.fake.getIssue(*issue)
}

// makeL2 turns a root into an L2 identity registered from ip (its own super-group and cohort).
func (e *tenv) makeL2(t *testing.T, id, ip string) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET rep = 5, created = now() - interval '4 days', verified_noncompute = 1,
		reg_ip = $2, cohort = $2 WHERE id = $1`, id, ip); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureBootstrap(t *testing.T) {
	e := newEnv(t, false)
	f := e.fake
	f.mu.Lock()
	if !f.orgs["commons"] {
		t.Fatal("org missing")
	}
	for _, r := range []string{"board", "notes", "kb", "gov"} {
		opts, ok := f.repos["commons/"+r]
		if !ok {
			t.Fatalf("repo %s missing", r)
		}
		if opts["has_pull_requests"] != false || opts["has_actions"] != false {
			t.Fatalf("repo %s not hardened: %v", r, opts)
		}
	}
	if f.repos["commons/board"]["has_issues"] != true || f.repos["commons/notes"]["has_wiki"] != true {
		t.Fatal("features")
	}
	names := map[string]bool{}
	for _, l := range f.labels["commons/board"] {
		names[l.Name] = true
	}
	f.mu.Unlock()
	if !names["claimed"] || !names["hidden"] {
		t.Fatalf("labels: %v", names)
	}
	// Idempotent.
	before := f.reqs.Load()
	if err := e.s.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	n := len(f.labels["commons/board"])
	f.mu.Unlock()
	if n != 2 || f.reqs.Load()-before > 7 {
		t.Fatalf("second ensure not idempotent: labels=%d reqs=%d", n, f.reqs.Load()-before)
	}
}

// The board serves from Postgres while the mirror is down: no `err frozen forge-starting` (7.2).
func TestBoardServesWhileMirrorDown(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	id, tok := e.register(t, "w")
	if e.s.Ready() {
		t.Fatal("mirror should not be ready while Forgejo is down")
	}
	n := e.create(t, tok, "works offline")
	if st, body := e.do(t, "GET", "/v1/t/"+itoa(n), "", nil); st != 200 || !strings.HasPrefix(body, fmt.Sprintf("#%d open by %s", n, id)) {
		t.Fatalf("get while mirror down: %d %s", st, body)
	}
	if st, body := e.do(t, "PUT", "/v1/n/x", tok, "hi"); st != 200 || body != "ok rev=1" {
		t.Fatalf("note while mirror down: %d %s", st, body)
	}
	if out, err := Ops(e.d)["t"](ctx, nil, json.RawMessage(`{"space":"`+e.space+`"}`)); err != nil || out != fmt.Sprintf("#%d open works offline\n", n) {
		t.Fatalf("op while mirror down: %q %v", out, err)
	}
	// Rows wait in the outbox; nothing is lost.
	var pending int
	testPool.QueryRow(ctx, `SELECT count(*) FROM forge_outbox WHERE kind IN ('task', 'note') AND ref IN ($1, $2)`, itoa(n), id+"/x").Scan(&pending)
	if pending != 2 {
		t.Fatalf("outbox rows: %d", pending)
	}
	e.fake.down.Store(false)
	e.waitReady(t)
	e.flush(t)
	if is := e.issueOf(t, n); is.Title != "works offline" {
		t.Fatalf("mirrored issue: %+v", is)
	}
}

func TestTaskFlow(t *testing.T) {
	e := newEnv(t, false)
	id, tok := e.register(t, "alice")
	st, body := e.do(t, "POST", "/v1/t", tok, e.taskBody("Fix the flux", map[string]any{"body": "line1\nline2", "tags": []string{"go", "net"}}))
	if st != 201 || !strings.HasPrefix(body, "#") {
		t.Fatalf("create: %d %s", st, body)
	}
	n1 := parseHash(t, body)
	if body != fmt.Sprintf("#%d", n1) {
		t.Fatalf("create body: %q", body)
	}
	p1 := fmt.Sprintf("/v1/t/%d", n1)
	if st, body := e.do(t, "POST", "/v1/t", "", map[string]any{"title": "x"}); st != 401 {
		t.Fatalf("anon create: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/t", tok, map[string]any{"title": strings.Repeat("x", 161)}); st != 400 {
		t.Fatalf("long title: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/t", tok, map[string]any{"title": "x", "tags": []string{"claimed"}}); st != 400 {
		t.Fatalf("reserved tag: %d %s", st, body)
	}
	// Mirror: hidden mark stored in Forgejo, never in the API output.
	e.flush(t)
	if is := e.issueOf(t, n1); !strings.HasPrefix(is.Body, "<!-- by:"+id+" root:"+id+" -->\nline1") || !is.HasLabel("go") {
		t.Fatalf("issue body: %q labels %v", is.Body, is.Labels)
	}
	if body := e.list(t, ""); body != fmt.Sprintf("#%d open Fix the flux", n1) {
		t.Fatalf("list: %s", body)
	}
	if st, body := e.do(t, "GET", "/v1/t?s=bogus", "", nil); st != 400 {
		t.Fatalf("bad state: %d %s", st, body)
	}
	if body := e.list(t, "q=flux"); body != fmt.Sprintf("#%d open Fix the flux", n1) {
		t.Fatalf("search: %s", body)
	}
	if body := e.list(t, "q=nomatch"); body != "" {
		t.Fatalf("search miss: %q", body)
	}
	st, body = e.do(t, "GET", p1, "", nil)
	want := fmt.Sprintf("#%d open by %s %s\ntitle: Fix the flux\nbody: line1\n  line2\ntags: go,net\nspace: %s", n1, id, core.Date(time.Now()), e.space) // continuation lines indented
	if st != 200 || body != want {
		t.Fatalf("get:\n%s\nwant:\n%s", body, want)
	}
	if st, _ := e.do(t, "GET", fmt.Sprintf("/v1/t/%d", n1+1_000_000_000), "", nil); st != 404 {
		t.Fatalf("get missing: %d", st)
	}
	if st, _ := e.do(t, "GET", "/v1/t/abc", "", nil); st != 400 {
		t.Fatalf("get bad n: %d", st)
	}
	for i := 0; i < 6; i++ {
		if st, body := e.do(t, "POST", p1+"/note", tok, map[string]any{"text": fmt.Sprintf("note %d\nmore", i)}); st != 200 || body != "ok" {
			t.Fatalf("note: %d %s", st, body)
		}
	}
	_, body = e.do(t, "GET", p1, "", nil)
	day := core.Date(time.Now())
	// Total count, then the last 5 notes; multi-line note text is indented (continuation lines).
	if !strings.Contains(body, fmt.Sprintf("\nnotes: 6\n- %s %s: note 1\n  more\n", id, day)) || !strings.Contains(body, fmt.Sprintf("- %s %s: note 5\n  more\nspace: ", id, day)) || strings.Contains(body, "note 0") {
		t.Fatalf("notes:\n%s", body)
	}
	if strings.Contains(body, "<!--") {
		t.Fatalf("mark leaked: %s", body)
	}
	// JSON view.
	st, body = e.do(t, "GET", p1+"?f=json", "", nil)
	var j Task
	if err := json.Unmarshal([]byte(body), &j); err != nil || j.N != n1 || j.By != id || j.Body != "line1\nline2" || len(j.Notes) != 5 || j.NoteCount != 6 || j.Notes[0].By != id || j.Space != e.space {
		t.Fatalf("json: %d %s (%v)", st, body, err)
	}
	st, body = e.do(t, "GET", "/v1/t?f=json&space="+e.space, "", nil)
	var jl []TaskLine
	if err := json.Unmarshal([]byte(body), &jl); err != nil || len(jl) != 1 || jl[0].State != "open" {
		t.Fatalf("json list: %s", body)
	}
	// Creator can close without claiming.
	if st, body := e.do(t, "POST", p1+"/done", tok, map[string]any{"text": "shipped"}); st != 200 {
		t.Fatalf("done: %d %s", st, body)
	}
	if body := e.list(t, "s=done"); body != fmt.Sprintf("#%d done Fix the flux", n1) {
		t.Fatalf("done list: %s", body)
	}
	if body := e.list(t, ""); body != "" {
		t.Fatalf("open list after done: %q", body)
	}
	if st, body := e.do(t, "POST", p1+"/claim", tok, nil); st != 409 {
		t.Fatalf("claim closed: %d %s", st, body)
	}
	e.flush(t)
	if is := e.issueOf(t, n1); is.State != "closed" || !strings.Contains(is.Body, "notes: 7") {
		t.Fatalf("mirrored done: %+v", is)
	}
	// Quota: 10/day for new roots (one used).
	for i := 0; i < 9; i++ {
		if st, body := e.do(t, "POST", "/v1/t", tok, e.taskBody(fmt.Sprintf("t%d", i), nil)); st != 201 {
			t.Fatalf("task %d: %d %s", i, st, body)
		}
	}
	if st, body := e.do(t, "POST", "/v1/t", tok, e.taskBody("over", nil)); st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("quota: %d %s", st, body)
	}
}

func TestClaimAtomic(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	a, atok := e.register(t, "a")
	b, btok := e.register(t, "b")
	_, ctok := e.register(t, "c")
	n1 := e.create(t, ctok, "race")
	p1 := fmt.Sprintf("/v1/t/%d", n1)
	// Two concurrent claimers: exactly one wins.
	var wg sync.WaitGroup
	start := make(chan struct{})
	res := make([]int, 2)
	bodies := make([]string, 2)
	for i, tk := range []string{atok, btok} {
		wg.Add(1)
		go func(i int, tk string) {
			defer wg.Done()
			<-start
			res[i], bodies[i] = e.do(t, "POST", p1+"/claim", tk, nil)
		}(i, tk)
	}
	close(start)
	wg.Wait()
	toks, ids := []string{atok, btok}, []string{a, b}
	wi := -1
	for i := range res {
		if res[i] == 200 {
			if wi >= 0 {
				t.Fatalf("two winners: %v %v", res, bodies)
			}
			wi = i
		}
	}
	if wi < 0 {
		t.Fatalf("no winner: %v %v", res, bodies)
	}
	li := 1 - wi
	winner, loser, holderID := toks[wi], toks[li], ids[wi]
	until := core.Date(time.Now().Add(claimTTL))
	if bodies[wi] != "ok until "+until+" fence=1" {
		t.Fatalf("win body: %s", bodies[wi])
	}
	if res[li] != 409 || bodies[li] != "err taken "+holderID+" "+until {
		t.Fatalf("loser: %d %s", res[li], bodies[li])
	}
	e.flush(t)
	if is := e.issueOf(t, n1); !is.HasLabel("claimed") {
		t.Fatal("claimed label missing")
	}
	if body := e.list(t, "s=claimed"); body != fmt.Sprintf("#%d claimed:%s race", n1, holderID) {
		t.Fatalf("claimed list: %s", body)
	}
	if body := e.list(t, ""); body != "" {
		t.Fatalf("open list should hide claimed: %q", body)
	}
	// Renew by holder bumps until; the fence does not move.
	testPool.Exec(ctx, `UPDATE task_claims SET until = now() + interval '1 hour' WHERE n = $1 AND root = $2`, n1, holderID)
	if st, body := e.do(t, "POST", p1+"/claim", winner, nil); st != 200 || body != "ok until "+core.Date(time.Now().Add(claimTTL))+" fence=1" {
		t.Fatalf("renew: %d %s", st, body)
	}
	// Non-holder cannot drop/done; loser still refused.
	if st, body := e.do(t, "POST", p1+"/done", loser, map[string]any{"text": "mine"}); st != 403 {
		t.Fatalf("done by non-holder: %d %s", st, body)
	}
	if st, _ := e.do(t, "POST", p1+"/drop", loser, nil); st != 403 {
		t.Fatal("drop by non-holder")
	}
	if st, _ := e.do(t, "POST", p1+"/claim", loser, nil); st != 409 {
		t.Fatal("loser should still be refused")
	}
	// Expiry: the task reads open; the janitor syncs the mirror; loser can then claim (fence moves).
	testPool.Exec(ctx, `UPDATE task_claims SET until = now() - interval '1 second' WHERE n = $1`, n1)
	if body := e.list(t, ""); body != fmt.Sprintf("#%d open race", n1) {
		t.Fatalf("expired should read open: %q", body)
	}
	if err := e.s.expireClaims(ctx); err != nil {
		t.Fatal(err)
	}
	e.flush(t)
	if is := e.issueOf(t, n1); is.HasLabel("claimed") {
		t.Fatal("label not removed on expiry")
	}
	if st, body := e.do(t, "POST", p1+"/claim", loser, nil); st != 200 || !strings.HasSuffix(body, " fence=2") {
		t.Fatalf("claim after expiry: %d %s", st, body)
	}
	// Holder drops, then done by holder after re-claim.
	if st, body := e.do(t, "POST", p1+"/drop", loser, nil); st != 200 || body != "ok" {
		t.Fatalf("drop: %d %s", st, body)
	}
	e.flush(t)
	if is := e.issueOf(t, n1); is.HasLabel("claimed") {
		t.Fatal("label not removed on drop")
	}
	if st, body := e.do(t, "POST", p1+"/claim", winner, nil); st != 200 || !strings.HasSuffix(body, " fence=3") {
		t.Fatalf("reclaim: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", p1+"/done", winner, nil); st != 200 {
		t.Fatalf("done by holder: %d %s", st, body)
	}
	e.flush(t)
	if is := e.issueOf(t, n1); is.State != "closed" || is.HasLabel("claimed") {
		t.Fatalf("issue after done: %+v", is)
	}
	var live bool
	testPool.QueryRow(ctx, `SELECT until > now() FROM task_claims WHERE n = $1`, n1).Scan(&live)
	if live {
		t.Fatal("claim still live after done")
	}
}

func TestNotes(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	id, tok := e.register(t, "owner")
	other, otok := e.register(t, "other")
	if st, body := e.do(t, "PUT", "/v1/n/todo", tok, "buy milk\nline2"); st != 200 || body != "ok rev=1" {
		t.Fatalf("put: %d %s", st, body)
	}
	if st, _ := e.do(t, "PUT", "/v1/n/Bad Name", tok, "x"); st != 400 {
		t.Fatal("bad name accepted")
	}
	if st, _ := e.do(t, "PUT", "/v1/n/todo", "", "x"); st != 401 {
		t.Fatal("anon put")
	}
	if st, body := e.do(t, "PUT", "/v1/n/big", tok, strings.Repeat("x", 32<<10+1)); st != 413 || !strings.HasPrefix(body, "err size") {
		t.Fatalf("oversize: %d %s", st, body)
	}
	// Anonymous read, raw text; own namespace only.
	if st, body := e.do(t, "GET", "/v1/n/"+id+"/todo", "", nil); st != 200 || body != "buy milk\nline2" {
		t.Fatalf("get: %d %s", st, body)
	}
	if st, _ := e.do(t, "GET", "/v1/n/"+other+"/todo", "", nil); st != 404 {
		t.Fatal("other's namespace should be empty")
	}
	e.flush(t)
	e.fake.mu.Lock()
	_, ok := e.fake.wiki["commons/notes/"+id+"--todo"]
	e.fake.mu.Unlock()
	if !ok {
		t.Fatal("wiki page name")
	}
	if st, body := e.do(t, "PUT", "/v1/n/todo", otok, "mine"); st != 200 || body != "ok rev=1" {
		t.Fatalf("other put: %d %s", st, body)
	}
	if _, body := e.do(t, "GET", "/v1/n/"+id+"/todo", "", nil); body != "buy milk\nline2" {
		t.Fatalf("other overwrote: %s", body)
	}
	// Update in place keeps count and bumps the revision.
	if st, body := e.do(t, "PUT", "/v1/n/todo", tok, "v2"); st != 200 || body != "ok rev=2" {
		t.Fatalf("update: %d %s", st, body)
	}
	if _, body := e.do(t, "GET", "/v1/n/"+id+"/todo", "", nil); body != "v2" {
		t.Fatalf("update not visible: %s", body)
	}
	e.do(t, "PUT", "/v1/n/a.b-c_d", tok, "x")
	if st, body := e.do(t, "GET", "/v1/n?o="+id, "", nil); st != 200 || body != "a.b-c_d\ntodo" {
		t.Fatalf("list: %d %s", st, body)
	}
	if _, body := e.do(t, "GET", "/v1/n", tok, nil); body != "a.b-c_d\ntodo" {
		t.Fatalf("list self: %s", body)
	}
	if st, body := e.do(t, "GET", "/v1/n?o="+id+"&f=json", "", nil); st != 200 || body != `["a.b-c_d","todo"]` {
		t.Fatalf("list json: %s", body)
	}
	// Quota: 50 notes for new roots, x5 from L2.
	var size int
	testPool.QueryRow(ctx, `SELECT size FROM notes WHERE owner = $1 AND name = 'todo'`, id).Scan(&size)
	if size != 2 {
		t.Fatalf("size=%d", size)
	}
	for i := 2; i < 50; i++ {
		testPool.Exec(ctx, `INSERT INTO notes (owner, name, root, size) VALUES ($1, $2, $1, 1)`, id, fmt.Sprintf("f%d", i))
	}
	if st, body := e.do(t, "PUT", "/v1/n/over", tok, "x"); st != 429 || body != "err quota notes limit" {
		t.Fatalf("quota: %d %s", st, body)
	}
	if st, _ := e.do(t, "PUT", "/v1/n/todo", tok, "still-updatable"); st != 200 {
		t.Fatal("existing note should update under quota")
	}
	e.makeL2(t, id, "10.9.1.1")
	if st, body := e.do(t, "PUT", "/v1/n/over", tok, "x"); st != 200 {
		t.Fatalf("L2 x5: %d %s", st, body)
	}
	// Delete.
	if st, _ := e.do(t, "DELETE", "/v1/n/todo", otok, nil); st != 200 {
		t.Fatal("other deleting its own note")
	}
	if st, _ := e.do(t, "GET", "/v1/n/"+id+"/todo", "", nil); st != 200 {
		t.Fatal("other's delete touched owner's note")
	}
	if st, body := e.do(t, "DELETE", "/v1/n/todo", tok, nil); st != 200 || body != "ok" {
		t.Fatalf("delete: %d %s", st, body)
	}
	if st, _ := e.do(t, "GET", "/v1/n/"+id+"/todo", "", nil); st != 404 {
		t.Fatal("deleted still readable")
	}
	if st, _ := e.do(t, "DELETE", "/v1/n/todo", tok, nil); st != 404 {
		t.Fatal("double delete")
	}
	e.flush(t)
	e.fake.mu.Lock()
	_, ok = e.fake.wiki["commons/notes/"+id+"--todo"]
	e.fake.mu.Unlock()
	if ok {
		t.Fatal("wiki page not deleted by the mirror")
	}
	// BlankNote (deprecated alias of HideNote, report auto-hide): the note reads as absent.
	e.do(t, "PUT", "/v1/n/spam", otok, "spam")
	if err := BlankNote(ctx, e.d, other, "spam"); err != nil {
		t.Fatal(err)
	}
	if st, body := e.do(t, "GET", "/v1/n/"+other+"/spam", "", nil); st != 404 {
		t.Fatalf("hidden note readable: %d %q", st, body)
	}
}

func TestOutboxFlushRetry(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	ref := "k" + core.NewID('k')[1:]
	if err := Enqueue(ctx, testPool, "kb", ref, []byte("# title\n\nbody")); err != nil {
		t.Fatal(err)
	}
	e.fake.failPath = "entries/" + ref + ".md"
	e.fake.failContents.Store(1)
	if err := FlushOutbox(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	var attempts int
	var due bool
	var lastErr string
	if err := testPool.QueryRow(ctx, `SELECT attempts, next_at > now(), last_err FROM forge_outbox WHERE kind = 'kb' AND ref = $1`, ref).Scan(&attempts, &due, &lastErr); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || !due || !strings.Contains(lastErr, "500") {
		t.Fatalf("after failure: attempts=%d future=%v err=%q", attempts, due, lastErr)
	}
	// Not retried before next_at.
	if err := FlushOutbox(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	e.fake.mu.Lock()
	_, ok := e.fake.files["commons/kb/entries/"+ref+".md"]
	e.fake.mu.Unlock()
	if ok {
		t.Fatal("written before backoff elapsed")
	}
	testPool.Exec(ctx, `UPDATE forge_outbox SET next_at = now() WHERE ref = $1`, ref)
	if err := FlushOutbox(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	e.fake.mu.Lock()
	sha1, ok := e.fake.files["commons/kb/entries/"+ref+".md"]
	e.fake.mu.Unlock()
	if !ok {
		t.Fatal("not written after retry")
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM forge_outbox WHERE ref = $1`, ref).Scan(&n)
	if n != 0 {
		t.Fatal("row not deleted")
	}
	// Update path (existing file -> fetch sha -> PUT).
	Enqueue(ctx, testPool, "kb", ref, []byte("v2"))
	if err := FlushOutbox(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	e.fake.mu.Lock()
	sha2 := e.fake.files["commons/kb/entries/"+ref+".md"]
	e.fake.mu.Unlock()
	if sha2 == sha1 {
		t.Fatal("update did not happen")
	}
	// Unknown kind backs off instead of looping.
	Enqueue(ctx, testPool, "zzz", ref, []byte("x"))
	FlushOutbox(ctx, e.d)
	testPool.QueryRow(ctx, `SELECT attempts FROM forge_outbox WHERE kind = 'zzz' AND ref = $1`, ref).Scan(&attempts)
	if attempts != 1 {
		t.Fatalf("unknown kind attempts=%d", attempts)
	}
	testPool.Exec(ctx, `DELETE FROM forge_outbox WHERE ref = $1`, ref)
}

func TestOpsMatchHTTP(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	_, tok := e.register(t, "ops")
	vid, vtok := e.register(t, "voter")
	me, voter := e.ident(t, tok), e.ident(t, vtok)
	ops := Ops(e.d)
	for _, n := range []string{"t", "tg", "tp", "tc", "td", "tdrop", "tn", "ta", "tok", "tbad", "n", "ng", "np", "nd"} {
		if ops[n] == nil {
			t.Fatalf("op %s missing", n)
		}
		if _, ok := OpMeta[n]; !ok {
			t.Fatalf("OpMeta %s missing", n)
		}
	}
	if _, err := ops["tp"](ctx, nil, json.RawMessage(`{"title":"x"}`)); err != core.ErrAuth {
		t.Fatalf("anon tp: %v", err)
	}
	out, err := ops["tp"](ctx, me, json.RawMessage(`{"title":"via mcp","body":"b","tags":["mcp"],"space":"`+e.space+`"}`))
	if err != nil || !strings.HasPrefix(out, "#") {
		t.Fatalf("tp: %q %v", out, err)
	}
	n1 := parseHash(t, out)
	ns := itoa(n1)
	if out, err := ops["tc"](ctx, me, json.RawMessage(`{"n":"#`+ns+`"}`)); err != nil || !strings.HasPrefix(out, "ok until ") || !strings.HasSuffix(out, " fence=1") {
		t.Fatalf("tc: %q %v", out, err)
	}
	if out, err := ops["tn"](ctx, me, json.RawMessage(`{"n":`+ns+`,"text":"hello"}`)); err != nil || out != "ok" {
		t.Fatalf("tn: %q %v", out, err)
	}
	if out, err := ops["ta"](ctx, me, json.RawMessage(`{"n":`+ns+`,"text":"which branch?"}`)); err != nil || out != "ok" {
		t.Fatalf("ta: %q %v", out, err)
	}
	if _, err := ops["ta"](ctx, voter, json.RawMessage(`{"n":`+ns+`,"text":"not mine"}`)); err == nil || err.Error() != "err auth holder only" {
		t.Fatalf("ta by non-holder: %v", err)
	}
	out, err = ops["tg"](ctx, nil, json.RawMessage(`{"n":`+ns+`}`))
	_, hbody := e.do(t, "GET", "/v1/t/"+ns, "", nil)
	if err != nil || strings.TrimSpace(out) != hbody || !strings.Contains(hbody, " ask\n") || !strings.Contains(hbody, "\nask: which branch?") {
		t.Fatalf("tg mismatch:\n%s\n%s", out, hbody)
	}
	out, _ = ops["t"](ctx, nil, json.RawMessage(`{"s":"claimed","space":"`+e.space+`"}`))
	hbody = e.list(t, "s=claimed")
	if strings.TrimSpace(out) != hbody || hbody == "" {
		t.Fatalf("t mismatch: %q %q", out, hbody)
	}
	if _, err := ops["tg"](ctx, nil, json.RawMessage(`{"n":"x"}`)); err == nil {
		t.Fatal("bad n accepted")
	}
	// Votes: tok/tbad are the task vote ops (never ok/bad); self votes are refused like HTTP.
	if _, err := ops["tok"](ctx, me, json.RawMessage(`{"n":`+ns+`}`)); err == nil || err.Error() != "err auth no self vote" {
		t.Fatalf("self tok: %v", err)
	}
	if out, err := ops["tok"](ctx, voter, json.RawMessage(`{"n":`+ns+`,"note":"fine"}`)); err != nil || out != "ok" {
		t.Fatalf("tok: %q %v", out, err)
	}
	st, hbody := e.do(t, "POST", "/v1/t/"+ns+"/ok", vtok, map[string]any{"note": "again"})
	if _, err := ops["tok"](ctx, voter, json.RawMessage(`{"n":`+ns+`}`)); err == nil || st != 409 || err.Error() != hbody {
		t.Fatalf("dup vote op/http: %v / %d %s", err, st, hbody)
	}
	if _, err := ops["tbad"](ctx, voter, json.RawMessage(`{"n":`+ns+`,"why":"meh"}`)); err == nil || err.Error() != "err dup already voted" {
		t.Fatalf("tbad after tok: %v", err)
	}
	_ = vid
	if out, err := ops["tdrop"](ctx, me, json.RawMessage(`{"n":`+ns+`}`)); err != nil || out != "ok" {
		t.Fatalf("tdrop: %q %v", out, err)
	}
	if out, err := ops["td"](ctx, me, json.RawMessage(`{"n":`+ns+`,"text":"bye"}`)); err != nil || out != "ok" {
		t.Fatalf("td: %q %v", out, err)
	}
	if out, err := ops["np"](ctx, me, json.RawMessage(`{"name":"k","text":"v"}`)); err != nil || out != "ok rev=1" {
		t.Fatalf("np: %q %v", out, err)
	}
	if out, err := ops["ng"](ctx, nil, json.RawMessage(`{"owner":"`+me.ID+`","name":"k"}`)); err != nil || out != "v" {
		t.Fatalf("ng: %q %v", out, err)
	}
	if out, err := ops["ng"](ctx, nil, json.RawMessage(`{"name":"`+me.ID+`/k"}`)); err != nil || out != "v" {
		t.Fatalf("ng slash: %q %v", out, err)
	}
	if out, err := ops["n"](ctx, me, nil); err != nil || out != "k" {
		t.Fatalf("n: %q %v", out, err)
	}
	if out, err := ops["nd"](ctx, me, json.RawMessage(`{"name":"k"}`)); err != nil || out != "ok" {
		t.Fatalf("nd: %q %v", out, err)
	}
	if _, err := ops["ng"](ctx, nil, json.RawMessage(`{"owner":"`+me.ID+`","name":"k"}`)); err != core.ErrNotFound {
		t.Fatalf("ng after delete: %v", err)
	}
}

func TestPurgeAndHide(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	id, tok := e.register(t, "victim")
	_, otok := e.register(t, "bystander")
	n1 := e.create(t, tok, "victim task")
	n2 := e.create(t, otok, "other task")
	for _, c := range []struct {
		m, p, tk string
		body     any
	}{
		{"POST", fmt.Sprintf("/v1/t/%d/claim", n2), tok, nil},
		{"PUT", "/v1/n/secret", tok, "s"},
	} {
		if st, body := e.do(t, c.m, c.p, c.tk, c.body); st/100 != 2 {
			t.Fatalf("%s %s: %d %s", c.m, c.p, st, body)
		}
	}
	e.flush(t)
	// Hide task 2 via the report hook: state hidden, claim released, mirror closed + labelled.
	if err := HideTask(ctx, e.d, int(n2)); err != nil {
		t.Fatal(err)
	}
	e.flush(t)
	if is := e.issueOf(t, n2); is.State != "closed" || !is.HasLabel("hidden") || is.HasLabel("claimed") {
		t.Fatalf("hidden issue: %+v", is)
	}
	if st, _ := e.do(t, "GET", fmt.Sprintf("/v1/t/%d", n2), "", nil); st != 404 {
		t.Fatal("hidden task readable")
	}
	if body := e.list(t, "s=done"); body != "" {
		t.Fatalf("hidden task listed: %q", body)
	}
	if body := e.list(t, "s=claimed"); body != "" {
		t.Fatalf("hidden task still claimed: %q", body)
	}
	// Report target registry: exists / hide / restore.
	tg, ok := e.d.Target("t")
	if !ok || tg.Exists(ctx, testPool, itoa(n1)) != nil || tg.Exists(ctx, testPool, "999999999") != core.ErrNotFound {
		t.Fatal("target t")
	}
	if err := tg.Restore(ctx, testPool, itoa(n2)); err != nil {
		t.Fatal(err)
	}
	if st, _ := e.do(t, "GET", fmt.Sprintf("/v1/t/%d", n2), "", nil); st != 200 {
		t.Fatal("restored task unreadable")
	}
	// Purge the victim: rows go, the mirror issue is closed (the payload carries its number).
	is1 := e.issueOf(t, n1)
	if st, body := e.do(t, "POST", "/admin/purge", "adm-token", map[string]any{"id": id}); st != 200 {
		t.Fatalf("purge: %d %s", st, body)
	}
	e.flush(t)
	if is := e.fake.getIssue(is1.Number); is.State != "closed" {
		t.Fatal("victim task not closed")
	}
	e.fake.mu.Lock()
	_, ok = e.fake.wiki["commons/notes/"+id+"--secret"]
	e.fake.mu.Unlock()
	if ok {
		t.Fatal("wiki page not deleted")
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM tasks WHERE id = $1`, id).Scan(&n)
	if n != 0 {
		t.Fatal("tasks ledger left")
	}
	testPool.QueryRow(ctx, `SELECT count(*) FROM task_claims WHERE id = $1`, id).Scan(&n)
	if n != 0 {
		t.Fatal("claims left")
	}
	testPool.QueryRow(ctx, `SELECT count(*) FROM notes WHERE owner = $1`, id).Scan(&n)
	if n != 0 {
		t.Fatal("notes left")
	}
	testPool.QueryRow(ctx, `SELECT count(*) FROM notes_content WHERE owner = $1`, id).Scan(&n)
	if n != 0 {
		t.Fatal("notes content left")
	}
}

func TestOutboxDeleteAndMarkdown(t *testing.T) {
	e := newEnv(t, false)
	ctx := context.Background()
	ref := core.NewID('k')
	key := "commons/kb/entries/" + ref + ".md"
	// Non-empty payload: wrapped into "# <title>" + fenced text block.
	text := ref + " fix ok0 bad0 2026-10-06 by a1234567\ntitle: Hello ``` world\nsymptom: boom\n"
	if err := Enqueue(ctx, testPool, "kb", ref, []byte(text)); err != nil {
		t.Fatal(err)
	}
	if err := FlushOutbox(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	e.fake.mu.Lock()
	b64, ok := e.fake.fileData[key]
	e.fake.mu.Unlock()
	if !ok {
		t.Fatal("not written")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	md := string(raw)
	if !strings.HasPrefix(md, "# Hello ``` world\n\n````text\n"+ref+" fix") || !strings.HasSuffix(md, "symptom: boom\n````\n") {
		t.Fatalf("markdown:\n%s", md)
	}
	// Empty payload: delete via contents API with sha.
	if err := Enqueue(ctx, testPool, "kb", ref, nil); err != nil {
		t.Fatal(err)
	}
	if err := FlushOutbox(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	e.fake.mu.Lock()
	_, ok = e.fake.files[key]
	e.fake.mu.Unlock()
	if ok {
		t.Fatal("not deleted")
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM forge_outbox WHERE ref = $1`, ref).Scan(&n)
	if n != 0 {
		t.Fatal("delete row not consumed")
	}
	// Deleting a missing file (404) is done, not an error.
	if err := Enqueue(ctx, testPool, "kb", ref, []byte{}); err != nil {
		t.Fatal(err)
	}
	if err := FlushOutbox(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	testPool.QueryRow(ctx, `SELECT count(*) FROM forge_outbox WHERE ref = $1`, ref).Scan(&n)
	if n != 0 {
		t.Fatal("404 delete row not consumed")
	}
	// Markdown without a title line falls back to the id.
	if got := string(kbMarkdown("kabcdef2", []byte("x\n"))); got != "# kabcdef2\n\n```text\nx\n```\n" {
		t.Fatalf("fallback: %q", got)
	}
}
