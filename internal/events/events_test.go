package events

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
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
)

var pool *pgxpool.Pool

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
		pool = p
		code := m.Run()
		p.Close()
		os.Exit(code)
	}
	p, cleanup := testdb.Open("events", core.Migrate)
	if p == nil {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping events DB tests")
		os.Exit(0)
	}
	pool = p
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type env struct {
	d   *core.Deps
	srv *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &env{d: d, srv: srv}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

// req sends a request (random client IP so anonymous limits never interfere).
func (e *env) req(method, path, token, body string, hdr ...string) (int, string, http.Header, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rd)
	r.Header.Set("CF-Connecting-IP", randIP())
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		return 0, "", nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), res.Header, nil
}

func (e *env) do(t *testing.T, method, path, token, body string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	st, b, h, err := e.req(method, path, token, body, hdr...)
	if err != nil {
		t.Fatal(err)
	}
	return st, b, h
}

// mkRoot inserts a root identity (no PoW needed) and returns (id, token).
func mkRoot(t *testing.T) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := pool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, reg_ip)
		VALUES ($1, 'r', NULL, $1, $2, 100, $3)`, id, h, randIP()); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

// mkSub inserts a subkey of root; scopes != nil makes it a scoped token.
func mkSub(t *testing.T, root string, scopes []string) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	class := "full"
	if scopes != nil {
		class = "scoped"
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, scopes, token_class)
		VALUES ($1, 's', $2, $2, $3, 0, $4, $5)`, id, root, h, scopes, class); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func head(t *testing.T) int64 {
	t.Helper()
	h, err := Head(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// emit appends an event through core.Event (autocommit, so the row is visible before the wake).
func emit(t *testing.T, kind, ref, scope, title string) int64 {
	t.Helper()
	if err := core.Event(context.Background(), pool, kind, ref, scope, title); err != nil {
		t.Fatal(err)
	}
	return head(t)
}

func ident(t *testing.T, e *env, tok string) *core.Ident {
	t.Helper()
	id, err := e.d.LookupToken(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCursorAndKinds(t *testing.T) {
	e := newEnv(t)
	h0 := head(t)
	s1 := emit(t, "kb", "kaaaaaa", "", "fix: python requests timeout")
	s2 := emit(t, "t", "42", "", "task title")
	s3 := emit(t, "kb", "kbbbbbb", "", "note: go modules\twith control\x01chars")
	want := fmt.Sprintf("%d kb kaaaaaa fix: python requests timeout\n%d kb kbbbbbb note: go modules with control chars\nnext=%d\n", s1, s3, s3)
	st, body, hdr := e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d&kinds=kb", h0), "", "")
	if st != 200 || body != want {
		t.Fatalf("kinds=kb: %d %q want %q", st, body, want)
	}
	if hdr.Get("X-Next") != fmt.Sprintf("GET /v1/ev?after=%d&kinds=kb", s3) || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: X-Next %q Cache-Control %q", hdr.Get("X-Next"), hdr.Get("Cache-Control"))
	}
	// Acceptance shape: after=0&kinds=kb is "<seq> kb k… <title>" lines then next=<seq>, nothing else.
	_, body, _ = e.do(t, "GET", "/v1/ev?after=0&kinds=kb", "", "")
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	rowRe := regexp.MustCompile(`^\d+ kb k[a-z2-7]{6} .+$`)
	for _, l := range lines[:len(lines)-1] {
		if !rowRe.MatchString(l) {
			t.Fatalf("row line %q", l)
		}
	}
	if !regexp.MustCompile(`^next=\d+$`).MatchString(lines[len(lines)-1]) || len(lines) < 3 {
		t.Fatalf("tail: %q", body)
	}
	// Cursor moves forward; kinds filters; k limits and sets next to the last returned row.
	if _, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d", s1), "", ""); body != fmt.Sprintf("%d t 42 task title\n%s", s2, strings.Join(strings.Split(want, "\n")[1:], "\n")) {
		t.Fatalf("after=s1: %q", body)
	}
	if _, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d&kinds=t", h0), "", ""); body != fmt.Sprintf("%d t 42 task title\nnext=%d\n", s2, s2) {
		t.Fatalf("kinds=t: %q", body)
	}
	if _, body, hdr = e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d&k=1", h0), "", ""); body != fmt.Sprintf("%d kb kaaaaaa fix: python requests timeout\nnext=%d\n", s1, s1) || hdr.Get("X-Next") != fmt.Sprintf("GET /v1/ev?after=%d", s1) {
		t.Fatalf("k=1: %q %q", body, hdr.Get("X-Next"))
	}
	// No cursor: the newest k rows, next = head.
	if _, body, _ = e.do(t, "GET", "/v1/ev?k=2", "", ""); body != fmt.Sprintf("%d t 42 task title\n%d kb kbbbbbb note: go modules with control chars\nnext=%d\n", s2, s3, s3) {
		t.Fatalf("latest k=2: %q", body)
	}
	// JSON.
	st, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d&kinds=kb&f=json", h0), "", "")
	var j struct {
		Rows []struct {
			Seq   int64  `json:"seq"`
			Kind  string `json:"kind"`
			Ref   string `json:"ref"`
			Title string `json:"title"`
		} `json:"rows"`
		Next int64 `json:"next_seq"`
	}
	if err := json.Unmarshal([]byte(body), &j); err != nil || st != 200 || len(j.Rows) != 2 || j.Rows[0].Seq != s1 || j.Rows[1].Ref != "kbbbbbb" || j.Next != s3 {
		t.Fatalf("json: %d %s %v", st, body, err)
	}
	// Budget truncation keeps whole lines and moves the cursor to the last returned row.
	if _, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d&b=20", h0), "", ""); body != fmt.Sprintf("%d kb kaaaaaa fix: python requests timeout\nnext=%d\n", s1, s1) {
		t.Fatalf("budget: %q", body)
	}
	// Bad parameters.
	for _, q := range []string{"after=x", "after=-1", "wait=90", "k=0", "k=201", "kinds=KB!", "w=zzz"} {
		if st, _, _ := e.do(t, "GET", "/v1/ev?"+q, "", ""); st != 400 && !(q == "w=zzz" && st == 404) {
			t.Fatalf("%s: %d", q, st)
		}
	}
	// The MCP op renders the same text; kinds as a list or a comma string.
	ops := Ops(e.d)
	for _, a := range []string{fmt.Sprintf(`{"after":%d,"kinds":"kb"}`, h0), fmt.Sprintf(`{"after":%d,"kinds":["kb"]}`, h0)} {
		if out, err := ops["ev"](context.Background(), nil, json.RawMessage(a)); err != nil || out != want {
			t.Fatalf("op ev %s: %q %v", a, out, err)
		}
	}
	if _, err := ops["ev"](context.Background(), nil, json.RawMessage(`{"wait":100}`)); err == nil {
		t.Fatal("op ev wait=100 accepted")
	}
}

func TestLongPollWake(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	h0 := head(t)
	type res struct {
		st   int
		body string
		dur  time.Duration
		err  error
	}
	poll := func(path string) chan res {
		ch := make(chan res, 1)
		go func() {
			start := time.Now()
			st, body, _, err := e.req("GET", path, tok, "")
			ch <- res{st, body, time.Since(start), err}
		}()
		return ch
	}
	wait := func(ch chan res) res {
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatal(r.err)
			}
			return r
		case <-time.After(15 * time.Second):
			t.Fatal("long poll never returned")
		}
		return res{}
	}
	// Woken by core.Event (autocommit): the row arrives well before the 10 s wait ends.
	ch := poll(fmt.Sprintf("/v1/ev?after=%d&wait=10", h0))
	time.Sleep(300 * time.Millisecond)
	seq := emit(t, "kb", "kcccccc", "", "woken")
	r := wait(ch)
	if r.st != 200 || r.body != fmt.Sprintf("%d kb kcccccc woken\nnext=%d\n", seq, seq) || r.dur < 250*time.Millisecond || r.dur > 4*time.Second {
		t.Fatalf("wake: %d %q in %v", r.st, r.body, r.dur)
	}
	// A kinds filter ignores unrelated wakes and still catches its row.
	ch = poll(fmt.Sprintf("/v1/ev?after=%d&kinds=t&wait=10", seq))
	time.Sleep(200 * time.Millisecond)
	emit(t, "kb", "kdddddd", "", "other kind")
	time.Sleep(200 * time.Millisecond)
	ts := emit(t, "t", "7", "", "the task")
	if r = wait(ch); r.body != fmt.Sprintf("%d t 7 the task\nnext=%d\n", ts, ts) || r.dur > 4*time.Second {
		t.Fatalf("filtered wake: %q in %v", r.body, r.dur)
	}
	// Event inside a tx: the wake precedes the commit; the settle re-read delivers it anyway.
	ch = poll(fmt.Sprintf("/v1/ev?after=%d&wait=10", ts))
	time.Sleep(200 * time.Millisecond)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Event(ctx, tx, "kb", "keeeeee", "", "committed late"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	late := head(t)
	if r = wait(ch); r.body != fmt.Sprintf("%d kb keeeeee committed late\nnext=%d\n", late, late) || r.dur > 4*time.Second {
		t.Fatalf("late commit: %q in %v", r.body, r.dur)
	}
	// Timeout: nothing matches -> next=<head> after about one second, no retry hint.
	r = wait(poll(fmt.Sprintf("/v1/ev?after=%d&kinds=zz&wait=1", late)))
	if r.body != fmt.Sprintf("next=%d\n", late) || r.dur < 900*time.Millisecond || r.dur > 4*time.Second {
		t.Fatalf("timeout: %q in %v", r.body, r.dur)
	}
	// Anonymous wait is 0: immediate reply with retry=5.
	start := time.Now()
	st, body, _ := e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d&wait=5", late), "", "")
	if st != 200 || body != fmt.Sprintf("next=%d retry=5\n", late) || time.Since(start) > time.Second {
		t.Fatalf("anonymous wait: %d %q", st, body)
	}
	// The per-root waiter slots are full: immediate reply with retry=5; JSON carries retry_s.
	for i := 0; i < core.MaxWaitersPerRoot; i++ {
		rel, ok := e.d.Waiters.Acquire(root, "")
		if !ok {
			t.Fatal("acquire")
		}
		defer rel()
	}
	start = time.Now()
	if _, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d&wait=5", late), tok, ""); body != fmt.Sprintf("next=%d retry=5\n", late) || time.Since(start) > time.Second {
		t.Fatalf("waiters full: %q", body)
	}
	if _, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d&wait=5&f=json", late), tok, ""); !strings.Contains(body, `"retry_s":5`) {
		t.Fatalf("json retry: %q", body)
	}
}

func TestRootScopedIsolation(t *testing.T) {
	e := newEnv(t)
	a, tokA := mkRoot(t)
	_, subA := mkSub(t, a, nil)
	b, tokB := mkRoot(t)
	h0 := head(t)
	pub := emit(t, "kb", "kffffff", "", "public row")
	privA := emit(t, "j", "jaaaaaa", a, "job done for a")
	privB := emit(t, "mail", "maaaaaa", b, "mail for b")
	get := func(tok string, q string) string {
		t.Helper()
		st, body, _ := e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d%s", h0, q), tok, "")
		if st != 200 {
			t.Fatalf("%d %s", st, body)
		}
		return body
	}
	// The cursor stops at the last row the caller may see: invisible rows are never counted.
	pubLine := fmt.Sprintf("%d kb kffffff public row\n", pub)
	if got := get("", ""); got != pubLine+fmt.Sprintf("next=%d\n", pub) {
		t.Fatalf("anonymous: %q", got)
	}
	wantA := pubLine + fmt.Sprintf("%d j jaaaaaa job done for a\nnext=%d\n", privA, privA)
	if got := get(tokA, ""); got != wantA {
		t.Fatalf("root a: %q", got)
	}
	if got := get(subA, ""); got != wantA {
		t.Fatalf("subkey of a: %q", got)
	}
	if got := get(tokB, ""); got != pubLine+fmt.Sprintf("%d mail maaaaaa mail for b\nnext=%d\n", privB, privB) {
		t.Fatalf("root b: %q", got)
	}
	// A kinds filter never leaks a scoped row to anonymous or foreign callers.
	if got := get("", "&kinds=j"); got != fmt.Sprintf("next=%d\n", h0) {
		t.Fatalf("anonymous kinds=j: %q", got)
	}
	if got := get(tokB, "&kinds=j"); got != fmt.Sprintf("next=%d\n", h0) {
		t.Fatalf("b kinds=j: %q", got)
	}
	// The op with an identity sees the same rows; Public never returns scoped rows.
	if out, err := Ops(e.d)["ev"](context.Background(), ident(t, e, tokA), json.RawMessage(fmt.Sprintf(`{"after":%d}`, h0))); err != nil || out != wantA {
		t.Fatalf("op ev as a: %q %v", out, err)
	}
	rows, err := Public(context.Background(), pool, nil, 50)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Scoped || r.Seq == privA || r.Seq == privB {
			t.Fatalf("Public leaked %+v", r)
		}
	}
	if len(rows) == 0 || rows[0].Seq < pub {
		t.Fatalf("Public newest first: %+v", rows)
	}
}

func TestWatchesCRUDAndFilter(t *testing.T) {
	e := newEnv(t)
	a, tokA := mkRoot(t)
	_, tokB := mkRoot(t)
	ctx := context.Background()
	st, body, _ := e.do(t, "POST", "/v1/watch", tokA, `{"kinds":["KB"],"tags":["Python"],"q":"timeout"}`, "Content-Type", "application/json")
	lines := strings.Split(strings.TrimSpace(body), "\n")
	m := regexp.MustCompile(`^ok (w[a-z2-7]{6}) kinds=kb tags=python$`).FindStringSubmatch(lines[0])
	if st != 201 || m == nil || len(lines) != 3 || lines[1] != "q: timeout" {
		t.Fatalf("create: %d %q", st, body)
	}
	wid := m[1]
	if lines[2] != "next: GET /v1/ev?w="+wid+" | DELETE /v1/watch/"+wid {
		t.Fatalf("tail: %q", lines[2])
	}
	h0 := head(t)
	m1 := emit(t, "kb", "kgggggg", "", "Python requests TIMEOUT after upgrade")
	emit(t, "kb", "khhhhhh", "", "go modules timeout")   // no tag word
	emit(t, "t", "9", "", "python timeout task")         // wrong kind
	emit(t, "kb", "kiiiiii", "", "python asyncio notes") // no query word
	m2 := emit(t, "kb", "kjjjjjj", "", "timeout: python again")
	st, body, hdr := e.do(t, "GET", fmt.Sprintf("/v1/ev?w=%s&after=%d", wid, h0), tokA, "")
	want := fmt.Sprintf("%d kb kgggggg Python requests TIMEOUT after upgrade\n%d kb kjjjjjj timeout: python again\nnext=%d\n", m1, m2, m2)
	if st != 200 || body != want || hdr.Get("X-Next") != fmt.Sprintf("GET /v1/ev?after=%d&w=%s", m2, wid) {
		t.Fatalf("filtered: %d %q %q", st, body, hdr.Get("X-Next"))
	}
	// Sparse filters still advance the cursor past examined non-matching rows.
	if _, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?w=%s&after=%d", wid, m1), tokA, ""); body != fmt.Sprintf("%d kb kjjjjjj timeout: python again\nnext=%d\n", m2, m2) {
		t.Fatalf("filtered after m1: %q", body)
	}
	if _, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?w=%s&after=%d&k=1", wid, h0), tokA, ""); body != fmt.Sprintf("%d kb kgggggg Python requests TIMEOUT after upgrade\nnext=%d\n", m1, m1) {
		t.Fatalf("filtered k=1: %q", body)
	}
	// kinds narrows a watch; a disjoint set is a client error.
	if _, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?w=%s&kinds=kb,t&after=%d", wid, h0), tokA, ""); body != want {
		t.Fatalf("narrowed: %q", body)
	}
	if st, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?w=%s&kinds=t&after=%d", wid, h0), tokA, ""); st != 400 || !strings.HasPrefix(body, "err bad kinds outside") {
		t.Fatalf("disjoint: %d %q", st, body)
	}
	// Foreign and anonymous use of a watch.
	if st, body, _ = e.do(t, "GET", "/v1/ev?w="+wid, tokB, ""); st != 404 || !strings.HasPrefix(body, "err notfound") {
		t.Fatalf("foreign watch: %d %q", st, body)
	}
	if st, _, _ = e.do(t, "GET", "/v1/ev?w="+wid, "", ""); st != 401 {
		t.Fatalf("anonymous watch: %d", st)
	}
	// Read back: list and get.
	st, body, _ = e.do(t, "GET", "/v1/watch", tokA, "")
	lines = strings.Split(strings.TrimSpace(body), "\n")
	if st != 200 || lines[0] != "watches n=1/20" || lines[1] != wid+" "+core.Date(time.Now())+" kb python timeout" {
		t.Fatalf("list: %d %q", st, body)
	}
	st, body, _ = e.do(t, "GET", "/v1/watch/"+wid, tokA, "")
	if st != 200 || !strings.HasPrefix(body, "watch "+wid+" kinds=kb tags=python created="+core.Date(time.Now())+"\nq: timeout\n") {
		t.Fatalf("get: %d %q", st, body)
	}
	if st, _, _ = e.do(t, "GET", "/v1/watch/"+wid, tokB, ""); st != 404 {
		t.Fatalf("foreign get: %d", st)
	}
	// Validation: grammar, line injection, size, empty filters, unknown fields.
	for _, in := range []string{`{"kinds":["KB!"]}`, `{"tags":["-x"]}`, `{"q":"a\nnext: GET /x"}`, `{"q":"` + strings.Repeat("x", 121) + `"}`, `{}`, `{"q":"!!!"}`, `{"zzz":1}`} {
		if st, body, _ = e.do(t, "POST", "/v1/watch", tokA, in, "Content-Type", "application/json"); st != 400 {
			t.Fatalf("%s: %d %q", in, st, body)
		}
	}
	// A scoped token with ev:r reads but cannot write watches.
	_, scoped := mkSub(t, a, []string{"ev:r"})
	if st, _, _ = e.do(t, "GET", "/v1/ev?after=0", scoped, ""); st != 200 {
		t.Fatalf("scoped ev: %d", st)
	}
	if st, _, _ = e.do(t, "GET", "/v1/watch", scoped, ""); st != 200 {
		t.Fatalf("scoped list: %d", st)
	}
	if st, body, _ = e.do(t, "POST", "/v1/watch", scoped, `{"kinds":["kb"]}`, "Content-Type", "application/json"); st != 403 || !strings.HasPrefix(body, "err scope w") {
		t.Fatalf("scoped create: %d %q", st, body)
	}
	// MCP ops.
	ops := Ops(e.d)
	out, err := ops["watch"](ctx, ident(t, e, tokA), json.RawMessage(`{"kinds":["t"],"q":"deploy  failed"}`))
	if err != nil || !regexp.MustCompile(`^ok w[a-z2-7]{6} kinds=t\nq: deploy  failed$`).MatchString(out) {
		t.Fatalf("op watch: %q %v", out, err)
	}
	w2 := strings.Fields(out)[1]
	if _, err := ops["watch"](ctx, nil, json.RawMessage(`{"kinds":["t"]}`)); err != core.ErrAuth {
		t.Fatalf("anonymous op watch: %v", err)
	}
	if out, err := ops["unwatch"](ctx, ident(t, e, tokB), json.RawMessage(`{"id":"`+w2+`"}`)); err != core.ErrNotFound {
		t.Fatalf("foreign unwatch: %q %v", out, err)
	}
	if out, err := ops["unwatch"](ctx, ident(t, e, tokA), json.RawMessage(`{"id":"`+w2+`"}`)); err != nil || out != "ok" {
		t.Fatalf("unwatch: %q %v", out, err)
	}
	// Delete: foreign is not found, owner ok, second time not found.
	if st, _, _ = e.do(t, "DELETE", "/v1/watch/"+wid, tokB, ""); st != 404 {
		t.Fatalf("foreign delete: %d", st)
	}
	if st, body, _ = e.do(t, "DELETE", "/v1/watch/"+wid, tokA, ""); st != 200 || !strings.HasPrefix(body, "ok\n") {
		t.Fatalf("delete: %d %q", st, body)
	}
	if st, _, _ = e.do(t, "DELETE", "/v1/watch/"+wid, tokA, ""); st != 404 {
		t.Fatalf("second delete: %d", st)
	}
	if st, _, _ = e.do(t, "GET", "/v1/ev?w="+wid, tokA, ""); st != 404 {
		t.Fatalf("deleted watch read: %d", st)
	}
	// Live cap: 20 per root (a fresh root keeps the limiter out of the way).
	c, tokC := mkRoot(t)
	idC := ident(t, e, tokC)
	for i := 0; i < MaxWatches; i++ {
		if _, err := ops["watch"](ctx, idC, json.RawMessage(fmt.Sprintf(`{"kinds":["k%d"]}`, i))); err != nil {
			t.Fatalf("watch %d: %v", i, err)
		}
	}
	if _, err := ops["watch"](ctx, idC, json.RawMessage(`{"kinds":["kb"]}`)); err == nil || !strings.HasPrefix(err.Error(), "err quota") {
		t.Fatalf("21st watch: %v", err)
	}
	// Purge hook removes the root's watches.
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM watches WHERE root = $1`, c).Scan(&n); err != nil || n != MaxWatches {
		t.Fatalf("count: %d %v", n, err)
	}
	// core.Purge needs the econ migration (0042, another package); on a schema without it only
	// the hook registration can be exercised through it, so a failure there is logged, not fatal.
	if _, err := e.d.Purge(ctx, c); err != nil {
		t.Logf("purge unavailable on this schema: %v", err)
	} else if err := pool.QueryRow(ctx, `SELECT count(*) FROM watches WHERE root = $1`, c).Scan(&n); err != nil || n != 0 {
		t.Fatalf("after purge: %d %v", n, err)
	}
}

func TestCursorPastHeadEmpty(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t)
	emit(t, "kb", "kkkkkkk", "", "something")
	h := head(t)
	st, body, hdr := e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d", h+1000), "", "")
	if st != 200 || body != fmt.Sprintf("next=%d\n", h) || hdr.Get("X-Next") != fmt.Sprintf("GET /v1/ev?after=%d", h) {
		t.Fatalf("past head: %d %q %q", st, body, hdr.Get("X-Next"))
	}
	if _, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d", h), "", ""); body != fmt.Sprintf("next=%d\n", h) {
		t.Fatalf("at head: %q", body)
	}
	// A clamped cursor long-polls normally and wakes on the next row.
	done := make(chan string, 1)
	go func() {
		_, body, _, _ := e.req("GET", fmt.Sprintf("/v1/ev?after=%d&wait=10", h+1000), tok, "")
		done <- body
	}()
	time.Sleep(300 * time.Millisecond)
	seq := emit(t, "kb", "kllllll", "", "after the clamp")
	select {
	case body := <-done:
		if body != fmt.Sprintf("%d kb kllllll after the clamp\nnext=%d\n", seq, seq) {
			t.Fatalf("clamped wait: %q", body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("clamped long poll never returned")
	}
	// JSON shape with no rows.
	if _, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/ev?after=%d&f=json", seq+5), "", ""); body != fmt.Sprintf("{\"rows\":[],\"next_seq\":%d}\n", seq) {
		t.Fatalf("json empty: %q", body)
	}
}

func TestFeedSourceRegistered(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	fn := e.d.Feeds()["ch"]
	if fn == nil {
		t.Fatal("feed source ch not registered")
	}
	a, _ := mkRoot(t)
	s := emit(t, "kb", "kmmmmmm", "", "feed title")
	emit(t, "j", "jbbbbbb", a, "secret job")
	tn := emit(t, "t", "12", "", "")
	items, err := fn(ctx, "", 50)
	if err != nil || len(items) < 2 {
		t.Fatalf("feed: %d items %v", len(items), err)
	}
	if it := items[0]; it.ID != fmt.Sprintf("ev/%d", tn) || it.URL != "/t/12" || it.Title != "t 12" || it.Summary != "t 12:" || it.Updated.IsZero() || it.Tags[0] != "t" {
		t.Fatalf("newest item: %+v", it)
	}
	if it := items[1]; it.ID != fmt.Sprintf("ev/%d", s) || it.URL != "/k/kmmmmmm" || it.Title != "feed title" || it.Summary != "kb kmmmmmm: feed title" {
		t.Fatalf("kb item: %+v", it)
	}
	for _, it := range items {
		if it.Summary == "" || strings.Contains(it.Title, "secret") || it.Tags[0] == "j" {
			t.Fatalf("feed leaked or empty: %+v", it)
		}
	}
	// Sub-feed = kinds filter; invalid kinds are refused.
	items, err = fn(ctx, "kb", 5)
	if err != nil || len(items) == 0 || items[0].ID != fmt.Sprintf("ev/%d", s) {
		t.Fatalf("sub kb: %+v %v", items, err)
	}
	for _, it := range items {
		if it.Tags[0] != "kb" {
			t.Fatalf("sub kb item: %+v", it)
		}
	}
	if _, err := fn(ctx, "kb,BAD!", 5); err == nil {
		t.Fatal("bad sub accepted")
	}
	// Public: kinds, newest first, n clamp.
	rows, err := Public(ctx, pool, []string{"kb"}, 1)
	if err != nil || len(rows) != 1 || rows[0].Seq != s {
		t.Fatalf("Public: %+v %v", rows, err)
	}
	// Match: kinds, tags (word or ref), q words.
	r := Row{Kind: "kb", Ref: "kmmmmmm", Title: "Fix: Python-requests TIMEOUT"}
	for _, c := range []struct {
		kinds, tags []string
		q           string
		want        bool
	}{
		{nil, nil, "", true}, {[]string{"t"}, nil, "", false}, {[]string{"kb", "t"}, nil, "", true},
		{nil, []string{"python"}, "", true}, {nil, []string{"python-requests"}, "", true}, {nil, []string{"kmmmmmm"}, "", true},
		{nil, []string{"go"}, "", false}, {nil, nil, "timeout fix", true}, {nil, nil, "timeout go", false},
	} {
		if got := Match(c.kinds, c.tags, c.q, r); got != c.want {
			t.Fatalf("Match(%v,%v,%q) = %v", c.kinds, c.tags, c.q, got)
		}
	}
}

func TestMetaAndOpenAPI(t *testing.T) {
	e := newEnv(t)
	if !json.Valid(openAPI) {
		t.Fatal("openAPI fragment is not valid JSON")
	}
	ops := Ops(e.d)
	for name := range ops {
		if _, ok := OpMeta[name]; !ok {
			t.Fatalf("op %s has no OpMeta", name)
		}
	}
	for name := range OpMeta {
		if _, ok := ops[name]; !ok {
			t.Fatalf("OpMeta %s has no op", name)
		}
	}
	if len(Help) > 800 {
		t.Fatalf("Help is %d bytes (> 200 tokens)", len(Help))
	}
	for _, pat := range []string{"GET /v1/ev", "POST /v1/watch", "GET /v1/watch", "GET /v1/watch/{id}", "DELETE /v1/watch/{id}"} {
		if _, ok := e.d.ScopeOf(pat); !ok {
			t.Fatalf("no scope for %s", pat)
		}
	}
	if e.d.CostOf("GET /v1/ev") != 0.2 {
		t.Fatalf("cost %v", e.d.CostOf("GET /v1/ev"))
	}
	found := false
	for _, c := range e.d.StorageClasses() {
		if c.Name == "events" && c.Cap == MaxBytes {
			found = true
		}
	}
	if !found {
		t.Fatal("storage class events missing")
	}
	// Export-me writes the root's watches as JSONL.
	_, tok := mkRoot(t)
	if _, err := ops["watch"](context.Background(), ident(t, e, tok), json.RawMessage(`{"kinds":["kb"],"q":"x y"}`)); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := e.d.Export(context.Background(), ident(t, e, tok).Root, &b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"kind":"watch"`) || !strings.Contains(b.String(), `"q":"x y"`) {
		t.Fatalf("export: %q", b.String())
	}
}

func TestRetention(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := pool.Exec(ctx, `INSERT INTO events (at, kind, ref, title) VALUES (now() - interval '8 days', 'kb', 'knnnnnn', 'old row')`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO events (at, kind, ref, title) VALUES (now() - interval '6 days', 'kb', 'knnnnnn', 'kept row')`); err != nil {
		t.Fatal(err)
	}
	n, err := Retain(ctx, pool, MaxRows)
	if err != nil || n < 3 {
		t.Fatalf("Retain: %d %v", n, err)
	}
	var old, kept int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE title = 'old row'), count(*) FILTER (WHERE title = 'kept row') FROM events`).Scan(&old, &kept); err != nil || old != 0 || kept != 1 {
		t.Fatalf("after age retention: old=%d kept=%d %v", old, kept, err)
	}
	// Row cap keeps the newest rows only.
	for i := 0; i < 10; i++ {
		emit(t, "kb", "koooooo", "", fmt.Sprintf("row %d", i))
	}
	h := head(t)
	if _, err := Retain(ctx, pool, 5); err != nil {
		t.Fatal(err)
	}
	var cnt int
	var minSeq int64
	if err := pool.QueryRow(ctx, `SELECT count(*), min(seq) FROM events`).Scan(&cnt, &minSeq); err != nil || cnt != 5 || minSeq != h-4 {
		t.Fatalf("after row cap: count=%d min=%d head=%d %v", cnt, minSeq, h, err)
	}
	// The janitor task is registered and runs without error.
	e.d.Janitor.RunOnce(ctx)
	if got := head(t); got != h {
		t.Fatalf("janitor changed head: %d -> %d", h, got)
	}
}
