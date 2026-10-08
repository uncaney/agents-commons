package taskdag

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/testdb"
)

var (
	testPool *pgxpool.Pool
	levels   sync.Map
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	var cleanup func()
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
	} else if pool, done := testdb.Open("taskdag", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL unset: skipping taskdag DB tests")
		os.Exit(0)
	}
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int {
		v, _ := levels.Load(root)
		n, _ := v.(int)
		return n
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	s   *Service
	srv *httptest.Server
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	forge.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, s: svc(d), srv: srv}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

func (e *tenv) do(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rd)
	r.Header.Set("CF-Connecting-IP", randIP())
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimRight(string(b), "\n")
}

func mkRoot(t *testing.T, rep int) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, earned, reg_ip, rep, created, verified_noncompute)
		VALUES ($1, 'r', NULL, $1, $2, 100, 100, $3, $4, now() - interval '5 days', 1)`, id, h, randIP(), rep); err != nil {
		t.Fatal(err)
	}
	lvl := 0
	switch {
	case rep >= 5:
		lvl = 2
	case rep >= 1:
		lvl = 1
	}
	levels.Store(id, lvl)
	return id, tok
}

func (e *tenv) ident(t *testing.T, tok string) *core.Ident {
	t.Helper()
	id, err := e.d.LookupToken(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *tenv) task(t *testing.T, tok, title string) int64 {
	t.Helper()
	n, err := forge.CreateTask(context.Background(), e.d, e.ident(t, tok), forge.TaskInput{Title: title})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *tenv) markDone(t *testing.T, n int64) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE tasks SET state = 'done', closed_at = now() WHERE n = $1`, n); err != nil {
		t.Fatal(err)
	}
}

func (e *tenv) janitor(t *testing.T) {
	t.Helper()
	if err := e.s.janitor(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func (e *tenv) needs(t *testing.T, tok string, n int64, add, del []int64) error {
	return e.s.Needs(context.Background(), e.ident(t, tok), n, add, del)
}

func blocked(t *testing.T, n int64) bool {
	t.Helper()
	b, err := Blocked(context.Background(), testPool, n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noteTexts(t *testing.T, n int64) []string {
	t.Helper()
	rows, err := testPool.Query(context.Background(), `SELECT text FROM task_notes WHERE n = $1 ORDER BY id`, n)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func hasNote(t *testing.T, n int64, want string) bool {
	for _, s := range noteTexts(t, n) {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// --- tests ---

func TestNeedsCycleRefused(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t, 5)
	a := e.task(t, tok, "A")
	b := e.task(t, tok, "B")
	// A needs B: fine.
	if err := e.needs(t, tok, a, []int64{b}, nil); err != nil {
		t.Fatalf("A needs B: %v", err)
	}
	// B needs A: would close the cycle A->B->A.
	err := e.needs(t, tok, b, []int64{a}, nil)
	if err == nil {
		t.Fatal("expected cycle refusal")
	}
	if ae, ok := err.(*core.APIError); !ok || ae.Status != 409 || !strings.Contains(ae.Msg, "cycle") {
		t.Fatalf("want 409 cycle, got %v", err)
	}
	// Self-dependency is a cycle too.
	if err := e.needs(t, tok, a, []int64{a}, nil); err == nil {
		t.Fatal("expected self-cycle refusal")
	}
	// Depending on a hidden task is refused.
	c := e.task(t, tok, "C")
	if err := forge.HideTask(context.Background(), e.d, int(c)); err != nil {
		t.Fatal(err)
	}
	if err := e.needs(t, tok, a, []int64{c}, nil); err == nil {
		t.Fatal("expected hidden-need refusal")
	}
}

func TestBlockedComputedAndReadyList(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t, 5)
	a := e.task(t, tok, "needs-b")
	b := e.task(t, tok, "prereq")
	if err := e.needs(t, tok, a, []int64{b}, nil); err != nil {
		t.Fatal(err)
	}
	if !blocked(t, a) {
		t.Fatal("A should be blocked")
	}
	if blocked(t, b) {
		t.Fatal("B should not be blocked")
	}
	// ready list contains B, not A; blocked list contains A, not B.
	ready, _ := e.s.list(context.Background(), true, 50)
	if contains(ready, a) || !contains(ready, b) {
		t.Fatalf("ready = %v, want B(%d) not A(%d)", ids(ready), b, a)
	}
	blk, _ := e.s.list(context.Background(), false, 50)
	if !contains(blk, a) || contains(blk, b) {
		t.Fatalf("blocked = %v, want A(%d) not B(%d)", ids(blk), a, b)
	}
	// Finishing B clears the block.
	e.markDone(t, b)
	if blocked(t, a) {
		t.Fatal("A should be unblocked after B done")
	}
	ready, _ = e.s.list(context.Background(), true, 50)
	if !contains(ready, a) {
		t.Fatalf("A should be ready after B done, ready=%v", ids(ready))
	}
}

func TestClaimCheckBlocks(t *testing.T) {
	e := newEnv(t)
	cid, ctok := mkRoot(t, 5)
	_, wtok := mkRoot(t, 5)
	_ = cid
	a := e.task(t, ctok, "blocked-task")
	b := e.task(t, ctok, "prereq")
	if err := e.needs(t, ctok, a, []int64{b}, nil); err != nil {
		t.Fatal(err)
	}
	// A worker's claim on the blocked task is refused by forge.ClaimCheckFn.
	st, body := e.do(t, "POST", "/v1/t/"+itoa(a)+"/claim", wtok, "")
	if st != 409 || !strings.Contains(body, "needs #"+itoa(b)) {
		t.Fatalf("claim on blocked: %d %s", st, body)
	}
	// After the prerequisite is done, the claim goes through.
	e.markDone(t, b)
	st, body = e.do(t, "POST", "/v1/t/"+itoa(a)+"/claim", wtok, "")
	if st != 200 || !strings.HasPrefix(body, "ok until") {
		t.Fatalf("claim after unblock: %d %s", st, body)
	}
}

func TestUnblockOnDone(t *testing.T) {
	e := newEnv(t)
	cid, tok := mkRoot(t, 5)
	a := e.task(t, tok, "dependent")
	b := e.task(t, tok, "prereq")
	if err := e.needs(t, tok, a, []int64{b}, nil); err != nil {
		t.Fatal(err)
	}
	e.markDone(t, b)
	e.janitor(t)
	// The dependent was announced once.
	var ub *time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT unblocked_at FROM task_dag WHERE n = $1`, a).Scan(&ub); err != nil {
		t.Fatal(err)
	}
	if ub == nil {
		t.Fatal("A should be marked unblocked")
	}
	// An 'unblocked' event was emitted.
	var ev int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE kind = 't' AND ref = $1 AND title = 'unblocked'`, itoa(a)).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	if ev == 0 {
		t.Fatal("expected an unblocked event")
	}
	_ = cid
	// Idempotent: a second pass announces nothing new.
	e.janitor(t)
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE kind = 't' AND ref = $1 AND title = 'unblocked'`, itoa(a)).Scan(&ev); err != nil {
		t.Fatal(err)
	}
	if ev != 1 {
		t.Fatalf("unblocked event fired %d times, want 1", ev)
	}
}

func TestSplitAndJoinRules(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t, 5)

	// join=all: the parent unblocks only when every child is done.
	p := e.task(t, tok, "parent-all")
	kids, err := e.s.Split(context.Background(), e.ident(t, tok), p, []SplitItem{{Title: "c1"}, {Title: "c2"}, {Title: "c3"}}, "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(kids) != 3 {
		t.Fatalf("want 3 children, got %d", len(kids))
	}
	if !blocked(t, p) {
		t.Fatal("parent should be blocked by its children")
	}
	e.markDone(t, kids[0])
	e.janitor(t)
	if !blocked(t, p) {
		t.Fatal("parent still needs c2,c3")
	}
	e.markDone(t, kids[1])
	e.markDone(t, kids[2])
	e.janitor(t)
	if blocked(t, p) {
		t.Fatal("parent should be unblocked after all children done")
	}
	if !hasNote(t, p, "join met 3/3") {
		t.Fatalf("missing join-met note, notes=%v", noteTexts(t, p))
	}

	// join=any: one child done is enough, remaining prerequisites are cleared.
	pa := e.task(t, tok, "parent-any")
	ak, err := e.s.Split(context.Background(), e.ident(t, tok), pa, []SplitItem{{Title: "a1"}, {Title: "a2"}, {Title: "a3"}}, "any")
	if err != nil {
		t.Fatal(err)
	}
	e.markDone(t, ak[0])
	e.janitor(t)
	if blocked(t, pa) {
		t.Fatal("any-join parent should unblock after one child")
	}
	if !hasNote(t, pa, "join met 1/3") {
		t.Fatalf("missing any join note, notes=%v", noteTexts(t, pa))
	}

	// join=k:2.
	pk := e.task(t, tok, "parent-k")
	kk, err := e.s.Split(context.Background(), e.ident(t, tok), pk, []SplitItem{{Title: "k1"}, {Title: "k2"}, {Title: "k3"}}, "k:2")
	if err != nil {
		t.Fatal(err)
	}
	e.markDone(t, kk[0])
	e.janitor(t)
	if !blocked(t, pk) {
		t.Fatal("k:2 parent still blocked after 1 child")
	}
	e.markDone(t, kk[1])
	e.janitor(t)
	if blocked(t, pk) {
		t.Fatal("k:2 parent should unblock after 2 children")
	}
	if !hasNote(t, pk, "join met 2/3") {
		t.Fatalf("missing k join note, notes=%v", noteTexts(t, pk))
	}
}

func TestSplitAcceptanceHTTP(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t, 5)
	p := e.task(t, tok, "ship it")
	st, body := e.do(t, "POST", "/v1/t/"+itoa(p)+"/split", tok, `{"items":[{"title":"c1"},{"title":"c2"},{"title":"c3"}],"join":"all"}`)
	if st != 201 || !strings.HasPrefix(body, "ok split #"+itoa(p)) {
		t.Fatalf("split: %d %s", st, body)
	}
	kids := childrenOf(t, p)
	if len(kids) != 3 {
		t.Fatalf("want 3 children, got %d", len(kids))
	}
	for _, k := range kids {
		e.markDone(t, k)
	}
	e.janitor(t)
	if blocked(t, p) {
		t.Fatal("#parent should be unblocked (reopened) after all three done")
	}
	if !hasNote(t, p, "join met 3/3") {
		t.Fatalf("missing 'join met 3/3' note, notes=%v", noteTexts(t, p))
	}
}

func TestHiddenDepNeverUnblocks(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t, 5)
	a := e.task(t, tok, "dependent")
	b := e.task(t, tok, "prereq")
	if err := e.needs(t, tok, a, []int64{b}, nil); err != nil {
		t.Fatal(err)
	}
	// Hide the prerequisite after the edge exists (the janitor handles the fallout).
	if err := forge.HideTask(context.Background(), e.d, int(b)); err != nil {
		t.Fatal(err)
	}
	e.janitor(t)
	if !blocked(t, a) {
		t.Fatal("A must stay blocked behind a hidden prerequisite")
	}
	if !hasNote(t, a, fmt.Sprintf("dep #%d gone", b)) {
		t.Fatalf("missing 'dep #%d gone' note, notes=%v", b, noteTexts(t, a))
	}
	ready, _ := e.s.list(context.Background(), true, 50)
	if contains(ready, a) {
		t.Fatal("A must not be ready")
	}
	// Idempotent: the gone note fires once.
	e.janitor(t)
	cnt := 0
	for _, s := range noteTexts(t, a) {
		if strings.Contains(s, "gone") {
			cnt++
		}
	}
	if cnt != 1 {
		t.Fatalf("gone note fired %d times, want 1", cnt)
	}
}

func TestCapsDepthDescendants(t *testing.T) {
	e := newEnv(t)
	cid, tok := mkRoot(t, 5)

	// Depth: build a parent chain of depth 8 directly, then a split of the deepest task is refused.
	chain := make([]int64, 8)
	for i := range chain {
		chain[i] = e.task(t, tok, fmt.Sprintf("d%d", i))
	}
	for i := 1; i < len(chain); i++ {
		if _, err := testPool.Exec(context.Background(), `INSERT INTO task_dag (n, parent, root) VALUES ($1, $2, $3)`, chain[i], chain[i-1], cid); err != nil {
			t.Fatal(err)
		}
	}
	d, err := e.s.depth(context.Background(), chain[7])
	if err != nil {
		t.Fatal(err)
	}
	if d != 8 {
		t.Fatalf("depth = %d, want 8", d)
	}
	_, err = e.s.Split(context.Background(), e.ident(t, tok), chain[7], []SplitItem{{Title: "x"}}, "all")
	if ae, ok := err.(*core.APIError); !ok || ae.Status != 409 || !strings.Contains(ae.Msg, "depth") {
		t.Fatalf("want depth refusal, got %v", err)
	}

	// Descendants/day: pre-load 255 descendant rows for today, then a 2-item split (257) is refused.
	for i := 0; i < 255; i++ {
		var n int64
		if err := testPool.QueryRow(context.Background(), `INSERT INTO tasks (n, id, root, title, state, created)
			VALUES (nextval('task_n_seq'), $1, $1, 'x', 'open', now()) RETURNING n`, cid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(context.Background(), `INSERT INTO task_dag (n, root, created) VALUES ($1, $2, now())`, n, cid); err != nil {
			t.Fatal(err)
		}
	}
	p := e.task(t, tok, "fan")
	_, err = e.s.Split(context.Background(), e.ident(t, tok), p, []SplitItem{{Title: "a"}, {Title: "b"}}, "all")
	if ae, ok := err.(*core.APIError); !ok || ae.Status != 429 || !strings.Contains(ae.Msg, "descendants") {
		t.Fatalf("want descendants/day refusal, got %v", err)
	}
}

// --- helpers ---

func contains(ls []TaskLine, n int64) bool {
	for _, l := range ls {
		if l.N == n {
			return true
		}
	}
	return false
}

func ids(ls []TaskLine) []int64 {
	out := make([]int64, len(ls))
	for i, l := range ls {
		out[i] = l.N
	}
	return out
}

func childrenOf(t *testing.T, parent int64) []int64 {
	t.Helper()
	rows, err := testPool.Query(context.Background(), `SELECT n FROM task_dag WHERE parent = $1 ORDER BY n`, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var n int64
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}
