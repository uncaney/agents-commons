package delta

import (
	"bytes"
	"context"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/testdb"
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
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("delta", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping delta DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d     *core.Deps
	srv   *httptest.Server
	ip    string
	roots []string
}

var (
	ipSeq  atomic.Int64
	ipBase = int64(70)
	uniqN  atomic.Int64
)

func nextIP() string {
	n := ipSeq.Add(1)
	return fmt.Sprintf("10.%d.%d.9", (ipBase+n/200)%256, 1+n%200)
}

func uniq(s string) string { return fmt.Sprintf("%s-%d", s, uniqN.Add(1)) }

func newDeltaEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	old := kb.PageLinksFn
	mux := http.NewServeMux()
	core.Register(mux, d)
	kb.Register(mux, d)
	kb.RegisterEdit(mux, d)
	kb.RegisterCite(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	e := &tenv{d: d, srv: srv, ip: nextIP()}
	t.Cleanup(func() {
		kb.PageLinksFn = old
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM kb WHERE author_root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM checkpoints WHERE root = ANY($1)`, e.roots)
	})
	return e
}

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

func (e *tenv) register(t *testing.T, name string) (id, tok string) {
	t.Helper()
	ip := nextIP()
	st, body, _ := e.do(t, "POST", "/v1/challenge", "", nil, "CF-Connecting-IP", ip)
	if st != 200 {
		t.Fatalf("challenge: %d %s", st, body)
	}
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(body, -1) {
		m[x[1]] = x[2]
	}
	c, bits := m["c"], e.d.Cfg.PowBits
	if b, err := strconv.Atoi(m["bits"]); err == nil && b > 0 {
		bits = b
	}
	st, body, _ = e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, bits), "name": name}, "CF-Connecting-IP", ip)
	if st != 201 {
		t.Fatalf("register: %d %s", st, body)
	}
	m = map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(body, -1) {
		m[x[1]] = x[2]
	}
	e.roots = append(e.roots, m["id"])
	return m["id"], m["token"]
}

func (e *tenv) do(t *testing.T, method, path, token string, body any, hdr ...string) (int, string, http.Header) {
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
	req.Header.Set("CF-Connecting-IP", e.ip)
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

func (e *tenv) post(t *testing.T, tok string, in map[string]any) string {
	t.Helper()
	st, body, _ := e.do(t, "POST", "/v1/kb", tok, in)
	if st != 201 || !strings.HasPrefix(body, "ok k") {
		t.Fatalf("post: %d %s", st, body)
	}
	return strings.Fields(body)[1]
}

// --- tests --------------------------------------------------------------------------------------

// TestKbDiffRoute checks the kb revision diff renders indented +/- hunks between a retained
// revision and the current one, and reports unchanged when the two revisions are equal.
func TestKbDiffRoute(t *testing.T) {
	e := newDeltaEnv(t)
	_, tok := e.register(t, "author")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("diff me"), "symptom": uniq("s"), "fix": "run the old command"})
	if st, b, _ := e.do(t, "PATCH", "/v1/kb/"+id, tok, map[string]any{"fix": "run the mid command"}); st != 200 { // rev 2
		t.Fatalf("edit: %d %s", st, b)
	}
	if st, b, _ := e.do(t, "PATCH", "/v1/kb/"+id, tok, map[string]any{"fix": "run the new command"}); st != 200 { // rev 3
		t.Fatalf("edit: %d %s", st, b)
	}
	st, body, _ := e.do(t, "GET", "/v1/kb/"+id+"/diff?from=2&to=3", "", nil)
	if st != 200 {
		t.Fatalf("diff: %d %s", st, body)
	}
	if !strings.Contains(body, "diff kb:"+id+" 2..3") {
		t.Fatalf("head: %s", body)
	}
	if !strings.Contains(body, "\n  -") || !strings.Contains(body, "\n  +") {
		t.Fatalf("missing two-space-indented +/- hunk lines:\n%s", body)
	}
	if !strings.Contains(body, "mid command") || !strings.Contains(body, "new command") {
		t.Fatalf("diff lacks both sides:\n%s", body)
	}
	// equal revisions
	st, body, _ = e.do(t, "GET", "/v1/kb/"+id+"/diff?from=3&to=3", "", nil)
	if st != 200 || !strings.HasPrefix(body, "ok unchanged rev=3") {
		t.Fatalf("unchanged: %d %s", st, body)
	}
	// to=latest resolves to the current rev
	st, body, _ = e.do(t, "GET", "/v1/kb/"+id+"/diff?from=2&to=latest", "", nil)
	if st != 200 || !strings.Contains(body, "2..3") {
		t.Fatalf("latest: %d %s", st, body)
	}
}

// TestTaskNotesAfter checks the task-note feed returns notes after a cursor and advances it.
func TestTaskNotesAfter(t *testing.T) {
	e := newDeltaEnv(t)
	id, _ := e.register(t, "owner")
	ctx := context.Background()
	var n int64
	if err := testPool.QueryRow(ctx, `INSERT INTO tasks (n, id, root, title, state) VALUES (nextval('task_n_seq'), $1, $2, 'a task', 'open') RETURNING n`, core.NewID('t'), id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM tasks WHERE n = $1`, n) })
	var ids []int64
	for i := 0; i < 3; i++ {
		var nid int64
		if err := testPool.QueryRow(ctx, `INSERT INTO task_notes (n, by, root, text, kind) VALUES ($1, $2, $2, $3, 'note') RETURNING id`,
			n, id, fmt.Sprintf("note number %d", i)).Scan(&nid); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, nid)
	}
	st, body, _ := e.do(t, "GET", fmt.Sprintf("/v1/t/%d/notes?after=%d", n, ids[0]), "", nil)
	if st != 200 {
		t.Fatalf("notes: %d %s", st, body)
	}
	if !strings.Contains(body, "n=2") {
		t.Fatalf("want 2 notes after cursor:\n%s", body)
	}
	if strings.Contains(body, "note number 0") {
		t.Fatalf("cursor not applied:\n%s", body)
	}
	if !strings.Contains(body, "note number 1") || !strings.Contains(body, "note number 2") {
		t.Fatalf("missing later notes:\n%s", body)
	}
}

// TestSpaceDocDiff checks the space-doc diff over space_doc_revs.
func TestSpaceDocDiff(t *testing.T) {
	e := newDeltaEnv(t)
	_, tok := e.register(t, "member")
	slug := "deltasp" + strconv.FormatInt(uniqN.Add(1), 10)
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `INSERT INTO spaces (slug, name, creator_root, rules) VALUES ($1, 'Delta Space', 'seed', '{}')`, slug); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO space_docs (space, name, text, rev) VALUES ($1, 'doc1', $2, 2)`, slug, "alpha\nbeta\n"); err != nil {
		t.Fatal(err)
	}
	testPool.Exec(ctx, `INSERT INTO space_doc_revs (space, name, rev, text) VALUES ($1,'doc1',1,$2),($1,'doc1',2,$3)`, slug, "alpha\nbeta\n", "alpha\nBETA\n")
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM spaces WHERE slug = $1`, slug) })

	st, body, _ := e.do(t, "GET", "/v1/s/"+slug+"/d/doc1/diff?from=1&to=2", tok, nil)
	if st != 200 {
		t.Fatalf("space diff: %d %s", st, body)
	}
	if !strings.Contains(body, "\n  -beta") || !strings.Contains(body, "\n  +BETA") {
		t.Fatalf("space diff hunk:\n%s", body)
	}
	// unauthenticated -> 401
	if st, _, _ := e.do(t, "GET", "/v1/s/"+slug+"/d/doc1/diff?from=1&to=2", "", nil); st != 401 {
		t.Fatalf("anon space diff: want 401, got %d", st)
	}
}

// TestCpDiff checks the checkpoint diff is root-private and renders a hunk.
func TestCpDiff(t *testing.T) {
	e := newDeltaEnv(t)
	root, tok := e.register(t, "cp-owner")
	ctx := context.Background()
	exp := time.Now().Add(24 * time.Hour)
	for i, body := range []string{"goal: ship\nnext: build\n", "goal: ship\nnext: test\n"} {
		if _, err := testPool.Exec(ctx, `INSERT INTO checkpoints (id, root, owner, name, seq, body, expires_at) VALUES ($1,$2,$2,'work',$3,$4,$5)`,
			core.NewID('c'), root, i+1, body, exp); err != nil {
			t.Fatal(err)
		}
	}
	st, body, _ := e.do(t, "GET", "/v1/cp/work/diff?from=1&to=2", tok, nil)
	if st != 200 {
		t.Fatalf("cp diff: %d %s", st, body)
	}
	if !strings.Contains(body, "\n  -next: build") || !strings.Contains(body, "\n  +next: test") {
		t.Fatalf("cp diff hunk:\n%s", body)
	}
}

// TestNotesDiffRing checks the wiki-note diff over the notes_revs ring and that only the last 10
// revisions survive.
func TestNotesDiffRing(t *testing.T) {
	e := newDeltaEnv(t)
	owner, _ := e.register(t, "note-owner")
	name := "page" + strconv.FormatInt(uniqN.Add(1), 10)
	ctx := context.Background()
	for i := 1; i <= 12; i++ {
		if _, err := testPool.Exec(ctx, `INSERT INTO notes_revs (owner, name, rev, text) VALUES ($1,$2,$3,$4)`,
			owner, name, i, fmt.Sprintf("line a\nrevision %d\n", i)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM notes_revs WHERE owner = $1`, owner) })
	// ring trimmed to 10: revs 1 and 2 are gone
	st, body, _ := e.do(t, "GET", "/v1/n/"+owner+"/"+name+"/diff?from=3&to=12", "", nil)
	if st != 200 {
		t.Fatalf("note diff: %d %s", st, body)
	}
	if !strings.Contains(body, "\n  -revision 3") || !strings.Contains(body, "\n  +revision 12") {
		t.Fatalf("note diff hunk:\n%s", body)
	}
	if st, _, _ := e.do(t, "GET", "/v1/n/"+owner+"/"+name+"/diff?from=1&to=12", "", nil); st != 404 {
		t.Fatalf("trimmed revision should 404, got %d", st)
	}
}

// TestVisibilityEnforced checks a hidden kb entry is not diffable and that a checkpoint diff is
// private to its owning root.
func TestVisibilityEnforced(t *testing.T) {
	e := newDeltaEnv(t)
	author, atok := e.register(t, "vauthor")
	id := e.post(t, atok, map[string]any{"kind": "fix", "title": uniq("to be hidden"), "symptom": uniq("s"), "fix": "secret"})
	e.do(t, "PATCH", "/v1/kb/"+id, atok, map[string]any{"fix": "secret v2"})
	if _, err := testPool.Exec(context.Background(), `UPDATE kb SET hidden = true, hidden_at = now() WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := e.do(t, "GET", "/v1/kb/"+id+"/diff?from=1&to=2", "", nil); st != 404 {
		t.Fatalf("hidden kb diff: want 404, got %d", st)
	}
	_ = author

	// checkpoint privacy: a second root cannot diff the first root's checkpoints.
	root, _ := e.register(t, "cpv-owner")
	_, otherTok := e.register(t, "cpv-other")
	ctx := context.Background()
	exp := time.Now().Add(24 * time.Hour)
	for i, body := range []string{"a\n", "b\n"} {
		if _, err := testPool.Exec(ctx, `INSERT INTO checkpoints (id, root, owner, name, seq, body, expires_at) VALUES ($1,$2,$2,'priv',$3,$4,$5)`,
			core.NewID('c'), root, i+1, body, exp); err != nil {
			t.Fatal(err)
		}
	}
	if st, _, _ := e.do(t, "GET", "/v1/cp/priv/diff?from=1&to=2", otherTok, nil); st != 404 {
		t.Fatalf("other root cp diff: want 404, got %d", st)
	}
}
