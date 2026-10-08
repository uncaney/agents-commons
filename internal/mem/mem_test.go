package mem

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
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
)

var (
	pool   *pgxpool.Pool
	levels sync.Map // root -> level, read by the core.LevelFn stub
	leaked sync.Map // tokens the core.LeakedTokenFn stub was consulted about
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		p, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, p); err != nil {
			panic(err)
		}
		pool, cleanup = p, p.Close
	} else if p, done := testdb.Open("mem", core.Migrate); p != nil {
		pool, cleanup = p, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping mem DB tests")
		os.Exit(0)
	}
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int {
		v, _ := levels.Load(root)
		n, _ := v.(int)
		return n
	}
	core.LeakedTokenFn = func(ctx context.Context, q core.Q, tok string) (string, error) {
		leaked.Store(tok, true)
		return "leak-noted", nil
	}
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

// do sends a request from a random client IP (override with a CF-Connecting-IP header pair).
func (e *env) do(t *testing.T, method, path, token, body string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	st, b, h, err := e.req(method, path, token, body, hdr...)
	if err != nil {
		t.Fatal(err)
	}
	return st, b, h
}

// req is do without the test hook (safe inside goroutines).
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

// want asserts the status and that every needle appears in the body.
func want(t *testing.T, st int, body string, wantSt int, needles ...string) {
	t.Helper()
	if st != wantSt {
		t.Fatalf("status %d, want %d: %s", st, wantSt, body)
	}
	for _, n := range needles {
		if !strings.Contains(body, n) {
			t.Fatalf("body lacks %q:\n%s", n, body)
		}
	}
}

func wantNot(t *testing.T, body string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if strings.Contains(body, n) {
			t.Fatalf("body must not contain %q:\n%s", n, body)
		}
	}
}

// mkRoot inserts a root identity (rep 20 keeps the request limiter generous) and returns (id, token).
func mkRoot(t *testing.T) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := pool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, rep, reg_ip)
		VALUES ($1, 'r', NULL, $1, $2, 100, 20, $3)`, id, h, randIP()); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

// mkSub inserts a scoped subkey of root.
func mkSub(t *testing.T, root string, scopes []string) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := pool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, scopes, token_class)
		VALUES ($1, 's', $2, $2, $3, 0, $4, 'scoped')`, id, root, h, scopes); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func setLevel(root string, lvl int) { levels.Store(root, lvl) }

// uniq returns a fresh lowercase name so shared namespaces never collide across tests or runs.
func uniq() string { return core.NewID('g')[1:] + core.NewID('g')[1:] }

func jsonBody(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// capOverride lowers a caps-table row for the test and restores it afterwards.
func capOverride(t *testing.T, kind string, row [4]int) {
	t.Helper()
	old := trust.Caps[kind]
	trust.Caps[kind] = row
	t.Cleanup(func() { trust.Caps[kind] = old })
}

// allowFence installs a FenceCheckFn that accepts every fence for the test.
func allowFence(t *testing.T) {
	t.Helper()
	old := FenceCheckFn
	FenceCheckFn = func(context.Context, core.Q, string, int64) error { return nil }
	t.Cleanup(func() { FenceCheckFn = old })
}

func count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// --- resume, audit log, scrub ------------------------------------------------------------------

func TestResumeFreshAndFull(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	st, b, _ := e.do(t, "GET", "/v1/me/resume", tok, "")
	want(t, st, b, 200, "resume "+root+" fresh", "seal=unset", "me: id="+root, "next: ")
	body := "cp1\ngoal: ship v2\ndone:\n  wrote tests\n  fixed bug\nnext:\n  deploy\nids:\n  t:12\n"
	st, b, _ = e.do(t, "POST", "/v1/cp", tok, jsonBody(map[string]any{"name": "work", "summary": "first pass", "body": body}), "Content-Type", "application/json")
	want(t, st, b, 201, "ok c", "seq=1")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/x", tok, "hello")
	want(t, st, b, 201, "ok ver=1")
	st, b, _ = e.do(t, "POST", "/v1/later", tok, `{"text":"remember the milk","after":"+0"}`, "Content-Type", "application/json")
	want(t, st, b, 201, "ok m", "deliver=")
	if err := LaterRun(context.Background(), pool, nil); err != nil {
		t.Fatal(err)
	}
	st, b, _ = e.do(t, "GET", "/v1/me/resume", tok, "")
	want(t, st, b, 200, "resume "+root+" lvl=L0 seal=unset cp=1 later=1 kv=1", "cp: c", " work seq=1 ", "summary: first pass",
		"body: cp1", "  goal:", "    ship v2", "  next:", "    deploy", "  ids:", "    t:12", "later: 1 unread", "  remember the milk", "kv: 1 keys", "  x 1 ")
	wantNot(t, b, "done:", "wrote tests", "fresh")
	st, b, _ = e.do(t, "GET", "/v1/me/resume?full=1&kv=1", tok, "")
	want(t, st, b, 200, "  done:", "    wrote tests", "    fixed bug", "    hello")
	st, b, _ = e.do(t, "GET", "/v1/me/resume?name=nothing", tok, "")
	want(t, st, b, 200, "cp=0")
	var seen *time.Time
	if err := pool.QueryRow(context.Background(), `SELECT last_seen FROM identities WHERE id = $1`, root).Scan(&seen); err != nil || seen == nil {
		t.Fatalf("last_seen not updated: %v %v", seen, err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE identities SET mk_wrapped = '\x01'::bytea WHERE id = $1`, root); err != nil {
		t.Fatal(err)
	}
	st, b, _ = e.do(t, "GET", "/v1/me/resume", tok, "")
	want(t, st, b, 200, "seal=set")
	st, b, _ = e.do(t, "GET", "/v1/me/resume", "", "")
	want(t, st, b, 401, "err auth")
	_, sub := mkSub(t, root, []string{"kb:r"})
	st, b, _ = e.do(t, "GET", "/v1/me/resume", sub, "")
	want(t, st, b, 403, "err scope me:r")
	_, sub = mkSub(t, root, []string{"me:r"})
	st, b, _ = e.do(t, "GET", "/v1/me/resume", sub, "")
	want(t, st, b, 200, "resume "+root)
}

func TestAuditLogRoute(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	st, b, _ := e.do(t, "PUT", "/v1/kv/me/x", tok, "1")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "POST", "/v1/cp", tok, `{"name":"n","summary":"s"}`, "Content-Type", "application/json")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "GET", "/v1/me/log", tok, "")
	want(t, st, b, 200, "log "+root+" n=2", " "+root+" kv a:"+root+"/x 1", " "+root+" cp c")
	st, b, _ = e.do(t, "GET", "/v1/me/log?op=kv", tok, "")
	want(t, st, b, 200, "n=1", " kv ")
	wantNot(t, b, " cp ")
	st, b, _ = e.do(t, "GET", "/v1/me/log?k=1", tok, "")
	want(t, st, b, 200, "n=1")
	st, b, _ = e.do(t, "GET", "/v1/me/log?since=2999-01-01", tok, "")
	want(t, st, b, 200, "n=0")
	st, b, _ = e.do(t, "GET", "/v1/me/log?op=Bad!", tok, "")
	want(t, st, b, 400, "err bad")
	_, other := mkRoot(t)
	st, b, _ = e.do(t, "GET", "/v1/me/log", other, "")
	want(t, st, b, 200, "n=0")
	// ring: 30 d TTL and the last 1000 rows per root
	ring, _ := mkRoot(t)
	if _, err := pool.Exec(context.Background(), `INSERT INTO audit (root, id, ts, op, ref, n)
		SELECT $1, $1, now() - (g || ' seconds')::interval, 'kv', 'r' || g, g FROM generate_series(1, 1005) g`, ring); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO audit (root, id, ts, op) VALUES ($1, $1, now() - interval '40 days', 'old')`, ring); err != nil {
		t.Fatal(err)
	}
	if err := AuditTrim(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	if n := count(t, `SELECT count(*) FROM audit WHERE root = $1`, ring); n != 1000 {
		t.Fatalf("ring kept %d rows, want 1000", n)
	}
	if n := count(t, `SELECT count(*) FROM audit WHERE root = $1 AND op = 'old'`, ring); n != 0 {
		t.Fatal("40-day-old row survived")
	}
	// a fresh root's resume shows the recent lines
	st, b, _ = e.do(t, "GET", "/v1/me/resume", tok, "")
	want(t, st, b, 200, "recent:", " cp c")
}

func TestScrubOnValues(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	st, b, _ := e.do(t, "PUT", "/v1/kv/me/s", tok, "aws AKIAZQ3X7V2M9KPL4RT8 key")
	want(t, st, b, 400, "err scrub")
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/e", tok, "mail me at bob@example.com please")
	want(t, st, b, 201, "ok ver=1", "masked=email")
	st, b, _ = e.do(t, "GET", "/v1/kv/me/e", tok, "")
	want(t, st, b, 200, "<email>")
	wantNot(t, b, "bob@example.com")
	st, b, _ = e.do(t, "POST", "/v1/cp", tok, jsonBody(map[string]any{"name": "c", "body": "key sk-ant-api03-" + strings.Repeat("Qz7", 20)}), "Content-Type", "application/json")
	want(t, st, b, 400, "err scrub")
	st, b, _ = e.do(t, "POST", "/v1/later", tok, jsonBody(map[string]any{"text": "ghp_" + strings.Repeat("A1b2C3d4E5", 4), "after": "+10"}), "Content-Type", "application/json")
	want(t, st, b, 400, "err scrub")
	// the caller's own live token in a value: refused and the leak link consulted
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/t", tok, "my token is "+tok)
	want(t, st, b, 400, "err scrub token", "leak-noted")
	if _, ok := leaked.Load(tok); !ok {
		t.Fatal("leak link not consulted")
	}
	// zero-width split secret is caught after normalisation
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/z", tok, "sk-ant-\u200bapi03-"+strings.Repeat("Qz7", 20))
	want(t, st, b, 400, "err scrub")
	// summary with a control character is refused, body with CRLF is normalised
	st, b, _ = e.do(t, "POST", "/v1/cp", tok, jsonBody(map[string]any{"name": "c", "summary": "a\nb"}), "Content-Type", "application/json")
	want(t, st, b, 400, "err bad summary")
	st, b, _ = e.do(t, "POST", "/v1/cp", tok, jsonBody(map[string]any{"name": "c", "body": "line1\r\nline2"}), "Content-Type", "application/json")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "GET", "/v1/cp/c", tok, "")
	want(t, st, b, 200, "body: line1\n  line2")
	_ = root
}

func TestExportPurgeAndTargets(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	allowFence(t)
	g := "g:" + uniq()
	st, b, _ := e.do(t, "POST", "/v1/cp", tok, `{"name":"x","summary":"s","body":"b"}`, "Content-Type", "application/json")
	want(t, st, b, 201)
	cpID := strings.Fields(b)[1]
	st, b, _ = e.do(t, "PUT", "/v1/kv/me/k", tok, "v")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "PUT", "/v1/kv/"+g+"/k", tok, "shared")
	want(t, st, b, 201)
	st, b, _ = e.do(t, "POST", "/v1/later", tok, `{"text":"t","after":"+100"}`, "Content-Type", "application/json")
	want(t, st, b, 201)
	var sb strings.Builder
	if err := e.d.Export(context.Background(), root, &sb); err != nil {
		t.Fatal(err)
	}
	out := sb.String()
	for _, n := range []string{`"kind":"cp"`, `"id":"` + cpID + `"`, `"kind":"kv"`, `"ns":"` + g + `"`, `"kind":"later"`} {
		if !strings.Contains(out, n) {
			t.Fatalf("export lacks %s:\n%s", n, out)
		}
	}
	// report targets
	if err := cpExists(context.Background(), pool, cpID); err != nil {
		t.Fatal(err)
	}
	if err := kvExists(context.Background(), pool, "a:"+root+"/k"); err != nil {
		t.Fatal(err)
	}
	if err := kvExists(context.Background(), pool, "a:"+root+"/nope"); err == nil {
		t.Fatal("missing key reported as existing")
	}
	if err := kvHide(context.Background(), pool, g+"/k"); err != nil {
		t.Fatal(err)
	}
	st, b, _ = e.do(t, "GET", "/v1/kv/"+g+"/k", "", "")
	want(t, st, b, 410, "err gone")
	st, b, _ = e.do(t, "PUT", "/v1/kv/"+g+"/k", tok, "again")
	want(t, st, b, 410, "err gone")
	if err := kvRestore(context.Background(), pool, g+"/k"); err != nil {
		t.Fatal(err)
	}
	st, b, _ = e.do(t, "GET", "/v1/kv/"+g+"/k", "", "")
	want(t, st, b, 200, "shared")
	// purge removes every row of the root
	if _, err := e.d.Purge(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if n := count(t, `SELECT count(*) FROM checkpoints WHERE root = $1`, root) + count(t, `SELECT count(*) FROM kv WHERE root = $1`, root) +
		count(t, `SELECT count(*) FROM mem_later WHERE root = $1`, root); n != 0 {
		t.Fatalf("%d rows survived the purge", n)
	}
}

func TestOpsMirrorHTTP(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t)
	id, err := e.d.LookupToken(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	ops := Ops(e.d)
	for name := range OpMeta {
		if ops[name] == nil {
			t.Fatalf("OpMeta lists %s but Ops lacks it", name)
		}
	}
	for name := range ops {
		if _, ok := OpMeta[name]; !ok {
			t.Fatalf("op %s has no OpMeta", name)
		}
	}
	ctx := context.Background()
	out, err := ops["cp"](ctx, id, json.RawMessage(`{"name":"o","summary":"via op","body":"cp1\ngoal: g\nnext:\n  n1\n"}`))
	if err != nil || !strings.HasPrefix(out, "ok c") {
		t.Fatalf("cp op: %q %v", out, err)
	}
	out, err = ops["kvp"](ctx, id, json.RawMessage(`{"k":"a","v":"1"}`))
	if err != nil || !strings.HasPrefix(out, "ok ver=1") {
		t.Fatalf("kvp op: %q %v", out, err)
	}
	out, err = ops["kv"](ctx, id, json.RawMessage(`{"k":"a"}`))
	if err != nil || !strings.Contains(out, "v: 1") {
		t.Fatalf("kv op: %q %v", out, err)
	}
	out, err = ops["kvi"](ctx, id, json.RawMessage(`{"k":"n","by":3}`))
	if err != nil || !strings.Contains(out, "v=3") {
		t.Fatalf("kvi op: %q %v", out, err)
	}
	out, err = ops["kvl"](ctx, id, json.RawMessage(`{}`))
	if err != nil || !strings.Contains(out, "kv a:"+root+" n=2") {
		t.Fatalf("kvl op: %q %v", out, err)
	}
	out, err = ops["cpg"](ctx, id, json.RawMessage(`{"name":"o","s":"next"}`))
	if err != nil || !strings.Contains(out, "  next:") || strings.Contains(out, "goal") {
		t.Fatalf("cpg op: %q %v", out, err)
	}
	out, err = ops["cpl"](ctx, id, json.RawMessage(`{"name":"o"}`))
	if err != nil || !strings.Contains(out, "cp o n=1") {
		t.Fatalf("cpl op: %q %v", out, err)
	}
	out, err = ops["later"](ctx, id, json.RawMessage(`{"text":"hi","after":"+5"}`))
	if err != nil || !strings.HasPrefix(out, "ok m") {
		t.Fatalf("later op: %q %v", out, err)
	}
	out, err = ops["resume"](ctx, id, json.RawMessage(`{"full":true}`))
	if err != nil || !strings.Contains(out, "resume "+root) || strings.Contains(out, "next: ") {
		t.Fatalf("resume op must be tail-free: %q %v", out, err)
	}
	out, err = ops["log"](ctx, id, json.RawMessage(`{"op":"kv"}`))
	if err != nil || !strings.Contains(out, "log "+root+" n=1") {
		t.Fatalf("log op: %q %v", out, err)
	}
	out, err = ops["kvm"](ctx, id, json.RawMessage(`{"ops":[{"op":"get","k":"a"},{"op":"del","k":"a"}]}`))
	if err != nil || !strings.Contains(out, "ok=2") {
		t.Fatalf("kvm op: %q %v", out, err)
	}
	if _, err := ops["kv"](ctx, nil, json.RawMessage(`{"k":"a"}`)); err != core.ErrAuth {
		t.Fatalf("anonymous me namespace: %v", err)
	}
	if _, err := ops["cpd"](ctx, id, json.RawMessage(`{"id":"c000000"}`)); err == nil {
		t.Fatal("cpd of an unknown id must fail")
	}
}

// service functions used by later packages (sessions, subscriptions)
func TestServiceFunctions(t *testing.T) {
	newEnv(t)
	root, _ := mkRoot(t)
	ctx := context.Background()
	ver, err := KVPut(ctx, pool, root, "me", "svc/k", []byte("v1"), 0)
	if err != nil || ver != 1 {
		t.Fatalf("KVPut: %d %v", ver, err)
	}
	v, ver, err := KVGet(ctx, pool, root, "a:"+root, "svc/k")
	if err != nil || string(v) != "v1" || ver != 1 {
		t.Fatalf("KVGet: %q %d %v", v, ver, err)
	}
	if _, _, err := KVGet(ctx, pool, "a000000", "a:"+root, "svc/k"); err != core.ErrForbid {
		t.Fatalf("foreign KVGet: %v", err)
	}
	id, seq, err := PutCheckpoint(ctx, pool, root, "", "svc", "interrupted", "cp1\ngoal: resume\n")
	if err != nil || seq != 1 || !core.ValidIDPrefix(id, 'c') {
		t.Fatalf("PutCheckpoint: %s %d %v", id, seq, err)
	}
	mid, err := Later(ctx, pool, root, "session expired", time.Now())
	if err != nil || !core.ValidIDPrefix(mid, 'm') {
		t.Fatalf("Later: %s %v", mid, err)
	}
	if n := count(t, `SELECT count(*) FROM audit WHERE root = $1`, root); n != 3 {
		t.Fatalf("service calls audited %d rows, want 3", n)
	}
}
