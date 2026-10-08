package session

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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
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
	} else if pool, done := testdb.Open("session", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping session DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
	s   *svc
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	s := newSvc(d)
	mux.HandleFunc("POST /v1/session", s.create)
	mux.HandleFunc("POST /v1/session/{id}/beat", s.beat)
	mux.HandleFunc("DELETE /v1/session/{id}", s.goodbye)
	mux.HandleFunc("GET /v1/session", s.list)
	d.RegisterScope("POST /v1/session", "cp")
	d.RegisterCost("POST /v1/session/{id}/beat", 0.2)
	// The heartbeat middleware wraps the whole chain, exactly as P60a installs it.
	srv := httptest.NewServer(Middleware(d, d.Handler(mux)))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, srv: srv, s: s}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

func (e *tenv) do(t *testing.T, method, path, token, session, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", randIP())
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if session != "" {
		req.Header.Set("X-Session", session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func newRoot(t *testing.T) (id, token string) {
	t.Helper()
	id, token, err := core.CreateRoot(context.Background(), testPool, "session-test", randIP())
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

// sidOf extracts the e… id from an "ok e… ttl=…" reply head.
func sidOf(t *testing.T, body string) string {
	t.Helper()
	f := strings.Fields(body)
	if len(f) < 2 || !core.ValidIDPrefix(f[1], 'e') {
		t.Fatalf("no session id in %q", body)
	}
	return f[1]
}

// --- create caps + plan validation ---------------------------------------------------------------

func TestCreateCapsAndPlanValidation(t *testing.T) {
	e := newEnv(t)
	_, tok := newRoot(t)

	// L0 cap is 2 live sessions; the third is refused.
	for i := 0; i < 2; i++ {
		st, body := e.do(t, "POST", "/v1/session", tok, "", fmt.Sprintf(`{"name":"s%d","ttl_s":120}`, i))
		if st != 201 {
			t.Fatalf("create %d: status %d body %s", i, st, body)
		}
	}
	if st, body := e.do(t, "POST", "/v1/session", tok, "", `{"name":"s3","ttl_s":120}`); st != 429 {
		t.Fatalf("3rd session: status %d body %s (want 429)", st, body)
	}

	_, tok2 := newRoot(t)
	bad := []struct{ name, body string }{
		{"ttl low", `{"name":"x","ttl_s":59}`},
		{"ttl high", `{"name":"x","ttl_s":3601}`},
		{"empty name", `{"name":"","ttl_s":120}`},
		{"unknown field", `{"name":"x","ttl_s":120,"bogus":1}`},
		{"bad op", `{"name":"x","ttl_s":120,"plan":[{"op":"nope"}]}`},
		{"tdrop no n", `{"name":"x","ttl_s":120,"plan":[{"op":"tdrop"}]}`},
		{"unknown step field", `{"name":"x","ttl_s":120,"plan":[{"op":"tdrop","n":1,"zzz":2}]}`},
		{"pub no text", `{"name":"x","ttl_s":120,"plan":[{"op":"pub","topic":"g:x"}]}`},
		{"too many steps", `{"name":"x","ttl_s":120,"plan":[` +
			strings.Repeat(`{"op":"later","text":"a"},`, 8) + `{"op":"later","text":"a"}]}`},
	}
	for _, c := range bad {
		if st, body := e.do(t, "POST", "/v1/session", tok2, "", c.body); st != 400 {
			t.Fatalf("%s: status %d body %s (want 400)", c.name, st, body)
		}
	}
	// A full, valid plan of every step kind is accepted.
	ok := `{"name":"full","ttl_s":600,"plan":[
		{"op":"tdrop","n":1},{"op":"lkrel","name":"build"},
		{"op":"cp","name":"handoff","text":"see {cp}"},{"op":"later","text":"ping"},
		{"op":"pub","topic":"g:room","text":"bye"},{"op":"wq","name":"g:q","body":"item"},
		{"op":"kv","ns":"a:me","k":"state","v":"x","ttl":60},{"op":"tnote","n":1,"text":"note"}]}`
	if st, body := e.do(t, "POST", "/v1/session", tok2, "", ok); st != 201 {
		t.Fatalf("full plan: status %d body %s", st, body)
	}
}

// --- heartbeat coalescer: no write in the request tx, flushed later ------------------------------

func TestHeartbeatCoalescedNoTxWrite(t *testing.T) {
	e := newEnv(t)
	_, tok := newRoot(t)
	st, body := e.do(t, "POST", "/v1/session", tok, "", `{"name":"beat","ttl_s":600}`)
	if st != 201 {
		t.Fatalf("create: %d %s", st, body)
	}
	sid := sidOf(t, body)
	ctx := context.Background()
	// Push last_beat into the past so any refresh is visible.
	if _, err := testPool.Exec(ctx, `UPDATE sessions SET last_beat = now() - interval '1 hour' WHERE id = $1`, sid); err != nil {
		t.Fatal(err)
	}
	before := beatOf(t, sid)

	// An authenticated request carrying X-Session must NOT write last_beat synchronously.
	if st, _ := e.do(t, "GET", "/v1/session", tok, sid, ""); st != 200 {
		t.Fatalf("list with X-Session: %d", st)
	}
	if got := beatOf(t, sid); !got.Equal(before) {
		t.Fatalf("last_beat changed inside the request (%v -> %v); heartbeat must be coalesced", before, got)
	}
	// The coalescer flush (every 5 s in production) performs the single UPDATE.
	if err := coalescerFor(e.d).Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := beatOf(t, sid); !got.After(before) {
		t.Fatalf("flush did not refresh last_beat (%v -> %v)", before, got)
	}
}

func beatOf(t *testing.T, sid string) time.Time {
	t.Helper()
	var ts time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT last_beat FROM sessions WHERE id = $1`, sid).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	return ts
}

// --- goodbye writes a checkpoint -----------------------------------------------------------------

func TestGoodbyeWritesCheckpoint(t *testing.T) {
	e := newEnv(t)
	root, tok := newRoot(t)
	st, body := e.do(t, "POST", "/v1/session", tok, "", `{"name":"farewell","ttl_s":600}`)
	if st != 201 {
		t.Fatalf("create: %d %s", st, body)
	}
	sid := sidOf(t, body)
	st, body = e.do(t, "DELETE", "/v1/session/"+sid, tok, "", `{"summary":"handed everything off"}`)
	if st != 200 || !strings.Contains(body, "goodbye") {
		t.Fatalf("goodbye: %d %s", st, body)
	}
	ctx := context.Background()
	var cause, summary string
	if err := testPool.QueryRow(ctx, `SELECT cause, summary FROM sessions WHERE id = $1`, sid).Scan(&cause, &summary); err != nil {
		t.Fatal(err)
	}
	if cause != "goodbye" || summary != "handed everything off" {
		t.Fatalf("session not closed as goodbye: cause=%q summary=%q", cause, summary)
	}
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM checkpoints WHERE root = $1 AND body LIKE '%handed everything off%'`, root).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("goodbye did not write a checkpoint carrying the summary")
	}
}

// --- expiry runs the plan as the owner -----------------------------------------------------------

func TestExpiryRunsStepsAsOwner(t *testing.T) {
	e := newEnv(t)
	root, tok := newRoot(t)
	ctx := context.Background()
	n := int64(900000000) + int64(time.Now().UnixNano()%100000000)
	lock := fmt.Sprintf("build-%d", n)

	// The owner holds a task claim and a lock.
	if _, err := testPool.Exec(ctx, `INSERT INTO tasks (n, id, root, state, title) VALUES ($1, $2, $2, 'open', 't')`, n, root); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO task_claims (n, id, root, until) VALUES ($1, $2, $2, now() + interval '1 hour')`, n, root); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO locks (name, holder, root, fence, until, since, notified) VALUES ($1, $2, $2, 1, now() + interval '1 hour', now(), false)`, lock, root); err != nil {
		t.Fatal(err)
	}

	plan := fmt.Sprintf(`{"name":"nightwork","ttl_s":60,"plan":[
		{"op":"tdrop","n":%d},{"op":"lkrel","name":%q},
		{"op":"cp","name":"handoff","text":"stopped at {task}"},
		{"op":"later","text":"resume {task}"}]}`, n, lock)
	st, body := e.do(t, "POST", "/v1/session", tok, "", plan)
	if st != 201 {
		t.Fatalf("create: %d %s", st, body)
	}
	sid := sidOf(t, body)
	// Simulate the client vanishing: last_beat well past last_beat + ttl_s.
	if _, err := testPool.Exec(ctx, `UPDATE sessions SET last_beat = now() - interval '2 hours' WHERE id = $1`, sid); err != nil {
		t.Fatal(err)
	}
	if err := Expire(ctx, e.d); err != nil {
		t.Fatal(err)
	}

	// Session ended as expired with all four steps fired ok.
	var cause string
	var fired []byte
	if err := testPool.QueryRow(ctx, `SELECT cause, fired FROM sessions WHERE id = $1`, sid).Scan(&cause, &fired); err != nil {
		t.Fatal(err)
	}
	if cause != "expired" {
		t.Fatalf("cause = %q, want expired", cause)
	}
	okN, total := firedCounts(fired)
	if total != 4 || okN != 4 {
		t.Fatalf("fired %d/%d, want 4/4 (fired=%s)", okN, total, fired)
	}
	// Claim dropped.
	if until := until(t, `SELECT until FROM task_claims WHERE n = $1`, n); until.After(time.Now()) {
		t.Fatalf("task claim not dropped (until %v)", until)
	}
	// Lock released.
	if until := until(t, `SELECT until FROM locks WHERE name = $1`, lock); until.After(time.Now()) {
		t.Fatalf("lock not released (until %v)", until)
	}
	// Checkpoint written, with {task} filled to the held claim.
	var cpBody string
	if err := testPool.QueryRow(ctx, `SELECT body FROM checkpoints WHERE root = $1 AND name = 'handoff' ORDER BY seq DESC LIMIT 1`, root).Scan(&cpBody); err != nil {
		t.Fatalf("no checkpoint written: %v", err)
	}
	if !strings.Contains(cpBody, fmt.Sprintf("t:%d", n)) {
		t.Fatalf("checkpoint body missing filled {task}: %q", cpBody)
	}
	// Self-mail queued.
	var mail int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM mem_later WHERE root = $1 AND text LIKE '%nightwork expired%'`, root).Scan(&mail); err != nil {
		t.Fatal(err)
	}
	if mail == 0 {
		t.Fatal("expiry did not queue the self-mail")
	}
	// A hb-fire audit line was written for the owner.
	var audits int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit WHERE root = $1 AND op = 'hb-fire'`, root).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits == 0 {
		t.Fatal("no hb-fire audit line")
	}
}

func until(t *testing.T, q string, arg any) time.Time {
	t.Helper()
	var ts time.Time
	if err := testPool.QueryRow(context.Background(), q, arg).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	return ts
}

// --- step failures recorded, never retried -------------------------------------------------------

func TestStepFailuresRecordedNotRetried(t *testing.T) {
	e := newEnv(t)
	root, tok := newRoot(t)
	ctx := context.Background()
	// tdrop on a non-existent task fails; later succeeds. One pass records both; a second pass is a no-op.
	plan := `{"name":"halfbad","ttl_s":60,"plan":[{"op":"tdrop","n":999999999},{"op":"later","text":"still here"}]}`
	st, body := e.do(t, "POST", "/v1/session", tok, "", plan)
	if st != 201 {
		t.Fatalf("create: %d %s", st, body)
	}
	sid := sidOf(t, body)
	if _, err := testPool.Exec(ctx, `UPDATE sessions SET last_beat = now() - interval '2 hours' WHERE id = $1`, sid); err != nil {
		t.Fatal(err)
	}
	if err := Expire(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	var fired []byte
	if err := testPool.QueryRow(ctx, `SELECT fired FROM sessions WHERE id = $1`, sid).Scan(&fired); err != nil {
		t.Fatal(err)
	}
	var rs []fireResult
	if err := json.Unmarshal(fired, &rs); err != nil || len(rs) != 2 {
		t.Fatalf("fired = %s (err %v)", fired, err)
	}
	if rs[0].OK || rs[0].Err == "" {
		t.Fatalf("tdrop failure not recorded: %+v", rs[0])
	}
	if !rs[1].OK {
		t.Fatalf("later should have succeeded despite the earlier failure: %+v", rs[1])
	}
	mailCount := func() int {
		var c int
		testPool.QueryRow(ctx, `SELECT count(*) FROM mem_later WHERE root = $1 AND text LIKE '%halfbad expired%'`, root).Scan(&c)
		return c
	}
	if mailCount() != 1 {
		t.Fatalf("want exactly one self-mail, got %d", mailCount())
	}
	// A second janitor pass must not re-run anything (session already ended).
	if err := Expire(ctx, e.d); err != nil {
		t.Fatal(err)
	}
	if mailCount() != 1 {
		t.Fatalf("second pass re-ran the plan: %d self-mails", mailCount())
	}
}

// --- resume section ------------------------------------------------------------------------------

func TestResumeSection(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// expired session.
	rootA, _ := newRoot(t)
	sidA := core.NewID('e')
	fired, _ := json.Marshal([]fireResult{{Op: "tdrop", OK: true}, {Op: "cp", OK: true}, {Op: "later", OK: false, Err: "x"}})
	if _, err := testPool.Exec(ctx, `INSERT INTO sessions (id, root, owner, name, started, last_beat, ttl_s, ended, cause, fired)
		VALUES ($1, $2, $2, 'bignight', now() - interval '20 minutes', now() - interval '12 minutes', 60, now() - interval '8 minutes', 'expired', $3)`,
		sidA, rootA, fired); err != nil {
		t.Fatal(err)
	}
	lines := resume(ctx, e.d.DB, rootA)
	if len(lines) != 1 || !strings.Contains(lines[0], "last session: bignight expired") ||
		!strings.Contains(lines[0], "(fired 2/3)") || !strings.Contains(lines[0], "min") {
		t.Fatalf("expired resume line wrong: %q", lines)
	}

	// goodbye session.
	rootB, _ := newRoot(t)
	sidB := core.NewID('e')
	if _, err := testPool.Exec(ctx, `INSERT INTO sessions (id, root, owner, name, started, last_beat, ttl_s, ended, cause, summary)
		VALUES ($1, $2, $2, 'clean', now() - interval '5 minutes', now(), 60, now(), 'goodbye', 'all shipped')`,
		sidB, rootB); err != nil {
		t.Fatal(err)
	}
	lines = resume(ctx, e.d.DB, rootB)
	if len(lines) != 1 || !strings.Contains(lines[0], "last session: clean goodbye all shipped") {
		t.Fatalf("goodbye resume line wrong: %q", lines)
	}

	// no ended session -> nothing.
	rootC, _ := newRoot(t)
	if lines := resume(ctx, e.d.DB, rootC); lines != nil {
		t.Fatalf("expected no resume line, got %q", lines)
	}
}

// --- placeholders --------------------------------------------------------------------------------

func TestPlaceholders(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, _ := newRoot(t)

	// A live checkpoint and a live task claim feed {cp} and {task}.
	cpID := core.NewID('c')
	if _, err := testPool.Exec(ctx, `INSERT INTO checkpoints (id, root, owner, name, seq, created, expires_at)
		VALUES ($1, $2, $2, 'wip', 1, now(), now() + interval '1 day')`, cpID, root); err != nil {
		t.Fatal(err)
	}
	n := int64(800000000) + int64(time.Now().UnixNano()%100000000)
	if _, err := testPool.Exec(ctx, `INSERT INTO tasks (n, id, root, state, title) VALUES ($1, $2, $2, 'open', 't')`, n, root); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO task_claims (n, id, root, until) VALUES ($1, $2, $2, now() + interval '1 hour')`, n, root); err != nil {
		t.Fatal(err)
	}

	ph := resolvePlaceholders(ctx, e.d.DB, root, "mysession")
	if ph.cp != cpID {
		t.Fatalf("{cp} = %q, want %q", ph.cp, cpID)
	}
	if ph.task != fmt.Sprintf("t:%d", n) {
		t.Fatalf("{task} = %q, want t:%d", ph.task, n)
	}
	if ph.name != "mysession" || ph.now == "" {
		t.Fatalf("{name}/{now} unset: %+v", ph)
	}
	got := ph.apply("cp={cp} name={name} task={task} at={now}")
	want := fmt.Sprintf("cp=%s name=mysession task=t:%d at=%s", cpID, n, ph.now)
	if got != want {
		t.Fatalf("apply:\n got %q\nwant %q", got, want)
	}
	// No placeholders -> string untouched.
	if s := ph.apply("plain text"); s != "plain text" {
		t.Fatalf("apply mangled a plain string: %q", s)
	}
}
