package bounty

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
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/testdb"
)

var (
	testPool *pgxpool.Pool
	levels   sync.Map // root -> level (core.LevelFn stub)
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
	} else if pool, done := testdb.Open("bounty", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping bounty DB tests")
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
	s   *svc
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
	return &tenv{d: d, s: svcFor(d), srv: srv}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

// do sends a request from a random client IP and returns status and body.
func (e *tenv) do(t *testing.T, method, path, token, body string, hdr ...string) (int, string) {
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
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimRight(string(b), "\n")
}

// mkRoot inserts a root registered from ip (5 days old) with credits/earned and rep; rep >= 5 is
// L2 (verified_noncompute = 1), rep 1 is L1, rep 0 is L0. Returns (id, token).
func mkRoot(t *testing.T, ip string, credits, earned int64, rep int) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, earned, reg_ip, rep, created, verified_noncompute)
		VALUES ($1, 'r', NULL, $1, $2, $3, $4, $5, $6, now() - interval '5 days', 1)`, id, h, credits, earned, ip, rep); err != nil {
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

// claim hands the claim on n to root (fence returned).
func (e *tenv) claim(t *testing.T, n int64, root string) int64 {
	t.Helper()
	f, err := forge.ClaimAssign(context.Background(), testPool, n, root, root, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// bounty posts a bounty on task n and returns its id; extra is appended inside the JSON object.
func (e *tenv) bounty(t *testing.T, tok string, n, credits int64, extra string) string {
	t.Helper()
	st, body := e.do(t, "POST", "/v1/bt", tok, fmt.Sprintf(`{"task":%d,"credits":%d%s}`, n, credits, extra))
	if st != 201 || !strings.HasPrefix(body, "ok b") {
		t.Fatalf("create: %d %s", st, body)
	}
	return strings.Fields(body)[1]
}

func (e *tenv) submit(t *testing.T, tok, id, body string) string {
	t.Helper()
	st, out := e.do(t, "POST", "/v1/bt/"+id+"/submit", tok, body)
	if st != 200 || !strings.HasPrefix(out, "ok "+id+" submitted") {
		t.Fatalf("submit: %d %s", st, out)
	}
	return out
}

// first is the head line of a text reply (the next: tail follows it).
func first(body string) string { return strings.SplitN(body, "\n", 2)[0] }

func row(t *testing.T, id string) *bounty {
	t.Helper()
	b, err := load(context.Background(), testPool, id, false)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func bal(t *testing.T, id string) (credits, earned int64) {
	t.Helper()
	if err := testPool.QueryRow(context.Background(), `SELECT credits, earned FROM identities WHERE id = $1`, id).Scan(&credits, &earned); err != nil {
		t.Fatal(err)
	}
	return
}

func wantBal(t *testing.T, who, id string, credits, earned int64) {
	t.Helper()
	c, e := bal(t, id)
	if c != credits || e != earned {
		t.Fatalf("%s balance = %d/%d want %d/%d", who, c, e, credits, earned)
	}
}

func ledgerCount(t *testing.T, where string, args ...any) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM ledger WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func taskState(t *testing.T, n int64) string {
	t.Helper()
	var s string
	if err := testPool.QueryRow(context.Background(), `SELECT state FROM tasks WHERE n = $1`, n).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func lastNote(t *testing.T, n int64) string {
	t.Helper()
	var s string
	if err := testPool.QueryRow(context.Background(), `SELECT text FROM task_notes WHERE n = $1 ORDER BY id DESC LIMIT 1`, n).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func holder(t *testing.T, n int64) string {
	t.Helper()
	_, root, err := forge.ClaimFence(context.Background(), testPool, n)
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func conserved(t *testing.T, e *tenv, step string) core.AuditReport {
	t.Helper()
	a, err := core.LedgerAudit(context.Background(), testPool, e.d.EscrowSQL())
	if err != nil {
		t.Fatal(err)
	}
	if !a.OK() {
		t.Fatalf("%s: %s", step, a.Line())
	}
	return a
}

func exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

func onDone(t *testing.T, j *compute.Job) {
	t.Helper()
	err := core.Tx(context.Background(), testPool, func(tx pgx.Tx) error { return OnDone(context.Background(), tx, j) })
	if err != nil {
		t.Fatal(err)
	}
}

// minWasm is a valid core module exporting an empty _start; wasmFor tags it with a custom section
// so every test owns a distinct blob.
var minWasm = []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
	1, 4, 1, 0x60, 0, 0,
	3, 2, 1, 0,
	7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0,
	10, 4, 1, 2, 0, 0x0b}

func uleb(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

func wasmFor(tag string) []byte {
	body := append(uleb(1), 't')
	body = append(body, tag...)
	sec := append([]byte{0}, uleb(len(body))...)
	return append(slices.Clone(minWasm), append(sec, body...)...)
}

func uniq() string {
	var b [4]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (e *tenv) put(t *testing.T, root string, b []byte) string {
	t.Helper()
	h, err := compute.PutBlobBytes(context.Background(), e.d, root, b, "")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCreateEscrowEarnedOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	grant, gtok := mkRoot(t, "10.1.1.1", 100, 0, 5)
	n := e.task(t, gtok, "grant only")
	st, body := e.do(t, "POST", "/v1/bt", gtok, fmt.Sprintf(`{"task":%d,"credits":40}`, n))
	if st != 402 || !strings.HasPrefix(body, "err credits earned required") {
		t.Fatalf("grant-only create: %d %s", st, body)
	}
	wantBal(t, "grant root", grant, 100, 0)

	cr, ctok := mkRoot(t, "10.1.2.1", 100, 100, 5)
	n2 := e.task(t, ctok, "earned")
	req := fmt.Sprintf(`{"task":%d,"credits":40,"deadline_h":48}`, n2)
	st, body = e.do(t, "POST", "/v1/bt", ctok, req, "Idempotency-Key", "k1")
	if st != 201 || !strings.HasPrefix(body, "ok b") || !strings.Contains(body, " task=#"+itoa(n2)) {
		t.Fatalf("create: %d %s", st, body)
	}
	id := strings.Fields(body)[1]
	wantBal(t, "creator", cr, 60, 60)
	if ledgerCount(t, `from_id = $1 AND to_id = 'hold' AND class = 'earned' AND reason = 'reserve' AND amount = 40`, cr) != 1 {
		t.Fatal("escrow ledger row missing")
	}
	b := row(t, id)
	if b.State != "open" || b.Held != 40 || b.Review != "creator" || b.Task != n2 || time.Until(b.Deadline) < 47*time.Hour {
		t.Fatalf("row: %+v", b)
	}
	if a := conserved(t, e, "create"); a.Escrow < 40 {
		t.Fatalf("escrow not registered in the audit: %+v", a)
	}
	// idempotent replay
	st, body = e.do(t, "POST", "/v1/bt", ctok, req, "Idempotency-Key", "k1")
	if st != 201 || !strings.Contains(body, "idem=replay") || strings.Fields(body)[1] != id {
		t.Fatalf("replay: %d %s", st, body)
	}
	wantBal(t, "creator after replay", cr, 60, 60)
	// one live bounty per task
	if st, body = e.do(t, "POST", "/v1/bt", ctok, fmt.Sprintf(`{"task":%d,"credits":10}`, n2)); st != 409 || !strings.HasPrefix(body, "err dup") {
		t.Fatalf("dup: %d %s", st, body)
	}
	// validation and caps
	for _, c := range []struct {
		body string
		want int
		msg  string
	}{
		{fmt.Sprintf(`{"task":%d,"credits":3}`, n2), 400, "credits"},
		{fmt.Sprintf(`{"task":%d,"credits":10,"deadline_h":400}`, n2), 400, "deadline_h"},
		{fmt.Sprintf(`{"task":%d,"credits":10,"review":"peer"}`, n2), 400, "peer"},
		{fmt.Sprintf(`{"task":%d,"credits":10,"review":"tests"}`, n2), 400, "test"},
		{`{"credits":10}`, 400, "task"},
	} {
		if st, body = e.do(t, "POST", "/v1/bt", ctok, c.body); st != c.want || !strings.Contains(body, c.msg) {
			t.Fatalf("%s: %d %s", c.body, st, body)
		}
	}
	_, l0tok := mkRoot(t, "10.1.3.1", 100, 100, 0)
	n3 := e.task(t, l0tok, "l0")
	if st, body = e.do(t, "POST", "/v1/bt", l0tok, fmt.Sprintf(`{"task":%d,"credits":10}`, n3)); st != 429 || !strings.HasPrefix(body, "err quota bounties") {
		t.Fatalf("L0: %d %s", st, body)
	}
	other, otok := mkRoot(t, "10.1.4.1", 100, 100, 5)
	if st, body = e.do(t, "POST", "/v1/bt", otok, fmt.Sprintf(`{"task":%d,"credits":10}`, n3)); st != 403 {
		t.Fatalf("other's task: %d %s", st, body)
	}
	_ = other
	// MCP op with a new task
	ops := Ops(e.d)
	out, err := ops["bt"](ctx, e.ident(t, ctok), json.RawMessage(`{"task":{"title":"from op","tags":["x"]},"credits":5}`))
	if err != nil || !strings.HasPrefix(out, "ok b") || !strings.Contains(out, " task=#") {
		t.Fatalf("op bt: %q %v", out, err)
	}
	wantBal(t, "creator after op", cr, 55, 55)
	for k := range ops {
		if _, ok := OpMeta[k]; !ok {
			t.Fatalf("OpMeta lacks %s", k)
		}
	}
	if len(ops) != len(OpMeta) {
		t.Fatal("OpMeta/Ops mismatch")
	}
	// resume and me lines
	if lines := e.s.resume(ctx, cr); len(lines) == 0 || lines[0] != "bounties: 2 open" {
		t.Fatalf("resume: %q", lines)
	}
	if me := e.s.meLine(ctx, e.ident(t, ctok)); len(me) != 1 || !strings.HasPrefix(me[0], "escrow=45 bounties=2/") {
		t.Fatalf("me: %q", me)
	}
	conserved(t, e, "end")
}

func TestSubmitRequiresClaimAndFence(t *testing.T) {
	e := newEnv(t)
	_, ctok := mkRoot(t, "10.2.1.1", 100, 100, 5)
	hu, htok := mkRoot(t, "10.2.2.1", 100, 0, 5)
	n := e.task(t, ctok, "fence")
	id := e.bounty(t, ctok, n, 40, "")
	st, body := e.do(t, "POST", "/v1/bt/"+id+"/submit", htok, `{"text":"done","fence":0}`)
	if st != 409 || !strings.HasPrefix(body, "err taken claim required") {
		t.Fatalf("no claim: %d %s", st, body)
	}
	fence := e.claim(t, n, hu)
	if st, body = e.do(t, "POST", "/v1/bt/"+id+"/submit", htok, fmt.Sprintf(`{"text":"done","fence":%d}`, fence+1)); st != 409 || !strings.HasPrefix(body, "err fenced") {
		t.Fatalf("wrong fence: %d %s", st, body)
	}
	if st, body = e.do(t, "POST", "/v1/bt/"+id+"/submit", htok, fmt.Sprintf(`{"text":"a","out":"%s","fence":%d}`, strings.Repeat("a", 64), fence)); st != 400 {
		t.Fatalf("out+text: %d %s", st, body)
	}
	if st, body = e.do(t, "POST", "/v1/bt/"+id+"/submit", ctok, fmt.Sprintf(`{"text":"mine","fence":%d}`, fence)); st != 403 {
		t.Fatalf("own bounty: %d %s", st, body)
	}
	out := e.submit(t, htok, id, fmt.Sprintf(`{"text":"done","fence":%d}`, fence))
	if !strings.HasPrefix(out, "ok "+id+" submitted bond=4 review=creator") {
		t.Fatalf("submit reply: %s", out)
	}
	wantBal(t, "hunter", hu, 96, 0)
	b := row(t, id)
	if b.State != "submitted" || b.Hunter != hu || b.SubFence != fence || b.SubText != "done" || b.Bond != 4 || b.SeenAt != nil {
		t.Fatalf("row: %+v", b)
	}
	var bstate string
	var bn int64
	if err := testPool.QueryRow(context.Background(), `SELECT state, credits FROM bonds WHERE ref = $1 AND root = $2`, id, hu).Scan(&bstate, &bn); err != nil || bstate != "held" || bn != 4 {
		t.Fatalf("bond: %s %d %v", bstate, bn, err)
	}
	if st, body = e.do(t, "POST", "/v1/bt/"+id+"/submit", htok, fmt.Sprintf(`{"text":"again","fence":%d}`, fence)); st != 409 {
		t.Fatalf("resubmit: %d %s", st, body)
	}
	conserved(t, e, "submitted")
}

func TestAcceptPaysAndCloses(t *testing.T) {
	e := newEnv(t)
	cr, ctok := mkRoot(t, "10.3.1.1", 100, 100, 5)
	hu, htok := mkRoot(t, "10.3.2.1", 100, 0, 5)
	n := e.task(t, ctok, "accept")
	id := e.bounty(t, ctok, n, 40, "")
	fence := e.claim(t, n, hu)
	e.submit(t, htok, id, fmt.Sprintf(`{"text":"work","fence":%d}`, fence))
	if st, body := e.do(t, "POST", "/v1/bt/"+id+"/accept", htok, ""); st != 403 {
		t.Fatalf("hunter accept: %d %s", st, body)
	}
	st, body := e.do(t, "POST", "/v1/bt/"+id+"/accept", ctok, "")
	if st != 200 || first(body) != fmt.Sprintf("ok %s paid 40 to %s", id, hu) {
		t.Fatalf("accept: %d %s", st, body)
	}
	wantBal(t, "hunter", hu, 140, 40)
	wantBal(t, "creator", cr, 60, 60)
	b := row(t, id)
	if b.State != "paid" || b.Payout != 40 || b.Held != 0 || b.Closed == nil {
		t.Fatalf("row: %+v", b)
	}
	if taskState(t, n) != "done" {
		t.Fatal("task not closed")
	}
	if holder(t, n) != "" {
		t.Fatal("claim still live")
	}
	if !strings.Contains(lastNote(t, n), "paid 40cr to "+hu) {
		t.Fatalf("note: %s", lastNote(t, n))
	}
	if st, body = e.do(t, "POST", "/v1/bt/"+id+"/accept", ctok, ""); st != 409 {
		t.Fatalf("second accept: %d %s", st, body)
	}
	if st, body = e.do(t, "GET", "/v1/bt/"+id+"?f=json", htok, ""); st != 200 || !strings.Contains(body, `"state":"paid"`) || !strings.Contains(body, `"payout":40`) {
		t.Fatalf("json: %d %s", st, body)
	}
	if st, body = e.do(t, "GET", "/v1/bt/"+id, htok, ""); st != 200 || !strings.HasPrefix(body, id+" paid 40cr task=#"+itoa(n)) || !strings.Contains(body, "paid: 40 to "+hu) {
		t.Fatalf("text: %d %s", st, body)
	}
	conserved(t, e, "paid")
}

func TestRejectReopensBondRules(t *testing.T) {
	e := newEnv(t)
	cr, ctok := mkRoot(t, "10.4.1.1", 100, 100, 5)
	h1, h1tok := mkRoot(t, "10.4.2.1", 100, 0, 5)
	h2, h2tok := mkRoot(t, "10.4.3.1", 100, 0, 5)
	n := e.task(t, ctok, "reject")
	id := e.bounty(t, ctok, n, 40, "")
	f := e.claim(t, n, h1)
	e.submit(t, h1tok, id, fmt.Sprintf(`{"text":"meh","fence":%d}`, f))
	st, body := e.do(t, "POST", "/v1/bt/"+id+"/reject", ctok, `{"why":"not what I asked"}`)
	if st != 200 || first(body) != "ok "+id+" open" {
		t.Fatalf("reject: %d %s", st, body)
	}
	b := row(t, id)
	if b.State != "open" || b.RejectedAt == nil || b.Rejects != 1 || b.Hunter != h1 {
		t.Fatalf("row: %+v", b)
	}
	if holder(t, n) != "" {
		t.Fatal("claim not dropped")
	}
	wantBal(t, "h1", h1, 100, 0)
	if !strings.Contains(lastNote(t, n), "rejected: not what I asked") {
		t.Fatalf("note: %s", lastNote(t, n))
	}
	// one submission per hunter
	f = e.claim(t, n, h1)
	if st, body = e.do(t, "POST", "/v1/bt/"+id+"/submit", h1tok, fmt.Sprintf(`{"text":"again","fence":%d}`, f)); st != 409 || !strings.HasPrefix(body, "err dup") {
		t.Fatalf("resubmit: %d %s", st, body)
	}
	wantBal(t, "h1 after dup", h1, 100, 0)
	// another hunter may
	f = e.claim(t, n, h2)
	e.submit(t, h2tok, id, fmt.Sprintf(`{"text":"better","fence":%d}`, f))
	wantBal(t, "h2", h2, 96, 0)
	// two Distinct peer reviewers confirm spam: bond forfeited, escrow (minus fees) back
	r1, _ := mkRoot(t, "10.4.4.1", 10, 0, 5)
	r2, _ := mkRoot(t, "10.4.5.1", 10, 0, 5)
	err := core.Tx(context.Background(), testPool, func(tx pgx.Tx) error {
		return PeerVerdict(context.Background(), tx, id, map[string]string{r1: "spam", r2: "spam"})
	})
	if err != nil {
		t.Fatal(err)
	}
	b = row(t, id)
	if b.State != "refunded" {
		t.Fatalf("after spam: %+v", b)
	}
	var bstate string
	testPool.QueryRow(context.Background(), `SELECT state FROM bonds WHERE ref = $1 AND root = $2`, id, h2).Scan(&bstate)
	if bstate != "forfeited" || ledgerCount(t, `from_id = 'hold' AND to_id = 'burn' AND reason = 'bond' AND ref = $1 AND amount = 4`, id) != 1 {
		t.Fatalf("bond %s not burnt", bstate)
	}
	wantBal(t, "h2 forfeited", h2, 96, 0)
	wantBal(t, "r1", r1, 14, 4)
	wantBal(t, "r2", r2, 14, 4)
	wantBal(t, "creator", cr, 92, 92)
	if taskState(t, n) != "open" {
		t.Fatal("task should stay open")
	}
	conserved(t, e, "spam")
}

func TestDefaultAccept72hGuardedOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, ctok := mkRoot(t, "10.5.1.1", 100, 100, 5)
	hu, htok := mkRoot(t, "10.5.2.1", 100, 0, 5)
	n := e.task(t, ctok, "default")
	id := e.bounty(t, ctok, n, 40, "")
	f := e.claim(t, n, hu)
	e.submit(t, htok, id, fmt.Sprintf(`{"text":"work","fence":%d}`, f))
	if st, body := e.do(t, "GET", "/v1/bt/"+id, ctok, ""); st != 200 || !strings.Contains(body, "seen "+core.Date(time.Now())) {
		t.Fatalf("creator read: %d %s", st, body)
	}
	if row(t, id).SeenAt == nil {
		t.Fatal("read receipt missing")
	}
	exec(t, `UPDATE bounties SET submitted_at = now() - interval '73 hours', sub_seen_at = now() - interval '72 hours' WHERE id = $1`, id)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.s.janitor(ctx); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	b := row(t, id)
	if b.State != "paid" || b.Payout != 40 {
		t.Fatalf("row: %+v", b)
	}
	if n := ledgerCount(t, `from_id = 'hold' AND to_id = $1 AND reason = 'earn'`, hu); n != 1 {
		t.Fatalf("payout rows = %d", n)
	}
	wantBal(t, "hunter", hu, 140, 40)
	if taskState(t, n) != "done" {
		t.Fatal("task not closed")
	}
	conserved(t, e, "default-accept")
}

func TestDeadlineRefund(t *testing.T) {
	e := newEnv(t)
	cr, ctok := mkRoot(t, "10.6.1.1", 100, 100, 5)
	hu, htok := mkRoot(t, "10.6.2.1", 100, 0, 5)
	n := e.task(t, ctok, "deadline")
	id := e.bounty(t, ctok, n, 40, `,"deadline_h":1`)
	wantBal(t, "creator", cr, 60, 60)
	exec(t, `UPDATE bounties SET deadline = now() - interval '1 minute' WHERE id = $1`, id)
	if err := e.s.janitor(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := row(t, id)
	if b.State != "refunded" || b.Held != 0 {
		t.Fatalf("row: %+v", b)
	}
	wantBal(t, "creator refunded", cr, 100, 100)
	if ledgerCount(t, `from_id = 'hold' AND to_id = $1 AND reason = 'refund' AND class = 'earned' AND amount = 40`, cr) != 1 {
		t.Fatal("refund row missing")
	}
	f := e.claim(t, n, hu)
	if st, body := e.do(t, "POST", "/v1/bt/"+id+"/submit", htok, fmt.Sprintf(`{"text":"late","fence":%d}`, f)); st != 409 {
		t.Fatalf("late submit: %d %s", st, body)
	}
	if st, body := e.do(t, "GET", "/v1/bt?s=open", htok, ""); st != 200 || strings.Contains(body, id) {
		t.Fatalf("list still shows refunded: %d %s", st, body)
	}
	conserved(t, e, "refund")
}

func TestSameSuperNoPayoutRule(t *testing.T) {
	e := newEnv(t)
	cr, ctok := mkRoot(t, "10.7.1.1", 100, 100, 5)
	hu, htok := mkRoot(t, "10.7.1.2", 100, 0, 5) // same /24 as the creator
	n := e.task(t, ctok, "same super")
	id := e.bounty(t, ctok, n, 40, "")
	f := e.claim(t, n, hu)
	if out := e.submit(t, htok, id, fmt.Sprintf(`{"text":"work","fence":%d}`, f)); !strings.Contains(out, "same super-group") {
		t.Fatalf("no warning: %s", out)
	}
	st, body := e.do(t, "POST", "/v1/bt/"+id+"/accept", ctok, "")
	if st != 200 || !strings.HasPrefix(body, "ok "+id+" paid 0 to "+hu) || !strings.Contains(body, "withheld") {
		t.Fatalf("accept: %d %s", st, body)
	}
	wantBal(t, "hunter", hu, 100, 0)
	wantBal(t, "creator", cr, 100, 100)
	b := row(t, id)
	if b.State != "paid" || b.Payout != 0 {
		t.Fatalf("row: %+v", b)
	}
	if taskState(t, n) != "done" {
		t.Fatal("task not closed")
	}
	if ledgerCount(t, `to_id = $1 AND reason = 'earn'`, hu) != 0 {
		t.Fatal("hunter earned")
	}
	conserved(t, e, "same super")
}

func TestLedgerConservationWithBounties(t *testing.T) {
	e := newEnv(t)
	conserved(t, e, "start")
	cr, ctok := mkRoot(t, "10.8.1.1", 300, 300, 5)
	hu, htok := mkRoot(t, "10.8.2.1", 100, 0, 5)
	n := e.task(t, ctok, "conserve 1")
	id := e.bounty(t, ctok, n, 50, "")
	conserved(t, e, "escrowed")
	f := e.claim(t, n, hu)
	e.submit(t, htok, id, fmt.Sprintf(`{"text":"w","fence":%d}`, f))
	conserved(t, e, "bond held")
	if st, body := e.do(t, "POST", "/v1/bt/"+id+"/accept", ctok, ""); st != 200 {
		t.Fatalf("accept: %d %s", st, body)
	}
	conserved(t, e, "paid")
	n2 := e.task(t, ctok, "conserve 2")
	id2 := e.bounty(t, ctok, n2, 20, `,"deadline_h":1`)
	exec(t, `UPDATE bounties SET deadline = now() - interval '1 minute' WHERE id = $1`, id2)
	if err := e.s.janitor(context.Background()); err != nil {
		t.Fatal(err)
	}
	conserved(t, e, "refunded")
	n3 := e.task(t, ctok, "conserve 3")
	id3 := e.bounty(t, ctok, n3, 30, "")
	f = e.claim(t, n3, hu)
	e.submit(t, htok, id3, fmt.Sprintf(`{"text":"w","fence":%d}`, f))
	if st, body := e.do(t, "POST", "/v1/bt/"+id3+"/reject", ctok, `{"why":"no"}`); st != 200 {
		t.Fatalf("reject: %d %s", st, body)
	}
	a := conserved(t, e, "rejected")
	var held int64
	if err := testPool.QueryRow(context.Background(), `SELECT (SELECT coalesce(sum(held), 0) FROM bounties WHERE state IN ('open', 'submitted', 'rejected'))
		+ (SELECT coalesce(sum(credits), 0) FROM bonds WHERE state = 'held')`).Scan(&held); err != nil {
		t.Fatal(err)
	}
	if a.Escrow != held || held < 30 {
		t.Fatalf("audit escrow %d != held %d", a.Escrow, held)
	}
	wantBal(t, "creator", cr, 220, 220)
	wantBal(t, "hunter", hu, 150, 50)
	// purge of the creator refunds the open bounty, then core burns; books stay exact
	if _, err := e.d.Purge(context.Background(), cr); err != nil {
		t.Fatal(err)
	}
	if row(t, id3).State != "refunded" {
		t.Fatal("purge did not refund")
	}
	conserved(t, e, "purged")
}

func TestTaskRenderHook(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cr, ctok := mkRoot(t, "10.9.1.1", 100, 100, 5)
	hu, htok := mkRoot(t, "10.9.2.1", 100, 0, 5)
	n := e.task(t, ctok, "render")
	id := e.bounty(t, ctok, n, 40, "")
	b := row(t, id)
	line := fmt.Sprintf("bounty: %s 40cr until %s", id, core.Date(b.Deadline))
	st, body := e.do(t, "GET", "/v1/t/"+itoa(n), htok, "")
	if st != 200 || !strings.Contains(body, "\n"+line+"\n") && !strings.HasSuffix(body, "\n"+line) {
		t.Fatalf("task detail: %d %s", st, body)
	}
	if lines := TaskExtra(ctx, testPool, n); len(lines) != 1 || lines[0] != line {
		t.Fatalf("hook: %q", lines)
	}
	f := e.claim(t, n, hu)
	e.submit(t, htok, id, fmt.Sprintf(`{"text":"work","fence":%d}`, f))
	if lines := TaskExtra(ctx, testPool, n); len(lines) != 1 || lines[0] != line+" submitted" {
		t.Fatalf("hook after submit: %q", lines)
	}
	// read receipt through the task detail: only the creator tree counts
	ReaderRootFn = func(context.Context) string { return hu }
	t.Cleanup(func() { ReaderRootFn = nil })
	e.do(t, "GET", "/v1/t/"+itoa(n), htok, "")
	if row(t, id).SeenAt != nil {
		t.Fatal("hunter read counted as receipt")
	}
	ReaderRootFn = func(context.Context) string { return cr }
	e.do(t, "GET", "/v1/t/"+itoa(n), ctok, "")
	if row(t, id).SeenAt == nil {
		t.Fatal("creator read not recorded")
	}
	// hidden bounties are not rendered
	if err := hide(ctx, testPool, id); err != nil {
		t.Fatal(err)
	}
	if lines := TaskExtra(ctx, testPool, n); len(lines) != 0 {
		t.Fatalf("hidden rendered: %q", lines)
	}
	if st, _ := e.do(t, "GET", "/v1/bt/"+id, htok, ""); st != 200 { // the hunter is a party
		t.Fatalf("party read of hidden: %d", st)
	}
	_, otok := mkRoot(t, "10.9.3.1", 10, 0, 5)
	if st, _ := e.do(t, "GET", "/v1/bt/"+id, otok, ""); st != 404 {
		t.Fatalf("stranger read of hidden: %d", st)
	}
	if err := restore(ctx, testPool, id); err != nil {
		t.Fatal(err)
	}
	if typ, title, url, ok := e.s.resolve(ctx, id); !ok || typ != "bounty" || url != "/v1/bt/"+id || !strings.Contains(title, "40cr") {
		t.Fatalf("resolve: %s %s %s %v", typ, title, url, ok)
	}
}

func TestReadReceiptGatedDefaultAccept(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cr, ctok := mkRoot(t, "10.10.1.1", 100, 100, 5)
	hu, htok := mkRoot(t, "10.10.2.1", 100, 0, 5)
	n := e.task(t, ctok, "receipt")
	id := e.bounty(t, ctok, n, 40, "")
	f := e.claim(t, n, hu)
	e.submit(t, htok, id, fmt.Sprintf(`{"text":"work","fence":%d}`, f))
	exec(t, `UPDATE bounties SET submitted_at = now() - interval '73 hours' WHERE id = $1`, id)
	if err := e.s.janitor(ctx); err != nil {
		t.Fatal(err)
	}
	if b := row(t, id); b.State != "submitted" {
		t.Fatalf("paid without a read receipt: %+v", b)
	}
	if lines := e.s.resume(ctx, cr); !slices.ContainsFunc(lines, func(l string) bool {
		return strings.HasPrefix(l, "awaiting you: bounty "+id+" submission (auto-refund ")
	}) {
		t.Fatalf("resume: %q", lines)
	}
	e.do(t, "GET", "/v1/bt/"+id, htok, "")
	if row(t, id).SeenAt != nil {
		t.Fatal("hunter read counted")
	}
	if st, body := e.do(t, "GET", "/v1/bt/"+id, ctok, ""); st != 200 || !strings.Contains(body, "default-accept: ") {
		t.Fatalf("creator read: %d %s", st, body)
	}
	if row(t, id).SeenAt == nil {
		t.Fatal("receipt not set")
	}
	if err := e.s.janitor(ctx); err != nil {
		t.Fatal(err)
	}
	if b := row(t, id); b.State != "paid" || b.Payout != 40 {
		t.Fatalf("not paid after receipt: %+v", b)
	}
	wantBal(t, "hunter", hu, 140, 40)
	conserved(t, e, "receipt")
}

func TestNeverSeenAutoRefund(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cr, ctok := mkRoot(t, "10.11.1.1", 100, 100, 5)
	hu, htok := mkRoot(t, "10.11.2.1", 100, 0, 5)
	n := e.task(t, ctok, "unread")
	id := e.bounty(t, ctok, n, 40, `,"deadline_h":1`)
	f := e.claim(t, n, hu)
	e.submit(t, htok, id, fmt.Sprintf(`{"text":"my work","fence":%d}`, f))
	// greatest(deadline, submitted + 72 h) + 72 h is still ahead
	exec(t, `UPDATE bounties SET deadline = now() - interval '100 hours', submitted_at = now() - interval '100 hours' WHERE id = $1`, id)
	if err := e.s.janitor(ctx); err != nil {
		t.Fatal(err)
	}
	if row(t, id).State != "submitted" {
		t.Fatal("refunded too early")
	}
	exec(t, `UPDATE bounties SET deadline = now() - interval '200 hours', submitted_at = now() - interval '150 hours' WHERE id = $1`, id)
	if err := e.s.janitor(ctx); err != nil {
		t.Fatal(err)
	}
	b := row(t, id)
	if b.State != "refunded" || b.Held != 0 {
		t.Fatalf("row: %+v", b)
	}
	wantBal(t, "creator", cr, 100, 100)
	wantBal(t, "hunter", hu, 100, 0)
	if taskState(t, n) != "open" {
		t.Fatal("task should stay open")
	}
	if note := lastNote(t, n); !strings.Contains(note, "submission by "+hu) || !strings.Contains(note, "my work") {
		t.Fatalf("note: %s", note)
	}
	conserved(t, e, "never seen")
}

func TestHunterEscalate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cr, ctok := mkRoot(t, "10.12.1.1", 100, 100, 5)
	hu, htok := mkRoot(t, "10.12.2.1", 100, 0, 5)
	n := e.task(t, ctok, "escalate")
	id := e.bounty(t, ctok, n, 40, "")
	f := e.claim(t, n, hu)
	e.submit(t, htok, id, fmt.Sprintf(`{"text":"work","fence":%d}`, f))
	if st, body := e.do(t, "POST", "/v1/bt/"+id+"/escalate", htok, ""); st != 409 || !strings.Contains(body, "unavailable") {
		t.Fatalf("without reviewers: %d %s", st, body)
	}
	var calls []int64
	PeerReviewFn = func(ctx context.Context, q core.Q, task int64, escrow int64) error {
		calls = append(calls, task)
		return nil
	}
	t.Cleanup(func() { PeerReviewFn = nil })
	if st, body := e.do(t, "POST", "/v1/bt/"+id+"/escalate", htok, ""); st != 409 || !strings.Contains(body, "after 72 h unread or after a reject") {
		t.Fatalf("too early: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/bt/"+id+"/reject", ctok, `{"why":"nope"}`); st != 200 {
		t.Fatalf("reject: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/bt/"+id+"/escalate", ctok, ""); st != 403 {
		t.Fatalf("creator escalate: %d %s", st, body)
	}
	st, body := e.do(t, "POST", "/v1/bt/"+id+"/escalate", htok, "")
	if st != 200 || first(body) != "ok "+id+" escalated bond=2" {
		t.Fatalf("escalate: %d %s", st, body)
	}
	wantBal(t, "hunter", hu, 98, 0)
	b := row(t, id)
	if b.State != "submitted" || b.EscalatedAt == nil || len(calls) != 1 || calls[0] != n {
		t.Fatalf("row: %+v calls=%v", b, calls)
	}
	if st, body = e.do(t, "POST", "/v1/bt/"+id+"/escalate", htok, ""); st != 409 {
		t.Fatalf("dup escalate: %d %s", st, body)
	}
	if st, body = e.do(t, "POST", "/v1/bt/"+id+"/reject", ctok, `{"why":"again"}`); st != 409 || !strings.Contains(body, "escalated") {
		t.Fatalf("reject while escalated: %d %s", st, body)
	}
	r1, _ := mkRoot(t, "10.12.3.1", 10, 0, 5)
	r2, _ := mkRoot(t, "10.12.4.1", 10, 0, 5)
	verdict := func(id string, v1, v2 string) error {
		return core.Tx(ctx, testPool, func(tx pgx.Tx) error { return PeerVerdict(ctx, tx, id, map[string]string{r1: v1, r2: v2}) })
	}
	// non-distinct reviewers refused
	r3, _ := mkRoot(t, "10.12.3.2", 10, 0, 5)
	if err := core.Tx(ctx, testPool, func(tx pgx.Tx) error { return PeerVerdict(ctx, tx, id, map[string]string{r1: "accept", r3: "accept"}) }); err == nil || !strings.Contains(err.Error(), "not distinct") {
		t.Fatalf("same-super reviewers: %v", err)
	}
	if err := verdict(id, "accept", "accept"); err != nil {
		t.Fatal(err)
	}
	b = row(t, id)
	if b.State != "paid" || b.Payout != 32 {
		t.Fatalf("after accept: %+v", b)
	}
	wantBal(t, "hunter paid", hu, 132, 32)
	wantBal(t, "r1", r1, 14, 4)
	wantBal(t, "r2", r2, 14, 4)
	wantBal(t, "creator", cr, 60, 60)
	if taskState(t, n) != "done" {
		t.Fatal("task not closed")
	}
	conserved(t, e, "escalated accept")
	// split after an escalation refunds the creator (minus the reviewer fees)
	n2 := e.task(t, ctok, "escalate 2")
	id2 := e.bounty(t, ctok, n2, 40, "")
	f = e.claim(t, n2, hu)
	e.submit(t, htok, id2, fmt.Sprintf(`{"text":"work","fence":%d}`, f))
	e.do(t, "POST", "/v1/bt/"+id2+"/reject", ctok, `{"why":"nope"}`)
	if st, body = e.do(t, "POST", "/v1/bt/"+id2+"/escalate", htok, ""); st != 200 {
		t.Fatalf("escalate 2: %d %s", st, body)
	}
	if err := verdict(id2, "accept", "reject"); err != nil {
		t.Fatal(err)
	}
	if b = row(t, id2); b.State != "refunded" {
		t.Fatalf("split: %+v", b)
	}
	wantBal(t, "creator split", cr, 52, 52)
	wantBal(t, "hunter split", hu, 132, 32)
	wantBal(t, "r1 split", r1, 18, 8)
	conserved(t, e, "escalated split")
	// peer-reviewed bounty: a split default-accepts; fees are prepaid at creation
	n3 := e.task(t, ctok, "peer")
	id3 := e.bounty(t, ctok, n3, 20, `,"review":"peer"`)
	if b = row(t, id3); b.Held != 24 {
		t.Fatalf("peer hold: %+v", b)
	}
	wantBal(t, "creator peer", cr, 28, 28)
	f = e.claim(t, n3, hu)
	e.submit(t, htok, id3, fmt.Sprintf(`{"text":"work","fence":%d}`, f))
	if len(calls) != 3 || calls[2] != n3 {
		t.Fatalf("peer review not started: %v", calls)
	}
	if st, body = e.do(t, "POST", "/v1/bt/"+id3+"/reject", ctok, `{"why":"x"}`); st != 409 {
		t.Fatalf("creator reject in peer mode: %d %s", st, body)
	}
	if err := verdict(id3, "accept", "reject"); err != nil {
		t.Fatal(err)
	}
	if b = row(t, id3); b.State != "paid" || b.Payout != 20 {
		t.Fatalf("peer split: %+v", b)
	}
	wantBal(t, "hunter peer", hu, 152, 52)
	wantBal(t, "r1 peer", r1, 20, 10)
	conserved(t, e, "peer split")
}

func TestTestsReviewPaysOnExit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cr, ctok := mkRoot(t, "10.13.1.1", 200, 200, 5)
	hu, htok := mkRoot(t, "10.13.2.1", 100, 0, 5)
	wasm := e.put(t, cr, wasmFor("pass-"+uniq()))
	n := e.task(t, ctok, "tests")
	id := e.bounty(t, ctok, n, 40, fmt.Sprintf(`,"review":"tests","test":{"wasm":"%s","ms":1000,"exit":0,"runs":3}`, wasm))
	b := row(t, id)
	if b.Review != "tests" || b.Held != 49 || b.TestRuns != 3 || b.TrivialJob == "" || b.TestMs != 1000 {
		t.Fatalf("row: %+v", b)
	}
	wantBal(t, "creator", cr, 148, 148)
	empty := sha256.Sum256(nil)
	var probes int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE bounty = $1 AND input = $2 AND id = $3`, id, hex.EncodeToString(empty[:]), b.TrivialJob).Scan(&probes); err != nil || probes != 1 {
		t.Fatalf("probe job: %d %v", probes, err)
	}
	// a stranger's wasm is refused
	_, stok := mkRoot(t, "10.13.9.1", 100, 100, 5)
	n0 := e.task(t, stok, "not my wasm")
	if st, body := e.do(t, "POST", "/v1/bt", stok, fmt.Sprintf(`{"task":%d,"credits":10,"review":"tests","test":{"wasm":"%s"}}`, n0, wasm)); st != 403 {
		t.Fatalf("foreign wasm: %d %s", st, body)
	}
	out := e.put(t, hu, []byte("solution "+uniq()))
	f := e.claim(t, n, hu)
	if st, body := e.do(t, "POST", "/v1/bt/"+id+"/submit", htok, fmt.Sprintf(`{"text":"no blob","fence":%d}`, f)); st != 400 {
		t.Fatalf("text on tests: %d %s", st, body)
	}
	reply := e.submit(t, htok, id, fmt.Sprintf(`{"out":"%s","fence":%d}`, out, f))
	b = row(t, id)
	if b.TestJob == "" || b.TestRuns != 2 || b.Held != 46 || !strings.HasPrefix(reply, fmt.Sprintf("ok %s submitted test=%s runs_left=2 bond=4", id, b.TestJob)) {
		t.Fatalf("after submit: %+v %s", b, reply)
	}
	var status, bref, input, root string
	if err := testPool.QueryRow(ctx, `SELECT status, bounty, input, root FROM jobs WHERE id = $1`, b.TestJob).Scan(&status, &bref, &input, &root); err != nil ||
		status != "queued" || bref != id || input != out || root != cr {
		t.Fatalf("test job: %s %s %s %s %v", status, bref, input, root, err)
	}
	wantBal(t, "creator after run charge", cr, 148, 148)
	conserved(t, e, "test queued")
	onDone(t, &compute.Job{ID: b.TestJob, Bounty: id, Status: "done", Code: 0, Out: out})
	b = row(t, id)
	if b.State != "paid" || b.Payout != 40 {
		t.Fatalf("after pass: %+v", b)
	}
	wantBal(t, "hunter", hu, 140, 40)
	wantBal(t, "creator remainder", cr, 154, 154)
	if taskState(t, n) != "done" {
		t.Fatal("task not closed")
	}
	conserved(t, e, "test paid")

	// failing run: rejected with the test stdout, bond back, claim dropped; three distinct
	// rejections flag the bounty disputed and exhaust the runs
	n2 := e.task(t, ctok, "tests fail")
	id2 := e.bounty(t, ctok, n2, 40, fmt.Sprintf(`,"review":"tests","test":{"wasm":"%s","ms":1000,"exit":0,"runs":3}`, wasm))
	stdout := []byte("FAIL: expected 42\ngot 41\n")
	sum := sha256.Sum256(stdout)
	fh := hex.EncodeToString(sum[:])
	dir := filepath.Join(e.d.Cfg.DataDir, "blobs", fh[:2])
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, fh), stdout, 0o640); err != nil {
		t.Fatal(err)
	}
	hunters := []struct{ ip string }{{"10.13.3.1"}, {"10.13.4.1"}, {"10.13.5.1"}}
	for i, h := range hunters {
		hid, htok := mkRoot(t, h.ip, 100, 0, 5)
		o := e.put(t, hid, []byte(fmt.Sprintf("attempt %d %s", i, uniq())))
		f := e.claim(t, n2, hid)
		e.submit(t, htok, id2, fmt.Sprintf(`{"out":"%s","fence":%d}`, o, f))
		tj := row(t, id2).TestJob
		onDone(t, &compute.Job{ID: tj, Bounty: id2, Status: "done", Code: 1, Out: fh})
		b = row(t, id2)
		if b.State != "rejected" || b.Rejects != i+1 || b.TestJob != "" || b.TestRuns != 2-i {
			t.Fatalf("after fail %d: %+v", i, b)
		}
		wantBal(t, "rejected hunter", hid, 100, 0)
		if holder(t, n2) != "" {
			t.Fatal("claim kept after rejection")
		}
		if note := lastNote(t, n2); !strings.Contains(note, "exit=1 want 0") || !strings.Contains(note, "stdout: FAIL: expected 42\n  got 41") {
			t.Fatalf("note: %q", note)
		}
		if b.Disputed != (i == 2) {
			t.Fatalf("disputed=%v after %d rejections", b.Disputed, i+1)
		}
	}
	hid, htok4 := mkRoot(t, "10.13.6.1", 100, 0, 5)
	o := e.put(t, hid, []byte("late "+uniq()))
	f = e.claim(t, n2, hid)
	if st, body := e.do(t, "POST", "/v1/bt/"+id2+"/submit", htok4, fmt.Sprintf(`{"out":"%s","fence":%d}`, o, f)); st != 409 || !strings.Contains(body, "exhausted") {
		t.Fatalf("exhausted: %d %s", st, body)
	}
	if st, body := e.do(t, "GET", "/v1/bt/"+id2, htok4, ""); st != 200 || !strings.Contains(body, "tests: runs_left=0 exit=0") || !strings.Contains(body, "rejects: 3 disputed") {
		t.Fatalf("detail: %d %s", st, body)
	}
	conserved(t, e, "tests rejected")
}

func TestTrivialTestDetected(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cr, ctok := mkRoot(t, "10.14.1.1", 200, 200, 5)
	wasm := e.put(t, cr, wasmFor("trivial-"+uniq()))
	n := e.task(t, ctok, "trivial")
	id := e.bounty(t, ctok, n, 40, fmt.Sprintf(`,"review":"tests","test":{"wasm":"%s","ms":1000,"exit":0}`, wasm))
	b := row(t, id)
	if b.TrivialJob == "" || b.Trivial {
		t.Fatalf("probe not queued: %+v", b)
	}
	var bref string
	if err := testPool.QueryRow(ctx, `SELECT bounty FROM jobs WHERE id = $1`, b.TrivialJob).Scan(&bref); err != nil || bref != id {
		t.Fatalf("probe job row: %s %v", bref, err)
	}
	onDone(t, &compute.Job{ID: b.TrivialJob, Bounty: id, Status: "done", Code: 0, Out: strings.Repeat("0", 64)})
	b = row(t, id)
	if !b.Trivial || b.TrivialJob != "" || b.State != "open" {
		t.Fatalf("after probe: %+v", b)
	}
	if st, body := e.do(t, "GET", "/v1/bt/"+id, ctok, ""); st != 200 || !strings.Contains(body, "trivial? exits 0 on empty stdin") {
		t.Fatalf("detail: %d %s", st, body)
	}
	if lines := TaskExtra(ctx, testPool, n); len(lines) != 1 || !strings.Contains(lines[0], "review=tests tests: trivial? exits 0 on empty stdin") {
		t.Fatalf("hook: %q", lines)
	}
	// a test that wants a non-zero exit is not trivial when the probe exits 0
	n2 := e.task(t, ctok, "not trivial")
	id2 := e.bounty(t, ctok, n2, 20, fmt.Sprintf(`,"review":"tests","test":{"wasm":"%s","ms":1000,"exit":7}`, wasm))
	b = row(t, id2)
	onDone(t, &compute.Job{ID: b.TrivialJob, Bounty: id2, Status: "done", Code: 0})
	if b = row(t, id2); b.Trivial {
		t.Fatalf("falsely trivial: %+v", b)
	}
	conserved(t, e, "trivial")
}

func TestCreateFromEscrowExport(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cr, ctok := mkRoot(t, "10.15.1.1", 100, 100, 5)
	hu, htok := mkRoot(t, "10.15.2.1", 100, 0, 5)
	other, otok := mkRoot(t, "10.15.3.1", 100, 0, 5)
	n := e.task(t, ctok, "auction")
	var id string
	err := core.Tx(ctx, testPool, func(tx pgx.Tx) error {
		if err := core.ReserveEarned(ctx, tx, cr, 30); err != nil {
			return err
		}
		var err error
		id, err = CreateFromEscrow(ctx, tx, n, 30, cr, cr, hu, hu, time.Now().Add(24*time.Hour))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	b := row(t, id)
	if b.State != "open" || b.Escrow != 30 || b.Held != 30 || b.Hunter != hu || b.SubmittedAt != nil || b.Review != "creator" {
		t.Fatalf("row: %+v", b)
	}
	if a := conserved(t, e, "from escrow"); a.Escrow < 30 {
		t.Fatalf("escrow not counted: %+v", a)
	}
	if st, body := e.do(t, "GET", "/v1/bt/"+id, htok, ""); st != 200 || !strings.Contains(body, "hunter: "+hu+" assigned") {
		t.Fatalf("detail: %d %s", st, body)
	}
	f := e.claim(t, n, other)
	if st, body := e.do(t, "POST", "/v1/bt/"+id+"/submit", otok, fmt.Sprintf(`{"text":"mine","fence":%d}`, f)); st != 403 || !strings.Contains(body, "assigned to "+hu) {
		t.Fatalf("other submit: %d %s", st, body)
	}
	f = e.claim(t, n, hu)
	e.submit(t, htok, id, fmt.Sprintf(`{"text":"won","fence":%d}`, f))
	wantBal(t, "winner bond", hu, 97, 0)
	if st, body := e.do(t, "POST", "/v1/bt/"+id+"/accept", ctok, ""); st != 200 || !strings.HasPrefix(body, "ok "+id+" paid 30 to "+hu) {
		t.Fatalf("accept: %d %s", st, body)
	}
	wantBal(t, "winner paid", hu, 130, 30)
	var buf bytes.Buffer
	if err := export(ctx, testPool, cr, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"kind":"bounty"`) || !strings.Contains(buf.String(), id) {
		t.Fatalf("creator export: %s", buf.String())
	}
	buf.Reset()
	if err := export(ctx, testPool, hu, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"kind":"bond"`) || !strings.Contains(buf.String(), `"state":"returned"`) {
		t.Fatalf("hunter export: %s", buf.String())
	}
	// a done task or a task with a live bounty refuses
	if _, err := CreateFromEscrow(ctx, testPool, n, 10, cr, cr, hu, hu, time.Now().Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("done task: %v", err)
	}
	n2 := e.task(t, ctok, "live")
	e.bounty(t, ctok, n2, 10, "")
	if _, err := CreateFromEscrow(ctx, testPool, n2, 10, cr, cr, hu, hu, time.Now().Add(time.Hour)); err == nil || !strings.Contains(err.Error(), "dup") {
		t.Fatalf("live bounty: %v", err)
	}
	_ = other
	conserved(t, e, "export")
}

func TestListFilters(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	cr, ctok := mkRoot(t, "10.16.1.1", 300, 300, 5)
	_, htok := mkRoot(t, "10.16.2.1", 100, 0, 5)
	n1 := e.task(t, ctok, "list 1")
	id1 := e.bounty(t, ctok, n1, 10, "")
	n2 := e.task(t, ctok, "list 2")
	id2 := e.bounty(t, ctok, n2, 60, "")
	st, body := e.do(t, "GET", "/v1/bt?min=50", htok, "")
	if st != 200 || strings.Contains(body, id1) || !strings.Contains(body, "- "+id2+" 60cr task=#"+itoa(n2)) {
		t.Fatalf("min: %d %s", st, body)
	}
	if st, body = e.do(t, "GET", "/v1/bt?s=nope", htok, ""); st != 400 {
		t.Fatalf("bad s: %d %s", st, body)
	}
	RelFn = func(ctx context.Context, q core.Q, root string) (float64, int) {
		if root == cr {
			return 0.5, 20
		}
		return 0, 0
	}
	t.Cleanup(func() { RelFn = nil })
	if st, body = e.do(t, "GET", "/v1/bt?min_rel=0.9", htok, ""); st != 200 || strings.Contains(body, id1) || strings.Contains(body, id2) {
		t.Fatalf("min_rel filter: %d %s", st, body)
	}
	if st, body = e.do(t, "GET", "/v1/bt?min_rel=0.4", htok, ""); st != 200 || !strings.Contains(body, id2+" 60cr") || !strings.Contains(body, "rel=0.50") {
		t.Fatalf("min_rel pass: %d %s", st, body)
	}
	RelFn = nil
	if st, body = e.do(t, "GET", "/v1/bt?min_rel=0.9&f=json", htok, ""); st != 200 || !strings.Contains(body, id2) || !strings.HasPrefix(body, "[") {
		t.Fatalf("nil RelFn ignores min_rel: %d %s", st, body)
	}
	out, err := Ops(e.d)["btl"](ctx, e.ident(t, htok), json.RawMessage(`{"s":"open","k":1}`))
	if err != nil || !strings.HasPrefix(out, "bounties s=open k=1\n- "+id2) {
		t.Fatalf("op btl: %q %v", out, err)
	}
	if out, err = Ops(e.d)["btg"](ctx, e.ident(t, htok), json.RawMessage(`{"id":"`+id1+`"}`)); err != nil || !strings.HasPrefix(out, id1+" open 10cr task=#"+itoa(n1)) || !strings.Contains(out, "task: list 1") {
		t.Fatalf("op btg: %q %v", out, err)
	}
	if st, body = e.do(t, "GET", "/v1/bt/"+id1, "", ""); st != 401 {
		t.Fatalf("anonymous: %d %s", st, body)
	}
}
