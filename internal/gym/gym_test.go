package gym

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
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
	"ekaii.fr/commons/internal/gym/mods"
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
	} else if pool, done := testdb.Open("gym", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping gym DB tests")
		os.Exit(0)
	}
	// Small pool so refill is cheap; relaxed caps are set per-test.
	PoolTarget = 3
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
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
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, srv: srv}
}

func (e *tenv) do(t *testing.T, method, path, token, body string) (int, string) {
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func randIP() string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.1", b[0], b[1])
}

// mkRoot inserts a 2 h old L0 root (100 credits) and returns (id, token).
func mkRoot(t *testing.T, family string) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	_, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, earned, reg_ip, rep, created, verified_noncompute, family)
		VALUES ($1, 'r', NULL, $1, $2, 100, 100, $3, 0, now() - interval '2 hours', 1, $4)`, id, h, randIP(), family)
	if err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func fundSystem(t *testing.T, n int64) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET credits = $1, earned = 0 WHERE id = $2`, n, core.SystemID); err != nil {
		t.Fatal(err)
	}
}

// seedTask inserts one instance (served to root when served) and returns its id and the generated
// task so the test knows the correct answer. It mirrors insertInstance.
func seedTask(t *testing.T, kind string, level int, served string) (string, mods.Task) {
	t.Helper()
	var sb [8]byte
	rand.Read(sb[:])
	seed := int64(binary.LittleEndian.Uint64(sb[:]))
	task, err := mods.Gen(kind, seed, level)
	if err != nil {
		t.Fatal(err)
	}
	return insertTask(t, kind, level, seed, task, served), task
}

// insertTask stores an explicit task (used for sentinel/no-leak tests).
func insertTask(t *testing.T, kind string, level int, seed int64, task mods.Task, served string) string {
	t.Helper()
	id := core.NewID('g')
	salt := make([]byte, 16)
	rand.Read(salt)
	h := sha256.Sum256(append([]byte(mods.Norm(task.Answer)), salt...))
	var servedTo *string
	var servedAt *time.Time
	if served != "" {
		servedTo = &served
		now := time.Now()
		servedAt = &now
	}
	_, err := testPool.Exec(context.Background(), `INSERT INTO gym_tasks (id, kind, level, seed, prompt, answer, secret, answer_hash, salt, checker, served_to, served_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		id, kind, level, seed, task.Prompt, task.Answer, task.Secret, h[:], salt, task.Check, servedTo, servedAt)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func unserved(t *testing.T, kind string, level int) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM gym_tasks WHERE kind=$1 AND level=$2 AND served_to IS NULL`, kind, level).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// ---------------------------------------------------------------------------

func TestGenCheckModulesDeterministic(t *testing.T) {
	for _, kind := range mods.Kinds {
		for level := 1; level <= MaxLevel; level++ {
			a, err := mods.Gen(kind, 12345, level)
			if err != nil {
				t.Fatalf("%s L%d gen: %v", kind, level, err)
			}
			b, _ := mods.Gen(kind, 12345, level)
			if a != b {
				t.Fatalf("%s L%d not deterministic:\n%+v\n%+v", kind, level, a, b)
			}
			if a.Prompt == "" || a.Answer == "" || a.Check == "" {
				t.Fatalf("%s L%d incomplete task %+v", kind, level, a)
			}
			if !mods.Check(kind, a, a.Answer) {
				t.Fatalf("%s L%d: correct answer %q rejected", kind, level, a.Answer)
			}
			wrong := a.Answer + "_WRONG_x"
			if kind == "leak" {
				wrong = a.Secret // leaking the planted credential must fail
			}
			if mods.Check(kind, a, wrong) {
				t.Fatalf("%s L%d: wrong answer %q accepted", kind, level, wrong)
			}
		}
	}
	// inj decoys escalate by level: level 2 hides them in HTML comments/alt, 3 zero-width-joins.
	l2, _ := mods.Gen("inj", 9, 2)
	if !strings.Contains(l2.Prompt, "<!--") && !strings.Contains(l2.Prompt, "alt=") {
		t.Errorf("inj L2 should hide a decoy in a comment or alt text")
	}
}

func TestPoolRefillServesOnceAndUnfundedSkips(t *testing.T) {
	e := newEnv(t)
	s := newSvc(e.d)
	ctx := context.Background()
	fundSystem(t, 100000)
	if err := s.Refill(ctx); err != nil {
		t.Fatalf("refill: %v", err)
	}
	for level := 1; level <= MaxLevel; level++ {
		if got := unserved(t, "arith", level); got != PoolTarget {
			t.Fatalf("arith L%d pool = %d, want %d", level, got, PoolTarget)
		}
	}
	// Serve-once: two roots draw distinct instances, each marked served to its root.
	_, tokA := mkRoot(t, "")
	_, tokB := mkRoot(t, "")
	stA, bodyA := e.do(t, "GET", "/v1/gym?kind=arith&level=1", tokA, "")
	stB, bodyB := e.do(t, "GET", "/v1/gym?kind=arith&level=1", tokB, "")
	if stA != 200 || stB != 200 {
		t.Fatalf("serve status %d/%d", stA, stB)
	}
	idA, idB := field(bodyA, "g="), field(bodyB, "g=")
	if idA == "" || idA == idB {
		t.Fatalf("instances not served once: A=%q B=%q", idA, idB)
	}
	// One open per root per kind: a second draw returns the same open instance.
	_, bodyA2 := e.do(t, "GET", "/v1/gym?kind=arith&level=1", tokA, "")
	if field(bodyA2, "g=") != idA {
		t.Fatalf("re-open gave a new instance: %q != %q", field(bodyA2, "g="), idA)
	}

	// Unfunded: create a deficit, drain the faucet, refill must skip and record an inbox event.
	if _, err := testPool.Exec(ctx, `DELETE FROM gym_tasks WHERE kind='arith' AND level=1 AND served_to IS NULL`); err != nil {
		t.Fatal(err)
	}
	fundSystem(t, 0)
	before := eventCount(t)
	if err := s.Refill(ctx); err != nil {
		t.Fatalf("unfunded refill returned error: %v", err)
	}
	if got := unserved(t, "arith", 1); got != 0 {
		t.Fatalf("unfunded refill inserted %d rows, want 0", got)
	}
	if eventCount(t) <= before {
		t.Fatalf("unfunded refill did not record an event")
	}
}

func TestAnswerCorrectWrongAndRateCap(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t, "")
	// Correct.
	id, task := seedTask(t, "arith", 1, root)
	st, body := e.do(t, "POST", "/v1/gym/"+id, tok, `{"answer":`+quote(task.Answer)+`}`)
	if st != 200 || !strings.HasPrefix(body, "ok correct") {
		t.Fatalf("correct attempt: %d %q", st, body)
	}
	// One attempt per instance.
	st, _ = e.do(t, "POST", "/v1/gym/"+id, tok, `{"answer":`+quote(task.Answer)+`}`)
	if st != 409 {
		t.Fatalf("second attempt should be 409, got %d", st)
	}
	// Wrong.
	id2, _ := seedTask(t, "arith", 1, root)
	st, body = e.do(t, "POST", "/v1/gym/"+id2, tok, `{"answer":"definitely-not-the-number"}`)
	if st != 200 || !strings.HasPrefix(body, "no ") {
		t.Fatalf("wrong attempt: %d %q", st, body)
	}
	// An instance served to someone else cannot be answered.
	other, _ := mkRoot(t, "")
	id3, task3 := seedTask(t, "arith", 1, other)
	st, _ = e.do(t, "POST", "/v1/gym/"+id3, tok, `{"answer":`+quote(task3.Answer)+`}`)
	if st != 403 {
		t.Fatalf("foreign instance should be 403, got %d", st)
	}
	// Rate cap.
	old := DailyTries
	DailyTries = 5
	defer func() { DailyTries = old }()
	cap2, tok2 := mkRoot(t, "")
	hit := 0
	for i := 0; i < DailyTries+2; i++ {
		cid, ct := seedTask(t, "arith", 1, cap2)
		st, _ := e.do(t, "POST", "/v1/gym/"+cid, tok2, `{"answer":`+quote(ct.Answer)+`}`)
		if st == 429 {
			hit++
		}
	}
	if hit == 0 {
		t.Fatalf("daily attempt cap never fired")
	}
}

func TestSkillsElo(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t, "")
	ctx := context.Background()
	// Eight correct answers at level 3 should raise the level above the 1.0 start.
	for i := 0; i < 8; i++ {
		id, task := seedTask(t, "arith", 3, root)
		if st, body := e.do(t, "POST", "/v1/gym/"+id, tok, `{"answer":`+quote(task.Answer)+`}`); st != 200 || !strings.HasPrefix(body, "ok") {
			t.Fatalf("attempt %d: %d %q", i, st, body)
		}
	}
	peak := scoreLevel(t, ctx, root, "arith")
	if peak <= 1.0 {
		t.Fatalf("level did not rise after correct answers: %v", peak)
	}
	attempts, acc := scoreAccuracy(t, ctx, root, "arith")
	if attempts != 8 || acc < 0.99 {
		t.Fatalf("after 8/8 correct: attempts=%d acc=%v", attempts, acc)
	}
	// Four wrong answers should drop the level below the peak.
	for i := 0; i < 4; i++ {
		id, _ := seedTask(t, "arith", 3, root)
		e.do(t, "POST", "/v1/gym/"+id, tok, `{"answer":"wrong"}`)
	}
	if after := scoreLevel(t, ctx, root, "arith"); after >= peak {
		t.Fatalf("level did not drop after wrong answers: peak=%v after=%v", peak, after)
	}
	_, acc2 := scoreAccuracy(t, ctx, root, "arith")
	if acc2 >= acc {
		t.Fatalf("accuracy did not fall: %v -> %v", acc, acc2)
	}
	// GET /v1/me/skills reflects it without exposing answers.
	st, body := e.do(t, "GET", "/v1/me/skills", tok, "")
	if st != 200 || !strings.Contains(body, "arith=") {
		t.Fatalf("skills: %d %q", st, body)
	}
	// SkillScores feeds review's min_skill gate.
	sc, err := SkillScores(ctx, testPool, root)
	if err != nil || sc["arith"] <= 0 {
		t.Fatalf("SkillScores: %v %v", sc, err)
	}
	line, err := SkillsLine(ctx, testPool, root)
	if err != nil || !strings.Contains(line, "arith=") {
		t.Fatalf("SkillsLine: %q %v", line, err)
	}
}

func TestLeaderboardThreshold(t *testing.T) {
	e := newEnv(t)
	s := newSvc(e.d)
	// rootA: 19 attempts (below threshold); rootB: 20 (on it).
	rootA, _ := mkRoot(t, "fam-a")
	rootB, _ := mkRoot(t, "fam-b")
	setScore(t, rootA, "arith", 2.5, 0.90, 19, 17)
	setScore(t, rootB, "arith", 2.2, 0.80, 20, 16)
	st, body := e.do(t, "GET", "/lb/arith.txt", "", "")
	if st != 200 {
		t.Fatalf("lb status %d", st)
	}
	if !strings.Contains(body, s.pseudo(rootB)) {
		t.Fatalf("rootB (>=20) missing from board:\n%s", body)
	}
	if strings.Contains(body, s.pseudo(rootA)) {
		t.Fatalf("rootA (<20) should not appear:\n%s", body)
	}
	if !strings.Contains(body, "self-declared") {
		t.Fatalf("families must be marked self-declared:\n%s", body)
	}
	// Pseudonymous: the raw root id never appears.
	if strings.Contains(body, rootB) {
		t.Fatalf("raw root id leaked on the board")
	}
}

func TestNoAnswersLeak(t *testing.T) {
	e := newEnv(t)
	root, tok := mkRoot(t, "")
	ctx := context.Background()
	const ansSentinel = "ZZSENTINELANSWER"
	const secSentinel = "ZZSENTINELSECRET"
	// Isolate the pool so the served instance is deterministically ours; its prompt contains
	// neither the stored answer nor the stored secret.
	if _, err := testPool.Exec(ctx, `DELETE FROM gym_tasks WHERE kind='arith' AND served_to IS NULL`); err != nil {
		t.Fatal(err)
	}
	seed := int64(778899)
	task := mods.Task{Prompt: "gym task: compute the integer value of the expression; reply with the number only.\n2 + 2", Answer: ansSentinel, Secret: secSentinel, Check: "exact"}
	id := insertTask(t, "arith", 1, seed, task, "")
	// Serve: the prompt is returned; the answer, secret, salt and seed are not.
	st, body := e.do(t, "GET", "/v1/gym?kind=arith&level=1", tok, "")
	if st != 200 || field(body, "g=") != id {
		t.Fatalf("serve: %d %q", st, body)
	}
	if !strings.Contains(body, "2 + 2") {
		t.Fatalf("prompt not served: %q", body)
	}
	assertNoSecret(t, "serve", body)
	if strings.Contains(body, fmt.Sprint(seed)) {
		t.Fatalf("seed served: %q", body)
	}
	// Grading reply for a wrong answer never reveals the correct answer.
	_, abody := e.do(t, "POST", "/v1/gym/"+id, tok, `{"answer":"0"}`)
	if !strings.HasPrefix(abody, "no ") {
		t.Fatalf("expected a wrong-answer reply, got %q", abody)
	}
	assertNoSecret(t, "grade", abody)
	// Skills and leaderboard pages never contain answers, secrets or seeds.
	setScore(t, root, "arith", 2.0, 1.0, 20, 20)
	_, lb := e.do(t, "GET", "/lb/arith", "", "")
	assertNoSecret(t, "lb", lb)
	if strings.Contains(lb, fmt.Sprint(seed)) {
		t.Fatalf("seed leaked on leaderboard")
	}
	_, sk := e.do(t, "GET", "/v1/me/skills", tok, "")
	assertNoSecret(t, "skills", sk)
}

// TestLBArithRendersClean is the explicit acceptance item: GET /lb/arith renders with no answer or
// seed text behind it.
func TestLBArithRendersClean(t *testing.T) {
	e := newEnv(t)
	root, _ := mkRoot(t, "fam")
	setScore(t, root, "arith", 3.0, 0.95, 42, 40)
	// A real instance with a sentinel answer exists but must never surface on the board.
	insertTask(t, "arith", 1, 4242, mods.Task{Prompt: "gym task: compute\n2 + 2", Answer: "ZZANSLEAK4242", Check: "numeric"}, "")
	for _, path := range []string{"/lb/arith", "/lb/arith.txt", "/lb/arith.md", "/lb/arith.json"} {
		st, body := e.do(t, "GET", path, "", "")
		if st != 200 {
			t.Fatalf("%s status %d", path, st)
		}
		if strings.Contains(body, "ZZANSLEAK4242") {
			t.Fatalf("%s leaked an answer", path)
		}
		if strings.Contains(body, "4242") {
			t.Fatalf("%s leaked a seed", path)
		}
	}
}

// ---- helpers ---------------------------------------------------------------

func field(body, prefix string) string {
	for _, f := range strings.Fields(body) {
		if strings.HasPrefix(f, prefix) {
			return strings.TrimPrefix(f, prefix)
		}
	}
	return ""
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

func eventCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE kind='gym'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func scoreLevel(t *testing.T, ctx context.Context, root, kind string) float64 {
	t.Helper()
	var lvl float64
	if err := testPool.QueryRow(ctx, `SELECT level FROM gym_scores WHERE root=$1 AND kind=$2`, root, kind).Scan(&lvl); err != nil {
		t.Fatal(err)
	}
	return lvl
}

func scoreAccuracy(t *testing.T, ctx context.Context, root, kind string) (int, float64) {
	t.Helper()
	var attempts int
	var acc float64
	if err := testPool.QueryRow(ctx, `SELECT attempts, acc FROM gym_scores WHERE root=$1 AND kind=$2`, root, kind).Scan(&attempts, &acc); err != nil {
		t.Fatal(err)
	}
	return attempts, acc
}

func setScore(t *testing.T, root, kind string, level, acc float64, attempts, solved int) {
	t.Helper()
	_, err := testPool.Exec(context.Background(), `INSERT INTO gym_scores (root, kind, level, acc, attempts, solved)
		VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (root,kind) DO UPDATE SET level=$3, acc=$4, attempts=$5, solved=$6`,
		root, kind, level, acc, attempts, solved)
	if err != nil {
		t.Fatal(err)
	}
}

func assertNoSecret(t *testing.T, where, body string) {
	t.Helper()
	for _, bad := range []string{"ZZSENTINELANSWER", "ZZSENTINELSECRET"} {
		if strings.Contains(body, bad) {
			t.Fatalf("%s leaked %q:\n%s", where, bad, body)
		}
	}
}
