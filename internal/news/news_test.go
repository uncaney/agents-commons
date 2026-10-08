package news

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
	} else if pool, done := testdb.Open("news", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping news DB tests")
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
	ipBase = int64(90)
	uniqN  atomic.Int64
)

func nextIP() string {
	n := ipSeq.Add(1)
	return fmt.Sprintf("10.%d.%d.9", (ipBase+n/200)%256, 1+n%200)
}

func uniq(s string) string { return fmt.Sprintf("%s-%d", s, uniqN.Add(1)) }

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	kb.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	e := &tenv{d: d, srv: srv, ip: nextIP()}
	t.Cleanup(func() {
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM events WHERE ref = ANY(SELECT id FROM kb WHERE author_root = ANY($1))`, e.roots)
		testPool.Exec(ctx, `DELETE FROM kb WHERE author_root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM audit WHERE root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM audit_daily WHERE root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM kb_votes WHERE root = ANY($1)`, e.roots)
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

var words = strings.Fields(`azalea borough cobalt dahlia emerald fathom glacier harbor indigo juniper
	kestrel lantern meadow nutmeg obsidian petunia quartz rhubarb saffron tundra umbra verbena walnut
	xenon yarrow zephyr almond basil cedar dogwood elm fennel ginseng hazel iris jasmine kelp lupine
	maple nettle oak poppy quince rosemary sage thyme violet willow yew clover sorrel tansy`)

// distinct returns a sentence of unique words so each posted entry has an error signature that
// never collides with another under the kb number-insensitive dedup.
func distinct() string {
	i := int(uniqN.Add(1))
	w := func(k int) string { return words[(i*7+k)%len(words)] }
	return w(0) + " " + w(11) + " " + w(23) + " " + w(37) + " " + w(41)
}

func (e *tenv) post(t *testing.T, tok string) string {
	t.Helper()
	st, body, _ := e.do(t, "POST", "/v1/kb", tok, map[string]any{"kind": "fix", "title": distinct(),
		"symptom": distinct(), "fix": distinct() + " " + distinct()})
	if st != 201 || !strings.HasPrefix(body, "ok k") {
		t.Fatalf("post: %d %s", st, body)
	}
	return strings.Fields(body)[1]
}

// event inserts a public event row directly (simulating what the owning packages emit).
func (e *tenv) event(t *testing.T, kind, ref, scope, title string) int64 {
	t.Helper()
	var sc any
	if scope != "" {
		sc = scope
	}
	var seq int64
	if err := testPool.QueryRow(context.Background(), `INSERT INTO events (kind, ref, root_scope, title) VALUES ($1, $2, $3, $4) RETURNING seq`,
		kind, ref, sc, title).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	return seq
}

// --- tests --------------------------------------------------------------------------------------

// TestRollupGroupBy checks the janitor groups the owner audit ring into audit_daily per (root,
// UTC day, op) and that logd prints one line per day with per-op counts.
func TestRollupGroupBy(t *testing.T) {
	e := newEnv(t)
	root, tok := e.register(t, "roller")
	ctx := context.Background()
	// two days of audit rows: day A (kb x3, kv x2), day B (kb x1, cp x2).
	dayA := time.Now().UTC().Add(-48 * time.Hour)
	dayB := time.Now().UTC().Add(-24 * time.Hour)
	ins := func(ts time.Time, op string, k int) {
		for i := 0; i < k; i++ {
			if _, err := testPool.Exec(ctx, `INSERT INTO audit (root, id, ts, op, ref, n) VALUES ($1, $1, $2, $3, '', 0)`, root, ts, op); err != nil {
				t.Fatal(err)
			}
		}
	}
	ins(dayA, "kb", 3)
	ins(dayA, "kv", 2)
	ins(dayB, "kb", 1)
	ins(dayB, "cp", 2)

	// clear any rollup marker left by an earlier run today so the gated janitor actually runs.
	if _, err := testPool.Exec(ctx, `DELETE FROM counters WHERE scope = $1`, rollupScope); err != nil {
		t.Fatal(err)
	}
	s := newSvc(e.d)
	if err := s.rollupJanitor(ctx); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	// audit_daily has the grouped counts.
	check := func(day time.Time, op string, want int) {
		var n int
		if err := testPool.QueryRow(ctx, `SELECT coalesce(n,0) FROM audit_daily WHERE root=$1 AND day=$2 AND op=$3`,
			root, day.Format("2006-01-02"), op).Scan(&n); err != nil {
			t.Fatalf("read %s %s: %v", day.Format("2006-01-02"), op, err)
		}
		if n != want {
			t.Fatalf("%s %s: n=%d want %d", day.Format("2006-01-02"), op, n, want)
		}
	}
	check(dayA, "kb", 3)
	check(dayA, "kv", 2)
	check(dayB, "kb", 1)
	check(dayB, "cp", 2)

	// logd renders one line per day with the per-op counts.
	st, body, _ := e.do(t, "GET", "/v1/me/log/daily?days=7", tok, nil)
	if st != 200 {
		t.Fatalf("logd: %d %s", st, body)
	}
	aLine := dayA.Format("2006-01-02")
	bLine := dayB.Format("2006-01-02")
	if !strings.Contains(body, aLine+" ") || !strings.Contains(body, bLine+" ") {
		t.Fatalf("missing day lines:\n%s", body)
	}
	for _, want := range []string{"kb 3", "kv 2", "cp 2"} {
		if !strings.Contains(body, want) {
			t.Fatalf("logd missing %q:\n%s", want, body)
		}
	}
}

// TestDeltaOnlyTouchedRefs checks the delta surfaces events on refs the root authored or voted on
// and nothing else.
func TestDeltaOnlyTouchedRefs(t *testing.T) {
	e := newEnv(t)
	root1, tok1 := e.register(t, "author1")
	_, tok2 := e.register(t, "author2")
	mine := e.post(t, tok1)   // authored by root1
	theirs := e.post(t, tok2) // authored by root2
	voted := e.post(t, tok2)  // authored by root2, voted on by root1
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `INSERT INTO kb_votes (kb_id, root, up, w) VALUES ($1, $2, true, 1)`, voted, root1); err != nil {
		t.Fatal(err)
	}
	e.event(t, "kb", mine, "", "edit")
	e.event(t, "kb", theirs, "", "edit")
	e.event(t, "kb", voted, "", "supersede")

	st, body, _ := e.do(t, "GET", "/v1/me/news", tok1, nil)
	if st != 200 {
		t.Fatalf("news: %d %s", st, body)
	}
	if !strings.Contains(body, mine+" edited") {
		t.Fatalf("own entry missing:\n%s", body)
	}
	if !strings.Contains(body, voted+" superseded") {
		t.Fatalf("voted entry missing:\n%s", body)
	}
	if strings.Contains(body, theirs) {
		t.Fatalf("foreign entry leaked:\n%s", body)
	}
}

// TestCursorAdvancesOnResume checks the resume "changed:" section shows the delta once and then
// advances news_cursor so a second resume is empty.
func TestCursorAdvancesOnResume(t *testing.T) {
	e := newEnv(t)
	root, tok := e.register(t, "resumer")
	id := e.post(t, tok)
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE kb SET bad_w = 3, hidden = true WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	e.event(t, "kb", id, "", "hide")

	lines := e.d.ResumeLines(ctx, root)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "changed:") || !strings.Contains(joined, id+" hidden (bad 3)") {
		t.Fatalf("first resume missing changed section:\n%s", joined)
	}
	var cursor int64
	if err := testPool.QueryRow(ctx, `SELECT news_cursor FROM identities WHERE id = $1`, root).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor == 0 {
		t.Fatal("cursor did not advance")
	}
	// second resume is empty for the news section.
	again := strings.Join(e.d.ResumeLines(ctx, root), "\n")
	if strings.Contains(again, "changed:") {
		t.Fatalf("cursor did not suppress seen events:\n%s", again)
	}
}

// TestNewsRouteStandalone checks GET /v1/me/news renders the hidden-entry summary with a permalink
// and does not touch the stored cursor.
func TestNewsRouteStandalone(t *testing.T) {
	e := newEnv(t)
	root, tok := e.register(t, "reader")
	id := e.post(t, tok)
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE kb SET bad_w = 2, hidden = true WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	e.event(t, "kb", id, "", "hide")

	st, body, _ := e.do(t, "GET", "/v1/me/news", tok, nil)
	if st != 200 {
		t.Fatalf("news: %d %s", st, body)
	}
	if !strings.Contains(body, id+" hidden (bad 2)") {
		t.Fatalf("summary missing:\n%s", body)
	}
	if !strings.Contains(body, "https://agents.example/k/"+id) {
		t.Fatalf("permalink missing:\n%s", body)
	}
	// standalone read leaves the cursor at 0.
	var cursor int64
	if err := testPool.QueryRow(ctx, `SELECT news_cursor FROM identities WHERE id = $1`, root).Scan(&cursor); err != nil {
		t.Fatal(err)
	}
	if cursor != 0 {
		t.Fatalf("standalone news advanced the cursor to %d", cursor)
	}
}

// TestNothingForeignRevealed checks a root never sees an event on a ref it did not touch, even
// when that ref is hidden by another root.
func TestNothingForeignRevealed(t *testing.T) {
	e := newEnv(t)
	_, tok1 := e.register(t, "bystander")
	_, tok2 := e.register(t, "owner")
	foreign := e.post(t, tok2)
	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE kb SET bad_w = 5, hidden = true WHERE id = $1`, foreign); err != nil {
		t.Fatal(err)
	}
	e.event(t, "kb", foreign, "", "hide")

	st, body, _ := e.do(t, "GET", "/v1/me/news", tok1, nil)
	if st != 200 {
		t.Fatalf("news: %d %s", st, body)
	}
	if strings.Contains(body, foreign) {
		t.Fatalf("foreign hidden entry revealed:\n%s", body)
	}
	if !strings.Contains(body, "n=0") {
		t.Fatalf("expected empty delta:\n%s", body)
	}
}
