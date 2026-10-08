package swarm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
)

var (
	testPool *pgxpool.Pool
	levels   sync.Map // root -> level (core.LevelFn stub)
	mails    sync.Map // root -> []string (NotifyExpired stub)
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
	} else if pool, done := testdb.Open("swarm", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping swarm DB tests")
		os.Exit(0)
	}
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int {
		v, _ := levels.Load(root)
		n, _ := v.(int)
		return n
	}
	NotifyExpired = func(ctx context.Context, q core.Q, root, subject, text string) error {
		v, _ := mails.Load(root)
		prev, _ := v.([]string)
		mails.Store(root, append(prev, subject+"\n"+text))
		return nil
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
	s := register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, s: s, srv: srv}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

// do sends a request with a random client IP (anonymous limits never interfere) and returns the
// status, body and headers.
func (e *tenv) do(t *testing.T, method, path, token, body string, hdr ...string) (int, string, http.Header) {
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
	return res.StatusCode, string(b), res.Header
}

// mkRoot inserts a root identity registered from ip with a stubbed level; returns (id, token).
func mkRoot(t *testing.T, ip string, level int) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, reg_ip, created)
		VALUES ($1, 'r', NULL, $1, $2, 100, $3, now() - interval '5 days')`, id, h, ip); err != nil {
		t.Fatal(err)
	}
	levels.Store(id, level)
	return id, tok
}

// mkSub inserts a full subkey below root; returns (id, token).
func mkSub(t *testing.T, root string) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits)
		VALUES ($1, 's', $2, $2, $3, 0)`, id, root, h); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func head(body string) string { l, _, _ := strings.Cut(body, "\n"); return l }

// field returns the value of key=<v> in the head line.
func field(body, key string) string {
	for _, f := range strings.Fields(head(body)) {
		if v, ok := strings.CutPrefix(f, key+"="); ok {
			return v
		}
	}
	return ""
}

func want(t *testing.T, st int, body string, wantSt int, sub string) {
	t.Helper()
	if st != wantSt || !strings.Contains(body, sub) {
		t.Fatalf("got %d %q, want %d containing %q", st, body, wantSt, sub)
	}
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// --- grammar and gates --------------------------------------------------------------------------

func TestNamespaceGrammar(t *testing.T) {
	root := core.NewID('a')
	cases := []struct {
		raw, caller, full string
		ns                byte
		ok                bool
	}{
		{"g:swarm.leader", "", "g:swarm.leader", 'g', true},
		{"~mine", root, "a:" + root + ".mine", 'a', true},
		{"a:" + root + ".x.y", "", "a:" + root + ".x.y", 'a', true},
		{"s:team-1.jobs", "", "s:team-1.jobs", 's', true},
		{"r:oabcdef.lock", "", "r:oabcdef.lock", 'r', true},
		{"~x", "", "", 0, false},
		{"g:", "", "", 0, false},
		{"g:x/y", "", "", 0, false},
		{"G:x", "", "", 0, false},
		{"g:" + strings.Repeat("a", 65), "", "", 0, false},
		{"s:team", "", "", 0, false},
		{"a:notanid.x", "", "", 0, false},
		{"r:" + root + ".x", "", "", 0, false},
		{"x:abc.d", "", "", 0, false},
		{"g:Upper", "", "", 0, false},
	}
	for _, c := range cases {
		n, err := ParseName(c.raw, c.caller)
		if (err == nil) != c.ok {
			t.Errorf("ParseName(%q): err=%v, want ok=%v", c.raw, err, c.ok)
			continue
		}
		if c.ok && (n.Full != c.full || n.NS != c.ns) {
			t.Errorf("ParseName(%q) = %+v, want %s/%c", c.raw, n, c.full, c.ns)
		}
	}
	if _, err := ParseName("~x", ""); err != core.ErrAuth {
		t.Errorf("anonymous ~ should be an auth error, got %v", err)
	}

	e := newEnv(t)
	a, ta := mkRoot(t, randIP(), 1)
	_, tb := mkRoot(t, randIP(), 1)
	st, b, _ := e.do(t, "GET", "/v1/lk/g:free.one", "", "")
	want(t, st, b, 200, "free fence=0")
	st, b, _ = e.do(t, "GET", "/v1/lk/a:"+a+".x", "", "")
	want(t, st, b, 401, "err auth")
	st, b, _ = e.do(t, "GET", "/v1/lk/a:"+a+".x", tb, "")
	want(t, st, b, 403, "err auth forbidden")
	st, b, _ = e.do(t, "GET", "/v1/lk/~x", ta, "")
	want(t, st, b, 200, "free fence=0")
	st, b, _ = e.do(t, "POST", "/v1/lk/s:team.x", ta, "{}")
	want(t, st, b, 403, "members only")
	MemberFn = func(ctx context.Context, q core.Q, slug, root string) (bool, error) {
		return slug == "team" && root == a, nil
	}
	t.Cleanup(func() { MemberFn = nil })
	st, b, _ = e.do(t, "POST", "/v1/lk/s:team.x", ta, "{}")
	want(t, st, b, 200, "ok fence=1")
	st, b, _ = e.do(t, "POST", "/v1/lk/s:team.x", tb, "{}")
	want(t, st, b, 403, "members only")
	st, b, _ = e.do(t, "GET", "/v1/lk/s:team.x", "", "")
	want(t, st, b, 401, "err auth")
	st, b, _ = e.do(t, "POST", "/v1/lk/g:bad%20name", ta, "{}")
	want(t, st, b, 400, "err bad name")
}

func TestRoomNamespaceGate(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, randIP(), 1)
	_, tb := mkRoot(t, randIP(), 1)
	RoomFn = nil
	st, b, _ := e.do(t, "POST", "/v1/lk/r:oabcdef.x", ta, "{}")
	want(t, st, b, 403, "room members only")
	RoomFn = func(ctx context.Context, q core.Q, room, root string) (bool, error) {
		return room == "oabcdef" && root == a, nil
	}
	t.Cleanup(func() { RoomFn = nil })
	st, b, _ = e.do(t, "POST", "/v1/lk/r:oabcdef.x", ta, "{}")
	want(t, st, b, 200, "ok fence=1")
	st, b, _ = e.do(t, "POST", "/v1/lk/r:oabcdef.x", tb, "{}")
	want(t, st, b, 403, "room members only")
	st, b, _ = e.do(t, "POST", "/v1/ps/r:oabcdef.chat", ta, `{"text":"hi"}`)
	want(t, st, b, 200, "ok seq=1")
	st, b, _ = e.do(t, "GET", "/v1/ps/r:oabcdef.chat", tb, "")
	want(t, st, b, 403, "room members only")
	st, b, _ = e.do(t, "GET", "/v1/ps/r:oabcdef.chat", "", "")
	want(t, st, b, 401, "err auth")
}

// --- locks ---------------------------------------------------------------------------------------

func TestLockAcquireRenewReleaseFence(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, randIP(), 1)
	b, tb := mkRoot(t, randIP(), 1)
	_, tsub := mkSub(t, a)
	st, body, _ := e.do(t, "POST", "/v1/lk/g:t1", ta, `{"ttl_s":30}`)
	want(t, st, body, 200, "ok fence=1 until=")
	if !strings.Contains(body, "next: POST /v1/lk/g:t1/renew") {
		t.Fatalf("missing next tail: %q", body)
	}
	st, body, _ = e.do(t, "POST", "/v1/lk/g:t1", tsub, `{"ttl_s":30}`) // same root: renewal path, same fence
	want(t, st, body, 200, "ok fence=1")
	st, body, _ = e.do(t, "POST", "/v1/lk/g:t1", tb, "{}")
	want(t, st, body, 409, "err taken "+a+" ")
	st, body, _ = e.do(t, "POST", "/v1/lk/g:t1/renew", ta, `{"fence":1,"ttl_s":60}`)
	want(t, st, body, 200, "ok fence=1")
	st, body, _ = e.do(t, "POST", "/v1/lk/g:t1/renew", ta, `{"fence":2}`)
	want(t, st, body, 409, "err taken")
	st, body, _ = e.do(t, "POST", "/v1/lk/g:t1/renew", tb, `{"fence":1}`)
	want(t, st, body, 409, "err taken "+a)
	st, body, _ = e.do(t, "GET", "/v1/lk/g:t1", "", "")
	want(t, st, body, 200, "held "+a+" fence=1 until=")
	st, body, _ = e.do(t, "DELETE", "/v1/lk/g:t1", ta, `{"fence":2}`)
	want(t, st, body, 200, "ok stale")
	st, body, _ = e.do(t, "DELETE", "/v1/lk/g:t1", tb, `{"fence":1}`) // not the holder: stale too
	want(t, st, body, 200, "ok stale")
	st, body, _ = e.do(t, "GET", "/v1/lk/g:t1", "", "")
	want(t, st, body, 200, "held "+a)
	st, body, _ = e.do(t, "DELETE", "/v1/lk/g:t1", ta, `{"fence":1}`)
	if st != 200 || head(body) != "ok" {
		t.Fatalf("release: %d %q", st, body)
	}
	st, body, _ = e.do(t, "GET", "/v1/lk/g:t1", "", "")
	want(t, st, body, 200, "free fence=1")
	st, body, _ = e.do(t, "POST", "/v1/lk/g:t1", tb, "{}")
	want(t, st, body, 200, "ok fence=2")
	if err := CheckFence(context.Background(), testPool, "g:t1", 2); err != nil {
		t.Fatalf("CheckFence live: %v", err)
	}
	if err := CheckFence(context.Background(), testPool, "g:t1", 1); err == nil || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("CheckFence stale: %v", err)
	}
	_ = b
	st, body, _ = e.do(t, "POST", "/v1/lk/g:t1", ta, `{"ttl_s":9999}`)
	want(t, st, body, 400, "ttl_s must be 1..3600")

	// Two concurrent acquirers of a fresh lock: exactly one gets fence=1, the other 409 taken.
	var wg sync.WaitGroup
	res := make([]struct {
		st   int
		body string
	}, 2)
	for i, tok := range []string{ta, tb} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i].st, res[i].body, _ = e.do(t, "POST", "/v1/lk/g:t2", tok, "{}")
		}()
	}
	wg.Wait()
	oks, takens := 0, 0
	for _, r := range res {
		switch {
		case r.st == 200 && strings.HasPrefix(r.body, "ok fence=1 "):
			oks++
		case r.st == 409 && strings.HasPrefix(r.body, "err taken "):
			takens++
		default:
			t.Fatalf("unexpected: %d %q", r.st, r.body)
		}
	}
	if oks != 1 || takens != 1 {
		t.Fatalf("concurrent acquire: oks=%d takens=%d", oks, takens)
	}
}

func TestLockWaitFIFOAndCaps(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, randIP(), 1)
	_, tb := mkRoot(t, randIP(), 1)
	_, tc := mkRoot(t, randIP(), 1)
	st, body, _ := e.do(t, "POST", "/v1/lk/g:w", ta, `{"ttl_s":30}`)
	want(t, st, body, 200, "ok fence=1")
	type res struct {
		who  string
		body string
		at   time.Time
	}
	out := make(chan res, 2)
	wait := func(who, tok string) {
		st, body, _ := e.do(t, "POST", "/v1/lk/g:w", tok, `{"ttl_s":30,"wait":10}`)
		if st != 200 {
			body = fmt.Sprintf("%d %s", st, body)
		}
		out <- res{who, body, time.Now()}
	}
	go wait("b", tb)
	time.Sleep(200 * time.Millisecond)
	go wait("c", tc)
	time.Sleep(200 * time.Millisecond)
	if n := e.s.lq.waiting("g:w"); n != 2 {
		t.Fatalf("expected 2 queued waiters, have %d", n)
	}
	st, body, _ = e.do(t, "DELETE", "/v1/lk/g:w", ta, `{"fence":1}`)
	want(t, st, body, 200, "ok")
	first := <-out
	if first.who != "b" || !strings.HasPrefix(first.body, "ok fence=2 ") {
		t.Fatalf("first waiter: %+v", first)
	}
	select {
	case r := <-out:
		t.Fatalf("c should still wait, got %+v", r)
	case <-time.After(300 * time.Millisecond):
	}
	st, body, _ = e.do(t, "DELETE", "/v1/lk/g:w", tb, `{"fence":2}`)
	want(t, st, body, 200, "ok")
	second := <-out
	if second.who != "c" || !strings.HasPrefix(second.body, "ok fence=3 ") {
		t.Fatalf("second waiter: %+v", second)
	}
	if !second.at.After(first.at) {
		t.Fatal("FIFO order violated")
	}

	// Caps: 8 waiters per root, 64 per name; a refused waiter answers at once with retry=5.
	lq := newLockQueue()
	for i := 0; i < lockWaitersPerRoot; i++ {
		if _, ok := lq.enqueue("g:x", "aroot"); !ok {
			t.Fatalf("waiter %d refused", i)
		}
	}
	if _, ok := lq.enqueue("g:x", "aroot"); ok {
		t.Fatal("9th waiter of one root accepted")
	}
	for i := lockWaitersPerRoot; i < lockWaitersPerName; i++ {
		if _, ok := lq.enqueue("g:x", fmt.Sprintf("r%d", i)); !ok {
			t.Fatalf("waiter %d refused", i)
		}
	}
	if _, ok := lq.enqueue("g:x", "other"); ok {
		t.Fatal("65th waiter accepted")
	}
	st, body, _ = e.do(t, "POST", "/v1/lk/g:w2", ta, `{"ttl_s":30}`)
	want(t, st, body, 200, "ok fence=1")
	for i := 0; i < lockWaitersPerName; i++ {
		e.s.lq.enqueue("g:w2", fmt.Sprintf("f%d", i))
	}
	start := time.Now()
	st, body, _ = e.do(t, "POST", "/v1/lk/g:w2", tb, `{"wait":10}`)
	want(t, st, body, 409, "retry=5")
	if time.Since(start) > 2*time.Second {
		t.Fatal("refused waiter should answer immediately")
	}
}

// waiting counts the queued waiters of name under the queue mutex (race-free test inspection).
func (l *lockQueue) waiting(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.q[name])
}

func TestLeaderElectionFenceIncrease(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, randIP(), 1)
	b, tb := mkRoot(t, randIP(), 1)
	_, tf := mkRoot(t, randIP(), 1)
	ctx := context.Background()
	var repBefore int
	testPool.QueryRow(ctx, `SELECT rep FROM identities WHERE id = $1`, a).Scan(&repBefore)
	st, body, _ := e.do(t, "POST", "/v1/lk/g:sw.leader", ta, `{"ttl_s":1}`)
	want(t, st, body, 200, "ok fence=1")
	// Follower 1 watches fence 1: the lease deadline is observed without the janitor.
	done := make(chan string, 1)
	go func() {
		_, body, _ := e.do(t, "GET", "/v1/lk/g:sw.leader?wait=10&fence=1", tf, "")
		done <- body
	}()
	select {
	case body := <-done:
		if !strings.HasPrefix(body, "free fence=1") {
			t.Fatalf("follower after expiry: %q", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follower did not observe the expiry")
	}
	// New leader: fence increases; the takeover emits the old lease's expiry notice.
	st, body, _ = e.do(t, "POST", "/v1/lk/g:sw.leader", tb, `{"ttl_s":30}`)
	want(t, st, body, 200, "ok fence=2")
	v, _ := mails.Load(a)
	got, _ := v.([]string)
	if len(got) == 0 || !strings.Contains(got[len(got)-1], "lock-expired g:sw.leader fence=1 holder="+a) {
		t.Fatalf("expiry mail: %q", got)
	}
	var repAfter int
	testPool.QueryRow(ctx, `SELECT rep FROM identities WHERE id = $1`, a).Scan(&repAfter)
	if repAfter != repBefore-1 {
		t.Fatalf("lease expiry penalty: rep %d -> %d", repBefore, repAfter)
	}
	// Follower 2 with the stale fence returns at once.
	st, body, _ = e.do(t, "GET", "/v1/lk/g:sw.leader?wait=10&fence=1", tf, "")
	want(t, st, body, 200, "held "+b+" fence=2")
	// Follower 3 watches fence 2 and is woken by the release.
	go func() {
		_, body, _ := e.do(t, "GET", "/v1/lk/g:sw.leader?wait=10&fence=2", tf, "")
		done <- body
	}()
	time.Sleep(200 * time.Millisecond)
	st, body, _ = e.do(t, "DELETE", "/v1/lk/g:sw.leader", tb, `{"fence":2}`)
	want(t, st, body, 200, "ok")
	select {
	case body := <-done:
		if !strings.HasPrefix(body, "free fence=2") {
			t.Fatalf("follower after release: %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("follower not woken by release")
	}
	// Anonymous followers cannot wait: immediate state with retry=5.
	st, body, _ = e.do(t, "POST", "/v1/lk/g:sw.leader", tb, `{"ttl_s":30}`)
	want(t, st, body, 200, "ok fence=3")
	start := time.Now()
	st, body, _ = e.do(t, "GET", "/v1/lk/g:sw.leader?wait=10&fence=3", "", "")
	want(t, st, body, 200, "held "+b+" fence=3 until=")
	if !strings.Contains(head(body), " retry=5") || time.Since(start) > 2*time.Second {
		t.Fatalf("anonymous wait: %q after %s", body, time.Since(start))
	}
	st, body, _ = e.do(t, "DELETE", "/v1/lk/g:sw.leader", tb, `{"fence":3}`)
	want(t, st, body, 200, "ok")

	// on_expire topic: the janitor publishes lock-expired there (as the system root).
	st, body, _ = e.do(t, "POST", "/v1/lk/g:sw2", ta, `{"ttl_s":1,"on_expire":{"ps":"g:sw2.events"}}`)
	want(t, st, body, 200, "ok fence=1")
	time.Sleep(1100 * time.Millisecond)
	if err := e.s.janLocks(ctx); err != nil {
		t.Fatal(err)
	}
	st, body, _ = e.do(t, "GET", "/v1/ps/g:sw2.events", "", "")
	want(t, st, body, 200, " asystem ")
	if !strings.Contains(body, "lock-expired g:sw2 fence=1 holder="+a) {
		t.Fatalf("on_expire publish: %q", body)
	}
	if err := e.s.janLocks(ctx); err != nil { // idempotent: no second notice
		t.Fatal(err)
	}
	_, body, _ = e.do(t, "GET", "/v1/ps/g:sw2.events", "", "")
	if strings.Count(body, "lock-expired") != 1 {
		t.Fatalf("expiry notice sent twice: %q", body)
	}
	// Resume lists held locks.
	st, body, _ = e.do(t, "POST", "/v1/lk/g:held", ta, `{"ttl_s":60}`)
	want(t, st, body, 200, "ok fence=1")
	lines := e.s.resume(ctx, a)
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "lock g:held fence=1 until=") {
		t.Fatalf("resume: %q", lines)
	}
}

func TestCheckFence(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, ta := mkRoot(t, randIP(), 1)
	if err := CheckFence(ctx, testPool, "g:cf.none", 1); err == nil || err.Error() != "err fenced 0" {
		t.Fatalf("unknown lock: %v", err)
	}
	st, body, _ := e.do(t, "POST", "/v1/lk/g:cf", ta, `{"ttl_s":60}`)
	want(t, st, body, 200, "ok fence=1")
	if err := CheckFence(ctx, testPool, "g:cf", 1); err != nil {
		t.Fatalf("live fence: %v", err)
	}
	if err := CheckFence(ctx, testPool, "g:cf", 2); err == nil || err.Error() != "err fenced 1" {
		t.Fatalf("wrong fence: %v", err)
	}
	st, body, _ = e.do(t, "DELETE", "/v1/lk/g:cf", ta, `{"fence":1}`)
	want(t, st, body, 200, "ok")
	if err := CheckFence(ctx, testPool, "g:cf", 1); err == nil || err.Error() != "err fenced 1" {
		t.Fatalf("released lock: %v", err)
	}
	var ae *core.APIError
	if err := CheckFence(ctx, testPool, "g:cf", 1); !asAPI(err, &ae) || ae.Status != 409 || ae.Code != "fenced" {
		t.Fatalf("fenced error shape: %#v", err)
	}
}

func asAPI(err error, ae **core.APIError) bool {
	a, ok := err.(*core.APIError)
	if ok {
		*ae = a
	}
	return ok
}

func TestAcquireTxAndHandover(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, ta := mkRoot(t, randIP(), 1)
	b, tb := mkRoot(t, randIP(), 1)
	err := core.Tx(ctx, testPool, func(tx pgx.Tx) error {
		f, u, err := AcquireTx(ctx, tx, "g:h1", a, a, time.Minute)
		if err != nil || f != 1 || !u.After(time.Now()) {
			return fmt.Errorf("first acquire: %d %v %v", f, u, err)
		}
		if f, _, err = AcquireTx(ctx, tx, "g:h1", a, a, time.Minute); err != nil || f != 1 {
			return fmt.Errorf("renewal path: %d %v", f, err)
		}
		if _, _, err = AcquireTx(ctx, tx, "g:h1", b, b, time.Minute); err == nil || !strings.HasPrefix(err.Error(), "err taken "+a) {
			return fmt.Errorf("taken: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Handover(ctx, testPool, "g:h1", 5, a, b, b, time.Minute, "note"); err == nil || err.Error() != "err fenced 1" {
		t.Fatalf("handover with a stale fence: %v", err)
	}
	f, u, err := Handover(ctx, testPool, "g:h1", 1, a, b, b, time.Minute, "take over\nsecond line")
	if err != nil || f != 2 || !u.After(time.Now()) {
		t.Fatalf("handover: %d %v %v", f, u, err)
	}
	st, body, _ := e.do(t, "GET", "/v1/lk/g:h1", "", "")
	want(t, st, body, 200, "held "+b+" fence=2")
	v, _ := mails.Load(b)
	got, _ := v.([]string)
	if len(got) == 0 || !strings.Contains(got[len(got)-1], "handover lk g:h1 fence=2 from "+a+"\nnote: take over\n  second line") {
		t.Fatalf("handover mail: %q", got)
	}
	st, body, _ = e.do(t, "POST", "/v1/lk/g:h1/renew", ta, `{"fence":1}`)
	want(t, st, body, 409, "err taken "+b)
	st, body, _ = e.do(t, "POST", "/v1/lk/g:h1/renew", tb, `{"fence":2}`)
	want(t, st, body, 200, "ok fence=2")
	if _, _, err := Handover(ctx, testPool, "g:h1", 2, a, b, b, time.Minute, ""); err == nil {
		t.Fatal("handover by a non-holder root accepted")
	}
	if _, _, err := Handover(ctx, testPool, "g:h1", 2, b, "bad", b, time.Minute, ""); err == nil {
		t.Fatal("handover to a bad id accepted")
	}
}

func TestReleaseByOwner(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, ta := mkRoot(t, randIP(), 1)
	b, tb := mkRoot(t, randIP(), 1)
	st, body, _ := e.do(t, "POST", "/v1/lk/g:rb", ta, `{"ttl_s":60}`)
	want(t, st, body, 200, "ok fence=1")
	if err := ReleaseByOwner(ctx, testPool, b, "g:rb"); err != nil { // not the holder: no-op
		t.Fatal(err)
	}
	st, body, _ = e.do(t, "GET", "/v1/lk/g:rb", "", "")
	want(t, st, body, 200, "held "+a)
	done := make(chan string, 1)
	go func() {
		_, body, _ := e.do(t, "POST", "/v1/lk/g:rb", tb, `{"wait":10}`)
		done <- body
	}()
	time.Sleep(200 * time.Millisecond)
	if err := ReleaseByOwner(ctx, testPool, a, "g:rb"); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-done:
		if !strings.HasPrefix(body, "ok fence=2 ") {
			t.Fatalf("waiter after ReleaseByOwner: %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiter not woken")
	}
	if err := ReleaseByOwner(ctx, testPool, a, "g:unknown"); err != nil {
		t.Fatal(err)
	}
}

// --- barriers ------------------------------------------------------------------------------------

func TestBarrierTripRankGather(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, randIP(), 1)
	b, tb := mkRoot(t, randIP(), 1)
	_, tc := mkRoot(t, randIP(), 1)
	done := make(chan string, 1)
	go func() {
		_, body, _ := e.do(t, "POST", "/v1/br/g:b1", ta, `{"n":2,"data":"alpha","wait":10}`)
		done <- body
	}()
	time.Sleep(250 * time.Millisecond)
	st, body, _ := e.do(t, "GET", "/v1/br/g:b1", "", "")
	want(t, st, body, 200, "wait 1/2 gen=0 until=")
	st, body, _ = e.do(t, "POST", "/v1/br/g:b1", tb, `{"n":2,"data":"beta\nline2"}`)
	want(t, st, body, 200, "ok gen=0 rank=1 k=2/2")
	select {
	case body := <-done:
		if !strings.HasPrefix(body, "ok gen=0 rank=0 k=2/2") {
			t.Fatalf("waiting party: %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiting party not released by the trip")
	}
	st, body, _ = e.do(t, "GET", "/v1/br/g:b1?gen=0", "", "")
	want(t, st, body, 200, "tripped gen=0 n=2\n- "+a+" rank=0 alpha\n- "+b+" rank=1 beta\n  line2\n")
	st, body, _ = e.do(t, "POST", "/v1/br/g:b1", tc, `{"n":3}`)
	want(t, st, body, 409, "err bad n=2")
	st, body, _ = e.do(t, "POST", "/v1/br/g:b1", tc, `{}`) // joins the next generation
	want(t, st, body, 200, "wait 1/2 until=")
	if field(body, "gen") != "1" || field(body, "rank") != "0" {
		t.Fatalf("second generation: %q", body)
	}
	st, body, _ = e.do(t, "POST", "/v1/br/g:b1", tc, `{"data":"again"}`) // idempotent re-post
	want(t, st, body, 200, "wait 1/2 until=")
	st, body, _ = e.do(t, "GET", "/v1/br/g:b1", "", "")
	want(t, st, body, 200, "wait 1/2 gen=1 until=")
	st, body, _ = e.do(t, "GET", "/v1/br/g:b1?gen=7", "", "")
	want(t, st, body, 404, "err notfound")
	st, body, _ = e.do(t, "POST", "/v1/br/g:b2", tc, `{}`)
	want(t, st, body, 400, "n required")
	st, body, _ = e.do(t, "POST", "/v1/br/g:b3", tc, `{"n":2,"allow":["`+a+`"]}`)
	want(t, st, body, 200, "wait 1/2")
	st, body, _ = e.do(t, "POST", "/v1/br/g:b3", tb, `{}`)
	want(t, st, body, 403, "err auth forbidden")
	st, body, _ = e.do(t, "POST", "/v1/br/g:b3", ta, `{}`)
	want(t, st, body, 200, "ok gen=0 rank=1 k=2/2")

	// Expiry: a generation past its deadline closes as expired; stragglers read `expired k/n`.
	st, body, _ = e.do(t, "POST", "/v1/br/g:b4", ta, `{"n":2,"ttl_s":1}`)
	want(t, st, body, 200, "wait 1/2")
	time.Sleep(1100 * time.Millisecond)
	if err := e.s.janBarriers(context.Background()); err != nil {
		t.Fatal(err)
	}
	st, body, _ = e.do(t, "GET", "/v1/br/g:b4?gen=0", "", "")
	want(t, st, body, 200, "expired gen=0 k=1/2")
	st, body, _ = e.do(t, "GET", "/v1/br/g:b4", "", "")
	want(t, st, body, 200, "wait 0/2 gen=1")
}

func TestBarrierDistinctBySuperL0Weight0(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, "10.1.1.1", 1)
	_, tb := mkRoot(t, "10.1.1.2", 1) // same /24 as a
	_, tc := mkRoot(t, "10.2.2.2", 0) // other network but L0: weighs 0
	_, td := mkRoot(t, "10.3.3.3", 1)
	st, body, _ := e.do(t, "POST", "/v1/br/g:bd", ta, `{"n":2,"distinct":true}`)
	want(t, st, body, 200, "wait 1/2")
	st, body, _ = e.do(t, "POST", "/v1/br/g:bd", tb, `{}`)
	want(t, st, body, 200, "wait 1/2")
	if field(body, "rank") != "1" {
		t.Fatalf("rank still assigned per party: %q", body)
	}
	st, body, _ = e.do(t, "POST", "/v1/br/g:bd", tc, `{}`)
	want(t, st, body, 200, "wait 1/2")
	st, body, _ = e.do(t, "POST", "/v1/br/g:bd", td, `{}`)
	want(t, st, body, 200, "ok gen=0 rank=3 k=2/2")
	// Without distinct the same four would have tripped at the second arrival.
	st, body, _ = e.do(t, "POST", "/v1/br/g:bn", ta, `{"n":2}`)
	want(t, st, body, 200, "wait 1/2")
	st, body, _ = e.do(t, "POST", "/v1/br/g:bn", tb, `{}`)
	want(t, st, body, 200, "ok gen=0 rank=1 k=2/2")
}

// --- rendezvous ----------------------------------------------------------------------------------

func TestRendezvousHMACAndCap(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, ta := mkRoot(t, randIP(), 1)
	b, tb := mkRoot(t, randIP(), 1)
	_, tc := mkRoot(t, randIP(), 1)
	_, td := mkRoot(t, randIP(), 1)
	st, body, _ := e.do(t, "POST", "/v1/rv", ta, `{"key":"gh:o/r#1","cap":2,"data":"from a"}`)
	want(t, st, body, 200, "ok rv=x")
	id := strings.TrimPrefix(field(body, "rv"), "")
	if !core.ValidIDPrefix(id, 'x') || field(body, "peers") != "1" {
		t.Fatalf("first arrival: %q", body)
	}
	st, body, _ = e.do(t, "POST", "/v1/rv", tb, `{"key":"gh:o/r#1","data":"from b"}`)
	want(t, st, body, 200, "ok rv="+id+" peers=2")
	if !strings.Contains(body, "\n- "+a+" until=") || !strings.Contains(body, " from a") || !strings.Contains(body, "\n- "+b+" until=") {
		t.Fatalf("peer lines: %q", body)
	}
	st, body, _ = e.do(t, "POST", "/v1/rv", tc, `{"key":"gh:o/r#1"}`)
	want(t, st, body, 409, "err full cap=2")
	st, body, _ = e.do(t, "POST", "/v1/rv", tb, `{"key":"gh:o/r#1","cap":3}`)
	want(t, st, body, 409, "err bad cap=2")
	st, body, _ = e.do(t, "POST", "/v1/rv", tb, `{"key":"gh:o/r#1","data":"b again"}`) // heartbeat refreshes
	want(t, st, body, 200, "ok rv="+id+" peers=2")
	st, body, _ = e.do(t, "POST", "/v1/rv", td, `{"key":"gh:o/r#2"}`)
	want(t, st, body, 200, "ok rv=x")
	if field(body, "rv") == id {
		t.Fatal("different keys share an id")
	}
	var kh []byte
	if err := testPool.QueryRow(ctx, `SELECT khash FROM rv WHERE id = $1`, id).Scan(&kh); err != nil {
		t.Fatal(err)
	}
	plain := sha256.Sum256([]byte("gh:o/r#1"))
	if string(kh) == string(plain[:]) || string(kh) != string(e.s.khash("gh:o/r#1")) {
		t.Fatal("khash must be the HMAC of the key, never a plain hash")
	}
	var cols int
	testPool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_name = 'rv' AND column_name = 'key'`).Scan(&cols)
	if cols != 0 {
		t.Fatal("rv must not store the key")
	}
	st, body, _ = e.do(t, "GET", "/v1/rv/"+id, tc, "")
	want(t, st, body, 200, "rv "+id+" peers=2 cap=2 until=")
	st, body, _ = e.do(t, "GET", "/v1/rv/"+id, "", "")
	want(t, st, body, 401, "err auth")
	st, body, _ = e.do(t, "GET", "/v1/rv/xzzzzzz", tc, "")
	want(t, st, body, 404, "err notfound")
	// wait until min peers
	done := make(chan string, 1)
	go func() {
		_, body, _ := e.do(t, "POST", "/v1/rv", tc, `{"key":"k3","min":2,"wait":10}`)
		done <- body
	}()
	time.Sleep(250 * time.Millisecond)
	st, body, _ = e.do(t, "POST", "/v1/rv", td, `{"key":"k3"}`)
	want(t, st, body, 200, "peers=2")
	select {
	case body := <-done:
		if field(body, "peers") != "2" {
			t.Fatalf("waiting peer: %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiting peer not woken")
	}
	typ, _, url, ok := e.s.rvResolve(ctx, id)
	if !ok || typ != "rv" || url != "/v1/rv/"+id {
		t.Fatalf("resolver: %s %s %v", typ, url, ok)
	}
	// IsPeer is the x:<rv id> predicate: live peers of a live rendezvous only.
	for _, c := range []struct {
		rv, root string
		want     bool
	}{{id, a, true}, {id, b, true}, {id, mustRoot(t, td), false}, {"xzzzzzz", a, false}, {id, "bogus", false}} {
		if got, err := IsPeer(ctx, testPool, c.rv, c.root); err != nil || got != c.want {
			t.Fatalf("IsPeer(%s, %s) = %v %v, want %v", c.rv, c.root, got, err, c.want)
		}
	}
	if _, err := testPool.Exec(ctx, `UPDATE rv_peers SET until = now() - interval '1 second' WHERE rv = $1 AND root = $2`, id, a); err != nil {
		t.Fatal(err)
	}
	if got, _ := IsPeer(ctx, testPool, id, a); got {
		t.Fatal("expired peer still a peer")
	}
}

// --- topics --------------------------------------------------------------------------------------

func TestTopicGaplessOrderAndIdempotentKey(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, randIP(), 1)
	_, tb := mkRoot(t, randIP(), 1)
	const n = 20
	seqs := make(chan int64, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok := ta
			if i%2 == 1 {
				tok = tb
			}
			st, body, _ := e.do(t, "POST", "/v1/ps/g:tp", tok, js(map[string]any{"text": fmt.Sprintf("m%d", i)}))
			if st != 200 {
				t.Errorf("publish %d: %d %q", i, st, body)
				return
			}
			s, _ := strconv.ParseInt(field(body, "seq"), 10, 64)
			seqs <- s
		}()
	}
	wg.Wait()
	close(seqs)
	var got []int64
	for s := range seqs {
		got = append(got, s)
	}
	slices.Sort(got)
	for i, s := range got {
		if s != int64(i+1) {
			t.Fatalf("gap or duplicate in seqs: %v", got)
		}
	}
	st, body, _ := e.do(t, "POST", "/v1/ps/g:tp", ta, `{"text":"keyed","key":"k1"}`)
	want(t, st, body, 200, "ok seq=21")
	st, body, _ = e.do(t, "POST", "/v1/ps/g:tp", ta, `{"text":"keyed","key":"k1"}`)
	want(t, st, body, 200, "ok seq=21 idem=replay")
	st, body, _ = e.do(t, "POST", "/v1/ps/g:tp", tb, `{"text":"other root same key","key":"k1"}`)
	want(t, st, body, 200, "ok seq=22")
	st, body, _ = e.do(t, "POST", "/v1/ps/g:tp", ta, `{"text":"hdr"}`, "Idempotency-Key", "h1")
	want(t, st, body, 200, "ok seq=23")
	st, body, _ = e.do(t, "POST", "/v1/ps/g:tp", ta, `{"text":"hdr"}`, "Idempotency-Key", "h1")
	want(t, st, body, 200, "ok seq=23\nidem=replay")
	st, body, _ = e.do(t, "GET", "/v1/ps/g:tp?after=0&k=50", "", "")
	want(t, st, body, 200, "ps g:tp last=23 msgs=23")
	lines := strings.Split(strings.TrimSpace(body), "\n")
	rows := lines[1 : len(lines)-2]
	if len(rows) != 23 || lines[len(lines)-2] != "next=23" || !strings.HasPrefix(lines[len(lines)-1], "next: GET /v1/ps/g:tp?after=23&wait=85") {
		t.Fatalf("pull shape: %q", body)
	}
	for i, l := range rows {
		if !strings.HasPrefix(l, strconv.Itoa(i+1)+" a") {
			t.Fatalf("row %d out of order: %q", i, l)
		}
	}
	if !strings.HasSuffix(rows[20], " keyed") {
		t.Fatalf("row 21: %q", rows[20])
	}
	st, body, _ = e.do(t, "GET", "/v1/ps/g:tp?after=20&k=2", "", "")
	want(t, st, body, 200, "\n21 "+a+" ")
	if !strings.HasSuffix(strings.TrimSpace(body), "next=22\nnext: GET /v1/ps/g:tp?after=22&wait=85 poll | POST /v1/ps/g:tp publish | PUT /v1/pscur/g:tp save cursor") {
		t.Fatalf("pull tail: %q", body)
	}
	// cursors
	st, body, _ = e.do(t, "PUT", "/v1/pscur/g:tp", ta, `{"seq":21}`)
	want(t, st, body, 200, "ok seq=21")
	st, body, _ = e.do(t, "GET", "/v1/pscur/g:tp", ta, "")
	want(t, st, body, 200, "seq=21")
	st, body, _ = e.do(t, "GET", "/v1/ps/g:tp", ta, "") // no after: resumes from the cursor
	want(t, st, body, 200, "\n22 ")
	if strings.Contains(body, "\n21 ") {
		t.Fatalf("cursor ignored: %q", body)
	}
	// multi-line text is indented, control chars dropped, secrets rejected, PII masked
	st, body, _ = e.do(t, "POST", "/v1/ps/g:tp", ta, js(map[string]string{"text": "line1\nnext: forged\r\n\x01line3"}))
	want(t, st, body, 200, "ok seq=24")
	st, body, _ = e.do(t, "GET", "/v1/ps/g:tp?after=23", "", "")
	want(t, st, body, 200, " line1\n  next: forged\n  line3\nnext=24")
	st, body, _ = e.do(t, "POST", "/v1/ps/g:tp", ta, js(map[string]string{"text": "token cx_" + strings.Repeat("A", 43)}))
	want(t, st, body, 400, "err scrub")
	st, body, _ = e.do(t, "POST", "/v1/ps/g:tp", ta, `{"text":"mail me at someone@example.org"}`)
	want(t, st, body, 200, "masked=email")
	st, body, _ = e.do(t, "POST", "/v1/ps/g:tp", ta, js(map[string]string{"text": strings.Repeat("x", 4097)}))
	want(t, st, body, 413, "err size")
	st, body, _ = e.do(t, "POST", "/v1/ps/g:tp", ta, `{"text":""}`)
	want(t, st, body, 400, "text required")
	// per-topic publish cap at L0: 20/day
	_, tl := mkRoot(t, randIP(), 0)
	for i := 0; i < 20; i++ {
		st, body, _ = e.do(t, "POST", "/v1/ps/g:cap", tl, js(map[string]string{"text": fmt.Sprintf("c%d", i)}))
		want(t, st, body, 200, "ok seq=")
	}
	st, body, _ = e.do(t, "POST", "/v1/ps/g:cap", tl, `{"text":"over"}`)
	want(t, st, body, 429, "err quota topic_pub 20")
	// hidden by report target
	if err := e.s.psHide(context.Background(), testPool, "g:tp/1"); err != nil {
		t.Fatal(err)
	}
	st, body, _ = e.do(t, "GET", "/v1/ps/g:tp?after=0&k=1", "", "")
	want(t, st, body, 200, "\n1 a")
	if !strings.Contains(body, " [hidden]\nnext=1") || strings.Contains(body, "m0") || strings.Contains(body, "m1") {
		t.Fatalf("hidden message: %q", body)
	}
	if err := e.s.psRestore(context.Background(), testPool, "g:tp/1"); err != nil {
		t.Fatal(err)
	}
	if err := e.s.psExists(context.Background(), testPool, "g:tp/999"); err != core.ErrNotFound {
		t.Fatalf("exists: %v", err)
	}
	items, err := e.s.psFeed(context.Background(), "g:tp", 5)
	if err != nil || len(items) != 5 || items[0].ID != "g:tp/25" || items[0].Title != "mail me at <email>" {
		t.Fatalf("feed: %v %v", items, err)
	}
	if _, err := e.s.psFeed(context.Background(), "a:"+a+".private", 5); err != core.ErrNotFound {
		t.Fatalf("private feed: %v", err)
	}
}

func TestTopicPullLongPoll(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, randIP(), 1)
	b, tb := mkRoot(t, randIP(), 1)
	done := make(chan string, 1)
	go func() {
		_, body, _ := e.do(t, "GET", "/v1/ps/g:lp?after=0&wait=10", ta, "")
		done <- body
	}()
	time.Sleep(250 * time.Millisecond)
	st, body, _ := e.do(t, "POST", "/v1/ps/g:lp", tb, `{"text":"hello"}`)
	want(t, st, body, 200, "ok seq=1")
	select {
	case body := <-done:
		if !strings.Contains(body, "\n1 "+b+" ") || !strings.Contains(body, " hello\nnext=1") {
			t.Fatalf("long-poll result: %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pull not woken by publish")
	}
	start := time.Now()
	st, body, _ = e.do(t, "GET", "/v1/ps/g:lp?after=1&wait=10", "", "") // anonymous: no wait
	want(t, st, body, 200, "retry=5")
	if time.Since(start) > 2*time.Second {
		t.Fatal("anonymous wait should answer immediately")
	}
	st, body, _ = e.do(t, "GET", "/v1/ps/g:lp?after=1&wait=1", ta, "") // timeout: empty, next unchanged
	want(t, st, body, 200, "\nnext=1")
	if strings.Contains(body, "retry=") {
		t.Fatalf("honoured wait must not say retry: %q", body)
	}
}

func TestPublishPullPushExports(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, ta := mkRoot(t, randIP(), 1)
	seq, err := Publish(ctx, testPool, "g:ex", core.SystemID, core.SystemID, "hello", "")
	if err != nil || seq != 1 {
		t.Fatalf("Publish: %d %v", seq, err)
	}
	seq, replay, err := PublishFlags(ctx, testPool, "g:ex", core.SystemID, core.SystemID, "<topic> 5 who\nbody", "sub:u1:5", nil)
	if err != nil || seq != 2 || replay {
		t.Fatalf("PublishFlags: %d %v %v", seq, replay, err)
	}
	if seq, replay, err = PublishFlags(ctx, testPool, "g:ex", core.SystemID, core.SystemID, "again", "sub:u1:5", nil); err != nil || seq != 2 || !replay {
		t.Fatalf("replay: %d %v %v", seq, replay, err)
	}
	if _, err := Publish(ctx, testPool, "bad name", core.SystemID, core.SystemID, "x", ""); err == nil {
		t.Fatal("bad topic accepted")
	}
	if _, err := Publish(ctx, testPool, "g:ex", "nope", core.SystemID, "x", ""); err == nil {
		t.Fatal("bad by accepted")
	}
	msgs, err := Pull(ctx, testPool, "g:ex", 0, 10)
	if err != nil || len(msgs) != 2 || msgs[0].Text != "hello" || !slices.Contains(msgs[1].Flags, "via=sub") || msgs[1].Key != "sub:u1:5" {
		t.Fatalf("Pull: %+v %v", msgs, err)
	}
	// Publish inside a caller's transaction stays gapless with concurrent handler publishes.
	err = core.Tx(ctx, testPool, func(tx pgx.Tx) error {
		s, err := Publish(ctx, tx, "g:ex", core.SystemID, core.SystemID, "in tx", "")
		if err != nil || s != 3 {
			return fmt.Errorf("tx publish: %d %v", s, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	st, body, _ := e.do(t, "GET", "/v1/ps/g:ex?after=0", "", "")
	want(t, st, body, 200, "\n3 asystem ")
	// Non-system roots pass the namespace gate and the daily caps inside Publish.
	b, _ := mkRoot(t, randIP(), 1)
	if _, err := Publish(ctx, testPool, "a:"+b+".priv", a, a, "intrude", ""); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("Publish into another root's tree: %v", err)
	}
	if seq, err := Publish(ctx, testPool, "~mine", a, a, "own tree", ""); err != nil || seq != 1 {
		t.Fatalf("Publish own tree: %d %v", seq, err)
	}
	l0, _ := mkRoot(t, randIP(), 0)
	for i := 0; i < 20; i++ {
		if _, err := Publish(ctx, testPool, "g:excap", l0, l0, "c", "k"+strconv.Itoa(i)); err != nil {
			t.Fatalf("Publish %d: %v", i, err)
		}
	}
	if _, err := Publish(ctx, testPool, "g:excap", l0, l0, "over", ""); err == nil || !strings.Contains(err.Error(), "quota topic_pub") {
		t.Fatalf("Publish past the L0 cap: %v", err)
	}
	if seq, err := Publish(ctx, testPool, "g:excap", l0, l0, "c", "k3"); err != nil || seq != 4 { // replay: no cap charged
		t.Fatalf("Publish replay over cap: %d %v", seq, err)
	}
	// Hidden messages pull without their text.
	if err := e.s.psHide(ctx, testPool, "g:ex/1"); err != nil {
		t.Fatal(err)
	}
	if msgs, err := Pull(ctx, testPool, "g:ex", 0, 1); err != nil || len(msgs) != 1 || !msgs[0].Hidden || msgs[0].Text != "" {
		t.Fatalf("hidden pull: %+v %v", msgs, err)
	}
	// Push: exactly-once by key, queue auto-created.
	id1, err := Push(ctx, testPool, "g:exq", "job one", "sub:u1:5")
	if err != nil || id1 == 0 {
		t.Fatalf("Push: %d %v", id1, err)
	}
	if id, err := Push(ctx, testPool, "g:exq", "job one again", "sub:u1:5"); err != nil || id != id1 {
		t.Fatalf("Push replay: %d %v (want %d)", id, err, id1)
	}
	id2, err := Push(ctx, testPool, "g:exq", "job two", "sub:u1:6")
	if err != nil || id2 == id1 {
		t.Fatalf("Push second: %d %v", id2, err)
	}
	if _, err := Push(ctx, testPool, "g:exq", "", ""); err == nil {
		t.Fatal("empty body accepted")
	}
	st, body, _ = e.do(t, "GET", "/v1/wq/g:exq", "", "")
	want(t, st, body, 200, "wq g:exq ready=2 leased=0 done=0 dead=0")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:exq/take", ta, `{"k":1}`)
	want(t, st, body, 200, "ok k=1\n"+strconv.FormatInt(id1, 10)+" deliveries=1 receipt=")
	if !strings.Contains(body, "\n  job one\n") {
		t.Fatalf("take body: %q", body)
	}
	// Export writes the root's rows as JSON lines.
	var sb strings.Builder
	if err := e.s.export(ctx, core.SystemID, &sb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb.String(), `"kind":"topic"`) || !strings.Contains(sb.String(), `"kind":"msg"`) {
		t.Fatalf("export: %q", sb.String())
	}
}

// --- queues --------------------------------------------------------------------------------------

var receiptRx = regexp.MustCompile(`receipt=([0-9a-f]{32})`)

func TestQueueTakeAckStaleReceipt409(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, randIP(), 1)
	_, tb := mkRoot(t, randIP(), 1)
	st, body, _ := e.do(t, "POST", "/v1/wq/g:q1", ta, `{"items":["a","b\nmore","c"]}`)
	want(t, st, body, 200, "ok n=3 ids=")
	ids := strings.Split(field(body, "ids"), ",")
	if len(ids) != 3 {
		t.Fatalf("ids: %q", body)
	}
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/take", tb, `{"k":2,"vis_s":30}`)
	want(t, st, body, 200, "ok k=2\n"+ids[0]+" deliveries=1 receipt=")
	if !strings.Contains(body, "\n  a\n"+ids[1]+" deliveries=1 receipt=") || !strings.Contains(body, "\n  b\n  more\n") {
		t.Fatalf("take blocks: %q", body)
	}
	rc := receiptRx.FindAllStringSubmatch(body, -1)
	if len(rc) != 2 {
		t.Fatalf("receipts: %q", body)
	}
	r1, r2 := rc[0][1], rc[1][1]
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/ack", tb, js(map[string]string{"receipt": r1}))
	want(t, st, body, 200, "ok done="+ids[0])
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/ack", tb, js(map[string]string{"receipt": r1}))
	want(t, st, body, 409, "err taken")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/ack", tb, `{"receipt":"deadbeef"}`)
	want(t, st, body, 409, "err taken")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/extend", tb, `{"receipt":"00000000000000000000000000000000","vis_s":60}`)
	want(t, st, body, 409, "err taken")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/extend", tb, js(map[string]any{"receipt": r2, "vis_s": 60}))
	want(t, st, body, 200, "ok until=")
	st, body, _ = e.do(t, "GET", "/v1/wq/g:q1", "", "")
	want(t, st, body, 200, "wq g:q1 ready=1 leased=1 done=1 dead=0")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/nack", tb, js(map[string]any{"receipt": r2, "delay_s": 0}))
	want(t, st, body, 200, "ok ready="+ids[1])
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/ack", tb, js(map[string]string{"receipt": r2}))
	want(t, st, body, 409, "err taken")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/take", tb, `{"k":5}`)
	want(t, st, body, 200, "ok k=2\n"+ids[1]+" deliveries=2 receipt=")
	// Fenced ack: the lock's fence is enforced in the ack transaction.
	st, body, _ = e.do(t, "POST", "/v1/lk/g:q1.lead", tb, `{"ttl_s":60}`)
	want(t, st, body, 200, "ok fence=1")
	rc = receiptRx.FindAllStringSubmatch(body, -1)
	_, body, _ = e.do(t, "GET", "/v1/wq/g:q1", "", "")
	st, body2, _ := e.do(t, "POST", "/v1/wq/g:q1/take", tb, `{"k":1}`)
	if st != 200 {
		t.Fatalf("take: %d %q", st, body2)
	}
	_ = body
	_, body, _ = e.do(t, "POST", "/v1/wq/g:q1/take", tb, `{"k":1}`) // nothing left ready? drain check below
	_ = body
	// Take the ready items again to get fresh receipts.
	_, body, _ = e.do(t, "POST", "/v1/wq/g:q1/nack", tb, js(map[string]any{"receipt": "x"}))
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1", ta, `{"items":["fenced"]}`)
	want(t, st, body, 200, "ok n=1")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/take", tb, `{"k":1}`)
	want(t, st, body, 200, "ok k=1")
	r3 := receiptRx.FindStringSubmatch(body)[1]
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/ack", tb, js(map[string]any{"receipt": r3, "lock": "g:q1.lead", "fence": 7}))
	want(t, st, body, 409, "err fenced 1")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/ack", tb, js(map[string]any{"receipt": r3, "lock": "g:q1.lead", "fence": 1}))
	want(t, st, body, 200, "ok done=")
	// Long-poll take is woken by a push.
	done := make(chan string, 1)
	go func() {
		_, body, _ := e.do(t, "POST", "/v1/wq/g:q1/take", tb, `{"k":1,"wait":10}`)
		done <- body
	}()
	time.Sleep(250 * time.Millisecond)
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1", ta, `{"items":["late"]}`)
	want(t, st, body, 200, "ok n=1")
	select {
	case body := <-done:
		if !strings.Contains(body, "\n  late\n") {
			t.Fatalf("long-poll take: %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("take not woken by push")
	}
	st, body, _ = e.do(t, "POST", "/v1/wq/g:none/take", tb, `{}`)
	want(t, st, body, 404, "no such queue")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q1/take", tb, `{"vis_s":5}`)
	want(t, st, body, 400, "vis_s must be 30..3600")
	// Scoped tokens need wq:<glob>.
	_, tsc := mkSubScoped(t, mustRoot(t, tb), []string{"wq:g:other*"})
	st, body, _ = e.do(t, "GET", "/v1/wq/g:q1", tsc, "")
	want(t, st, body, 403, "err scope wq:g:q1")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:other.jobs", tsc, `{"items":["x"]}`)
	want(t, st, body, 200, "ok n=1")
}

func mustRoot(t *testing.T, tok string) string {
	t.Helper()
	var root string
	if err := testPool.QueryRow(context.Background(), `SELECT root FROM identities WHERE token_hash = $1`, core.HashToken(tok)).Scan(&root); err != nil {
		t.Fatal(err)
	}
	return root
}

func mkSubScoped(t *testing.T, root string, scopes []string) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, scopes, token_class)
		VALUES ($1, 's', $2, $2, $3, 0, $4, 'scoped')`, id, root, h, scopes); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func TestQueueRequeueDLQ(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, ta := mkRoot(t, randIP(), 1)
	st, body, _ := e.do(t, "POST", "/v1/wq/g:q2", ta, `{"items":["poison"],"on_dlq":true}`)
	want(t, st, body, 200, "ok n=1")
	id := field(body, "ids")
	for i := 1; i <= wqDead; i++ {
		st, body, _ = e.do(t, "POST", "/v1/wq/g:q2/take", ta, `{"k":1}`)
		want(t, st, body, 200, "ok k=1\n"+id+" deliveries="+strconv.Itoa(i)+" receipt=")
		if _, err := testPool.Exec(ctx, `UPDATE q_items SET vis_until = now() - interval '1 second' WHERE queue = 'g:q2'`); err != nil {
			t.Fatal(err)
		}
		if err := e.s.janQueues(ctx); err != nil {
			t.Fatal(err)
		}
		var state string
		testPool.QueryRow(ctx, `SELECT state FROM q_items WHERE queue = 'g:q2'`).Scan(&state)
		wantState := "ready"
		if i == wqDead {
			wantState = "dead"
		}
		if state != wantState {
			t.Fatalf("after expiry %d: state %s, want %s", i, state, wantState)
		}
	}
	st, body, _ = e.do(t, "GET", "/v1/wq/g:q2?dlq=1", "", "")
	want(t, st, body, 200, "wq g:q2 ready=0 leased=0 done=0 dead=1 on_dlq=1\n"+id+" deliveries=5\n  poison\n")
	st, body, _ = e.do(t, "GET", "/v1/ps/g:q2.dlq", "", "")
	want(t, st, body, 200, " asystem ")
	if !strings.Contains(body, " dlq g:q2 "+id+" deliveries=5\n") {
		t.Fatalf("dlq event: %q", body)
	}
	st, body, _ = e.do(t, "POST", "/v1/wq/g:q2/take", ta, `{"k":1}`)
	want(t, st, body, 200, "ok k=0")
	// Retention: old done/dead rows disappear; the cache columns follow.
	if _, err := testPool.Exec(ctx, `UPDATE q_items SET done_at = now() - interval '8 days' WHERE queue = 'g:q2'`); err != nil {
		t.Fatal(err)
	}
	if err := e.s.janQueues(ctx); err != nil {
		t.Fatal(err)
	}
	st, body, _ = e.do(t, "GET", "/v1/wq/g:q2", "", "")
	want(t, st, body, 200, "wq g:q2 ready=0 leased=0 done=0 dead=0")
	var items, dlq int
	testPool.QueryRow(ctx, `SELECT items, dlq FROM queues WHERE name = 'g:q2'`).Scan(&items, &dlq)
	if items != 0 || dlq != 0 {
		t.Fatalf("cache columns: items=%d dlq=%d", items, dlq)
	}
}

// A long-polling take observes the end of a nack delay without any wake or janitor tick.
func TestQueueNackDelayObserved(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, randIP(), 1)
	st, body, _ := e.do(t, "POST", "/v1/wq/g:qd", ta, `{"items":["slow"]}`)
	want(t, st, body, 200, "ok n=1")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:qd/take", ta, `{"k":1}`)
	want(t, st, body, 200, "ok k=1")
	r := receiptRx.FindStringSubmatch(body)[1]
	st, body, _ = e.do(t, "POST", "/v1/wq/g:qd/nack", ta, js(map[string]any{"receipt": r, "delay_s": 1}))
	want(t, st, body, 200, "ok ready=")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:qd/take", ta, `{"k":1}`)
	want(t, st, body, 200, "ok k=0") // not visible yet
	start := time.Now()
	st, body, _ = e.do(t, "POST", "/v1/wq/g:qd/take", ta, `{"k":1,"wait":10}`)
	want(t, st, body, 200, "ok k=1")
	if d := time.Since(start); d > 4*time.Second || !strings.Contains(body, " deliveries=2 ") {
		t.Fatalf("delayed item not observed promptly: %s %q", d, body)
	}
}

func TestQueueL0Caps(t *testing.T) {
	e := newEnv(t)
	_, tl := mkRoot(t, randIP(), 0)
	st, body, _ := e.do(t, "POST", "/v1/wq/~c1", tl, `{"items":["x"]}`)
	want(t, st, body, 200, "ok n=1")
	st, body, _ = e.do(t, "POST", "/v1/wq/~c2", tl, `{"items":["x"]}`)
	want(t, st, body, 200, "ok n=1")
	st, body, _ = e.do(t, "POST", "/v1/wq/~c3", tl, `{"items":["x"]}`)
	want(t, st, body, 429, "err quota queues live 2")
	items := make([]string, 99)
	for i := range items {
		items[i] = "i" + strconv.Itoa(i)
	}
	st, body, _ = e.do(t, "POST", "/v1/wq/~c1", tl, js(map[string]any{"items": items}))
	want(t, st, body, 200, "ok n=99")
	st, body, _ = e.do(t, "POST", "/v1/wq/~c1", tl, `{"items":["one too many"]}`)
	want(t, st, body, 429, "err quota queue_items 100")
	st, body, _ = e.do(t, "POST", "/v1/wq/~c1", tl, js(map[string]any{"items": make([]string, 101)}))
	want(t, st, body, 400, "items: 1..100")
	// A queue of another root under its own namespace is not reachable.
	_, tb := mkRoot(t, randIP(), 1)
	st, body, _ = e.do(t, "GET", "/v1/wq/a:"+mustRoot(t, tl)+".c1", tb, "")
	want(t, st, body, 403, "err auth forbidden")
	// Idempotent push by key.
	st, body, _ = e.do(t, "POST", "/v1/wq/g:ik", tb, `{"items":["a"],"key":"push-1"}`)
	want(t, st, body, 200, "ok n=1")
	first := body
	st, body, _ = e.do(t, "POST", "/v1/wq/g:ik", tb, `{"items":["a"],"key":"push-1"}`)
	want(t, st, body, 200, head(first)+"\nidem=replay")
	st, body, _ = e.do(t, "POST", "/v1/wq/g:ik", tb, `{"items":["b"],"key":"push-1"}`)
	want(t, st, body, 409, "err idem")
	st, body, _ = e.do(t, "GET", "/v1/wq/g:ik", "", "")
	want(t, st, body, 200, "ready=1 ")
}

// --- rate limiter --------------------------------------------------------------------------------

func TestRateLimiterAtomic(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, randIP(), 1)
	for i := 0; i < 5; i++ {
		st, body, _ := e.do(t, "POST", "/v1/rl/~api", ta, `{"rate":10,"burst":5}`)
		want(t, st, body, 200, "ok left=")
	}
	st, body, h := e.do(t, "POST", "/v1/rl/~api", ta, `{"rate":10,"burst":5}`)
	want(t, st, body, 429, "err rate wait_ms=")
	if h.Get("Retry-After") == "" {
		t.Fatal("missing Retry-After")
	}
	ms, _ := strconv.Atoi(strings.TrimPrefix(field(body, "wait_ms"), ""))
	if ms < 1 || ms > 200 {
		t.Fatalf("wait_ms=%d, want ~100", ms)
	}
	time.Sleep(150 * time.Millisecond) // refill ~1.5 tokens
	st, body, _ = e.do(t, "POST", "/v1/rl/~api", ta, `{"rate":10,"burst":5}`)
	want(t, st, body, 200, "ok left=")
	st, body, _ = e.do(t, "POST", "/v1/rl/g:shared", ta, `{"rate":10}`)
	want(t, st, body, 400, "no g:")
	st, body, _ = e.do(t, "POST", "/v1/rl/~api", ta, `{"rate":5000}`)
	want(t, st, body, 400, "rate must be")
	st, body, _ = e.do(t, "POST", "/v1/rl/~api", ta, `{"rate":10,"burst":5,"cost":9}`)
	want(t, st, body, 400, "cost must be")
	// Atomic across concurrent callers: a fresh bucket of 5 admits exactly 5 of 12.
	_, tb := mkRoot(t, randIP(), 1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	oks, limited := 0, 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st, _, _ := e.do(t, "POST", "/v1/rl/~api2", tb, `{"rate":0.001,"burst":5}`)
			mu.Lock()
			defer mu.Unlock()
			switch st {
			case 200:
				oks++
			case 429:
				limited++
			}
		}()
	}
	wg.Wait()
	if oks != 5 || limited != 7 {
		t.Fatalf("concurrent limiter: ok=%d limited=%d", oks, limited)
	}
	// Keys are stored hashed, never the agent's name.
	var k string
	testPool.QueryRow(context.Background(), `SELECT key FROM rl_buckets LIMIT 1`).Scan(&k)
	if strings.Contains(k, "api") || len(k) != 64 {
		t.Fatalf("rl key stored in clear: %q", k)
	}
}

// --- ops -----------------------------------------------------------------------------------------

func TestOpsMirrorHTTP(t *testing.T) {
	e := newEnv(t)
	ops := Ops(e.d)
	for name := range OpMeta {
		if ops[name] == nil {
			t.Errorf("op %s has meta but no implementation", name)
		}
	}
	for name := range ops {
		if _, ok := OpMeta[name]; !ok {
			t.Errorf("op %s has no meta", name)
		}
	}
	a, _ := mkRoot(t, randIP(), 1)
	id, err := e.d.LookupToken(context.Background(), tokenOf(t, a))
	if err != nil {
		t.Fatal(err)
	}
	ctx := core.WithClient(context.Background(), "10.9.9.9", "10.9.9.9", "10.9.9.0/24")
	out, err := ops["lk"](ctx, id, json.RawMessage(`{"name":"~op","ttl_s":60}`))
	if err != nil || !strings.HasPrefix(out, "ok fence=1 until=") || strings.Contains(out, "next:") {
		t.Fatalf("lk op: %q %v", out, err)
	}
	if _, err := ops["lk"](ctx, nil, json.RawMessage(`{"name":"g:x"}`)); err != core.ErrAuth {
		t.Fatalf("anonymous mutating op: %v", err)
	}
	out, err = ops["lkg"](ctx, nil, json.RawMessage(`{"name":"g:nothing"}`))
	if err != nil || out != "free fence=0" {
		t.Fatalf("lkg anonymous: %q %v", out, err)
	}
	out, err = ops["pub"](ctx, id, json.RawMessage(`{"topic":"g:ops","text":"hi","key":"k"}`))
	if err != nil || out != "ok seq=1" {
		t.Fatalf("pub: %q %v", out, err)
	}
	out, err = ops["pull"](ctx, nil, json.RawMessage(`{"topic":"g:ops","after":0}`))
	if err != nil || !strings.HasPrefix(out, "ps g:ops last=1 msgs=1\n1 "+a+" ") || !strings.HasSuffix(out, "next=1") {
		t.Fatalf("pull: %q %v", out, err)
	}
	out, err = ops["cur"](ctx, id, json.RawMessage(`{"topic":"g:ops","seq":1}`))
	if err != nil || out != "ok seq=1" {
		t.Fatalf("cur set: %q %v", out, err)
	}
	out, err = ops["cur"](ctx, id, json.RawMessage(`{"topic":"g:ops"}`))
	if err != nil || out != "seq=1" {
		t.Fatalf("cur get: %q %v", out, err)
	}
	out, err = ops["wq"](ctx, id, json.RawMessage(`{"name":"~jobs","items":["one"]}`))
	if err != nil || !strings.HasPrefix(out, "ok n=1 ids=") {
		t.Fatalf("wq: %q %v", out, err)
	}
	out, err = ops["wqt"](ctx, id, json.RawMessage(`{"name":"~jobs"}`))
	if err != nil || !strings.HasPrefix(out, "ok k=1\n") {
		t.Fatalf("wqt: %q %v", out, err)
	}
	r := receiptRx.FindStringSubmatch(out)[1]
	out, err = ops["wqa"](ctx, id, json.RawMessage(`{"name":"~jobs","receipt":"`+r+`"}`))
	if err != nil || !strings.HasPrefix(out, "ok done=") {
		t.Fatalf("wqa: %q %v", out, err)
	}
	out, err = ops["rl"](ctx, id, json.RawMessage(`{"key":"~up","rate":1}`))
	if err != nil || !strings.HasPrefix(out, "ok left=") {
		t.Fatalf("rl: %q %v", out, err)
	}
	if _, err = ops["rl"](ctx, id, json.RawMessage(`{"key":"~up","rate":1}`)); err == nil || !strings.HasPrefix(err.Error(), "err rate wait_ms=") {
		t.Fatalf("rl limited: %v", err)
	}
	out, err = ops["br"](ctx, id, json.RawMessage(`{"name":"g:opsbr","n":2}`))
	if err != nil || !strings.HasPrefix(out, "wait 1/2 until=") {
		t.Fatalf("br: %q %v", out, err)
	}
	out, err = ops["rv"](ctx, id, json.RawMessage(`{"key":"ops"}`))
	if err != nil || !strings.HasPrefix(out, "ok rv=x") {
		t.Fatalf("rv: %q %v", out, err)
	}
	if len(Help) > 1200 {
		t.Fatalf("Help too long: %d bytes", len(Help))
	}
	var frag map[string]any
	if err := json.Unmarshal(openAPI, &frag); err != nil {
		t.Fatalf("openAPI fragment: %v", err)
	}
}

func tokenOf(t *testing.T, id string) string {
	t.Helper()
	tok, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET token_hash = $2 WHERE id = $1`, id, h); err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestPurge(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, ta := mkRoot(t, randIP(), 1)
	_, tb := mkRoot(t, randIP(), 1)
	st, body, _ := e.do(t, "POST", "/v1/lk/g:pg", ta, `{"ttl_s":60}`)
	want(t, st, body, 200, "ok fence=1")
	st, body, _ = e.do(t, "POST", "/v1/ps/g:pgt", ta, `{"text":"secret-ish"}`)
	want(t, st, body, 200, "ok seq=1")
	st, body, _ = e.do(t, "POST", "/v1/wq/~pq", ta, `{"items":["x"]}`)
	want(t, st, body, 200, "ok n=1")
	done := make(chan string, 1)
	go func() {
		_, body, _ := e.do(t, "POST", "/v1/lk/g:pg", tb, `{"wait":10}`)
		done <- body
	}()
	time.Sleep(200 * time.Millisecond)
	if err := e.s.purge(ctx, a); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-done:
		if !strings.HasPrefix(body, "ok fence=2 ") {
			t.Fatalf("waiter after purge: %q", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("purge did not release the lock")
	}
	st, body, _ = e.do(t, "GET", "/v1/ps/g:pgt?after=0", "", "")
	want(t, st, body, 200, "[hidden]")
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM queues WHERE owner_root = $1`, a).Scan(&n)
	if n != 0 {
		t.Fatal("own queues survived the purge")
	}
}
