package sem

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/swarm"
	"ekaii.fr/commons/internal/testdb"
)

var (
	testPool *pgxpool.Pool
	levels   sync.Map // root -> level
	mails    sync.Map // root -> []string
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
	} else if pool, done := testdb.Open("sem", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping sem DB tests")
		os.Exit(0)
	}
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int {
		v, _ := levels.Load(root)
		n, _ := v.(int)
		return n
	}
	swarm.NotifyExpired = func(ctx context.Context, q core.Q, root, subject, text string) error {
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
	swarm.Register(mux, d)
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
	return res.StatusCode, string(b)
}

// mkRoot inserts a root identity (last_seen now) with a stubbed level; returns (id, token).
func mkRoot(t *testing.T, level int) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, reg_ip, created, last_seen)
		VALUES ($1, 'r', NULL, $1, $2, 100, $3, now() - interval '5 days', now())`, id, h, randIP()); err != nil {
		t.Fatal(err)
	}
	levels.Store(id, level)
	return id, tok
}

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

// --- semaphores ---------------------------------------------------------------------------------

func TestAcquireSlotsAndPerRootCeiling(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, 2)
	_, tb := mkRoot(t, 2)
	// n=4, per_root default ceil(4/2)=2.
	st, b := e.do(t, "POST", "/v1/sm/g:pool", ta, `{"n":4,"ttl_s":60}`)
	want(t, st, b, 200, "ok slot=1 fence=1 ")
	want(t, st, b, 200, "free=3/4")
	st, b = e.do(t, "POST", "/v1/sm/g:pool", ta, `{"n":4}`)
	want(t, st, b, 200, "ok slot=2 fence=2 ")
	want(t, st, b, 200, "free=2/4")
	// Third from the same root exceeds the per-root ceiling (2); reported as full for this caller.
	st, b = e.do(t, "POST", "/v1/sm/g:pool", ta, `{"n":4}`)
	want(t, st, b, 409, "err full")
	// Creator fixes n: a different n is rejected.
	st, b = e.do(t, "POST", "/v1/sm/g:pool", tb, `{"n":8}`)
	want(t, st, b, 409, "err bad n=4")
	// B takes the remaining two slots.
	st, b = e.do(t, "POST", "/v1/sm/g:pool", tb, `{"n":4}`)
	want(t, st, b, 200, "ok slot=3")
	st, b = e.do(t, "POST", "/v1/sm/g:pool", tb, `{"n":4}`)
	want(t, st, b, 200, "ok slot=4")
	want(t, st, b, 200, "free=0/4")
	// Now the semaphore is globally full.
	st, b = e.do(t, "POST", "/v1/sm/g:pool", tb, `{"n":4}`)
	want(t, st, b, 409, "err full free=0/4 until=")
	_ = a
	// GET state (anonymous for g:).
	st, b = e.do(t, "GET", "/v1/sm/g:pool", "", "")
	want(t, st, b, 200, "free=0/4")
	if strings.Count(b, "slot=") < 4 {
		t.Fatalf("state should list 4 held slots:\n%s", b)
	}
}

func TestRenewReleaseStaleFence(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, 2)
	st, b := e.do(t, "POST", "/v1/sm/g:rr", ta, `{"n":2,"ttl_s":30}`)
	want(t, st, b, 200, "ok slot=1 fence=1")
	slot := field(b, "slot")
	fence := field(b, "fence")
	// renew with the right fence.
	st, b = e.do(t, "POST", "/v1/sm/g:rr/renew", ta, fmt.Sprintf(`{"slot":%s,"fence":%s,"ttl_s":60}`, slot, fence))
	want(t, st, b, 200, "ok slot=1 fence=1")
	// renew with a stale fence.
	st, b = e.do(t, "POST", "/v1/sm/g:rr/renew", ta, fmt.Sprintf(`{"slot":%s,"fence":99}`, slot))
	want(t, st, b, 409, "err fenced")
	// release with a stale fence -> ok stale.
	st, b = e.do(t, "DELETE", "/v1/sm/g:rr/"+slot, ta, `{"fence":99}`)
	want(t, st, b, 200, "ok stale")
	// release with the right fence.
	st, b = e.do(t, "DELETE", "/v1/sm/g:rr/"+slot, ta, fmt.Sprintf(`{"fence":%s}`, fence))
	if st != 200 || head(b) != "ok" {
		t.Fatalf("release: %d %q", st, b)
	}
	// the slot is free again.
	st, b = e.do(t, "POST", "/v1/sm/g:rr", ta, `{"n":2}`)
	want(t, st, b, 200, "ok slot=1")
}

func TestWaitFIFOWake(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, 2)
	_, tb := mkRoot(t, 2)
	st, b := e.do(t, "POST", "/v1/sm/g:one", ta, `{"n":1,"ttl_s":60}`)
	want(t, st, b, 200, "ok slot=1 fence=1")
	fence := field(b, "fence")
	done := make(chan string, 1)
	go func() {
		_, wb := e.do(t, "POST", "/v1/sm/g:one", tb, `{"n":1,"wait":5}`)
		done <- wb
	}()
	time.Sleep(300 * time.Millisecond)
	// release A's permit; the waiter should acquire it.
	st, b = e.do(t, "DELETE", "/v1/sm/g:one/1", ta, fmt.Sprintf(`{"fence":%s}`, fence))
	if st != 200 {
		t.Fatalf("release: %d %q", st, b)
	}
	select {
	case wb := <-done:
		want(t, 200, wb, 200, "ok slot=1")
	case <-time.After(5 * time.Second):
		t.Fatal("waiter never woke")
	}
}

func TestCheckFencePermit(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, 2)
	st, b := e.do(t, "POST", "/v1/sm/g:cf", ta, `{"n":2,"ttl_s":60}`)
	want(t, st, b, 200, "ok slot=1 fence=1")
	ctx := context.Background()
	if err := CheckFence(ctx, testPool, "g:cf/1", 1); err != nil {
		t.Fatalf("live fence: %v", err)
	}
	if err := CheckFence(ctx, testPool, "g:cf/1", 2); err == nil || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("stale fence: %v", err)
	}
	if err := CheckFence(ctx, testPool, "g:cf/2", 1); err == nil || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("never-held slot: %v", err)
	}
	// release -> no longer live.
	st, b = e.do(t, "DELETE", "/v1/sm/g:cf/1", ta, `{"fence":1}`)
	if st != 200 {
		t.Fatalf("release: %d %q", st, b)
	}
	if err := CheckFence(ctx, testPool, "g:cf/1", 1); err == nil || !strings.Contains(err.Error(), "fenced") {
		t.Fatalf("released slot still fences: %v", err)
	}
}

func TestExpiryPublishesAndCountsAsLeaseExpiry(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, 2)
	ctx := context.Background()
	var rep0 int
	testPool.QueryRow(ctx, `SELECT rep FROM identities WHERE id = $1`, a).Scan(&rep0)
	st, b := e.do(t, "POST", "/v1/sm/g:exp", ta, `{"n":1,"ttl_s":60}`)
	want(t, st, b, 200, "ok slot=1")
	// force the lease to lapse.
	if _, err := testPool.Exec(ctx, `UPDATE sem_permits SET until = now() - interval '1 second' WHERE name = 'g:exp'`); err != nil {
		t.Fatal(err)
	}
	if err := e.s.janPermits(ctx); err != nil {
		t.Fatalf("janitor: %v", err)
	}
	// a sys mail went to the holder root.
	v, _ := mails.Load(a)
	ms, _ := v.([]string)
	found := false
	for _, m := range ms {
		if strings.Contains(m, "permit-expired g:exp") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no permit-expired mail for %s: %v", a, ms)
	}
	// rep dropped by one (lease expiry, 4.2).
	var rep1 int
	testPool.QueryRow(ctx, `SELECT rep FROM identities WHERE id = $1`, a).Scan(&rep1)
	if rep1 != rep0-1 {
		t.Fatalf("rep: got %d want %d", rep1, rep0-1)
	}
	// idempotent: a second janitor pass does not re-notify or re-penalise.
	if err := e.s.janPermits(ctx); err != nil {
		t.Fatal(err)
	}
	var rep2 int
	testPool.QueryRow(ctx, `SELECT rep FROM identities WHERE id = $1`, a).Scan(&rep2)
	if rep2 != rep1 {
		t.Fatalf("second pass changed rep: %d -> %d", rep1, rep2)
	}
}

func TestExpiryPublishesToOnExpire(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, 2)
	ctx := context.Background()
	st, b := e.do(t, "POST", "/v1/sm/g:expt", ta, `{"n":1,"ttl_s":60,"on_expire":{"ps":"g:alarms"}}`)
	want(t, st, b, 200, "ok slot=1")
	testPool.Exec(ctx, `UPDATE sem_permits SET until = now() - interval '1 second' WHERE name = 'g:expt'`)
	if err := e.s.janPermits(ctx); err != nil {
		t.Fatal(err)
	}
	st, b = e.do(t, "GET", "/v1/ps/g:alarms?after=0", ta, "")
	want(t, st, b, 200, "permit-expired g:expt")
}

// --- multi-lock ---------------------------------------------------------------------------------

func TestMultiLockAllOrNothing(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, 2)
	_, tb := mkRoot(t, 2)
	// A holds g:aon.api alone.
	st, b := e.do(t, "POST", "/v1/lk/g:aon.api", ta, `{"ttl_s":60}`)
	want(t, st, b, 200, "ok fence=1")
	// B asks for both g:aon.repo and g:aon.api: must fail atomically and leave g:aon.repo free.
	st, b = e.do(t, "POST", "/v1/lkm", tb, `{"names":["g:aon.repo","g:aon.api"],"ttl_s":60}`)
	want(t, st, b, 409, "err taken g:aon.api "+a)
	st, b = e.do(t, "GET", "/v1/lk/g:aon.repo", "", "")
	want(t, st, b, 200, "free")
}

func TestMultiLockNoDeadlockOppositeOrder(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, 2)
	_, tb := mkRoot(t, 2)
	var wg sync.WaitGroup
	res := make([]struct {
		st int
		b  string
	}, 2)
	bodies := []string{
		`{"names":["g:dl.repo","g:dl.api"],"ttl_s":60}`,
		`{"names":["g:dl.api","g:dl.repo"],"ttl_s":60}`,
	}
	toks := []string{ta, tb}
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			defer wg.Done()
			res[i].st, res[i].b = e.do(t, "POST", "/v1/lkm", toks[i], bodies[i])
		}(i)
	}
	wg.Wait()
	ok, taken := 0, 0
	for _, r := range res {
		switch r.st {
		case 200:
			ok++
			if !strings.Contains(r.b, "g:dl.repo fence=") || !strings.Contains(r.b, "g:dl.api fence=") {
				t.Fatalf("winner should hold both:\n%s", r.b)
			}
		case 409:
			taken++
			want(t, r.st, r.b, 409, "err taken")
		default:
			t.Fatalf("unexpected %d %q", r.st, r.b)
		}
	}
	if ok != 1 || taken != 1 {
		t.Fatalf("want exactly one winner and one taken, got ok=%d taken=%d", ok, taken)
	}
}

func TestMultiLockWaitRetry(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, 2)
	_, tb := mkRoot(t, 2)
	st, b := e.do(t, "POST", "/v1/lk/g:wr.api", ta, `{"ttl_s":60}`)
	want(t, st, b, 200, "ok fence=1")
	fence := field(b, "fence")
	done := make(chan [2]string, 1)
	go func() {
		s2, b2 := e.do(t, "POST", "/v1/lkm", tb, `{"names":["g:wr.repo","g:wr.api"],"ttl_s":60,"wait":6}`)
		done <- [2]string{strconv.Itoa(s2), b2}
	}()
	time.Sleep(400 * time.Millisecond)
	// A releases g:wr.api; the waiter should then grab both.
	st, b = e.do(t, "DELETE", "/v1/lk/g:wr.api", ta, fmt.Sprintf(`{"fence":%s}`, fence))
	if st != 200 {
		t.Fatalf("release: %d %q", st, b)
	}
	select {
	case r := <-done:
		want(t, 200, r[1], 200, "g:wr.api fence=")
		if !strings.Contains(r[1], "g:wr.repo fence=") {
			t.Fatalf("waiter should hold both:\n%s", r[1])
		}
	case <-time.After(8 * time.Second):
		t.Fatal("multi-lock waiter never woke")
	}
	_ = a
}

// --- handover -----------------------------------------------------------------------------------

func TestHandoverLockFenceIncrementsAndMails(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, 2)
	b, _ := mkRoot(t, 2)
	st, body := e.do(t, "POST", "/v1/lk/g:hand", ta, `{"ttl_s":60}`)
	want(t, st, body, 200, "ok fence=1")
	// hand over to B (a live, reliable, distinct root -> allowed for g:).
	st, body = e.do(t, "POST", "/v1/lk/g:hand/handover", ta, fmt.Sprintf(`{"fence":1,"to":"%s","ttl_s":60,"note":"take it"}`, b))
	want(t, st, body, 200, "ok handover lk g:hand fence=2 to="+b)
	// the lock now belongs to B at fence 2.
	st, body = e.do(t, "GET", "/v1/lk/g:hand", "", "")
	want(t, st, body, 200, "held "+b+" fence=2")
	// B received a sys mail with the note.
	v, _ := mails.Load(b)
	ms, _ := v.([]string)
	found := false
	for _, m := range ms {
		if strings.Contains(m, "handover lk g:hand fence=2") && strings.Contains(m, "take it") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no handover mail to %s: %v", b, ms)
	}
	// a stale fence from the old holder is refused.
	st, body = e.do(t, "POST", "/v1/lk/g:hand/handover", ta, fmt.Sprintf(`{"fence":1,"to":"%s"}`, b))
	want(t, st, body, 409, "err fenced")
	_ = a
}

func TestHandoverEligibility(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, 2)
	bsub, _ := mkSub(t, a)
	// same-root handover (to a subkey of A) is always eligible.
	st, b := e.do(t, "POST", "/v1/lk/g:elg", ta, `{"ttl_s":60}`)
	want(t, st, b, 200, "ok fence=1")
	st, b = e.do(t, "POST", "/v1/lk/g:elg/handover", ta, fmt.Sprintf(`{"fence":1,"to":"%s"}`, bsub))
	want(t, st, b, 200, "ok handover lk g:elg fence=2 to="+bsub)
	// a g: handover to a stale (not-live) root is refused.
	stale, _ := mkRoot(t, 2)
	testPool.Exec(context.Background(), `UPDATE identities SET last_seen = now() - interval '20 minutes' WHERE id = $1`, stale)
	st, b = e.do(t, "POST", "/v1/lk/g:elg2", ta, `{"ttl_s":60}`)
	want(t, st, b, 200, "ok fence=1")
	st, b = e.do(t, "POST", "/v1/lk/g:elg2/handover", ta, fmt.Sprintf(`{"fence":1,"to":"%s"}`, stale))
	want(t, st, b, 409, "to not live")
	// low reliability is also refused when RelFn is wired.
	RelFn = func(ctx context.Context, q core.Q, root string) float64 {
		if root == stale {
			return 0.2
		}
		return 1.0
	}
	t.Cleanup(func() { RelFn = nil })
	testPool.Exec(context.Background(), `UPDATE identities SET last_seen = now() WHERE id = $1`, stale)
	st, b = e.do(t, "POST", "/v1/lk/g:elg2/handover", ta, fmt.Sprintf(`{"fence":1,"to":"%s"}`, stale))
	want(t, st, b, 409, "to not live")
	// an s: handover to a non-member is refused.
	swarm.MemberFn = func(ctx context.Context, q core.Q, slug, root string) (bool, error) {
		return slug == "team" && root == a, nil
	}
	t.Cleanup(func() { swarm.MemberFn = nil })
	st, b = e.do(t, "POST", "/v1/lk/s:team.x", ta, `{"ttl_s":60}`)
	want(t, st, b, 200, "ok fence=1")
	st, b = e.do(t, "POST", "/v1/lk/s:team.x/handover", ta, fmt.Sprintf(`{"fence":1,"to":"%s"}`, stale))
	want(t, st, b, 409, "to not live")
}

func TestHandoverPermit(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, 2)
	bsub, _ := mkSub(t, a)
	st, b := e.do(t, "POST", "/v1/sm/g:ph", ta, `{"n":2,"ttl_s":60}`)
	want(t, st, b, 200, "ok slot=1 fence=1")
	st, b = e.do(t, "POST", "/v1/sm/g:ph/1/handover", ta, fmt.Sprintf(`{"fence":1,"to":"%s","note":"yours"}`, bsub))
	want(t, st, b, 200, "ok handover sm g:ph slot=1 fence=2 to="+bsub)
	// the new fence is live; the old one is stale.
	ctx := context.Background()
	if err := CheckFence(ctx, testPool, "g:ph/1", 2); err != nil {
		t.Fatalf("new fence: %v", err)
	}
	if err := CheckFence(ctx, testPool, "g:ph/1", 1); err == nil {
		t.Fatalf("old permit fence still live")
	}
	_ = a
}

func TestClaimHandover(t *testing.T) {
	e := newEnv(t)
	a, ta := mkRoot(t, 2)
	bsub, _ := mkSub(t, a)
	ctx := context.Background()
	// create an open task and assign the claim to A.
	var n int64
	if err := testPool.QueryRow(ctx, `INSERT INTO tasks (n, id, root) VALUES (90001, $1, $1) RETURNING n`, a).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if _, err := forge.ClaimAssign(ctx, testPool, n, a, a, time.Hour); err != nil {
		t.Fatalf("assign: %v", err)
	}
	// A hands the claim to a subkey (same tree).
	st, b := e.do(t, "POST", fmt.Sprintf("/v1/t/%d/handover", n), ta, fmt.Sprintf(`{"to":"%s","note":"relay"}`, bsub))
	want(t, st, b, 200, fmt.Sprintf("ok handover t #%d fence=2 to=%s", n, bsub))
	var holder string
	var fence int64
	testPool.QueryRow(ctx, `SELECT id, fence FROM task_claims WHERE n = $1`, n).Scan(&holder, &fence)
	if holder != bsub || fence != 2 {
		t.Fatalf("after handover: holder=%s fence=%d", holder, fence)
	}
	// a non-holder cannot hand it over.
	_, tc := mkRoot(t, 2)
	st, b = e.do(t, "POST", fmt.Sprintf("/v1/t/%d/handover", n), tc, fmt.Sprintf(`{"to":"%s"}`, a))
	want(t, st, b, 409, "not holder")
}
