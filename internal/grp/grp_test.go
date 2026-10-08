package grp

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
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
)

var testPool *pgxpool.Pool

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
	} else if pool, done := testdb.Open("grp", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping grp DB tests")
		os.Exit(0)
	}
	core.LevelFn = trust.LevelOf
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

// mkRoot inserts a root registered from ip five days ago at the given standing level.
func mkRoot(t *testing.T, ip string, level int) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	rep, vnc := 0, 0
	switch level {
	case 1:
		rep = 1
	case 2:
		rep, vnc = 5, 1
	}
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, reg_ip, created, rep, verified_noncompute)
		VALUES ($1, 'r', NULL, $1, $2, 100, $3, now() - interval '5 days', $4, $5)`, id, h, ip, rep, vnc); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func headLine(body string) string { l, _, _ := strings.Cut(body, "\n"); return l }

func field(body, key string) string {
	for _, f := range strings.Fields(headLine(body)) {
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

// expire forces a member's heartbeat deadline into the past so the next touch or the janitor reaps it.
func expire(t *testing.T, name, id string) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE group_members SET until = now() - interval '1 second' WHERE name = $1 AND id = $2`, name, id); err != nil {
		t.Fatal(err)
	}
}

// --- acceptance ---------------------------------------------------------------------------------

func TestJoinHeartbeatEpoch(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, randIP(), 1)
	// First join creates the group at epoch 2 (created at 1, bumped once on the join).
	st, body := e.do(t, "POST", "/v1/grp/g:j", ta, `{"ttl_s":30,"shards":64}`)
	want(t, st, body, 200, "ok epoch=")
	e1 := field(body, "epoch")
	if field(body, "rank") != "0" || field(body, "n") != "1" || field(body, "every") != "1" || field(body, "from") != "0" {
		t.Fatalf("first join head: %q", body)
	}
	// A heartbeat does not change membership: same epoch, no bump.
	st, body = e.do(t, "POST", "/v1/grp/g:j", ta, `{}`)
	want(t, st, body, 200, "ok epoch="+e1)
	if field(body, "rank") != "0" || field(body, "n") != "1" {
		t.Fatalf("heartbeat head: %q", body)
	}
	// A second distinct member bumps the epoch.
	_, tb := mkRoot(t, randIP(), 1)
	st, body = e.do(t, "POST", "/v1/grp/g:j", tb, `{}`)
	want(t, st, body, 200, "ok epoch=")
	if field(body, "epoch") == e1 {
		t.Fatalf("epoch did not bump on the second join: %q", body)
	}
	if field(body, "rank") != "1" || field(body, "n") != "2" {
		t.Fatalf("second member head: %q", body)
	}
}

func TestRanksDenseByJoinOrder(t *testing.T) {
	e := newEnv(t)
	ids := make([]string, 3)
	toks := make([]string, 3)
	for i := range ids {
		ids[i], toks[i] = mkRoot(t, randIP(), 1)
		st, body := e.do(t, "POST", "/v1/grp/g:crawl", toks[i], `{"ttl_s":60}`)
		want(t, st, body, 200, "ok epoch=")
		if field(body, "rank") != fmt.Sprint(i) {
			t.Fatalf("member %d expected rank %d: %q", i, i, body)
		}
	}
	// All three ranked 0,1,2 with every=3.
	st, body := e.do(t, "GET", "/v1/grp/g:crawl", "", "")
	want(t, st, body, 200, "n=3")
	for i, id := range ids {
		if !strings.Contains(body, fmt.Sprintf("- %s rank=%d", id, i)) {
			t.Fatalf("member line %d missing: %q", i, body)
		}
	}
	// The middle member stops heartbeating: a survivor's touch reaps it and ranks stay dense (0,1).
	expire(t, "g:crawl", ids[1])
	st, body = e.do(t, "POST", "/v1/grp/g:crawl", toks[0], `{}`)
	want(t, st, body, 200, "n=2")
	if field(body, "rank") != "0" || field(body, "every") != "2" {
		t.Fatalf("survivor 0 after reap: %q", body)
	}
	st, body = e.do(t, "POST", "/v1/grp/g:crawl", toks[2], `{}`)
	if field(body, "rank") != "1" || field(body, "n") != "2" {
		t.Fatalf("survivor 2 re-ranked to 1: %q", body)
	}
}

func TestShardOwnershipEveryFrom(t *testing.T) {
	e := newEnv(t)
	toks := make([]string, 3)
	for i := range toks {
		_, toks[i] = mkRoot(t, randIP(), 1)
		e.do(t, "POST", "/v1/grp/g:shard", toks[i], `{"shards":4096,"ttl_s":60}`)
	}
	// With n=3 each member owns {s : s mod 3 == rank}: every=3, from=rank.
	for i, tk := range toks {
		st, body := e.do(t, "POST", "/v1/grp/g:shard", tk, `{}`)
		want(t, st, body, 200, fmt.Sprintf("every=3 from=%d", i))
		if field(body, "n") != "3" {
			t.Fatalf("member %d n: %q", i, body)
		}
	}
}

func TestEpochFence(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, ta := mkRoot(t, randIP(), 1)
	_, body := e.do(t, "POST", "/v1/grp/g:fence", ta, `{"ttl_s":60}`)
	var epoch int64
	fmt.Sscan(field(body, "epoch"), &epoch)
	// The live epoch fences nothing.
	if err := CheckFence(ctx, testPool, "grp:g:fence", epoch); err != nil {
		t.Fatalf("CheckFence at the live epoch: %v", err)
	}
	// A second member rebalances the group: the old epoch now fences out.
	_, tb := mkRoot(t, randIP(), 1)
	e.do(t, "POST", "/v1/grp/g:fence", tb, `{}`)
	err := CheckFence(ctx, testPool, "grp:g:fence", epoch)
	if err == nil {
		t.Fatal("stale epoch should be fenced")
	}
	if ae, ok := err.(*core.APIError); !ok || ae.Status != 409 || ae.Code != "fenced" {
		t.Fatalf("want 409 fenced, got %v", err)
	}
	// The new epoch passes again.
	if err := CheckFence(ctx, testPool, "grp:g:fence", epoch+1); err != nil {
		t.Fatalf("CheckFence at the new epoch: %v", err)
	}
}

func TestDistinctStandby(t *testing.T) {
	e := newEnv(t)
	// Two roots share a /24 (same super-group); a third is elsewhere.
	_, t1 := mkRoot(t, "10.9.9.1", 1)
	_, t2 := mkRoot(t, "10.9.9.2", 1)
	_, t3 := mkRoot(t, "10.8.8.1", 1)
	st, body := e.do(t, "POST", "/v1/grp/g:dist", t1, `{"distinct":true,"ttl_s":60}`)
	want(t, st, body, 200, "rank=0")
	// Same super-group: the second member stands by at rank -1.
	st, body = e.do(t, "POST", "/v1/grp/g:dist", t2, `{}`)
	want(t, st, body, 200, "standby")
	if field(body, "rank") != "-1" {
		t.Fatalf("second member of a super-group should stand by: %q", body)
	}
	// A different super-group is ranked next (rank 1), so n=2.
	st, body = e.do(t, "POST", "/v1/grp/g:dist", t3, `{}`)
	want(t, st, body, 200, "rank=1")
	if field(body, "n") != "2" {
		t.Fatalf("distinct n should count super-groups: %q", body)
	}
}

func TestFlappingLimit(t *testing.T) {
	e := newEnv(t)
	_, tk := mkRoot(t, randIP(), 1)
	ok := 0
	got429 := false
	for i := 0; i < 60 && !got429; i++ {
		st, body := e.do(t, "POST", "/v1/grp/g:flap", tk, `{"ttl_s":60}`)
		if st == 429 {
			want(t, st, body, 429, "flapping")
			got429 = true
			break
		}
		if st != 200 {
			t.Fatalf("join %d: %d %q", i, st, body)
		}
		ok++
		st, body = e.do(t, "DELETE", "/v1/grp/g:flap", tk, "")
		if st == 429 {
			want(t, st, body, 429, "flapping")
			got429 = true
			break
		}
		if st != 200 {
			t.Fatalf("leave %d: %d %q", i, st, body)
		}
		ok++
	}
	if !got429 {
		t.Fatal("expected 429 err rate flapping within 30 epoch bumps")
	}
	if ok < 10 || ok > 31 {
		t.Fatalf("flapping tripped after %d successful bumps (want ~30)", ok)
	}
}

func TestLongPollOnEpochChange(t *testing.T) {
	e := newEnv(t)
	_, ta := mkRoot(t, randIP(), 1)
	_, body := e.do(t, "POST", "/v1/grp/g:lp", ta, `{"ttl_s":60}`)
	epoch := field(body, "epoch")
	// Immediate return when the query epoch already differs.
	st, imm := e.do(t, "GET", "/v1/grp/g:lp?epoch=0&wait=5", "", "")
	want(t, st, imm, 200, "epoch="+epoch)
	// Long-poll at the current epoch: a second join wakes it.
	type res struct {
		st   int
		body string
	}
	ch := make(chan res, 1)
	go func() {
		st, b := e.do(t, "GET", "/v1/grp/g:lp?epoch="+epoch+"&wait=10", ta, "")
		ch <- res{st, b}
	}()
	time.Sleep(200 * time.Millisecond)
	_, tb := mkRoot(t, randIP(), 1)
	e.do(t, "POST", "/v1/grp/g:lp", tb, `{}`)
	select {
	case r := <-ch:
		want(t, r.st, r.body, 200, "n=2")
		if field(r.body, "epoch") == epoch {
			t.Fatalf("long-poll returned the stale epoch: %q", r.body)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("long-poll did not wake on the epoch change")
	}
}

func TestReapAndIdleDelete(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ida, ta := mkRoot(t, randIP(), 1)
	idb, tb := mkRoot(t, randIP(), 1)
	e.do(t, "POST", "/v1/grp/g:reap", ta, `{"ttl_s":60}`)
	st, body := e.do(t, "POST", "/v1/grp/g:reap", tb, `{}`)
	want(t, st, body, 200, "n=2")
	epoch2 := field(body, "epoch")
	// b stops heartbeating: the janitor reaps it, bumps the epoch and re-ranks a as rank 0.
	expire(t, "g:reap", idb)
	if err := e.s.janitor(ctx); err != nil {
		t.Fatal(err)
	}
	st, body = e.do(t, "GET", "/v1/grp/g:reap", "", "")
	want(t, st, body, 200, "n=1")
	if field(body, "epoch") == epoch2 {
		t.Fatalf("reap did not bump the epoch: %q", body)
	}
	if !strings.Contains(body, fmt.Sprintf("- %s rank=0", ida)) || strings.Contains(body, idb) {
		t.Fatalf("after reap only a remains at rank 0: %q", body)
	}
	// Empty and idle past 7 days: the janitor deletes the group.
	expire(t, "g:reap", ida)
	if err := e.s.janitor(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE groups SET touched = now() - interval '8 days' WHERE name = 'g:reap'`); err != nil {
		t.Fatal(err)
	}
	if err := e.s.janitor(ctx); err != nil {
		t.Fatal(err)
	}
	st, body = e.do(t, "GET", "/v1/grp/g:reap", "", "")
	want(t, st, body, 404, "notfound")
}

func TestL0CannotJoinForeignG(t *testing.T) {
	e := newEnv(t)
	_, towner := mkRoot(t, randIP(), 1)
	e.do(t, "POST", "/v1/grp/g:owned", towner, `{"ttl_s":60}`)
	_, tl0 := mkRoot(t, randIP(), 0)
	st, body := e.do(t, "POST", "/v1/grp/g:owned", tl0, `{}`)
	want(t, st, body, 403, "l0 cannot join")
}
