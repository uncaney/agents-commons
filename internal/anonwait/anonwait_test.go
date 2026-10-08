package anonwait

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
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
	} else if pool, done := testdb.Open("anonwait", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping anonwait DB tests")
		os.Exit(0)
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
	ctx := context.Background()
	for _, sql := range []string{`TRUNCATE a2a_pending`, `TRUNCATE pow_wait`, `TRUNCATE wait_writes`,
		`TRUNCATE used_challenges`, `TRUNCATE counters`, `TRUNCATE tasks CASCADE`} {
		if _, err := testPool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", OpsToken: "ops-token", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(ctx, cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
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

// fixClock pins now() for the test and restores the real clock afterwards.
func fixClock(t *testing.T, at time.Time) *time.Time {
	t.Helper()
	clk := at
	nowFn = func() time.Time { return clk }
	t.Cleanup(func() { nowFn = time.Now })
	return &clk
}

// waitReq builds a POST request carrying the given X-PoW header, with a lane cell seeded on its
// context (as the middleware would) and a fixed source IP.
func waitReq(header string) (*http.Request, context.Context) {
	r := httptest.NewRequest(http.MethodPost, "/w/kb", nil)
	r.RemoteAddr = "203.0.113.7:5000"
	if header != "" {
		r.Header.Set("X-PoW", header)
	}
	ctx := WithLane(context.Background())
	return r.WithContext(ctx), ctx
}

func mintWait(secret []byte, exp time.Time, waitS int) string {
	return pow.New(secret, exp, waitS/10, pow.PurposeWait)
}

func TestWaitChallengeTooEarlyRejected(t *testing.T) {
	e := newEnv(t)
	secret := e.d.Cfg.ServerSecret
	t0 := time.Now().Truncate(time.Second)
	clk := fixClock(t, t0)
	c := mintWait(secret, t0.Add(challengeTTL), 20) // ready = t0 + 20 s

	var innerCalled bool
	wrapped := Wrap(func(context.Context, core.Q, *http.Request) (string, string, error) {
		innerCalled = true
		return "g", "s", nil
	})

	*clk = t0.Add(5 * time.Second) // 5 s after issuance: still inside the 20 s wait
	r, ctx := waitReq(c + ":wait")
	_, _, err := wrapped(ctx, e.d.DB, r)
	if err == nil || !strings.Contains(err.Error(), "too early") {
		t.Fatalf("want err pow too early, got %v", err)
	}
	if innerCalled {
		t.Fatal("inner hashcash checker must not run for a wait header")
	}
	if WaitMode(ctx) {
		t.Fatal("a rejected wait must not mark the request wait-mode")
	}
}

func TestWaitChallengeAcceptedInWindowSingleUse(t *testing.T) {
	e := newEnv(t)
	secret := e.d.Cfg.ServerSecret
	t0 := time.Now().Truncate(time.Second)
	clk := fixClock(t, t0)
	c := mintWait(secret, t0.Add(challengeTTL), 20)

	wrapped := Wrap(func(context.Context, core.Q, *http.Request) (string, string, error) {
		t.Fatal("inner must not run when a wait header is accepted")
		return "", "", nil
	})

	*clk = t0.Add(20 * time.Second) // exactly at ready
	r, ctx := waitReq(c + ":wait")
	grp, super, err := wrapped(ctx, e.d.DB, r)
	if err != nil {
		t.Fatalf("accept in window: %v", err)
	}
	if grp == "" || super == "" {
		t.Fatalf("network keys not returned: %q %q", grp, super)
	}
	if !WaitMode(ctx) || !IsWait(ctx) {
		t.Fatal("accepted wait must mark the request wait-mode")
	}
	// The write was charged to the super-group for the adaptive counter.
	var writes int
	if err := e.d.DB.QueryRow(context.Background(), `SELECT COALESCE(sum(n),0)::int FROM wait_writes WHERE super_h = $1`, grpHash(super)).Scan(&writes); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("wait_writes = %d, want 1", writes)
	}
	// Single use: the same header is now spent.
	r2, ctx2 := waitReq(c + ":wait")
	if _, _, err := wrapped(ctx2, e.d.DB, r2); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("want challenge already used, got %v", err)
	}
}

func TestWrapDelegatesHashcash(t *testing.T) {
	e := newEnv(t)
	var got string
	wrapped := Wrap(func(_ context.Context, _ core.Q, r *http.Request) (string, string, error) {
		got = r.Header.Get("X-PoW")
		return "grp", "sup", nil
	})
	// A normal hashcash header (<c>:<nonce>) falls through to inner unchanged.
	r, ctx := waitReq("abc123:4815162342")
	grp, sup, err := wrapped(ctx, e.d.DB, r)
	if err != nil || grp != "grp" || sup != "sup" {
		t.Fatalf("delegate: %q %q %v", grp, sup, err)
	}
	if got != "abc123:4815162342" {
		t.Fatalf("inner saw %q", got)
	}
	if WaitMode(ctx) {
		t.Fatal("hashcash delegation must not mark wait-mode")
	}
	// An empty header also delegates (inner owns the 'required' hint).
	r2, ctx2 := waitReq("")
	if _, _, err := wrapped(ctx2, e.d.DB, r2); err != nil {
		t.Fatalf("empty header delegate: %v", err)
	}
}

func TestAdaptiveWaitAndOutstandingCaps(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	super := "198.51.100.0/24"
	// No writes yet: base wait.
	if w, err := adaptiveWait(ctx, e.d.DB, super); err != nil || w != 20 {
		t.Fatalf("base wait = %d (%v), want 20", w, err)
	}
	for _, tc := range []struct{ writes, want int }{{9, 20}, {10, 40}, {20, 80}, {30, 160}, {40, 300}, {100, 300}} {
		if _, err := e.d.DB.Exec(ctx, `INSERT INTO wait_writes (super_h, day, n) VALUES ($1, current_date, $2)
			ON CONFLICT (super_h, day) DO UPDATE SET n = $2`, grpHash(super), tc.writes); err != nil {
			t.Fatal(err)
		}
		w, err := adaptiveWait(ctx, e.d.DB, super)
		if err != nil {
			t.Fatal(err)
		}
		if w != tc.want {
			t.Fatalf("writes=%d: wait_s=%d, want %d", tc.writes, w, tc.want)
		}
	}
	// Outstanding caps. Group: 10 issuances per group per hour, then 429 (distinct supers so the
	// super cap never interferes).
	fixClock(t, time.Now())
	for i := 1; i <= 10; i++ {
		if err := chargeOutstanding(ctx, e.d.DB, "gc", "spU"+strconv.Itoa(i)); err != nil {
			t.Fatalf("group issuance %d: %v", i, err)
		}
	}
	if err := chargeOutstanding(ctx, e.d.DB, "gc", "spUx"); err == nil || !strings.Contains(err.Error(), "outstanding") {
		t.Fatalf("11th group issuance should 429, got %v", err)
	}
	// Super: 40 issuances from distinct groups under one super, then 429.
	for i := 1; i <= 40; i++ {
		if err := chargeOutstanding(ctx, e.d.DB, "gs"+strconv.Itoa(i), "sc"); err != nil {
			t.Fatalf("super issuance %d: %v", i, err)
		}
	}
	if err := chargeOutstanding(ctx, e.d.DB, "gs999", "sc"); err == nil || !strings.Contains(err.Error(), "outstanding") {
		t.Fatalf("41st super issuance should 429, got %v", err)
	}
}

func TestIssuanceRouteText(t *testing.T) {
	e := newEnv(t)
	fixClock(t, time.Now().Truncate(time.Second))
	res, err := http.Get(e.srv.URL + "/v1/challenge/wait?for=w")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	body := strings.TrimSpace(string(b))
	if res.StatusCode != 200 {
		t.Fatalf("status %d: %s", res.StatusCode, body)
	}
	for _, want := range []string{"for=w", "mode=wait", "wait_s=20", "c=", "ready=", "exp="} {
		if !strings.Contains(body, want) {
			t.Fatalf("issuance reply %q missing %q", body, want)
		}
	}
	// The minted challenge is a w_wait token readable with the server secret.
	c := field(body, "c=")
	info, err := pow.VerifyV2(e.d.Cfg.ServerSecret, c, now())
	if err != nil || info.Purpose != pow.PurposeWait || info.Bits != 2 {
		t.Fatalf("minted token bad: %+v %v", info, err)
	}
}

func field(line, key string) string {
	for _, f := range strings.Fields(line) {
		if strings.HasPrefix(f, key) {
			return strings.TrimPrefix(f, key)
		}
	}
	return ""
}

func TestPendingTicketLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	clk := fixClock(t, time.Now())

	ticket, err := Pending(ctx, e.d.DB, "192.0.2.5", "192.0.2.0/24", "fix the flaky retry loop\nit double-sends on reconnect")
	if err != nil {
		t.Fatal(err)
	}
	if !core.ValidIDPrefix(ticket, 'q') {
		t.Fatalf("ticket %q is not a q… id", ticket)
	}
	// Early: the same working ticket, no board task yet.
	n, state, err := PendingGet(ctx, e.d, ticket)
	if err != nil || n > 0 || state != forgeWorking {
		t.Fatalf("early get: n=%d state=%q err=%v", n, state, err)
	}

	// After 30 s: materialised into a quarantined board task.
	*clk = time.Now().Add(31 * time.Second)
	n, _, err = PendingGet(ctx, e.d, ticket)
	if err != nil || n <= 0 {
		t.Fatalf("materialise: n=%d err=%v", n, err)
	}
	var quarantine bool
	var title string
	if err := e.d.DB.QueryRow(ctx, `SELECT quarantine, title FROM tasks WHERE n = $1`, n).Scan(&quarantine, &title); err != nil {
		t.Fatalf("task %d not created: %v", n, err)
	}
	if !quarantine {
		t.Fatal("materialised ticket must be quarantined")
	}
	if title != "fix the flaky retry loop" {
		t.Fatalf("title = %q", title)
	}
	// A repeat get returns the same board task, not a new one.
	n2, _, err := PendingGet(ctx, e.d, ticket)
	if err != nil || n2 != n {
		t.Fatalf("repeat get: n2=%d (want %d) err=%v", n2, n, err)
	}

	// A fresh ticket left past 10 min is -32001 and its row is deleted.
	*clk = time.Now()
	late, err := Pending(ctx, e.d.DB, "192.0.2.6", "192.0.2.0/24", "stale ticket")
	if err != nil {
		t.Fatal(err)
	}
	*clk = time.Now().Add(11 * time.Minute)
	if _, _, err := PendingGet(ctx, e.d, late); err != core.ErrNotFound {
		t.Fatalf("expired get: want ErrNotFound, got %v", err)
	}
	var cnt int
	e.d.DB.QueryRow(context.Background(), `SELECT count(*) FROM a2a_pending WHERE ticket = $1`, late).Scan(&cnt)
	if cnt != 0 {
		t.Fatal("expired ticket row must be deleted")
	}
}

func TestPendingCaps(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	fixClock(t, time.Now())

	// 5 live tickets per group, then 429.
	for i := 0; i < 5; i++ {
		if _, err := Pending(ctx, e.d.DB, "198.51.100.9", "198.51.100.0/24", "t"+strconv.Itoa(i)); err != nil {
			t.Fatalf("ticket %d: %v", i, err)
		}
	}
	if _, err := Pending(ctx, e.d.DB, "198.51.100.9", "198.51.100.0/24", "overflow"); err == nil || !strings.Contains(err.Error(), "live tickets") {
		t.Fatalf("6th same-group ticket should 429, got %v", err)
	}

	// 20 live per super-group across distinct groups, then 429.
	for i := 0; i < 20; i++ {
		grp := fmt.Sprintf("203.0.113.%d", i+1)
		if _, err := Pending(ctx, e.d.DB, grp, "203.0.113.0/24", "s"+strconv.Itoa(i)); err != nil {
			t.Fatalf("super ticket %d: %v", i, err)
		}
	}
	if _, err := Pending(ctx, e.d.DB, "203.0.113.200", "203.0.113.0/24", "super overflow"); err == nil || !strings.Contains(err.Error(), "live tickets") {
		t.Fatalf("21st same-super ticket should 429, got %v", err)
	}

	// 2 materialisations per group per day, then 429.
	clk := fixClock(t, time.Now())
	var tickets []string
	for i := 0; i < 3; i++ {
		tk, err := Pending(ctx, e.d.DB, "192.0.2.50", "192.0.2.0/24", "mat"+strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		tickets = append(tickets, tk)
	}
	*clk = time.Now().Add(31 * time.Second)
	for i, tk := range tickets {
		_, _, err := PendingGet(ctx, e.d, tk)
		if i < 2 && err != nil {
			t.Fatalf("materialisation %d should pass: %v", i, err)
		}
		if i == 2 && (err == nil || !strings.Contains(err.Error(), "materialisation")) {
			t.Fatalf("3rd materialisation should 429, got %v", err)
		}
	}
}
