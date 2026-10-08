package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/pow"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	// Core drops the whole schema, so it gets its own database when TEST_CORE_DATABASE_URL is set
	// (other packages share TEST_DATABASE_URL concurrently).
	url := os.Getenv("TEST_CORE_DATABASE_URL")
	if url == "" {
		url = os.Getenv("TEST_DATABASE_URL")
	}
	if url == "" {
		fmt.Println("TEST_CORE_DATABASE_URL/TEST_DATABASE_URL unset: skipping core DB tests")
		os.Exit(0)
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		panic(err)
	}
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		panic(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		panic(err)
	}
	testPool = pool
	code := m.Run()
	pool.Close()
	os.Exit(code)
}

type tenv struct {
	d   *Deps
	srv *httptest.Server
	ip  string // per-env client IP (TrustCF on) so the per-IP registration cap does not leak across tests
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example"}
	d, err := NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	Register(mux, d)
	RegisterAuthV2(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	// Three random bytes: envs rarely share a /24, so the super-group registration cap never leaks.
	var b [3]byte
	rand.Read(b[:])
	return &tenv{d, srv, fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])}
}

// challenge asks for a registration challenge and solves it at the bits it announces (3.1: a
// root's bits are what the challenge demanded, so helpers never assume Cfg.PowBits).
func (e *tenv) challenge(t *testing.T, hdr ...string) (c, nonce string) {
	t.Helper()
	st, body := e.do(t, "POST", "/v1/challenge", "", nil, hdr...)
	if st != 200 {
		t.Fatalf("challenge: %d %s", st, body)
	}
	m := kv(body)
	bits, err := strconv.Atoi(m["bits"])
	if err != nil || m["for"] != "reg" {
		t.Fatalf("challenge reply: %s", body)
	}
	return m["c"], pow.Solve(m["c"], bits)
}

func (e *tenv) do(t *testing.T, method, path, token string, body any, hdr ...string) (int, string) {
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
	return res.StatusCode, strings.TrimSpace(string(b))
}

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

func kv(s string) map[string]string {
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(s, -1) {
		m[x[1]] = x[2]
	}
	return m
}

func (e *tenv) register(t *testing.T, name string) (id, tok string) {
	t.Helper()
	c, nonce := e.challenge(t)
	st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": name})
	if st != 201 {
		t.Fatalf("register: %d %s", st, body)
	}
	m := kv(body)
	if !ValidID(m["id"]) || !strings.HasPrefix(m["token"], "cx_") || m["credits"] != "100" || !ValidRecovery(m["recovery"]) || m["aup"] != "/aup.txt" {
		t.Fatalf("bad register reply: %s", body)
	}
	return m["id"], m["token"]
}

// badNonce returns a nonce that solves no difficulty at all for c (deterministic failure).
func badNonce(c string) string {
	for i := 0; ; i++ {
		n := "bad" + strconv.Itoa(i)
		if pow.LeadingZeros(c, n) == 0 {
			return n
		}
	}
}

// registerIP registers from a given client IP, returning the status and body.
func (e *tenv) registerIP(t *testing.T, ip, name string) (int, string) {
	t.Helper()
	c, nonce := e.challenge(t, "CF-Connecting-IP", ip)
	return e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": name}, "CF-Connecting-IP", ip)
}

func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, testPool); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	files, _ := fs.Glob(migrationFS, "migrations/*.sql")
	if n != len(files) {
		t.Fatalf("schema_migrations=%d files=%d", n, len(files))
	}
	var ext bool
	testPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='pg_trgm')`).Scan(&ext)
	if !ext {
		t.Fatal("pg_trgm missing")
	}
}

func TestRegisterAndMe(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register(t, "alice")
	st, body := e.do(t, "GET", "/v1/me", tok, nil)
	if st != 200 {
		t.Fatalf("me: %d %s", st, body)
	}
	m := kv(body)
	if m["id"] != id || m["name"] != "alice" || m["root"] != id || m["credits"] != "100" || m["rep"] != "0" || m["exp"] != "never" {
		t.Fatalf("me: %s", body)
	}
	st, body = e.do(t, "GET", "/v1/me?f=json", tok, nil)
	var j map[string]any
	if err := json.Unmarshal([]byte(body), &j); err != nil || j["id"] != id {
		t.Fatalf("me json: %d %s", st, body)
	}
	// JSON via Accept + error shape.
	st, body = e.do(t, "GET", "/v1/me", "", nil, "Accept", "application/json")
	if st != 401 || !strings.Contains(body, `"err":"auth"`) {
		t.Fatalf("anon me json: %d %s", st, body)
	}
}

func TestRegisterValidation(t *testing.T) {
	e := newEnv(t)
	c, nonce := e.challenge(t)
	st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": badNonce(c), "name": "a"})
	if st != 400 || !strings.HasPrefix(body, "err pow") {
		t.Fatalf("bad nonce: %d %s", st, body)
	}
	st, body = e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "bad name!"})
	if st != 400 || !strings.HasPrefix(body, "err bad") {
		t.Fatalf("bad name: %d %s", st, body)
	}
	st, body = e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "ok", "extra": "1"})
	if st != 400 || !strings.Contains(body, "unknown field") {
		t.Fatalf("unknown field: %d %s", st, body)
	}
	st, body = e.do(t, "POST", "/v1/register", "", map[string]string{"c": "AAAA", "nonce": nonce, "name": "ok"})
	if st != 400 || !strings.HasPrefix(body, "err pow") {
		t.Fatalf("forged challenge: %d %s", st, body)
	}
	// Reuse rejected.
	st, body = e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "ok"})
	if st != 201 {
		t.Fatalf("first: %d %s", st, body)
	}
	st, body = e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "ok2"})
	if st != 400 || !strings.Contains(body, "already used") {
		t.Fatalf("reuse: %d %s", st, body)
	}
}

// 3.2: registrations 1-5 per IP group per day get 100 credits, later ones 10 (tier=2); the v1 hard
// cap at 5 is gone (the super-group cap bounds the day).
func TestRegisterTiering(t *testing.T) {
	e := newEnv(t)
	ip := "203.0.113.7"
	for i := 0; i < regPerIP; i++ {
		st, body := e.registerIP(t, ip, "n")
		if st != 201 || kv(body)["credits"] != "100" || strings.Contains(body, "tier=") {
			t.Fatalf("reg %d: %d %s", i, st, body)
		}
	}
	for i := 0; i < 2; i++ {
		st, body := e.registerIP(t, ip, "n")
		if m := kv(body); st != 201 || m["credits"] != "10" || m["tier"] != "2" {
			t.Fatalf("reg %d (tier 2): %d %s", regPerIP+i, st, body)
		}
	}
	var credits int64
	testPool.QueryRow(context.Background(), `SELECT sum(credits) FROM identities WHERE reg_ip = $1 AND parent IS NULL`, ip).Scan(&credits)
	if credits != 5*100+2*10 {
		t.Fatalf("minted %d credits", credits)
	}
	// Another IP group in another super-group is at tier 1.
	if st, body := e.registerIP(t, "203.0.114.8", "n"); st != 201 || kv(body)["credits"] != "100" {
		t.Fatalf("other ip: %d %s", st, body)
	}
}

func TestSubkeyCascade(t *testing.T) {
	e := newEnv(t)
	root, rtok := e.register(t, "treeowner")
	_, otherTok := e.register(t, "other")
	st, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"name": "s1", "credits": 30})
	if st != 201 {
		t.Fatalf("subkey: %d %s", st, body)
	}
	s1 := kv(body)
	st, body = e.do(t, "POST", "/v1/subkey", s1["token"], map[string]any{"name": "s2", "credits": 10, "ttl_h": 2000})
	if st != 400 {
		t.Fatalf("ttl: %d %s", st, body)
	}
	st, body = e.do(t, "POST", "/v1/subkey", s1["token"], map[string]any{"name": "s2", "credits": 10, "ttl_h": 24})
	if st != 201 {
		t.Fatalf("subkey2: %d %s", st, body)
	}
	s2 := kv(body)
	if st, body := e.do(t, "POST", "/v1/subkey", s2["token"], map[string]any{"credits": 11}); st != 402 {
		t.Fatalf("over credits: %d %s", st, body)
	}
	_, body = e.do(t, "GET", "/v1/me", rtok, nil)
	if m := kv(body); m["credits"] != "70" {
		t.Fatalf("root credits: %s", body)
	}
	_, body = e.do(t, "GET", "/v1/me", s2["token"], nil)
	if m := kv(body); m["root"] != root || m["credits"] != "10" || m["exp"] == "never" {
		t.Fatalf("s2 me: %s", body)
	}
	// Non-ancestors cannot revoke.
	if st, _ := e.do(t, "DELETE", "/v1/subkey/"+s1["id"], s2["token"], nil); st != 404 {
		t.Fatalf("child revoking parent: %d", st)
	}
	if st, _ := e.do(t, "DELETE", "/v1/subkey/"+s1["id"], otherTok, nil); st != 404 {
		t.Fatalf("stranger revoking: %d", st)
	}
	st, body = e.do(t, "DELETE", "/v1/subkey/"+s1["id"], rtok, nil)
	if st != 200 || body != "ok revoked=2" {
		t.Fatalf("revoke: %d %s", st, body)
	}
	for _, tk := range []string{s1["token"], s2["token"]} {
		if st, body := e.do(t, "GET", "/v1/me", tk, nil); st != 401 {
			t.Fatalf("revoked still works: %d %s", st, body)
		}
	}
	_, body = e.do(t, "GET", "/v1/me", rtok, nil)
	if m := kv(body); m["credits"] != "100" {
		t.Fatalf("credits not refunded: %s", body)
	}
}

func TestAuthBadToken(t *testing.T) {
	e := newEnv(t)
	cases := map[string]string{"garbage": "nope", "wrong-len": "cx_abc", "unknown": "cx_" + strings.Repeat("A", 43)}
	for n, tk := range cases {
		if st, body := e.do(t, "GET", "/v1/me", tk, nil); st != 401 || !strings.HasPrefix(body, "err auth") {
			t.Fatalf("%s: %d %s", n, st, body)
		}
	}
	if st, body := e.do(t, "GET", "/v1/me", "", nil); st != 401 || body != "err auth token required" {
		t.Fatalf("no token: %d %s", st, body)
	}
	if st, _ := e.do(t, "POST", "/v1/subkey", "", map[string]any{}); st != 401 {
		t.Fatalf("anon subkey: %d", st)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register(t, "r")
	got429 := false
	for i := 0; i < 40; i++ {
		st, _ := e.do(t, "GET", "/v1/me", tok, nil)
		if st == 429 {
			if i < 30 {
				t.Fatalf("limited too early at %d", i)
			}
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("never rate limited")
	}
	// Bucket refills with time.
	l := e.d.Lim
	base := time.Now()
	l.now = func() time.Time { return base }
	for i := 0; i < 30; i++ {
		l.Allow("k", 10, 30)
	}
	if l.Allow("k", 10, 30) {
		t.Fatal("burst exceeded")
	}
	l.now = func() time.Time { return base.Add(time.Second) }
	for i := 0; i < 10; i++ {
		if !l.Allow("k", 10, 30) {
			t.Fatalf("refill %d", i)
		}
	}
	if l.Allow("k", 10, 30) {
		t.Fatal("over refill")
	}
	l.now = func() time.Time { return base.Add(time.Hour) }
	l.Evict(10 * time.Minute)
	if l.Len() != 0 {
		t.Fatalf("evict: %d", l.Len())
	}
}

func TestFreeze(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register(t, "f")
	if st, _ := e.do(t, "POST", "/admin/freeze", tok, map[string]any{"what": "reg", "on": true}); st != 401 {
		t.Fatalf("non-admin freeze: %d", st)
	}
	if st, body := e.do(t, "POST", "/admin/freeze", "adm-token", map[string]any{"what": "bogus", "on": true}); st != 400 {
		t.Fatalf("bogus: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/admin/freeze", "adm-token", map[string]any{"what": "reg", "on": true}); st != 200 {
		t.Fatalf("freeze: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/challenge", "", nil); st != 503 || body != "err frozen reg" {
		t.Fatalf("frozen challenge: %d %s", st, body)
	}
	if st, _ := e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 1}); st != 201 {
		t.Fatalf("write should still work: %d", st)
	}
	e.do(t, "POST", "/admin/freeze", "adm-token", map[string]any{"what": "all", "on": true})
	if st, body := e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 1}); st != 503 || body != "err frozen write" {
		t.Fatalf("frozen write: %d %s", st, body)
	}
	if !e.d.Frozen("compute") {
		t.Fatal("all should freeze compute")
	}
	// Persisted: a fresh Deps sees it.
	d2, err := NewDeps(context.Background(), e.d.Cfg, testPool, e.d.Log)
	if err != nil || !d2.Frozen("reg") {
		t.Fatal("freeze not persisted")
	}
	e.do(t, "POST", "/admin/freeze", "adm-token", map[string]any{"what": "all", "on": false})
	e.do(t, "POST", "/admin/freeze", "adm-token", map[string]any{"what": "reg", "on": false})
	if st, _ := e.do(t, "POST", "/v1/challenge", "", nil); st != 200 {
		t.Fatal("unfreeze failed")
	}
	st, body := e.do(t, "GET", "/admin/stats", "adm-token", nil)
	if st != 200 || !strings.Contains(body, "roots=") || !strings.Contains(body, "frozen=\n") {
		t.Fatalf("stats: %d %s", st, body)
	}
}

func TestPurge(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, rtok := e.register(t, "p")
	_, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"credits": 5})
	sub := kv(body)
	for _, q := range []string{
		`INSERT INTO kb (id, kind, title, author, author_root, expires_at) VALUES ('k' || substr(md5(random()::text),1,6), 'fix', 't', $1, $1, now() + interval '1 day')`,
		`INSERT INTO blobs (hash, size, owner_root) VALUES (repeat('a', 64), 1, $1)`,
		`INSERT INTO jobs (id, submitter, root, wasm, input, ms, mb) VALUES ('j' || substr(md5(random()::text),1,6), $1, $1, 'w', 'i', 1000, 64)`,
	} {
		if _, err := testPool.Exec(ctx, q, root); err != nil {
			t.Fatal(err)
		}
	}
	var hooked string
	e.d.OnPurge(func(_ context.Context, id string) error {
		hooked = id
		var n int
		testPool.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE owner_root = $1`, id).Scan(&n)
		if n != 1 {
			t.Errorf("hook should see rows before deletion, got %d", n)
		}
		return nil
	})
	if st, _ := e.do(t, "POST", "/admin/purge", "adm-token", map[string]any{"id": "a222222"}); st != 404 {
		t.Fatalf("purge unknown: %d", st)
	}
	st, body := e.do(t, "POST", "/admin/purge", "adm-token", map[string]any{"id": root})
	if st != 200 || body != "ok purged=2" {
		t.Fatalf("purge: %d %s", st, body)
	}
	if hooked != root {
		t.Fatalf("hook got %q", hooked)
	}
	for _, tk := range []string{rtok, sub["token"]} {
		if st, _ := e.do(t, "GET", "/v1/me", tk, nil); st != 401 {
			t.Fatalf("token alive after purge: %d", st)
		}
	}
	var kbN, blobN int
	var jobStatus string
	testPool.QueryRow(ctx, `SELECT count(*) FROM kb WHERE author_root = $1`, root).Scan(&kbN)
	testPool.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE owner_root = $1`, root).Scan(&blobN)
	testPool.QueryRow(ctx, `SELECT status FROM jobs WHERE root = $1`, root).Scan(&jobStatus)
	if kbN != 0 || blobN != 0 || jobStatus != "failed" {
		t.Fatalf("rows left: kb=%d blobs=%d job=%s", kbN, blobN, jobStatus)
	}
}

func TestQuotaCreditsRep(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, _ := e.register(t, "q")
	id := &Ident{ID: root, Root: root}
	for i := 0; i < 2; i++ {
		if err := UseQuota(ctx, testPool, id, "kb", 2); err != nil {
			t.Fatal(err)
		}
	}
	if err := UseQuota(ctx, testPool, id, "kb", 2); err != ErrQuota {
		t.Fatalf("expected quota, got %v", err)
	}
	id.Rep = 5
	if err := UseQuota(ctx, testPool, id, "kb", 2); err != nil {
		t.Fatalf("established x5: %v", err)
	}
	if err := UseIPQuota(ctx, testPool, "1.2.3.4", "report", 1); err != nil {
		t.Fatal(err)
	}
	if err := UseIPQuota(ctx, testPool, "1.2.3.4", "report", 1); err != ErrQuota {
		t.Fatal("ip quota")
	}
	if err := Reserve(ctx, testPool, root, 101); err != ErrCredits {
		t.Fatalf("reserve: %v", err)
	}
	if err := Reserve(ctx, testPool, root, 100); err != nil {
		t.Fatal(err)
	}
	if err := Refund(ctx, testPool, root, 40); err != nil {
		t.Fatal(err)
	}
	var c int64
	testPool.QueryRow(ctx, `SELECT credits FROM identities WHERE id=$1`, root).Scan(&c)
	if c != 40 {
		t.Fatalf("credits=%d", c)
	}
	// rep with daily cap 3: +2, +2 (capped to +1), +2 (0), -5 always.
	for i, want := range []int{2, 1, 0} {
		got, err := AddRep(ctx, testPool, root, 2, "rep:test", 3)
		if err != nil || got != want {
			t.Fatalf("AddRep %d: got %d want %d err %v", i, got, want, err)
		}
	}
	if got, _ := AddRep(ctx, testPool, root, -5, "", 0); got != -5 {
		t.Fatal("negative rep should always apply")
	}
	if r, _ := Rep(ctx, testPool, root); r != -2 {
		t.Fatalf("rep=%d", r)
	}
	if VoteWeight(0) != 1 || VoteWeight(10) != 2 || VoteWeight(50) != 3 {
		t.Fatal("vote weight")
	}
}

func TestBannedAndSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	root, tok := e.register(t, "b")
	testPool.Exec(context.Background(), `UPDATE identities SET rep = -10 WHERE id = $1`, root)
	st, body := e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 1})
	if st != 403 || body != "err auth banned" {
		t.Fatalf("banned write: %d %s", st, body)
	}
	if st, _ := e.do(t, "GET", "/v1/me", tok, nil); st != 200 {
		t.Fatal("banned should still read")
	}
	res, err := http.Get(e.srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("X-Content-Type-Options") != "nosniff" || res.Header.Get("X-Frame-Options") != "DENY" || res.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers: %v", res.Header)
	}
}

func TestNotifierAndJanitor(t *testing.T) {
	n := NewNotifier()
	done := make(chan bool)
	go func() { done <- n.Wait(context.Background(), "x", time.Second) }()
	time.Sleep(10 * time.Millisecond)
	n.Wake("x")
	if !<-done {
		t.Fatal("not woken")
	}
	if n.Wait(context.Background(), "y", 5*time.Millisecond) {
		t.Fatal("spurious wake")
	}
	j := &Janitor{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ran := 0
	j.Add("a", func(context.Context) error { ran++; return nil })
	j.Add("b", func(context.Context) error { ran++; return fmt.Errorf("boom") })
	j.RunOnce(context.Background())
	if ran != 2 {
		t.Fatal("janitor tasks")
	}
}

// #5: waiters must not leave topics behind.
func TestNotifierLeakFree(t *testing.T) {
	n := NewNotifier()
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 10000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n.Wait(ctx, fmt.Sprintf("job:j%06x", mrand.IntN(1<<30)), time.Microsecond)
		}()
	}
	wg.Wait()
	if n.Len() != 0 {
		t.Fatalf("leaked %d topics after 10k waits", n.Len())
	}
	// Subscribe/cancel refcount: the topic lives while one subscriber remains.
	c1, cancel1 := n.Subscribe("t")
	_, cancel2 := n.Subscribe("t")
	cancel1()
	if n.Len() != 1 {
		t.Fatal("topic dropped while still subscribed")
	}
	n.Wake("t")
	select {
	case <-c1:
	default:
		t.Fatal("c1 not closed by Wake")
	}
	cancel2()
	cancel2() // idempotent
	if n.Len() != 0 {
		t.Fatalf("after wake+cancel: %d", n.Len())
	}
	// A cancel after Wake must not delete a newer entry for the same topic.
	_, cancelOld := n.Subscribe("u")
	n.Wake("u")
	cNew, cancelNew := n.Subscribe("u")
	cancelOld()
	if n.Len() != 1 {
		t.Fatal("stale cancel removed the new entry")
	}
	n.Wake("u")
	<-cNew
	cancelNew()
	// Legacy Chan entries are reclaimed (and closed) by Sweep.
	c := n.Chan("legacy")
	n.Sweep(time.Hour)
	if n.Len() != 1 {
		t.Fatal("sweep dropped a fresh legacy entry")
	}
	n.Sweep(0)
	select {
	case <-c:
	case <-time.After(time.Second):
		t.Fatal("swept legacy channel not closed")
	}
	if n.Len() != 0 {
		t.Fatalf("after sweep: %d", n.Len())
	}
}

// #6: credits must be conserved when a spend races a revoke (previously the pre-wait tuple was refunded).
func TestRevokeRaceConservesCredits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, _ := e.register(t, "racer")
	parent := &Ident{ID: root, Root: root}
	var sub string
	if err := Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		sub, _, err = CreateSubkey(ctx, tx, parent, "s", 100, time.Now().Add(time.Hour))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	total := func() int64 {
		var n int64
		testPool.QueryRow(ctx, `SELECT sum(credits) FROM identities WHERE root = $1`, root).Scan(&n)
		return n
	}
	if total() != 100 {
		t.Fatalf("setup total %d", total())
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Reserve(ctx, tx, sub, 90); err != nil { // spend held open
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- Tx(ctx, testPool, func(tx pgx.Tx) error {
			_, err := RevokeTree(ctx, tx, sub, root)
			return err
		})
	}()
	select {
	case err := <-done:
		t.Fatalf("revoke did not block on the locked row: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var rc, sc int64
	testPool.QueryRow(ctx, `SELECT credits FROM identities WHERE id = $1`, root).Scan(&rc)
	testPool.QueryRow(ctx, `SELECT credits FROM identities WHERE id = $1`, sub).Scan(&sc)
	if rc != 10 || sc != 0 || total() != 10 {
		t.Fatalf("credits minted: root=%d sub=%d total=%d (spent 90 of 100)", rc, sc, total())
	}
	// Concurrent many-spend vs revoke: no creation either way.
	root2, _ := e.register(t, "racer2")
	p2 := &Ident{ID: root2, Root: root2}
	var sub2 string
	Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		sub2, _, err = CreateSubkey(ctx, tx, p2, "s", 100, time.Now().Add(time.Hour))
		return
	})
	var wg sync.WaitGroup
	var spent int64
	var mu sync.Mutex
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if Reserve(ctx, testPool, sub2, 3) == nil {
					mu.Lock()
					spent += 3
					mu.Unlock()
				}
			}
		}()
	}
	time.Sleep(5 * time.Millisecond)
	if err := Tx(ctx, testPool, func(tx pgx.Tx) error { _, err := RevokeTree(ctx, tx, sub2, root2); return err }); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	var tot int64
	testPool.QueryRow(ctx, `SELECT sum(credits) FROM identities WHERE root = $1`, root2).Scan(&tot)
	if tot+spent != 100 {
		t.Fatalf("not conserved: remaining=%d spent=%d", tot, spent)
	}
}

// #6 (janitor): expired subkeys refund their real balance to the parent, chain-wise.
func TestRevokeExpiredRefund(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, _ := e.register(t, "exp")
	p := &Ident{ID: root, Root: root}
	var s1, s2 string
	if err := Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
		if s1, _, err = CreateSubkey(ctx, tx, p, "s1", 60, time.Now().Add(time.Hour)); err != nil {
			return err
		}
		s2, _, err = CreateSubkey(ctx, tx, &Ident{ID: s1, Root: root}, "s2", 25, time.Now().Add(time.Hour))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// root 40, s1 35, s2 25. Expire both; s2 must flow into s1, then s1 (60) into root.
	testPool.Exec(ctx, `UPDATE identities SET expires_at = now() - interval '1 second' WHERE id IN ($1, $2)`, s1, s2)
	n, err := RevokeExpired(ctx, testPool)
	if err != nil || n != 2 {
		t.Fatalf("RevokeExpired: n=%d err=%v", n, err)
	}
	var rc int64
	var revoked int
	testPool.QueryRow(ctx, `SELECT credits FROM identities WHERE id = $1`, root).Scan(&rc)
	testPool.QueryRow(ctx, `SELECT count(*) FROM identities WHERE root = $1 AND revoked_at IS NOT NULL AND credits = 0`, root).Scan(&revoked)
	if rc != 100 || revoked != 2 {
		t.Fatalf("root credits=%d revoked=%d (want 100, 2)", rc, revoked)
	}
	// Janitor removes subkeys revoked > 30 days ago, leaves first; roots stay.
	testPool.Exec(ctx, `UPDATE identities SET revoked_at = now() - interval '31 days' WHERE id IN ($1, $2)`, s1, s2)
	e.d.Janitor.RunOnce(ctx)
	var left int
	testPool.QueryRow(ctx, `SELECT count(*) FROM identities WHERE root = $1`, root).Scan(&left)
	if left != 2 { // s2 (leaf) gone, s1 next run
		t.Fatalf("after 1st run: %d rows", left)
	}
	e.d.Janitor.RunOnce(ctx)
	testPool.QueryRow(ctx, `SELECT count(*) FROM identities WHERE root = $1`, root).Scan(&left)
	if left != 1 {
		t.Fatalf("after 2nd run: %d rows", left)
	}
}

func TestSubkeyCap(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, tok := e.register(t, "cap")
	p := &Ident{ID: root, Root: root}
	for i := 0; i < MaxLiveSubkeys; i++ {
		if err := Tx(ctx, testPool, func(tx pgx.Tx) (err error) {
			_, _, err = CreateSubkey(ctx, tx, p, "s", 0, time.Now().Add(time.Hour))
			return err
		}); err != nil {
			t.Fatalf("subkey %d: %v", i, err)
		}
	}
	if st, body := e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 0}); st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("101st subkey: %d %s", st, body)
	}
	// Revoking one frees a slot.
	var one string
	testPool.QueryRow(ctx, `SELECT id FROM identities WHERE root = $1 AND parent IS NOT NULL LIMIT 1`, root).Scan(&one)
	if st, _ := e.do(t, "DELETE", "/v1/subkey/"+one, tok, nil); st != 200 {
		t.Fatal("revoke")
	}
	if st, body := e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 0}); st != 201 {
		t.Fatalf("after revoke: %d %s", st, body)
	}
}

func TestIPGroup(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":          "203.0.113.7",
		"::ffff:203.0.113.7":   "203.0.113.7",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::1": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"garbage":              "garbage",
	} {
		if got := IPGroup(in); got != want {
			t.Errorf("IPGroup(%q)=%q want %q", in, got, want)
		}
	}
	// The registration tier is per /64: five from one /64 put a sixth address in it on tier 2.
	e := newEnv(t)
	var b [2]byte
	rand.Read(b[:])
	pfx := fmt.Sprintf("2001:db8:%x:%x:", b[0], b[1])
	for i := 0; i < regPerIP; i++ {
		if st, body := e.registerIP(t, fmt.Sprintf("%s%x::1", pfx, i+1), "v6"); st != 201 || kv(body)["credits"] != "100" {
			t.Fatalf("v6 reg %d: %d %s", i, st, body)
		}
	}
	if st, body := e.registerIP(t, pfx+"dead:beef::7", "v6"); st != 201 || kv(body)["tier"] != "2" {
		t.Fatalf("6th in /64: %d %s", st, body)
	}
	// Anonymous rate limit shares the /64 bucket too.
	e2 := newEnv(t)
	hit := 0
	for i := 0; i < 40; i++ {
		if st, _ := e2.do(t, "GET", "/healthz", "", nil, "CF-Connecting-IP", fmt.Sprintf("2001:db8:ffff:%x::%x", b[0], i+1)); st == 429 {
			hit++
		}
	}
	if hit == 0 {
		t.Fatal("rotating IPv6 hosts in one /64 bypassed the anonymous rate limit")
	}
}

func TestRegisterGlobalRate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var hour int
	testPool.QueryRow(ctx, `SELECT count(*) FROM reg_ips WHERE at > now() - interval '1 hour'`).Scan(&hour)
	e.d.Cfg.RegPerHour = hour + 1
	e.register(t, "g1")
	c, nonce := e.challenge(t)
	st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "g2"})
	if st != 429 || !strings.Contains(body, "per hour") {
		t.Fatalf("global rate: %d %s", st, body)
	}
	e.d.Cfg.RegPerHour = 0 // default (300) applies again
	e.register(t, "g3")
}

func TestLimiterCap(t *testing.T) {
	l := NewLimiter()
	base := time.Now()
	l.now = func() time.Time { return base }
	l.max = 4
	for i := 0; i < 4; i++ {
		l.Allow(fmt.Sprintf("ip:10.0.0.%d", i), 5, 2)
	}
	// New anonymous keys at cap share the overflow bucket (burst 2 total), no allocation.
	ok := 0
	for i := 0; i < 10; i++ {
		if l.Allow(fmt.Sprintf("ip:192.0.2.%d", i), 5, 2) {
			ok++
		}
	}
	if ok != 2 || l.Len() != 4 {
		t.Fatalf("overflow: ok=%d len=%d", ok, l.Len())
	}
	// Roots still get their own bucket.
	if !l.Allow("a1234567", 10, 30) || l.Len() != 5 {
		t.Fatal("root at cap")
	}
	// Idle entries are evicted under pressure (once per 10 s).
	l.now = func() time.Time { return base.Add(2 * time.Minute) }
	if !l.Allow("ip:198.51.100.1", 5, 2) || l.Len() > 5 {
		t.Fatalf("evict under pressure: len=%d", l.Len())
	}
}
