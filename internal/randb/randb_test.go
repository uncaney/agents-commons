package randb

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

const secret = "test-secret-0123456789-randb"

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
	} else if pool, done := testdb.Open("randb", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping randb DB tests")
		os.Exit(0)
	}
	// The package signer, for tests that call Advance directly without going through Register.
	signerP.Store(sign.MustNew(core.Config{ServerSecret: []byte(secret)}))
	// Auth's anonymous seam, stubbed: "X-PoW: ok" is a valid proof.
	core.XPoWFn = func(ctx context.Context, q core.Q, r *http.Request) (string, string, error) {
		if r.Header.Get("X-PoW") != "ok" {
			return "", "", core.ErrPow
		}
		_, grp, sup := core.ClientFrom(ctx)
		return grp, sup, nil
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
	ip  string
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte(secret), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
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
	return &tenv{d: d, srv: srv, ip: randIP()}
}

func randIP() string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.9.%d.%d", b[0], b[1])
}

func (e *tenv) do(t *testing.T, method, path, token, body string, hdr ...string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", e.ip)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// reset clears the beacon tables so each test starts from an empty chain.
func reset(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `TRUNCATE rand_rounds, rand_mix`); err != nil {
		t.Fatal(err)
	}
}

// atMinute returns a wall-clock time at the start of unix minute m.
func atMinute(m int64) time.Time { return time.Unix(m*60, 0).UTC() }

func TestCommitThenReveal(t *testing.T) {
	reset(t)
	ctx := context.Background()
	key := seedKey([]byte(secret))
	m0 := minute(time.Now())
	// Produce round m0, then round m0+1 one minute later.
	if _, err := Advance(ctx, testPool, []byte(secret), atMinute(m0)); err != nil {
		t.Fatal(err)
	}
	if _, err := Advance(ctx, testPool, []byte(secret), atMinute(m0+1)); err != nil {
		t.Fatal(err)
	}
	r0, err := loadRound(ctx, testPool, m0)
	if err != nil || r0 == nil {
		t.Fatalf("round m0: %v %v", r0, err)
	}
	r1, err := loadRound(ctx, testPool, m0+1)
	if err != nil || r1 == nil {
		t.Fatalf("round m0+1: %v %v", r1, err)
	}
	// The commitment published one round ahead (c_next in round m0) must equal sha256 of the seed
	// revealed in round m0+1.
	cNext := commit(seed(key, m0+1))
	if hex.EncodeToString(commit(r1.S)) != hex.EncodeToString(cNext) {
		t.Fatalf("reveal does not match commitment")
	}
	// And that commitment is the c_next field of round m0's signed statement.
	r0.CNext = cNext
	if !strings.Contains(r0.Line(), "c_next="+hex.EncodeToString(cNext)) {
		t.Fatalf("round m0 statement missing c_next: %s", r0.Line())
	}
	// r_t binds the revealed seed and the mix.
	if hex.EncodeToString(r1.R) != hex.EncodeToString(beacon(r1.S, r1.Mix)) {
		t.Fatalf("r_t != sha256(s||mix)")
	}
}

func TestMixIncludedSorted(t *testing.T) {
	reset(t)
	ctx := context.Background()
	m := minute(time.Now())
	// Insert contributions for minute m in a deliberately unsorted order.
	var raw [][]byte
	for i := 0; i < 5; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("contribution-%d", i)))
		raw = append(raw, h[:])
	}
	// Shuffle the insert order (reverse) to prove folding sorts.
	for i := len(raw) - 1; i >= 0; i-- {
		if err := addMix(ctx, testPool, m, raw[i]); err != nil {
			t.Fatal(err)
		}
	}
	// Duplicate one contribution: it must collapse (PK), not be double-counted.
	if err := addMix(ctx, testPool, m, raw[2]); err != nil {
		t.Fatal(err)
	}
	// Round m+1 folds minute m's contributions.
	if _, err := Advance(ctx, testPool, []byte(secret), atMinute(m+1)); err != nil {
		t.Fatal(err)
	}
	r1, err := loadRound(ctx, testPool, m+1)
	if err != nil || r1 == nil {
		t.Fatalf("round m+1: %v %v", r1, err)
	}
	sorted := append([][]byte(nil), raw...)
	sort.Slice(sorted, func(i, j int) bool { return string(sorted[i]) < string(sorted[j]) })
	h := sha256.New()
	for _, x := range sorted {
		h.Write(x)
	}
	if hex.EncodeToString(r1.Mix) != hex.EncodeToString(h.Sum(nil)) {
		t.Fatalf("mix is not sha256 of the sorted contributions")
	}
	if r1.NMix != len(raw) {
		t.Fatalf("n_mix = %d, want %d (duplicate must collapse)", r1.NMix, len(raw))
	}
}

func TestRand1Verifies(t *testing.T) {
	reset(t)
	ctx := context.Background()
	m := minute(time.Now())
	if _, err := Advance(ctx, testPool, []byte(secret), atMinute(m)); err != nil {
		t.Fatal(err)
	}
	rd, err := loadRound(ctx, testPool, m)
	if err != nil || rd == nil {
		t.Fatalf("round: %v %v", rd, err)
	}
	rd.CNext = commit(seed(seedKey([]byte(secret)), m+1))
	s, err := sign.New(core.Config{ServerSecret: []byte(secret)})
	if err != nil {
		t.Fatal(err)
	}
	kid, ok := s.Verify(TypeRand, rd.Line(), rd.Sig)
	if !ok {
		t.Fatalf("signature does not verify: %s / %s", rd.Line(), rd.Sig)
	}
	if kid != s.KID() {
		t.Fatalf("kid = %d, want %d", kid, s.KID())
	}
}

// recomputePick is an independent re-implementation of the published recipe, standing in for a
// second agent recomputing a pick from the revealed r_t alone.
func recomputePick(r []byte, n, of int, salt string) []int {
	info := append(append([]byte("pick"), 0), salt...)
	ctr := uint32(0)
	var buf []byte
	pos := 0
	next := func() byte {
		if pos >= len(buf) {
			mac := hmac.New(sha256.New, r)
			var c [4]byte
			c[0] = byte(ctr >> 24)
			c[1] = byte(ctr >> 16)
			c[2] = byte(ctr >> 8)
			c[3] = byte(ctr)
			mac.Write(info)
			mac.Write(c[:])
			buf = mac.Sum(nil)
			pos = 0
			ctr++
		}
		b := buf[pos]
		pos++
		return b
	}
	word := func() uint32 {
		return uint32(next())<<24 | uint32(next())<<16 | uint32(next())<<8 | uint32(next())
	}
	uni := func(bound uint32) uint32 {
		if bound <= 1 {
			return 0
		}
		limit := uint32((uint64(1) << 32) - (uint64(1)<<32)%uint64(bound))
		for {
			v := word()
			if v < limit {
				return v % bound
			}
		}
	}
	a := make([]int, of)
	for i := range a {
		a[i] = i
	}
	for i := 0; i < n; i++ {
		j := i + int(uni(uint32(of-i)))
		a[i], a[j] = a[j], a[i]
	}
	return a[:n]
}

func TestPickDeterministic(t *testing.T) {
	reset(t)
	ctx := context.Background()
	m := minute(time.Now())
	if _, err := Advance(ctx, testPool, []byte(secret), atMinute(m)); err != nil {
		t.Fatal(err)
	}
	rd, err := loadRound(ctx, testPool, m)
	if err != nil || rd == nil {
		t.Fatalf("round: %v %v", rd, err)
	}
	a := pick(rd.R, 3, 12, "task-42")
	b := pick(rd.R, 3, 12, "task-42")
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatalf("pick not deterministic: %v vs %v", a, b)
	}
	// A second agent recomputes the same indices from r_t and the recipe alone.
	if fmt.Sprint(a) != fmt.Sprint(recomputePick(rd.R, 3, 12, "task-42")) {
		t.Fatalf("independent recompute differs: %v vs %v", a, recomputePick(rd.R, 3, 12, "task-42"))
	}
	// A different salt yields a different draw (overwhelmingly).
	if fmt.Sprint(a) == fmt.Sprint(pick(rd.R, 3, 12, "task-43")) {
		t.Fatalf("salt did not change the pick")
	}
	// The HTTP endpoint returns the same indices, so two agents hitting /pick agree.
	e := newEnv(t)
	ts := fmt.Sprint(m)
	st, body := e.do(t, "GET", "/rand/"+ts+"/pick?n=3&of=12&salt=task-42", "", "")
	if st != 200 {
		t.Fatalf("pick endpoint: %d %s", st, body)
	}
	want := indicesCSV(a)
	if !strings.Contains(body, "=> "+want) {
		t.Fatalf("endpoint indices %q missing from %q", want, body)
	}
}

func indicesCSV(a []int) string {
	parts := make([]string, len(a))
	for i, v := range a {
		parts[i] = fmt.Sprint(v)
	}
	return strings.Join(parts, ",")
}

var pendingRe = regexp.MustCompile(`pending c=([0-9a-f]{64})`)

func TestPendingFutureRound(t *testing.T) {
	reset(t)
	e := newEnv(t)
	future := minute(time.Now()) + 30
	ts := fmt.Sprint(future)
	st, body := e.do(t, "GET", "/rand/"+ts, "", "")
	if st != 200 {
		t.Fatalf("future round: %d %s", st, body)
	}
	mm := pendingRe.FindStringSubmatch(body)
	if mm == nil {
		t.Fatalf("no pending commitment in %q", body)
	}
	want := hex.EncodeToString(commit(seed(seedKey([]byte(secret)), future)))
	if mm[1] != want {
		t.Fatalf("pending commitment %s, want %s", mm[1], want)
	}
	// A /pick on a future round is refused (nothing revealed yet).
	st, _ = e.do(t, "GET", "/rand/"+ts+"/pick?n=1&of=2&salt=x", "", "")
	if st != 409 {
		t.Fatalf("pick on future round: %d, want 409", st)
	}
}

func TestContributionRate(t *testing.T) {
	reset(t)
	e := newEnv(t)
	id, token := newRoot(t, e.ip)
	_ = id
	for i := 0; i < MixPerMin; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("entropy-%d", i)))
		st, body := e.do(t, "POST", "/v1/rand/mix", token, fmt.Sprintf(`{"h":%q}`, hex.EncodeToString(h[:])))
		if st != 201 {
			t.Fatalf("mix %d: %d %s", i, st, body)
		}
	}
	h := sha256.Sum256([]byte("entropy-over"))
	st, body := e.do(t, "POST", "/v1/rand/mix", token, fmt.Sprintf(`{"h":%q}`, hex.EncodeToString(h[:])))
	if st != 429 {
		t.Fatalf("over-limit mix: %d %s, want 429", st, body)
	}
}

func newRoot(t *testing.T, ip string) (id, token string) {
	t.Helper()
	id, token, err := core.CreateRoot(context.Background(), testPool, "randb-test", ip)
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

func TestNotaryStampDaily(t *testing.T) {
	reset(t)
	ctx := context.Background()
	now := time.Now().UTC()
	y, mo, d := now.Date()
	today := time.Date(y, mo, d, 0, 0, 0, 0, time.UTC)
	yest := today.AddDate(0, 0, -1)
	lo := yest.Unix() / 60
	// Write a few rounds for yesterday with known r values.
	h := sha256.New()
	for i := int64(0); i < 4; i++ {
		s := seed(seedKey([]byte(secret)), lo+i)
		r := beacon(s, []byte{})
		if _, err := testPool.Exec(ctx, `INSERT INTO rand_rounds (t, s, mix, r, n_mix, sig) VALUES ($1,$2,$3,$4,0,'sig=x')`,
			lo+i, s, []byte{}, r); err != nil {
			t.Fatal(err)
		}
		h.Write(r)
	}
	want := h.Sum(nil)
	if err := stampDays(ctx, testPool, now); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM ts WHERE h = $1`, want).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("day rounds hash not stamped into notary (ts rows = %d)", n)
	}
	// Idempotent: a second pass does not create a duplicate.
	if err := stampDays(ctx, testPool, now); err != nil {
		t.Fatal(err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM ts WHERE h = $1`, want).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("re-stamp created a duplicate (ts rows = %d)", n)
	}
}
