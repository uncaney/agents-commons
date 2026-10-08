package svcget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
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
		if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("svcget", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping svcget DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type env struct {
	t   *testing.T
	d   *core.Deps
	srv *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://t.example"}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	return &env{t: t, d: d, srv: srv}
}

func (e *env) get(path string) (int, string, http.Header) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

func (e *env) getIP(path, ip string) (int, string, http.Header) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Header.Set("CF-Connecting-IP", ip)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

func shaHex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// minWasm is a valid core module exporting an empty _start; tag lands in a custom section so each
// service gets a distinct wasm hash.
func minWasm(tag string) []byte {
	b := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0,
		3, 2, 1, 0,
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0,
		10, 4, 1, 2, 0, 0x0b}
	sec := append([]byte{0}, byte(len("t")+1+len(tag)))
	sec = append(sec, byte(len("t")), 't')
	sec = append(sec, tag...)
	return append(b, sec...)
}

// mkSvc inserts a verified stable service with the given manifest and returns its wasm hash. When
// storeWasm, the wasm module is also written to the blob store (precompute needs a runnable module).
func (e *env) mkSvc(name, manifest string, storeWasm bool) string {
	e.t.Helper()
	ctx := context.Background()
	mod := minWasm(name)
	var wasm string
	if storeWasm {
		h, err := compute.PutBlobBytes(ctx, e.d, core.SystemID, mod, "")
		if err != nil {
			e.t.Fatal(err)
		}
		wasm = h
	} else {
		wasm = shaHex(string(mod))
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO services (name, owner_root, stable_ver) VALUES ($1, 'aowner', 1)
		ON CONFLICT (name) DO UPDATE SET stable_ver = 1`, name); err != nil {
		e.t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO service_versions (name, ver, wasm, size, manifest, state, verified_at)
		VALUES ($1, 1, $2, $3, $4::jsonb, 'verified', now())
		ON CONFLICT (name, ver) DO UPDATE SET wasm = EXCLUDED.wasm, manifest = EXCLUDED.manifest, state = 'verified'`,
		name, wasm, len(mod), manifest); err != nil {
		e.t.Fatal(err)
	}
	return wasm
}

// seedGlobal inserts a global, attested, done cache row for (wasm, sha(in), fs, mb) with out holding
// outText, so a GET is a cache hit.
func (e *env) seedGlobal(wasm, in, out string, mb int) {
	e.t.Helper()
	ctx := context.Background()
	outHash, err := compute.PutBlobBytes(ctx, e.d, core.SystemID, []byte(out), "")
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO jobs (id, submitter, root, wasm, input, fs, ms, mb, status, reason, out, used_ms, att_d, cache_scope, finished_at)
		VALUES ($1, $2, $2, $3, $4, '', 10000, $5, 'done', '', $6, 5, true, 'global', now())`,
		core.NewID('j'), core.SystemID, wasm, shaHex(in), mb, outHash); err != nil {
		e.t.Fatal(err)
	}
}

func TestGlobalHitServed(t *testing.T) {
	e := newEnv(t)
	wasm := e.mkSvc("cx-semver", `{}`, false)
	e.seedGlobal(wasm, "compare 1.2.0 1.10.0", "-1", 64)

	st, body, hdr := e.get("/svc/cx-semver/compare%201.2.0%201.10.0")
	if st != 200 || body != "-1" {
		t.Fatalf("hit: %d %q", st, body)
	}
	if cc := hdr.Get("Cache-Control"); cc != "public, max-age=3600" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	if l := hdr.Get("Link"); !strings.Contains(l, `</svc/cx-semver>; rel="describedby"`) {
		t.Fatalf("Link = %q", l)
	}
	// ?v=2 prepends the head line; ?raw=1 keeps stdout only.
	if _, body, _ := e.get("/svc/cx-semver/compare%201.2.0%201.10.0?v=2"); !strings.HasPrefix(body, "cx-semver done out=") || !strings.HasSuffix(body, "-1") {
		t.Fatalf("v=2 body = %q", body)
	}
	if _, body, _ := e.get("/svc/cx-semver/compare%201.2.0%201.10.0?v=2&raw=1"); body != "-1" {
		t.Fatalf("raw body = %q", body)
	}
}

func TestMissIs402AndRecorded(t *testing.T) {
	e := newEnv(t)
	e.mkSvc("cx-up", `{}`, false)

	st, body, hdr := e.get("/svc/cx-up/hello%20world")
	if st != http.StatusPaymentRequired {
		t.Fatalf("miss status = %d (%s)", st, body)
	}
	for _, want := range []string{"POST /v1/svc/cx-up", "join at /join.py", "no cached result"} {
		if !strings.Contains(body, want) {
			t.Fatalf("miss body missing %q: %s", want, body)
		}
	}
	if l := hdr.Get("Link"); !strings.Contains(l, "rel=\"describedby\"") {
		t.Fatalf("miss Link = %q", l)
	}
	ctx := context.Background()
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM wanted WHERE kind = 'svc'`).Scan(&n); err != nil || n == 0 {
		t.Fatalf("demand not recorded: n=%d err=%v", n, err)
	}
	// The input was stored (by its sha) so a later system precompute can reference it by hash.
	var blobs int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM blobs WHERE hash = $1`, shaHex("hello world")).Scan(&blobs); err != nil || blobs != 1 {
		t.Fatalf("input blob not stored: %d err=%v", blobs, err)
	}
}

func TestNoComputeFromGet(t *testing.T) {
	e := newEnv(t)
	e.mkSvc("cx-nc", `{}`, false)
	for i := 0; i < 5; i++ {
		if st, _, _ := e.getIP(fmt.Sprintf("/svc/cx-nc/same%%20input"), fmt.Sprintf("198.51.100.%d", i+1)); st != http.StatusPaymentRequired {
			t.Fatalf("get %d: %d", i, st)
		}
	}
	// No job was ever created for this input: an anonymous GET never computes.
	var jobs int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE input = $1`, shaHex("same input")).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("anonymous GET created %d job(s)", jobs)
	}
}

func TestInputCapsAndScrub(t *testing.T) {
	e := newEnv(t)
	e.mkSvc("cx-caps", `{}`, false)
	e.mkSvc("cx-json", `{"abi":"json","get_ok":false}`, false)

	// Over 2 KiB -> 413.
	big := strings.Repeat("a", 2100)
	if st, body, _ := e.get("/svc/cx-caps/" + big); st != 413 {
		t.Fatalf("oversized input: %d %s", st, body)
	}
	// Secret-looking input -> 400 err scrub.
	secret := "sk-ant-api03-ZzYyXxWw0011223344556677abcd"
	if st, body, _ := e.get("/svc/cx-caps/" + secret); st != 400 || !strings.Contains(body, "scrub") {
		t.Fatalf("secret input: %d %s", st, body)
	}
	// A service that opts out of GET reads (get_ok:false) is refused.
	if st, body, _ := e.get("/svc/cx-json/x"); st != 400 || !strings.Contains(body, "GET-readable") {
		t.Fatalf("get_ok=false: %d %s", st, body)
	}
	// Unknown service -> 404.
	if st, _, _ := e.get("/svc/cx-nope/x"); st != 404 {
		t.Fatalf("unknown service: %d", st)
	}
}

func TestPrecomputeThresholdAndCap(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Fund the system faucet so precompute submits can reserve (the row is seeded by migrations).
	if _, err := testPool.Exec(ctx, `UPDATE identities SET credits = 1000000 WHERE id = $1`, core.SystemID); err != nil {
		t.Fatal(err)
	}
	e.mkSvc("cx-pc", `{}`, true)

	// Three eligible inputs (each missed by >= 3 distinct super-groups) and one below threshold.
	eligible := []string{"in-a", "in-b", "in-c"}
	for _, in := range eligible {
		e.recordMiss(t, "cx-pc", in, 3)
	}
	e.recordMiss(t, "cx-pc", "in-weak", 2) // only 2 super-groups: not precomputed

	defer func(old int) { precomputeCap = old }(precomputeCap)
	precomputeCap = 2 // cap below the 3 eligible

	s := &svc{d: e.d}
	if err := s.precompute(ctx); err != nil {
		t.Fatalf("precompute: %v", err)
	}

	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE root = $1 AND svc = 'cx-pc@1'`, core.SystemID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("cap not honoured: %d system jobs (want 2)", n)
	}
	// The below-threshold input was never submitted.
	var weak int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE input = $1`, shaHex("in-weak")).Scan(&weak); err != nil {
		t.Fatal(err)
	}
	if weak != 0 {
		t.Fatalf("below-threshold input precomputed: %d", weak)
	}
	// A second run under the cap submits nothing new (cap reached) and does not duplicate in-flight.
	if err := s.precompute(ctx); err != nil {
		t.Fatalf("precompute 2: %v", err)
	}
	var n2 int
	testPool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE root = $1 AND svc = 'cx-pc@1'`, core.SystemID).Scan(&n2)
	if n2 != 2 {
		t.Fatalf("second run changed count: %d", n2)
	}
}

// recordMiss drives svcget's own miss path (which stores the input blob and records demand) from
// `groups` distinct client super-groups, so the demand row crosses the precompute threshold.
func (e *env) recordMiss(t *testing.T, name, in string, groups int) {
	t.Helper()
	for i := 0; i < groups; i++ {
		ip := fmt.Sprintf("10.%d.%d.1", i+1, i+1)
		if st, _, _ := e.getIP("/svc/"+name+"/"+in, ip); st != http.StatusPaymentRequired {
			t.Fatalf("recordMiss %s/%s: %d", name, in, st)
		}
	}
}
