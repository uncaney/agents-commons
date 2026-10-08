package cachens

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/cache"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
)

var (
	pool   *pgxpool.Pool
	levels sync.Map // root -> level, read by the core.LevelFn stub
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		p, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, p); err != nil {
			panic(err)
		}
		pool, cleanup = p, p.Close
	} else if p, done := testdb.Open("cachens", core.Migrate); p != nil {
		pool, cleanup = p, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping cachens DB tests")
		os.Exit(0)
	}
	core.LevelFn = func(ctx context.Context, q core.Q, root string) int {
		v, _ := levels.Load(root)
		n, _ := v.(int)
		return n
	}
	cache.CanonFn = Canon // the integration package wires this in production (27.3)
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type env struct {
	d   *core.Deps
	srv *httptest.Server
	ops map[string]Op
}

func newEnv(t *testing.T) *env {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `TRUNCATE cache_ns, cache, identities RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &env{d: d, srv: srv, ops: Ops(d)}
}

func (e *env) do(t *testing.T, method, path, token string, body ...string) (int, string) {
	t.Helper()
	var rd io.Reader
	if len(body) > 0 && body[0] != "" {
		rd = strings.NewReader(body[0])
	}
	r, _ := http.NewRequest(method, e.srv.URL+path, rd)
	r.Header.Set("CF-Connecting-IP", "10.1.2.3")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func mkRoot(t *testing.T, lvl int) (*core.Ident, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := pool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, rep, reg_ip)
		VALUES ($1, 'r', NULL, $1, $2, 100, 20, '10.9.9.9')`, id, h); err != nil {
		t.Fatal(err)
	}
	levels.Store(id, lvl)
	return &core.Ident{ID: id, Name: "r", Root: id, Credits: 100, Rep: 20, Created: time.Now(), Class: "full"}, tok
}

func putRecipe(t *testing.T, e *env, tok, ns string, req putReq) (int, string) {
	t.Helper()
	b, _ := json.Marshal(req)
	return e.do(t, http.MethodPut, "/v1/cns/"+ns, tok, string(b))
}

func keyOf(t *testing.T, e *env, ns, in string) string {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"ns": ns, "in": in})
	st, body := e.do(t, http.MethodPost, "/v1/c/key", "", string(b))
	if st != 200 {
		t.Fatalf("ckey status %d: %s", st, body)
	}
	for _, f := range strings.Fields(body) {
		if len(f) == 64 {
			return f
		}
	}
	// head is "key <sha256> ns=..."
	line := strings.SplitN(body, "\n", 2)[0]
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		return parts[1]
	}
	t.Fatalf("no key in %q", body)
	return ""
}

// --- TestRecipeValidationRE2Only -------------------------------------------------------------------

func TestRecipeValidationRE2Only(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t, 2)

	// A valid RE2 recipe is accepted and compiled.
	st, body := putRecipe(t, e, tok, "re2-ok", putReq{Rules: []rule{{Re: `\d+`, To: "<n>"}}, StripHex: true})
	if st != 200 || !strings.Contains(body, "cns re2-ok@1") {
		t.Fatalf("valid recipe rejected: %d %s", st, body)
	}

	// A backreference (PCRE, not RE2) does not compile under Go's regexp: rejected.
	st, body = putRecipe(t, e, tok, "re2-bad", putReq{Rules: []rule{{Re: `(a)\1`, To: "x"}}})
	if st != 400 {
		t.Fatalf("backreference recipe: want 400, got %d %s", st, body)
	}

	// Lookahead is also not RE2: rejected.
	st, _ = putRecipe(t, e, tok, "re2-la", putReq{Rules: []rule{{Re: `foo(?=bar)`, To: "x"}}})
	if st != 400 {
		t.Fatalf("lookahead recipe: want 400, got %d", st)
	}

	// Over-long pattern, replacement, and too many rules are rejected.
	st, _ = putRecipe(t, e, tok, "re2-long", putReq{Rules: []rule{{Re: strings.Repeat("a", MaxRe+1), To: "x"}}})
	if st != 400 {
		t.Fatalf("over-long re: want 400, got %d", st)
	}
	st, _ = putRecipe(t, e, tok, "re2-to", putReq{Rules: []rule{{Re: "a", To: strings.Repeat("x", MaxTo+1)}}})
	if st != 400 {
		t.Fatalf("over-long to: want 400, got %d", st)
	}
	many := make([]rule, MaxRules+1)
	for i := range many {
		many[i] = rule{Re: "a", To: "b"}
	}
	st, _ = putRecipe(t, e, tok, "re2-many", putReq{Rules: many})
	if st != 400 {
		t.Fatalf("too many rules: want 400, got %d", st)
	}
}

// --- TestVersionBumpKeepsOldKeys -------------------------------------------------------------------

func TestVersionBumpKeepsOldKeys(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t, 2)
	const in = "hello 123 world"

	st, body := putRecipe(t, e, tok, "bump", putReq{})
	if st != 200 || !strings.Contains(body, "cns bump@1") {
		t.Fatalf("create: %d %s", st, body)
	}
	k1 := keyOf(t, e, "bump", in)

	// An identical submission is idempotent: no version bump.
	st, body = putRecipe(t, e, tok, "bump", putReq{})
	if st != 200 || !strings.Contains(body, "cns bump@1") {
		t.Fatalf("idempotent re-put bumped version: %d %s", st, body)
	}
	if keyOf(t, e, "bump", in) != k1 {
		t.Fatal("key changed without a recipe change")
	}

	// A real change bumps to v2: the same input now derives a different key, but the old key is
	// still reachable (the old version is embedded in the key, not looked up).
	st, body = putRecipe(t, e, tok, "bump", putReq{StripHex: true, Rules: []rule{{Re: `\d+`, To: "<n>"}}})
	if st != 200 || !strings.Contains(body, "cns bump@2") {
		t.Fatalf("change did not bump: %d %s", st, body)
	}
	k2 := keyOf(t, e, "bump", in)
	if k2 == k1 {
		t.Fatal("version bump did not change the derived key")
	}
	// The old key is independent of the current recipe: recomputing it from the stored version
	// still yields k1 (rows under @1 stay reachable).
	if got := cache.Key("bump", cache.Canonical(in), 1); got != k1 {
		t.Fatalf("old-version key not reproducible: %s vs %s", got, k1)
	}
}

// --- TestCanonBuiltins -----------------------------------------------------------------------------

func TestCanonBuiltins(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t, 2)
	if st, body := putRecipe(t, e, tok, "builtins", putReq{
		StripTS: true, StripHex: true, StripPaths: true, StripLines: true, Lower: true,
	}); st != 200 {
		t.Fatalf("put: %d %s", st, body)
	}

	cases := []struct{ in, want string }{
		{"Error at 2026-10-07T12:00:00Z", "error at <ts>"},
		{"id=DEADBEEF1234 failed", "id=<hex> failed"},
		{"open /Users/dev/app/main.go", "open ~/app/main.go"},
		{"main.go:12:5: boom", "main.go:n: boom"},
	}
	for _, c := range cases {
		got, v := Canon("builtins", c.in)
		if v != 1 {
			t.Fatalf("Canon(%q) version=%d, want 1", c.in, v)
		}
		if got != c.want {
			t.Fatalf("Canon(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// An undeclared namespace falls back to the default NFC/LF/trim at v=0.
	got, v := Canon("never-declared", "  Hello\r\nWorld  ")
	if v != 0 || got != "Hello\nWorld" {
		t.Fatalf("default canon = %q v=%d", got, v)
	}
}

// --- TestKeyRoutePure (POST /v1/c/key stores nothing) ----------------------------------------------

func TestKeyRoutePure(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t, 2)
	if st, _ := putRecipe(t, e, tok, "pure", putReq{StripHex: true, StripTS: true}); st != 200 {
		t.Fatal("put recipe")
	}

	before := count(t, `SELECT count(*) FROM cache`)
	k := keyOf(t, e, "pure", "run 2026-10-07T00:00:00Z abc123def456")
	if len(k) != 64 {
		t.Fatalf("bad key %q", k)
	}
	if n := count(t, `SELECT count(*) FROM cache`); n != before {
		t.Fatalf("ckey wrote %d cache rows", n-before)
	}
	// The key equals the server-side derivation of the canonicalised input.
	canon, v := Canon("pure", "run 2026-10-07T00:00:00Z abc123def456")
	if cache.Key("pure", canon, v) != k {
		t.Fatal("ckey disagrees with Canon+Key")
	}
	// Bad ns and empty canonical input are 400s.
	if st, _ := e.do(t, http.MethodPost, "/v1/c/key", "", `{"ns":"BAD NS","in":"x"}`); st != 400 {
		t.Fatalf("bad ns: want 400, got %d", st)
	}
	if st, _ := e.do(t, http.MethodPost, "/v1/c/key", "", `{"ns":"pure","in":"   "}`); st != 400 {
		t.Fatalf("empty canonical: want 400, got %d", st)
	}
}

// --- TestNearMissVisibilityRules -------------------------------------------------------------------

func TestNearMissVisibilityRules(t *testing.T) {
	e := newEnv(t)
	owner, tok := mkRoot(t, 2)
	if st, _ := putRecipe(t, e, tok, "nearns", putReq{}); st != 200 {
		t.Fatal("put recipe")
	}

	// Rows sharing a very similar preview: an L2 inline row (public), an L1 inline row
	// (point-to-point, anon-invisible) and an L2 blob row (needs a token).
	insertRow(t, "nearns", "k2inline", 2, "", "connection timeout to database host prod-01", "L2 BODY")
	insertRow(t, "nearns", "k1inline", 1, "", "connection timeout to database host prod-02", "L1 BODY")
	insertRow(t, "nearns", "k2blob", 2, "blobhash", "connection timeout to database host prod-03", "")

	in := "connection timeout to database host prod-09"
	k2inline, k1inline, k2blob := cache64("k2inline"), cache64("k1inline"), cache64("k2blob")

	// Anonymous: only the public L2 inline row, and never the body.
	st, body := e.do(t, http.MethodGet, "/v1/c/near?ns=nearns&in="+urlq(in), "")
	if st != 200 {
		t.Fatalf("anon near: %d %s", st, body)
	}
	if !strings.Contains(body, k2inline) {
		t.Fatalf("anon near missing public row:\n%s", body)
	}
	if strings.Contains(body, k1inline) || strings.Contains(body, k2blob) {
		t.Fatalf("anon near leaked a non-public row:\n%s", body)
	}
	if strings.Contains(body, "BODY") {
		t.Fatalf("near leaked a body:\n%s", body)
	}
	if !strings.Contains(body, "sim=") || !strings.Contains(body, "lvl=L2") {
		t.Fatalf("near line malformed:\n%s", body)
	}

	// Token caller: every live row in the namespace, still previews only.
	st, body = e.do(t, http.MethodGet, "/v1/c/near?ns=nearns&in="+urlq(in), tok)
	if st != 200 {
		t.Fatalf("auth near: %d %s", st, body)
	}
	if !strings.Contains(body, k2inline) || !strings.Contains(body, k1inline) || !strings.Contains(body, k2blob) {
		t.Fatalf("auth near missing a row:\n%s", body)
	}
	if strings.Contains(body, "BODY") {
		t.Fatalf("auth near leaked a body:\n%s", body)
	}
	_ = owner

	// A dissimilar input returns no near lines (threshold > 0.55).
	st, body = e.do(t, http.MethodGet, "/v1/c/near?ns=nearns&in="+urlq("something entirely unrelated xyzzy"), tok)
	if st != 200 || strings.Contains(body, "\nnear ") {
		t.Fatalf("dissimilar input returned near lines:\n%s", body)
	}

	// A hidden row is never returned.
	insertRow(t, "nearns", "k2hidden", 2, "", "connection timeout to database host prod-77", "H")
	if _, err := pool.Exec(context.Background(), `UPDATE cache SET hidden = true, hidden_at = now() WHERE key = $1`, cache64("k2hidden")); err != nil {
		t.Fatal(err)
	}
	_, body = e.do(t, http.MethodGet, "/v1/c/near?ns=nearns&in="+urlq(in), tok)
	if strings.Contains(body, cache64("k2hidden")) {
		t.Fatalf("hidden row returned:\n%s", body)
	}
}

// --- TestL2OwnerOnly -------------------------------------------------------------------------------

func TestL2OwnerOnly(t *testing.T) {
	e := newEnv(t)

	// L1 cannot declare a namespace.
	_, l1 := mkRoot(t, 1)
	if st, body := putRecipe(t, e, l1, "l1ns", putReq{}); st != 403 {
		t.Fatalf("L1 declare: want 403, got %d %s", st, body)
	}

	// L2 can.
	owner, l2 := mkRoot(t, 2)
	if st, body := putRecipe(t, e, l2, "ownedns", putReq{StripHex: true}); st != 200 {
		t.Fatalf("L2 declare: %d %s", st, body)
	}

	// Another L2 root cannot overwrite a namespace it does not own.
	_, other := mkRoot(t, 2)
	if st, body := putRecipe(t, e, other, "ownedns", putReq{Lower: true}); st != 409 {
		t.Fatalf("non-owner overwrite: want 409, got %d %s", st, body)
	}

	// The owner can update its own namespace.
	if st, _ := putRecipe(t, e, l2, "ownedns", putReq{StripHex: true, Lower: true}); st != 200 {
		t.Fatal("owner update rejected")
	}

	// The live cap is enforced: 5 namespaces per root (cache_ns L2 column), the 6th is a quota.
	for i := 0; i < 4; i++ { // already owns ownedns -> 1; add 4 more = 5
		if st, body := putRecipe(t, e, l2, fmt.Sprintf("own%d", i), putReq{}); st != 200 {
			t.Fatalf("cap fill %d: %d %s", i, st, body)
		}
	}
	if st, body := putRecipe(t, e, l2, "own-over", putReq{}); st != 429 {
		t.Fatalf("6th namespace: want 429, got %d %s", st, body)
	}

	// After purge, the owner is cleared but the row (and its version) survive, so old keys stay
	// reachable and a slot is freed.
	if err := purge(context.Background(), pool, owner.ID); err != nil {
		t.Fatal(err)
	}
	var ownerRoot string
	var v int
	if err := pool.QueryRow(context.Background(), `SELECT owner_root, v FROM cache_ns WHERE ns = 'ownedns'`).Scan(&ownerRoot, &v); err != nil {
		t.Fatal(err)
	}
	if ownerRoot != "" {
		t.Fatalf("purge left owner_root = %q", ownerRoot)
	}
	if v < 1 {
		t.Fatalf("purge dropped the version (%d)", v)
	}
}

// --- TestTimestampHexSameKey (acceptance: two inputs differing only by a timestamp and a hex id) ---

func TestTimestampHexSameKey(t *testing.T) {
	e := newEnv(t)
	_, tok := mkRoot(t, 2)
	if st, body := putRecipe(t, e, tok, "build-errors", putReq{StripHex: true, StripTS: true}); st != 200 {
		t.Fatalf("put: %d %s", st, body)
	}
	a := "build failed at 2026-10-07T12:00:00Z ref=deadbeef1234cafe"
	b := "build failed at 2026-10-06T08:30:00Z ref=0123456789abcdef"
	ka := keyOf(t, e, "build-errors", a)
	kb := keyOf(t, e, "build-errors", b)
	if ka != kb {
		t.Fatalf("timestamp+hex-only difference produced different keys:\n%s\n%s", ka, kb)
	}
}

// --- helpers ---------------------------------------------------------------------------------------

func count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// cache64 maps a short label to a deterministic 64-hex cache key.
func cache64(label string) string {
	h := sha256.Sum256([]byte(label))
	return hex.EncodeToString(h[:])
}

// insertRow inserts a cache row directly (near-miss tests need rows with a preview, independent of
// the cput write path).
func insertRow(t *testing.T, ns, label string, lvl int, blob, prev, body string) {
	t.Helper()
	var blobP any
	if blob != "" {
		blobP = cache64(blob)
	}
	_, err := pool.Exec(context.Background(), `INSERT INTO cache
		(key, ns, out, blob, attest, producer, producer_root, producer_lvl, cost_tokens, in_preview, expires_at)
		VALUES ($1, $2, $3, $4, 'claim', 'aprod00', 'aprod00', $5, 7, $6, now() + interval '1 hour')`,
		cache64(label), ns, body, blobP, lvl, prev)
	if err != nil {
		t.Fatal(err)
	}
}

func urlq(s string) string {
	return strings.NewReplacer(" ", "%20", ":", "%3A", "/", "%2F", "=", "%3D").Replace(s)
}
