package know

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
)

var (
	testPool *pgxpool.Pool
	sysMail  sync.Map // root -> last subject (core.SysMailFn stub)
)

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
		// A reused database keeps the previous run's rows: start this package's tables clean.
		for _, sql := range []string{
			`TRUNCATE claims, claim_votes, digests, digest_votes, digest_diffs, wanted, wanted_grp, libs`,
			`DELETE FROM lib_alias WHERE NOT seeded`,
			`DELETE FROM egress_outbox WHERE kind = 'libmeta'`,
			`DELETE FROM forge_outbox WHERE kind IN ('claim', 'digest')`,
		} {
			if _, err := pool.Exec(ctx, sql); err != nil {
				panic(err)
			}
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("know", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping know DB tests")
		os.Exit(0)
	}
	core.LevelFn = trust.LevelOf
	core.RepLogger = trust.RecordRep
	core.SysMailFn = func(ctx context.Context, q core.Q, toRoot, subject, text string) error {
		sysMail.Store(toRoot, subject)
		return nil
	}
	// Anonymous writes: the X-PoW header carries "grp" directly (the real checker is auth's).
	core.XPoWFn = func(ctx context.Context, q core.Q, r *http.Request) (string, string, error) {
		h := r.Header.Get("X-PoW")
		if h == "" {
			return "", "", core.ErrPow
		}
		return core.IPGroup(h), core.IPSuper(h), nil
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
	ipBase = func() int64 {
		var b [1]byte
		rand.Read(b[:])
		return 16 + int64(b[0])%200
	}()
)

// nextIP hands every registration its own /24 so super-group collapse never merges two voters.
func nextIP() string {
	n := ipSeq.Add(1)
	return fmt.Sprintf("10.%d.%d.7", (ipBase+n/200)%256, 1+n%200)
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, srv: srv, ip: nextIP()}
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

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

func kv(body string) map[string]string {
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(body, -1) {
		m[x[1]] = x[2]
	}
	return m
}

// register creates a root from a fresh /24.
func (e *tenv) register(t *testing.T, name string) (id, tok string) {
	t.Helper()
	return e.registerIP(t, name, nextIP())
}

// registerIP creates a root registered from ip (reg_ip decides the super-group of its votes).
func (e *tenv) registerIP(t *testing.T, name, ip string) (id, tok string) {
	t.Helper()
	st, body, _ := e.do(t, "POST", "/v1/challenge", "", nil, "CF-Connecting-IP", ip)
	if st != 200 {
		t.Fatalf("challenge: %d %s", st, body)
	}
	m := kv(body)
	c, bits := m["c"], e.d.Cfg.PowBits
	if b, err := strconv.Atoi(m["bits"]); err == nil && b > 0 {
		bits = b
	}
	st, body, _ = e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, bits), "name": name}, "CF-Connecting-IP", ip)
	if st != 201 {
		t.Fatalf("register: %d %s", st, body)
	}
	m = kv(body)
	e.roots = append(e.roots, m["id"])
	return m["id"], m["token"]
}

// registerL registers a root and gives it standing level lvl (4.1 minimums).
func (e *tenv) registerL(t *testing.T, name string, lvl int) (id, tok string) {
	t.Helper()
	id, tok = e.register(t, name)
	setLevel(t, id, lvl)
	return id, tok
}

func setLevel(t *testing.T, root string, lvl int) {
	t.Helper()
	rep, days, vnc := 0, 0, 0
	switch lvl {
	case 1:
		rep, days = 1, 4
	case 2:
		rep, days, vnc = 5, 4, 1
	case 3:
		rep, days, vnc = 20, 31, 1
	}
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET rep = $2, created = now() - $3 * interval '1 day', verified_noncompute = $4 WHERE id = $1`, root, rep, days, vnc); err != nil {
		t.Fatal(err)
	}
}

func (e *tenv) ident(t *testing.T, tok string) *core.Ident {
	t.Helper()
	id, err := e.d.LookupToken(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func first(body string) string { return strings.SplitN(body, "\n", 2)[0] }

func lines(body string) []string {
	ls := strings.Split(body, "\n")
	if n := len(ls); n > 0 && strings.HasPrefix(ls[n-1], "next: ") {
		ls = ls[:n-1]
	}
	return ls
}

func queryInt(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func queryStr(t *testing.T, sql string, args ...any) string {
	t.Helper()
	var s string
	if err := testPool.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return s
}

// claim posts a claim as tok and returns its id.
func (e *tenv) claim(t *testing.T, tok string, in map[string]any) string {
	t.Helper()
	st, body, _ := e.do(t, "POST", "/v1/v", tok, in)
	if st != 201 {
		t.Fatalf("cv %v: %d %s", in, st, body)
	}
	f := strings.Fields(first(body))
	if len(f) < 3 || f[0] != "ok" || !core.ValidIDPrefix(f[1], 'v') {
		t.Fatalf("cv reply: %s", body)
	}
	return f[1]
}

func (e *tenv) vote(t *testing.T, tok, id string, up bool, body map[string]any) (int, string) {
	t.Helper()
	side := "ok"
	if !up {
		side = "bad"
	}
	var payload any
	if body != nil {
		payload = body
	}
	st, b, _ := e.do(t, "POST", "/v1/v/"+id+"/"+side, tok, payload)
	return st, b
}

func (e *tenv) mustVote(t *testing.T, tok, id string, up bool, body map[string]any) string {
	t.Helper()
	st, b := e.vote(t, tok, id, up, body)
	if st != 200 {
		t.Fatalf("vote %v on %s: %d %s", up, id, st, b)
	}
	return first(b)
}

// word returns the status word of a claim as GET /v1/v/{id}?all=1 renders it.
func (e *tenv) word(t *testing.T, id string) string {
	t.Helper()
	st, body, _ := e.do(t, "GET", "/v1/v/"+id+"?all=1", "", nil)
	if st != 200 {
		t.Fatalf("get %s: %d %s", id, st, body)
	}
	f := strings.Fields(first(body))
	return f[1]
}

// --- pure tests --------------------------------------------------------------------------------

func TestVKeyOrdering(t *testing.T) {
	order := []string{"0.9.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-rc.1", "1.0.0-rc.2", "1.0.0", "1.0.1", "1.2.0", "1.10.0", "2.0.0", "v2.0.1", "10.0.0"}
	keys := make([]string, len(order))
	for i, v := range order {
		keys[i] = VKey(v)
	}
	if !sort.StringsAreSorted(keys) {
		t.Fatalf("vkeys not ordered: %q", keys)
	}
	for i := 1; i < len(keys); i++ {
		if keys[i] == keys[i-1] {
			t.Fatalf("equal keys for %s and %s", order[i-1], order[i])
		}
	}
	if VKey("1.0") != VKey("1.0.0") || VKey("v1.0.0") != VKey("1.0.0") {
		t.Fatalf("padding: %q %q %q", VKey("1.0"), VKey("1.0.0"), VKey("v1.0.0"))
	}
	if VKey("1.0.0+build.7") != VKey("1.0.0") {
		t.Fatalf("build metadata must be ignored: %q", VKey("1.0.0+build.7"))
	}
	for _, bad := range []string{"", "latest", "main", "~1", "1.0 beta", "x.y"} {
		k := VKey(bad)
		if !strings.HasPrefix(k, "~") || Parseable(bad) {
			t.Fatalf("%q should be unparseable: %q", bad, k)
		}
		if k < VKey("999.0.0") {
			t.Fatalf("unparseable %q must sort last: %q", bad, k)
		}
	}
	// Go pseudo-versions and prereleases sort before their release.
	if VKey("v0.0.0-20240606120523-5a60cdf6a761") >= VKey("v0.0.0") || VKey("5.7.0-beta.1") >= VKey("5.7.0") {
		t.Fatal("prerelease must sort before release")
	}
	if from, to, ok := ParseRange("18..19"); !ok || from != "18" || to != "19" {
		t.Fatalf("range: %q %q %v", from, to, ok)
	}
	if _, _, ok := ParseRange("18..latest"); ok {
		t.Fatal("range with an unparseable end must be refused")
	}
}

func TestLibKeyAndAliasesAndPercentPaths(t *testing.T) {
	for in, want := range map[string]string{
		"npm:React": "npm:react", "PyPI:Requests": "pypi:requests", "pypi:Py_Yaml.Ext": "pypi:py-yaml-ext",
		"go:GitHub.com/jackc/pgx/v5": "go:github.com/jackc/pgx/v5", "npm:@Scope/Pkg": "npm:@scope/pkg", "docker:Postgres": "docker:postgres",
		"maven:org.X:Y": "maven:org.X:Y",
	} {
		got, err := ParseKey(in)
		if err != nil || got != want {
			t.Fatalf("ParseKey(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"react", "foo:bar", "npm:", "npm:a..b", "npm:/x", "go:github.com//x", "npm:a b", ""} {
		if _, err := ParseKey(bad); err == nil {
			t.Fatalf("ParseKey(%q) should fail", bad)
		}
	}
	key := "go:github.com/jackc/pgx/v5"
	if p := LibPath(key, "5.7"); p != "/v/go%3Agithub.com%2Fjackc%2Fpgx%2Fv5/5.7" {
		t.Fatalf("LibPath = %q", p)
	}
	if p := LibPath("npm:@scope/pkg", "18..19"); p != "/v/npm%3A%40scope%2Fpkg/18..19" {
		t.Fatalf("LibPath scoped = %q", p)
	}
	e := newEnv(t)
	ctx := context.Background()
	for alias, want := range map[string]string{"react": "npm:react", "requests": "pypi:requests", "pgx": "go:github.com/jackc/pgx/v5", "serde": "crates:serde", "postgres": "docker:postgres", "React": "npm:react"} {
		got, ok := ResolveLib(ctx, testPool, alias)
		if !ok || got != want {
			t.Fatalf("ResolveLib(%q) = %q %v; want %q", alias, got, ok, want)
		}
	}
	if _, ok := ResolveLib(ctx, testPool, "definitely-not-a-lib-xyz"); ok {
		t.Fatal("unknown alias must not resolve")
	}
	if n := queryInt(t, `SELECT count(*) FROM lib_alias WHERE seeded`); n < 300 {
		t.Fatalf("seeded aliases = %d, want >= 300", n)
	}
	// a new alias needs an L2 proposer; it never crosses ecosystems
	l0, _ := e.registerL(t, "alias-l0", 0)
	l2, _ := e.registerL(t, "alias-l2", 2)
	if err := ProposeAlias(ctx, testPool, "mycoollib", "npm:my-cool-lib", l0, 0); err != nil {
		t.Fatal(err)
	}
	if _, ok := ResolveLib(ctx, testPool, "mycoollib"); ok {
		t.Fatal("an L0 proposal must stay pending")
	}
	if err := ProposeAlias(ctx, testPool, "mycoollib", "npm:my-cool-lib", l2, 2); err != nil {
		t.Fatal(err)
	}
	if got, ok := ResolveLib(ctx, testPool, "mycoollib"); !ok || got != "npm:my-cool-lib" {
		t.Fatalf("alias after L2 confirmation: %q %v", got, ok)
	}
	if err := ProposeAlias(ctx, testPool, "mycoollib", "pypi:my-cool-lib", l2, 2); err == nil {
		t.Fatal("alias must never cross ecosystems")
	}
	if err := ProposeAlias(ctx, testPool, "react", "npm:preact", l2, 2); err == nil {
		t.Fatal("seeded alias must be immutable")
	}
	// percent-encoded keys in paths reach the handler decoded
	st, body, _ := e.do(t, "GET", "/v/go%3Agithub.com%2Fjackc%2Fpgx%2Fv5/5.7", "", nil)
	if st != 404 || !strings.Contains(body, "no entries yet; gap listed on /wanted") {
		t.Fatalf("unknown lib page: %d %s", st, body)
	}
	if n := queryInt(t, `SELECT count(*) FROM wanted WHERE kind = 'v' AND key = $1`, key+"@5.7"); n != 1 {
		t.Fatalf("miss not recorded: %d", n)
	}
	st, body, _ = e.do(t, "GET", "/v/react", "", nil)
	if st != 404 {
		t.Fatalf("alias hub without claims: %d %s", st, body)
	}
}

func TestOfficialSourcePathPrefix(t *testing.T) {
	m := &LibMeta{Key: "npm:react", Repo: "https://github.com/facebook/react.git", Homepage: "https://react.dev", Docs: "https://react.dev/reference"}
	cases := map[string]string{
		"https://gist.github.com/someone/abc123":                   "community",
		"https://github.com/facebook/react/releases/tag/v19.0.0":   "official",
		"https://github.com/facebook/react":                        "official",
		"https://GitHub.com/Facebook/React/blob/main/CHANGELOG.md": "official",
		"https://github.com/facebook/reactjs-fake/releases":        "community",
		"https://github.com/other/react/releases":                  "community",
		"https://www.npmjs.com/package/react":                      "official",
		"https://www.npmjs.com/package/react-dom":                  "community",
		"https://react.dev/blog/2024/12/05/react-19":               "official",
		"https://medium.com/@someone/react-19-is-here":             "community",
		"https://facebook.github.io/react/":                        "community",
		"https://stackoverflow.com/questions/1/react-19":           "community",
		"https://pypi.org/project/react/":                          "community",
		"":                                                         "community",
	}
	for src, want := range cases {
		if got := SourceTier("npm:react", src, m); got != want {
			t.Errorf("SourceTier(%q) = %s, want %s", src, got, want)
		}
	}
	// without a registry record the key alone yields the registry page and the forge of a go module
	if got := SourceTier("go:github.com/jackc/pgx/v5", "https://github.com/jackc/pgx/releases/tag/v5.7.0", nil); got != "official" {
		t.Fatalf("go forge prefix: %s", got)
	}
	if got := SourceTier("go:github.com/jackc/pgx/v5", "https://github.com/jackc/pgxmock/releases", nil); got != "community" {
		t.Fatalf("go forge sibling: %s", got)
	}
	if got := SourceTier("pypi:requests", "https://pypi.org/project/requests/2.32.0/", nil); got != "official" {
		t.Fatalf("pypi registry page: %s", got)
	}
	if got := SourceTier("pypi:requests", "https://pypi.org/project/requests-oauthlib/", nil); got != "community" {
		t.Fatalf("pypi sibling: %s", got)
	}
	// a shared docs host never becomes official through libs.docs
	if got := SourceTier("pypi:requests", "https://requests.readthedocs.io/en/latest/", &LibMeta{Docs: "https://requests.readthedocs.io"}); got != "community" {
		t.Fatalf("readthedocs must stay community: %s", got)
	}
	// URL hygiene
	if _, err := CleanSourceURL("https://user:pw@github.com/x/y"); err == nil {
		t.Fatal("userinfo must be refused")
	}
	for _, bad := range []string{"http://127.0.0.1/x", "http://localhost/x", "ftp://github.com/x", "http://[::1]/x", "http://intranet/x"} {
		if _, err := CleanSourceURL(bad); err == nil {
			t.Fatalf("%q must be refused", bad)
		}
	}
	got, err := CleanSourceURL("HTTPS://GitHub.com/facebook/react/releases?token=abc&tab=x&sig=1#frag")
	if err != nil || got != "https://github.com/facebook/react/releases?tab=x" {
		t.Fatalf("CleanSourceURL = %q %v", got, err)
	}
	// stored path: libs.repo decides src:official on the posted claim
	e := newEnv(t)
	_, tok := e.registerL(t, "src-author", 1)
	if _, err := testPool.Exec(context.Background(), `INSERT INTO libs (key, repo, fetched_at) VALUES ('npm:tierlib', 'https://github.com/tier/tierlib', now()) ON CONFLICT (key) DO UPDATE SET repo = EXCLUDED.repo`); err != nil {
		t.Fatal(err)
	}
	off := e.claim(t, tok, map[string]any{"lib": "npm:tierlib", "kind": "new", "v_to": "2.0.0", "title": "tierlib adds the official thing", "source_url": "https://github.com/tier/tierlib/releases/tag/v2.0.0"})
	com := e.claim(t, tok, map[string]any{"lib": "npm:tierlib", "kind": "new", "v_to": "2.1.0", "title": "tierlib gist says something else entirely", "source_url": "https://gist.github.com/tier/0123456789abcdef"})
	if s := queryStr(t, `SELECT source_tier FROM claims WHERE id = $1`, off); s != "official" {
		t.Fatalf("repo prefix claim tier = %s", s)
	}
	if s := queryStr(t, `SELECT source_tier FROM claims WHERE id = $1`, com); s != "community" {
		t.Fatalf("gist claim tier = %s", s)
	}
	st, body, _ := e.do(t, "GET", "/v1/v?lib=npm:tierlib", "", nil)
	if st != 200 || !strings.Contains(body, off+" unverified new npm:tierlib 2.0.0 tierlib adds the official thing src:official sev0") {
		t.Fatalf("list line: %d %s", st, body)
	}
}

func TestDigestDedupeAndBoundedDiff(t *testing.T) {
	a := "alpha\nbeta\ngamma\ndelta"
	b := "alpha\nbeta changed\ngamma\nepsilon\ndelta"
	diff, ok := LineDiff(a, b)
	if !ok {
		t.Fatal("small diff must be ok")
	}
	want := []string{" alpha", "-beta", "+beta changed", " gamma", "+epsilon", " delta"}
	if got := strings.Split(diff, "\n"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("diff = %q", got)
	}
	if d, ok := LineDiff(a, a); !ok || d != "" {
		t.Fatalf("identical bodies: %q %v", d, ok)
	}
	big := strings.Repeat("line\n", MaxDiffLines+1)
	if _, ok := LineDiff(big, a); ok {
		t.Fatal("more than 400 lines per side must be too different")
	}
	if _, ok := myers(strings.Split(strings.TrimSpace(strings.Repeat("x\n", 300)), "\n"), strings.Split(strings.TrimSpace(strings.Repeat("y\n", 300)), "\n"), 100); ok {
		t.Fatal("the D ceiling must refuse")
	}

	e := newEnv(t)
	_, tok := e.registerL(t, "dg-author", 1)
	_, tok2 := e.registerL(t, "dg-author2", 1)
	body1 := "## install\nnpm install dgtestlib@1.0.0\n## config\nset DGTEST_URL in the environment\nthe default port is 8080"
	st, out, _ := e.do(t, "POST", "/v1/dg", tok, map[string]any{"lib": "npm:dgtestlib", "topic": "setup", "v_to": "1.0.0", "body": body1})
	if st != 201 || !strings.HasPrefix(out, "ok d") || !strings.Contains(first(out), "tok="+strconv.Itoa((len(body1)+3)/4)) {
		t.Fatalf("dp: %d %s", st, out)
	}
	d1 := strings.Fields(out)[1]
	if st, out, _ = e.do(t, "POST", "/v1/dg", tok2, map[string]any{"lib": "npm:dgtestlib", "topic": "setup", "v_to": "1.0.0", "body": body1}); st != 409 || !strings.Contains(out, "err dup "+d1) {
		t.Fatalf("exact dup: %d %s", st, out)
	}
	near := body1 + "\nnothing else changed here"
	if st, out, _ = e.do(t, "POST", "/v1/dg", tok2, map[string]any{"lib": "npm:dgtestlib", "topic": "setup", "v_to": "1.0.0", "body": near}); st != 409 {
		t.Fatalf("trigram dup: %d %s", st, out)
	}
	body2 := "## install\nnpm install dgtestlib@2.0.0\n## config\nset DGTEST_DSN in the environment (DGTEST_URL was removed)\nthe default port is 9090\n## migration\nrun dgtestlib migrate once"
	st, out, _ = e.do(t, "POST", "/v1/dg", tok2, map[string]any{"lib": "npm:dgtestlib", "topic": "setup", "v_from": "1.0.0", "v_to": "2.0.0", "body": body2})
	if st != 201 {
		t.Fatalf("dp v2: %d %s", st, out)
	}
	st, out, _ = e.do(t, "GET", "/dg/npm%3Adgtestlib/1.0.0..2.0.0/setup", "", nil)
	if st != 200 || !strings.HasPrefix(out, "dg: npm:dgtestlib 1.0.0..2.0.0 setup diff lines=") || !strings.Contains(out, "-npm install dgtestlib@1.0.0") || !strings.Contains(out, "+npm install dgtestlib@2.0.0") {
		t.Fatalf("diff page: %d %s", st, out)
	}
	if n := queryInt(t, `SELECT count(*) FROM digest_diffs`); n < 1 {
		t.Fatal("diff must be cached in digest_diffs")
	}
	// too different: 401-line bodies
	huge := strings.TrimSpace(strings.Repeat("a line that is long enough to be distinct from the other\n", 401))
	if st, out, _ = e.do(t, "POST", "/v1/dg", tok, map[string]any{"lib": "npm:dgtestlib", "topic": "huge", "v_to": "1.0.0", "body": "x\ny"}); st != 201 {
		t.Fatalf("dp huge1: %d %s", st, out)
	}
	huge2 := strings.ReplaceAll(huge, "long", "wide")
	_ = huge2
	if len(huge) > MaxDigestBody {
		huge = strings.TrimSpace(strings.Repeat("l\n", 401))
	}
	if st, out, _ = e.do(t, "POST", "/v1/dg", tok2, map[string]any{"lib": "npm:dgtestlib", "topic": "huge", "v_to": "2.0.0", "body": huge}); st != 201 {
		t.Fatalf("dp huge2: %d %s", st, out)
	}
	if st, out, _ = e.do(t, "GET", "/dg/npm%3Adgtestlib/1.0.0..2.0.0/huge", "", nil); st != 200 || !strings.Contains(first(out), "too different") {
		t.Fatalf("too different: %d %s", st, out)
	}
	// best-first page and list
	if st, out, _ = e.do(t, "GET", "/dg/npm%3Adgtestlib/2.0.0/setup", "", nil); st != 200 || !strings.Contains(out, "body: ## install") {
		t.Fatalf("digest page: %d %s", st, out)
	}
	if st, out, _ = e.do(t, "GET", "/dg/npm%3Adgtestlib", "", nil); st != 200 || !strings.HasPrefix(out, "dg: npm:dgtestlib digests=") {
		t.Fatalf("digest list: %d %s", st, out)
	}
	if st, out, _ = e.do(t, "GET", "/v1/dg?lib=npm:dgtestlib&topic=setup&q=migrate", "", nil); st != 200 || !strings.Contains(out, " live npm:dgtestlib 1.0.0..2.0.0 setup tok=") {
		t.Fatalf("ds: %d %s", st, out)
	}
	// dgbad hides at bad_w >= ok_w + 2
	_, l2a := e.registerL(t, "dg-l2a", 2)
	_, l2b := e.registerL(t, "dg-l2b", 2)
	for _, tk := range []string{l2a, l2b} {
		if st, out, _ = e.do(t, "POST", "/v1/dg/"+d1+"/bad", tk, map[string]any{"why": "wrong port"}); st != 200 {
			t.Fatalf("dgbad: %d %s", st, out)
		}
	}
	if !strings.Contains(out, "hidden") {
		t.Fatalf("digest should be hidden after two L2 bads: %s", out)
	}
	if st, _, _ = e.do(t, "GET", "/v1/dg/"+d1, "", nil); st != 404 {
		t.Fatalf("hidden digest readable: %d", st)
	}
}
