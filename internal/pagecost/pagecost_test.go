package pagecost

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
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
	} else if pool, done := testdb.Open("pagecost", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping pagecost DB tests")
		os.Exit(0)
	}
	// Auth's seam, stubbed: "X-PoW: ok" is a valid proof; keys come from the request context.
	core.XPoWFn = func(ctx context.Context, q core.Q, r *http.Request) (string, string, error) {
		if r.Header.Get("X-PoW") != "ok" {
			return "", "", core.ErrPow
		}
		_, grp, sup := core.ClientFrom(ctx)
		return grp, sup, nil
	}
	CacheTTL = 0 // caching off: every test reads fresh numbers
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
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(),
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
	return &tenv{d: d, srv: srv, ip: randSuper() + ".10"}
}

// randSuper returns a fresh /24 prefix "10.<a>.<b>" (hosts are appended by the caller).
func randSuper() string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d", b[0], b[1])
}

// uniqueHost returns a fresh host under a fresh registrable domain.
func uniqueHost(t *testing.T) string {
	t.Helper()
	var b [4]byte
	rand.Read(b[:])
	return fmt.Sprintf("docs.h%x.com", b)
}

// do sends a request as e.ip (override with "CF-Connecting-IP" in hdr pairs).
func (e *tenv) do(t *testing.T, method, path, token, body string, hdr ...string) (int, string, http.Header) {
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
	return resp.StatusCode, string(b), resp.Header
}

// newRoot registers a fresh root from ip (its super-group is ip's /24).
func newRoot(t *testing.T, ip string) (id, token string) {
	t.Helper()
	id, token, err := core.CreateRoot(context.Background(), testPool, "pc-test", ip)
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

// rootIn registers a root in a fresh /24 and returns its token.
func rootIn(t *testing.T) string {
	t.Helper()
	_, tok := newRoot(t, randSuper()+".1")
	return tok
}

// sample posts one JSON sample with a token and asserts 201.
func (e *tenv) sample(t *testing.T, token, body string) string {
	t.Helper()
	st, out, _ := e.do(t, "POST", "/v1/pc", token, body)
	if st != 201 {
		t.Fatalf("sample %s: %d %s", body, st, out)
	}
	return out
}

// anon posts one anonymous sample (X-PoW stub) from ip and asserts 201.
func (e *tenv) anon(t *testing.T, ip, body string) string {
	t.Helper()
	st, out, _ := e.do(t, "POST", "/v1/pc", "", body, "X-PoW", "ok", "CF-Connecting-IP", ip)
	if st != 201 {
		t.Fatalf("anon sample from %s: %d %s", ip, st, out)
	}
	return out
}

func body(u string, tokens int, extra string) string {
	if extra != "" {
		extra = "," + extra
	}
	return fmt.Sprintf(`{"url":%q,"tokens":%d%s}`, u, tokens, extra)
}

var uhRe16 = regexp.MustCompile(`uh=([0-9a-f]{16})`)

func uhOf(t *testing.T, out string) string {
	t.Helper()
	m := uhRe16.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no uh in %q", out)
	}
	return m[1]
}

func TestCanonicalURLRules(t *testing.T) {
	good := map[string]string{
		"https://Docs.Example.COM/Guide/x":              "https://docs.example.com/Guide/x",
		"HTTPS://docs.example.com/guide/x?utm=1#frag":   "https://docs.example.com/guide/x",
		"https://docs.example.com":                      "https://docs.example.com/",
		"https://docs.example.com.":                     "https://docs.example.com/",
		"https://docs.example.com:443/a/./b/../c/":      "https://docs.example.com/a/c/",
		"http://docs.example.com:80//a//b":              "http://docs.example.com/a/b",
		"https://docs.example.com/a%20b":                "https://docs.example.com/a%20b",
		"https://docs.example.com/a b":                  "https://docs.example.com/a%20b",
		" https://docs.example.com/guide/x ":            "https://docs.example.com/guide/x",
		"https://docs.example.com/internationalization": "https://docs.example.com/internationalization",
		"https://docs.example.com/getting-started-with-postgres-logical-replication-in-production": "https://docs.example.com/getting-started-with-postgres-logical-replication-in-production",
		"https://docs.example.com/wiki/Python-3.12-Release-Notes":                                  "https://docs.example.com/wiki/Python-3.12-Release-Notes",
		"https://user.github.io/project/guide.html":                                                "https://user.github.io/project/guide.html",
	}
	for in, want := range good {
		p, err := Canon(in)
		if err != nil || p.URL != want {
			t.Errorf("Canon(%q) = %q, %v; want %q", in, p.URL, err, want)
			continue
		}
		if len(p.UH) != 32 || len(p.Short()) != 16 || p.Display() != p.Host+p.Path {
			t.Errorf("Canon(%q): bad hash/display %x %q", in, p.UH, p.Display())
		}
	}
	bad := map[string]error{
		"":                                   errURL,
		"docs.example.com/x":                 errURL,
		"ftp://docs.example.com/x":           errURL,
		"https://docs.example.com/x\ny":      errURL,
		"https://docs.exämple.com/x":         errURL,
		"https://user:pw@docs.example.com/x": errUserinfo,
		"https://user@docs.example.com/x":    errUserinfo,
		"https://localhost/x":                errHost,
		"https://foo/x":                      errHost,
		"https://127.0.0.1/x":                errHost,
		"https://10.0.0.1/admin":             errHost,
		"https://[::1]/x":                    errHost,
		"https://[2001:db8::1]/x":            errHost,
		"https://x.local/x":                  errHost,
		"https://svc.internal/x":             errHost,
		"https://foo.example/x":              errHost,
		"https://a.onion/x":                  errHost,
		"https://docs.example.com:8080/x":    errHost,
		"https://-bad.example.com/x":         errHost,
		"https://docs.example.com/x%zz":      errURL, // bad percent-encoding fails at parse time
		"https://docs.example.com/" + strings.Repeat("a/", 101):                 errPath,
		"https://docs.example.com/share/4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f":       errCap, // hex token
		"https://docs.example.com/s/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9":       errCap, // JWT part
		"https://docs.example.com/d/550e8400-e29b-41d4-a716-446655440000":       errCap, // dashed UUID
		"https://docs.example.com/invite/aB3xY9kQ-pL2mN8vC_zR5tW7uJ4hG6fD":      errCap, // base64url with separators
		"https://docs.example.com/dl/Hk3jd9sKd2kdjs8SksDk3ms9slQ":               errCap,
		"https://docs.example.com/u/john.doe@gmail.com/profile":                 errPII, // tier-2 finding in the path
		"https://docs.example.com/k/AKIAIOSFODNN7EXAMPLE/AKIAIOSFODNN7EXAMPLE1": nil,    // tier-1 secret: err scrub (any refusal)
	}
	for in, want := range bad {
		p, err := Canon(in)
		if err == nil {
			t.Errorf("Canon(%q) = %q, want refusal", in, p.URL)
			continue
		}
		if want != nil && err != want {
			t.Errorf("Canon(%q): %v, want %v", in, err, want)
		}
	}
	for in, want := range map[string]string{
		"docs.example.com": "example.com", "example.com": "example.com", "a.b.c.example.com": "example.com",
		"www.example.co.uk": "example.co.uk", "example.co.uk": "example.co.uk", "user.github.io": "user.github.io",
		"a.user.github.io": "user.github.io", "app.vercel.app": "app.vercel.app",
	} {
		if got := Registrable(in); got != want {
			t.Errorf("Registrable(%q) = %q, want %q", in, got, want)
		}
	}
	page, _ := Canon("https://docs.example.com/guide/x")
	for alt, want := range map[string]error{
		"https://raw.example.com/guide/x":      nil,
		"https://docs.example.com/guide/x.md":  nil,
		"https://docs.example.com/guide/x":     errAltSame,
		"https://docs.example.com/guide/x?v=1": errAltSame,
		"https://docs.other.com/guide/x.md":    errAltRD,
		"https://user:pw@docs.example.com/x":   errUserinfo,
	} {
		if _, err := CanonAlt(page, alt); err != want {
			t.Errorf("CanonAlt(%q): %v, want %v", alt, err, want)
		}
	}
	for _, c := range [][3]string{
		{"https://d.x.com/guide/x", "https://d.x.com/guide/x.md", "append .md"},
		{"https://d.x.com/guide/x/", "https://d.x.com/guide/x.md", "append .md"},
		{"https://d.x.com/guide/", "https://d.x.com/guide/index.md", "append index.md"},
		{"https://d.x.com/guide/x.html", "https://d.x.com/guide/x.md", "replace .html with .md"},
		{"https://d.x.com/guide/x", "https://d.x.com/raw/guide/x", "prefix /raw"},
		{"https://d.x.com/guide/x", "https://md.x.com/guide/x", "host md.x.com"},
		{"https://d.x.com/guide/x", "https://d.x.com/other", ""},
		{"https://d.x.com/guide/x", "https://md.x.com/other", ""},
	} {
		if got := AltPattern(c[0], c[1]); got != c[2] {
			t.Errorf("AltPattern(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
	for n, want := range map[int64]string{0: "0", 820: "820", 1000: "1k", 4100: "4.1k", 8200: "8.2k", 19000: "19k", 61000: "61k", 999_499: "999k", 1_200_000: "1.2M", 12_000_000: "12M"} {
		if got := kfmt(n); got != want {
			t.Errorf("kfmt(%d) = %q, want %q", n, got, want)
		}
	}
	if !json.Valid(openAPI) {
		t.Error("openAPI fragment is not valid JSON")
	}
	if len(Help) > 900 {
		t.Errorf("Help is %d bytes (> 200 tokens)", len(Help))
	}
	// The same rules guard the write path and the lookup.
	e := newEnv(t)
	tok := rootIn(t)
	for _, c := range []struct{ url, want string }{
		{"https://10.0.0.1/admin", "public hostname"},
		{"https://localhost/x", "public hostname"},
		{"https://docs.example.com/share/4f3c2b1a9e8d7c6b5a4f3e2d1c0b9a8f", "capability"},
		{"https://user:pw@docs.example.com/x", "userinfo"},
		{"docs.example.com/x", "absolute http"},
	} {
		if st, out, _ := e.do(t, "POST", "/v1/pc", tok, body(c.url, 500, "")); st != 400 || !strings.Contains(out, c.want) {
			t.Errorf("POST %s: %d %s (want 400 %s)", c.url, st, out, c.want)
		}
		if st, out, _ := e.do(t, "GET", "/pc?u="+urlEscape(c.url), "", ""); st != 400 || !strings.Contains(out, c.want) {
			t.Errorf("GET /pc?u=%s: %d %s (want 400 %s)", c.url, st, out, c.want)
		}
	}
	if st, out, _ := e.do(t, "POST", "/v1/pc", tok, body("https://docs.example.com/x", 0, "")); st != 400 || !strings.Contains(out, "tokens must be") {
		t.Errorf("tokens 0: %d %s", st, out)
	}
	if st, out, _ := e.do(t, "POST", "/v1/pc", tok, body("https://docs.example.com/x", 5, `"fmt":"docx"`)); st != 400 || !strings.Contains(out, "fmt must be") {
		t.Errorf("bad fmt: %d %s", st, out)
	}
}

func urlEscape(s string) string {
	r := strings.NewReplacer(":", "%3A", "/", "%2F", "@", "%40", "?", "%3F", "#", "%23", "&", "%26", " ", "%20")
	return r.Replace(s)
}

// TestLookupLine is the acceptance line: GET /pc?u=https://docs.example.com/guide/x prints
// "pc docs.example.com/guide/x n=… tok~…" (query and fragment dropped, suffix twins, 404 shape).
func TestLookupLine(t *testing.T) {
	e := newEnv(t)
	tok := rootIn(t)
	out := e.sample(t, tok, body("https://docs.example.com/guide/x", 8200, `"bytes":61000,"fmt":"html"`))
	if !regexp.MustCompile(`^ok uh=[0-9a-f]{16} n=\d+ tok~8\.2k\n`).MatchString(out) || !strings.Contains(out, "next: GET /pc/") {
		t.Fatalf("write reply: %q", out)
	}
	uh := uhOf(t, out)
	lineRe := regexp.MustCompile(`^pc docs\.example\.com/guide/x n=\d+ tok~8\.2k \(8\.2k\.\.8\.2k\) bytes~61k fmt=html\n`)
	st, got, hdr := e.do(t, "GET", "/pc?u=https://docs.example.com/guide/x?utm=1", "", "")
	if st != 200 || !lineRe.MatchString(got) {
		t.Fatalf("GET /pc?u=: %d %q", st, got)
	}
	if !strings.Contains(got, "url: https://docs.example.com/guide/x\n") || !strings.Contains(got, "next: GET /pc/h/docs.example.com host") {
		t.Errorf("fields/next: %q", got)
	}
	if cc := hdr.Get("Cache-Control"); !strings.Contains(cc, "max-age=60") {
		t.Errorf("Cache-Control %q", cc)
	}
	if rb := hdr.Get("X-Robots-Tag"); !strings.Contains(rb, "noindex") {
		t.Errorf("X-Robots-Tag %q", rb)
	}
	if st, got, _ = e.do(t, "GET", "/pc/"+uh, "", ""); st != 200 || !lineRe.MatchString(got) {
		t.Errorf("GET /pc/{uh}: %d %q", st, got)
	}
	st, got, hdr = e.do(t, "GET", "/pc/"+uh+".json", "", "")
	var js map[string]any
	if st != 200 || json.Unmarshal([]byte(got), &js) != nil || !strings.HasPrefix(fmt.Sprint(js["head"]), "pc docs.example.com/guide/x n=") {
		t.Errorf("GET /pc/{uh}.json: %d %s %q", st, hdr.Get("Content-Type"), got)
	}
	if st, got, _ = e.do(t, "GET", "/pc/"+uh+".html", "", ""); st != 200 || !strings.Contains(got, "<h1>token cost of docs.example.com/guide/x</h1>") {
		t.Errorf("GET /pc/{uh}.html: %d %q", st, got)
	}
	if st, got, _ = e.do(t, "GET", "/pc?u=https://docs.example.com/nothing/here", "", ""); st != 404 || !strings.Contains(got, "err notfound no samples for docs.example.com/nothing/here") {
		t.Errorf("unknown url: %d %q", st, got)
	}
	if st, got, _ = e.do(t, "GET", "/pc/0123456789abcdef", "", ""); st != 404 || !strings.Contains(got, "err notfound") {
		t.Errorf("unknown uh: %d %q", st, got)
	}
	if st, got, _ = e.do(t, "GET", "/pc/xyz", "", ""); st != 400 || !strings.Contains(got, "uh must be") {
		t.Errorf("bad uh: %d %q", st, got)
	}
	if st, got, _ = e.do(t, "GET", "/pc", "", ""); st != 200 || !strings.HasPrefix(got, "pc about:") {
		t.Errorf("GET /pc without query: %d %q", st, got)
	}
	// Query-parameter form of the write.
	u := "https://" + uniqueHost(t) + "/q"
	if st, got, _ = e.do(t, "POST", "/v1/pc?url="+urlEscape(u)+"&tokens=500&fmt=md", tok, ""); st != 201 || !strings.Contains(got, "n=1 tok~500") {
		t.Errorf("query write: %d %q", st, got)
	}
}

func TestMediansDistinctSupers(t *testing.T) {
	e := newEnv(t)
	u := "https://" + uniqueHost(t) + "/guide/median"
	// Five roots from one /24 report 100k; two roots from two other /24s report 5k and 6k.
	sup := randSuper()
	var same []string
	for i := 1; i <= 5; i++ {
		_, tok := newRoot(t, fmt.Sprintf("%s.%d", sup, i))
		same = append(same, tok)
		e.sample(t, tok, body(u, 100_000, ""))
	}
	tokA, tokB := rootIn(t), rootIn(t)
	e.sample(t, tokA, body(u, 5000, ""))
	out := e.sample(t, tokB, body(u, 6000, ""))
	if !strings.HasPrefix(out, "ok uh=") || !strings.Contains(out, " n=7 tok~6k") {
		t.Fatalf("write reply: %q", out)
	}
	st, got, _ := e.do(t, "GET", "/pc?u="+urlEscape(u), "", "")
	if st != 200 || !strings.Contains(got, " n=7 tok~6k (5k..100k) fmt=html\n") {
		t.Fatalf("collapsed median: %d %q", st, got)
	}
	// One sample per reporter per day: a re-sample replaces, n stays 7 and the value moves.
	e.sample(t, tokA, body(u, 7000, ""))
	if st, got, _ = e.do(t, "GET", "/pc?u="+urlEscape(u), "", ""); st != 200 || !strings.Contains(got, " n=7 tok~7k (6k..100k)") {
		t.Fatalf("re-sample: %d %q", st, got)
	}
	// The /24's latest sample is the one that counts for it.
	e.sample(t, same[0], body(u, 8000, ""))
	if st, got, _ = e.do(t, "GET", "/pc?u="+urlEscape(u), "", ""); st != 200 || !strings.Contains(got, " n=7 tok~7k (6k..8k)") {
		t.Fatalf("latest per super: %d %q", st, got)
	}
}

func TestAnonHalfWeight(t *testing.T) {
	e := newEnv(t)
	u := "https://" + uniqueHost(t) + "/guide/anon"
	// Two token roots (distinct /24s) at 1k, three anonymous networks at 9k: weighted median 1k.
	e.sample(t, rootIn(t), body(u, 1000, `"bytes":5000`))
	e.sample(t, rootIn(t), body(u, 1000, `"bytes":5000`))
	for i := 0; i < 3; i++ {
		out := e.anon(t, randSuper()+".7", body(u, 9000, `"bytes":50000,"fmt":"md"`))
		if !strings.HasPrefix(out, "ok uh=") {
			t.Fatalf("anon reply: %q", out)
		}
	}
	st, got, _ := e.do(t, "GET", "/pc?u="+urlEscape(u), "", "")
	if st != 200 || !strings.Contains(got, " n=5 tok~1k (1k..9k) bytes~5k fmt=html\n") {
		t.Fatalf("half weight: %d %q", st, got)
	}
	// Unweighted the three 9k samples would win: a fourth anonymous network still loses to two roots.
	e.anon(t, randSuper()+".7", body(u, 9000, `"bytes":50000,"fmt":"md"`))
	if st, got, _ = e.do(t, "GET", "/pc?u="+urlEscape(u), "", ""); st != 200 || !strings.Contains(got, " n=6 tok~1k ") {
		t.Fatalf("four anon vs two roots: %d %q", st, got)
	}
	// Anonymous without a proof: 401 with the PoW challenge; a bad proof: err pow.
	if st, got, hdr := e.do(t, "POST", "/v1/pc", "", body(u, 9000, "")); st != 401 || hdr.Get("WWW-Authenticate") == "" || !strings.Contains(got, "/v1/challenge?for=w") {
		t.Errorf("anonymous without X-PoW: %d %q %q", st, got, hdr.Get("WWW-Authenticate"))
	}
	if st, got, _ := e.do(t, "POST", "/v1/pc", "", body(u, 9000, ""), "X-PoW", "nope"); st != 400 || !strings.Contains(got, "err pow") {
		t.Errorf("bad X-PoW: %d %q", st, got)
	}
	// The same anonymous network re-sampling the same day replaces its sample.
	ip := randSuper() + ".9"
	e.anon(t, ip, body(u, 2000, ""))
	e.anon(t, ip, body(u, 3000, ""))
	if st, got, _ = e.do(t, "GET", "/pc?u="+urlEscape(u), "", ""); st != 200 || !strings.Contains(got, " n=7 ") {
		t.Fatalf("anon dedupe: %d %q", st, got)
	}
	// Anonymous samples store HMAC'd keys only, never the address.
	var raw int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM pagecost_samples WHERE who LIKE 'n:%' AND (who LIKE '%10.%' OR sup LIKE '%10.%' OR sup LIKE '%/24%')`).Scan(&raw); err != nil || raw != 0 {
		t.Errorf("raw network keys stored: %d %v", raw, err)
	}
}

func TestAltSameDomainAndConfirmations(t *testing.T) {
	e := newEnv(t)
	host := uniqueHost(t)
	u := "https://" + host + "/guide/x"
	alt := u + ".md"
	supP := randSuper()
	_, tokP := newRoot(t, supP+".1") // proposer
	if st, out, _ := e.do(t, "POST", "/v1/pc", tokP, body(u, 8000, fmt.Sprintf(`"alt":%q`, "https://docs.other-domain.com/guide/x.md"))); st != 400 || !strings.Contains(out, "registrable domain") {
		t.Fatalf("foreign alt: %d %s", st, out)
	}
	if st, out, _ := e.do(t, "POST", "/v1/pc", tokP, body(u, 8000, fmt.Sprintf(`"alt":%q`, u+"#frag"))); st != 400 || !strings.Contains(out, "differ") {
		t.Fatalf("alt = url: %d %s", st, out)
	}
	out := e.sample(t, tokP, body(u, 8000, fmt.Sprintf(`"alt":%q`, alt)))
	if !strings.Contains(out, " alt=set") {
		t.Fatalf("alt set: %q", out)
	}
	uh := uhOf(t, out)
	get := func() string {
		t.Helper()
		st, got, _ := e.do(t, "GET", "/pc/"+uh, "", "")
		if st != 200 {
			t.Fatalf("GET /pc/%s: %d %s", uh, st, got)
		}
		return got
	}
	if got := get(); strings.Contains(got, " alt: ") || strings.Contains(got, "next: GET "+alt) || !strings.Contains(got, "alt_pending: "+alt+" ok0 bad0") {
		t.Fatalf("unconfirmed alt shows: %q", got)
	}
	// A vote from the proposer's own /24 never confirms.
	_, tokP2 := newRoot(t, supP+".2")
	if st, got, _ := e.do(t, "POST", "/v1/pc/"+uh+"/altok", tokP2, ""); st != 200 || !strings.HasPrefix(got, "ok alt ok=0 bad=0\n") {
		t.Fatalf("same-super altok: %d %q", st, got)
	}
	// One other network: still hidden.
	if st, got, _ := e.do(t, "POST", "/v1/pc/"+uh+"/altok", rootIn(t), ""); st != 200 || !strings.HasPrefix(got, "ok alt ok=1 bad=0\n") {
		t.Fatalf("first altok: %d %q", st, got)
	}
	if got := get(); strings.Contains(got, " alt: ") || !strings.Contains(got, "alt_pending: "+alt+" ok1 bad0") {
		t.Fatalf("one confirmation shows: %q", got)
	}
	// Posting the same alt from a third network is an implicit confirmation: the alt shows.
	if out := e.sample(t, rootIn(t), body(u, 7000, fmt.Sprintf(`"alt":%q`, alt))); !strings.Contains(out, " alt=ok") {
		t.Fatalf("implicit confirm: %q", out)
	}
	got := get()
	if !strings.Contains(got, " fmt=html alt: "+alt+" ok2\n") || !strings.Contains(got, "next: GET "+alt+" | GET /pc/h/"+host) || strings.Contains(got, "alt_pending") {
		t.Fatalf("confirmed alt: %q", got)
	}
	// A different alt while the current one stands is kept out; the same vote twice counts once.
	if out := e.sample(t, rootIn(t), body(u, 7000, fmt.Sprintf(`"alt":%q`, u+".txt"))); !strings.Contains(out, " alt=kept") {
		t.Fatalf("competing alt: %q", out)
	}
	tokV := rootIn(t)
	e.do(t, "POST", "/v1/pc/"+uh+"/altok", tokV, "")
	if st, got, _ := e.do(t, "POST", "/v1/pc/"+uh+"/altok", tokV, ""); st != 200 || !strings.HasPrefix(got, "ok alt ok=3 bad=0 visible\n") {
		t.Fatalf("double vote: %d %q", st, got)
	}
	// Contests: ok must exceed bad for the alt to show; once bad > ok a new proposal replaces it.
	for i := 0; i < 3; i++ {
		if st, got, _ := e.do(t, "POST", "/v1/pc/"+uh+"/altbad", rootIn(t), ""); st != 200 || !strings.HasPrefix(got, fmt.Sprintf("ok alt ok=3 bad=%d", i+1)) {
			t.Fatalf("altbad %d: %d %q", i, st, got)
		}
	}
	if got := get(); strings.Contains(got, " alt: ") || !strings.Contains(got, "alt_pending: "+alt+" ok3 bad3") {
		t.Fatalf("contested alt still shows: %q", got)
	}
	if out := e.sample(t, rootIn(t), body(u, 7000, fmt.Sprintf(`"alt":%q`, u+".txt"))); !strings.Contains(out, " alt=kept") {
		t.Fatalf("tie keeps: %q", out)
	}
	e.do(t, "POST", "/v1/pc/"+uh+"/altbad", rootIn(t), "")
	if out := e.sample(t, rootIn(t), body(u, 7000, fmt.Sprintf(`"alt":%q`, u+".txt"))); !strings.Contains(out, " alt=set") {
		t.Fatalf("replace contested alt: %q", out)
	}
	if got := get(); !strings.Contains(got, "alt_pending: "+u+".txt ok0 bad0") {
		t.Fatalf("replaced alt votes reset: %q", got)
	}
	// Votes need a token; a page without an alt has nothing to vote on; bad ids are refused.
	if st, got, _ := e.do(t, "POST", "/v1/pc/"+uh+"/altok", "", "", "X-PoW", "ok"); st != 401 || !strings.Contains(got, "err auth") {
		t.Errorf("anonymous vote: %d %q", st, got)
	}
	out2 := e.sample(t, rootIn(t), body("https://"+host+"/plain", 100, ""))
	if st, got, _ := e.do(t, "POST", "/v1/pc/"+uhOf(t, out2)+"/altok", rootIn(t), ""); st != 404 || !strings.Contains(got, "no alt proposed") {
		t.Errorf("vote without alt: %d %q", st, got)
	}
	if st, got, _ := e.do(t, "POST", "/v1/pc/zz/altok", rootIn(t), ""); st != 400 || !strings.Contains(got, "uh must be") {
		t.Errorf("bad uh vote: %d %q", st, got)
	}
	if st, got, _ := e.do(t, "POST", "/v1/pc/0123456789abcdef/altok", rootIn(t), ""); st != 404 {
		t.Errorf("unknown uh vote: %d %q", st, got)
	}
}

func TestHostSummaryAltRule(t *testing.T) {
	e := newEnv(t)
	host := uniqueHost(t)
	rd := Registrable(host)
	pages := map[string]int{"/a": 3000, "/b": 9000, "/c": 1000}
	for p, tok := range pages {
		u := "https://" + host + p
		alt := fmt.Sprintf(`"alt":%q`, u+".md")
		e.sample(t, rootIn(t), body(u, tok, alt)) // proposer
		e.sample(t, rootIn(t), body(u, tok, alt)) // two independent confirmations
		e.sample(t, rootIn(t), body(u, tok, alt))
	}
	e.sample(t, rootIn(t), body("https://"+host+"/d", 2000, "")) // no alt
	st, got, _ := e.do(t, "GET", "/pc/h/"+host, "", "")
	if st != 200 {
		t.Fatalf("host summary: %d %s", st, got)
	}
	want := []string{
		"pc host " + host + " pages=4 tok~2.5k/page\n",
		"alt_rule: append .md (confirmed 6x)\n",
		"/b 9k 3 https://" + host + "/b.md\n",
		"/a 3k 3 https://" + host + "/a.md\n",
		"/d 2k 1 -\n",
		"/c 1k 3 https://" + host + "/c.md\n",
	}
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("host summary lacks %q:\n%s", w, got)
		}
	}
	if ia, ib := strings.Index(got, "/b 9k"), strings.Index(got, "/a 3k"); ia < 0 || ib < ia {
		t.Errorf("rows not ordered by tokens desc:\n%s", got)
	}
	// The registrable domain covers its subdomains; the JSON twin carries the rule as a field.
	if st, got2, _ := e.do(t, "GET", "/pc/h/"+rd+".json", "", ""); st != 200 || !strings.Contains(got2, `"alt_rule":"append .md (confirmed 6x)"`) || !strings.Contains(got2, "pages=4") {
		t.Errorf("rd summary json: %d %s", st, got2)
	}
	if st, got2, _ := e.do(t, "GET", "/pc/h/"+host+".html", "", ""); st != 200 || !strings.Contains(got2, "<strong>alt rule:</strong> append .md (confirmed 6x)") || !strings.Contains(got2, `rel="nofollow ugc noopener"`) {
		t.Errorf("host html: %d %s", st, got2)
	}
	// Below two confirmations no rule is stated; unknown hosts and bad hosts are refused.
	h2 := uniqueHost(t)
	u2 := "https://" + h2 + "/x.html"
	e.sample(t, rootIn(t), body(u2, 4000, fmt.Sprintf(`"alt":%q`, "https://"+h2+"/x.md")))
	e.sample(t, rootIn(t), body(u2, 4000, fmt.Sprintf(`"alt":%q`, "https://"+h2+"/x.md")))
	if st, got2, _ := e.do(t, "GET", "/pc/h/"+h2, "", ""); st != 200 || strings.Contains(got2, "alt_rule") || !strings.Contains(got2, "pages=1 tok~4k/page") {
		t.Errorf("single confirmation rule: %d %s", st, got2)
	}
	e.sample(t, rootIn(t), body(u2, 4000, fmt.Sprintf(`"alt":%q`, "https://"+h2+"/x.md")))
	if st, got2, _ := e.do(t, "GET", "/pc/h/"+h2, "", ""); st != 200 || !strings.Contains(got2, "alt_rule: replace .html with .md (confirmed 2x)") {
		t.Errorf("replace rule: %d %s", st, got2)
	}
	if st, got2, _ := e.do(t, "GET", "/pc/h/"+uniqueHost(t), "", ""); st != 404 || !strings.Contains(got2, "err notfound no samples for host") {
		t.Errorf("unknown host: %d %s", st, got2)
	}
	if st, got2, _ := e.do(t, "GET", "/pc/h/localhost", "", ""); st != 400 || !strings.Contains(got2, "public hostname") {
		t.Errorf("bad host: %d %s", st, got2)
	}
}

func TestIdleDeletion(t *testing.T) {
	ctx := context.Background()
	old, fresh := Canon2(t, "https://"+uniqueHost(t)+"/old"), Canon2(t, "https://"+uniqueHost(t)+"/fresh")
	for _, c := range []struct {
		p   Page
		age string
	}{{old, "181 days"}, {fresh, "10 days"}} {
		if _, err := testPool.Exec(ctx, `INSERT INTO pagecost (uh, url, host, rd, path, n, tok_p50, first, last) VALUES ($1, $2, $3, $4, $5, 1, 100, now() - $6::interval, now() - $6::interval)`,
			c.p.UH, c.p.URL, c.p.Host, Registrable(c.p.Host), c.p.Path, c.age); err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx, `INSERT INTO pagecost_samples (uh, who, sup, tok, fmt, day, created) VALUES ($1, 'aroot00', 'sup', 100, 'html', (now() - $2::interval)::date, now() - $2::interval)`, c.p.UH, c.age); err != nil {
			t.Fatal(err)
		}
		if _, err := testPool.Exec(ctx, `INSERT INTO pagecost_alt_votes (uh, who, sup, ok) VALUES ($1, 'aroot01', 'sup2', true)`, c.p.UH); err != nil {
			t.Fatal(err)
		}
	}
	if err := Janitor(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	count := func(table string, uh []byte) int {
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE uh = $1`, uh).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, table := range []string{"pagecost", "pagecost_samples", "pagecost_alt_votes"} {
		if n := count(table, old.UH); n != 0 {
			t.Errorf("%s: idle row survived (%d)", table, n)
		}
		if n := count(table, fresh.UH); n != 1 {
			t.Errorf("%s: fresh row deleted (%d)", table, n)
		}
	}
	// The janitor is registered under the package name and runs through Deps.
	e := newEnv(t)
	if _, err := testPool.Exec(ctx, `UPDATE pagecost SET last = now() - interval '200 days' WHERE uh = $1`, fresh.UH); err != nil {
		t.Fatal(err)
	}
	e.d.Janitor.RunOnce(ctx)
	if n := count("pagecost", fresh.UH); n != 0 {
		t.Errorf("Deps janitor did not run: %d", n)
	}
}

// Canon2 canonicalises or fails the test.
func Canon2(t *testing.T, u string) Page {
	t.Helper()
	p, err := Canon(u)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCapsDedupeAndPurge(t *testing.T) {
	e := newEnv(t)
	u := "https://" + uniqueHost(t) + "/caps"
	p := Canon2(t, u)
	// 100 samples/day/root: lowered to 3 for the test, the 4th is err quota.
	old := RootDaily
	RootDaily = 3
	t.Cleanup(func() { RootDaily = old })
	tok := rootIn(t)
	for i := 0; i < 3; i++ {
		e.sample(t, tok, body(fmt.Sprintf("https://%s/caps/%d", p.Host, i), 100, ""))
	}
	if st, out, _ := e.do(t, "POST", "/v1/pc", tok, body(u, 100, "")); st != 429 || !strings.Contains(out, "err quota") {
		t.Fatalf("root quota: %d %s", st, out)
	}
	RootDaily = old
	// <= 32 samples per uh: 35 distinct roots leave the newest 32, n follows.
	var who string
	for i := 0; i < 35; i++ {
		id, tk := newRoot(t, randSuper()+".3")
		if i == 0 {
			who = id
		}
		e.sample(t, tk, body(u, 1000+i, ""))
	}
	var n, cnt int
	if err := testPool.QueryRow(context.Background(), `SELECT n, (SELECT count(*) FROM pagecost_samples WHERE uh = $1) FROM pagecost WHERE uh = $1`, p.UH).Scan(&n, &cnt); err != nil || n != 32 || cnt != 32 {
		t.Fatalf("per-uh cap: n=%d samples=%d %v", n, cnt, err)
	}
	var oldest int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM pagecost_samples WHERE uh = $1 AND who = $2`, p.UH, who).Scan(&oldest); err != nil || oldest != 0 {
		t.Errorf("oldest sample kept: %d %v", oldest, err)
	}
	// Anonymous quota per IP group (4x per super-group).
	oldA := AnonDaily
	AnonDaily = 2
	t.Cleanup(func() { AnonDaily = oldA })
	ip := randSuper() + ".5"
	for i := 0; i < 2; i++ {
		e.anon(t, ip, body(fmt.Sprintf("https://%s/anon/%d", p.Host, i), 100, ""))
	}
	if st, out, _ := e.do(t, "POST", "/v1/pc", "", body(u, 100, ""), "X-PoW", "ok", "CF-Connecting-IP", ip); st != 429 || !strings.Contains(out, "err quota") {
		t.Fatalf("anon quota: %d %s", st, out)
	}
	AnonDaily = oldA
	// Purge removes a root's samples and votes and recomputes; a row left empty disappears.
	u2 := "https://" + p.Host + "/purge"
	p2 := Canon2(t, u2)
	id, tk := newRoot(t, randSuper()+".4")
	e.sample(t, tk, body(u2, 700, ""))
	if err := Purge(context.Background(), testPool, id); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM pagecost WHERE uh = $1`, p2.UH).Scan(&left); err != nil || left != 0 {
		t.Errorf("purged row left: %d %v", left, err)
	}
	// Owner audit rows name the page, never the token.
	var audits int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM audit WHERE root = $1 AND op = 'pc' AND ref = $2 AND n = 700`, id, p2.Display()).Scan(&audits); err != nil || audits != 1 {
		t.Errorf("audit rows: %d %v", audits, err)
	}
}

func TestOps(t *testing.T) {
	e := newEnv(t)
	ops := Ops(e.d)
	for _, name := range []string{"pc", "pcg"} {
		if ops[name] == nil || OpMeta[name].Cost == 0 {
			t.Fatalf("op %s missing or without meta", name)
		}
	}
	if !OpMeta["pc"].Mutating || OpMeta["pc"].Scope != "w" || OpMeta["pcg"].Mutating {
		t.Errorf("OpMeta: %+v", OpMeta)
	}
	ctx := core.WithClient(context.Background(), e.ip, core.IPGroup(e.ip), core.IPSuper(e.ip))
	host := uniqueHost(t)
	u := "https://" + host + "/ops"
	id, _ := newRoot(t, randSuper()+".2")
	ident := &core.Ident{ID: id, Root: id}
	out, err := ops["pc"](ctx, ident, json.RawMessage(fmt.Sprintf(`{"url":%q,"tokens":4100,"bytes":30000,"fmt":"md","alt":%q}`, u, u+".txt")))
	if err != nil || !strings.HasPrefix(out, "ok uh=") || !strings.HasSuffix(out, " n=1 tok~4.1k alt=set") {
		t.Fatalf("op pc: %q %v", out, err)
	}
	if _, err := ops["pc"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"url":%q,"tokens":10}`, u))); err != core.ErrAuth {
		t.Errorf("anonymous op pc without pow: %v", err)
	}
	if out, err := ops["pc"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"url":%q,"tokens":10,"pow":"ok"}`, u))); err != nil || !strings.Contains(out, " n=2 tok~4.1k") {
		t.Errorf("anonymous op pc: %q %v", out, err)
	}
	out, err = ops["pcg"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"u":%q}`, u+"?x=1")))
	if err != nil || !strings.HasPrefix(out, "pc "+host+"/ops n=2 tok~4.1k (10..4.1k) bytes~30k fmt=md\nurl: "+u+"\n") || !strings.Contains(out, "next: GET /pc/h/"+host) {
		t.Fatalf("op pcg{u}: %q %v", out, err)
	}
	if out2, err := ops["pcg"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"uh":%q}`, hex.EncodeToString(Canon2(t, u).UH)[:16]))); err != nil || out2 != out {
		t.Errorf("op pcg{uh}: %q %v", out2, err)
	}
	if out, err := ops["pcg"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"host":%q}`, host))); err != nil || !strings.HasPrefix(out, "pc host "+host+" pages=1 tok~4.1k/page\n/ops 4.1k 2 -\n") {
		t.Errorf("op pcg{host}: %q %v", out, err)
	}
	if _, err := ops["pcg"](ctx, nil, json.RawMessage(`{"u":"https://localhost/x"}`)); err == nil {
		t.Error("op pcg accepted a private host")
	}
	if _, err := ops["pcg"](ctx, nil, json.RawMessage(`{}`)); err == nil {
		t.Error("op pcg without arguments")
	}
	if _, err := ops["pcg"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"u":%q}`, "https://"+uniqueHost(t)+"/none"))); err == nil || !strings.Contains(err.Error(), "notfound") {
		t.Errorf("op pcg unknown: %v", err)
	}
	// Package text carries no raw IPs and the llms section names the routes.
	if !strings.Contains(llmsText, "GET /pc?u=") || !strings.Contains(llmsText, "POST /v1/pc") {
		t.Error("llms text lacks the routes")
	}
}
