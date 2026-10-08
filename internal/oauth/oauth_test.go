package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
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
	} else if pool, done := testdb.Open("oauth", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping oauth DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

const (
	base     = "https://agents.example"
	redirect = "https://app.example/cb"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type tenv struct {
	t    *testing.T
	d    *core.Deps
	srv  *httptest.Server
	ip   string
	logs *syncBuf
	cl   *http.Client
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, PowBitsW: 4, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: base, RegPerHour: 1 << 20}
	logs := &syncBuf{}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAuthV2(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &tenv{t: t, d: d, srv: srv, ip: randIP(), logs: logs, cl: cl}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

type resp struct {
	status int
	body   string
	hdr    http.Header
}

// do sends a request as e.ip (hdr pairs override headers, e.g. CF-Connecting-IP). The rate
// limiter is reset first so a fast test never trips the per-group burst.
func (e *tenv) do(method, path, body string, hdr ...string) resp {
	e.t.Helper()
	e.d.Lim.Evict(0)
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("CF-Connecting-IP", e.ip)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := e.cl.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, string(b), res.Header}
}

// form posts the consent form as a browser would: urlencoded body + the public Origin.
func (e *tenv) form(path string, v url.Values, hdr ...string) resp {
	e.t.Helper()
	h := append([]string{"Content-Type", "application/x-www-form-urlencoded", "Origin", base}, hdr...)
	return e.do("POST", path, v.Encode(), h...)
}

func (e *tenv) root(name string) (id, tok string) {
	e.t.Helper()
	id, tok, err := core.CreateRoot(context.Background(), testPool, name, e.ip)
	if err != nil {
		e.t.Fatal(err)
	}
	return id, tok
}

func (e *tenv) client(uris ...string) string {
	e.t.Helper()
	b, _ := json.Marshal(map[string]any{"redirect_uris": uris, "client_name": "Test Client"})
	r := e.do("POST", "/oauth/register", string(b))
	if r.status != 201 {
		e.t.Fatalf("register: %d %s", r.status, r.body)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal([]byte(r.body), &out); err != nil || out.ClientID == "" {
		e.t.Fatalf("register reply: %s", r.body)
	}
	return out.ClientID
}

func pkce() (verifier, challenge string) {
	var b [32]byte
	rand.Read(b[:])
	verifier = enc.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(verifier))
	return verifier, enc.EncodeToString(sum[:])
}

func authURL(client, redirectURI, challenge, state, scope string) string {
	q := url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {redirectURI},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {state}}
	if scope != "" {
		q.Set("scope", scope)
	}
	return "/oauth/authorize?" + q.Encode()
}

var (
	ftRe    = regexp.MustCompile(`name="ft" value="([0-9a-f]{32})"`)
	checkRe = regexp.MustCompile(`<input type="checkbox" name="s" value="([^"]+)"( checked)?>`)
	powRe   = regexp.MustCompile(`id="pow" data-c="([A-Za-z0-9_-]+)" data-bits="(\d+)"`)
	codeRe  = regexp.MustCompile(`[?&]code=([A-Za-z0-9_-]+)`)
	tokRe   = regexp.MustCompile(`token=(cx_[A-Za-z0-9_-]{43})`)
	idRe    = regexp.MustCompile(`\bid=(a[a-z2-7]{6})`)
	nonceRe = regexp.MustCompile(`'nonce-([A-Za-z0-9_-]+)'`)
)

// consent GETs the page and returns its body and form token.
func (e *tenv) consent(client, redirectURI, challenge, state, scope string, hdr ...string) (page, ft string) {
	e.t.Helper()
	r := e.do("GET", authURL(client, redirectURI, challenge, state, scope), "", hdr...)
	if r.status != 200 {
		e.t.Fatalf("consent page: %d %s", r.status, r.body)
	}
	m := ftRe.FindStringSubmatch(r.body)
	if m == nil {
		e.t.Fatalf("no form token in page: %s", r.body)
	}
	return r.body, m[1]
}

// baseForm is the hidden-field set of the consent form plus ticked scopes.
func baseForm(ft, client, redirectURI, challenge, state string, scopes ...string) url.Values {
	v := url.Values{"ft": {ft}, "response_type": {"code"}, "client_id": {client}, "redirect_uri": {redirectURI},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {state}}
	for _, s := range scopes {
		v.Add("s", s)
	}
	return v
}

// grant runs path (a) end to end (page, form POST with the pasted token) and returns the code.
func (e *tenv) grant(client, redirectURI, challenge, tok string, scopes []string, extra url.Values) (code string, loc *url.URL) {
	e.t.Helper()
	_, ft := e.consent(client, redirectURI, challenge, "st", strings.Join(scopes, " "))
	v := baseForm(ft, client, redirectURI, challenge, "st", scopes...)
	v.Set("how", "token")
	v.Set("token", tok)
	for k, xs := range extra {
		v[k] = xs
	}
	r := e.form("/oauth/authorize", v)
	if r.status != 302 {
		e.t.Fatalf("consent POST: %d %s", r.status, r.body)
	}
	loc, err := url.Parse(r.hdr.Get("Location"))
	if err != nil || loc.Query().Get("code") == "" {
		e.t.Fatalf("bad Location %q", r.hdr.Get("Location"))
	}
	return loc.Query().Get("code"), loc
}

// exchange posts to /oauth/token (form body, no Origin: clients are not browsers).
func (e *tenv) exchange(v url.Values) (int, map[string]any) {
	e.t.Helper()
	r := e.do("POST", "/oauth/token", v.Encode(), "Content-Type", "application/x-www-form-urlencoded")
	var out map[string]any
	if err := json.Unmarshal([]byte(r.body), &out); err != nil {
		e.t.Fatalf("token reply not JSON (%d): %s", r.status, r.body)
	}
	if cc := r.hdr.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		e.t.Errorf("token reply Cache-Control %q", cc)
	}
	return r.status, out
}

func codeGrant(code, verifier, client, redirectURI string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "client_id": {client}, "redirect_uri": {redirectURI}}
}

// access completes a code exchange and returns the access token, refresh token and reply.
func (e *tenv) access(code, verifier, client, redirectURI string) (string, string, map[string]any) {
	e.t.Helper()
	st, out := e.exchange(codeGrant(code, verifier, client, redirectURI))
	if st != 200 {
		e.t.Fatalf("exchange: %d %v", st, out)
	}
	tok, _ := out["access_token"].(string)
	rt, _ := out["refresh_token"].(string)
	if len(tok) != 46 || !strings.HasPrefix(tok, "cx_") || rt == "" || out["token_type"] != "Bearer" {
		e.t.Fatalf("token reply: %v", out)
	}
	return tok, rt, out
}

func (e *tenv) me(tok string) resp {
	e.t.Helper()
	return e.do("GET", "/v1/me", "", "Authorization", "Bearer "+tok)
}

func checkboxes(page string) map[string]bool {
	out := map[string]bool{}
	for _, m := range checkRe.FindAllStringSubmatch(page, -1) {
		out[m[1]] = m[2] != ""
	}
	return out
}

func str(v map[string]any, k string) string {
	s, _ := v[k].(string)
	return s
}

func list(v map[string]any, k string) []string {
	xs, _ := v[k].([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, fmt.Sprint(x))
	}
	return out
}

func has(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// --- tests -------------------------------------------------------------------------------------

func TestMetadataEndpoints(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/.well-known/oauth-protected-resource", "")
	if r.status != 200 || !strings.HasPrefix(r.hdr.Get("Content-Type"), "application/json") {
		t.Fatalf("prm: %d %q %s", r.status, r.hdr.Get("Content-Type"), r.body)
	}
	var prm map[string]any
	json.Unmarshal([]byte(r.body), &prm)
	if str(prm, "resource") != base || !has(list(prm, "authorization_servers"), base) || len(list(prm, "authorization_servers")) != 1 {
		t.Errorf("RFC 9728 fields: %v", prm)
	}
	if bm := list(prm, "bearer_methods_supported"); len(bm) != 1 || bm[0] != "header" {
		t.Errorf("bearer_methods_supported %v", bm)
	}
	if !has(list(prm, "scopes_supported"), "kb:r") {
		t.Errorf("scopes_supported %v", prm["scopes_supported"])
	}
	if r.hdr.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("CORS header missing on .well-known: %v", r.hdr)
	}
	r = e.do("GET", "/.well-known/oauth-protected-resource/mcp", "")
	json.Unmarshal([]byte(r.body), &prm)
	if r.status != 200 || str(prm, "resource") != base+"/mcp" {
		t.Errorf("path-specific metadata: %d %s", r.status, r.body)
	}
	if r = e.do("GET", "/.well-known/oauth-protected-resource/nope", ""); r.status != 404 {
		t.Errorf("unknown resource: %d", r.status)
	}
	r = e.do("GET", "/.well-known/oauth-authorization-server", "")
	if r.status != 200 {
		t.Fatalf("asm: %d %s", r.status, r.body)
	}
	var asm map[string]any
	json.Unmarshal([]byte(r.body), &asm)
	want := map[string]string{"issuer": base, "authorization_endpoint": base + "/oauth/authorize", "token_endpoint": base + "/oauth/token", "registration_endpoint": base + "/oauth/register"}
	for k, v := range want {
		if str(asm, k) != v {
			t.Errorf("%s = %q want %q", k, str(asm, k), v)
		}
	}
	if m := list(asm, "code_challenge_methods_supported"); len(m) != 1 || m[0] != "S256" {
		t.Errorf("code_challenge_methods_supported %v", m)
	}
	if m := list(asm, "token_endpoint_auth_methods_supported"); len(m) != 1 || m[0] != "none" {
		t.Errorf("token_endpoint_auth_methods_supported %v", m)
	}
	if g := list(asm, "grant_types_supported"); !has(g, "authorization_code") || !has(g, "refresh_token") {
		t.Errorf("grant_types_supported %v", g)
	}
	if rt := list(asm, "response_types_supported"); len(rt) != 1 || rt[0] != "code" {
		t.Errorf("response_types_supported %v", rt)
	}
	if r = e.do("HEAD", "/.well-known/oauth-authorization-server", ""); r.status != 200 || r.body != "" {
		t.Errorf("HEAD: %d %q", r.status, r.body)
	}
	// The 401 hint every protected route gains (RFC 9728 5.1).
	wantWWW := `Bearer resource_metadata="` + base + `/.well-known/oauth-protected-resource"`
	if core.WWWAuthenticate != wantWWW {
		t.Errorf("core.WWWAuthenticate = %q", core.WWWAuthenticate)
	}
	if r = e.do("GET", "/v1/me", ""); r.status != 401 || r.hdr.Get("WWW-Authenticate") != wantWWW {
		t.Errorf("401 hint: %d %q", r.status, r.hdr.Get("WWW-Authenticate"))
	}
}

func TestDCRStateless(t *testing.T) {
	e := newEnv(t)
	id1 := e.client(redirect, "http://127.0.0.1/cb")
	id2 := e.client(redirect, "http://127.0.0.1/cb")
	if id1 != id2 {
		t.Errorf("same redirect URIs must give the same client_id (stateless): %s vs %s", id1, id2)
	}
	if e.client(redirect) == id1 {
		t.Errorf("different URI sets share a client_id")
	}
	var n int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM information_schema.tables WHERE table_name LIKE 'oauth_client%'`).Scan(&n)
	if n != 0 {
		t.Errorf("a client table exists; registration must be stateless")
	}
	s := newSvc(e.d)
	uris, err := s.parseClient(id1)
	if err != nil || len(uris) != 2 || uris[0] != redirect || uris[1] != "http://127.0.0.1/cb" {
		t.Fatalf("parseClient: %v %v", uris, err)
	}
	// A flipped MAC character or a foreign secret is refused.
	last := "A"
	if strings.HasSuffix(id1, "A") {
		last = "B"
	}
	bad := id1[:len(id1)-1] + last
	if _, err := s.parseClient(bad); err == nil {
		t.Errorf("tampered client_id accepted")
	}
	other := &svc{d: &core.Deps{Cfg: core.Config{ServerSecret: []byte("another-secret-0123456789")}}}
	if _, err := other.parseClient(id1); err == nil {
		t.Errorf("client_id accepted under another secret")
	}
	for _, s := range []string{"", "x", enc.EncodeToString([]byte("short"))} {
		if _, err := newSvc(e.d).parseClient(s); err == nil {
			t.Errorf("parseClient(%q) accepted", s)
		}
	}
	// Reply shape.
	b, _ := json.Marshal(map[string]any{"redirect_uris": []string{redirect, redirect}, "client_name": strings.Repeat("n", 100), "grant_types": []string{"authorization_code"}, "token_endpoint_auth_method": "none", "logo_uri": "https://x/y.png"})
	r := e.do("POST", "/oauth/register", string(b))
	var out map[string]any
	json.Unmarshal([]byte(r.body), &out)
	if r.status != 201 || str(out, "token_endpoint_auth_method") != "none" || len(list(out, "redirect_uris")) != 1 || len(str(out, "client_name")) != 64 ||
		!has(list(out, "grant_types"), "refresh_token") || list(out, "response_types")[0] != "code" || !strings.Contains(r.hdr.Get("Cache-Control"), "no-store") {
		t.Errorf("register reply: %d %s", r.status, r.body)
	}
	// Refused registrations.
	refused := [][]string{{"http://app.example/cb"}, {"ftp://app.example/cb"}, {redirect + "#frag"}, {"https://user@app.example/cb"},
		{"https://app.example/cb with space"}, {}, {"https://app.example/" + strings.Repeat("p", 600)}, {"javascript:alert(1)"}, {"https:///cb"}}
	for i := 0; i < 9; i++ {
		refused = append(refused[:len(refused)-1], append(refused[len(refused)-1], fmt.Sprintf("https://h%d.example/cb", i)))
	}
	for _, uris := range refused {
		b, _ := json.Marshal(map[string]any{"redirect_uris": uris})
		r := e.do("POST", "/oauth/register", string(b))
		json.Unmarshal([]byte(r.body), &out)
		if r.status != 400 || str(out, "error") != "invalid_redirect_uri" {
			t.Errorf("register %v: %d %s", uris, r.status, r.body)
		}
	}
	if r := e.do("POST", "/oauth/register", "not json"); r.status != 400 || !strings.Contains(r.body, "invalid_client_metadata") {
		t.Errorf("non-JSON register: %d %s", r.status, r.body)
	}
	b, _ = json.Marshal(map[string]any{"redirect_uris": []string{redirect}, "grant_types": []string{"client_credentials"}})
	if r := e.do("POST", "/oauth/register", string(b)); r.status != 400 || !strings.Contains(r.body, "invalid_client_metadata") {
		t.Errorf("client_credentials register: %d %s", r.status, r.body)
	}
	// Loopback http is fine on any loopback host.
	e.client("http://localhost:3000/cb", "http://[::1]:8080/cb", "http://127.0.0.1/cb")
	// The consent page refuses a tampered client_id with a page, never a redirect; the token
	// endpoint answers invalid_client.
	_, ch := pkce()
	r = e.do("GET", authURL(bad, redirect, ch, "st", ""), "")
	if r.status != 400 || r.hdr.Get("Location") != "" || !strings.Contains(r.body, "invalid_client") {
		t.Errorf("tampered client on authorize: %d %q %s", r.status, r.hdr.Get("Location"), r.body)
	}
	st, out := e.exchange(codeGrant(randToken(32), randToken(32), bad, redirect))
	if st != 400 || str(out, "error") != "invalid_grant" {
		t.Errorf("unknown code with tampered client: %d %v", st, out)
	}
}

func TestAuthorizeShowsRedirectHost(t *testing.T) {
	e := newEnv(t)
	client := e.client("https://app.example:8443/cb")
	_, ch := pkce()
	r := e.do("GET", authURL(client, "https://app.example:8443/cb", ch, "xyz", ""), "")
	if r.status != 200 {
		t.Fatalf("consent: %d %s", r.status, r.body)
	}
	if !strings.Contains(r.body, "<h1>Grant app.example:8443 access to agents.example?</h1>") {
		t.Errorf("heading must name the redirect host: %s", r.body)
	}
	for _, want := range []string{"no passwords", "<code>cx_</code>", `name="state" value="xyz"`, "python3 -c", `id="nonce"`, `name="credits" value="0"`, `name="how" value="token"`, `name="how" value="create"`} {
		if !strings.Contains(r.body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if !strings.Contains(r.hdr.Get("Cache-Control"), "no-store") || r.hdr.Get("X-Robots-Tag") != "noindex" || r.hdr.Get("X-Frame-Options") != "DENY" || !strings.HasPrefix(r.hdr.Get("Content-Type"), "text/html") {
		t.Errorf("headers: %v", r.hdr)
	}
	csp := r.hdr.Get("Content-Security-Policy")
	m := nonceRe.FindStringSubmatch(csp)
	if m == nil || !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "form-action 'self'") || strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Fatalf("CSP: %q", csp)
	}
	if !strings.Contains(r.body, `<script nonce="`+m[1]+`">`) {
		t.Errorf("solver script does not carry the CSP nonce %s", m[1])
	}
	if strings.Count(r.body, "<script") != 1 {
		t.Errorf("exactly one inline script expected: %d", strings.Count(r.body, "<script"))
	}
	r2 := e.do("GET", authURL(client, "https://app.example:8443/cb", ch, "xyz", ""), "")
	if m2 := nonceRe.FindStringSubmatch(r2.hdr.Get("Content-Security-Policy")); m2 == nil || m2[1] == m[1] {
		t.Errorf("nonce must differ per request")
	}
	// Parameter errors go back to the (verified) redirect URI with the state.
	q := url.Values{"response_type": {"code"}, "client_id": {client}, "redirect_uri": {"https://app.example:8443/cb"}, "state": {"xyz"}}
	r = e.do("GET", "/oauth/authorize?"+q.Encode(), "")
	loc, _ := url.Parse(r.hdr.Get("Location"))
	if r.status != 302 || loc == nil || loc.Host != "app.example:8443" || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("state") != "xyz" {
		t.Errorf("missing code_challenge: %d %q", r.status, r.hdr.Get("Location"))
	}
	q.Set("code_challenge", ch)
	q.Set("code_challenge_method", "plain")
	r = e.do("GET", "/oauth/authorize?"+q.Encode(), "")
	if loc, _ = url.Parse(r.hdr.Get("Location")); r.status != 302 || loc.Query().Get("error") != "invalid_request" {
		t.Errorf("plain PKCE: %d %q", r.status, r.hdr.Get("Location"))
	}
	q.Del("code_challenge_method")
	q.Set("response_type", "token")
	r = e.do("GET", "/oauth/authorize?"+q.Encode(), "")
	if loc, _ = url.Parse(r.hdr.Get("Location")); r.status != 302 || loc.Query().Get("error") != "unsupported_response_type" {
		t.Errorf("response_type=token: %d %q", r.status, r.hdr.Get("Location"))
	}
	q.Set("response_type", "code")
	q.Set("resource", "https://elsewhere.example/mcp")
	r = e.do("GET", "/oauth/authorize?"+q.Encode(), "")
	if loc, _ = url.Parse(r.hdr.Get("Location")); r.status != 302 || loc.Query().Get("error") != "invalid_target" {
		t.Errorf("foreign resource: %d %q", r.status, r.hdr.Get("Location"))
	}
	q.Set("resource", base+"/mcp")
	if r = e.do("GET", "/oauth/authorize?"+q.Encode(), ""); r.status != 200 {
		t.Errorf("own resource: %d", r.status)
	}
	// Exported pieces for /ui/join.
	if got := string(SolverFragment(`ab"c`)); !strings.HasPrefix(got, `<script nonce="ab&#34;c">`) || !strings.HasSuffix(got, "</script>") || strings.Contains(got, "eval(") {
		t.Errorf("SolverFragment: %s", got)
	}
	if got := NonceCSP(&core.Config{}, "n1"); got != "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'; script-src 'nonce-n1'" {
		t.Errorf("NonceCSP: %s", got)
	}
	if got := NonceCSP(&core.Config{UmamiSrc: "https://u.example/s.js", UmamiID: "x"}, "n1"); !strings.Contains(got, "script-src 'nonce-n1' https://u.example; connect-src https://u.example") {
		t.Errorf("NonceCSP with umami: %s", got)
	}
}

func TestDangerousScopesNeverDefault(t *testing.T) {
	e := newEnv(t)
	client := e.client(redirect)
	ver, ch := pkce()
	page, _ := e.consent(client, redirect, ch, "s", "")
	boxes := checkboxes(page)
	for _, d := range DangerScopes {
		if _, ok := boxes[d]; ok {
			t.Errorf("%s offered without being requested (never implied)", d)
		}
		if !Dangerous(d) {
			t.Errorf("Dangerous(%s) false", d)
		}
	}
	for _, s := range DefaultScopes() {
		if !boxes[s] {
			t.Errorf("default scope %s not pre-ticked", s)
		}
	}
	if Dangerous("kb:r") || len(boxes) != len(DefaultScopes()) {
		t.Errorf("default page: %v", boxes)
	}
	page, ft := e.consent(client, redirect, ch, "s", "kb:r me:r bt pr:req sub gov sp mb:r w kv:myapp* bogus")
	boxes = checkboxes(page)
	if !boxes["kb:r"] || !boxes["me:r"] || !boxes["kv:myapp*"] {
		t.Errorf("requested safe scopes must be pre-ticked: %v", boxes)
	}
	if on, ok := boxes["w"]; !ok || on {
		t.Errorf("neutral scope w: present=%v ticked=%v", ok, on)
	}
	if _, ok := boxes["bogus"]; ok {
		t.Errorf("unknown scope offered")
	}
	for _, d := range DangerScopes {
		if on, ok := boxes[d]; !ok || on {
			t.Errorf("dangerous %s: present=%v ticked=%v", d, ok, on)
		}
	}
	if !strings.Contains(page, "never pre-ticked") || !strings.Contains(page, "move credits or reach your whole identity tree") {
		t.Errorf("page lacks the danger warning")
	}
	// Leaving bt unticked never grants it.
	_, rootTok := e.root("owner")
	v := baseForm(ft, client, redirect, ch, "s", "kb:r", "me:r")
	v.Set("how", "token")
	v.Set("token", rootTok)
	r := e.form("/oauth/authorize", v)
	if r.status != 302 {
		t.Fatalf("consent: %d %s", r.status, r.body)
	}
	loc, _ := url.Parse(r.hdr.Get("Location"))
	tok, _, out := e.access(loc.Query().Get("code"), ver, client, redirect)
	if str(out, "scope") != "kb:r me:r" {
		t.Errorf("scope echo %q", str(out, "scope"))
	}
	if me := e.me(tok); me.status != 200 || !strings.Contains(me.body, "scopes=kb:r,me:r") || strings.Contains(me.body, "bt") {
		t.Errorf("subkey scopes: %d %s", me.status, me.body)
	}
	// Ticking an unknown scope or nothing is refused.
	_, ft = e.consent(client, redirect, ch, "s", "")
	v = baseForm(ft, client, redirect, ch, "s", "kb:r", "nonsense")
	v.Set("how", "token")
	v.Set("token", rootTok)
	if r = e.form("/oauth/authorize", v); r.status != 400 || !strings.Contains(r.body, "unknown scope") {
		t.Errorf("unknown ticked scope: %d %s", r.status, r.body)
	}
	v = baseForm(ft, client, redirect, ch, "s")
	v.Set("how", "token")
	v.Set("token", rootTok)
	if r = e.form("/oauth/authorize", v); r.status != 400 || !strings.Contains(r.body, "tick at least one scope") {
		t.Errorf("no scope ticked: %d %s", r.status, r.body)
	}
}

func TestZeroCreditsDefault(t *testing.T) {
	e := newEnv(t)
	client := e.client(redirect)
	rootID, rootTok := e.root("owner")
	ver, ch := pkce()
	page, _ := e.consent(client, redirect, ch, "s", "")
	if !strings.Contains(page, `name="credits" value="0"`) {
		t.Errorf("credits field must default to 0")
	}
	// No credits field at all -> 0 moved.
	code, _ := e.grant(client, redirect, ch, rootTok, []string{"kb:r", "me:r"}, nil)
	tok, _, _ := e.access(code, ver, client, redirect)
	if me := e.me(tok); !strings.Contains(me.body, "credits=0 ") {
		t.Errorf("subkey credits: %s", me.body)
	}
	if me := e.me(rootTok); !strings.Contains(me.body, "credits=100 ") {
		t.Errorf("root credits after a 0-credit grant: %s", me.body)
	}
	// An explicit amount moves at exchange time.
	ver2, ch2 := pkce()
	code, _ = e.grant(client, redirect, ch2, rootTok, []string{"kb:r", "me:r"}, url.Values{"credits": {"7"}})
	tok, _, _ = e.access(code, ver2, client, redirect)
	if me := e.me(tok); !strings.Contains(me.body, "credits=7 ") {
		t.Errorf("subkey credits: %s", me.body)
	}
	if me := e.me(rootTok); !strings.Contains(me.body, "credits=93 ") {
		t.Errorf("root credits after a 7-credit grant: %s", me.body)
	}
	var sub string
	testPool.QueryRow(context.Background(), `SELECT id FROM identities WHERE parent = $1 AND credits = 7`, rootID).Scan(&sub)
	if sub == "" {
		t.Errorf("no 7-credit subkey row under %s", rootID)
	}
	// More than the balance, or negative, is refused on the page.
	_, ch3 := pkce()
	_, ft := e.consent(client, redirect, ch3, "s", "")
	v := baseForm(ft, client, redirect, ch3, "s", "kb:r")
	v.Set("how", "token")
	v.Set("token", rootTok)
	v.Set("credits", "500")
	if r := e.form("/oauth/authorize", v); r.status != 402 || !strings.Contains(r.body, "err credits") {
		t.Errorf("over-balance credits: %d %s", r.status, r.body)
	}
	v.Set("credits", "-1")
	if r := e.form("/oauth/authorize", v); r.status != 400 {
		t.Errorf("negative credits: %d", r.status)
	}
	v.Set("credits", "0")
	v.Set("ttl_h", "721")
	if r := e.form("/oauth/authorize", v); r.status != 400 || !strings.Contains(r.body, "ttl_h") {
		t.Errorf("ttl above 30 d: %d", r.status)
	}
}

func TestAuthorizePasteTokenMintsSubkey(t *testing.T) {
	e := newEnv(t)
	client := e.client(redirect)
	rootID, rootTok := e.root("owner")
	ver, ch := pkce()
	_, ft := e.consent(client, redirect, ch, "state-1", "kb:r kb:w me:r")
	v := baseForm(ft, client, redirect, ch, "state-1", "kb:r", "kb:w", "me:r")
	v.Set("how", "token")
	v.Set("token", rootTok)
	v.Set("ttl_h", "24")
	r := e.form("/oauth/authorize", v)
	if r.status != 302 || !strings.Contains(r.hdr.Get("Cache-Control"), "no-store") {
		t.Fatalf("consent: %d %v %s", r.status, r.hdr, r.body)
	}
	loc, _ := url.Parse(r.hdr.Get("Location"))
	if loc.Scheme != "https" || loc.Host != "app.example" || loc.Path != "/cb" || loc.Query().Get("state") != "state-1" || loc.Query().Get("code") == "" {
		t.Fatalf("Location %q", r.hdr.Get("Location"))
	}
	// Nothing is minted before the exchange; the pasted token is nowhere in the oauth tables.
	var subs int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM identities WHERE parent = $1`, rootID).Scan(&subs)
	if subs != 0 {
		t.Errorf("subkey minted at consent time")
	}
	tok, rt, out := e.access(loc.Query().Get("code"), ver, client, redirect)
	if exp, _ := out["expires_in"].(float64); exp < 86000 || exp > 86400 {
		t.Errorf("expires_in %v for ttl_h=24", out["expires_in"])
	}
	if str(out, "scope") != "kb:r kb:w me:r" {
		t.Errorf("scope %q", str(out, "scope"))
	}
	me := e.me(tok)
	if me.status != 200 || !strings.Contains(me.body, "root="+rootID) || !strings.Contains(me.body, "class=oauth") || !strings.Contains(me.body, "scopes=kb:r,kb:w,me:r") {
		t.Fatalf("me: %d %s", me.status, me.body)
	}
	subID := idRe.FindStringSubmatch(me.body)[1]
	if subID == rootID {
		t.Errorf("access token is the root token")
	}
	var parent, class, name string
	var expAt time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT parent, token_class, name, expires_at FROM identities WHERE id = $1`, subID).Scan(&parent, &class, &name, &expAt); err != nil {
		t.Fatal(err)
	}
	if parent != rootID || class != "oauth" || name != "oauth-app.example" || time.Until(expAt) > 24*time.Hour || time.Until(expAt) < 23*time.Hour {
		t.Errorf("subkey row: parent=%s class=%s name=%s exp=%s", parent, class, name, expAt)
	}
	// Scopes bind: the subkey cannot mint subkeys (no sub scope); a scope-less probe is 403.
	if r := e.do("POST", "/v1/subkey", `{"name":"x"}`, "Authorization", "Bearer "+tok); r.status != 403 || !strings.Contains(r.body, "err scope sub") {
		t.Errorf("oauth subkey minting a subkey: %d %s", r.status, r.body)
	}
	// Refresh token exists for it.
	var n int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM oauth_refresh WHERE ident = $1 AND used_at IS NULL`, subID).Scan(&n)
	if n != 1 || rt == "" {
		t.Errorf("refresh rows %d", n)
	}
	// A subkey without me:r cannot even read /v1/me (scope table), proving scopes are enforced.
	ver2, ch2 := pkce()
	code, _ := e.grant(client, redirect, ch2, rootTok, []string{"kb:r"}, nil)
	tok2, _, _ := e.access(code, ver2, client, redirect)
	if me := e.me(tok2); me.status != 403 || !strings.Contains(me.body, "err scope me:r") {
		t.Errorf("kb:r-only subkey on /v1/me: %d %s", me.status, me.body)
	}
	// Refusals on the consent page: bad token, url/ui class, scoped parent without sub, widening.
	_, ft = e.consent(client, redirect, ch, "s", "")
	v = baseForm(ft, client, redirect, ch, "s", "kb:r")
	v.Set("how", "token")
	v.Set("token", "cx_"+strings.Repeat("A", 43))
	if r := e.form("/oauth/authorize", v); r.status != 401 || !strings.Contains(r.body, "err auth invalid token") {
		t.Errorf("bad token: %d %s", r.status, r.body)
	}
	v.Set("token", "nope")
	if r := e.form("/oauth/authorize", v); r.status != 401 {
		t.Errorf("malformed token: %d", r.status)
	}
	urlTok := e.mintSub(rootTok, `{"class":"url","scopes":["kb:r"]}`)
	v.Set("token", urlTok)
	if r := e.form("/oauth/authorize", v); r.status != 403 || !strings.Contains(r.body, "cannot delegate") {
		t.Errorf("url token delegating: %d %s", r.status, r.body)
	}
	scopedTok := e.mintSub(rootTok, `{"scopes":["kb:r","kb:w"]}`)
	v.Set("token", scopedTok)
	if r := e.form("/oauth/authorize", v); r.status != 403 || !strings.Contains(r.body, "err scope sub") {
		t.Errorf("scoped parent without sub: %d %s", r.status, r.body)
	}
	subTok := e.mintSub(rootTok, `{"scopes":["kb:r","sub"]}`)
	v.Set("token", subTok)
	v["s"] = []string{"kb:r", "kb:w"}
	if r := e.form("/oauth/authorize", v); r.status != 400 || !strings.Contains(r.body, "scope widening: your token lacks kb:w") {
		t.Errorf("widening: %d %s", r.status, r.body)
	}
	v["s"] = []string{"kb:r"}
	if r := e.form("/oauth/authorize", v); r.status != 302 {
		t.Errorf("scoped parent with sub granting a subset: %d %s", r.status, r.body)
	}
}

// mintSub mints a subkey through core's route and returns its token.
func (e *tenv) mintSub(parentTok, body string) string {
	e.t.Helper()
	r := e.do("POST", "/v1/subkey", body, "Authorization", "Bearer "+parentTok)
	m := tokRe.FindStringSubmatch(r.body)
	if r.status != 201 || m == nil {
		e.t.Fatalf("subkey %s: %d %s", body, r.status, r.body)
	}
	return m[1]
}

func TestAuthorizeCreateIdentityPow(t *testing.T) {
	e := newEnv(t)
	client := e.client(redirect)
	ver, ch := pkce()
	page, ft := e.consent(client, redirect, ch, "st", "")
	m := powRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no challenge on the page: %s", page)
	}
	c := m[1]
	bits, _ := strconv.Atoi(m[2])
	if bits != 4 || !strings.Contains(html.UnescapeString(page), "c='"+c+"';b=4;") || !strings.Contains(page, `name="c" value="`+c+`"`) {
		t.Errorf("challenge bits=%d one-liner missing: %s", bits, page)
	}
	nonce := pow.Solve(c, bits)
	v := baseForm(ft, client, redirect, ch, "st", "kb:r", "me:r")
	v.Set("how", "create")
	v.Set("name", "fresh-agent")
	v.Set("c", c)
	v.Set("nonce", nonce)
	v.Set("credits", "5")
	r := e.form("/oauth/authorize", v)
	if r.status != 201 || !strings.Contains(r.hdr.Get("Cache-Control"), "no-store") {
		t.Fatalf("create: %d %s", r.status, r.body)
	}
	idm, tm := idRe.FindStringSubmatch(r.body), tokRe.FindStringSubmatch(r.body)
	rec := regexp.MustCompile(`recovery=([a-z2-7]{26})`).FindStringSubmatch(r.body)
	if idm == nil || tm == nil || rec == nil || !strings.Contains(r.body, "shown once") || !strings.Contains(r.body, "and 5 credits") {
		t.Fatalf("created page: %s", r.body)
	}
	newID, newTok := idm[1], tm[1]
	cm := codeRe.FindStringSubmatch(r.body)
	if cm == nil || !strings.Contains(r.body, `href="https://app.example/cb?code=`) || !strings.Contains(r.body, "state=st") {
		t.Fatalf("continue link: %s", r.body)
	}
	tok, _, _ := e.access(cm[1], ver, client, redirect)
	me := e.me(tok)
	if me.status != 200 || !strings.Contains(me.body, "root="+newID) || !strings.Contains(me.body, "class=oauth") || !strings.Contains(me.body, "credits=5 ") {
		t.Errorf("subkey of the new root: %d %s", me.status, me.body)
	}
	if me := e.me(newTok); me.status != 200 || !strings.Contains(me.body, "id="+newID) || !strings.Contains(me.body, "recovery=set") || !strings.Contains(me.body, "credits=95 ") {
		t.Errorf("new root: %d %s", me.status, me.body)
	}
	// The challenge is single use; a wrong or missing nonce, or a reserved name, are refused.
	page, ft = e.consent(client, redirect, ch, "st", "")
	v.Set("ft", ft)
	if r := e.form("/oauth/authorize", v); r.status != 400 || !strings.Contains(r.body, "challenge already used") {
		t.Errorf("challenge replay: %d %s", r.status, r.body)
	}
	m = powRe.FindStringSubmatch(page)
	v.Set("c", m[1])
	v.Set("nonce", "")
	if r := e.form("/oauth/authorize", v); r.status != 400 || !strings.Contains(r.body, "nonce required") {
		t.Errorf("missing nonce: %d %s", r.status, r.body)
	}
	v.Set("nonce", "x")
	if r := e.form("/oauth/authorize", v); r.status != 400 || !strings.Contains(r.body, "err pow") {
		t.Errorf("bad nonce: %d %s", r.status, r.body)
	}
	v.Set("nonce", pow.Solve(m[1], bits))
	v.Set("name", "admin")
	if r := e.form("/oauth/authorize", v); r.status != 400 || !strings.Contains(r.body, "name reserved") {
		t.Errorf("reserved name: %d %s", r.status, r.body)
	}
	// Registration frozen: the page hides path (b) and the POST is refused.
	if err := e.d.SetFreeze(context.Background(), "reg", true); err != nil {
		t.Fatal(err)
	}
	page, ft = e.consent(client, redirect, ch, "st", "")
	if powRe.MatchString(page) || strings.Contains(page, "<script") || !strings.Contains(page, "Registration is paused") {
		t.Errorf("frozen registration still offers the PoW path")
	}
	v.Set("ft", ft)
	v.Set("name", "other")
	if r := e.form("/oauth/authorize", v); r.status != 503 {
		t.Errorf("create while frozen: %d", r.status)
	}
	e.d.SetFreeze(context.Background(), "reg", false)
}

func TestTokenPKCEAndRefreshRotation(t *testing.T) {
	e := newEnv(t)
	client := e.client(redirect)
	rootID, rootTok := e.root("owner")
	// A wrong verifier voids the code; the right one afterwards is refused.
	ver, ch := pkce()
	code, _ := e.grant(client, redirect, ch, rootTok, []string{"kb:r", "me:r"}, nil)
	wrong, _ := pkce()
	st, out := e.exchange(codeGrant(code, wrong, client, redirect))
	if st != 400 || str(out, "error") != "invalid_grant" || !strings.Contains(str(out, "error_description"), "PKCE") {
		t.Errorf("wrong verifier: %d %v", st, out)
	}
	if st, out = e.exchange(codeGrant(code, ver, client, redirect)); st != 400 || str(out, "error") != "invalid_grant" {
		t.Errorf("code after a failed attempt: %d %v", st, out)
	}
	var subs int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM identities WHERE parent = $1`, rootID).Scan(&subs)
	if subs != 0 {
		t.Errorf("a failed exchange minted a subkey")
	}
	// Malformed verifier / missing code / wrong client.
	if st, out = e.exchange(codeGrant(code, "short", client, redirect)); st != 400 || str(out, "error") != "invalid_request" {
		t.Errorf("short verifier: %d %v", st, out)
	}
	if st, out = e.exchange(url.Values{"grant_type": {"authorization_code"}}); st != 400 || str(out, "error") != "invalid_request" {
		t.Errorf("no code: %d %v", st, out)
	}
	if st, out = e.exchange(url.Values{"grant_type": {"password"}}); st != 400 || str(out, "error") != "unsupported_grant_type" {
		t.Errorf("password grant: %d %v", st, out)
	}
	if st, out = e.exchange(url.Values{}); st != 400 || str(out, "error") != "invalid_request" {
		t.Errorf("no grant_type: %d %v", st, out)
	}
	ver, ch = pkce()
	code, _ = e.grant(client, redirect, ch, rootTok, []string{"kb:r", "me:r"}, nil)
	other := e.client("https://other.example/cb")
	if st, out = e.exchange(codeGrant(code, ver, other, redirect)); st != 401 || str(out, "error") != "invalid_client" {
		t.Errorf("other client: %d %v", st, out)
	}
	// The happy path with a 1 h lifetime, then refresh.
	ver, ch = pkce()
	code, _ = e.grant(client, redirect, ch, rootTok, []string{"kb:r", "me:r"}, url.Values{"ttl_h": {"1"}})
	a, r1, out := e.access(code, ver, client, redirect)
	if exp, _ := out["expires_in"].(float64); exp < 3500 || exp > 3600 {
		t.Errorf("expires_in %v for ttl_h=1", out["expires_in"])
	}
	me := e.me(a)
	if me.status != 200 {
		t.Fatalf("me(A): %d %s", me.status, me.body)
	}
	subID := idRe.FindStringSubmatch(me.body)[1]
	// JSON bodies are accepted too.
	rb, _ := json.Marshal(map[string]string{"grant_type": "refresh_token", "refresh_token": r1, "client_id": client})
	rr := e.do("POST", "/oauth/token", string(rb))
	json.Unmarshal([]byte(rr.body), &out)
	if rr.status != 200 {
		t.Fatalf("refresh: %d %s", rr.status, rr.body)
	}
	b, r2 := str(out, "access_token"), str(out, "refresh_token")
	if b == a || b == "" || r2 == r1 || r2 == "" || str(out, "scope") != "kb:r me:r" || out["token_type"] != "Bearer" {
		t.Errorf("refresh reply: %v", out)
	}
	if exp, _ := out["expires_in"].(float64); exp < 3500 || exp > 3600 {
		t.Errorf("refreshed expires_in %v", out["expires_in"])
	}
	if me := e.me(b); me.status != 200 || !strings.Contains(me.body, "id="+subID+" ") {
		t.Errorf("rotated token is a new token of the same subkey: %d %s", me.status, me.body)
	}
	// The old access token keeps the 60 s rotate grace, then dies.
	if me := e.me(a); me.status != 200 {
		t.Errorf("old token inside the grace: %d", me.status)
	}
	testPool.Exec(context.Background(), `UPDATE identities SET rotated_at = now() - interval '2 minutes' WHERE id = $1`, subID)
	if me := e.me(a); me.status != 401 {
		t.Errorf("old token after the grace: %d %s", me.status, me.body)
	}
	// Reusing the consumed refresh token revokes the family.
	st, out = e.exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r1}, "client_id": {client}})
	if st != 400 || str(out, "error") != "invalid_grant" || !strings.Contains(str(out, "error_description"), "revoked") {
		t.Errorf("refresh reuse: %d %v", st, out)
	}
	if me := e.me(b); me.status != 401 {
		t.Errorf("subkey alive after refresh reuse: %d", me.status)
	}
	if st, out = e.exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r2}, "client_id": {client}}); st != 400 || str(out, "error") != "invalid_grant" {
		t.Errorf("sibling refresh after revocation: %d %v", st, out)
	}
	var revoked bool
	testPool.QueryRow(context.Background(), `SELECT revoked_at IS NOT NULL FROM identities WHERE id = $1`, subID).Scan(&revoked)
	if !revoked {
		t.Errorf("subkey row not revoked")
	}
	// client_id mismatch voids the refresh token; an expired one is unknown; unknown is unknown.
	ver, ch = pkce()
	code, _ = e.grant(client, redirect, ch, rootTok, []string{"kb:r"}, nil)
	_, r3, _ := e.access(code, ver, client, redirect)
	if st, out = e.exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r3}, "client_id": {other}}); st != 401 || str(out, "error") != "invalid_client" {
		t.Errorf("refresh with another client: %d %v", st, out)
	}
	if st, out = e.exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r3}, "client_id": {client}}); st != 400 || str(out, "error") != "invalid_grant" {
		t.Errorf("voided refresh: %d %v", st, out)
	}
	ver, ch = pkce()
	code, _ = e.grant(client, redirect, ch, rootTok, []string{"kb:r"}, nil)
	_, r4, _ := e.access(code, ver, client, redirect)
	testPool.Exec(context.Background(), `UPDATE oauth_refresh SET exp = now() - interval '1 second' WHERE rt_hash = $1`, hash(r4))
	if st, out = e.exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r4}, "client_id": {client}}); st != 400 || !strings.Contains(str(out, "error_description"), "unknown or expired") {
		t.Errorf("expired refresh: %d %v", st, out)
	}
	if st, out = e.exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {randToken(32)}, "client_id": {client}}); st != 400 || str(out, "error") != "invalid_grant" {
		t.Errorf("unknown refresh: %d %v", st, out)
	}
	// Only sha256 hashes are stored.
	var n int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM oauth_refresh WHERE rt_hash = $1`, hash(r4)).Scan(&n)
	if n != 1 {
		t.Errorf("refresh row keyed by hash missing")
	}
}

func TestCodeSingleUseTTL(t *testing.T) {
	e := newEnv(t)
	client := e.client(redirect)
	_, rootTok := e.root("owner")
	ver, ch := pkce()
	code, _ := e.grant(client, redirect, ch, rootTok, []string{"kb:r", "me:r"}, nil)
	var exp time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT exp FROM oauth_codes WHERE code_hash = $1`, hash(code)).Scan(&exp); err != nil {
		t.Fatal(err)
	}
	if until := time.Until(exp); until < 9*time.Minute || until > 10*time.Minute+time.Second {
		t.Errorf("code TTL %s, want 10 min", until)
	}
	a, r1, _ := e.access(code, ver, client, redirect)
	if me := e.me(a); me.status != 200 {
		t.Fatalf("me: %d", me.status)
	}
	// Second use: refused, and the subkey it minted is revoked (a replayed code leaked).
	st, out := e.exchange(codeGrant(code, ver, client, redirect))
	if st != 400 || str(out, "error") != "invalid_grant" || !strings.Contains(str(out, "error_description"), "revoked") {
		t.Errorf("code replay: %d %v", st, out)
	}
	if me := e.me(a); me.status != 401 {
		t.Errorf("subkey alive after code replay: %d", me.status)
	}
	if st, out = e.exchange(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {r1}, "client_id": {client}}); st != 400 {
		t.Errorf("refresh after code replay: %d %v", st, out)
	}
	// Expired code.
	ver, ch = pkce()
	code, _ = e.grant(client, redirect, ch, rootTok, []string{"kb:r"}, nil)
	testPool.Exec(context.Background(), `UPDATE oauth_codes SET exp = now() - interval '1 minute' WHERE code_hash = $1`, hash(code))
	if st, out = e.exchange(codeGrant(code, ver, client, redirect)); st != 400 || !strings.Contains(str(out, "error_description"), "unknown or expired") {
		t.Errorf("expired code: %d %v", st, out)
	}
	if st, out = e.exchange(codeGrant(randToken(32), ver, client, redirect)); st != 400 || str(out, "error") != "invalid_grant" {
		t.Errorf("unknown code: %d %v", st, out)
	}
	// Janitor drops codes an hour past expiry and refresh rows a day past theirs.
	testPool.Exec(context.Background(), `UPDATE oauth_codes SET exp = now() - interval '2 hours' WHERE code_hash = $1`, hash(code))
	testPool.Exec(context.Background(), `UPDATE oauth_refresh SET exp = now() - interval '2 days' WHERE rt_hash = $1`, hash(r1))
	if err := Janitor(context.Background(), testPool); err != nil {
		t.Fatal(err)
	}
	var n int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM oauth_codes WHERE code_hash = $1`, hash(code)).Scan(&n)
	if n != 0 {
		t.Errorf("janitor kept the dead code")
	}
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM oauth_refresh WHERE rt_hash = $1`, hash(r1)).Scan(&n)
	if n != 0 {
		t.Errorf("janitor kept the dead refresh row")
	}
	// Pending codes per root are capped.
	old := MaxLiveCodes
	MaxLiveCodes = 2
	t.Cleanup(func() { MaxLiveCodes = old })
	rootID2, rootTok2 := e.root("capped")
	for i := 0; i < 2; i++ {
		_, ch := pkce()
		e.grant(client, redirect, ch, rootTok2, []string{"kb:r"}, nil)
	}
	_, ch = pkce()
	_, ft := e.consent(client, redirect, ch, "s", "")
	v := baseForm(ft, client, redirect, ch, "s", "kb:r")
	v.Set("how", "token")
	v.Set("token", rootTok2)
	if r := e.form("/oauth/authorize", v); r.status != 429 || !strings.Contains(r.body, "pending authorizations") || r.hdr.Get("Retry-After") == "" {
		t.Errorf("code cap: %d %s", r.status, r.body)
	}
	// Purge removes a root's oauth rows.
	if _, err := e.d.Purge(context.Background(), rootID2); err != nil {
		t.Fatal(err)
	}
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM oauth_codes WHERE root = $1`, rootID2).Scan(&n)
	if n != 0 {
		t.Errorf("purge left %d codes", n)
	}
}

func TestRedirectExactMatch(t *testing.T) {
	e := newEnv(t)
	client := e.client(redirect, "http://127.0.0.1/cb")
	_, ch := pkce()
	for _, bad := range []string{redirect + "/", redirect + "?x=1", "http://app.example/cb", "https://app.example/CB", "https://APP.example/cb",
		"https://app.example.evil/cb", redirect + "#x", "https://app.example:443/cb", "http://127.0.0.1:5000/cb/x", "http://127.0.0.2/cb"} {
		r := e.do("GET", authURL(client, bad, ch, "s", ""), "")
		if r.status != 400 || r.hdr.Get("Location") != "" || !strings.Contains(r.body, "redirect_uri") {
			t.Errorf("redirect %q: %d loc=%q", bad, r.status, r.hdr.Get("Location"))
		}
	}
	if r := e.do("GET", authURL(client, redirect, ch, "s", ""), ""); r.status != 200 {
		t.Errorf("exact redirect: %d", r.status)
	}
	// Loopback registrations ignore the port (RFC 8252 7.3) and the page names what was presented.
	r := e.do("GET", authURL(client, "http://127.0.0.1:51234/cb", ch, "s", ""), "")
	if r.status != 200 || !strings.Contains(r.body, "<h1>Grant 127.0.0.1:51234 access") {
		t.Errorf("loopback port: %d %s", r.status, r.body)
	}
	// Missing redirect_uri: only a single-URI client may omit it.
	q := url.Values{"response_type": {"code"}, "client_id": {client}, "code_challenge": {ch}, "code_challenge_method": {"S256"}}
	if r := e.do("GET", "/oauth/authorize?"+q.Encode(), ""); r.status != 400 || !strings.Contains(r.body, "redirect_uri required") {
		t.Errorf("missing redirect with two registered: %d", r.status)
	}
	single := e.client(redirect)
	q.Set("client_id", single)
	if r := e.do("GET", "/oauth/authorize?"+q.Encode(), ""); r.status != 200 || !strings.Contains(r.body, `name="redirect_uri" value="`+redirect+`"`) {
		t.Errorf("single-URI client without redirect_uri: %d", r.status)
	}
	// The POSTed hidden redirect is re-validated.
	_, rootTok := e.root("owner")
	_, ft := e.consent(client, redirect, ch, "s", "")
	v := baseForm(ft, client, redirect+"/", ch, "s", "kb:r")
	v.Set("how", "token")
	v.Set("token", rootTok)
	if r := e.form("/oauth/authorize", v); r.status != 400 || r.hdr.Get("Location") != "" {
		t.Errorf("tampered hidden redirect: %d", r.status)
	}
	// Token exchange with another redirect_uri is refused and voids the code.
	ver, ch2 := pkce()
	code, _ := e.grant(client, redirect, ch2, rootTok, []string{"kb:r"}, nil)
	st, out := e.exchange(codeGrant(code, ver, client, "http://127.0.0.1/cb"))
	if st != 400 || str(out, "error") != "invalid_grant" || !strings.Contains(str(out, "error_description"), "redirect_uri") {
		t.Errorf("mismatched redirect at exchange: %d %v", st, out)
	}
	if st, _ = e.exchange(codeGrant(code, ver, client, redirect)); st != 400 {
		t.Errorf("code survived a mismatched exchange: %d", st)
	}
	// matchRedirect table.
	for _, c := range []struct {
		reg, got string
		ok       bool
	}{{redirect, redirect, true}, {redirect, redirect + "/", false}, {"http://127.0.0.1/cb", "http://127.0.0.1:9/cb", true},
		{"http://localhost/cb", "http://LOCALHOST:7/cb", true}, {"http://[::1]/cb", "http://[::1]:4000/cb", true}, {"http://127.0.0.1/cb", "https://127.0.0.1/cb", false},
		{"http://127.0.0.1/cb", "http://127.0.0.1/cb?x", false}, {"https://a.example/cb", "https://a.example:444/cb", false}} {
		if got := matchRedirect(c.reg, c.got); got != c.ok {
			t.Errorf("matchRedirect(%q, %q) = %v", c.reg, c.got, got)
		}
	}
}

func TestCSRFTokens(t *testing.T) {
	e := newEnv(t)
	client := e.client(redirect)
	_, rootTok := e.root("owner")
	_, ch := pkce()
	_, ft := e.consent(client, redirect, ch, "s", "")
	good := baseForm(ft, client, redirect, ch, "s", "kb:r")
	good.Set("how", "token")
	good.Set("token", rootTok)
	clone := func(extra map[string]string) url.Values {
		v := url.Values{}
		for k, xs := range good {
			v[k] = append([]string(nil), xs...)
		}
		for k, x := range extra {
			if x == "" {
				v.Del(k)
			} else {
				v.Set(k, x)
			}
		}
		return v
	}
	if r := e.form("/oauth/authorize", clone(map[string]string{"ft": ""})); r.status != 403 || !strings.Contains(r.body, "err bad form token") {
		t.Errorf("missing ft: %d %s", r.status, r.body)
	}
	if r := e.form("/oauth/authorize", clone(map[string]string{"ft": strings.Repeat("0", 32)})); r.status != 403 {
		t.Errorf("wrong ft: %d", r.status)
	}
	if r := e.form("/oauth/authorize", good, "Origin", "https://evil.example"); r.status != 403 || !strings.Contains(r.body, "err bad form token") {
		t.Errorf("foreign Origin: %d %s", r.status, r.body)
	}
	if r := e.do("POST", "/oauth/authorize", good.Encode(), "Content-Type", "application/x-www-form-urlencoded"); r.status != 403 {
		t.Errorf("no Origin/Referer: %d", r.status)
	}
	// A token minted for another IP group is refused.
	otherIP := randIP()
	_, ft2 := e.consent(client, redirect, ch, "s", "", "CF-Connecting-IP", otherIP)
	if r := e.form("/oauth/authorize", clone(map[string]string{"ft": ft2})); r.status != 403 {
		t.Errorf("ft of another group: %d", r.status)
	}
	// A cross-site POST cannot carry the form fields through JSON either.
	b, _ := json.Marshal(map[string]any{"ft": ft, "how": "token", "token": rootTok})
	if r := e.do("POST", "/oauth/authorize", string(b), "Origin", base); r.status != 403 {
		t.Errorf("JSON body: %d", r.status)
	}
	// Referer stands in for Origin; the real thing works.
	if r := e.do("POST", "/oauth/authorize", good.Encode(), "Content-Type", "application/x-www-form-urlencoded", "Referer", base+"/oauth/authorize?x=1"); r.status != 302 {
		t.Errorf("Referer-only POST: %d %s", r.status, r.body)
	}
	if r := e.form("/oauth/authorize", good); r.status != 302 {
		t.Errorf("good POST: %d %s", r.status, r.body)
	}
	// The form token is bound to the path and the day (core.FormToken); the token endpoint needs
	// no form token (clients are not browsers) and the consent page never lets the GET mint.
	if ft == core.FormToken(e.d.Cfg.ServerSecret, "/other", core.IPGroup(e.ip), time.Now()) {
		t.Errorf("form token not bound to the path")
	}
	if r := e.do("GET", "/oauth/authorize?"+good.Encode(), ""); r.status != 200 || r.hdr.Get("Location") != "" {
		t.Errorf("GET with form fields must only render: %d", r.status)
	}
}

func TestUrlTokenClassLimits(t *testing.T) {
	e := newEnv(t)
	_, rootTok := e.root("owner")
	urlTok := e.mintSub(rootTok, `{"class":"url","scopes":["kb:r","t:r"]}`)
	var mu sync.Mutex
	var gotAuth, gotPath string
	calls := 0
	MCPHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		calls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	})
	t.Cleanup(func() { MCPHandler = nil })
	rpc := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	r := e.do("POST", "/mcp/t/"+urlTok, rpc)
	mu.Lock()
	auth, path, n := gotAuth, gotPath, calls
	mu.Unlock()
	if r.status != 200 || r.body != `{"ok":true}` || auth != "Bearer "+urlTok || path != "/mcp" || n != 1 {
		t.Errorf("forward: %d %s auth=%q path=%q calls=%d", r.status, r.body, auth, path, n)
	}
	if !strings.Contains(r.hdr.Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control %q", r.hdr.Get("Cache-Control"))
	}
	// A full token in the path never authenticates (a leaked URL is not a header).
	r = e.do("POST", "/mcp/t/"+rootTok, rpc)
	if r.status != 401 || !strings.Contains(r.body, "url-class token required") || r.hdr.Get("WWW-Authenticate") != core.WWWAuthenticate {
		t.Errorf("full token in path: %d %s %q", r.status, r.body, r.hdr.Get("WWW-Authenticate"))
	}
	oauthTok := e.mintSub(rootTok, `{"class":"oauth","scopes":["kb:r"]}`)
	if r = e.do("POST", "/mcp/t/"+oauthTok, rpc); r.status != 401 {
		t.Errorf("oauth token in path: %d", r.status)
	}
	for _, p := range []string{"/mcp/t/garbage", "/mcp/t/cx_" + strings.Repeat("A", 43)} {
		if r = e.do("POST", p, rpc); r.status != 401 {
			t.Errorf("%s: %d", p, r.status)
		}
	}
	// A url token holding a scope outside the ceiling is refused here.
	wide := e.mintSub(rootTok, `{"class":"url","scopes":["kb:r","lk"]}`)
	if r = e.do("POST", "/mcp/t/"+wide, rpc); r.status != 403 || !strings.Contains(r.body, "err scope") {
		t.Errorf("wide url token: %d %s", r.status, r.body)
	}
	// The default url scope set (core.URLReadScopes) and the 19.4 set pass.
	def := e.mintSub(rootTok, `{"class":"url"}`)
	if r = e.do("POST", "/mcp/t/"+def, rpc); r.status != 200 {
		t.Errorf("default url token: %d %s", r.status, r.body)
	}
	mu.Lock()
	n = calls
	mu.Unlock()
	if n != 2 {
		t.Errorf("handler called %d times, want 2 (refusals never forward)", n)
	}
	for scopes, ok := range map[string]bool{"": false, "kb:r,bt": false, "kv:x*": false, "mb:r": false, "kb:r,kb:w,t:r,t:w,n:w": true, "cp:r,ev:r,kv:r,mb:env,me:r": true} {
		var in []string
		if scopes != "" {
			in = strings.Split(scopes, ",")
		}
		if got := URLScopeOK(in); got != ok {
			t.Errorf("URLScopeOK(%q) = %v", scopes, got)
		}
	}
	if !URLScopeOK(core.URLReadScopes) {
		t.Errorf("core.URLReadScopes outside the ceiling")
	}
	// Class limits enforced at mint: no credits, 90 d max (default), revocable.
	if r = e.do("POST", "/v1/subkey", `{"class":"url","credits":1}`, "Authorization", "Bearer "+rootTok); r.status != 400 || !strings.Contains(r.body, "no credits") {
		t.Errorf("url credits: %d %s", r.status, r.body)
	}
	if r = e.do("POST", "/v1/subkey", `{"class":"url","ttl_h":2161}`, "Authorization", "Bearer "+rootTok); r.status != 400 {
		t.Errorf("url ttl > 90 d: %d %s", r.status, r.body)
	}
	r = e.do("POST", "/v1/subkey", `{"class":"url"}`, "Authorization", "Bearer "+rootTok)
	if exp := regexp.MustCompile(`exp=(\d{4}-\d{2}-\d{2})`).FindStringSubmatch(r.body); exp == nil || exp[1] != time.Now().UTC().Add(90*24*time.Hour).Format("2006-01-02") {
		t.Errorf("url default expiry: %s", r.body)
	}
	id := regexp.MustCompile(`id=(a[a-z2-7]{6})`).FindStringSubmatch(r.body)[1]
	if r = e.do("DELETE", "/v1/subkey/"+id, "", "Authorization", "Bearer "+rootTok); r.status != 200 {
		t.Errorf("revoke url token: %d %s", r.status, r.body)
	}
	// Without the integration seam the route fails closed; GET is 405.
	MCPHandler = nil
	if r = e.do("POST", "/mcp/t/"+urlTok, rpc); r.status != 503 {
		t.Errorf("nil handler: %d %s", r.status, r.body)
	}
	if r = e.do("GET", "/mcp/t/"+urlTok, ""); r.status != 405 {
		t.Errorf("GET: %d", r.status)
	}
	// The request log never shows the token: the path is masked before the log line is written.
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(e.logs.String(), "/mcp/t/-") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	logs := e.logs.String()
	if !strings.Contains(logs, "/mcp/t/-") {
		t.Errorf("masked path missing from the request log")
	}
	for _, tok := range []string{urlTok, rootTok, oauthTok, wide, def} {
		if strings.Contains(logs, tok[3:]) {
			t.Errorf("token leaked into the request log")
		}
	}
}
