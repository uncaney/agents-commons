package ui

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/pages"
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
	} else if pool, done := testdb.Open("ui", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping ui DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

const base = "https://agents.example"

type tenv struct {
	t   *testing.T
	d   *core.Deps
	srv *httptest.Server
	ip  string
	cl  *http.Client
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, PowBitsW: 4,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: base, RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAuthV2(mux, d)
	kb.Register(mux, d)
	pages.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &tenv{t: t, d: d, srv: srv, ip: randIP(), cl: cl}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

// randWord returns 12 random lowercase letters, so two entries built from them share almost no
// trigrams and never collide in kb.DupCheck.
func randWord() string {
	var b [12]byte
	rand.Read(b[:])
	for i := range b {
		b[i] = 'a' + b[i]%26
	}
	return string(b[:])
}

type resp struct {
	status int
	body   string
	hdr    http.Header
}

// do sends a request as e.ip; hdr pairs are extra headers (e.g. Cookie, Origin, Authorization).
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

func (e *tenv) root(name string) (id, tok string) {
	e.t.Helper()
	id, tok, err := core.CreateRoot(context.Background(), testPool, name, e.ip)
	if err != nil {
		e.t.Fatal(err)
	}
	return id, tok
}

// ft computes the form token for a POST path (today, this env's IP group).
func (e *tenv) ft(path string) string {
	return core.FormToken(e.d.Cfg.ServerSecret, path, core.IPGroup(e.ip), time.Now())
}

// form posts an urlencoded body with the public Origin, as a browser would.
func (e *tenv) form(path string, v url.Values, hdr ...string) resp {
	h := append([]string{"Content-Type", "application/x-www-form-urlencoded", "Origin", base}, hdr...)
	return e.do("POST", path, v.Encode(), h...)
}

// login mints a ui session for tok and returns the subkey cookie value.
func (e *tenv) login(tok string) (cookie string, r resp) {
	v := url.Values{"ft": {e.ft("/ui/login")}, "token": {tok}}
	r = e.form("/ui/login", v)
	return cookieVal(r.hdr), r
}

func cookieVal(h http.Header) string {
	for _, c := range h["Set-Cookie"] {
		if strings.HasPrefix(c, CookieName+"=") {
			v := strings.TrimPrefix(strings.SplitN(c, ";", 2)[0], CookieName+"=")
			return v
		}
	}
	return ""
}

func setCookieLine(h http.Header) string {
	for _, c := range h["Set-Cookie"] {
		if strings.HasPrefix(c, CookieName+"=") {
			return c
		}
	}
	return ""
}

// mkEntry creates a published fix entry authored by a fresh root; returns its id and the author
// root token.
func (e *tenv) mkEntry(t *testing.T) (id, authorTok string) {
	t.Helper()
	_, authorTok = e.root("author-" + randIP())
	body, _ := json.Marshal(map[string]any{"kind": "fix", "title": randWord() + " " + randWord(),
		"symptom": randWord() + " " + randWord() + " " + randWord() + " " + randWord(),
		"fix":     randWord() + " " + randWord() + " " + randWord() + " " + randWord()})
	r := e.do("POST", "/v1/kb", string(body), "Authorization", "Bearer "+authorTok, "Content-Type", "application/json", "Accept", "application/json")
	if r.status != 201 {
		t.Fatalf("create entry: %d %s", r.status, r.body)
	}
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(r.body), &out); err != nil || out.ID == "" {
		t.Fatalf("create reply: %s", r.body)
	}
	return out.ID, authorTok
}

func okVotes(t *testing.T, kid string) int {
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM kb_votes WHERE kb_id = $1 AND up`, kid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

var (
	formActionRe = regexp.MustCompile(`action="/ui/do"`)
	pathFieldRe  = regexp.MustCompile(`name="_path" value="([^"]+)"`)
	nonceRe      = regexp.MustCompile(`'nonce-([A-Za-z0-9_-]+)'`)
	scriptRe     = regexp.MustCompile(`(?i)<script`)
)

// --- tests -------------------------------------------------------------------------------------

func TestLoginMintsUiSubkeyAndNeverStoresToken(t *testing.T) {
	e := newEnv(t)
	rootID, tok := e.root("console-user")
	cookie, r := e.login(tok)
	if r.status != http.StatusSeeOther {
		t.Fatalf("login status: %d %s", r.status, r.body)
	}
	if cookie == "" || cookie == tok || !strings.HasPrefix(cookie, "cx_") {
		t.Fatalf("cookie subkey: %q (pasted %q)", cookie, tok)
	}
	line := setCookieLine(r.hdr)
	for _, want := range []string{"Secure", "HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=86400"} {
		if !strings.Contains(line, want) {
			t.Errorf("Set-Cookie missing %q: %s", want, line)
		}
	}
	// The subkey is a distinct ui-class identity below the root with credits 0 and the dropped
	// scopes absent; the pasted token's hash is stored only once (the root itself).
	sub, err := e.d.LookupToken(context.Background(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Class != "ui" || sub.Root != rootID || sub.Credits != 0 {
		t.Fatalf("subkey: class=%s root=%s credits=%d", sub.Class, sub.Root, sub.Credits)
	}
	if !core.ScopeAllowed(sub.Scopes, "kb:w") || core.ScopeAllowed(sub.Scopes, "sub") || core.ScopeAllowed(sub.Scopes, "gov") || core.ScopeAllowed(sub.Scopes, "bt") {
		t.Fatalf("subkey scopes wrong: %v", sub.Scopes)
	}
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM identities WHERE token_hash = $1`, core.HashToken(tok)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pasted token stored %d times, want 1 (the root only)", n)
	}
}

func TestCookieIgnoredOutsideUi(t *testing.T) {
	e := newEnv(t)
	_, tok := e.root("u")
	cookie, _ := e.login(tok)
	if cookie == "" {
		t.Fatal("no cookie")
	}
	ck := CookieName + "=" + cookie
	// The cookie must not authenticate /v1/*, /kb, or a page: those read only the Authorization
	// header, so a cookie-only request is anonymous (401 on a token route).
	if r := e.do("GET", "/v1/me", "", "Cookie", ck); r.status != 401 {
		t.Errorf("/v1/me with cookie only: status %d, want 401 (cookie ignored)", r.status)
	}
	// With the token as a bearer the same route works, proving the subkey itself is valid.
	if r := e.do("GET", "/v1/me", "", "Authorization", "Bearer "+cookie); r.status != 200 {
		t.Errorf("/v1/me with bearer: %d %s", r.status, r.body)
	}
}

func TestPageRendersNextAsForms(t *testing.T) {
	e := newEnv(t)
	kid, _ := e.mkEntry(t)
	_, tok := e.root("viewer")
	cookie, _ := e.login(tok)
	r := e.do("GET", "/ui/k/"+kid, "", "Cookie", CookieName+"="+cookie)
	if r.status != 200 {
		t.Fatalf("view: %d %s", r.status, r.body)
	}
	if !formActionRe.MatchString(r.body) {
		t.Fatalf("no /ui/do form rendered:\n%s", r.body)
	}
	paths := pathFieldRe.FindAllStringSubmatch(r.body, -1)
	var foundOk bool
	for _, m := range paths {
		if m[1] == "/v1/kb/"+kid+"/ok" {
			foundOk = true
		}
	}
	if !foundOk {
		t.Fatalf("confirm form (_path=/v1/kb/%s/ok) not found; paths=%v", kid, paths)
	}
	// Read actions render as links back into the console, not forms.
	if !strings.Contains(r.body, `href="/ui/q`) && !strings.Contains(r.body, `href="`+base+"/k/"+kid+".md") {
		t.Errorf("expected a GET next rendered as a link:\n%s", r.body)
	}
}

func TestDoDispatchesInProcess(t *testing.T) {
	e := newEnv(t)
	kid, _ := e.mkEntry(t)
	_, tok := e.root("confirmer")
	cookie, loginResp := e.login(tok)
	// The login reply mints the session cookie with the required attributes.
	line := setCookieLine(loginResp.hdr)
	for _, want := range []string{"Secure", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(line, want) {
			t.Errorf("login Set-Cookie missing %q: %s", want, line)
		}
	}
	before := okVotes(t, kid)
	v := url.Values{"ft": {e.ft("/ui/do")}, "_method": {"POST"}, "_path": {"/v1/kb/" + kid + "/ok"}}
	r := e.form("/ui/do", v, "Cookie", CookieName+"="+cookie)
	if r.status != 200 {
		t.Fatalf("confirm: %d %s", r.status, r.body)
	}
	if after := okVotes(t, kid); after != before+1 {
		t.Fatalf("ok count: before=%d after=%d", before, after)
	}
}

func TestCSRFTokenAndOrigin(t *testing.T) {
	e := newEnv(t)
	_, tok := e.root("csrf")
	// Missing form token -> 403.
	if r := e.form("/ui/login", url.Values{"token": {tok}}); r.status != 403 {
		t.Errorf("no ft: %d", r.status)
	}
	// Valid ft but foreign Origin -> 403.
	badOrigin := e.do("POST", "/ui/login", url.Values{"ft": {e.ft("/ui/login")}, "token": {tok}}.Encode(),
		"Content-Type", "application/x-www-form-urlencoded", "Origin", "https://evil.example")
	if badOrigin.status != 403 {
		t.Errorf("foreign origin: %d", badOrigin.status)
	}
	// Correct ft + Origin -> session minted.
	if r := e.form("/ui/login", url.Values{"ft": {e.ft("/ui/login")}, "token": {tok}}); r.status != http.StatusSeeOther {
		t.Errorf("good form: %d %s", r.status, r.body)
	}
}

func TestLogoutRevokes(t *testing.T) {
	e := newEnv(t)
	_, tok := e.root("bye")
	cookie, _ := e.login(tok)
	sub, err := e.d.LookupToken(context.Background(), cookie)
	if err != nil {
		t.Fatal(err)
	}
	r := e.form("/ui/logout", url.Values{"ft": {e.ft("/ui/logout")}}, "Cookie", CookieName+"="+cookie)
	if r.status != http.StatusSeeOther {
		t.Fatalf("logout: %d %s", r.status, r.body)
	}
	if _, err := e.d.LookupToken(context.Background(), cookie); err == nil {
		t.Fatal("subkey still valid after logout")
	}
	var revoked *time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT revoked_at FROM identities WHERE id = $1`, sub.ID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked == nil {
		t.Fatal("subkey not revoked in DB")
	}
	if line := setCookieLine(r.hdr); !strings.Contains(line, "Max-Age=0") && !strings.Contains(line, "Max-Age=-1") {
		t.Errorf("cookie not cleared: %s", line)
	}
}

func TestJoinSolverNonceCSP(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/ui/join", "")
	if r.status != 200 {
		t.Fatalf("join: %d", r.status)
	}
	csp := r.hdr.Get("Content-Security-Policy")
	m := nonceRe.FindStringSubmatch(csp)
	if m == nil {
		t.Fatalf("no nonce in CSP: %q", csp)
	}
	if !strings.Contains(r.body, `<script nonce="`+m[1]+`"`) {
		t.Fatalf("solver script nonce does not match CSP nonce %q:\n%s", m[1], r.body)
	}
}

func TestNoJSExceptJoin(t *testing.T) {
	e := newEnv(t)
	kid, _ := e.mkEntry(t)
	_, tok := e.root("nojs")
	cookie, _ := e.login(tok)
	ck := CookieName + "=" + cookie
	for _, p := range []string{"/ui", "/ui/q", "/ui/k/" + kid, "/ui/me"} {
		r := e.do("GET", p, "", "Cookie", ck)
		if scriptRe.MatchString(r.body) {
			t.Errorf("%s contains a <script> tag (no JS allowed off /ui/join):\n%s", p, r.body)
		}
	}
	// /ui/join is the one exception.
	if j := e.do("GET", "/ui/join", ""); !scriptRe.MatchString(j.body) {
		t.Error("/ui/join should carry the solver script")
	}
}
