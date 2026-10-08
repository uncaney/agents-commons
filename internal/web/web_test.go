package web

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
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

// TestMain opens the package database: TEST_DATABASE_URL (a builder's scratch database, migrated
// here) or testdb.Open("web") from TEST_PG_ADMIN_URL; neither set skips the DB tests.
func TestMain(m *testing.M) {
	ctx := context.Background()
	done := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, done = pool, pool.Close
	} else if pool, d := testdb.Open("web", core.Migrate); pool != nil {
		testPool, done = pool, d
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping web DB tests")
		os.Exit(0)
	}
	code := m.Run()
	done()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
	ip  string
}

type envOpt func(*core.Config)

func newEnv(t *testing.T, opts ...envOpt) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true, RegPerHour: 1 << 20,
		ForgejoURL: "http://127.0.0.1:1", ForgejoToken: "x", PublicURL: "https://agents.test/", AbuseContact: "abuse@agents.test", LicenseContent: "CC0-1.0"}
	for _, o := range opts {
		o(&cfg)
	}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	kb.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	var b [2]byte
	rand.Read(b[:])
	return &tenv{d, srv, fmt.Sprintf("10.6.%d.%d", b[0], b[1])}
}

// noRedirect never follows redirects (303 assertions).
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (e *tenv) do(t *testing.T, method, path, token string, body any, hdr ...string) (int, http.Header, string) {
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
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(b)
}

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

func (e *tenv) register(t *testing.T, name string) (id, tok string) {
	t.Helper()
	_, _, body := e.do(t, "POST", "/v1/challenge", "", nil)
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(body, -1) {
		m[x[1]] = x[2]
	}
	c := m["c"]
	bits, _ := strconv.Atoi(m["bits"]) // adaptive registration difficulty (3.1)
	st, _, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, bits), "name": name})
	if st != 201 {
		t.Fatalf("register: %d %s", st, body)
	}
	m = map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(body, -1) {
		m[x[1]] = x[2]
	}
	return m["id"], m["token"]
}

func TestRoutes(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		path, ct string
		want     []string
	}{
		{"/", "text/html; charset=utf-8", []string{"<h1>agents.ekaii.fr</h1>", "https://agents.test/mcp", "identities", "KB entries", "workers active", "untrusted data", "/llms.txt", "memory across sessions", "claude mcp add --transport http cx https://agents.test/mcp"}},
		{"/llms.txt", "text/plain; charset=utf-8", []string{"https://agents.test/mcp", "/v1/challenge", "hashlib", "leading zero bits", "untrusted data", "abuse@agents.test", "clients: /cx.py /cx.mjs /cx.sh", "## Optional", "/skills/index.json", "/brief", "/limits", "/grammar", "/llms-full.txt", "/openapi.json"}},
		{"/AGENTS.md", "text/markdown; charset=utf-8", []string{"# AGENTS.md", "POST https://agents.test/mcp", "/v1/register", "untrusted data", "/aup.txt"}},
		{"/legal", "text/html; charset=utf-8", []string{"<h1>Legal</h1>", "abuse@agents.test", "no warranty", "automated"}},
		{"/aup.txt", "text/plain; charset=utf-8", []string{"err scrub", "err hazard", "POST /v1/report"}},
		{"/worker", "text/html; charset=utf-8", []string{"<h1>Donate compute</h1>", "wazero", "CX_TOKEN_FILE: /run/secrets/donor_token", "read_only: true", `"@type":"HowTo"`}},
		{"/about", "text/html; charset=utf-8", []string{"<h1>About</h1>", "ekaii.fr", "/legal"}},
		{"/openapi.json", "application/json", []string{`"openapi": "3.1.0"`, `"https://agents.test"`, `"/v1/report"`}},
		{"/opensearch.xml", "application/opensearchdescription+xml", []string{"https://agents.test/q/{searchTerms}"}},
		{"/.well-known/agent.json", "application/json", []string{`"organization": "ekaii.fr"`, `"text/plain"`, `"x-cx-hosted-agents": "https://agents.test/agents"`}},
		{"/.well-known/agent-card.json", "application/json", []string{`"organization": "ekaii.fr"`}},
		{"/.well-known/mcp.json", "application/json", []string{"https://agents.test/mcp", "streamable-http", `"cx"`, `"documentation": "https://agents.test/openapi.json"`}},
		{"/.well-known/mcp/server.json", "application/json", []string{`"name": "fr.ekaii.agents/commons"`, `"type": "streamable-http"`}},
		{"/.well-known/api-catalog", "application/linkset+json", []string{`"linkset"`, `"service-desc"`, "https://agents.test/openapi.json"}},
		{"/.well-known/security.txt", "text/plain; charset=utf-8", []string{"Contact: mailto:abuse@agents.test", "Expires: ", "Canonical: https://agents.test/.well-known/security.txt", "Policy: https://agents.test/legal", "Preferred-Languages: en, fr"}},
		{"/.well-known/ai-plugin.json", "application/json", []string{`"schema_version": "v1"`, "https://agents.test/openapi.json"}},
	}
	for _, c := range cases {
		st, h, body := e.do(t, "GET", c.path, "", nil)
		if st != 200 {
			t.Fatalf("%s: %d %s", c.path, st, body)
		}
		if h.Get("Content-Type") != c.ct {
			t.Fatalf("%s: content-type %q", c.path, h.Get("Content-Type"))
		}
		if cc := h.Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=300") {
			t.Fatalf("%s: cache-control %q", c.path, cc)
		}
		if h.Get("ETag") == "" {
			t.Fatalf("%s: no ETag", c.path)
		}
		for _, w := range c.want {
			if !strings.Contains(body, w) {
				t.Fatalf("%s lacks %q:\n%s", c.path, w, body)
			}
		}
		if strings.HasSuffix(c.ct, "html; charset=utf-8") && h.Get("Content-Security-Policy") == "" {
			t.Fatalf("%s: no CSP", c.path)
		}
		// Conditional requests: the ETag round-trips to a 304.
		if st, _, _ := e.do(t, "GET", c.path, "", nil, "If-None-Match", h.Get("ETag")); st != 304 {
			t.Fatalf("%s: If-None-Match -> %d", c.path, st)
		}
	}
	// Root pattern must not swallow other paths; removed v1 routes are gone (P44b re-adds them).
	for _, p := range []string{"/nothing-here", "/robots.txt", "/sitemap.xml", "/.well-known/mcp-registry-auth", "/cx"} {
		if st, _, _ := e.do(t, "GET", p, "", nil); st != 404 {
			t.Fatalf("%s: %d", p, st)
		}
	}
	if st, _, _ := e.do(t, "GET", "/kb/", "", nil); st != 200 {
		t.Fatalf("/kb/: %d", st)
	}
	// Scopes and costs are registered for every route.
	for _, pat := range []string{"GET /{$}", "GET /llms.txt", "GET /legal", "GET /.well-known/api-catalog", "POST /v1/report"} {
		if _, ok := e.d.ScopeOf(pat); !ok {
			t.Fatalf("no scope for %s", pat)
		}
	}
	if e.d.CostOf("GET /llms.txt") != 0.2 || e.d.CostOf("GET /{$}") != 1 {
		t.Fatalf("costs: llms %v landing %v", e.d.CostOf("GET /llms.txt"), e.d.CostOf("GET /{$}"))
	}
}

func TestLLMSBudget(t *testing.T) {
	e := newEnv(t)
	_, _, body := e.do(t, "GET", "/llms.txt", "", nil)
	t.Logf("/llms.txt: %d bytes, %d words", len(body), len(strings.Fields(body)))
	if len(body) >= llmsBudget {
		t.Fatalf("llms.txt %d bytes >= %d", len(body), llmsBudget)
	}
	// Headroom for the voted sections (18.4): the fixed text leaves at least 100 bytes.
	if len(body) > llmsBudget-100 {
		t.Fatalf("llms.txt fixed text %d bytes leaves < 100 for voted sections", len(body))
	}
	// The embedded solver must be valid: 6 lines starting at "import".
	i := strings.Index(body, "import hashlib")
	j := strings.Index(body, "# POST /v1/register")
	if i < 0 || j < i {
		t.Fatal("solver missing")
	}
	if n := strings.Count(body[i:j], "\n"); n != 5 {
		t.Fatalf("solver lines: %d", n+1)
	}
	// Fixed footer order: Optional section is last and lists the three fixed pointers.
	if k := strings.Index(body, "## Optional"); k < 0 || !strings.Contains(body[k:], "/grammar") || !strings.Contains(body[k:], "/llms-full.txt") || !strings.Contains(body[k:], "/openapi.json") {
		t.Fatalf("footer: %s", body)
	}
	// /aup.txt stays within 200 tokens (words as the proxy).
	_, _, aup := e.do(t, "GET", "/aup.txt", "", nil)
	if n := len(strings.Fields(aup)); n > 200 {
		t.Fatalf("aup.txt %d words > 200", n)
	}
}

func TestWellKnownJSON(t *testing.T) {
	e := newEnv(t)
	_, _, body := e.do(t, "GET", "/.well-known/agent.json", "", nil)
	var card struct {
		Name, Description, URL, Version, ProtocolVersion, PreferredTransport string
		Provider                                                             struct{ Organization string }
		Capabilities                                                         struct{ Streaming, StateTransitionHistory bool }
		DefaultInputModes                                                    []string
		DefaultOutputModes                                                   []string
		Skills                                                               []struct {
			ID, Name, Description string
			Examples              []string
		}
		SecuritySchemes map[string]struct{ Type, Scheme string }
		License         string
	}
	if err := json.Unmarshal([]byte(body), &card); err != nil {
		t.Fatal(err)
	}
	if card.Name == "" || card.URL != "https://agents.test/a2a" || card.Version == "" || card.ProtocolVersion != "0.3.0" || card.PreferredTransport != "JSONRPC" ||
		card.Provider.Organization != "ekaii.fr" || card.Capabilities.Streaming || !card.Capabilities.StateTransitionHistory ||
		len(card.DefaultInputModes) != 1 || card.DefaultInputModes[0] != "text/plain" || len(card.Skills) != 4 || card.SecuritySchemes["bearer"].Scheme != "bearer" ||
		card.License != "https://creativecommons.org/publicdomain/zero/1.0/" {
		t.Fatalf("agent card: %s", body)
	}
	ids := map[string]bool{}
	for _, s := range card.Skills {
		ids[s.ID] = true
		if len(s.Examples) == 0 {
			t.Fatalf("skill %s without examples", s.ID)
		}
	}
	for _, id := range []string{"kb", "board", "notes", "compute"} {
		if !ids[id] {
			t.Fatalf("skill %s missing", id)
		}
	}
	_, _, body = e.do(t, "GET", "/.well-known/mcp.json", "", nil)
	var mc struct {
		Name, Description, Version string
		Endpoints                  []struct{ URL, Transport string }
		Remotes                    []struct {
			URL           string
			TransportType string `json:"transport_type"`
		}
		Tools          []struct{ Name, Description string }
		Authentication struct {
			Type     string
			Required bool
		}
		Documentation string
		Ops           []string `json:"x-ops"`
	}
	if err := json.Unmarshal([]byte(body), &mc); err != nil {
		t.Fatal(err)
	}
	if mc.Name == "" || mc.Version == "" || len(mc.Endpoints) != 1 || mc.Endpoints[0].URL != "https://agents.test/mcp" || mc.Endpoints[0].Transport != "streamable-http" ||
		len(mc.Remotes) != 1 || mc.Remotes[0].TransportType != "streamable-http" || len(mc.Tools) != 1 || mc.Tools[0].Name != "cx" || mc.Tools[0].Description == "" ||
		mc.Authentication.Type != "bearer" || mc.Authentication.Required || mc.Documentation != "https://agents.test/openapi.json" {
		t.Fatalf("mcp card: %s", body)
	}
	ops := map[string]bool{}
	for _, o := range mc.Ops {
		ops[o] = true
	}
	for _, o := range []string{"help", "s", "p", "tp", "j"} {
		if !ops[o] {
			t.Fatalf("x-ops lacks %s: %v", o, mc.Ops)
		}
	}
}

func TestComposeInSync(t *testing.T) {
	src, err := os.ReadFile("../../deploy/worker/compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	if string(src) != workerCompose {
		t.Fatal("internal/web/assets/compose.yml differs from deploy/worker/compose.yml: copy it over")
	}
}

func TestReportAutoHide(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	author, tok := e.register(t, "author")
	var rnd [4]byte
	rand.Read(rnd[:])
	title := fmt.Sprintf("report target %x", rnd)
	st, _, body := e.do(t, "POST", "/v1/kb", tok, map[string]any{"kind": "fix", "title": title, "symptom": "sym " + title, "fix": "f", "force": true})
	if st != 201 {
		t.Fatalf("kb create: %d %s", st, body)
	}
	kid := strings.TrimPrefix(strings.TrimSpace(body), "ok ")
	// Bad targets.
	for _, bad := range []string{"", "x:1", "kb:zzz", "t:abc", "n:nope", "n:" + kid + "/x"} {
		if st, _, body = e.do(t, "POST", "/v1/report", "", map[string]string{"target": bad}); st != 400 {
			t.Fatalf("target %q: %d %s", bad, st, body)
		}
	}
	// Nonexistent targets: 404, nothing recorded.
	for _, missing := range []string{"kb:kzzzzzz", "t:987654321", "n:" + author + "/nothing"} {
		if st, _, body = e.do(t, "POST", "/v1/report", "", map[string]string{"target": missing}); st != 404 || strings.TrimSpace(body) != "err notfound not found" {
			t.Fatalf("missing %q: %d %s", missing, st, body)
		}
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM reports WHERE target IN ('kb:kzzzzzz', 't:987654321', $1)`, "n:"+author+"/nothing").Scan(&n)
	if n != 0 {
		t.Fatalf("reports recorded for missing targets: %d", n)
	}
	report := func(ip, token string) (int, string) {
		req, _ := http.NewRequest("POST", e.srv.URL+"/v1/report", strings.NewReader(`{"target":"kb:`+kid+`","why":"spam"}`))
		req.Header.Set("CF-Connecting-IP", ip)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, strings.TrimSpace(string(b))
	}
	visible := func() bool {
		_, err := kb.Get(ctx, testPool, kid)
		return err == nil
	}
	ipA, ipB := e.ip, "10.5."+e.ip[5:]
	// Two reports from the same IP count once (idempotent); two anonymous /32s + a fresh root = 0.84 < 3.
	for i := 0; i < 2; i++ {
		if st, body := report(ipA, ""); st != 200 || body != "ok" {
			t.Fatalf("report A: %d %s", st, body)
		}
	}
	if st, body := report(ipB, ""); st != 200 || body != "ok" {
		t.Fatalf("report B: %d %s", st, body)
	}
	_, freshTok := e.register(t, "fresh")
	if st, body := report(e.ip4(10, 1), freshTok); st != 200 {
		t.Fatalf("report fresh root: %d %s", st, body)
	}
	if !visible() {
		t.Fatal("hidden by two anonymous IPs and one fresh root")
	}
	// IPv6 hosts in one /64 are one reporter.
	v6 := fmt.Sprintf("2001:db8:%x:%x", rnd[0], rnd[1])
	report(v6+"::1", "")
	report(v6+":dead:beef::2", "")
	testPool.QueryRow(ctx, `SELECT count(*) FROM reports WHERE target = $1 AND reporter = $2`, "kb:"+kid, "ip:"+v6+"::/64").Scan(&n)
	if n != 1 {
		t.Fatalf("/64 grouping: %d rows for the prefix", n)
	}
	testPool.QueryRow(ctx, `SELECT count(DISTINCT reporter) FROM reports WHERE target = $1`, "kb:"+kid).Scan(&n)
	if n != 4 || !visible() { // A, B, /64, fresh root = 0.25*3 + 0.34
		t.Fatalf("distinct reporters=%d visible=%v", n, visible())
	}
	// Eight more fresh roots (9 x 0.34 = 3.06) would do it; so would three established roots from
	// three distinct networks (3 x 1.0). Each established root reports from its own /24: roots on
	// one super-group collapse to a single weight, so they only stack across distinct networks.
	// Use the established path: rep >= 5 and age >= 3 days, set directly.
	repBefore := func() int {
		var r int
		testPool.QueryRow(ctx, `SELECT rep FROM identities WHERE id = $1`, author).Scan(&r)
		return r
	}()
	for i := 0; i < 3; i++ {
		e.d.Lim.Evict(0) // this test alone exceeds the anonymous burst from one IP
		rid, rtok := e.register(t, fmt.Sprintf("est%d", i))
		testPool.Exec(ctx, `UPDATE identities SET rep = 5, created = now() - interval '4 days' WHERE id = $1`, rid)
		if st, body := report(e.ip4(20+i, 1), rtok); st != 200 {
			t.Fatalf("established %d: %d %s", i, st, body)
		}
		// 0.75 (3 IP groups) + 0.34 (fresh root) + 1.0 = 2.09 after one: still visible; 3.09 after two: hidden.
		if (i == 0) != visible() {
			t.Fatalf("after %d established reporters visible=%v", i+1, visible())
		}
	}
	if r := repBefore; r != 0 {
		t.Fatalf("setup: author rep %d", r)
	}
	var repAfter int
	testPool.QueryRow(ctx, `SELECT rep FROM identities WHERE id = $1`, author).Scan(&repAfter)
	if repAfter != repBefore {
		t.Fatalf("report hide penalised the author: rep %d -> %d", repBefore, repAfter)
	}
	// Idempotent after hide; reporting again is still ok.
	if st, body := report("10.4."+e.ip[5:], ""); st != 200 || body != "ok" {
		t.Fatalf("report C: %d %s", st, body)
	}
	// Mirror got the delete row (empty payload).
	var empty bool
	if err := testPool.QueryRow(ctx, `SELECT length(payload) = 0 FROM forge_outbox WHERE kind = 'kb' AND ref = $1 ORDER BY id DESC LIMIT 1`, kid).Scan(&empty); err != nil || !empty {
		t.Fatalf("outbox delete row: %v %v", err, empty)
	}
	// Daily IP quota: 20 reports/day per IP group, on existing targets.
	ipQ := "10.3." + e.ip[5:]
	base := 500_000_000 + int(rnd[0])<<16 + int(rnd[1])<<8 + int(rnd[2])
	for i := 0; i <= 20; i++ {
		if _, err := testPool.Exec(ctx, `INSERT INTO tasks (n, id, root) VALUES ($1, $2, $2)`, int64(base+i), author); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		testPool.Exec(ctx, `DELETE FROM reports WHERE reporter = $1`, "ip:"+ipQ)
		testPool.Exec(ctx, `DELETE FROM tasks WHERE n BETWEEN $1 AND $2`, int64(base), int64(base+20))
	})
	for i := 0; i <= 20; i++ {
		e.d.Lim.Evict(0)
		req, _ := http.NewRequest("POST", e.srv.URL+"/v1/report", strings.NewReader(fmt.Sprintf(`{"target":"t:%d"}`, base+i)))
		req.Header.Set("CF-Connecting-IP", ipQ)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if want := 200; i == 20 {
			want = 429
			if res.StatusCode != want {
				t.Fatalf("quota: %d", res.StatusCode)
			}
		} else if res.StatusCode != want {
			t.Fatalf("report %d: %d", i, res.StatusCode)
		}
	}
}
