package beacon

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

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
	} else if pool, done := testdb.Open("beacon", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping beacon DB tests")
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
	CacheTTL = 0 // caching off: every test reads fresh numbers; TestCacheAndJanitor sets its own TTL
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
	return &tenv{d: d, srv: srv, ip: randIP("10.7")}
}

func randIP(prefix string) string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("%s.%d.%d", prefix, b[0], b[1])
}

// randSuper returns a fresh /24 prefix "10.<a>.<b>" (hosts are appended by the caller).
func randSuper() string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d", b[0], b[1])
}

func uniqueTarget(t *testing.T) string {
	t.Helper()
	var b [4]byte
	rand.Read(b[:])
	return fmt.Sprintf("t%x.example.com", b)
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

func newRoot(t *testing.T, ip string) (id, token string) {
	t.Helper()
	id, token, err := core.CreateRoot(context.Background(), testPool, "beacon-test", ip)
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

// beaconJSON posts one beacon with a token from ip and asserts 201.
func (e *tenv) beaconJSON(t *testing.T, token, ip, target, sym string) string {
	t.Helper()
	st, body, _ := e.do(t, "POST", "/v1/beacon", token, fmt.Sprintf(`{"target":%q,"sym":%q}`, target, sym), "CF-Connecting-IP", ip)
	if st != 201 {
		t.Fatalf("beacon from %s: %d %s", ip, st, body)
	}
	return body
}

// insert writes a raw row (root "" = anonymous) at the given age.
func insert(t *testing.T, target, sym, root, ip string, age time.Duration) {
	t.Helper()
	var r *string
	if root != "" {
		r = &root
	}
	_, err := testPool.Exec(context.Background(), `INSERT INTO beacons (target, sym, root, ipgroup, ipsuper, created) VALUES ($1, $2, $3, $4, $5, now() - $6::interval)`,
		target, sym, r, core.IPGroup(ip), core.IPSuper(ip), age)
	if err != nil {
		t.Fatal(err)
	}
}

func hourly(t *testing.T, target string, age time.Duration, reports float64, roots, nets int, syms string) {
	t.Helper()
	_, err := testPool.Exec(context.Background(), `INSERT INTO st_hourly (target, hour, reports, roots, nets, syms)
		VALUES ($1, date_trunc('hour', now() - $2::interval), $3, $4, $5, $6::jsonb)
		ON CONFLICT (target, hour) DO UPDATE SET reports = EXCLUDED.reports, roots = EXCLUDED.roots, nets = EXCLUDED.nets, syms = EXCLUDED.syms`,
		target, age, reports, roots, nets, syms)
	if err != nil {
		t.Fatal(err)
	}
}

var verdictRe = regexp.MustCompile(`(?i)\b(down|outage|broken)\b`)

func TestTargetValidation(t *testing.T) {
	good := map[string]string{
		"api.example.com": "api.example.com", "API.Example.COM.": "api.example.com", "model:openai/gpt-4o": "model:openai/gpt-4o",
		"Model:Anthropic/claude-3.5": "model:anthropic/claude-3.5", "1.1.1.1": "1.1.1.1", "a-b.c-d.io": "a-b.c-d.io",
	}
	for in, want := range good {
		got, err := NormTarget(in)
		if err != nil || got != want {
			t.Errorf("NormTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"localhost", "foo", "ab", "10.0.0.1", "192.168.1.5", "172.16.3.4", "127.0.0.1", "0.0.0.0", "169.254.1.1", "100.64.0.1",
		"x.local", "a.b.internal", "foo.example", "svc.test", "db.corp", "model:openai", "model:openai/", "model:/x", "model:open ai/x",
		"http://x.com", "ex ample.com", "-bad.example.com", "bad-.example.com", "api.example.com:443", "api.example.com/v1", "999.1.1.1",
		"a..b", strings.Repeat("a", 80) + ".com", "::1", "x.y.1", "api.example.com\nx", "Ａpi.example.com"}
	for _, in := range bad {
		if got, err := NormTarget(in); err == nil {
			t.Errorf("NormTarget(%q) = %q, want error", in, got)
		}
	}
	for _, s := range []string{"529", "5xx", "timeout", "auth", "slow", "ok"} {
		if !ValidSym(s) {
			t.Errorf("sym %s should be valid", s)
		}
	}
	for _, s := range []string{"", "500", "OK", "up", "fail"} {
		if ValidSym(s) {
			t.Errorf("sym %q should be invalid", s)
		}
	}
	if !json.Valid(openAPI) {
		t.Error("openAPI fragment is not valid JSON")
	}
	if len(Help) > 800 {
		t.Errorf("Help is %d bytes (> 200 tokens)", len(Help))
	}
	if verdictRe.MatchString(Help) || verdictRe.MatchString(llmsText) || verdictRe.MatchString(string(openAPI)) {
		t.Error("package texts carry a verdict word")
	}
}

func TestAggregatesDistinctRootsSupers(t *testing.T) {
	e := newEnv(t)
	target := uniqueTarget(t)
	var tokens, ips []string
	for i := 0; i < 3; i++ {
		ip := randSuper() + ".10"
		_, tok := newRoot(t, ip)
		tokens, ips = append(tokens, tok), append(ips, ip)
	}
	for i := range tokens {
		body := e.beaconJSON(t, tokens[i], ips[i], target, "529")
		want := fmt.Sprintf("ok %s 529 15m: %d reports (%d roots, %d nets)", target, i+1, i+1, i+1)
		if !strings.HasPrefix(body, want+"\n") {
			t.Fatalf("post reply %q, want prefix %q", body, want)
		}
		if !strings.Contains(body, "next: GET /st/"+target+" | GET /f/st/"+target+".atom feed") {
			t.Errorf("post reply tail: %q", body)
		}
	}
	st, body, h := e.do(t, "GET", "/st/"+target, "", "")
	if st != 200 || !strings.Contains(body, "15m: 3 reports (3 roots, 3 nets)") {
		t.Fatalf("GET /st/%s: %d %s", target, st, body)
	}
	if !strings.Contains(body, "529x3 | 1h: 3 (3 roots, 3 nets) | 24h baseline 0.1/h | last ok never") {
		t.Errorf("head line: %q", body)
	}
	if cc := h.Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=300") {
		t.Errorf("Cache-Control %q", cc)
	}
	if !strings.Contains(h.Get("Link"), `</st/`+target+`>; rel="canonical"`) {
		t.Errorf("canonical Link: %q", h.Values("Link"))
	}
	// Same root and same network twice more: reports grow, roots and nets do not.
	e.beaconJSON(t, tokens[0], ips[0], target, "timeout")
	e.beaconJSON(t, tokens[0], ips[0], target, "ok")
	_, body, _ = e.do(t, "GET", "/st/"+target, "", "")
	if !strings.Contains(body, "15m: 5 reports (3 roots, 3 nets) 529x3 okx1 timeoutx1") || !strings.Contains(body, "last ok <1m ago") {
		t.Errorf("after repeats: %q", body)
	}
	// Query-parameter form and an empty body.
	st, body, _ = e.do(t, "POST", "/v1/beacon?target="+target+"&sym=5xx", tokens[1], "", "CF-Connecting-IP", ips[1])
	if st != 201 || !strings.HasPrefix(body, "ok "+target+" 5xx 15m: 6 reports (3 roots, 3 nets)") {
		t.Errorf("query form: %d %s", st, body)
	}
	// JSON twin: head plus day rows as objects.
	st, body, _ = e.do(t, "GET", "/st/"+target+".json", "", "")
	var js struct {
		Head string              `json:"head"`
		Rows []map[string]string `json:"rows"`
	}
	if st != 200 || json.Unmarshal([]byte(body), &js) != nil || !strings.HasPrefix(js.Head, target+" 15m: 6 reports") || len(js.Rows) != 1 || js.Rows[0]["reports"] != "6" || js.Rows[0]["top"] != "529" {
		t.Errorf("json twin: %d %s", st, body)
	}
	// Unknown target: 404 with the report hint; malformed: 400.
	if st, body, _ = e.do(t, "GET", "/st/"+uniqueTarget(t), "", ""); st != 404 || !strings.Contains(body, "err notfound no reports for") {
		t.Errorf("unknown target: %d %s", st, body)
	}
	if st, _, _ = e.do(t, "GET", "/st/localhost", "", ""); st != 400 {
		t.Errorf("bad target status %d", st)
	}
}

func TestAnonWeight(t *testing.T) {
	e := newEnv(t)
	target := uniqueTarget(t)
	supA, supB := randSuper(), randSuper()
	for i, ip := range []string{supA + ".1", supA + ".2", supA + ".3", supB + ".1", supB + ".2"} {
		st, body, _ := e.do(t, "POST", "/v1/beacon", "", fmt.Sprintf(`{"target":%q,"sym":"timeout"}`, target), "CF-Connecting-IP", ip, "X-PoW", "ok")
		if st != 201 {
			t.Fatalf("anon beacon %d: %d %s", i, st, body)
		}
	}
	_, body, _ := e.do(t, "GET", "/st/"+target, "", "")
	if !strings.Contains(body, "15m: 1 reports (0 roots, 2 nets) timeoutx5") {
		t.Fatalf("five anonymous beacons weigh one report: %q", body)
	}
	ip := randSuper() + ".9"
	_, tok := newRoot(t, ip)
	e.beaconJSON(t, tok, ip, target, "timeout")
	_, body, _ = e.do(t, "GET", "/st/"+target, "", "")
	if !strings.Contains(body, "15m: 2 reports (1 roots, 3 nets)") {
		t.Errorf("token adds a full report and a root: %q", body)
	}
	// One more anonymous beacon: 2.2 is shown with one decimal.
	e.do(t, "POST", "/v1/beacon", "", fmt.Sprintf(`{"target":%q,"sym":"timeout"}`, target), "CF-Connecting-IP", supA+".4", "X-PoW", "ok")
	_, body, _ = e.do(t, "GET", "/st/"+target, "", "")
	if !strings.Contains(body, "15m: 2.2 reports (1 roots, 3 nets)") {
		t.Errorf("fractional weight: %q", body)
	}
}

func TestCapsAndPow(t *testing.T) {
	e := newEnv(t)
	target := uniqueTarget(t)
	body := fmt.Sprintf(`{"target":%q,"sym":"529"}`, target)
	// Anonymous without a proof: 401 plus the stateless PoW challenge header.
	st, out, h := e.do(t, "POST", "/v1/beacon", "", body)
	if st != 401 || !strings.HasPrefix(out, "err auth") {
		t.Fatalf("no pow: %d %s", st, out)
	}
	if !strings.Contains(strings.Join(h.Values("WWW-Authenticate"), " "), `PoW realm="w"`) {
		t.Errorf("WWW-Authenticate: %v", h.Values("WWW-Authenticate"))
	}
	if st, out, _ = e.do(t, "POST", "/v1/beacon", "", body, "X-PoW", "nope"); st != 400 || !strings.HasPrefix(out, "err pow") {
		t.Errorf("bad pow: %d %s", st, out)
	}
	// Anonymous group cap, then the 4x super-group cap.
	defer func(a, r int, m int64) { AnonDaily, RootDaily, MaxLive = a, r, m }(AnonDaily, RootDaily, MaxLive)
	AnonDaily = 2
	g := randSuper() + ".1"
	for i := 0; i < 2; i++ {
		if st, out, _ = e.do(t, "POST", "/v1/beacon", "", body, "CF-Connecting-IP", g, "X-PoW", "ok"); st != 201 {
			t.Fatalf("anon %d: %d %s", i, st, out)
		}
	}
	if st, out, _ = e.do(t, "POST", "/v1/beacon", "", body, "CF-Connecting-IP", g, "X-PoW", "ok"); st != 429 || !strings.HasPrefix(out, "err quota") {
		t.Errorf("3rd anon from one group: %d %s", st, out)
	}
	AnonDaily = 1
	sup := randSuper()
	for i := 1; i <= 4; i++ {
		if st, out, _ = e.do(t, "POST", "/v1/beacon", "", body, "CF-Connecting-IP", fmt.Sprintf("%s.%d", sup, i), "X-PoW", "ok"); st != 201 {
			t.Fatalf("super group %d: %d %s", i, st, out)
		}
	}
	if st, out, _ = e.do(t, "POST", "/v1/beacon", "", body, "CF-Connecting-IP", sup+".5", "X-PoW", "ok"); st != 429 {
		t.Errorf("5th group of one /24 at 4x: %d %s", st, out)
	}
	// Root cap, flat (not x5 for established roots).
	RootDaily = 2
	ip := randSuper() + ".7"
	id, tok := newRoot(t, ip)
	testPool.Exec(context.Background(), `UPDATE identities SET rep = 10, created = now() - interval '10 days' WHERE id = $1`, id)
	for i := 0; i < 2; i++ {
		e.beaconJSON(t, tok, ip, target, "529")
	}
	if st, out, _ = e.do(t, "POST", "/v1/beacon", tok, body, "CF-Connecting-IP", ip); st != 429 || !strings.HasPrefix(out, "err quota") {
		t.Errorf("3rd token beacon: %d %s", st, out)
	}
	// Per-super admission share (27.8): 2 % of the live cap.
	RootDaily = 60
	MaxLive = 100
	sup = randSuper()
	_, tok2 := newRoot(t, sup+".1")
	for i := 1; i <= 2; i++ {
		e.beaconJSON(t, tok2, fmt.Sprintf("%s.%d", sup, i), target, "slow")
	}
	if st, out, _ = e.do(t, "POST", "/v1/beacon", tok2, body, "CF-Connecting-IP", sup+".3"); st != 429 || !strings.Contains(out, "beacon share") {
		t.Errorf("share cap: %d %s", st, out)
	}
	// Input validation.
	for _, c := range []struct{ body, want string }{
		{`{"target":"localhost","sym":"529"}`, "err bad"},
		{fmt.Sprintf(`{"target":%q,"sym":"up"}`, target), "err bad sym"},
		{fmt.Sprintf(`{"target":%q,"sym":"529","note":%q}`, target, strings.Repeat("x", 121)), "err bad note"},
		{fmt.Sprintf(`{"target":%q,"sym":"529","note":"a\nb"}`, target), "err bad note"},
		{fmt.Sprintf(`{"target":%q,"sym":"529","note":"token cx_%s"}`, target, strings.Repeat("A", 43)), "err scrub"},
		{fmt.Sprintf(`{"target":%q,"sym":"529","pow":"x"}`, target), "err bad pow"},
	} {
		if st, out, _ = e.do(t, "POST", "/v1/beacon", tok2, c.body, "CF-Connecting-IP", sup+".9"); st != 400 || !strings.HasPrefix(out, c.want) {
			t.Errorf("%s: %d %s", c.body, st, out)
		}
	}
	// Frozen writes.
	e.d.SetFreeze(context.Background(), "write", true)
	if st, out, _ = e.do(t, "POST", "/v1/beacon", tok2, body, "CF-Connecting-IP", sup+".9"); st != 503 || !strings.HasPrefix(out, "err frozen") {
		t.Errorf("frozen: %d %s", st, out)
	}
	e.d.SetFreeze(context.Background(), "write", false)
}

func TestTopList(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	testPool.Exec(ctx, `DELETE FROM beacons`)
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM beacons WHERE target LIKE 'top%.example.net'`) })
	var targets []string
	for i := 1; i <= 22; i++ {
		target := fmt.Sprintf("top%02d.example.net", i)
		targets = append(targets, target)
		if _, err := testPool.Exec(ctx, `INSERT INTO beacons (target, sym, root, ipgroup, ipsuper, created)
			SELECT $1, '5xx', 'r' || g, '10.' || $2::text || '.' || g || '.1', '10.' || $2::text || '.' || g || '.0/24', now() - interval '1 minute'
			FROM generate_series(1, $3) g`, target, fmt.Sprint(100+i), 30+i); err != nil {
			t.Fatal(err)
		}
	}
	st, body, _ := e.do(t, "GET", "/st", "", "")
	if st != 200 {
		t.Fatalf("GET /st: %d %s", st, body)
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if lines[0] != "st n=20 window=15m cols: target reports roots nets base/h" {
		t.Errorf("head: %q", lines[0])
	}
	rows := lines[1 : len(lines)-1]
	if len(rows) != 20 || !strings.HasPrefix(lines[len(lines)-1], "next: ") {
		t.Fatalf("rows=%d body:\n%s", len(rows), body)
	}
	// Row i is target 22-i with n = 52-i distinct nets, roots and reports and a baseline of n/24 per hour.
	for i, r := range rows {
		n := 52 - i
		if want := fmt.Sprintf("%s %d %d %d %s", targets[21-i], n, n, n, num(float64(n)/24)); r != want {
			t.Errorf("row %d = %q, want %q", i, r, want)
			break
		}
	}
	if rows[0] != "top22.example.net 52 52 52 2.2" {
		t.Errorf("first row %q", rows[0])
	}
	if rows[19] != "top03.example.net 33 33 33 1.4" {
		t.Errorf("20th row %q", rows[19])
	}
	if verdictRe.MatchString(body) {
		t.Errorf("verdict word in /st: %s", body)
	}
	// Hidden targets leave the list; the JSON twin keeps 20 rows.
	testPool.Exec(ctx, `INSERT INTO st_hidden (target) VALUES ('top22.example.net') ON CONFLICT DO NOTHING`)
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM st_hidden WHERE target = 'top22.example.net'`) })
	st, body, _ = e.do(t, "GET", "/st.json", "", "")
	var js struct {
		Rows []map[string]string `json:"rows"`
	}
	if st != 200 || json.Unmarshal([]byte(body), &js) != nil || len(js.Rows) != 20 || js.Rows[0]["target"] != "top21.example.net" || js.Rows[0]["nets"] != "51" {
		t.Errorf("/st.json after hide: %d %s", st, body)
	}
	// HTML is a CollectionPage linking every target.
	st, body, _ = e.do(t, "GET", "/st.html", "", "")
	if st != 200 || !strings.Contains(body, `"@type":"CollectionPage"`) || !strings.Contains(body, `href="/st/top21.example.net"`) {
		t.Errorf("/st.html: %d %s", st, body)
	}
}

func TestCacheAndJanitor(t *testing.T) {
	e := newEnv(t)
	target := uniqueTarget(t)
	defer func(d time.Duration) { CacheTTL = d }(CacheTTL)
	CacheTTL = 400 * time.Millisecond
	ip := randSuper() + ".1"
	_, tok := newRoot(t, ip)
	e.beaconJSON(t, tok, ip, target, "529")
	_, body, _ := e.do(t, "GET", "/st/"+target, "", "")
	if !strings.Contains(body, "15m: 1 reports (1 roots, 1 nets)") {
		t.Fatalf("first read: %q", body)
	}
	e.beaconJSON(t, tok, ip, target, "529")
	if _, body, _ = e.do(t, "GET", "/st/"+target, "", ""); !strings.Contains(body, "15m: 1 reports") {
		t.Errorf("second read within the TTL should be served from the cache: %q", body)
	}
	time.Sleep(450 * time.Millisecond)
	if _, body, _ = e.do(t, "GET", "/st/"+target, "", ""); !strings.Contains(body, "15m: 2 reports (1 roots, 1 nets)") {
		t.Errorf("read after the TTL: %q", body)
	}
	// Janitor: rows older than 72 h are rolled up into st_hourly, then deleted.
	ctx := context.Background()
	insert(t, target, "timeout", "rold", "10.9.9.9", 73*time.Hour)
	if err := Janitor(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	var live int
	testPool.QueryRow(ctx, `SELECT count(*) FROM beacons WHERE target = $1 AND created < now() - interval '72 hours'`, target).Scan(&live)
	var reports float64
	var roots, nets int
	var syms string
	err := testPool.QueryRow(ctx, `SELECT reports::float8, roots, nets, syms::text FROM st_hourly WHERE target = $1 AND hour = date_trunc('hour', now() - interval '73 hours')`, target).Scan(&reports, &roots, &nets, &syms)
	if live != 0 || err != nil || reports != 1 || roots != 1 || nets != 1 || syms != `{"timeout": 1}` {
		t.Errorf("rollup: live=%d err=%v reports=%v roots=%d nets=%d syms=%s", live, err, reports, roots, nets, syms)
	}
	// Recent rows stay live and are not touched by the janitor.
	testPool.QueryRow(ctx, `SELECT count(*) FROM beacons WHERE target = $1`, target).Scan(&live)
	if live != 2 {
		t.Errorf("live rows after janitor = %d, want 2", live)
	}
}

func TestHourlyRollupAndRetention(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	target := uniqueTarget(t)
	a, b, c := randSuper()+".1", randSuper()+".1", randSuper()+".1"
	insert(t, target, "529", "r1", a, 50*time.Hour)
	insert(t, target, "529", "r2", b, 50*time.Hour)
	insert(t, target, "529", "", c, 50*time.Hour)
	insert(t, target, "timeout", "r1", a, 50*time.Hour)
	if err := Janitor(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	var reports float64
	var roots, nets int
	var syms string
	q := `SELECT reports::float8, roots, nets, syms::text FROM st_hourly WHERE target = $1 AND hour = date_trunc('hour', now() - interval '50 hours')`
	if err := testPool.QueryRow(ctx, q, target).Scan(&reports, &roots, &nets, &syms); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%.1f", reports) != "3.2" || roots != 2 || nets != 3 || syms != `{"529": 3, "timeout": 1}` {
		t.Errorf("hourly bucket: reports=%v roots=%d nets=%d syms=%s", reports, roots, nets, syms)
	}
	// A bucket is never lowered: a partially deleted hour keeps its complete counts.
	testPool.Exec(ctx, `DELETE FROM beacons WHERE target = $1 AND root IS NULL`, target)
	if err := Janitor(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	testPool.QueryRow(ctx, q, target).Scan(&reports, &roots, &nets, &syms)
	if fmt.Sprintf("%.1f", reports) != "3.2" || nets != 3 || syms != `{"529": 3, "timeout": 1}` {
		t.Errorf("bucket lowered: reports=%v nets=%d syms=%s", reports, nets, syms)
	}
	// Retention: 90 d.
	hourly(t, target, 91*24*time.Hour, 4, 4, 4, `{"5xx": 4}`)
	hourly(t, target, 80*24*time.Hour, 4, 4, 4, `{"5xx": 4}`)
	if err := Janitor(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	var old, kept int
	testPool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE hour < now() - interval '90 days'), count(*) FILTER (WHERE hour > now() - interval '81 days' AND hour < now() - interval '79 days') FROM st_hourly WHERE target = $1`, target).Scan(&old, &kept)
	if old != 0 || kept != 1 {
		t.Errorf("retention: old=%d kept=%d", old, kept)
	}
	// Series merges live hours and rolled-up hours without duplicates, newest first.
	pts, err := Series(ctx, testPool, target, 3000)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[time.Time]bool{}
	for i, p := range pts {
		if seen[p.Hour] {
			t.Errorf("duplicate hour %s", p.Hour)
		}
		seen[p.Hour] = true
		if i > 0 && !p.Hour.Before(pts[i-1].Hour) {
			t.Errorf("series not newest first at %d", i)
		}
	}
	// The complete rolled-up bucket (3.2 reports) wins over the thinned live rows (3.0).
	h50 := time.Now().UTC().Add(-50 * time.Hour).Truncate(time.Hour)
	if len(pts) != 2 || !pts[0].Hour.Equal(h50) || fmt.Sprintf("%.1f", pts[0].Reports) != "3.2" || pts[0].Roots != 2 || pts[0].Nets != 3 || pts[0].Syms["529"] != 3 || pts[0].Syms["timeout"] != 1 {
		t.Errorf("series: %+v", pts)
	}
	// The day table shows that day: reports summed, roots/nets of the busiest hour, top symptom.
	day := h50.Format("2006-01-02")
	_, body, _ := e.do(t, "GET", "/st/"+target, "", "")
	if !strings.Contains(body, "\n"+day+" 3.2 2 3 529\n") {
		t.Errorf("day row for %s missing: %q", day, body)
	}
}

func TestIndexablePredicateSevenDaysFiveSupers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	seven := uniqueTarget(t)
	for i := 1; i <= 7; i++ {
		hourly(t, seven, time.Duration(i)*24*time.Hour, 6, 5, 5, `{"529": 6}`)
	}
	if ok, err := Indexable(ctx, testPool, seven); err != nil || !ok {
		t.Fatalf("7 days x 5 nets: %v %v", ok, err)
	}
	st, body, h := e.do(t, "GET", "/st/"+seven+".html", "", "")
	if st != 200 || h.Get("X-Robots-Tag") != "" || !strings.Contains(body, `<meta name="robots" content="index,follow`) {
		t.Errorf("indexable page: %d robots=%q body=%s", st, h.Get("X-Robots-Tag"), body)
	}
	six := uniqueTarget(t)
	for i := 1; i <= 6; i++ {
		hourly(t, six, time.Duration(i)*24*time.Hour, 6, 5, 5, `{"529": 6}`)
	}
	if ok, _ := Indexable(ctx, testPool, six); ok {
		t.Error("6 days must not be indexable")
	}
	st, body, h = e.do(t, "GET", "/st/"+six+".html", "", "")
	if st != 200 || h.Get("X-Robots-Tag") != "noindex, follow" || !strings.Contains(body, `<meta name="robots" content="noindex">`) {
		t.Errorf("non-indexable page: %d robots=%q", st, h.Get("X-Robots-Tag"))
	}
	four := uniqueTarget(t)
	for i := 1; i <= 7; i++ {
		hourly(t, four, time.Duration(i)*24*time.Hour, 6, 5, 4, `{"529": 6}`)
	}
	if ok, _ := Indexable(ctx, testPool, four); ok {
		t.Error("4 nets per day must not be indexable")
	}
	// Live rows count with exact daily distinct nets: 4 rolled-up days + 3 live days.
	mixed := uniqueTarget(t)
	for i := 4; i <= 7; i++ {
		hourly(t, mixed, time.Duration(i)*24*time.Hour, 6, 5, 5, `{"529": 6}`)
	}
	for day := 0; day < 3; day++ {
		for n := 0; n < 5; n++ {
			insert(t, mixed, "529", "", randSuper()+".1", time.Duration(day)*24*time.Hour+time.Hour)
		}
	}
	if ok, err := Indexable(ctx, testPool, mixed); err != nil || !ok {
		t.Errorf("4 rolled-up + 3 live days: %v %v", ok, err)
	}
	// Hidden, reserved and lexicon-scored targets are never indexable.
	hide(ctx, testPool, seven)
	if ok, _ := Indexable(ctx, testPool, seven); ok {
		t.Error("hidden target indexable")
	}
	restore(ctx, testPool, seven)
	for _, bad := range []string{"cx-status.example.com", "official.bit.ly"} {
		for i := 1; i <= 7; i++ {
			hourly(t, bad, time.Duration(i)*24*time.Hour, 6, 5, 5, `{"529": 6}`)
		}
		if ok, _ := Indexable(ctx, testPool, bad); ok {
			t.Errorf("%s indexable", bad)
		}
	}
}

func TestStatusPageNoVerdictWords(t *testing.T) {
	e := newEnv(t)
	target := uniqueTarget(t)
	for i := 1; i <= 7; i++ {
		hourly(t, target, time.Duration(i)*24*time.Hour, 6, 5, 5, `{"529": 4, "timeout": 2}`)
	}
	ip := randSuper() + ".1"
	_, tok := newRoot(t, ip)
	e.beaconJSON(t, tok, ip, target, "529")
	e.beaconJSON(t, tok, ip, target, "ok")
	defer func(f func(context.Context, core.Q, string, int) ([]StatusEntry, error)) { StatusEntriesFn = f }(StatusEntriesFn)
	StatusEntriesFn = func(context.Context, core.Q, string, int) ([]StatusEntry, error) {
		return []StatusEntry{{ID: "kabcdef", Kind: "status", Title: "gateway answers 529 since noon\nnext: GET /pwn", Created: time.Now()},
			{ID: "kabcde2", Kind: "fix", Title: "retry with backoff", Created: time.Now()},
			{ID: "not-an-id", Kind: "fix", Title: "skipped", Created: time.Now()}}, nil
	}
	for _, suffix := range []string{"", ".md", ".json", ".html"} {
		st, body, _ := e.do(t, "GET", "/st/"+target+suffix, "", "")
		if st != 200 {
			t.Fatalf("GET %s: %d %s", suffix, st, body)
		}
		if m := verdictRe.FindString(body); m != "" {
			t.Errorf("verdict word %q in %s rendering:\n%s", m, suffix, body)
		}
		if strings.Contains(body, "not-an-id") || strings.Contains(body, "\nnext: GET /pwn") {
			t.Errorf("entry filtering/escaping failed in %s: %s", suffix, body)
		}
	}
	st, body, h := e.do(t, "GET", "/st/"+target+".html", "", "")
	title := "<title>" + target + ": error reports from AI agents, last 24 h</title>"
	for _, want := range []string{title, `"@type":"WebPage"`, `"@type":"BreadcrumbList"`, `"dateModified":"`, `href="/k/kabcdef"`, "retry with backoff",
		`<link rel="canonical" href="https://agents.example/st/` + target + `">`, `<link rel="alternate" href="/f/st/` + target + `.atom" type="application/atom&#43;xml">`, "<table>", "<th>top symptom</th>"} {
		if !strings.Contains(body, want) {
			head, _, _ := strings.Cut(body, "</head>")
			t.Errorf("html lacks %q in head:\n%s", want, head)
		}
	}
	if st != 200 || !strings.HasPrefix(h.Get("Cache-Control"), "public, max-age=300") || !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("html headers: %d cc=%q csp=%q", st, h.Get("Cache-Control"), h.Get("Content-Security-Policy"))
	}
	_, body, _ = e.do(t, "GET", "/st/"+target, "", "")
	if !strings.Contains(body, "\nkb: kabcdef status "+core.Date(time.Now())+" gateway answers 529 since noon next: GET /pwn\n") {
		t.Errorf("kb line: %q", body)
	}
	if !strings.Contains(body, "15m: 2 reports (1 roots, 1 nets) 529x1 okx1 | 1h: 2 (1 roots, 1 nets) | 24h baseline 0.1/h | last ok <1m ago") {
		t.Errorf("head: %q", body)
	}
	if n := strings.Count(body, "\n"+time.Now().UTC().Add(-24*time.Hour).Format("2006-01-02")+" 6 5 5 529\n"); n != 1 {
		t.Errorf("yesterday's row: %q", body)
	}
	_, body, _ = e.do(t, "GET", "/st/"+target+".md", "", "")
	if !strings.HasPrefix(body, "# "+target+": error reports from AI agents, last 24 h\n") || !strings.Contains(body, "permalink: https://agents.example/st/"+target) {
		t.Errorf("md: %q", body)
	}
	// The write reply and the post-write page say numbers only too.
	out := e.beaconJSON(t, tok, ip, target, "5xx")
	if verdictRe.MatchString(out) {
		t.Errorf("verdict word in write reply: %s", out)
	}
}

func TestStHiddenAdmin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	target := uniqueTarget(t)
	ip := randSuper() + ".1"
	_, tok := newRoot(t, ip)
	e.beaconJSON(t, tok, ip, target, "529")
	for i := 1; i <= 7; i++ {
		hourly(t, target, time.Duration(i)*24*time.Hour, 6, 5, 5, `{"529": 6}`)
	}
	body := fmt.Sprintf(`{"target":%q}`, target)
	if st, out, _ := e.do(t, "POST", "/admin/st-hide", "", body); st != 401 || !strings.HasPrefix(out, "err auth admin") {
		t.Errorf("no admin token: %d %s", st, out)
	}
	if st, out, _ := e.do(t, "POST", "/admin/st-hide", "wrong", body); st != 401 {
		t.Errorf("wrong admin token: %d %s", st, out)
	}
	st, out, _ := e.do(t, "POST", "/admin/st-hide", "adm-token", body)
	if st != 200 || !strings.HasPrefix(out, "ok st:"+target+" hidden=1\n") {
		t.Fatalf("hide: %d %s", st, out)
	}
	if hidden, _ := isHidden(ctx, testPool, target); !hidden {
		t.Error("st_hidden row missing")
	}
	st, out, h := e.do(t, "GET", "/st/"+target, "", "")
	if st != 200 || !strings.Contains(out, "last ok never hidden\n") || h.Get("X-Robots-Tag") != "noindex, follow" {
		t.Errorf("hidden page: %d robots=%q %s", st, h.Get("X-Robots-Tag"), out)
	}
	if _, out, _ = e.do(t, "GET", "/st", "", ""); strings.Contains(out, target) {
		t.Error("hidden target listed in /st")
	}
	if items, err := e.d.Feeds()["st"](ctx, target, 10); err != nil || len(items) != 0 {
		t.Errorf("hidden target feed: %d items, %v", len(items), err)
	}
	if urls, err := e.d.Sitemaps()["st"](ctx); err != nil || strings.Contains(fmt.Sprint(urls), target) {
		t.Errorf("hidden target in sitemap: %v %v", urls, err)
	}
	st, out, _ = e.do(t, "POST", "/admin/st-hide", "adm-token", fmt.Sprintf(`{"target":%q,"restore":true}`, target))
	if st != 200 || !strings.HasPrefix(out, "ok st:"+target+" hidden=0\n") {
		t.Fatalf("restore: %d %s", st, out)
	}
	if _, out, _ = e.do(t, "GET", "/st", "", ""); !strings.Contains(out, target) {
		t.Error("restored target absent from /st")
	}
	// Report target hooks (4.7).
	tg, ok := e.d.Target("st")
	if !ok {
		t.Fatal("report target st not registered")
	}
	if err := tg.Exists(ctx, testPool, uniqueTarget(t)); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("exists(unknown) = %v", err)
	}
	if err := tg.Exists(ctx, testPool, target); err != nil {
		t.Errorf("exists = %v", err)
	}
	if err := tg.Hide(ctx, testPool, target); err != nil {
		t.Fatal(err)
	}
	if hidden, _ := isHidden(ctx, testPool, target); !hidden {
		t.Error("report hide did not hide")
	}
	if err := tg.Restore(ctx, testPool, target); err != nil {
		t.Fatal(err)
	}
	if hidden, _ := isHidden(ctx, testPool, target); hidden {
		t.Error("report restore did not restore")
	}
}

func TestStSitemapChild(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	indexable, plain := uniqueTarget(t), uniqueTarget(t)
	for i := 1; i <= 7; i++ {
		hourly(t, indexable, time.Duration(i)*24*time.Hour, 6, 5, 5, `{"529": 6}`)
	}
	hourly(t, plain, 24*time.Hour, 6, 5, 5, `{"529": 6}`)
	fn := e.d.Sitemaps()["st"]
	if fn == nil {
		t.Fatal("sitemap st not registered")
	}
	urls, err := fn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, u := range urls {
		if strings.HasSuffix(u.Loc, "/st/"+plain) {
			t.Errorf("non-indexable target in sitemap: %s", u.Loc)
		}
		if u.Loc == "https://agents.example/st/"+indexable {
			found = true
			if want := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Hour); !u.LastMod.Equal(want) {
				t.Errorf("lastmod %s, want %s (last hour bucket with reports)", u.LastMod, want)
			}
		}
	}
	if !found {
		t.Errorf("indexable target missing from sitemap: %v", urls)
	}
}

func TestFeedSourceAndSeries(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	target := uniqueTarget(t)
	ip := randSuper() + ".1"
	_, tok := newRoot(t, ip)
	e.beaconJSON(t, tok, ip, target, "timeout")
	e.beaconJSON(t, tok, ip, target, "529")
	hourly(t, target, 5*24*time.Hour, 3, 3, 3, `{"5xx": 3}`)
	fn := e.d.Feeds()["st"]
	if fn == nil {
		t.Fatal("feed st not registered")
	}
	items, err := fn(ctx, target, 20)
	if err != nil || len(items) != 2 {
		t.Fatalf("feed items: %d %v", len(items), err)
	}
	now := time.Now().UTC().Truncate(time.Hour)
	first := items[0]
	if first.URL != "/st/"+target || first.ID != fmt.Sprintf("st/%s/%d", target, now.Unix()) || !first.Published.Equal(now) {
		t.Errorf("first item: %+v", first)
	}
	if !strings.HasPrefix(first.Title, target+" "+now.Format("2006-01-02 15:00 UTC")+": 2 reports (1 roots, 1 nets)") || !strings.HasPrefix(first.Summary, "529x1 timeoutx1;") {
		t.Errorf("first item text: %q / %q", first.Title, first.Summary)
	}
	if items[1].Title != fmt.Sprintf("%s %s: 3 reports (3 roots, 3 nets)", target, now.Add(-5*24*time.Hour).Format("2006-01-02 15:00 UTC")) {
		t.Errorf("rolled-up item: %q", items[1].Title)
	}
	for _, it := range items {
		if verdictRe.MatchString(it.Title + it.Summary) {
			t.Errorf("verdict word in feed item %q", it.Title)
		}
	}
	if items, err := fn(ctx, "", 50); err != nil || len(items) == 0 {
		t.Errorf("top feed: %d %v", len(items), err)
	}
	if _, err := fn(ctx, "localhost", 10); !errors.Is(err, core.ErrNotFound) {
		t.Errorf("bad sub: %v", err)
	}
}

func TestOpsStBc(t *testing.T) {
	e := newEnv(t)
	ops := Ops(e.d)
	for _, name := range []string{"st", "bc"} {
		if ops[name] == nil || OpMeta[name].Cost <= 0 {
			t.Fatalf("op %s missing or without meta", name)
		}
	}
	if !OpMeta["bc"].Mutating || OpMeta["bc"].Scope != "kb:w" || OpMeta["st"].Mutating {
		t.Errorf("OpMeta: %+v", OpMeta)
	}
	target := uniqueTarget(t)
	ip := randSuper() + ".1"
	_, tok := newRoot(t, ip)
	ctx := core.WithClient(context.Background(), ip, core.IPGroup(ip), core.IPSuper(ip))
	id, err := e.d.LookupToken(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ops["bc"](ctx, id, json.RawMessage(fmt.Sprintf(`{"target":%q,"sym":"auth","note":"401 on every call"}`, target)))
	if err != nil || out != fmt.Sprintf("ok %s auth 15m: 1 reports (1 roots, 1 nets)", target) {
		t.Errorf("bc: %q %v", out, err)
	}
	if _, err := ops["bc"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"target":%q,"sym":"auth"}`, target))); !errors.Is(err, core.ErrAuth) {
		t.Errorf("anonymous bc without pow: %v", err)
	}
	anon := randSuper() + ".2"
	actx := core.WithClient(context.Background(), anon, core.IPGroup(anon), core.IPSuper(anon))
	if out, err := ops["bc"](actx, nil, json.RawMessage(fmt.Sprintf(`{"target":%q,"sym":"auth","pow":"ok"}`, target))); err != nil || out != fmt.Sprintf("ok %s auth 15m: 1.2 reports (1 roots, 2 nets)", target) {
		t.Errorf("anonymous bc with pow: %q %v", out, err)
	}
	if _, err := ops["bc"](actx, nil, json.RawMessage(fmt.Sprintf(`{"target":%q,"sym":"auth","pow":"bad"}`, target))); err == nil {
		t.Error("bad pow accepted")
	}
	out, err = ops["st"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"target":%q}`, target)))
	if err != nil || !strings.HasPrefix(out, target+" 15m: 1.2 reports (1 roots, 2 nets) authx2 | 1h: 1.2 (1 roots, 2 nets)") {
		t.Errorf("st: %q %v", out, err)
	}
	out, err = ops["st"](ctx, nil, nil)
	if err != nil || !strings.HasPrefix(out, "st n=") || !strings.Contains(out, target+" 1.2 1 2 ") {
		t.Errorf("st top: %q %v", out, err)
	}
	if _, err := ops["st"](ctx, nil, json.RawMessage(`{"target":"x.example.org"}`)); err == nil {
		t.Error("st on an unknown target should be notfound")
	}
}

func TestEvictionBySuperShare(t *testing.T) {
	ctx := context.Background()
	testPool.Exec(ctx, `DELETE FROM beacons`)
	defer func(m int64) { MaxLive = m }(MaxLive)
	MaxLive = 20
	a, b := randSuper(), randSuper()
	target := uniqueTarget(t)
	for i := 0; i < 14; i++ {
		insert(t, target, "529", fmt.Sprintf("ra%d", i), fmt.Sprintf("%s.%d", a, i+1), time.Duration(14-i)*time.Minute)
	}
	for i := 0; i < 8; i++ {
		insert(t, target, "529", fmt.Sprintf("rb%d", i), fmt.Sprintf("%s.%d", b, i+1), time.Duration(8-i)*time.Minute)
	}
	if err := Evict(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	var na, nb, total int
	testPool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE ipsuper = $1), count(*) FILTER (WHERE ipsuper = $2), count(*) FROM beacons`, core.IPSuper(a+".1"), core.IPSuper(b+".1")).Scan(&na, &nb, &total)
	if total != 18 || na != 10 || nb != 8 {
		t.Errorf("after eviction: a=%d b=%d total=%d (want 10, 8, 18)", na, nb, total)
	}
	// The oldest rows of the largest super-group went first.
	var oldest string
	testPool.QueryRow(ctx, `SELECT root FROM beacons WHERE ipsuper = $1 ORDER BY created LIMIT 1`, core.IPSuper(a+".1")).Scan(&oldest)
	if oldest != "ra4" {
		t.Errorf("oldest surviving row of a = %s, want ra4", oldest)
	}
	// Below 95 % nothing moves.
	if err := Evict(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	testPool.QueryRow(ctx, `SELECT count(*) FROM beacons`).Scan(&total)
	if total != 18 {
		t.Errorf("second eviction changed the table: %d", total)
	}
	if ShareCap() != 1 {
		t.Errorf("ShareCap at MaxLive=20 = %d, want 1 (2 %%, floor 1)", ShareCap())
	}
}
