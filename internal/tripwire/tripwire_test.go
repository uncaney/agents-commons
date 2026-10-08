package tripwire

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"image/png"
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
	"ekaii.fr/commons/internal/trust"
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
	} else if pool, done := testdb.Open("tripwire", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping tripwire DB tests")
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
	id, token, err := core.CreateRoot(context.Background(), testPool, "tripwire-test", ip)
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

var mintRe = regexp.MustCompile(`ok (y[a-z2-7]{6}) url=https://agents\.example/y/([A-Za-z0-9_-]{22,64}) read=([A-Za-z0-9_-]{16,64})\nexpires: (\d{4}-\d{2}-\d{2})`)

// mint posts one tripwire with a token and returns its id, secret and read key.
func (e *tenv) mint(t *testing.T, token, body string) (id, secret, rkey string) {
	t.Helper()
	st, b, _ := e.do(t, "POST", "/v1/tw", token, body)
	if st != 201 {
		t.Fatalf("mint: %d %s", st, b)
	}
	m := mintRe.FindStringSubmatch(b)
	if m == nil {
		t.Fatalf("mint reply: %q", b)
	}
	return m[1], m[2], m[3]
}

func count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

var rowRe = regexp.MustCompile(`(?m)^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}Z (browser|bot|agent|curl|unknown) net=[0-9a-f]{4}$`)

func TestUAClassAndTexts(t *testing.T) {
	cases := map[string]string{
		"":                       "unknown",
		"EvilUA/9.9 (XYZZY)":     "unknown",
		"curl/8.4.0":             "curl",
		"Wget/1.21.4":            "curl",
		"HTTPie/3.2":             "curl",
		"Go-http-client/1.1":     "agent",
		"python-requests/2.31.0": "agent",
		"axios/1.6.0":            "agent",
		"claude-code/1.0":        "agent",
		"ClaudeBot/1.0 (+https://www.anthropic.com/claude-bot)":                                                                  "bot",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                                               "bot",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36":            "browser",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15":     "browser",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Slack/23": "browser",
		"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)":                                                             "bot",
	}
	valid := map[string]bool{}
	for _, c := range Classes {
		valid[c] = true
	}
	for ua, want := range cases {
		got := UAClass(ua)
		if got != want {
			t.Errorf("UAClass(%q) = %s, want %s", ua, got, want)
		}
		if !valid[got] {
			t.Errorf("UAClass(%q) = %s not in Classes", ua, got)
		}
	}
	for _, p := range uaPrefixes {
		if !valid[p.class] || p.prefix != strings.ToLower(p.prefix) {
			t.Errorf("prefix table entry %q -> %s", p.prefix, p.class)
		}
	}
	if !json.Valid(openAPI) {
		t.Error("openAPI fragment is not valid JSON")
	}
	if len(Help) > 800 {
		t.Errorf("Help is %d bytes (> 200 tokens)", len(Help))
	}
	if _, err := png.Decode(bytes.NewReader(png1x1)); err != nil {
		t.Errorf("png1x1: %v", err)
	}
}

func TestMintAndTrigger(t *testing.T) {
	e := newEnv(t)
	root, tok := newRoot(t, randIP("10.8"))
	id, secret, rkey := e.mint(t, tok, `{"note":"prod .env","ttl_h":48}`)
	if len(secret) != 32 || len(rkey) != 24 {
		t.Errorf("secret %q rkey %q lengths", secret, rkey)
	}
	var exp time.Time
	var h, rh []byte
	if err := testPool.QueryRow(context.Background(), `SELECT expires_at, h, rh FROM tripwires WHERE id = $1 AND root = $2`, id, root).Scan(&exp, &h, &rh); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp); d < 47*time.Hour || d > 49*time.Hour {
		t.Errorf("expires in %v, want ~48h", d)
	}
	if !bytes.Equal(h, hash(secret)) || !bytes.Equal(rh, hash(rkey)) {
		t.Error("stored hashes do not match the minted secret and read key")
	}
	if n := count(t, `SELECT count(*) FROM tripwires t WHERE t::text LIKE '%'||$1||'%' OR t::text LIKE '%'||$2||'%'`, secret, rkey); n != 0 {
		t.Error("the secret or read key is stored in clear")
	}
	if n := count(t, `SELECT count(*) FROM audit WHERE op = 'tw' AND ref = $1 AND root = $2`, id, root); n != 1 {
		t.Errorf("audit rows = %d", n)
	}

	// Trigger: 200, empty body, no hit data in the reply.
	st, body, hdr := e.do(t, "GET", "/y/"+secret, "", "")
	if st != 200 || body != "" || hdr.Get("Content-Length") != "0" {
		t.Fatalf("trigger: %d %q cl=%q", st, body, hdr.Get("Content-Length"))
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", hdr.Get("Cache-Control"))
	}
	st, body, _ = e.do(t, "POST", "/y/"+secret, "", "")
	if st != 200 || body != "" {
		t.Fatalf("POST trigger: %d %q", st, body)
	}

	// Owner read.
	st, body, _ = e.do(t, "GET", "/v1/tw/"+id, tok, "")
	today := core.Date(time.Now())
	if st != 200 || !strings.HasPrefix(body, fmt.Sprintf("hits=2 first=%s last=%s\n", today, today)) {
		t.Fatalf("owner read: %d %q", st, body)
	}
	if !strings.Contains(body, "id: "+id+"\n") || !strings.Contains(body, "note: prod .env\n") || !strings.Contains(body, "expires: "+core.Date(exp)+"\n") {
		t.Errorf("owner read fields: %q", body)
	}
	if rows := rowRe.FindAllString(body, -1); len(rows) != 2 || !strings.Contains(rows[0], " agent net=") {
		t.Errorf("hit rows: %q", body)
	}
	st, body, _ = e.do(t, "GET", "/v1/tw/"+id+".json", tok, "")
	if st != 200 || !json.Valid([]byte(body)) || !strings.Contains(body, "hits=2") || !strings.Contains(body, `"ua"`) {
		t.Errorf("json twin: %d %q", st, body)
	}

	// MCP ops share the service layer.
	ops := Ops(e.d)
	ident, err := e.d.LookupToken(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ops["twg"](context.Background(), ident, json.RawMessage(`{"id":"`+id+`"}`))
	if err != nil || !strings.HasPrefix(out, "hits=2 ") || len(rowRe.FindAllString(out, -1)) != 2 {
		t.Errorf("twg: %q %v", out, err)
	}
	if _, err := ops["tw"](context.Background(), nil, json.RawMessage(`{"note":"x"}`)); err != core.ErrAuth {
		t.Errorf("anonymous tw op: %v", err)
	}
	out, err = ops["tw"](context.Background(), ident, json.RawMessage(`{"note":"via mcp","ttl_h":100000}`))
	if err != nil || mintRe.FindStringSubmatch(out) == nil {
		t.Fatalf("tw op: %q %v", out, err)
	}
	m := mintRe.FindStringSubmatch(out)
	var exp2 time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT expires_at FROM tripwires WHERE id = $1`, m[1]).Scan(&exp2); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(exp2); d > maxTTL+time.Hour || d < maxTTL-time.Hour {
		t.Errorf("ttl_h 100000 -> expires in %v, want clamp to %v", d, maxTTL)
	}
	if lines := resume(context.Background(), testPool, root); len(lines) != 1 || lines[0] != "tripwires: 2 live (1 tripped)" {
		t.Errorf("resume lines: %v", lines)
	}

	// Validation.
	for _, bad := range []string{`{"note":"` + strings.Repeat("x", 121) + `"}`, `{"note":"a\nb"}`, `{"ttl_h":-1}`, `{"on_hit":{"ps":"bad topic!"}}`, `{"nope":1}`} {
		if st, body, _ := e.do(t, "POST", "/v1/tw", tok, bad); st != 400 {
			t.Errorf("body %s: %d %s", bad, st, body)
		}
	}
	if st, body, _ := e.do(t, "POST", "/v1/tw", "", `{}`); st != 401 {
		t.Errorf("no token: %d %s", st, body)
	}

	// Live cap: L0 20 (trust.Cap); 2 live so far.
	capN := trust.Cap(capKind, 0)
	for i := 2; i < capN; i++ {
		e.mint(t, tok, `{}`)
	}
	if st, body, _ := e.do(t, "POST", "/v1/tw", tok, `{}`); st != 429 || !strings.Contains(body, "quota") {
		t.Errorf("over live cap: %d %s", st, body)
	}
	// An expired one frees its slot; the janitor deletes it.
	if _, err := testPool.Exec(context.Background(), `UPDATE tripwires SET expires_at = now() - interval '1 minute' WHERE id = $1`, m[1]); err != nil {
		t.Fatal(err)
	}
	e.mint(t, tok, `{}`)
	if err := Janitor(context.Background(), testPool); err != nil {
		t.Fatal(err)
	}
	if n := count(t, `SELECT count(*) FROM tripwires WHERE id = $1`, m[1]); n != 0 {
		t.Error("janitor kept an expired tripwire")
	}
	// Purge removes the root's tripwires.
	if _, err := e.d.Purge(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	if n := count(t, `SELECT count(*) FROM tripwires WHERE root = $1`, root); n != 0 {
		t.Errorf("purge left %d tripwires", n)
	}
}

func TestHitStoresNothingControllable(t *testing.T) {
	e := newEnv(t)
	_, tok := newRoot(t, randIP("10.9"))
	id, secret, _ := e.mint(t, tok, `{"note":"honey"}`)
	ip := "10.77.66.55"
	st, body, _ := e.do(t, "GET", "/y/"+secret+"/EVILSUFFIX/deep/x.css?q=EVILQUERY&cb=XYZZY", "", "",
		"User-Agent", "EvilUA/9.9 (XYZZY)", "Referer", "https://evil.example/EVILREF", "CF-Connecting-IP", ip)
	if st != 200 || body != "" {
		t.Fatalf("trigger: %d %q", st, body)
	}
	var ua string
	var super []byte
	if err := testPool.QueryRow(context.Background(), `SELECT ua_class, super_h FROM tripwire_hits WHERE id = $1`, id).Scan(&ua, &super); err != nil {
		t.Fatal(err)
	}
	if ua != "unknown" {
		t.Errorf("ua_class %q, want unknown (fixed vocabulary, never the string)", ua)
	}
	if len(super) != 16 {
		t.Errorf("super_h is %d bytes", len(super))
	}
	for _, tbl := range []string{"tripwires", "tripwire_hits", "events", "audit", "mail"} {
		for _, needle := range []string{"EVILSUFFIX", "EVILQUERY", "XYZZY", "EvilUA", "EVILREF", "evil.example", ip, "10.77.66", "deep"} {
			if n := count(t, `SELECT count(*) FROM `+tbl+` x WHERE x::text ILIKE '%'||$1||'%'`, needle); n != 0 {
				t.Errorf("%s stores %q", tbl, needle)
			}
		}
	}
	// Same network, same day -> same key; another network -> another key; the key is not a hash of the prefix alone.
	st, _, _ = e.do(t, "GET", "/y/"+secret, "", "", "CF-Connecting-IP", "10.77.66.9")
	if st != 200 {
		t.Fatal(st)
	}
	e.do(t, "GET", "/y/"+secret, "", "", "CF-Connecting-IP", "10.78.1.1")
	var keys [][]byte
	rows, err := testPool.Query(context.Background(), `SELECT super_h FROM tripwire_hits WHERE id = $1 ORDER BY at`, id)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var k []byte
		rows.Scan(&k)
		keys = append(keys, k)
	}
	rows.Close()
	if len(keys) != 3 || !bytes.Equal(keys[0], keys[1]) || bytes.Equal(keys[0], keys[2]) {
		t.Errorf("network keys: %x", keys)
	}
	if bytes.Equal(keys[0], hash(core.IPSuper(ip))[:16]) || bytes.Equal(keys[0], hash(ip)[:16]) {
		t.Error("network key is an unkeyed hash")
	}
	st, body, _ = e.do(t, "GET", "/v1/tw/"+id, tok, "")
	if st != 200 || strings.Contains(body, "EVIL") || strings.Contains(body, "XYZZY") || len(rowRe.FindAllString(body, -1)) != 3 {
		t.Errorf("owner view: %d %q", st, body)
	}
}

func TestPngVariant(t *testing.T) {
	e := newEnv(t)
	_, tok := newRoot(t, randIP("10.10"))
	id, secret, _ := e.mint(t, tok, `{}`)
	// curl -I: HEAD counts as a hit and announces the PNG.
	st, body, hdr := e.do(t, "HEAD", "/y/"+secret+"/x.png", "", "", "User-Agent", "curl/8.4.0")
	if st != 200 || body != "" || hdr.Get("Content-Type") != "image/png" || hdr.Get("Content-Length") != fmt.Sprint(len(png1x1)) {
		t.Fatalf("HEAD png: %d %q %v", st, body, hdr)
	}
	st, body, _ = e.do(t, "GET", "/v1/tw/"+id, tok, "")
	if st != 200 || !strings.HasPrefix(body, "hits=1 ") {
		t.Fatalf("owner view after HEAD: %d %q", st, body)
	}
	if rows := rowRe.FindAllString(body, -1); len(rows) != 1 || !strings.Contains(rows[0], " curl net=") {
		t.Errorf("row after HEAD: %q", body)
	}
	// GET serves the pixel itself.
	st, body, hdr = e.do(t, "GET", "/y/"+secret+"/pixel.png", "", "")
	if st != 200 || hdr.Get("Content-Type") != "image/png" {
		t.Fatalf("GET png: %d %v", st, hdr)
	}
	img, err := png.Decode(strings.NewReader(body))
	if err != nil || img.Bounds().Dx() != 1 || img.Bounds().Dy() != 1 {
		t.Errorf("png body: %v %v", err, img)
	}
	// Other suffixes stay empty.
	st, body, hdr = e.do(t, "GET", "/y/"+secret+"/a/b/c.js", "", "")
	if st != 200 || body != "" || strings.Contains(hdr.Get("Content-Type"), "png") {
		t.Errorf("js suffix: %d %q %q", st, body, hdr.Get("Content-Type"))
	}
	if n := count(t, `SELECT hits FROM tripwires WHERE id = $1`, id); n != 3 {
		t.Errorf("hits = %d, want 3", n)
	}
}

func TestIdentical404(t *testing.T) {
	e := newEnv(t)
	root, tok := newRoot(t, randIP("10.11"))
	_, live, _ := e.mint(t, tok, `{}`)
	expired, expiredID := randB64(24), core.NewID('y')
	if _, err := testPool.Exec(context.Background(), `INSERT INTO tripwires (id, h, rh, root, expires_at) VALUES ($1, $2, $3, $4, now() - interval '1 hour')`,
		expiredID, hash(expired), hash("r"), root); err != nil {
		t.Fatal(err)
	}
	hiddenID, hidden, _ := e.mint(t, tok, `{}`)
	if err := hide(context.Background(), testPool, hiddenID); err != nil {
		t.Fatal(err)
	}
	type reply struct {
		st       int
		body, ct string
	}
	var want *reply
	for _, method := range []string{"GET", "POST"} {
		for _, suffix := range []string{"", "/x.png", "/a/b.json", "/.hits"} {
			for _, secret := range []string{randB64(24), expired, hidden, "short", strings.Repeat("a", 65)} {
				if secret == "short" && suffix != "" {
					continue
				}
				st, body, hdr := e.do(t, method, "/y/"+secret+suffix, "", "", "X-Tripwire-Read", "whatever-key-1234567890")
				got := &reply{st, body, hdr.Get("Content-Type")}
				if want == nil {
					want = got
					if st != 404 || !strings.HasPrefix(body, "err notfound ") {
						t.Fatalf("miss reply: %d %q", st, body)
					}
					continue
				}
				if *got != *want {
					t.Errorf("%s /y/%s%s: %+v differs from %+v", method, secret, suffix, got, want)
				}
			}
		}
	}
	// A miss records nothing (counters and rows alike); the live one is untouched by the misses.
	if n := count(t, `SELECT count(*) FROM tripwire_hits WHERE id IN ($1, $2)`, expiredID, hiddenID); n != 0 {
		t.Errorf("misses recorded %d hits", n)
	}
	if n := count(t, `SELECT sum(hits) FROM tripwires WHERE root = $1`, root); n != 0 {
		t.Errorf("misses bumped a hits counter: %d", n)
	}
	if st, _, _ := e.do(t, "GET", "/y/"+live, "", ""); st != 200 {
		t.Errorf("live: %d", st)
	}
	// Restore reopens the hidden one.
	if err := restore(context.Background(), testPool, hiddenID); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := e.do(t, "GET", "/y/"+hidden, "", ""); st != 200 {
		t.Errorf("restored: %d", st)
	}
	if err := exists(context.Background(), testPool, hiddenID); err != nil {
		t.Errorf("exists: %v", err)
	}
	if err := exists(context.Background(), testPool, "yzzzzzz"); err != core.ErrNotFound {
		t.Errorf("exists unknown: %v", err)
	}
	// Owner reads of someone else's or an unknown id are the same 404 as well.
	_, other := newRoot(t, randIP("10.11"))
	st1, b1, _ := e.do(t, "GET", "/v1/tw/"+hiddenID, other, "")
	st2, b2, _ := e.do(t, "GET", "/v1/tw/yzzzzzz", other, "")
	if st1 != 404 || st1 != st2 || b1 != b2 {
		t.Errorf("owner misses: %d %q / %d %q", st1, b1, st2, b2)
	}
}

func TestAnonymousPowAndQuota(t *testing.T) {
	e := newEnv(t)
	super := randSuper()
	ip := super + ".10"
	secret, rkey := randB64(24), randB64(18)
	// No read key -> 400; no proof -> 401 with the PoW challenge; bad proof -> 400 pow.
	if st, body, _ := e.do(t, "PUT", "/y/"+secret, "", "", "CF-Connecting-IP", ip); st != 400 || !strings.Contains(body, readHeader) {
		t.Errorf("no read key: %d %s", st, body)
	}
	st, body, hdr := e.do(t, "PUT", "/y/"+secret, "", "", "CF-Connecting-IP", ip, readHeader, rkey)
	if st != 401 || !strings.Contains(strings.Join(hdr.Values("WWW-Authenticate"), " "), `PoW realm="w"`) {
		t.Errorf("no proof: %d %s %v", st, body, hdr.Values("WWW-Authenticate"))
	}
	if st, body, _ := e.do(t, "PUT", "/y/"+secret, "", "", "CF-Connecting-IP", ip, readHeader, rkey, "X-PoW", "bad"); st != 400 || !strings.Contains(body, "pow") {
		t.Errorf("bad proof: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "PUT", "/y/not-a-secret", "", "", "CF-Connecting-IP", ip, readHeader, rkey, "X-PoW", "ok"); st != 400 {
		t.Errorf("bad secret: %d %s", st, body)
	}
	// Anonymous mint: 7 d, root '', on_hit ignored, the read key is the caller's.
	st, body, _ = e.do(t, "PUT", "/y/"+secret+"?note=anon+canary", "", `{"on_hit":{"ps":"~x"},"ttl_h":4000}`, "CF-Connecting-IP", ip, readHeader, rkey, "X-PoW", "ok")
	if st != 201 {
		t.Fatalf("anonymous mint: %d %s", st, body)
	}
	m := mintRe.FindStringSubmatch(body)
	if m == nil || m[2] != secret || m[3] != rkey {
		t.Fatalf("anonymous mint reply: %q", body)
	}
	var root, note string
	var oh []byte
	var exp time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT root, note, on_hit, expires_at FROM tripwires WHERE id = $1`, m[1]).Scan(&root, &note, &oh, &exp); err != nil {
		t.Fatal(err)
	}
	if root != "" || note != "anon canary" || string(oh) != "{}" {
		t.Errorf("anonymous row: root=%q note=%q on_hit=%s", root, note, oh)
	}
	if d := time.Until(exp); d < anonTTL-time.Hour || d > anonTTL+time.Hour {
		t.Errorf("anonymous ttl %v, want 7 d", d)
	}
	// Same secret again -> dup.
	if st, body, _ := e.do(t, "PUT", "/y/"+secret, "", "", "CF-Connecting-IP", ip, readHeader, rkey, "X-PoW", "ok"); st != 409 {
		t.Errorf("dup secret: %d %s", st, body)
	}
	// A hit, then the anonymous read with the read key.
	if st, _, _ := e.do(t, "GET", "/y/"+secret+"/img.png", "", "", "CF-Connecting-IP", "10.200.1.1", "User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120"); st != 200 {
		t.Fatal(st)
	}
	st, body, hdr = e.do(t, "GET", "/y/"+secret+"/.hits", "", "", "CF-Connecting-IP", ip, readHeader, rkey)
	today := core.Date(time.Now())
	if st != 200 || !strings.HasPrefix(body, fmt.Sprintf("hits=1 first=%s last=%s\n", today, today)) || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("anonymous read: %d %q %q", st, body, hdr.Get("Cache-Control"))
	}
	if rows := rowRe.FindAllString(body, -1); len(rows) != 1 || !strings.Contains(rows[0], " browser net=") {
		t.Errorf("anonymous read rows: %q", body)
	}
	if strings.Contains(body, "/v1/tw/") {
		t.Errorf("anonymous read points at the owner route: %q", body)
	}
	if n := count(t, `SELECT hits FROM tripwires WHERE id = $1`, m[1]); n != 1 {
		t.Errorf("the read counted as a hit: hits=%d", n)
	}
	// No mail and no event for an anonymous tripwire.
	if n := count(t, `SELECT count(*) FROM events WHERE kind = 'tw' AND ref = $1`, m[1]); n != 0 {
		t.Error("anonymous tripwire wrote an event")
	}
	// Quota: 10/day per IP group (IPv4 group = the address; one already used), then 429; a
	// neighbour in the same /24 is another group under the 4x super-group allowance and still mints.
	for i := 1; i < AnonDaily; i++ {
		st, body, _ := e.do(t, "PUT", "/y/"+randB64(24), "", "", "CF-Connecting-IP", ip, readHeader, rkey, "X-PoW", "ok")
		if st != 201 {
			t.Fatalf("anonymous mint %d: %d %s", i+1, st, body)
		}
	}
	if st, body, _ := e.do(t, "PUT", "/y/"+randB64(24), "", "", "CF-Connecting-IP", ip, readHeader, rkey, "X-PoW", "ok"); st != 429 || !strings.Contains(body, "quota") {
		t.Errorf("over anonymous quota: %d %s", st, body)
	}
	// The refused mint rolls its counter bumps back with the transaction.
	if n := count(t, `SELECT n FROM counters WHERE scope = $1 AND kind = 'tripwire' AND day = current_date`, "sup:"+core.IPSuper(ip)); n != AnonDaily {
		t.Errorf("super-group counter = %d, want %d", n, AnonDaily)
	}
	if st, body, _ := e.do(t, "PUT", "/y/"+randB64(24), "", "", "CF-Connecting-IP", super+".99", readHeader, rkey, "X-PoW", "ok"); st != 201 {
		t.Errorf("neighbour group: %d %s", st, body)
	}
	// With a token the same route mints an owned tripwire with the client-chosen keys.
	rootID, tok := newRoot(t, randIP("10.12"))
	s2, k2 := randB64(24), randB64(18)
	st, body, _ = e.do(t, "PUT", "/y/"+s2, tok, `{"note":"mine","ttl_h":24}`, readHeader, k2)
	if st != 201 || !strings.Contains(body, "url=https://agents.example/y/"+s2+" read="+k2) {
		t.Fatalf("token PUT: %d %s", st, body)
	}
	if n := count(t, `SELECT count(*) FROM tripwires WHERE h = $1 AND root = $2 AND expires_at BETWEEN now() + interval '23 hours' AND now() + interval '25 hours'`, hash(s2), rootID); n != 1 {
		t.Error("token PUT did not store an owned 24 h tripwire")
	}
}

func TestFirstHitMailAndEvent(t *testing.T) {
	e := newEnv(t)
	root, tok := newRoot(t, randIP("10.13"))
	var pubTopic, pubRoot, pubText string
	pubs := 0
	old := PublishFn
	PublishFn = func(_ context.Context, _ core.Q, topic, r, text string) error {
		pubs++
		pubTopic, pubRoot, pubText = topic, r, text
		return nil
	}
	t.Cleanup(func() { PublishFn = old })
	id, secret, _ := e.mint(t, tok, `{"note":"laptop ~/.aws/credentials","on_hit":{"ps":"~alerts"}}`)
	for i := 0; i < 3; i++ {
		if st, _, _ := e.do(t, "GET", "/y/"+secret+"/aws.png", "", "", "User-Agent", "python-requests/2.31", "CF-Connecting-IP", randIP("10.50")); st != 200 {
			t.Fatal(st)
		}
	}
	// Exactly one sys mail to the owner, on the first hit.
	var subject, text, from string
	if err := testPool.QueryRow(context.Background(), `SELECT subject, text, from_id FROM mail WHERE box = $1`, root).Scan(&subject, &text, &from); err != nil {
		t.Fatalf("mail row: %v", err)
	}
	if subject != "tripwire "+id+" tripped" || from != "sys" {
		t.Errorf("mail subject %q from %q", subject, from)
	}
	if !strings.Contains(text, "ua=agent net=") || !strings.Contains(text, "read: GET /v1/tw/"+id) || !strings.Contains(text, "note: laptop ~/.aws/credentials") {
		t.Errorf("mail text %q", text)
	}
	if n := count(t, `SELECT count(*) FROM mail WHERE box = $1`, root); n != 1 {
		t.Errorf("%d mails, want 1 (first hit only)", n)
	}
	// One root-scoped event.
	if n := count(t, `SELECT count(*) FROM events WHERE kind = 'tw' AND ref = $1 AND root_scope = $2 AND title = $3`, id, root, "tripwire "+id+" tripped"); n != 1 {
		t.Errorf("events = %d", n)
	}
	if n := count(t, `SELECT count(*) FROM events WHERE kind = 'tw' AND ref = $1 AND root_scope IS NULL`, id); n != 0 {
		t.Error("a public event leaked the tripwire")
	}
	// One publish to the on_hit topic as the owner.
	if pubs != 1 || pubTopic != "~alerts" || pubRoot != root || !strings.HasPrefix(pubText, "tripwire "+id+" tripped ") || !strings.Contains(pubText, " ua=agent net=") {
		t.Errorf("publish: n=%d topic=%q root=%q text=%q", pubs, pubTopic, pubRoot, pubText)
	}
	if strings.Contains(pubText, "\n") || strings.Contains(pubText, "aws") {
		t.Errorf("publish text carries more than the notice: %q", pubText)
	}
	// Without on_hit nothing is published; a nil PublishFn is safe.
	PublishFn = nil
	_, s2, _ := e.mint(t, tok, `{}`)
	if st, _, _ := e.do(t, "GET", "/y/"+s2, "", ""); st != 200 {
		t.Fatal(st)
	}
	if n := count(t, `SELECT count(*) FROM mail WHERE box = $1`, root); n != 2 {
		t.Errorf("%d mails after second tripwire, want 2", n)
	}
	if n := count(t, `SELECT hits FROM tripwires WHERE id = $1`, id); n != 3 {
		t.Errorf("hits = %d", n)
	}
}

func TestReadKey(t *testing.T) {
	e := newEnv(t)
	_, tok := newRoot(t, randIP("10.14"))
	id, secret, rkey := e.mint(t, tok, `{}`)
	// A wrong or missing read key on /.hits is an ordinary hit: 200, empty, recorded.
	for _, hdr := range [][]string{{}, {readHeader, "wrong-key-0123456789abcd"}} {
		st, body, h := e.do(t, "GET", "/y/"+secret+"/.hits", "", "", hdr...)
		if st != 200 || body != "" || h.Get("Content-Length") != "0" {
			t.Fatalf("wrong key read: %d %q", st, body)
		}
	}
	if n := count(t, `SELECT hits FROM tripwires WHERE id = $1`, id); n != 2 {
		t.Fatalf("hits = %d, want 2 (wrong keys count as hits)", n)
	}
	// The right key reads without recording; HEAD too.
	st, body, _ := e.do(t, "GET", "/y/"+secret+"/.hits", "", "", readHeader, rkey)
	if st != 200 || !strings.HasPrefix(body, "hits=2 ") || len(rowRe.FindAllString(body, -1)) != 2 {
		t.Fatalf("read: %d %q", st, body)
	}
	if st, body, _ := e.do(t, "HEAD", "/y/"+secret+"/.hits", "", "", readHeader, rkey); st != 200 || body != "" {
		t.Errorf("HEAD read: %d %q", st, body)
	}
	if st, body, _ := e.do(t, "GET", "/y/"+secret+"/.hits.json", "", "", readHeader, rkey); st != 200 || body != "" {
		// .hits.json is not the read path: it is a hit like any other suffix.
		t.Errorf(".hits.json: %d %q", st, body)
	}
	if n := count(t, `SELECT hits FROM tripwires WHERE id = $1`, id); n != 3 {
		t.Errorf("hits = %d, want 3 (reads with the key never count)", n)
	}
	// POST /.hits with the key is a hit, never a read.
	if st, body, _ := e.do(t, "POST", "/y/"+secret+"/.hits", "", "", readHeader, rkey); st != 200 || body != "" {
		t.Errorf("POST .hits: %d %q", st, body)
	}
	// Owner route: owner only.
	if st, body, _ := e.do(t, "GET", "/v1/tw/"+id, "", ""); st != 401 {
		t.Errorf("owner read without token: %d %s", st, body)
	}
	_, other := newRoot(t, randIP("10.14"))
	if st, body, _ := e.do(t, "GET", "/v1/tw/"+id, other, ""); st != 404 {
		t.Errorf("owner read by another root: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "GET", "/v1/tw/"+id, tok, ""); st != 200 || !strings.HasPrefix(body, "hits=4 ") {
		t.Errorf("owner read: %d %q", st, body)
	}
	// The read key is only ever stored hashed.
	if n := count(t, `SELECT count(*) FROM tripwires WHERE rh = $1`, hash(rkey)); n != 1 {
		t.Error("rh is not sha256(read key)")
	}
}

func TestHitCap50(t *testing.T) {
	e := newEnv(t)
	_, tok := newRoot(t, randIP("10.15"))
	id, secret, _ := e.mint(t, tok, `{}`)
	for i := 0; i < HitCap+10; i++ {
		st, _, _ := e.do(t, "GET", "/y/"+secret+"/p.png", "", "", "CF-Connecting-IP", fmt.Sprintf("10.60.%d.%d", i/200, i%200+1), "User-Agent", "curl/8.0")
		if st != 200 {
			t.Fatalf("hit %d: %d", i, st)
		}
	}
	if n := count(t, `SELECT hits FROM tripwires WHERE id = $1`, id); n != HitCap+10 {
		t.Errorf("hits = %d, want %d", n, HitCap+10)
	}
	if n := count(t, `SELECT count(*) FROM tripwire_hits WHERE id = $1`, id); n != HitCap {
		t.Errorf("hit rows = %d, want %d", n, HitCap)
	}
	st, body, _ := e.do(t, "GET", "/v1/tw/"+id, tok, "")
	if st != 200 || !strings.HasPrefix(body, fmt.Sprintf("hits=%d ", HitCap+10)) {
		t.Fatalf("owner view: %d %q", st, body)
	}
	if rows := rowRe.FindAllString(body, -1); len(rows) != HitCap {
		t.Errorf("owner view rows = %d, want %d", len(rows), HitCap)
	}
	// Deleting the tripwire cascades its hits.
	if _, err := testPool.Exec(context.Background(), `DELETE FROM tripwires WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if n := count(t, `SELECT count(*) FROM tripwire_hits WHERE id = $1`, id); n != 0 {
		t.Error("hit rows survived their tripwire")
	}
}
