package sign

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	// Crypto tests always run; the route test needs a database for core.NewDeps (limiter, flags):
	// TEST_DATABASE_URL (a scratch db), else testdb's per-package database.
	var cleanup func()
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		ctx := context.Background()
		pool, err := pgxpool.New(ctx, dsn)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if testPool, cleanup = testdb.Open("sign", core.Migrate); testPool == nil {
		fmt.Println("TEST_DATABASE_URL and TEST_PG_ADMIN_URL unset: skipping sign route tests")
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
	n   int // requests made: each one comes from its own /24 so anonymous buckets never interfere
}

func newEnv(t *testing.T, kid int) *tenv {
	t.Helper()
	if testPool == nil {
		t.Skip("no test database")
	}
	c := core.Config{ServerSecret: []byte(testSecret), SignKID: kid, PowBits: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), c, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	return &tenv{d: d, srv: srv}
}

func (e *tenv) get(t *testing.T, path string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	e.n++
	req.Header.Set("CF-Connecting-IP", fmt.Sprintf("10.%d.%d.1", 6+e.n/250, e.n%250))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimRight(string(b), "\n"), res.Header
}

func verifyURL(s, sig string) string {
	v := url.Values{"s": {s}}
	if sig != "" {
		v.Set("sig", sig)
	}
	return "/verify?" + v.Encode()
}

func TestWellKnownAndVerifyRoutes(t *testing.T) {
	e := newEnv(t, 1)
	st, body, h := e.get(t, "/.well-known/cx-key")
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/json") {
		t.Fatalf("cx-key: %d %s %s", st, h.Get("Content-Type"), body)
	}
	if h.Get("Access-Control-Allow-Origin") != "*" || h.Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("cx-key headers %v", h)
	}
	var wk WellKnown
	if err := json.Unmarshal([]byte(body), &wk); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(wk, Default().WellKnown()) || wk.KID != 1 || wk.Alg != "Ed25519" || wk.Pub != hex.EncodeToString(Public()) ||
		wk.Prev == nil || len(wk.Prev) != 0 || wk.Domain != "cx-sig-v1\x00<type>\x00<line>" || !contains(wk.Types, "att1") {
		t.Fatalf("cx-key body %s", body)
	}
	if !strings.Contains(body, `"prev":[]`) || !strings.Contains(body, `\u0000<type>\u0000<line>`) {
		t.Fatalf("cx-key wire form %s", body)
	}

	line := Canonical("att1", KV{"j", "j7f2"}, KV{"w", "3a1c"}, KV{"o", "71"}, KV{"s", "exit"}, KV{"c", "0"}, KV{"n", "2/2"}, KV{"d", "1"}, KV{"t", "1760000000"}, KV{"k", "1"})
	sig := Sign("att1", line)
	st, body, h = e.get(t, verifyURL(line, sig))
	if st != 200 || body != "valid kid=1 type=att1" {
		t.Fatalf("verify: %d %q", st, body)
	}
	if h.Get("RateLimit") == "" || h.Get("X-Robots-Tag") != "noindex" || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("verify headers %v", h)
	}
	if st, body, _ = e.get(t, verifyURL(line, strings.TrimPrefix(sig, "sig="))); st != 200 || body != "valid kid=1 type=att1" {
		t.Fatalf("verify bare token: %d %q", st, body)
	}
	if st, body, _ = e.get(t, verifyURL(line+"\n"+sig, "")); st != 200 || body != "valid kid=1 type=att1" {
		t.Fatalf("verify two-line form: %d %q", st, body)
	}
	if st, body, _ = e.get(t, verifyURL(line, sig)+"&f=json"); st != 200 || !strings.Contains(body, `"valid":true`) || !strings.Contains(body, `"kid":1`) || !strings.Contains(body, `"type":"att1"`) {
		t.Fatalf("verify json: %d %q", st, body)
	}
	if st, body, _ = e.get(t, verifyURL(line, sig), "Accept", "application/json"); st != 200 || !strings.Contains(body, `"valid":true`) {
		t.Fatalf("verify accept json: %d %q", st, body)
	}
	invalid := map[string]string{
		"tampered line":               verifyURL(strings.Replace(line, "o=71", "o=72", 1), sig),
		"tampered sig":                verifyURL(line, flip(sig)),
		"cross type":                  verifyURL(strings.Replace(line, "att1 ", "ts1 ", 1), sig),
		"att1 sig on a ts1 statement": verifyURL("ts1 h=ab t=1 n=1 k=1", Sign("att1", "ts1 h=ab t=1 n=1 k=1")),
		"unknown first token":         verifyURL("Att1 "+line, sig),
		"control char":                verifyURL(line+"\x01", sig),
		"second line":                 verifyURL(line+"\nsig=forged", sig),
		"garbage sig":                 verifyURL(line, "sig=!!"),
	}
	for name, u := range invalid {
		if st, body, _ := e.get(t, u); st != 200 || body != "invalid" {
			t.Errorf("%s: %d %q", name, st, body)
		}
	}
	if st, body, _ = e.get(t, verifyURL(line, sig)+"&s="+url.QueryEscape(line)); st != 200 {
		t.Fatalf("repeated param: %d %q", st, body)
	}
	if st, body, _ = e.get(t, "/verify"); st != 400 || !strings.HasPrefix(body, "err bad ") {
		t.Fatalf("missing params: %d %q", st, body)
	}
	if st, body, _ = e.get(t, verifyURL(line, "")); st != 400 {
		t.Fatalf("missing sig: %d %q", st, body)
	}
	if st, body, _ = e.get(t, verifyURL(strings.Repeat("a", MaxLine+MaxSig+2), sig)); st != 413 || !strings.HasPrefix(body, "err size") {
		t.Fatalf("oversize statement: %d %q", st, body)
	}
	if st, body, _ = e.get(t, verifyURL(line, strings.Repeat("A", MaxSig+1))); st != 413 {
		t.Fatalf("oversize sig: %d %q", st, body)
	}
	if st, body, _ = e.get(t, verifyURL("att1 "+strings.Repeat("a", MaxLine), sig)); st != 200 || body != "invalid" {
		t.Fatalf("long but under the body cap: %d %q", st, body)
	}
	if st, _, _ = e.get(t, "/verify?f=json"); st != 400 {
		t.Fatalf("missing params json: %d", st)
	}

	// Rotation seen through the routes: SIGN_KID=2 publishes kid 1 in prev and still verifies it.
	e2 := newEnv(t, 2)
	st, body, _ = e2.get(t, "/.well-known/cx-key")
	var wk2 WellKnown
	if err := json.Unmarshal([]byte(body), &wk2); st != 200 || err != nil || wk2.KID != 2 || len(wk2.Prev) != 1 || wk2.Prev[0].KID != 1 || wk2.Prev[0].Pub != wk.Pub || wk2.Pub == wk.Pub {
		t.Fatalf("rotated cx-key: %d %s", st, body)
	}
	if st, body, _ = e2.get(t, verifyURL(line, sig)); st != 200 || body != "valid kid=1 type=att1" {
		t.Fatalf("rotated verify of old signature: %d %q", st, body)
	}
	if st, body, _ = e2.get(t, verifyURL(line, Sign("att1", line))); st != 200 || body != "valid kid=2 type=att1" {
		t.Fatalf("rotated verify of new signature: %d %q", st, body)
	}
}

func TestOps(t *testing.T) {
	d := &core.Deps{Cfg: cfg(1)} // ops need only the config
	ops := Ops(d)
	ctx := context.Background()
	line := Canonical("ts1", KV{"h", strings.Repeat("ab", 32)}, KV{"t", "1760000000"}, KV{"n", "7"}, KV{"k", "1"})
	sig := MustNew(cfg(1)).Sign("ts1", line)
	arg, _ := json.Marshal(map[string]string{"s": line, "sig": sig})
	if out, err := ops["verify"](ctx, nil, arg); err != nil || out != "valid kid=1 type=ts1" {
		t.Fatalf("verify op: %q %v", out, err)
	}
	arg, _ = json.Marshal(map[string]string{"s": line + "\n" + sig})
	if out, err := ops["verify"](ctx, nil, arg); err != nil || out != "valid kid=1 type=ts1" {
		t.Fatalf("verify op two-line: %q %v", out, err)
	}
	arg, _ = json.Marshal(map[string]string{"s": line + "x", "sig": sig})
	if out, err := ops["verify"](ctx, nil, arg); err != nil || out != "invalid" {
		t.Fatalf("verify op tampered: %q %v", out, err)
	}
	if _, err := ops["verify"](ctx, nil, nil); err == nil || !strings.HasPrefix(err.Error(), "err bad ") {
		t.Fatalf("verify op without args: %v", err)
	}
	if _, err := ops["verify"](ctx, nil, json.RawMessage(`{"s":1}`)); err == nil {
		t.Fatal("verify op bad args accepted")
	}
	arg, _ = json.Marshal(map[string]string{"s": strings.Repeat("a", MaxLine+MaxSig+2), "sig": sig})
	if _, err := ops["verify"](ctx, nil, arg); err == nil || !strings.HasPrefix(err.Error(), "err size") {
		t.Fatalf("verify op oversize: %v", err)
	}
	out, err := ops["key"](ctx, nil, nil)
	if err != nil || !strings.HasPrefix(out, "kid=1 alg=Ed25519 pub="+vecPub1) || !strings.Contains(out, "\ndomain=cx-sig-v1\\0<type>\\0<line>\ntypes=att1 ") || strings.Contains(out, "prev ") {
		t.Fatalf("key op: %q %v", out, err)
	}
	if out, _ := Ops(&core.Deps{Cfg: cfg(2)})["key"](ctx, nil, nil); !strings.Contains(out, "\nprev kid=1 pub="+vecPub1+"\n") {
		t.Fatalf("key op kid 2: %q", out)
	}
	if len(Help) > 200 || !strings.Contains(Help, "verify{s,sig}") {
		t.Fatalf("help %q", Help)
	}
}
