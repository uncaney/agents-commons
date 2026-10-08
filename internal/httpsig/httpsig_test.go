package httpsig

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/testdb"

	"github.com/jackc/pgx/v5/pgxpool"
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
	} else if pool, done := testdb.Open("httpsig", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping httpsig DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

const (
	testSecret = "test-secret-0123456789abcdef"
	mdType     = "text/markdown; charset=utf-8"
)

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
	ip  string
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte(testSecret), AdminToken: "adm", SignKID: 1, PowBits: 6,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	if _, err := sign.Init(cfg); err != nil {
		t.Fatal(err)
	}
	// The scratch DB persists flags across tests/runs; start from a clean shed state.
	d.SetFlag(context.Background(), "shed:anon-search", false, "")
	mux := http.NewServeMux()
	sign.Register(mux, d)
	Register(mux, d)
	// Two renditions: a static one that carries an ETag, and a dynamic one that does not.
	mux.HandleFunc("GET /t.md", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", mdType)
		w.Header().Set("ETag", `W/"deadbeefdeadbeef"`)
		w.Write([]byte("# hello\nworld\n"))
	})
	mux.HandleFunc("GET /dyn.md", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", mdType)
		w.Write([]byte("dynamic\n"))
	})
	srv := httptest.NewServer(d.Handler(Middleware(d, mux)))
	t.Cleanup(srv.Close)
	return &tenv{d: d, srv: srv, ip: "10.9.8.7"}
}

func (e *tenv) get(t *testing.T, path string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Host = "agents.example"
	req.Header.Set("CF-Connecting-IP", e.ip)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	return res, b
}

func TestSignatureBaseVector(t *testing.T) {
	s, err := sign.New(core.Config{ServerSecret: []byte(testSecret), SignKID: 1})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("# hello\nworld\n")
	digest := Digest(body)
	const created = int64(1700000000)
	params := Params(created, "1")
	wantParams := `("@authority" "@path" "content-digest" "content-type");created=1700000000;keyid="1";alg="ed25519"`
	if params != wantParams {
		t.Fatalf("params=\n%s\nwant\n%s", params, wantParams)
	}
	base := SignatureBase("agents.example", "/kb/abc.md", digest, mdType, params)
	want := strings.Join([]string{
		`"@authority": agents.example`,
		`"@path": /kb/abc.md`,
		`"content-digest": ` + digest,
		`"content-type": ` + mdType,
		`"@signature-params": ` + wantParams,
	}, "\n")
	if string(base) != want {
		t.Fatalf("base=\n%q\nwant\n%q", base, want)
	}
	sig := s.SignBytes(base)
	if !ed25519.Verify(s.Public(), base, sig) {
		t.Fatal("signature does not verify over the base")
	}
}

func TestStaticSignedOncePerETag(t *testing.T) {
	e := newEnv(t)
	orig := timeNow
	defer func() { timeNow = orig }()
	now := time.Unix(1700000000, 0)
	timeNow = func() time.Time { return now }

	res1, _ := e.get(t, "/t.md")
	sig1 := res1.Header.Get("Signature")
	in1 := res1.Header.Get("Signature-Input")
	if sig1 == "" || in1 == "" {
		t.Fatalf("no signature on first request: sig=%q input=%q", sig1, in1)
	}
	// Advance the clock: if the static bytes were re-signed, created (and the signature) would change.
	now = now.Add(time.Hour)
	res2, _ := e.get(t, "/t.md")
	if got := res2.Header.Get("Signature"); got != sig1 {
		t.Fatalf("static rendition re-signed: %q != %q", got, sig1)
	}
	if got := res2.Header.Get("Signature-Input"); got != in1 {
		t.Fatalf("Signature-Input changed across requests: %q != %q", got, in1)
	}
	// The dynamic rendition (no ETag) is signed per request: created tracks the clock.
	d1, _ := e.get(t, "/dyn.md")
	now = now.Add(time.Hour)
	d2, _ := e.get(t, "/dyn.md")
	if d1.Header.Get("Signature") == d2.Header.Get("Signature") {
		t.Fatal("dynamic rendition should be re-signed each request")
	}
}

func TestSkippedUnderShed(t *testing.T) {
	e := newEnv(t)
	if err := e.d.SetFlag(context.Background(), "shed:anon-search", true, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.d.SetFlag(context.Background(), "shed:anon-search", false, "") })
	res, _ := e.get(t, "/t.md")
	if sig := res.Header.Get("Signature"); sig != "" {
		t.Fatalf("expected no Signature under shed:anon-search, got %q", sig)
	}
	if cd := res.Header.Get("Content-Digest"); cd != "" {
		t.Fatalf("expected no Content-Digest under shed, got %q", cd)
	}
}

func TestCardSigJWSVerifies(t *testing.T) {
	if _, err := sign.Init(core.Config{ServerSecret: []byte(testSecret), SignKID: 1}); err != nil {
		t.Fatal(err)
	}
	card := json.RawMessage(`{"name":"commons","url":"https://agents.example/a2a"}`)
	protected, signature := CardSig(card)
	ue := base64.RawURLEncoding
	hb, err := ue.DecodeString(protected)
	if err != nil {
		t.Fatalf("protected: %v", err)
	}
	var hdr struct{ Alg, Kid, Typ string }
	if err := json.Unmarshal(hb, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Alg != "EdDSA" || hdr.Typ != "JOSE" || hdr.Kid != "1" {
		t.Fatalf("protected header = %+v", hdr)
	}
	input := protected + "." + ue.EncodeToString(card)
	raw, err := ue.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(sign.Public(), []byte(input), raw) {
		t.Fatal("card JWS does not verify")
	}
}

func TestVerifyBodyHeaders(t *testing.T) {
	e := newEnv(t)
	res, body := e.get(t, "/t.md")
	if res.Header.Get("Signature") == "" {
		t.Fatal("rendition not signed")
	}
	post := func(b []byte) (int, string) {
		req, _ := http.NewRequest("POST", e.srv.URL+"/verify?path=/t.md&authority=agents.example", strings.NewReader(string(b)))
		req.Header.Set("CF-Connecting-IP", e.ip)
		req.Header.Set("Content-Type", mdType)
		req.Header.Set("Content-Digest", res.Header.Get("Content-Digest"))
		req.Header.Set("Signature-Input", res.Header.Get("Signature-Input"))
		req.Header.Set("Signature", res.Header.Get("Signature"))
		rr, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(rr.Body)
		rr.Body.Close()
		return rr.StatusCode, strings.TrimSpace(string(out))
	}
	if code, out := post(body); code != 200 || !strings.HasPrefix(out, "ok type=page kid=1 created=") {
		t.Fatalf("verify good: code=%d out=%q", code, out)
	}
	if _, out := post([]byte("tampered\n")); out != "bad" {
		t.Fatalf("verify tampered: out=%q want bad", out)
	}
}

func TestJwksMatchesCxKey(t *testing.T) {
	e := newEnv(t)
	_, body := e.get(t, "/.well-known/jwks.json")
	var jwks struct {
		Keys []struct{ Kty, Crv, Kid, Alg, Use, X string } `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		t.Fatalf("jwks: %v (%s)", err, body)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("no keys in jwks")
	}
	k := jwks.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" || k.Use != "sig" {
		t.Fatalf("jwk shape = %+v", k)
	}
	if k.Kid != KIDString() {
		t.Fatalf("kid=%q want %q", k.Kid, KIDString())
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		t.Fatalf("x: %v", err)
	}
	if !ed25519.PublicKey(x).Equal(sign.Public()) {
		t.Fatal("jwks x does not match the server signing key")
	}
}
