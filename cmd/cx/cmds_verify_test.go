package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/sign"
)

// verifyFixture is a fake gateway for cx verify: a published echo job (uppercase stdin), a server
// key signing its att1 line, and two agreeing donors each signing the result fingerprint.
type verifyFixture struct {
	job     string
	line    string
	sig     string
	rows    []donorRow
	blobs   map[string][]byte
	signer  *sign.Signer
	outHash string
}

const verifyInput = "hello commons"

// newVerifyFixture builds a valid fixture; mutators tweak it before the att line / donor sigs are
// signed (badOut) or after (corrupt sig / donor).
func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	wasm, err := os.ReadFile(filepath.Join("..", "..", "testdata", "wasm", "out", "echo.wasm"))
	if err != nil {
		t.Skipf("missing echo.wasm (run testdata/wasm/build.sh): %v", err)
	}
	in := []byte(verifyInput)
	out := bytes.ToUpper(in)
	fx := &verifyFixture{
		job:     "jverify01",
		blobs:   map[string][]byte{},
		signer:  sign.MustNew(core.Config{ServerSecret: []byte("verify-test-secret")}),
		outHash: sha256hex(out),
	}
	fx.blobs[sha256hex(wasm)] = wasm
	fx.blobs[sha256hex(in)] = in
	fx.blobs[fx.outHash] = out
	fx.build(sha256hex(wasm), sha256hex(in), fx.outHash)
	return fx
}

// build (re)computes the att1 line, the server signature and the donor tuples for the given blob
// hashes and output hash. oHash is what the line attests; the donors sign the matching fingerprint.
func (fx *verifyFixture) build(wasm, input, oHash string) {
	fx.line = sign.Canonical("att1",
		sign.KV{K: "j", V: fx.job}, sign.KV{K: "w", V: wasm}, sign.KV{K: "i", V: input},
		sign.KV{K: "o", V: oHash}, sign.KV{K: "s", V: "ok"}, sign.KV{K: "c", V: "0"},
		sign.KV{K: "n", V: "2/2"}, sign.KV{K: "d", V: "1"}, sign.KV{K: "t", V: "1767225600"},
		sign.KV{K: "k", V: strconv.Itoa(fx.signer.KID())}, sign.KV{K: "ds", V: "2"})
	fx.sig = fx.signer.Sign("att1", fx.line)
	fp := "ok:0:" + oHash
	fx.rows = nil
	for i := 0; i < 2; i++ {
		pub, priv, _ := ed25519.GenerateKey(nil)
		lease := "lease" + strconv.Itoa(i)
		msg := []byte(dsigDomain + fx.job + "\x00" + lease + "\x00" + fp)
		dsig := ed25519.Sign(priv, msg)
		fx.rows = append(fx.rows, donorRow{
			Donor: "a" + strconv.Itoa(i) + "donor",
			Pub:   hexEncode(pub),
			Dsig:  base64.RawURLEncoding.EncodeToString(dsig),
			Lease: lease,
		})
	}
}

// server starts an httptest gateway serving the attestation, the server key and the blobs.
func (fx *verifyFixture) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /att/{job}", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(attReply{Line: fx.line, Sig: fx.sig, Rows: fx.rows})
	})
	mux.HandleFunc("GET /.well-known/cx-key", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(fx.signer.WellKnown())
	})
	mux.HandleFunc("GET /v1/b/{hash}", func(w http.ResponseWriter, r *http.Request) {
		b, ok := fx.blobs[r.PathValue("hash")]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, "err notfound not found\n")
			return
		}
		w.Write(b)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func runVerify(t *testing.T, srv *httptest.Server, args ...string) (string, *exitErr) {
	t.Helper()
	c, out, _ := testCLI(t, srv, "tok")
	err := c.run(context.Background(), append([]string{"verify"}, args...))
	var ee *exitErr
	if err != nil && !asExit(err, &ee) {
		t.Fatalf("verify returned non-exit error: %v", err)
	}
	return out.String(), ee
}

func TestVerifyMatch(t *testing.T) {
	fx := newVerifyFixture(t)
	out, ee := runVerify(t, fx.server(t), fx.job)
	if ee != nil {
		t.Fatalf("exit %d, stdout %q", ee.code, out)
	}
	if got := strings.TrimSpace(out); got != "match server=valid donors=2/2 local=same" {
		t.Fatalf("stdout %q", got)
	}
	// The /att URL form targets the same host and gives the same verdict.
	out, ee = runVerify(t, fx.server(t), fx.server(t).URL+"/att/"+fx.job)
	if ee != nil || !strings.Contains(out, "match server=valid donors=2/2 local=same") {
		t.Fatalf("url form: stdout %q ee %v", out, ee)
	}
}

func TestVerifyLocalMismatch(t *testing.T) {
	fx := newVerifyFixture(t)
	// Attest a bogus output hash: signatures stay valid, the local re-run disagrees.
	bad := sha256hex([]byte("not the real output"))
	fx.build(sha256hex(fx.blobs[attField(fx.line, "w")]), attField(fx.line, "i"), bad)
	out, ee := runVerify(t, fx.server(t), fx.job)
	if ee == nil || ee.code == 0 {
		t.Fatalf("want non-zero exit, stdout %q", out)
	}
	if got := strings.TrimSpace(out); got != "mismatch server=valid donors=2/2 local=differ" {
		t.Fatalf("stdout %q", got)
	}
}

func TestVerifyBadServerSig(t *testing.T) {
	fx := newVerifyFixture(t)
	fx.sig = flipLastB64(fx.sig) // corrupt the server signature
	out, ee := runVerify(t, fx.server(t), fx.job)
	if ee == nil || ee.code == 0 {
		t.Fatalf("want non-zero exit, stdout %q", out)
	}
	if got := strings.TrimSpace(out); got != "mismatch server=invalid donors=2/2 local=same" {
		t.Fatalf("stdout %q", got)
	}
}

func TestVerifyBadDonorSig(t *testing.T) {
	fx := newVerifyFixture(t)
	fx.rows[0].Dsig = flipLastB64(fx.rows[0].Dsig) // one donor signature no longer verifies
	out, ee := runVerify(t, fx.server(t), fx.job)
	if ee == nil || ee.code == 0 {
		t.Fatalf("want non-zero exit, stdout %q", out)
	}
	if got := strings.TrimSpace(out); got != "mismatch server=valid donors=1/2 local=same" {
		t.Fatalf("stdout %q", got)
	}
}

func TestVerifyNoRun(t *testing.T) {
	fx := newVerifyFixture(t)
	// --no-run checks signatures only: a wrong output hash is never noticed (no local part).
	fx.build(attField(fx.line, "w"), attField(fx.line, "i"), sha256hex([]byte("whatever")))
	out, ee := runVerify(t, fx.server(t), "--no-run", fx.job)
	if ee != nil {
		t.Fatalf("exit %d, stdout %q", ee.code, out)
	}
	if got := strings.TrimSpace(out); got != "match server=valid donors=2/2" {
		t.Fatalf("stdout %q", got)
	}
	if strings.Contains(out, "local=") {
		t.Fatalf("--no-run must not report a local run: %q", out)
	}
}

// --- helpers ---

func attField(line, key string) string { return parseAttLine(line)[key] }

func hexEncode(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2], out[i*2+1] = hexd[c>>4], hexd[c&0xf]
	}
	return string(out)
}

// flipLastB64 mutates the first base64url character (a full 6 data bits, so the decode still
// succeeds) so the decoded signature no longer verifies.
func flipLastB64(s string) string {
	had := strings.HasPrefix(s, "sig=")
	s = strings.TrimPrefix(s, "sig=")
	if s == "" {
		return s
	}
	repl := byte('A')
	if s[0] == 'A' {
		repl = 'B'
	}
	s = string(repl) + s[1:]
	if had {
		s = "sig=" + s
	}
	return s
}
