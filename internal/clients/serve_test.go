package clients

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/errsig"
)

// testSigner installs a throwaway online key as the X-Cx-Sig-Server seam so the package needs no
// database, and returns its public key for verification.
func testSigner(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, sk, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldSign, oldPub := signResp, onlinePub
	signResp = func(path string, body []byte) string {
		return e2e.SignResp(sk, path, uint64(time.Now().Unix()), body)
	}
	onlinePub = func() []byte { return pub }
	t.Cleanup(func() { signResp, onlinePub = oldSign, oldPub })
	return pub
}

func testMux() *http.ServeMux {
	mux := http.NewServeMux()
	mount(mux, func(string) {})
	return mux
}

// TestServedWithSignatureAndManifest checks every client is served with the static-asset headers, a
// verifying X-Cx-Sig-Server signature over the exact bytes, noindex and a strict CSP, that HEAD and
// conditional GET work, and that the manifest parses with every served file listed.
func TestServedWithSignatureAndManifest(t *testing.T) {
	pub := testSigner(t)
	srv := httptest.NewServer(testMux())
	defer srv.Close()

	paths := []string{"/cx.py", "/cx.mjs", "/cx.sh", "/e2e.py", "/e2e.mjs", "/e2e-vectors.json",
		"/seal.py", "/seal.mjs", "/srchash.py", "/cx-manifest.json"}
	for _, p := range paths {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		body := readAll(t, resp)
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: status %d", p, resp.StatusCode)
		}
		for _, h := range []string{"ETag", "Last-Modified", "Content-Type", "X-Cx-Sig-Server"} {
			if resp.Header.Get(h) == "" {
				t.Errorf("GET %s: missing %s header", p, h)
			}
		}
		if got := resp.Header.Get("X-Robots-Tag"); got != "noindex" {
			t.Errorf("GET %s: X-Robots-Tag = %q, want noindex", p, got)
		}
		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
			t.Errorf("GET %s: weak CSP %q", p, csp)
		}
		if _, err := e2e.VerifyResp(pub, p, resp.Header.Get("X-Cx-Sig-Server"), body); err != nil {
			t.Errorf("GET %s: X-Cx-Sig-Server does not verify: %v", p, err)
		}
		// ETag round-trips to 304.
		req, _ := http.NewRequest("GET", srv.URL+p, nil)
		req.Header.Set("If-None-Match", resp.Header.Get("ETag"))
		r2, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		readAll(t, r2)
		if r2.StatusCode != http.StatusNotModified {
			t.Errorf("GET %s with If-None-Match: status %d, want 304", p, r2.StatusCode)
		}
		// HEAD returns the headers and no body.
		hr, err := http.Head(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		if b := readAll(t, hr); len(b) != 0 {
			t.Errorf("HEAD %s: non-empty body (%d bytes)", p, len(b))
		}
	}

	var m manifest
	if err := json.Unmarshal(Manifest(), &m); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if m.Version == "" || m.BuiltFrom == "" {
		t.Errorf("manifest missing version/built_from: %+v", m)
	}
	for _, f := range served {
		if _, ok := m.Files[f.name]; !ok {
			t.Errorf("manifest omits served file %s", f.name)
		}
	}
}

// TestManifestHashesMatchFiles asserts every sha256 in cx-manifest.json equals the sha256 of the
// bytes actually served for that file: the manifest and the delivered code never drift.
func TestManifestHashesMatchFiles(t *testing.T) {
	var m manifest
	if err := json.Unmarshal(Manifest(), &m); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if len(m.Files) == 0 {
		t.Fatal("manifest lists no files")
	}
	for name, want := range m.Files {
		sum := sha256.Sum256(mustAsset(name))
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s: manifest hash %s != file hash %s", name, want, got)
		}
	}
	// The manifest must hash to what the server delivers for /cx-manifest.json too.
	pub := testSigner(t)
	srv := httptest.NewServer(testMux())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/cx-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, resp)
	if _, err := e2e.VerifyResp(pub, "/cx-manifest.json", resp.Header.Get("X-Cx-Sig-Server"), body); err != nil {
		t.Errorf("manifest signature: %v", err)
	}
	if string(body) != string(Manifest()) {
		t.Errorf("served manifest != Manifest()")
	}
}

var (
	forbidPy = regexp.MustCompile(`\beval\s*\(|\bexec\s*\(|os\.system|shell\s*=\s*True|\bpickle\b|__import__\s*\(|subprocess\.(call|Popen)\([^]]*shell`)
	forbidJS = regexp.MustCompile(`\beval\s*\(|new\s+Function\s*\(|\bexecSync\b|import[^;]*\bexec\b[^;]*child_process|require\(['"](child_process|vm)['"]\)|runInNewContext|vm\.run`)
)

// TestNoEvalOrShellOut is the grep gate over the served clients (SPEC-v2 27.2: "No eval, no
// shell-out, no pickle; static assets"). Delegation to e2e.py/e2e.mjs uses subprocess/spawn with an
// argument list (no shell), which is allowed; a shell, eval, dynamic code or pickle is not.
func TestNoEvalOrShellOut(t *testing.T) {
	for _, name := range assetNames() {
		body := string(mustAsset(name))
		switch {
		case strings.HasSuffix(name, ".py"):
			if loc := forbidPy.FindString(body); loc != "" {
				t.Errorf("%s: forbidden construct %q", name, loc)
			}
		case strings.HasSuffix(name, ".mjs"), strings.HasSuffix(name, ".js"):
			if loc := forbidJS.FindString(body); loc != "" {
				t.Errorf("%s: forbidden construct %q", name, loc)
			}
		case strings.HasSuffix(name, ".sh"):
			if strings.Contains(body, "eval ") || strings.Contains(body, "eval\t") {
				t.Errorf("%s: shell eval", name)
			}
		}
	}
}

// TestErrsigVectorsMatchGo runs the served errsig.py against every kb.ErrSig test vector and checks
// the reference client computes the same signature the server does. Skips when python3 is absent.
func TestErrsigVectorsMatchGo(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "errsig.py")
	if err := os.WriteFile(script, mustAsset("errsig.py"), 0o644); err != nil {
		t.Fatal(err)
	}
	vecs := errsig.Vectors()
	if len(vecs) == 0 {
		t.Fatal("no errsig vectors")
	}
	for _, v := range vecs {
		out, err := exec.Command(py, "-I", script, v.Input).Output()
		if err != nil {
			t.Fatalf("errsig.py %q: %v", v.Input, err)
		}
		got := ""
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "sig:") {
				got = strings.TrimSpace(strings.TrimPrefix(line, "sig:"))
			}
		}
		if got != v.Sig {
			t.Errorf("errsig.py(%q) = %q, Go kb.ErrSig = %q", v.Input, got, v.Sig)
		}
	}
}

// TestSealRecipeInteropWithE2E checks the served seal.py produces seal2 values that internal/e2e
// opens, and opens seal2 values internal/e2e produced: the 26.4 recipe is byte-identical across the
// Go core and the zero-install Python client. Falls back to a Go-only round-trip without python3.
func TestSealRecipeInteropWithE2E(t *testing.T) {
	mk := []byte("0123456789abcdef0123456789abcdef")
	kv := e2e.SealV1Key(mk)
	mkHex := hex.EncodeToString(mk)
	plaintext := "sealed checkpoint: held t:12 lock:build"

	// Go seals, e2e opens (always runs).
	// seal.py binds no aad (stated limit); pass aad "" so the Go side uses the same unbound MAC base
	// and stays byte-identical with the reference recipe.
	goVal, err := e2e.Seal2(kv, "", []byte(plaintext), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := e2e.Open2(kv, "", goVal); err != nil || string(got) != plaintext {
		t.Fatalf("e2e round-trip: %v %q", err, got)
	}

	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available (Go round-trip passed)")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "seal.py")
	if err := os.WriteFile(script, mustAsset("seal.py"), 0o644); err != nil {
		t.Fatal(err)
	}
	// python seals -> Go opens.
	out, err := exec.Command(py, "-I", script, "seal", mkHex, plaintext).Output()
	if err != nil {
		t.Fatalf("seal.py seal: %v", err)
	}
	pyVal := strings.TrimSpace(string(out))
	if !strings.HasPrefix(pyVal, "seal2:") {
		t.Fatalf("seal.py did not emit a seal2 value: %q", pyVal)
	}
	got, err := e2e.Open2(kv, "", pyVal)
	if err != nil {
		t.Fatalf("e2e.Open2(python seal2): %v", err)
	}
	if string(got) != plaintext {
		t.Errorf("python seal opened to %q, want %q", got, plaintext)
	}
	// Go seals -> python opens.
	out, err = exec.Command(py, "-I", script, "open", mkHex, goVal).Output()
	if err != nil {
		t.Fatalf("seal.py open: %v", err)
	}
	if string(out) != plaintext {
		t.Errorf("seal.py opened Go seal2 to %q, want %q", out, plaintext)
	}
}

// TestClientsDirMatchesServed asserts the published repo-root clients/ tree is byte-identical to the
// embedded, served and manifested assets, so "the grep gate over clients/" and the served code are
// the same bytes and never drift. Skips if the repo-root dir is not present (e.g. a stripped build).
func TestClientsDirMatchesServed(t *testing.T) {
	root := filepath.Join("..", "..", "clients")
	if _, err := os.Stat(root); err != nil {
		t.Skip("repo-root clients/ not present")
	}
	for _, name := range assetNames() {
		disk, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Errorf("clients/%s: %v", name, err)
			continue
		}
		if string(disk) != string(mustAsset(name)) {
			t.Errorf("clients/%s differs from the served asset (regenerate/copy from internal/clients/assets)", name)
		}
	}
}

func readAll(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
