package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// kvCapture is one parsed Cloudflare KV write the fake endpoint saw.
type kvCapture struct {
	method, path, auth, host string
	value                    []byte
	meta                     map[string]string
}

// fakeKV serves the Cloudflare KV values API, parsing the multipart write into value + metadata.
func fakeKV(t *testing.T, calls *[]kvCapture, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/storage/kv/namespaces/") {
			w.WriteHeader(404)
			return
		}
		c := kvCapture{method: r.Method, path: r.RequestURI, auth: r.Header.Get("Authorization"),
			host: r.Header.Get("X-Egress-Host"), meta: map[string]string{}}
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err == nil {
			mr := multipart.NewReader(r.Body, params["boundary"])
			for {
				part, err := mr.NextPart()
				if err != nil {
					break
				}
				b, _ := io.ReadAll(part)
				switch part.FormName() {
				case "value":
					c.value = b
				case "metadata":
					json.Unmarshal(b, &c.meta)
				}
			}
		}
		mu.Lock()
		*calls = append(*calls, c)
		mu.Unlock()
		io.WriteString(w, `{"success":true,"errors":[],"result":null}`)
	}))
}

func TestKvMirrorPayloadAndCap(t *testing.T) {
	var mu sync.Mutex
	var calls []kvCapture
	fake := fakeKV(t, &calls, &mu)
	defer fake.Close()

	te := testEnv(t, fake)
	e := te.e
	te.secret(t, "cf_kv_token", "cf-kv-secret-token")
	acct := strings.Repeat("a", 32)
	ns := strings.Repeat("b", 32)
	te.envs["CF_ACCOUNT_ID"] = acct
	te.envs["CF_KV_NAMESPACE_ID"] = ns

	job := func(path, ct, lm string, body []byte) *Job {
		b, _ := json.Marshal(kvMirrorPayload{Path: path, CT: ct, Body: base64.StdEncoding.EncodeToString(body), LastModified: lm})
		return &Job{ID: 1, Kind: "kv_mirror", Payload: b}
	}

	// 1. A normal small file is written with its value, content-type and Last-Modified metadata.
	robots := []byte("User-agent: *\nAllow: /\nSitemap: https://agents.example/sitemap.xml\n")
	res, err := runKvMirror(context.Background(), e, job("/robots.txt", "text/plain; charset=utf-8", "Tue, 07 Oct 2026 10:00:00 GMT", robots))
	if err != nil {
		t.Fatalf("runKvMirror: %v", err)
	}
	if res == nil || !strings.Contains(string(res), `"bytes"`) {
		t.Fatalf("ack result = %s", res)
	}
	mu.Lock()
	n := len(calls)
	var c kvCapture
	if n == 1 {
		c = calls[0]
	}
	mu.Unlock()
	if n != 1 {
		t.Fatalf("KV writes = %d, want 1", n)
	}
	if c.method != http.MethodPut {
		t.Fatalf("method = %s, want PUT", c.method)
	}
	if c.host != "api.cloudflare.com" {
		t.Fatalf("egress host = %q", c.host)
	}
	wantPath := "/client/v4/accounts/" + acct + "/storage/kv/namespaces/" + ns + "/values/" + "%2Frobots.txt"
	if c.path != wantPath {
		t.Fatalf("PUT path = %q, want %q", c.path, wantPath)
	}
	if c.auth != "Bearer cf-kv-secret-token" {
		t.Fatalf("auth = %q", c.auth)
	}
	if string(c.value) != string(robots) {
		t.Fatalf("value = %q, want robots body", c.value)
	}
	if c.meta["ct"] != "text/plain; charset=utf-8" {
		t.Fatalf("meta ct = %q", c.meta["ct"])
	}
	if c.meta["last_modified"] != "Tue, 07 Oct 2026 10:00:00 GMT" {
		t.Fatalf("meta last_modified = %q", c.meta["last_modified"])
	}

	// 2. A body over the 64 KiB value cap is dead-lettered with a note, never written.
	mu.Lock()
	calls = nil
	mu.Unlock()
	big := make([]byte, kvMirrorMaxBody+1)
	res, err = runKvMirror(context.Background(), e, job("/llms.txt", "text/plain", "", big))
	if err != nil {
		t.Fatalf("over-cap runKvMirror err = %v, want nil (dead-letter)", err)
	}
	if res == nil || !strings.Contains(string(res), "too large") {
		t.Fatalf("over-cap ack = %s, want a too-large note", res)
	}
	mu.Lock()
	n = len(calls)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("over-cap KV writes = %d, want 0", n)
	}

	// 3. A path outside the mirror route set is dropped, never written.
	res, err = runKvMirror(context.Background(), e, job("/kb/abc", "text/html", "", []byte("<html>")))
	if err != nil {
		t.Fatalf("off-route err = %v, want nil (dropped)", err)
	}
	if res == nil || !strings.Contains(string(res), `"skipped":"path"`) {
		t.Fatalf("off-route ack = %s", res)
	}
	mu.Lock()
	n = len(calls)
	mu.Unlock()
	if n != 0 {
		t.Fatalf("off-route KV writes = %d, want 0", n)
	}

	// 4. Missing namespace config is a retryable error (nothing written).
	te.envs["CF_KV_NAMESPACE_ID"] = ""
	if _, err := runKvMirror(context.Background(), e, job("/robots.txt", "text/plain", "", robots)); err == nil {
		t.Fatal("expected an error when CF_KV_NAMESPACE_ID is unset")
	}
}

func TestKvMirrorPathSet(t *testing.T) {
	ok := []string{"/robots.txt", "/sitemap.xml", "/sitemaps/0.xml", "/llms.txt", "/index.md",
		"/.well-known/agent.json", "/.well-known/security.txt", "/" + strings.Repeat("a", 32) + ".txt"}
	for _, p := range ok {
		if !kvMirrorPath(p) {
			t.Errorf("kvMirrorPath(%q) = false, want true", p)
		}
	}
	bad := []string{"/", "/kb/x", "/index.html", "/sitemaps/../secret", "/.well-known/../etc",
		"/AAAA.txt", "/" + strings.Repeat("a", 31) + ".txt", "/robots.txtx", "/favicon.ico"}
	for _, p := range bad {
		if kvMirrorPath(p) {
			t.Errorf("kvMirrorPath(%q) = true, want false", p)
		}
	}
}
