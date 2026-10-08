package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// upstream is a fake gateway: it records the last request it fully read and answers its name.
type upstream struct {
	srv  *httptest.Server
	seen atomic.Pointer[http.Request]
	hits atomic.Int64
}

func fakeUpstream(t *testing.T, name string) *upstream {
	t.Helper()
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := r.Clone(r.Context())
		b, _ := io.ReadAll(r.Body)
		c.ContentLength = int64(len(b))
		u.seen.Store(c)
		u.hits.Add(1)
		if r.URL.Path == "/busy" {
			w.Header().Set("Retry-After", "120")
			http.Error(w, "err busy retry shed:feeds", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("X-Upstream", name)
		io.WriteString(w, name)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// wait blocks until the upstream handler finished n requests (the proxy may answer the client
// before a streamed body is fully consumed upstream).
func (u *upstream) wait(t *testing.T, n int64) *http.Request {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for u.hits.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("upstream saw %d requests, want %d", u.hits.Load(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return u.seen.Load()
}

func writeUpstream(t *testing.T, file, u string) {
	t.Helper()
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, []byte(u+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, file); err != nil {
		t.Fatal(err)
	}
}

func newTestEdge(t *testing.T, upstream string) (*edge, *httptest.Server, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "upstream")
	writeUpstream(t, file, upstream)
	e, err := newEdge(file, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(e)
	t.Cleanup(srv.Close)
	return e, srv, file
}

func do(t *testing.T, srv *httptest.Server, method, path, host string, body io.Reader, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestEdgePreservesInboundHost(t *testing.T) {
	up := fakeUpstream(t, "A")
	upURL, _ := url.Parse(up.srv.URL)
	_, srv, _ := newTestEdge(t, up.srv.URL)
	resp, body := do(t, srv, http.MethodGet, "/v1/me?x=1", "agents.ekaii.fr", nil,
		"X-Forwarded-For", "203.0.113.9", "X-Forwarded-Proto", "https", "X-Forwarded-Host", "agents.ekaii.fr", "CF-Connecting-IP", "203.0.113.9")
	if resp.StatusCode != 200 || body != "A" || resp.Header.Get("X-Upstream") != "A" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	r := up.wait(t, 1)
	if r.Host != "agents.ekaii.fr" {
		t.Fatalf("upstream Host %q, want the inbound host", r.Host)
	}
	if strings.Contains(r.Host, upURL.Host) || r.Header.Get("Host") == upURL.Host {
		t.Fatalf("upstream address leaked into Host: %q", r.Host)
	}
	if r.URL.Path != "/v1/me" || r.URL.RawQuery != "x=1" {
		t.Fatalf("path/query not forwarded: %s", r.URL)
	}
	xff := r.Header.Get("X-Forwarded-For")
	if !strings.HasPrefix(xff, "203.0.113.9, ") || !strings.HasSuffix(xff, "127.0.0.1") {
		t.Fatalf("X-Forwarded-For %q: inbound value copied, edge appended", xff)
	}
	if r.Header.Get("X-Forwarded-Proto") != "https" || r.Header.Get("X-Forwarded-Host") != "agents.ekaii.fr" || r.Header.Get("CF-Connecting-IP") != "203.0.113.9" {
		t.Fatalf("forwarded headers: %v", r.Header)
	}
	// Without inbound X-Forwarded-* the edge fills them from what it sees.
	do(t, srv, http.MethodGet, "/", "agents.ekaii.fr", nil)
	r = up.wait(t, 2)
	if r.Header.Get("X-Forwarded-Proto") != "http" || r.Header.Get("X-Forwarded-Host") != "agents.ekaii.fr" || r.Header.Get("X-Forwarded-For") != "127.0.0.1" {
		t.Fatalf("defaults: %v", r.Header)
	}
}

func TestUpstreamFlipSIGHUP(t *testing.T) {
	a, b := fakeUpstream(t, "A"), fakeUpstream(t, "B")
	e, srv, file := newTestEdge(t, a.srv.URL)
	ctx, cancel := signalCtx()
	defer cancel()
	go e.watchHUP(ctx)
	time.Sleep(50 * time.Millisecond) // signal.Notify installed
	if _, body := do(t, srv, http.MethodGet, "/", "agents.ekaii.fr", nil); body != "A" {
		t.Fatalf("before flip %q", body)
	}
	writeUpstream(t, file, b.srv.URL)
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for e.up.Load().String() != b.srv.URL {
		if time.Now().After(deadline) {
			t.Fatalf("upstream still %s after SIGHUP", e.up.Load())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, body := do(t, srv, http.MethodGet, "/", "agents.ekaii.fr", nil); body != "B" {
		t.Fatalf("after flip %q", body)
	}
	if r := b.wait(t, 1); r.Host != "agents.ekaii.fr" {
		t.Fatalf("host after flip %q", r.Host)
	}
	// A broken file keeps the previous upstream.
	writeUpstream(t, file, "ftp://nope")
	if err := e.reload(); err == nil || e.up.Load().String() != b.srv.URL {
		t.Fatalf("bad upstream accepted: %v %s", err, e.up.Load())
	}
	os.Remove(file)
	if err := e.reload(); err == nil || e.up.Load().String() != b.srv.URL {
		t.Fatalf("missing file accepted: %v %s", err, e.up.Load())
	}
	// Only the first line counts; surrounding whitespace is fine.
	writeUpstream(t, file, "  "+a.srv.URL+"  \nignored")
	if err := e.reload(); err != nil || e.up.Load().String() != a.srv.URL {
		t.Fatalf("reload: %v %s", err, e.up.Load())
	}
}

func TestEdgeRetryAfterPassThroughAndErrors(t *testing.T) {
	up := fakeUpstream(t, "A")
	e, srv, _ := newTestEdge(t, up.srv.URL)
	resp, body := do(t, srv, http.MethodGet, "/busy", "agents.ekaii.fr", nil)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "120" || !strings.Contains(body, "err busy") {
		t.Fatalf("Retry-After pass-through: %d %q %q", resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
	up.wait(t, 1)
	// Body cap: a declared oversize body is refused before the upstream sees it; a chunked one is
	// cut at 5 MB while streaming and the client gets 413.
	resp, _ = do(t, srv, http.MethodPost, "/v1/kb", "agents.ekaii.fr", strings.NewReader(strings.Repeat("x", maxBody+1)), "Content-Type", "text/plain")
	if resp.StatusCode != 413 || up.hits.Load() != 1 {
		t.Fatalf("declared oversize: %d hits=%d", resp.StatusCode, up.hits.Load())
	}
	resp, _ = do(t, srv, http.MethodPost, "/v1/kb", "agents.ekaii.fr", io.NopCloser(strings.NewReader(strings.Repeat("y", maxBody+1))), "Content-Type", "text/plain")
	if resp.StatusCode != 413 {
		t.Fatalf("chunked oversize: %d", resp.StatusCode)
	}
	if r := up.wait(t, 2); r.ContentLength > maxBody {
		t.Fatalf("upstream received %d bytes, cap is %d", r.ContentLength, maxBody)
	}
	resp, body = do(t, srv, http.MethodPost, "/v1/kb", "agents.ekaii.fr", strings.NewReader("hello"), "Content-Type", "text/plain")
	if r := up.wait(t, 3); resp.StatusCode != 200 || body != "A" || r.ContentLength != 5 {
		t.Fatalf("small body: %d %q len=%d", resp.StatusCode, body, r.ContentLength)
	}
	// Dead upstream: 503 + Retry-After: 1, never another 5xx.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	writeUpstream(t, e.file, deadURL)
	if err := e.reload(); err != nil {
		t.Fatal(err)
	}
	resp, body = do(t, srv, http.MethodGet, "/v1/ev?wait=30", "agents.ekaii.fr", nil)
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "1" || !strings.Contains(body, "err busy") {
		t.Fatalf("dead upstream: %d %q %q", resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
}
