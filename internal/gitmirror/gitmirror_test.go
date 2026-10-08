package gitmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
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
	} else if pool, done := testdb.Open("gitmirror", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping gitmirror DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// fakeUp stands in for Forgejo: it records every request (path+query, headers, body), answers
// canned smart-HTTP replies with the cookies and banners a real server adds, optionally blocks
// upload-pack on a gate (semaphore test) or delegates git paths to a real git http-backend.
type fakeUp struct {
	srv *httptest.Server

	mu            sync.Mutex
	paths         []string
	hdrs          []http.Header
	bodies        [][]byte
	hits          map[string]int
	gate          chan struct{}
	next          http.Handler
	archive       []byte
	archiveStatus int

	inflight, maxInflight atomic.Int32
}

const (
	upRefs = "/commons/kb.git/info/refs"
	upPack = "/commons/kb.git/git-upload-pack"
	upArch = "/api/v1/repos/commons/kb/archive/main.tar.gz"
)

func (f *fakeUp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.RequestURI())
	f.hdrs = append(f.hdrs, r.Header.Clone())
	f.bodies = append(f.bodies, body)
	f.hits[r.URL.Path]++
	gate, next, archive, status := f.gate, f.next, f.archive, f.archiveStatus
	f.mu.Unlock()
	switch r.URL.Path {
	case upRefs, upPack:
		if next != nil {
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == upPack && gate != nil {
			n := f.inflight.Add(1)
			defer f.inflight.Add(-1)
			for m := f.maxInflight.Load(); n > m && !f.maxInflight.CompareAndSwap(m, n); m = f.maxInflight.Load() {
			}
			<-gate
		}
		w.Header().Set("Set-Cookie", "i_like_gitea=1; Path=/")
		w.Header().Set("Server", "forgejo")
		w.Header().Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
		if r.URL.Path == upRefs {
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			io.WriteString(w, "001e# service=git-upload-pack\n0000")
			return
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
		io.WriteString(w, "0008NAK\n")
	case "/api/v1/repos/commons/kb":
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"name":"kb","default_branch":"main"}`)
	case upArch:
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(archive)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeUp) set(fn func(*fakeUp)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeUp) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

// lastHeader returns the headers of the latest request to path.
func (f *fakeUp) lastHeader(path string) http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.paths) - 1; i >= 0; i-- {
		if p, _, _ := strings.Cut(f.paths[i], "?"); p == path {
			return f.hdrs[i]
		}
	}
	return nil
}

func (f *fakeUp) lastBody() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.bodies) == 0 {
		return nil
	}
	return f.bodies[len(f.bodies)-1]
}

type tenv struct {
	t   *testing.T
	d   *core.Deps
	s   *svc
	srv *httptest.Server
	up  *fakeUp
	net string // 10.a.b: one /24 per env so quotas never leak across tests
}

func newEnv(t *testing.T, enabled bool) *tenv {
	t.Helper()
	up := &fakeUp{hits: map[string]int{}}
	up.srv = httptest.NewServer(up)
	t.Cleanup(up.srv.Close)
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20, ForgejoROToken: "test-ro"}
	cfg.ExportDir = filepath.Join(cfg.DataDir, "export")
	if enabled {
		cfg.ForgejoURL = up.srv.URL
	}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	core.Register(mux, d)
	s := register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	var b [2]byte
	rand.Read(b[:])
	return &tenv{t: t, d: d, s: s, srv: srv, up: up, net: fmt.Sprintf("10.%d.%d", b[0], b[1])}
}

func (e *tenv) ip(n int) string { return fmt.Sprintf("%s.%d", e.net, n) }

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// try sends one request as client ip (CF-Connecting-IP); hdr are key/value pairs.
func (e *tenv) try(method, path, ip string, body io.Reader, hdr ...string) (*http.Response, string, error) {
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		return nil, "", err
	}
	if ip != "" {
		req.Header.Set("CF-Connecting-IP", ip)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	return res, string(b), err
}

func (e *tenv) do(method, path, ip string, body io.Reader, hdr ...string) (*http.Response, string) {
	e.t.Helper()
	res, b, err := e.try(method, path, ip, body, hdr...)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	return res, b
}

const (
	refsPath = "/git/kb.git/info/refs?service=git-upload-pack"
	packPath = "/git/kb.git/git-upload-pack"
	tarPath  = "/git/kb.tar.gz"
)

func (e *tenv) pack(ip string, body []byte, hdr ...string) (*http.Response, string) {
	e.t.Helper()
	return e.do("POST", packPath, ip, bytes.NewReader(body), append([]string{"Content-Type", ctUploadReq}, hdr...)...)
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	io.WriteString(w, s)
	w.Close()
	return b.Bytes()
}

func TestOnlyTwoPatterns(t *testing.T) {
	e := newEnv(t, true)
	if got := e.d.CostOf("GET /git/kb.git/info/refs"); got != 3 {
		t.Fatalf("limiter cost = %v, want 3", got)
	}
	if got := e.d.CostOf("POST " + packPath); got != 3 {
		t.Fatalf("limiter cost = %v, want 3", got)
	}
	if sc, ok := e.d.ScopeOf("GET " + tarPath); !ok || sc != "kb:r" {
		t.Fatalf("scope = %q %v", sc, ok)
	}
	cases := []struct {
		method, path string
		want         int
	}{
		{"GET", refsPath, 200},
		{"POST", packPath, 200},
		{"HEAD", refsPath, 404}, // matches the GET pattern but is not a clone
		{"GET", "/git/kb.git/info/refs", 404},
		{"GET", "/git/kb.git/info/refs?service=git-upload-pack&x=1", 404},
		{"GET", "/git/kb.git/info/refs?service=git-upload-pack%2F", 404},
		{"GET", "/git/kb.git/info/refs?service=git-upload-pack&service=git-upload-pack", 404},
		{"GET", "/git/kb.git/info/refs?service=git-upload-pack#frag", 200}, // fragments never leave the client
		{"GET", "/git/kb%2Egit/info/refs?service=git-upload-pack", 404},
		{"GET", "/git/kb.git/info%2Frefs?service=git-upload-pack", 404},
		{"GET", "/git/kb.git/info/refs?service=git-receive-pack", 403},
		{"POST", "/git/kb.git/git-receive-pack", 403},
		{"GET", "/git/kb.git/HEAD", 404},
		{"GET", "/git/kb.git/objects/info/packs", 404},
		{"GET", "/git/other.git/info/refs?service=git-upload-pack", 404},
		{"GET", packPath, 404},
		{"POST", packPath + "?x=1", 404},
		{"POST", refsPath, 404},
		{"GET", "/git/", 404},
		{"GET", "/git", 307}, // the mux redirects to the /git/ subtree; still never proxied
		{"GET", "/git/kb.git", 404},
	}
	for i, c := range cases {
		var body io.Reader
		var hdr []string
		if c.method == "POST" {
			body, hdr = strings.NewReader("0000"), []string{"Content-Type", ctUploadReq}
		}
		res, b := e.do(c.method, c.path, e.ip(i+1), body, hdr...)
		if res.StatusCode != c.want {
			t.Errorf("%s %s = %d, want %d: %s", c.method, c.path, res.StatusCode, c.want, b)
		}
		if res.StatusCode == 404 && c.method != "HEAD" && !strings.Contains(b, "/git/kb.tar.gz") {
			t.Errorf("%s %s: 404 body should point to the tarball: %s", c.method, c.path, b)
		}
	}
	// A dot segment is cleaned and redirected by the mux (never proxied); either way no upstream call.
	res, _ := e.do("GET", "/git/kb.git/../kb.git/info/refs?service=git-upload-pack", e.ip(40), nil)
	if res.StatusCode == 200 {
		t.Errorf("dot segment path answered 200")
	}
	e.up.mu.Lock()
	defer e.up.mu.Unlock()
	for _, p := range e.up.paths {
		if p != upRefs+"?service=git-upload-pack" && p != upPack {
			t.Errorf("upstream saw %q", p)
		}
	}
	if len(e.up.paths) != 3 {
		t.Errorf("upstream saw %d requests, want 3 (refs, pack, refs#frag): %q", len(e.up.paths), e.up.paths)
	}
}

func TestNoAuthForwarding(t *testing.T) {
	e := newEnv(t, true)
	client := []string{"Authorization", "Bearer cx_" + strings.Repeat("a", 43), "Cookie", "sid=1", "X-Forwarded-For", "9.9.9.9",
		"X-Real-IP", "8.8.8.8", "Git-Protocol", "version=2", "Accept", "application/x-git-upload-pack-advertisement",
		"User-Agent", "git/2.50.1", "Accept-Encoding", "gzip, br", "Referer", "https://evil.example/"}
	res, body := e.do("GET", refsPath, e.ip(1), nil, client...)
	if res.StatusCode != 200 || !strings.HasPrefix(body, "001e# service=git-upload-pack") {
		t.Fatalf("refs: %d %q", res.StatusCode, body)
	}
	h := e.up.lastHeader(upRefs)
	if h == nil {
		t.Fatal("upstream saw no info/refs")
	}
	if got := h.Get("Authorization"); got != "token test-ro" {
		t.Errorf("upstream Authorization = %q, want the read-only token", got)
	}
	for _, k := range []string{"Cookie", "X-Forwarded-For", "X-Real-IP", "Accept-Encoding", "Referer", "CF-Connecting-IP", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
		if v := h.Get(k); v != "" {
			t.Errorf("upstream got %s: %q", k, v)
		}
	}
	if h.Get("Git-Protocol") != "version=2" || h.Get("Accept") != "application/x-git-upload-pack-advertisement" {
		t.Errorf("whitelisted headers not forwarded: %v", h)
	}
	if h.Get("User-Agent") != userAgent {
		t.Errorf("User-Agent = %q", h.Get("User-Agent"))
	}
	// Upstream cookies and banners never reach the client; the git content type does.
	if res.Header.Get("Set-Cookie") != "" || res.Header.Get("Server") != "" {
		t.Errorf("leaked response headers: %v", res.Header)
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/x-git-upload-pack-advertisement" {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(res.Header.Get("Cache-Control"), "no-cache") {
		t.Errorf("Cache-Control = %q", res.Header.Get("Cache-Control"))
	}
	// Same on the POST path, with the raw body passed through byte for byte.
	want := "0032want 0000000000000000000000000000000000000000\n00000009done\n"
	res, body = e.pack(e.ip(2), []byte(want), client...)
	if res.StatusCode != 200 || body != "0008NAK\n" {
		t.Fatalf("pack: %d %q", res.StatusCode, body)
	}
	h = e.up.lastHeader(upPack)
	if h.Get("Authorization") != "token test-ro" || h.Get("Cookie") != "" || h.Get("X-Forwarded-For") != "" {
		t.Errorf("pack upstream headers: %v", h)
	}
	if h.Get("Content-Type") != ctUploadReq || h.Get("Content-Length") != fmt.Sprint(len(want)) {
		t.Errorf("pack upstream Content-Type/Length: %v", h)
	}
	if got := string(e.up.lastBody()); got != want {
		t.Errorf("upstream body = %q", got)
	}
}

func TestBodyCapAndSemaphore(t *testing.T) {
	e := newEnv(t, true)
	res, body := e.pack(e.ip(1), bytes.Repeat([]byte("a"), int(MaxBody)+1))
	if res.StatusCode != 413 || !strings.Contains(body, "err size") {
		t.Fatalf("over cap: %d %q", res.StatusCode, body)
	}
	if res, _ = e.pack(e.ip(2), bytes.Repeat([]byte("b"), int(MaxBody))); res.StatusCode != 200 {
		t.Fatalf("at cap: %d", res.StatusCode)
	}
	if got := len(e.up.lastBody()); int64(got) != MaxBody {
		t.Fatalf("upstream got %d bytes", got)
	}
	// gzip request bodies (git sends them past 1 KiB) are inflated here; the cap counts real bytes.
	plain := strings.Repeat("0032have 0000000000000000000000000000000000000000\n", 40)
	if res, _ = e.pack(e.ip(3), gz(t, plain), "Content-Encoding", "gzip"); res.StatusCode != 200 {
		t.Fatalf("gzip body: %d", res.StatusCode)
	}
	if string(e.up.lastBody()) != plain || e.up.lastHeader(upPack).Get("Content-Encoding") != "" {
		t.Fatalf("gzip body not inflated for upstream")
	}
	bomb := gz(t, strings.Repeat("\x00", int(MaxBody)+1))
	if res, body = e.pack(e.ip(4), bomb, "Content-Encoding", "gzip"); res.StatusCode != 413 {
		t.Fatalf("gzip bomb: %d %q (compressed %d bytes)", res.StatusCode, body, len(bomb))
	}
	if res, _ = e.pack(e.ip(5), []byte("0000"), "Content-Encoding", "br"); res.StatusCode != 415 {
		t.Fatalf("unsupported encoding: %d", res.StatusCode)
	}
	res, _ = e.do("POST", packPath, e.ip(6), strings.NewReader("0000"), "Content-Type", "text/plain")
	if res.StatusCode != 415 {
		t.Fatalf("wrong content type: %d", res.StatusCode)
	}
	if n := e.up.count(upPack); n != 2 {
		t.Fatalf("upstream saw %d upload-packs, want 2 (refused bodies never leave)", n)
	}

	// Semaphore: two fetches run upstream at once, the third waits SemWait then gets 503.
	old := SemWait
	SemWait = 300 * time.Millisecond
	t.Cleanup(func() { SemWait = old })
	gate := make(chan struct{})
	e.up.set(func(f *fakeUp) { f.gate = gate })
	var wg sync.WaitGroup
	var finished atomic.Int32
	statuses := make([]int, 3)
	errs := make([]error, 3)
	for i := range statuses {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer finished.Add(1)
			res, _, err := e.try("POST", packPath, e.ip(10+i), strings.NewReader("0000"), "Content-Type", ctUploadReq)
			if err != nil {
				errs[i] = err
				return
			}
			statuses[i] = res.StatusCode
			if res.StatusCode == 503 && res.Header.Get("Retry-After") == "" {
				errs[i] = fmt.Errorf("503 without Retry-After")
			}
		}(i)
	}
	for deadline := time.Now().Add(10 * time.Second); finished.Load() < 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	close(gate)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	sort.Ints(statuses)
	if fmt.Sprint(statuses) != "[200 200 503]" {
		t.Fatalf("statuses = %v", statuses)
	}
	if m := e.up.maxInflight.Load(); m != 2 {
		t.Fatalf("max concurrent upstream fetches = %d, want 2", m)
	}
	if n := e.up.count(upPack); n != 4 {
		t.Fatalf("upstream saw %d upload-packs, want 4", n)
	}
}

func TestCloneQuotaPerSuper(t *testing.T) {
	e := newEnv(t, true)
	for i := 1; i <= CloneQuota; i++ {
		if res, body := e.do("GET", refsPath, e.ip(i), nil); res.StatusCode != 200 {
			t.Fatalf("clone %d: %d %s", i, res.StatusCode, body)
		}
	}
	res, body := e.do("GET", refsPath, e.ip(CloneQuota+1), nil)
	if res.StatusCode != 429 || !strings.Contains(body, "/git/kb.tar.gz") || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("over quota: %d %q", res.StatusCode, body)
	}
	if res.Header.Get("Retry-After") == "" {
		t.Errorf("429 without Retry-After")
	}
	if n := e.up.count(upRefs); n != CloneQuota {
		t.Errorf("upstream saw %d info/refs, want %d", n, CloneQuota)
	}
	// The counter is keyed on the super-group, not the IP group.
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT n FROM counters WHERE scope = $1 AND kind = 'git-clone' AND day = current_date`,
		"ip:"+core.IPSuper(e.ip(1))).Scan(&n); err != nil || n != CloneQuota+1 {
		t.Errorf("super counter = %d %v, want %d", n, err, CloneQuota+1)
	}
	// Another /24 is unaffected.
	other := newEnv(t, true)
	if res, body := other.do("GET", refsPath, other.ip(1), nil); res.StatusCode != 200 {
		t.Fatalf("other network: %d %s", res.StatusCode, body)
	}
	// Fetch rounds have their own daily quota per super-group.
	old := PackQuota
	PackQuota = 2
	t.Cleanup(func() { PackQuota = old })
	for i := 1; i <= 2; i++ {
		if res, body := e.pack(e.ip(20+i), []byte("0000")); res.StatusCode != 200 {
			t.Fatalf("pack %d: %d %s", i, res.StatusCode, body)
		}
	}
	if res, body := e.pack(e.ip(23), []byte("0000")); res.StatusCode != 429 || !strings.Contains(body, "/git/kb.tar.gz") {
		t.Fatalf("pack over quota: %d %q", res.StatusCode, body)
	}
	if n := e.up.count(upPack); n != 2 {
		t.Errorf("upstream saw %d upload-packs, want 2", n)
	}
}

func TestTarballCache(t *testing.T) {
	e := newEnv(t, true)
	v1 := gz(t, "snapshot one")
	e.up.set(func(f *fakeUp) { f.archive = v1 })
	res, body := e.do("GET", tarPath, e.ip(1), nil)
	if res.StatusCode != 200 || body != string(v1) {
		t.Fatalf("first: %d %d bytes", res.StatusCode, len(body))
	}
	if ct := res.Header.Get("Content-Type"); ct != "application/gzip" {
		t.Errorf("Content-Type = %q", ct)
	}
	if h := e.up.lastHeader(upArch); h == nil || h.Get("Authorization") != "token test-ro" {
		t.Errorf("archive request headers: %v", h)
	}
	path := filepath.Join(e.d.Cfg.ExportDir, tarName)
	if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, v1) {
		t.Fatalf("cache file: %v", err)
	}
	if res, body = e.do("GET", tarPath, e.ip(2), nil); res.StatusCode != 200 || body != string(v1) || e.up.count(upArch) != 1 {
		t.Fatalf("second: %d, upstream hits %d", res.StatusCode, e.up.count(upArch))
	}
	if res, body = e.do("HEAD", tarPath, e.ip(3), nil); res.StatusCode != 200 || body != "" || res.Header.Get("Content-Length") != fmt.Sprint(len(v1)) {
		t.Fatalf("HEAD: %d %q %q", res.StatusCode, body, res.Header.Get("Content-Length"))
	}
	lm := res.Header.Get("Last-Modified")
	if res, _ = e.do("GET", tarPath, e.ip(4), nil, "If-Modified-Since", lm); res.StatusCode != 304 {
		t.Errorf("If-Modified-Since: %d", res.StatusCode)
	}
	if res, body = e.do("GET", tarPath+"?x=1", e.ip(5), nil); res.StatusCode != 404 {
		t.Errorf("query on tarball: %d %s", res.StatusCode, body)
	}
	// Older than a day: refreshed from upstream on the next request.
	stale := time.Now().Add(-TarballTTL - time.Hour)
	os.Chtimes(path, stale, stale)
	v2 := gz(t, "snapshot two")
	e.up.set(func(f *fakeUp) { f.archive = v2 })
	if res, body = e.do("GET", tarPath, e.ip(6), nil); res.StatusCode != 200 || body != string(v2) || e.up.count(upArch) != 2 {
		t.Fatalf("refresh: %d %q, upstream hits %d", res.StatusCode, body, e.up.count(upArch))
	}
	// Upstream down: the stale snapshot is served and the next request backs off.
	os.Chtimes(path, stale, stale)
	e.up.set(func(f *fakeUp) { f.archiveStatus = 500 })
	if res, body = e.do("GET", tarPath, e.ip(7), nil); res.StatusCode != 200 || body != string(v2) || e.up.count(upArch) != 3 {
		t.Fatalf("stale fallback: %d, upstream hits %d", res.StatusCode, e.up.count(upArch))
	}
	if res, body = e.do("GET", tarPath, e.ip(8), nil); res.StatusCode != 200 || body != string(v2) || e.up.count(upArch) != 3 {
		t.Fatalf("back-off: %d, upstream hits %d", res.StatusCode, e.up.count(upArch))
	}
	if b, err := os.ReadFile(path); err != nil || !bytes.Equal(b, v2) {
		t.Fatalf("cache file after failure: %v", err)
	}
	if m, _ := filepath.Glob(filepath.Join(e.d.Cfg.ExportDir, "*.tmp")); len(m) != 0 {
		t.Errorf("temp files left behind: %v", m)
	}

	// No snapshot yet and an unusable upstream: 503, nothing cached.
	oldRetry := TarballRetry
	TarballRetry = 0
	t.Cleanup(func() { TarballRetry = oldRetry })
	e2 := newEnv(t, true)
	e2.up.set(func(f *fakeUp) { f.archiveStatus = 500 })
	if res, body = e2.do("GET", tarPath, e2.ip(1), nil); res.StatusCode != 503 {
		t.Fatalf("no snapshot, upstream 500: %d %s", res.StatusCode, body)
	}
	e2.up.set(func(f *fakeUp) { f.archiveStatus = 0; f.archive = []byte("<html>not an archive</html>") })
	if res, body = e2.do("GET", tarPath, e2.ip(2), nil); res.StatusCode != 503 {
		t.Fatalf("no snapshot, html upstream: %d %s", res.StatusCode, body)
	}
	if _, err := os.Stat(filepath.Join(e2.d.Cfg.ExportDir, tarName)); err == nil {
		t.Fatal("non-gzip body was cached")
	}
	e2.up.set(func(f *fakeUp) { f.archive = v1 })
	if res, body = e2.do("GET", tarPath, e2.ip(3), nil); res.StatusCode != 200 || body != string(v1) {
		t.Fatalf("recovered: %d", res.StatusCode)
	}
}

func TestDisabledWithoutForgejo(t *testing.T) {
	e := newEnv(t, false)
	if e.s != nil {
		t.Fatal("service built with FORGEJO_URL empty")
	}
	for _, c := range []struct{ method, path string }{{"GET", refsPath}, {"POST", packPath}, {"GET", tarPath}, {"GET", "/git/kb.git/HEAD"}} {
		var body io.Reader
		if c.method == "POST" {
			body = strings.NewReader("0000")
		}
		res, b := e.do(c.method, c.path, e.ip(1), body, "Content-Type", ctUploadReq)
		if res.StatusCode != 404 || !strings.Contains(b, "disabled") {
			t.Errorf("%s %s = %d %q, want 404 disabled", c.method, c.path, res.StatusCode, b)
		}
	}
	if len(e.up.paths) != 0 {
		t.Errorf("upstream contacted while disabled: %v", e.up.paths)
	}
	if _, ok := e.d.ScopeOf("GET " + tarPath); ok {
		t.Error("routes registered while disabled")
	}
}

// gitTools finds git and its http-backend CGI, skipping the test without them.
func gitTools(t *testing.T) (git, backend string) {
	t.Helper()
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	out, err := exec.Command(git, "--exec-path").Output()
	if err != nil {
		t.Skip("git --exec-path failed")
	}
	backend = filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend not installed")
	}
	return git, backend
}

func gitEnv(home string) []string {
	return append(os.Environ(), "HOME="+home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
}

func gitRun(t *testing.T, home, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir, cmd.Env = dir, gitEnv(home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}

// TestGitClone clones through the proxy from a real `git http-backend` behind the fake upstream
// (which still checks the read-only token), with protocol v2 and v0, then sees a push refused.
func TestGitClone(t *testing.T) {
	git, backend := gitTools(t)
	home, root := t.TempDir(), t.TempDir()
	repo := filepath.Join(root, "commons", "kb.git")
	gitRun(t, home, "", git, "init", "-q", "--bare", "-b", "main", repo)
	work := t.TempDir()
	gitRun(t, home, work, git, "init", "-q", "-b", "main")
	os.MkdirAll(filepath.Join(work, "entries"), 0o755)
	os.WriteFile(filepath.Join(work, "entries", "k1.md"), []byte("---\nid: k1\n---\n# hello\n"), 0o644)
	gitRun(t, home, work, git, "add", ".")
	gitRun(t, home, work, git, "commit", "-q", "-m", "seed")
	gitRun(t, home, work, git, "push", "-q", repo, "main")

	e := newEnv(t, true)
	cgiH := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}, Logger: log.New(io.Discard, "", 0)}
	e.up.set(func(f *fakeUp) {
		f.next = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "token test-ro" {
				http.Error(w, "no token", 401)
				return
			}
			cgiH.ServeHTTP(w, r)
		})
	})
	var dst string
	for _, ver := range []string{"2", "0"} {
		dst = filepath.Join(t.TempDir(), "clone")
		gitRun(t, home, "", git, "-c", "protocol.version="+ver, "clone", "-q", e.srv.URL+"/git/kb.git", dst)
		if b, err := os.ReadFile(filepath.Join(dst, "entries", "k1.md")); err != nil || !strings.Contains(string(b), "# hello") {
			t.Fatalf("protocol v%s clone content: %v", ver, err)
		}
	}
	if n := e.up.count(upRefs); n != 2 {
		t.Errorf("upstream saw %d ref advertisements, want 2", n)
	}
	if e.up.count(upPack) < 2 {
		t.Errorf("upstream saw %d upload-packs", e.up.count(upPack))
	}
	os.WriteFile(filepath.Join(dst, "entries", "k2.md"), []byte("# two\n"), 0o644)
	gitRun(t, home, dst, git, "add", ".")
	gitRun(t, home, dst, git, "commit", "-q", "-m", "more")
	cmd := exec.Command(git, "push", "-q", "origin", "main")
	cmd.Dir, cmd.Env = dst, gitEnv(home)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "403") {
		t.Fatalf("push should be refused with 403: %v\n%s", err, out)
	}
}
