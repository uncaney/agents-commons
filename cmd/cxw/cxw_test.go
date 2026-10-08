package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ekaii.fr/commons/internal/sandbox"
)

func TestParseWindow(t *testing.T) {
	loc := time.UTC
	at := func(h, m int) time.Time { return time.Date(2026, 10, 6, h, m, 0, 0, loc) }
	cases := []struct {
		in   string
		ok   bool
		pos  []time.Time
		neg  []time.Time
		repr string
	}{
		{"", true, []time.Time{at(0, 0), at(12, 0), at(23, 59)}, nil, "always"},
		{"22-07", true, []time.Time{at(22, 0), at(23, 30), at(0, 0), at(6, 59)}, []time.Time{at(7, 0), at(12, 0), at(21, 59)}, "22:00-07:00"},
		{"09-17", true, []time.Time{at(9, 0), at(16, 59)}, []time.Time{at(8, 59), at(17, 0), at(23, 0)}, "09:00-17:00"},
		{"08:30-09:15", true, []time.Time{at(8, 30), at(9, 14)}, []time.Time{at(8, 29), at(9, 15)}, "08:30-09:15"},
		{"0-24", true, []time.Time{at(0, 0), at(23, 59)}, nil, "always"},
		{"7", false, nil, nil, ""},
		{"25-07", false, nil, nil, ""},
		{"a-b", false, nil, nil, ""},
		{"22:60-07", false, nil, nil, ""},
	}
	for _, c := range cases {
		w, err := ParseWindow(c.in)
		if (err == nil) != c.ok {
			t.Errorf("%q: err=%v", c.in, err)
			continue
		}
		if !c.ok {
			continue
		}
		if w.String() != c.repr {
			t.Errorf("%q: repr %q", c.in, w.String())
		}
		for _, tm := range c.pos {
			if !w.Contains(tm) {
				t.Errorf("%q should contain %v", c.in, tm)
			}
		}
		for _, tm := range c.neg {
			if w.Contains(tm) {
				t.Errorf("%q should not contain %v", c.in, tm)
			}
		}
	}
	w, _ := ParseWindow("22-07")
	if d := w.Until(at(20, 0)); d != 2*time.Hour {
		t.Errorf("until from 20:00 = %v", d)
	}
	if d := w.Until(at(23, 0)); d != 0 {
		t.Errorf("until inside = %v", d)
	}
	if d := w.Until(at(23, 0).Add(-time.Minute)); d != 0 {
		t.Errorf("until inside = %v", d)
	}
}

func TestLoadConfig(t *testing.T) {
	tf := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(tf, []byte("cx_secret\n"), 0o600)
	env := map[string]string{"CX_TOKEN_FILE": tf, "MAX_MS": "5000", "HOURS": "22-07", "CX_URL": "http://x/"}
	get := func(k string) string { return env[k] }
	cfg, err := loadConfig(get)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != "cx_secret" || cfg.MaxMs != 5000 || cfg.MaxMb != 256 || cfg.Parallel != 1 || cfg.URL != "http://x" || cfg.Hours.String() != "22:00-07:00" || cfg.MemLimit != 400 {
		t.Fatalf("%+v", cfg)
	}
	// v2 defaults: no pins, 10 s compile budget, probation and L0 jobs opt-in.
	if cfg.PinMaxMb != 0 || cfg.CompileMs != 10000 || cfg.AcceptNew || cfg.AcceptL0 {
		t.Fatalf("v2 defaults: %+v", cfg)
	}
	env["MEM_LIMIT_MB"] = "256"
	if cfg, err := loadConfig(get); err != nil || cfg.MemLimit != 256 {
		t.Fatalf("MEM_LIMIT_MB: %+v %v", cfg, err)
	}
	env["MEM_LIMIT_MB"] = "1"
	if _, err := loadConfig(get); err == nil {
		t.Fatal("expected MEM_LIMIT_MB range error")
	}
	delete(env, "MEM_LIMIT_MB")
	env["MAX_MB"] = "999"
	if _, err := loadConfig(get); err == nil {
		t.Fatal("expected MAX_MB range error")
	}
	delete(env, "MAX_MB")
	env["PIN_MAX_MB"] = "64"
	if _, err := loadConfig(get); err == nil || !strings.Contains(err.Error(), "CACHE_DIR") {
		t.Fatalf("PIN_MAX_MB without CACHE_DIR must fail: %v", err)
	}
	env["CACHE_DIR"], env["COMPILE_MS"], env["ACCEPT_NEW"], env["ACCEPT_L0"] = "/cache", "2500", "1", "0"
	cfg, err = loadConfig(get)
	if err != nil || cfg.PinMaxMb != 64 || cfg.CacheDir != "/cache" || cfg.CompileMs != 2500 || !cfg.AcceptNew || cfg.AcceptL0 {
		t.Fatalf("v2 config: %+v %v", cfg, err)
	}
	env["PIN_MAX_MB"] = "5000"
	if _, err := loadConfig(get); err == nil {
		t.Fatal("expected PIN_MAX_MB range error")
	}
	if _, err := loadConfig(func(string) string { return "" }); err == nil {
		t.Fatal("expected missing token error")
	}
}

// fake is a minimal gateway: leases, blob store, pins, pub registration, done capture.
type fake struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	leases    []Lease
	leaseReqs []LeaseReq
	done      []Done
	pins      []Pin
	pinsCalls int
	pub       string // last PUT /v1/me pub
	pubReply  string // pub the gateway claims to hold (empty = echo)
	meStatus  int    // non-zero: PUT /v1/me fails with this status
	auth      string
	leased    int
	corrupt   bool
	gets      map[string]int // GET /v1/b/{hash} count
	getLease  []string       // X-Lease header of each blob download
	putLease  []string       // X-Lease header of each upload
}

func newFake(token string) *fake {
	return &fake{blobs: map[string][]byte{}, gets: map[string]int{}, auth: "Bearer " + token}
}

func (f *fake) put(b []byte) string {
	h := sha256hex(b)
	f.mu.Lock()
	f.blobs[h] = b
	f.mu.Unlock()
	return h
}

func (f *fake) handler() http.Handler {
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != f.auth || r.Header.Get("Accept") != "application/json" {
				http.Error(w, `{"err":"auth"}`, 401)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("POST /v1/w/lease", auth(func(w http.ResponseWriter, r *http.Request) {
		var req LeaseReq
		json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		f.leaseReqs = append(f.leaseReqs, req)
		if f.leased >= len(f.leases) || req.MaxMs <= 0 {
			w.WriteHeader(204)
			return
		}
		l := f.leases[f.leased]
		f.leased++
		json.NewEncoder(w).Encode(l)
	}))
	mux.HandleFunc("GET /v1/b/{hash}", auth(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		b, ok := f.blobs[r.PathValue("hash")]
		f.gets[r.PathValue("hash")]++
		f.getLease = append(f.getLease, r.Header.Get("X-Lease"))
		f.mu.Unlock()
		if !ok {
			http.Error(w, `{"err":"notfound"}`, 404)
			return
		}
		if f.corrupt {
			b = append([]byte("X"), b[1:]...)
		}
		w.Write(b)
	}))
	mux.HandleFunc("POST /v1/b", auth(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.putLease = append(f.putLease, r.Header.Get("X-Lease"))
		f.mu.Unlock()
		io.WriteString(w, f.put(b)+"\n")
	}))
	mux.HandleFunc("POST /v1/w/done", auth(func(w http.ResponseWriter, r *http.Request) {
		var d Done
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			http.Error(w, `{"err":"bad"}`, 400)
			return
		}
		f.mu.Lock()
		f.done = append(f.done, d)
		f.mu.Unlock()
		io.WriteString(w, `{"ok":true}`)
	}))
	mux.HandleFunc("GET /v1/pins", auth(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.pinsCalls++
		pins := append([]Pin{}, f.pins...)
		f.mu.Unlock()
		json.NewEncoder(w).Encode(pins)
	}))
	mux.HandleFunc("PUT /v1/me", auth(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Pub string `json:"pub"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.meStatus != 0 {
			http.Error(w, `{"err":"scope"}`, f.meStatus)
			return
		}
		f.pub = in.Pub
		reply := f.pubReply
		if reply == "" {
			reply = in.Pub
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "pub": reply})
	}))
	return mux
}

func TestClient(t *testing.T) {
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	ctx := context.Background()
	cl := NewClient(srv.URL, "cx_t")

	if _, err := cl.Lease(ctx, 1, 1000, 64); err != ErrNoLease {
		t.Fatalf("want ErrNoLease, got %v", err)
	}
	h := f.put([]byte("hello"))
	f.leases = []Lease{{Lease: "L1", Job: "j1", Wasm: h, In: h, Ms: 1000, Mb: 64}}
	l, err := cl.Lease(ctx, 1, 1000, 64)
	if err != nil || l.Lease != "L1" || l.Wasm != h {
		t.Fatalf("lease: %+v %v", l, err)
	}
	b, err := cl.GetBlob(ctx, h)
	if err != nil || string(b) != "hello" {
		t.Fatalf("get: %q %v", b, err)
	}
	f.corrupt = true
	if _, err := cl.GetBlob(ctx, h); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("want sha mismatch, got %v", err)
	}
	f.corrupt = false
	if _, err := cl.GetBlob(ctx, strings.Repeat("0", 64)); err == nil {
		t.Fatal("want 404 error")
	}
	if _, err := cl.GetBlob(ctx, "../"+strings.Repeat("a", 61)); err == nil || !strings.Contains(err.Error(), "bad hash") {
		t.Fatalf("a non-hex hash must be refused before any request: %v", err)
	}
	got, err := cl.PutBlob(ctx, []byte("out"), "L1")
	if err != nil || got != sha256hex([]byte("out")) || len(f.putLease) != 1 || f.putLease[0] != "L1" {
		t.Fatalf("put: %s %v lease hdr %v", got, err, f.putLease)
	}
	if _, err := cl.GetBlobMax(ctx, h, 3); !errors.Is(err, ErrTooBig) {
		t.Fatalf("want ErrTooBig, got %v", err)
	}
	if _, err := cl.fetch(ctx, h, 16, "L1"); err != nil || f.getLease[len(f.getLease)-1] != "L1" {
		t.Fatalf("fetch under a lease must send X-Lease: %v %v", err, f.getLease)
	}
	if err := cl.Done(ctx, Done{Lease: "L1", Status: "ok", Out: got}); err != nil {
		t.Fatal(err)
	}
	if len(f.done) != 1 || f.done[0].Out != got {
		t.Fatalf("done: %+v", f.done)
	}
	// Pins: the JSON form (what Accept: application/json gets) and the text form.
	f.pins = []Pin{{Hash: h, Name: "echo", Ver: "1.0", Size: 5}, {Hash: "short", Name: "bad", Size: 1}, {Hash: strings.Repeat("a", 64), Name: "zero", Size: 0}}
	pins, err := cl.Pins(ctx)
	if err != nil || len(pins) != 1 || pins[0].Hash != h || pins[0].Name != "echo" || pins[0].Ver != "1.0" || pins[0].Size != 5 {
		t.Fatalf("pins: %+v %v", pins, err)
	}
	txt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, h+" echo@1.0 5 by=seed\nbad line\n"+strings.Repeat("b", 64)+" lua@5.4 42\n")
	}))
	defer txt.Close()
	pins, err = NewClient(txt.URL, "x").Pins(ctx)
	if err != nil || len(pins) != 2 || pins[0].Ver != "1.0" || pins[1].Name != "lua" || pins[1].Size != 42 {
		t.Fatalf("text pins: %+v %v", pins, err)
	}
	// Pub registration echoes the key the gateway holds.
	pub := strings.Repeat("ab", 32)
	if got, err := cl.PutPub(ctx, pub); err != nil || got != pub || f.pub != pub {
		t.Fatalf("putpub: %q %v (server saw %q)", got, err, f.pub)
	}
	bad := NewClient(srv.URL, "wrong")
	var he *HTTPError
	if _, err := bad.Lease(ctx, 1, 1000, 64); err == nil || !errorsAs(err, &he) || he.Status != 401 {
		t.Fatalf("want 401, got %v", err)
	}
}

func errorsAs(err error, target **HTTPError) bool {
	e, ok := err.(*HTTPError)
	if ok {
		*target = e
	}
	return ok
}

func testModule(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "wasm", "out", name+".wasm"))
	if err != nil {
		t.Skipf("missing test module (run testdata/wasm/build.sh): %v", err)
	}
	return b
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testCfg(url string) Config {
	return Config{URL: url, Token: "cx_t", MaxMs: 30000, MaxMb: 256, Parallel: 1, MemLimit: 400, CompileMs: 10000}
}

// runOnce processes exactly one lease and fails the test when the worker does not stop.
func runOnce(t *testing.T, w *Worker) {
	t.Helper()
	w.once = true
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	w.Run(ctx)
	if ctx.Err() != nil {
		t.Fatal("worker did not stop after one lease")
	}
}

func TestWorkerOnce(t *testing.T) {
	wasm := testModule(t, "echo")
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	wh, ih := f.put(wasm), f.put([]byte("abc"))
	f.leases = []Lease{{Lease: "L1", Job: "j1", Wasm: wh, In: ih, Ms: 5000, Mb: 64}}

	sb, _ := sandbox.New("", 2)
	defer sb.Close(context.Background())
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	cfg := testCfg(srv.URL)
	cfg.Parallel = 2
	w := NewWorker(cfg, NewClient(srv.URL, "cx_t"), sb, log)
	runOnce(t, w)
	if len(f.done) != 1 || f.done[0].Status != "ok" || f.done[0].Lease != "L1" || f.done[0].Dsig != "" {
		t.Fatalf("done: %+v", f.done)
	}
	if out := f.blobs[f.done[0].Out]; string(out) != "ABC" {
		t.Fatalf("out blob %q", out)
	}
	if len(f.putLease) != 1 || f.putLease[0] != "L1" {
		t.Fatalf("output must be uploaded under the lease (X-Lease): %v", f.putLease)
	}
	for _, l := range f.getLease {
		if l != "L1" {
			t.Fatalf("job blobs must be downloaded under the lease (X-Lease): %v", f.getLease)
		}
	}
	if strings.Contains(logs.String(), "cx_t") {
		t.Fatal("token leaked in logs")
	}
	if _, ok := w.blobs.get("w:" + wh); !ok {
		t.Fatal("wasm not cached")
	}

	// cheat mode: wrong output hash but blob still uploaded.
	f.leases = append(f.leases, Lease{Lease: "L2", Job: "j2", Wasm: wh, In: ih, Ms: 5000, Mb: 64})
	w.cheat = true
	runOnce(t, w)
	if len(f.done) != 2 || f.done[1].Out == f.done[0].Out || string(f.blobs[f.done[1].Out]) != "ABCcheat\n" {
		t.Fatalf("cheat done: %+v\nlogs: %s", f.done, logs.String())
	}
}

func TestBackoff(t *testing.T) {
	for n := 1; n < 20; n++ {
		d := backoff(n)
		if d < 500*time.Millisecond || d > maxBackoff {
			t.Fatalf("n=%d d=%v", n, d)
		}
	}
}

// The blob cache is a byte-budget LRU: eviction by accounted size, oversize values not kept.
func TestBlobCache(t *testing.T) {
	c := newBlobCache(2)
	c.put("a", []byte("1"), 1)
	c.put("b", []byte("2"), 1)
	c.get("a")
	c.put("c", []byte("3"), 1)
	if _, ok := c.get("b"); ok {
		t.Fatal("b should be evicted")
	}
	if v, ok := c.get("a"); !ok || string(v.([]byte)) != "1" {
		t.Fatal("a missing")
	}
	c.put("huge", make([]byte, 3), 3)
	if _, ok := c.get("huge"); ok || c.bytes() != 2 {
		t.Fatalf("a value over the budget must not be kept (bytes=%d)", c.bytes())
	}
	c.put("big", nil, 2)
	if _, ok := c.get("a"); ok || c.bytes() != 2 {
		t.Fatalf("budget not enforced: bytes=%d", c.bytes())
	}
}

// Review #4c: a module over the size cap is refused before download/compile and reported as error.
func TestWorkerRefusesBigWasm(t *testing.T) {
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	big := make([]byte, maxWasm+1)
	copy(big, "\x00asm\x01\x00\x00\x00")
	wh, ih := f.put(big), f.put([]byte("abc"))
	f.leases = []Lease{{Lease: "LB", Job: "jb", Wasm: wh, In: ih, Ms: 5000, Mb: 64}}
	sb, _ := sandbox.New("", 2)
	defer sb.Close(context.Background())
	w := NewWorker(testCfg(srv.URL), NewClient(srv.URL, "cx_t"), sb, quietLog())
	runOnce(t, w)
	if len(f.done) != 1 || f.done[0].Status != "error" || f.done[0].Lease != "LB" || f.done[0].Out != "" {
		t.Fatalf("done: %+v", f.done)
	}
	if _, ok := w.blobs.get("w:" + wh); ok {
		t.Fatal("oversized module must not be cached")
	}
}

// --- v2: caps, pins, warm phase, child compile, key, diag (SPEC-v2 14.4, 27.6) ------------------

// TestHelperProcess is the child of the tests below: the re-executed test binary runs the real
// `cxw precompile` entry point.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("CXW_HELPER_PROCESS") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	os.Exit(precompileMain(args, os.Getenv, os.Stdout, os.Stderr))
}

func helperChild(dir string) func(context.Context, string) *exec.Cmd {
	return func(ctx context.Context, path string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProcess$", "--", path)
		cmd.Env = append(os.Environ(), "CXW_HELPER_PROCESS=1", "CACHE_DIR="+dir, "GOMEMLIMIT=400MiB")
		return cmd
	}
}

// padWasm appends a custom section of zeros so the module reaches total bytes and stays valid.
func padWasm(mod []byte, total int) []byte {
	leb := func(n int) []byte {
		var b []byte
		for {
			c := byte(n & 0x7f)
			n >>= 7
			if n == 0 {
				return append(b, c)
			}
			b = append(b, c|0x80)
		}
	}
	body := append(leb(3), "pad"...)
	body = append(body, make([]byte, total-len(mod)-len(body)-8)...)
	out := append([]byte{}, mod...)
	out = append(out, 0)
	out = append(out, leb(len(body))...)
	return append(out, body...)
}

func TestPrecompileMain(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		if k == "CACHE_DIR" {
			return dir
		}
		return ""
	}
	var out, errb bytes.Buffer
	if c := precompileMain(nil, env, &out, &errb); c != 2 {
		t.Fatalf("no args: %d", c)
	}
	if c := precompileMain([]string{"x"}, func(string) string { return "" }, &out, &errb); c != 2 {
		t.Fatalf("no CACHE_DIR: %d", c)
	}
	if c := precompileMain([]string{filepath.Join(dir, "missing")}, env, &out, &errb); c != 2 {
		t.Fatalf("missing file: %d", c)
	}
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("not wasm"), 0o600)
	if c := precompileMain([]string{bad}, env, &out, &errb); c != 1 || !strings.Contains(errb.String(), "precompile:") {
		t.Fatalf("bad module: %d %q", c, errb.String())
	}
	good := filepath.Join(dir, "echo")
	os.WriteFile(good, testModule(t, "echo"), 0o600)
	if c := precompileMain([]string{good}, env, &out, &errb); c != 0 || !strings.Contains(out.String(), "compile_ms=") {
		t.Fatalf("echo: %d %q %q", c, out.String(), errb.String())
	}
	if entries, _ := filepath.Glob(filepath.Join(dir, "wazero-*", "*")); len(entries) == 0 {
		t.Fatal("no file cache entry written")
	}
}

func TestLeaseSendsCapsAndPins(t *testing.T) {
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	ctx := context.Background()
	cfg := testCfg(srv.URL)
	cfg.CacheDir, cfg.PinMaxMb = t.TempDir(), 64
	w := NewWorker(cfg, NewClient(srv.URL, "cx_t"), nil, quietLog())
	h1, h2 := strings.Repeat("b", 64), strings.Repeat("a", 64)
	w.setPin(h1, 10<<20)
	w.setPin(h2, 20<<20)
	if _, err := w.cl.LeaseV2(ctx, 1, w.leaseReq()); err != ErrNoLease {
		t.Fatal(err)
	}
	req := f.leaseReqs[0]
	if req.Ver != 2 || req.MaxMs != 30000 || req.MaxMb != 256 || strings.Join(req.Caps, ",") != "wasm4m,pin" ||
		strings.Join(req.Pins, ",") != h2+","+h1 || strings.Join(req.Lanes, ",") != "public,own" {
		t.Fatalf("lease request: %+v", req)
	}
	// At most 32 pins are listed.
	for i := 0; i < 40; i++ {
		w.setPin(sha256hex([]byte{byte(i)}), 1)
	}
	if n := len(w.leaseReq().Pins); n != maxLeasePins {
		t.Fatalf("pins listed: %d", n)
	}
	// A malformed lease (path-traversal hash) is refused by the client.
	f.leases = []Lease{{Lease: "LX", Job: "jx", Wasm: "../" + strings.Repeat("a", 61), In: h1, Ms: 100, Mb: 1}}
	if _, err := w.cl.LeaseV2(ctx, 1, w.leaseReq()); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed lease accepted: %v", err)
	}
}

func TestAcceptNewL0Caps(t *testing.T) {
	cfg := testCfg("http://x")
	w := NewWorker(cfg, nil, nil, quietLog())
	if caps := strings.Join(w.leaseReq().Caps, ","); caps != "wasm4m" {
		t.Fatalf("default caps: %s", caps)
	}
	cfg.AcceptNew = true
	if caps := strings.Join(NewWorker(cfg, nil, nil, quietLog()).leaseReq().Caps, ","); caps != "wasm4m,new" {
		t.Fatalf("ACCEPT_NEW caps: %s", caps)
	}
	cfg.AcceptL0, cfg.PinMaxMb, cfg.CacheDir = true, 16, "/cache"
	req := NewWorker(cfg, nil, nil, quietLog()).leaseReq()
	if caps := strings.Join(req.Caps, ","); caps != "wasm4m,pin,new,l0" || len(req.Pins) != 0 || req.Ver != 2 {
		t.Fatalf("all caps: %+v", req)
	}
	// On the wire: the gateway sees exactly those caps.
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	cfg.URL = srv.URL
	w = NewWorker(cfg, NewClient(srv.URL, "cx_t"), nil, quietLog())
	w.cl.LeaseV2(context.Background(), 1, w.leaseReq())
	if len(f.leaseReqs) != 1 || strings.Join(f.leaseReqs[0].Caps, ",") != "wasm4m,pin,new,l0" {
		t.Fatalf("wire caps: %+v", f.leaseReqs)
	}
}

// PIN_MAX_MB=0: the offer is the v1 contract (no pin cap, no pins, no warm phase), a module over
// 4 MiB is refused before download completes, and the done report keeps the v1 fields.
func TestV1BehaviourWhenPinsOff(t *testing.T) {
	echo := testModule(t, "echo")
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	big := padWasm(echo, 5<<20) // valid, 5 MiB, unpinned
	bh, eh, ih := f.put(big), f.put(echo), f.put([]byte("abc"))
	f.pins = []Pin{{Hash: bh, Name: "big", Ver: "1", Size: int64(len(big))}}
	f.leases = []Lease{{Lease: "L1", Job: "j1", Wasm: bh, In: ih, Ms: 5000, Mb: 64}, {Lease: "L2", Job: "j2", Wasm: eh, In: ih, Ms: 5000, Mb: 64}}

	sb, _ := sandbox.New("", 2)
	defer sb.Close(context.Background())
	cfg := testCfg(srv.URL) // PinMaxMb 0, no CACHE_DIR
	w := NewWorker(cfg, NewClient(srv.URL, "cx_t"), sb, quietLog())
	w.Warm(context.Background())
	if err := w.RegisterKey(context.Background()); err != nil || w.signer() != nil {
		t.Fatalf("no CACHE_DIR: no key, no registration: %v", err)
	}
	if f.pinsCalls != 0 || f.pub != "" || len(w.pinList()) != 0 {
		t.Fatalf("v1 donor must not warm pins or register a key: pins calls %d pub %q", f.pinsCalls, f.pub)
	}
	runOnce(t, w)
	runOnce(t, w)
	req := f.leaseReqs[0]
	if req.Ver != 2 || strings.Join(req.Caps, ",") != "wasm4m" || req.Pins != nil {
		t.Fatalf("offer with pins off: %+v", req)
	}
	if len(f.done) != 2 {
		t.Fatalf("done: %+v", f.done)
	}
	if d := f.done[0]; d.Lease != "L1" || d.Status != "error" || d.Out != "" || d.Dsig != "" {
		t.Fatalf("unpinned 5 MiB module must be refused: %+v", d)
	}
	if d := f.done[1]; d.Lease != "L2" || d.Status != "ok" || d.Code.N != 0 || d.Code.Word != "" || string(f.blobs[d.Out]) != "ABC" || d.Dsig != "" {
		t.Fatalf("v1 echo report: %+v", d)
	}
	var raw map[string]any
	b, _ := json.Marshal(f.done[1])
	json.Unmarshal(b, &raw)
	for _, k := range []string{"lease", "status", "out", "code", "ms"} {
		if _, ok := raw[k]; !ok {
			t.Fatalf("v1 done field %s missing: %s", k, b)
		}
	}
	if _, ok := raw["code"].(float64); !ok {
		t.Fatalf("v1 code must stay a JSON number: %s", b)
	}
}

// A 30 MiB pinned module downloads with PIN_MAX_MB=64 (and runs, the sandbox cap raised to the
// pin size); an unpinned 17 MiB blob is refused as a module (4 MiB) and as a blob (16 MiB).
func TestPinAwareDownloadCap(t *testing.T) {
	echo := testModule(t, "echo")
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	pinned, unpinned := padWasm(echo, 30<<20), padWasm(echo, 17<<20)
	h30, h17, ih := f.put(pinned), f.put(unpinned), f.put([]byte("abc"))
	f.pins = []Pin{{Hash: h30, Name: "big", Ver: "1", Size: int64(len(pinned))}}

	dir := t.TempDir()
	sb, err := sandbox.New(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close(context.Background())
	cfg := testCfg(srv.URL)
	cfg.CacheDir, cfg.PinMaxMb, cfg.CompileMs = dir, 64, 60000
	w := NewWorker(cfg, NewClient(srv.URL, "cx_t"), sb, quietLog())
	w.child = helperChild(dir)
	ctx := context.Background()
	w.Warm(ctx)
	if pins := w.pinList(); len(pins) != 1 || pins[0] != h30 || w.pinSize(h30) != int64(len(pinned)) {
		t.Fatalf("warmed pins: %v", pins)
	}
	if b, err := os.ReadFile(w.modPath(h30)); err != nil || len(b) != len(pinned) {
		t.Fatalf("pinned module not kept on disk: %v", err)
	}

	if _, err := w.fetchWasm(ctx, h17, 0, ""); !errors.Is(err, ErrTooBig) {
		t.Fatalf("unpinned 17 MiB module: want ErrTooBig, got %v", err)
	}
	if _, err := w.cl.GetBlob(ctx, h17); !errors.Is(err, ErrTooBig) {
		t.Fatalf("unpinned 17 MiB blob: want ErrTooBig, got %v", err)
	}
	if _, err := w.fetchFS(ctx, h17, ""); !errors.Is(err, ErrTooBig) {
		t.Fatalf("unpinned 17 MiB fs: want ErrTooBig, got %v", err)
	}
	if _, ok := w.blobs.get("w:" + h17); ok {
		t.Fatal("refused blob cached")
	}
	// Pinned: served from CACHE_DIR/mod without a second download, cached in memory, and the job runs.
	gets := f.gets[h30]
	b, err := w.fetchWasm(ctx, h30, w.pinSize(h30), "")
	if err != nil || len(b) != len(pinned) || f.gets[h30] != gets {
		t.Fatalf("pinned fetch: %d bytes %v (downloads %d -> %d)", len(b), err, gets, f.gets[h30])
	}
	if _, ok := w.blobs.get("w:" + h30); !ok {
		t.Fatal("pinned module not cached in memory")
	}
	f.leases = []Lease{{Lease: "L1", Job: "j1", Wasm: h30, In: ih, Ms: 10000, Mb: 64}}
	runOnce(t, w)
	if len(f.done) != 1 || f.done[0].Status != "ok" || string(f.blobs[f.done[0].Out]) != "ABC" {
		t.Fatalf("pinned job: %+v", f.done)
	}
	if f.done[0].Diag == nil || f.done[0].Diag.CompileMs <= 0 {
		t.Fatalf("diag must carry the compile time: %+v", f.done[0].Diag)
	}
	if req := f.leaseReqs[0]; strings.Join(req.Caps, ",") != "wasm4m,pin" || len(req.Pins) != 1 || req.Pins[0] != h30 {
		t.Fatalf("offer: %+v", req)
	}
}

// A pin whose child compile fails (bad module, killed child) is skipped; the others are warmed.
func TestWarmSkipsOnChildFailure(t *testing.T) {
	echo := testModule(t, "echo")
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	bad := bytes.Repeat([]byte("\x00asm\x01\x00\x00\x00junk"), 10)
	bh, eh, ih := f.put(bad), f.put(echo), f.put([]byte("abc"))
	missing := strings.Repeat("c", 64)
	f.pins = []Pin{
		{Hash: bh, Name: "bad", Ver: "1", Size: int64(len(bad))},
		{Hash: eh, Name: "echo", Ver: "1", Size: int64(len(echo))},
		{Hash: missing, Name: "gone", Ver: "1", Size: 100},
		{Hash: strings.Repeat("d", 64), Name: "huge", Ver: "1", Size: 100 << 20},
	}
	dir := t.TempDir()
	sb, _ := sandbox.New(dir, 2)
	defer sb.Close(context.Background())
	cfg := testCfg(srv.URL)
	cfg.CacheDir, cfg.PinMaxMb = dir, 64
	w := NewWorker(cfg, NewClient(srv.URL, "cx_t"), sb, quietLog())
	w.child = helperChild(dir)
	ctx := context.Background()
	w.Warm(ctx)
	if pins := w.pinList(); len(pins) != 1 || pins[0] != eh || f.pinsCalls != 1 {
		t.Fatalf("warmed %v (pins calls %d)", pins, f.pinsCalls)
	}
	if _, err := os.Stat(w.modPath(bh)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a pin that failed to compile must not stay on disk")
	}
	if _, err := os.Stat(w.modPath(eh)); err != nil {
		t.Fatal("warmed pin missing on disk")
	}
	if f.gets[strings.Repeat("d", 64)] != 0 {
		t.Fatal("a pin over PIN_MAX_MB must not be downloaded")
	}
	// The warmed pin runs without another compile; the second start finds it on disk.
	f.leases = []Lease{{Lease: "L1", Job: "j1", Wasm: eh, In: ih, Ms: 5000, Mb: 64}}
	runOnce(t, w)
	if len(f.done) != 1 || f.done[0].Status != "ok" || f.gets[eh] != 1 {
		t.Fatalf("job on a warmed pin: %+v downloads=%d", f.done, f.gets[eh])
	}
	w2 := NewWorker(cfg, NewClient(srv.URL, "cx_t"), sb, quietLog())
	w2.child = helperChild(dir)
	w2.Warm(ctx)
	if len(w2.pinList()) != 1 || f.gets[eh] != 1 {
		t.Fatalf("restart must reuse the module on disk: pins %v downloads %d", w2.pinList(), f.gets[eh])
	}
	// A child killed by a signal (the OOM killer in production) skips the pin too.
	w3 := NewWorker(cfg, NewClient(srv.URL, "cx_t"), sb, quietLog())
	w3.child = func(ctx context.Context, path string) *exec.Cmd {
		return exec.CommandContext(ctx, "sh", "-c", "kill -9 $$")
	}
	if _, err := w3.warmPin(ctx, f.pins[1]); !errors.Is(err, errCompileKilled) {
		t.Fatalf("killed child: %v", err)
	}
	if len(w3.pinList()) != 0 {
		t.Fatal("killed pin offered")
	}
}

// The child compile runs under COMPILE_MS: past it the lease is reported as an error with the
// code word compile-timeout, nothing is compiled in-process and the module file is not kept.
func TestCompileTimeoutCode(t *testing.T) {
	echo := testModule(t, "echo")
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	eh, ih := f.put(echo), f.put([]byte("abc"))
	f.leases = []Lease{{Lease: "L1", Job: "j1", Wasm: eh, In: ih, Ms: 5000, Mb: 64}}
	dir := t.TempDir()
	sb, _ := sandbox.New(dir, 2)
	defer sb.Close(context.Background())
	cfg := testCfg(srv.URL)
	cfg.CacheDir, cfg.CompileMs = dir, 300
	w := NewWorker(cfg, NewClient(srv.URL, "cx_t"), sb, quietLog())
	w.child = func(ctx context.Context, path string) *exec.Cmd { return exec.CommandContext(ctx, "sleep", "30") }
	start := time.Now()
	runOnce(t, w)
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("compile timeout not enforced: %v", el)
	}
	if len(f.done) != 1 {
		t.Fatalf("done: %+v", f.done)
	}
	d := f.done[0]
	if d.Status != "error" || d.Code.Word != "compile-timeout" || d.Out != "" || d.Diag == nil || d.Diag.CompileMs < 250 {
		t.Fatalf("compile-timeout report: %+v diag=%+v", d, d.Diag)
	}
	if w.isCompiled(eh) {
		t.Fatal("timed-out module marked compiled")
	}
	if _, err := os.Stat(w.modPath(eh)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unpinned module file must not stay on disk")
	}
	// The wire form is a string code with status error (the gateway's codeVal contract).
	b, _ := json.Marshal(d)
	if !strings.Contains(string(b), `"code":"compile-timeout"`) || !strings.Contains(string(b), `"status":"error"`) {
		t.Fatalf("wire: %s", b)
	}
	// The next job on a healthy child path compiles (under a normal budget) and runs.
	w.child, w.cfg.CompileMs = helperChild(dir), 30000
	f.leases = append(f.leases, Lease{Lease: "L2", Job: "j2", Wasm: eh, In: ih, Ms: 5000, Mb: 64})
	runOnce(t, w)
	if len(f.done) != 2 || f.done[1].Status != "ok" || !w.isCompiled(eh) {
		t.Fatalf("after timeout: %+v", f.done)
	}
}

// The donor key lives in CACHE_DIR/key (0600), is registered through PUT /v1/me and signs every
// report over cx-dsig-v1 || job || lease || fingerprint; when the gateway holds another key the
// reports go unsigned.
func TestDonorKeyAndDsig(t *testing.T) {
	echo := testModule(t, "echo")
	dir := t.TempDir()
	k1, err := loadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := loadKey(dir)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("key not stable across loads: %v", err)
	}
	st, _ := os.Stat(filepath.Join(dir, "key"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode())
	}
	os.WriteFile(filepath.Join(dir, "key"), []byte("zz\n"), 0o600)
	if _, err := loadKey(dir); err == nil {
		t.Fatal("corrupt key file accepted")
	}
	os.Remove(filepath.Join(dir, "key"))

	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	eh, ih := f.put(echo), f.put([]byte("abc"))
	f.leases = []Lease{{Lease: "L1", Job: "j1", Wasm: eh, In: ih, Ms: 5000, Mb: 64}, {Lease: "L2", Job: "j2", Wasm: eh, In: ih, Ms: 5000, Mb: 64}}
	sb, _ := sandbox.New(dir, 2)
	defer sb.Close(context.Background())
	cfg := testCfg(srv.URL)
	cfg.CacheDir = dir
	w := NewWorker(cfg, NewClient(srv.URL, "cx_t"), sb, quietLog())
	w.child = helperChild(dir)
	ctx := context.Background()
	if err := w.RegisterKey(ctx); err != nil {
		t.Fatal(err)
	}
	key, _ := loadKey(dir)
	pub := key.Public().(ed25519.PublicKey)
	if f.pub != hex.EncodeToString(pub) || w.signer() == nil {
		t.Fatalf("registered %q, signer %v", f.pub, w.signer() != nil)
	}
	runOnce(t, w)
	if len(f.done) != 1 || f.done[0].Status != "ok" || f.done[0].Dsig == "" {
		t.Fatalf("done: %+v", f.done)
	}
	d := f.done[0]
	sig, err := base64.RawURLEncoding.DecodeString(d.Dsig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("dsig encoding: %v", err)
	}
	msg := []byte("cx-dsig-v1\x00j1\x00L1\x00ok:0:" + d.Out)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("dsig does not verify over cx-dsig-v1 || job || lease || fingerprint")
	}
	if ed25519.Verify(pub, []byte("cx-dsig-v1\x00j1\x00L2\x00ok:0:"+d.Out), sig) {
		t.Fatal("dsig must bind the lease")
	}
	// Error reports are signed over "error:0:" (no output, exit code ignored).
	if fp := fingerprint(Done{Status: "error", Code: DoneCode{N: 7, Word: "compile-timeout"}, Out: "x"}); fp != "error:0:" {
		t.Fatalf("error fingerprint %q", fp)
	}
	if fp := fingerprint(Done{Status: "exit", Code: DoneCode{N: 3}, Out: "h"}); fp != "exit:3:h" {
		t.Fatalf("exit fingerprint %q", fp)
	}

	// The gateway holds another key (rotation quota): the worker reports unsigned.
	f.pubReply = strings.Repeat("ee", 32)
	w2 := NewWorker(cfg, NewClient(srv.URL, "cx_t"), sb, quietLog())
	w2.child = helperChild(dir)
	if err := w2.RegisterKey(ctx); err == nil || !strings.Contains(err.Error(), "another key") || w2.signer() != nil {
		t.Fatalf("mismatched pub: %v", err)
	}
	runOnce(t, w2)
	if len(f.done) != 2 || f.done[1].Status != "ok" || f.done[1].Dsig != "" {
		t.Fatalf("unsigned report: %+v", f.done)
	}
	// A scoped token (403 on PUT /v1/me) is reported, not fatal.
	f.pubReply, f.meStatus = "", 403
	w3 := NewWorker(cfg, NewClient(srv.URL, "cx_t"), sb, quietLog())
	if err := w3.RegisterKey(ctx); err == nil || w3.signer() != nil {
		t.Fatalf("403 registration: %v", err)
	}
}

// The done report carries diag {stderr b64, trace, compile_ms, mem_pages} (27.6).
func TestDiagInDone(t *testing.T) {
	membomb := testModule(t, "membomb")
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	trap := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0, // type () -> ()
		3, 2, 1, 0, // func 0: type 0
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0, // export _start
		10, 5, 1, 3, 0, 0x00, 0x0b, // body: unreachable; end
	}
	mh, th, ih := f.put(membomb), f.put(trap), f.put([]byte(""))
	f.leases = []Lease{{Lease: "L1", Job: "j1", Wasm: mh, In: ih, Ms: 10000, Mb: 32}, {Lease: "L2", Job: "j2", Wasm: th, In: ih, Ms: 1000, Mb: 16}}
	sb, _ := sandbox.New("", 2)
	defer sb.Close(context.Background())
	w := NewWorker(testCfg(srv.URL), NewClient(srv.URL, "cx_t"), sb, quietLog())
	runOnce(t, w)
	runOnce(t, w)
	if len(f.done) != 2 {
		t.Fatalf("done: %+v", f.done)
	}
	oom := f.done[0]
	if oom.Status != "oom" || oom.Diag == nil || oom.Diag.MemPages == 0 || oom.Diag.Stderr == "" {
		t.Fatalf("oom diag: %+v %+v", oom, oom.Diag)
	}
	stderr, err := base64.RawURLEncoding.DecodeString(oom.Diag.Stderr)
	if err != nil || len(stderr) == 0 || len(stderr) > sandbox.MaxStderr {
		t.Fatalf("stderr b64: %v (%d bytes)", err, len(stderr))
	}
	t.Logf("membomb: mem_pages=%d compile_ms=%d stderr=%q", oom.Diag.MemPages, oom.Diag.CompileMs, stderr[:min(len(stderr), 60)])
	tr := f.done[1]
	if tr.Status != "error" || tr.Diag == nil || tr.Diag.Trace == "" || len(tr.Diag.Trace) > sandbox.MaxTrace {
		t.Fatalf("trap diag: %+v %+v", tr, tr.Diag)
	}
	var raw map[string]any
	b, _ := json.Marshal(tr)
	json.Unmarshal(b, &raw)
	if dg, ok := raw["diag"].(map[string]any); !ok || dg["trace"] == nil {
		t.Fatalf("wire diag: %s", b)
	}
	if diagOf(sandbox.Result{Status: "ok"}) != nil {
		t.Fatal("empty diag must be omitted")
	}
}

// A lease with an fs blob mounts it read-only; the parsed archive is cached by its byte size.
func TestFsLeaseMountsZip(t *testing.T) {
	probe, err := os.ReadFile(filepath.Join("..", "..", "internal", "sandbox", "testdata", "fsprobe.wasm"))
	if err != nil {
		t.Skipf("missing fsprobe module (run internal/sandbox/testdata/build.sh): %v", err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, _ := zw.Create("lib/a.txt")
	fw.Write([]byte("alpha"))
	zw.Close()
	f := newFake("cx_t")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	ph, zh, ih, bad := f.put(probe), f.put(buf.Bytes()), f.put([]byte("/lib/a.txt")), f.put([]byte("PK\x03\x04 not a zip"))
	f.leases = []Lease{{Lease: "L1", Job: "j1", Wasm: ph, In: ih, FS: zh, Ms: 10000, Mb: 64}, {Lease: "L2", Job: "j2", Wasm: ph, In: ih, FS: bad, Ms: 10000, Mb: 64}}
	sb, _ := sandbox.New("", 2)
	defer sb.Close(context.Background())
	w := NewWorker(testCfg(srv.URL), NewClient(srv.URL, "cx_t"), sb, quietLog())
	runOnce(t, w)
	if len(f.done) != 1 || f.done[0].Status != "ok" {
		t.Fatalf("done: %+v", f.done)
	}
	if out := string(f.blobs[f.done[0].Out]); !strings.Contains(out, `read /lib/a.txt x1 total=5 head="alpha"`) || !strings.Contains(out, "write error") {
		t.Fatalf("fs output:\n%s", out)
	}
	if _, ok := w.blobs.get("fs:" + zh); !ok {
		t.Fatal("parsed fs not cached")
	}
	if n := w.blobs.bytes(); n != int64(len(probe)+buf.Len()) {
		t.Fatalf("cache accounting %d, want %d", n, len(probe)+buf.Len())
	}
	// An unusable zip is a deterministic error report, not an expired lease.
	runOnce(t, w)
	if len(f.done) != 2 || f.done[1].Status != "error" || f.done[1].Out != "" {
		t.Fatalf("bad fs: %+v", f.done)
	}
}

func TestUpgradeHintLoggedOncePerDay(t *testing.T) {
	var logs bytes.Buffer
	w := NewWorker(testCfg("http://x"), nil, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	now := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return now }
	l := &Lease{Upgrade: "https://agents.ekaii.fr/worker", Sunset: "2027-01-01"}
	w.noteUpgrade(l, w.log)
	w.noteUpgrade(l, w.log)
	now = now.Add(23 * time.Hour)
	w.noteUpgrade(l, w.log)
	if n := strings.Count(logs.String(), "worker upgrade"); n != 1 {
		t.Fatalf("logged %d times in a day:\n%s", n, logs.String())
	}
	now = now.Add(2 * time.Hour)
	w.noteUpgrade(l, w.log)
	if n := strings.Count(logs.String(), "worker upgrade"); n != 2 {
		t.Fatalf("logged %d times after a day", n)
	}
	w.noteUpgrade(&Lease{}, w.log)
	if strings.Count(logs.String(), "worker upgrade") != 2 || !strings.Contains(logs.String(), "sunset=2027-01-01") {
		t.Fatalf("logs:\n%s", logs.String())
	}
}
