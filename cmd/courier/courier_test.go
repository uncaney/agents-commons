package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testToken = "courier-token-0123456789"

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// ---- transport ----

func fakeResolver(table map[string][]string) func(context.Context, string) ([]netip.Addr, error) {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		ips, ok := table[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		var out []netip.Addr
		for _, s := range ips {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
}

func TestAllowlistDialer(t *testing.T) {
	allow := buildAllowlist(nil)
	for _, h := range []string{"api.indexnow.org", "www.bing.com", "api.github.com", "huggingface.co", "pypi.org", "registry.npmjs.org",
		"proxy.golang.org", "crates.io", "rubygems.org", "api.cloudflare.com", "web.archive.org", "api.osv.dev", "endoflife.date",
		"ssl.bing.com", "chatgpt.com", "openai.com"} {
		if !allow.Allow(h) {
			t.Fatalf("base host %s missing", h)
		}
	}
	if allow.Allow("evil.example") || allow.Allow("api.indexnow.org.evil.example") || allow.Allow("indexnow.org") {
		t.Fatal("non-listed host allowed")
	}
	var dialed []string
	d := &dialer{
		allow:   allow.Allow,
		resolve: fakeResolver(map[string][]string{"api.indexnow.org": {"93.184.216.34", "2606:4700::1111"}, "evil.example": {"93.184.216.35"}}),
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			c1, c2 := net.Pipe()
			c2.Close()
			return c1, nil
		},
	}
	ctx := context.Background()
	for _, addr := range []string{"api.indexnow.org:443", "API.IndexNow.org.:443"} {
		c, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		c.Close()
	}
	if len(dialed) != 2 || dialed[0] != "93.184.216.34:443" || dialed[1] != "93.184.216.34:443" {
		t.Fatalf("dialed %v", dialed)
	}
	cases := []struct {
		network, addr string
		want          error
	}{
		{"tcp", "evil.example:443", errNotAllowed},
		{"tcp", "nx.example:443", errNotAllowed},
		{"tcp", "api.indexnow.org:80", errTLSOnly},
		{"tcp", "api.indexnow.org:8443", errTLSOnly},
		{"tcp", "93.184.216.34:443", errIPLiteral},
		{"tcp", "[2606:4700::1111]:443", errIPLiteral},
		{"tcp", "api.indexnow.org", nil}, // no port: SplitHostPort error
		{"udp", "api.indexnow.org:443", nil},
	}
	for _, c := range cases {
		n := len(dialed)
		_, err := d.DialContext(ctx, c.network, c.addr)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Fatalf("%s %s: err=%v want %v", c.network, c.addr, err, c.want)
		}
		if len(dialed) != n {
			t.Fatalf("%s: refused host was dialled", c.addr)
		}
	}
	// Kinds and S3_ENDPOINT contribute hosts; invalid contributions panic.
	k := &Kind{Name: "t_hosts", Hosts: []string{"s3.example.net"}}
	a2 := buildAllowlist([]*Kind{k}, s3Host("https://minio.example.org:9000/bucket"), "")
	if !a2.Allow("s3.example.net") || !a2.Allow("minio.example.org") || a2.Allow("bucket") {
		t.Fatalf("contributions: %v", a2)
	}
	for _, bad := range []string{"10.0.0.1", "*.example.com", "localhost", "evil.example:443", "Has Space.example"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("host %q accepted", bad)
				}
			}()
			buildAllowlist(nil, bad)
		}()
	}
	// The real transport never uses a proxy and only speaks TLS >= 1.2.
	tr := newTransport(allow)
	if tr.Proxy != nil || tr.TLSClientConfig.MinVersion < 0x0303 || tr.ResponseHeaderTimeout != dialTimeout {
		t.Fatal("transport settings")
	}
}

func TestPrivateIPRefused(t *testing.T) {
	allow := buildAllowlist(nil)
	for _, ip := range []string{"10.0.0.5", "127.0.0.1", "169.254.1.1", "fd00::1", "100.64.0.1", "::ffff:10.0.0.1", "192.168.1.1",
		"172.16.0.1", "0.0.0.0", "::1", "::", "fe80::1", "224.0.0.1", "ff02::1", "198.18.0.1", "2001:db8::1", "2002:a00::1",
		"64:ff9b::a00:1", "192.0.2.1", "198.51.100.7", "203.0.113.9", "240.0.0.1", "192.0.0.1", "100::1", "2001::1"} {
		dialed := false
		d := &dialer{allow: allow.Allow, resolve: fakeResolver(map[string][]string{"huggingface.co": {ip}}),
			dial: func(context.Context, string, string) (net.Conn, error) { dialed = true; return nil, nil }}
		_, err := d.DialContext(context.Background(), "tcp", "huggingface.co:443")
		if !errors.Is(err, errPrivateIP) || dialed {
			t.Fatalf("%s: err=%v dialed=%v", ip, err, dialed)
		}
		if publicIP(netip.MustParseAddr(ip)) {
			t.Fatalf("publicIP(%s) = true", ip)
		}
	}
	for _, ip := range []string{"93.184.216.34", "2606:4700::1111", "1.1.1.1", "::ffff:93.184.216.34"} {
		if !publicIP(netip.MustParseAddr(ip)) {
			t.Fatalf("publicIP(%s) = false", ip)
		}
	}
	// A name with one private address among public ones is refused as a whole (rebinding/split answers).
	d := &dialer{allow: allow.Allow, resolve: fakeResolver(map[string][]string{"huggingface.co": {"93.184.216.34", "10.0.0.1"}, "pypi.org": {}}),
		dial: func(context.Context, string, string) (net.Conn, error) { t.Fatal("dialled"); return nil, nil }}
	if _, err := d.DialContext(context.Background(), "tcp", "huggingface.co:443"); !errors.Is(err, errPrivateIP) {
		t.Fatalf("mixed answer: %v", err)
	}
	if _, err := d.DialContext(context.Background(), "tcp", "pypi.org:443"); !errors.Is(err, errNoAddrs) {
		t.Fatalf("empty answer: %v", err)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func TestRedirectPolicyAndReadCap(t *testing.T) {
	via := []*http.Request{{URL: mustURL("https://huggingface.co/a")}}
	if err := checkRedirect(&http.Request{URL: mustURL("https://huggingface.co/b")}, via); err != nil {
		t.Fatalf("same host: %v", err)
	}
	if err := checkRedirect(&http.Request{URL: mustURL("https://HuggingFace.co./b")}, via); err != nil {
		t.Fatalf("same host (case, dot): %v", err)
	}
	for _, to := range []string{"https://evil.example/b", "http://huggingface.co/b", "https://cdn.huggingface.co/b"} {
		if err := checkRedirect(&http.Request{URL: mustURL(to)}, via); !errors.Is(err, errRedirect) {
			t.Fatalf("%s: %v", to, err)
		}
	}
	if err := checkRedirect(&http.Request{URL: mustURL("https://huggingface.co/c")}, []*http.Request{via[0], via[0], via[0]}); err == nil {
		t.Fatal("4th redirect accepted")
	}
	if _, err := readAll(strings.NewReader(strings.Repeat("x", readCap+1)), readCap); !errors.Is(err, errTooLarge) {
		t.Fatalf("over cap: %v", err)
	}
	if b, err := readAll(strings.NewReader(strings.Repeat("x", readCap)), readCap); err != nil || len(b) != readCap {
		t.Fatalf("at cap: %d %v", len(b), err)
	}
	// The locked internal dialer refuses anything but the gateway hosts.
	ld := lockedDialer("gateway", "GATEWAY.")
	if _, err := ld(context.Background(), "tcp", "pypi.org:443"); err == nil {
		t.Fatal("locked dialer dialled a foreign host")
	}
}

// ---- fake internal (gateway) server ----

type fakeInternal struct {
	t         *testing.T
	srv       *httptest.Server
	mu        sync.Mutex
	queue     []Job
	acks      map[int64]json.RawMessage
	fails     map[int64]string
	polls     int
	failFirst int
	kinds     []string
	onIdle    func()
}

func newFakeInternal(t *testing.T) *fakeInternal {
	f := &fakeInternal{t: t, acks: map[int64]json.RawMessage{}, fails: map[int64]string{}}
	mux := http.NewServeMux()
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(401)
			return false
		}
		return true
	}
	mux.HandleFunc("GET /internal/config", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"public_url": "https://agents.example", "indexnow_key": strings.Repeat("k", 32)})
	})
	mux.HandleFunc("GET /internal/egress", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.polls++
		if f.failFirst > 0 {
			f.failFirst--
			w.WriteHeader(500)
			return
		}
		f.kinds = append(f.kinds, r.URL.Query().Get("kinds"))
		want := map[string]bool{}
		for _, k := range strings.Split(r.URL.Query().Get("kinds"), ",") {
			want[k] = true
		}
		for i, j := range f.queue {
			if want[j.Kind] {
				f.queue = append(f.queue[:i], f.queue[i+1:]...)
				json.NewEncoder(w).Encode(j)
				return
			}
		}
		if f.onIdle != nil {
			f.onIdle()
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /internal/egress/{id}/ack", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var id int64
		fmt.Sscanf(r.PathValue("id"), "%d", &id)
		var in struct {
			Result json.RawMessage `json:"result"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.acks[id] = in.Result
		f.mu.Unlock()
		io.WriteString(w, `{"ok":true}`)
	})
	mux.HandleFunc("POST /internal/egress/{id}/fail", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		var id int64
		fmt.Sscanf(r.PathValue("id"), "%d", &id)
		var in struct {
			Err string `json:"err"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.fails[id] = in.Err
		f.mu.Unlock()
		io.WriteString(w, `{"ok":true}`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

var (
	testKindsOnce sync.Once
	batchMu       sync.Mutex
	batchSizes    []int
)

func testKinds() []*Kind {
	testKindsOnce.Do(func() {
		Register(&Kind{Name: "t_ok", Run: func(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
			return json.RawMessage(`{"x":1}`), nil
		}})
		Register(&Kind{Name: "t_fail", Run: func(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
			return nil, errors.New("boom\nline2\x00")
		}})
		Register(&Kind{Name: "t_batch", Batch: 3, Every: 10 * time.Minute, RunBatch: func(ctx context.Context, e *Env, jobs []*Job) error {
			batchMu.Lock()
			batchSizes = append(batchSizes, len(jobs))
			batchMu.Unlock()
			return nil
		}})
	})
	var out []*Kind
	for _, n := range []string{"t_ok", "t_fail", "t_batch"} {
		k, _ := Lookup(n)
		out = append(out, k)
	}
	return out
}

func testCourier(t *testing.T, f *fakeInternal) (*courier, *[]time.Duration) {
	t.Helper()
	cfg := config{InternalURL: f.srv.URL, GatewayURL: f.srv.URL, PublicURL: "https://agents.example", Token: testToken, SecretsDir: t.TempDir()}
	e := newEnv(cfg, &http.Client{}, discard)
	sleeps := &[]time.Duration{}
	c := &courier{e: e, kinds: testKinds(), last: map[string]time.Time{},
		sleep: func(ctx context.Context, d time.Duration) bool { *sleeps = append(*sleeps, d); return ctx.Err() == nil }}
	return c, sleeps
}

func TestPollAckFailBackoff(t *testing.T) {
	f := newFakeInternal(t)
	f.queue = []Job{{ID: 1, Kind: "t_ok", Payload: json.RawMessage(`{}`)}, {ID: 2, Kind: "t_fail", Payload: json.RawMessage(`{}`)}}
	f.failFirst = 2
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f.onIdle = func() {
		if len(f.acks) == 1 && len(f.fails) == 1 {
			cancel()
		}
	}
	c, sleeps := testCourier(t, f)
	c.waitConfig(ctx)
	if c.e.IndexNowKey != strings.Repeat("k", 32) || c.e.PublicURL != "https://agents.example" {
		t.Fatalf("config not loaded: %q %q", c.e.IndexNowKey, c.e.PublicURL)
	}
	c.run(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	if string(f.acks[1]) != `{"x":1}` {
		t.Fatalf("ack result %s", f.acks[1])
	}
	if f.fails[2] != "boom line2" {
		t.Fatalf("fail err %q", f.fails[2])
	}
	if len(*sleeps) < 2 || (*sleeps)[0] != time.Second || (*sleeps)[1] != 2*time.Second {
		t.Fatalf("backoff sleeps %v", *sleeps)
	}
	if len(f.kinds) == 0 || f.kinds[0] != "t_ok,t_fail,t_batch" {
		t.Fatalf("kinds filter %v", f.kinds)
	}
	// Wrong bearer: every call is refused and the loop reports an error (no panic, no ack).
	f2 := newFakeInternal(t)
	f2.queue = []Job{{ID: 9, Kind: "t_ok", Payload: json.RawMessage(`{}`)}}
	c2, _ := testCourier(t, f2)
	c2.e.token = "wrong"
	if _, err := c2.cycle(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong token: %v", err)
	}
	if len(f2.acks) != 0 {
		t.Fatal("acked with a wrong token")
	}
}

func TestBatchDrainAndThrottle(t *testing.T) {
	f := newFakeInternal(t)
	for i := int64(1); i <= 5; i++ {
		f.queue = append(f.queue, Job{ID: i, Kind: "t_batch", Payload: json.RawMessage(`{}`)})
	}
	c, _ := testCourier(t, f)
	batchMu.Lock()
	batchSizes = nil
	batchMu.Unlock()
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	c.e.Now = func() time.Time { return now }
	ctx := context.Background()
	if n, err := c.cycle(ctx); err != nil || n != 3 {
		t.Fatalf("first drain: n=%d err=%v", n, err)
	}
	// A full batch does not start the throttle: the kind is still due.
	if due, _ := c.due(now); len(due) != 3 {
		t.Fatalf("after full drain due=%d", len(due))
	}
	if n, err := c.cycle(ctx); err != nil || n != 2 {
		t.Fatalf("second drain: n=%d err=%v", n, err)
	}
	batchMu.Lock()
	sizes := append([]int(nil), batchSizes...)
	batchMu.Unlock()
	if len(sizes) != 2 || sizes[0] != 3 || sizes[1] != 2 {
		t.Fatalf("batch sizes %v", sizes)
	}
	if len(f.acks) != 5 {
		t.Fatalf("acks %d", len(f.acks))
	}
	// A partial drain throttles the kind for Every.
	due, next := c.due(now.Add(time.Minute))
	if len(due) != 2 || next < 8*time.Minute || next > 9*time.Minute {
		t.Fatalf("throttled: due=%d next=%s", len(due), next)
	}
	if due, _ := c.due(now.Add(11 * time.Minute)); len(due) != 3 {
		t.Fatalf("after Every: due=%d", len(due))
	}
}

// ---- kinds ----

type tenv struct {
	e    *Env
	dir  string
	envs map[string]string
}

func (te *tenv) secret(t *testing.T, name, val string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(te.dir, name), []byte(val+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// testEnv routes every egress request to fake (X-Egress-Host carries the intended host) and uses
// fake as the gateway too.
func testEnv(t *testing.T, fake *httptest.Server) *tenv {
	t.Helper()
	dir := t.TempDir()
	cfg := config{InternalURL: fake.URL, GatewayURL: fake.URL, PublicURL: "https://agents.example", Token: testToken, SecretsDir: dir}
	client := newClient(rewriteTransport{base: mustURL(fake.URL), next: http.DefaultTransport})
	e := newEnv(cfg, client, discard)
	e.IndexNowKey = strings.Repeat("k", 32)
	te := &tenv{e: e, dir: dir, envs: map[string]string{}}
	e.Getenv = func(k string) string { return te.envs[k] }
	return te
}

type recorded struct {
	host, method, path, auth, ctype string
	body                            []byte
}

func TestIndexNowBatchAndDailyCap(t *testing.T) {
	var mu sync.Mutex
	var calls []recorded
	status := 200
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, recorded{r.Header.Get("X-Egress-Host"), r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), b})
		mu.Unlock()
		w.WriteHeader(status)
	}))
	defer fake.Close()
	te := testEnv(t, fake)
	e := te.e
	oldPer, oldCap := indexNowPerPost, indexNowDailyCap
	indexNowPerPost, indexNowDailyCap = 3, 5
	t.Cleanup(func() { indexNowPerPost, indexNowDailyCap = oldPer, oldCap })
	job := func(id int64, urls ...string) *Job {
		b, _ := json.Marshal(map[string]any{"urls": urls})
		return &Job{ID: id, Kind: "indexnow", Payload: b}
	}
	jobs := []*Job{
		job(1, "https://agents.example/kb/a1", "https://agents.example/v/pypi:requests"),
		job(2, "https://agents.example/v/pypi:requests", "https://agents.example/tag/x"),
		job(3, "https://agents.example/kb/d4", "https://evil.example/x", "http://agents.example/plain", "https://agents.example:8443/p", "https://agents.example/sp ace"),
	}
	if err := runIndexNow(context.Background(), e, jobs); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]recorded(nil), calls...)
	mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("posts %d", len(got))
	}
	var bodies [][]string
	for _, c := range got {
		if c.host != "api.indexnow.org" || c.method != "POST" || c.path != "/indexnow" || !strings.HasPrefix(c.ctype, "application/json") {
			t.Fatalf("call %+v", c)
		}
		var p struct {
			Host, Key, KeyLocation string
			URLList                []string `json:"urlList"`
		}
		if err := json.Unmarshal(c.body, &p); err != nil {
			t.Fatal(err)
		}
		if p.Host != "agents.example" || p.Key != e.IndexNowKey || p.KeyLocation != "https://agents.example/"+e.IndexNowKey+".txt" {
			t.Fatalf("payload %+v", p)
		}
		bodies = append(bodies, p.URLList)
	}
	want := [][]string{{"https://agents.example/kb/a1", "https://agents.example/v/pypi:requests", "https://agents.example/tag/x"}, {"https://agents.example/kb/d4"}}
	if fmt.Sprint(bodies) != fmt.Sprint(want) {
		t.Fatalf("urlLists %v want %v", bodies, want)
	}
	// Daily cap: 4 of 5 used; two more URLs exceed it and the batch fails (retried later by backoff).
	err := runIndexNow(context.Background(), e, []*Job{job(4, "https://agents.example/kb/e5", "https://agents.example/kb/f6")})
	if !errors.Is(err, errIndexNowQuota) {
		t.Fatalf("cap: %v", err)
	}
	// One URL still fits.
	if err := runIndexNow(context.Background(), e, []*Job{job(5, "https://agents.example/kb/e5")}); err != nil {
		t.Fatalf("last slot: %v", err)
	}
	// Next UTC day resets the quota.
	e.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if err := runIndexNow(context.Background(), e, []*Job{job(6, "https://agents.example/kb/g7")}); err != nil {
		t.Fatalf("after day roll: %v", err)
	}
	// Nothing valid to send: acked silently without a POST.
	n := len(calls)
	if err := runIndexNow(context.Background(), e, []*Job{job(7, "https://evil.example/z")}); err != nil || len(calls) != n {
		t.Fatalf("empty batch: err=%v posts=%d", err, len(calls)-n)
	}
	// Upstream rejection is an error; a missing key too.
	status = 429
	if err := runIndexNow(context.Background(), e, []*Job{job(8, "https://agents.example/kb/h8")}); err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("429: %v", err)
	}
	e.IndexNowKey = ""
	if err := runIndexNow(context.Background(), e, []*Job{job(9, "https://agents.example/kb/i9")}); err == nil {
		t.Fatal("missing key accepted")
	}
	k, _ := Lookup("indexnow")
	if k.Every != 10*time.Minute || k.RunBatch == nil || k.Batch < 2 {
		t.Fatalf("indexnow kind %+v", k)
	}
}

func gzipLines(lines ...string) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	for _, l := range lines {
		zw.Write([]byte(l + "\n"))
	}
	zw.Close()
	return b.Bytes()
}

func TestHFCommitPayloadSquash(t *testing.T) {
	rows := []string{`{"id":"a1","title":"one"}`, `{"id":"b2","title":"two"}`, `{"id":"c3","title":"tre"}`}
	var mu sync.Mutex
	var seq []string
	var commit []byte
	var commitAuth, commitCT string
	commitStatus := 200
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seq = append(seq, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-Egress-Host") != "huggingface.co" {
			t.Errorf("HF call without the huggingface.co host: %s", r.URL.Path)
		}
		switch r.URL.Path {
		case "/export/manifest.json":
			json.NewEncoder(w).Encode(map[string]any{"date": "2026-10-07", "license": "CC0-1.0", "retention": "latest + 7 dailies",
				"files": []map[string]any{{"name": "kb-2026-10-07.jsonl.gz", "rows": 3}, {"name": "kb-2026-10-06.jsonl.gz"}, {"name": "tasks-2026-10-07.jsonl.gz"}, {"name": "claims-2026-10-05.jsonl.gz"}}})
		case "/export/kb-2026-10-07.jsonl.gz":
			w.Write(gzipLines(rows...))
		case "/api/datasets/ekaii/commons/tree/main/data":
			json.NewEncoder(w).Encode([]map[string]string{
				{"type": "file", "path": "data/kb-2026-09-20-00000.jsonl"}, {"type": "file", "path": "data/kb-2026-10-07-00000.jsonl"},
				{"type": "file", "path": "data/kb-2026-10-07-00002.jsonl"}, {"type": "file", "path": "data/tasks-2026-10-07-00000.jsonl"},
				{"type": "directory", "path": "data/other"}})
		case "/api/datasets/ekaii/commons/commit/main":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			commit, commitAuth, commitCT = b, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
			mu.Unlock()
			w.WriteHeader(commitStatus)
			io.WriteString(w, `{"commitUrl":"https://huggingface.co/datasets/ekaii/commons/commit/abc123","commitOid":"abc123"}`)
		case "/api/datasets/ekaii/commons/super-squash/main":
			if r.Header.Get("Authorization") != "Bearer hf_test" {
				w.WriteHeader(401)
				return
			}
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer fake.Close()
	te := testEnv(t, fake)
	te.envs["HF_REPO"] = "ekaii/commons"
	te.secret(t, "hf_token", "hf_test")
	old := hfShardBytes
	hfShardBytes = 60 // two rows per shard
	t.Cleanup(func() { hfShardBytes = old })

	job := &Job{ID: 1, Kind: "hf", Payload: json.RawMessage(`{"file":"kb-2026-10-07.jsonl.gz"}`)}
	res, err := runHF(context.Background(), te.e, job)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Shards, Deleted int
		Rows            int
		Commit          string
		Squashed        bool
	}
	if err := json.Unmarshal(res, &out); err != nil || out.Shards != 2 || out.Rows != 3 || out.Deleted != 2 || out.Commit != "abc123" || !out.Squashed {
		t.Fatalf("result %s (%v)", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	wantSeq := []string{"GET /export/manifest.json", "GET /api/datasets/ekaii/commons/tree/main/data", "GET /export/kb-2026-10-07.jsonl.gz",
		"POST /api/datasets/ekaii/commons/commit/main", "POST /api/datasets/ekaii/commons/super-squash/main"}
	if fmt.Sprint(seq) != fmt.Sprint(wantSeq) {
		t.Fatalf("sequence %v", seq)
	}
	if commitAuth != "Bearer hf_test" || commitCT != "application/x-ndjson" {
		t.Fatalf("commit headers %q %q", commitAuth, commitCT)
	}
	var lines []map[string]json.RawMessage
	for _, l := range bytes.Split(bytes.TrimSpace(commit), []byte("\n")) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatalf("ndjson line %q: %v", l, err)
		}
		lines = append(lines, m)
	}
	key := func(i int) string { var k string; json.Unmarshal(lines[i]["key"], &k); return k }
	if key(0) != "header" {
		t.Fatalf("first line %s", lines[0]["key"])
	}
	files := map[string][]byte{}
	var deleted []string
	for _, m := range lines[1:] {
		var k string
		json.Unmarshal(m["key"], &k)
		switch k {
		case "file":
			var v struct{ Path, Encoding, Content string }
			json.Unmarshal(m["value"], &v)
			if v.Encoding != "base64" {
				t.Fatalf("encoding %q", v.Encoding)
			}
			b, err := base64.StdEncoding.DecodeString(v.Content)
			if err != nil {
				t.Fatal(err)
			}
			files[v.Path] = b
		case "deletedFile":
			var v struct{ Path string }
			json.Unmarshal(m["value"], &v)
			deleted = append(deleted, v.Path)
		default:
			t.Fatalf("unexpected line key %q", k)
		}
	}
	if string(files["data/kb-2026-10-07-00000.jsonl"]) != rows[0]+"\n"+rows[1]+"\n" || string(files["data/kb-2026-10-07-00001.jsonl"]) != rows[2]+"\n" {
		t.Fatalf("shards %q", files)
	}
	for path, f := range files {
		if hfShardRe.MatchString(path) && len(f) > hfShardBytes+len(rows[0])+1 {
			t.Fatalf("shard %s over size: %d", path, len(f))
		}
	}
	card := string(files["README.md"])
	for _, want := range []string{"---\nlicense: cc0-1.0\n", "config_name: kb\n    data_files: data/kb-2026-10-07-*.jsonl",
		"config_name: tasks\n    data_files: data/tasks-2026-10-07-*.jsonl", "config_name: claims\n    data_files: data/claims-2026-10-05-*.jsonl",
		"tombstones.jsonl", "squashed after every commit", `load_dataset("ekaii/commons", "kb")`} {
		if !strings.Contains(card, want) {
			t.Fatalf("card missing %q:\n%s", want, card)
		}
	}
	if strings.Contains(card, "config_name: digests") {
		t.Fatal("card lists a kind the manifest does not have")
	}
	if fmt.Sprint(deleted) != "[data/kb-2026-09-20-00000.jsonl data/kb-2026-10-07-00002.jsonl]" {
		t.Fatalf("deleted %v", deleted)
	}
	// Failures: bad payload, missing config, commit refused (no squash afterwards).
	if _, err := runHF(context.Background(), te.e, &Job{Payload: json.RawMessage(`{"file":"../etc/passwd"}`)}); err == nil {
		t.Fatal("bad file accepted")
	}
	te.envs["HF_REPO"] = ""
	if _, err := runHF(context.Background(), te.e, job); err == nil {
		t.Fatal("missing HF_REPO accepted")
	}
	te.envs["HF_REPO"] = "ekaii/commons"
	commitStatus = 401
	n := len(seq)
	mu.Unlock()
	_, err = runHF(context.Background(), te.e, job)
	mu.Lock()
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("refused commit: %v", err)
	}
	for _, s := range seq[n:] {
		if strings.Contains(s, "super-squash") {
			t.Fatal("squash attempted after a failed commit")
		}
	}
}

func TestLibmetaFetchersParse(t *testing.T) {
	big := strings.Repeat(" ", readCap+10)
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Egress-Host") + r.URL.Path
		switch key {
		case "pypi.org/pypi/requests/json":
			io.WriteString(w, `{"info":{"name":"requests","version":"2.32.3","home_page":"","project_urls":{"Homepage":"https://requests.readthedocs.io","Source":"https://github.com/psf/requests","Documentation":"https://requests.readthedocs.io/en/latest/"}},
				"releases":{"2.32.3":[{"upload_time_iso_8601":"2024-05-29T15:00:00Z","yanked":false}],"2.32.2":[{"upload_time_iso_8601":"2024-05-21T10:00:00Z","yanked":true},{"upload_time_iso_8601":"2024-05-21T09:00:00Z","yanked":true}],"0.0.1":[]}}`)
		case "pypi.org/pypi/nope/json":
			w.WriteHeader(404)
		case "pypi.org/pypi/huge/json":
			io.WriteString(w, big)
		case "registry.npmjs.org/left-pad":
			io.WriteString(w, `{"name":"left-pad","dist-tags":{"latest":"1.3.0"},"homepage":"https://github.com/stevemao/left-pad#readme","repository":{"type":"git","url":"git+https://github.com/stevemao/left-pad.git"},
				"time":{"created":"2014-01-01T00:00:00Z","1.0.0":"2014-03-01T00:00:00Z","1.3.0":"2018-04-01T00:00:00Z"},"versions":{"1.0.0":{"deprecated":"use String.prototype.padStart"},"1.3.0":{}}}`)
		case "registry.npmjs.org/@types/node":
			io.WriteString(w, big)
		case "registry.npmjs.org/@types/node/latest":
			io.WriteString(w, `{"name":"@types/node","version":"22.7.4","homepage":"https://github.com/DefinitelyTyped/DefinitelyTyped/tree/master/types/node","repository":"github:DefinitelyTyped/DefinitelyTyped"}`)
		case "proxy.golang.org/github.com/jackc/pgx/v5/@v/list":
			io.WriteString(w, "v5.0.0\nv5.1.0\nv5.2.0-beta.1\n")
		case "proxy.golang.org/github.com/jackc/pgx/v5/@latest":
			io.WriteString(w, `{"Version":"v5.1.0","Time":"2024-01-02T00:00:00Z"}`)
		case "proxy.golang.org/github.com/!azure/azure-sdk/@v/list":
			w.WriteHeader(410)
		case "crates.io/api/v1/crates/serde":
			if !strings.Contains(r.Header.Get("User-Agent"), "courier") {
				w.WriteHeader(403)
				return
			}
			io.WriteString(w, `{"crate":{"name":"serde","homepage":"https://serde.rs","repository":"https://github.com/serde-rs/serde","documentation":"https://docs.rs/serde","max_stable_version":"1.0.210","newest_version":"1.0.210"},
				"versions":[{"num":"1.0.210","yanked":false,"created_at":"2024-09-06T00:00:00Z"},{"num":"1.0.209","yanked":true,"created_at":"2024-08-26T00:00:00Z"},{"num":"2.0.0-alpha.1","yanked":false,"created_at":"2024-09-07T00:00:00Z"}]}`)
		case "rubygems.org/api/v1/gems/rails.json":
			io.WriteString(w, `{"name":"rails","version":"7.2.1","homepage_uri":"https://rubyonrails.org","source_code_uri":"https://github.com/rails/rails/tree/v7.2.1","documentation_uri":"https://api.rubyonrails.org/v7.2.1/"}`)
		case "rubygems.org/api/v1/versions/rails.json":
			io.WriteString(w, `[{"number":"7.2.1","created_at":"2024-08-22T00:00:00Z","prerelease":false},{"number":"8.0.0.beta1","created_at":"2024-09-26T00:00:00Z","prerelease":true}]`)
		default:
			w.WriteHeader(500)
			io.WriteString(w, "unexpected "+key)
		}
	}))
	defer fake.Close()
	e := testEnv(t, fake).e
	run := func(key string) (libResult, error) {
		b, _ := json.Marshal(map[string]string{"key": key})
		raw, err := runLibmeta(context.Background(), e, &Job{ID: 1, Kind: "libmeta", Payload: b})
		var r libResult
		if err == nil {
			if uerr := json.Unmarshal(raw, &r); uerr != nil {
				t.Fatal(uerr)
			}
		}
		return r, err
	}
	vmap := func(r libResult) map[string]libVersion {
		m := map[string]libVersion{}
		for _, v := range r.Versions {
			m[v.V] = v
		}
		return m
	}

	r, err := run("pypi:requests")
	if err != nil {
		t.Fatal(err)
	}
	vs := vmap(r)
	if r.Display != "requests" || r.Latest != "2.32.3" || r.LatestAt != "2024-05-29T15:00:00Z" || r.Homepage != "https://requests.readthedocs.io" ||
		r.Repo != "https://github.com/psf/requests" || r.Docs != "https://requests.readthedocs.io/en/latest/" || r.Registry != "https://pypi.org" ||
		len(r.Versions) != 3 || !vs["2.32.2"].Yanked || vs["2.32.2"].At != "2024-05-21T09:00:00Z" || vs["2.32.3"].Yanked || vs["0.0.1"].Yanked || r.Err != "" {
		t.Fatalf("pypi: %+v", r)
	}
	if r.Versions[len(r.Versions)-1].V != "2.32.3" {
		t.Fatalf("pypi versions not sorted by time: %+v", r.Versions)
	}
	if r, err := run("pypi:nope"); err != nil || r.Err != "not found" || r.Key != "pypi:nope" {
		t.Fatalf("pypi 404: %+v %v", r, err)
	}
	if r, err := run("pypi:huge"); err != nil || r.Err != "too large" {
		t.Fatalf("pypi too large: %+v %v", r, err)
	}

	r, err = run("npm:left-pad")
	if err != nil {
		t.Fatal(err)
	}
	vs = vmap(r)
	if r.Latest != "1.3.0" || r.LatestAt != "2018-04-01T00:00:00Z" || r.Repo != "https://github.com/stevemao/left-pad" || !vs["1.0.0"].Deprecated || vs["1.3.0"].Deprecated || len(r.Versions) != 2 {
		t.Fatalf("npm: %+v", r)
	}
	r, err = run("npm:@types/node")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Partial || r.Latest != "22.7.4" || r.Display != "@types/node" || len(r.Versions) != 1 || r.Repo != "" {
		t.Fatalf("npm fallback: %+v", r)
	}

	r, err = run("go:github.com/jackc/pgx/v5")
	if err != nil {
		t.Fatal(err)
	}
	vs = vmap(r)
	if r.Latest != "v5.1.0" || r.LatestAt != "2024-01-02T00:00:00Z" || r.Repo != "https://github.com/jackc/pgx" || r.Homepage != "https://pkg.go.dev/github.com/jackc/pgx/v5" ||
		len(r.Versions) != 3 || !vs["v5.2.0-beta.1"].Pre || vs["v5.1.0"].At != "2024-01-02T00:00:00Z" {
		t.Fatalf("go: %+v", r)
	}
	if escapeModule("github.com/Azure/azure-sdk") != "github.com/!azure/azure-sdk" {
		t.Fatal("module escaping")
	}
	if r, err := run("go:github.com/Azure/azure-sdk"); err != nil || r.Err != "not found" {
		t.Fatalf("go 410: %+v %v", r, err)
	}

	r, err = run("crates:serde")
	if err != nil {
		t.Fatal(err)
	}
	vs = vmap(r)
	if r.Latest != "1.0.210" || r.LatestAt != "2024-09-06T00:00:00Z" || r.Docs != "https://docs.rs/serde" || !vs["1.0.209"].Yanked || !vs["2.0.0-alpha.1"].Pre || len(r.Versions) != 3 {
		t.Fatalf("crates: %+v", r)
	}

	r, err = run("gem:rails")
	if err != nil {
		t.Fatal(err)
	}
	vs = vmap(r)
	if r.Latest != "7.2.1" || r.LatestAt != "2024-08-22T00:00:00Z" || r.Repo != "https://github.com/rails/rails/tree/v7.2.1" || !vs["8.0.0.beta1"].Pre || len(r.Versions) != 2 {
		t.Fatalf("gem: %+v", r)
	}

	// Unsupported ecosystems are acked with err; invalid names fail the row (no request is made).
	if r, err := run("maven:org.x:y"); err != nil || r.Err != "unsupported ecosystem" {
		t.Fatalf("maven: %+v %v", r, err)
	}
	for _, bad := range []string{"pypi:../x", "npm:Left-Pad", "go:not-a-module", "crates:a b", "gem:", "requests", "x:y"} {
		if _, err := run(bad); err == nil {
			t.Fatalf("key %q accepted", bad)
		}
	}
	// Transient registry errors fail the row (retry), not an ack.
	if _, err := run("gem:unknown-gem"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("500: %v", err)
	}
	// Version cap.
	lr := libResult{}
	for i := 0; i < libMaxVersions+5; i++ {
		lr.Versions = append(lr.Versions, libVersion{V: fmt.Sprintf("1.%d.0", i), At: fmt.Sprintf("2024-01-01T00:%02d:%02dZ", i/60, i%60)})
	}
	lr.finish()
	if len(lr.Versions) != libMaxVersions || !lr.Truncated || lr.Versions[len(lr.Versions)-1].V != fmt.Sprintf("1.%d.0", libMaxVersions+4) {
		t.Fatalf("version cap: %d %v", len(lr.Versions), lr.Truncated)
	}
	if cleanURL("git+ssh://git@github.com/x/y.git") != "" || cleanURL("git://github.com/x/y.git") != "https://github.com/x/y" || cleanURL("javascript:alert(1)") != "" {
		t.Fatal("cleanURL")
	}
}

func TestCFPurgePayload(t *testing.T) {
	zone := strings.Repeat("ab", 16)
	var mu sync.Mutex
	var calls []recorded
	reply := `{"success":true,"errors":[],"result":{"id":"x"}}`
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, recorded{r.Header.Get("X-Egress-Host"), r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), b})
		mu.Unlock()
		io.WriteString(w, reply)
	}))
	defer fake.Close()
	te := testEnv(t, fake)
	te.envs["CF_ZONE_ID"] = zone
	te.secret(t, "cf_token", "cf_purge_only")
	var urls []string
	for i := 0; i < 35; i++ {
		urls = append(urls, fmt.Sprintf("https://agents.example/kb/%07d", i))
	}
	urls = append(urls, "https://evil.example/kb/x", urls[0], "https://agents.example/export/kb-2026-10-07.jsonl.gz")
	b, _ := json.Marshal(map[string]any{"urls": urls})
	res, err := runCFPurge(context.Background(), te.e, &Job{ID: 1, Kind: "cf_purge", Payload: b})
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ Purged, Calls, Dropped int }
	if json.Unmarshal(res, &out) != nil || out.Purged != 36 || out.Calls != 2 || out.Dropped != 2 {
		t.Fatalf("result %s", res)
	}
	mu.Lock()
	got := append([]recorded(nil), calls...)
	mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("calls %d", len(got))
	}
	var sizes []int
	for _, c := range got {
		if c.host != "api.cloudflare.com" || c.method != "POST" || c.path != "/client/v4/zones/"+zone+"/purge_cache" || c.auth != "Bearer cf_purge_only" || !strings.HasPrefix(c.ctype, "application/json") {
			t.Fatalf("call %+v", c)
		}
		var p struct {
			Files []string `json:"files"`
		}
		if err := json.Unmarshal(c.body, &p); err != nil {
			t.Fatal(err)
		}
		for _, u := range p.Files {
			if !strings.HasPrefix(u, "https://agents.example/") {
				t.Fatalf("foreign url sent: %s", u)
			}
		}
		sizes = append(sizes, len(p.Files))
	}
	if sizes[0] != cfPurgeMax || sizes[1] != 6 {
		t.Fatalf("chunk sizes %v", sizes)
	}
	// Cloudflare-level failure, missing config, empty payload.
	reply = `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`
	if _, err := runCFPurge(context.Background(), te.e, &Job{Payload: b}); err == nil || !strings.Contains(err.Error(), "10000 Authentication error") {
		t.Fatalf("cf error: %v", err)
	}
	te.envs["CF_ZONE_ID"] = "not-a-zone"
	if _, err := runCFPurge(context.Background(), te.e, &Job{Payload: b}); !errors.Is(err, errCFNoConfig) {
		t.Fatalf("bad zone: %v", err)
	}
	te.envs["CF_ZONE_ID"] = zone
	n := len(calls)
	res, err = runCFPurge(context.Background(), te.e, &Job{Payload: json.RawMessage(`{"urls":["https://evil.example/"]}`)})
	if err != nil || len(calls) != n || !strings.Contains(string(res), `"purged":0`) {
		t.Fatalf("nothing to purge: %s %v calls=%d", res, err, len(calls)-n)
	}
}

func TestKindsRegistryAndEnv(t *testing.T) {
	names := Names()
	for _, want := range []string{"indexnow", "hf", "libmeta", "cf_purge"} {
		if k, ok := Lookup(want); !ok || k.Name != want {
			t.Fatalf("kind %s not registered (have %v)", want, names)
		}
	}
	for _, bad := range []*Kind{
		{Name: "Bad", Run: func(context.Context, *Env, *Job) (json.RawMessage, error) { return nil, nil }},
		{Name: "two", Run: func(context.Context, *Env, *Job) (json.RawMessage, error) { return nil, nil }, Scan: func(context.Context, *Env) error { return nil }},
		{Name: "none"},
		{Name: "indexnow", Run: func(context.Context, *Env, *Job) (json.RawMessage, error) { return nil, nil }},
		{Name: "badhost", Hosts: []string{"10.0.0.1"}, Run: func(context.Context, *Env, *Job) (json.RawMessage, error) { return nil, nil }},
		{Name: "scan_no_every", Scan: func(context.Context, *Env) error { return nil }},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("kind %+v accepted", bad)
				}
			}()
			Register(bad)
		}()
	}
	ks, err := enabledKinds([]string{"indexnow", " libmeta ", "indexnow", ""})
	if err != nil || len(ks) != 2 || ks[0].Name != "indexnow" || ks[1].Name != "libmeta" {
		t.Fatalf("enabledKinds: %v %v", ks, err)
	}
	if _, err := enabledKinds([]string{"indexnow", "nosuch"}); err == nil || !strings.Contains(err.Error(), "nosuch") {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := enabledKinds(nil); err == nil {
		t.Fatal("empty kinds accepted")
	}
	// The scanner hook runs on its own ticker without outbox rows.
	var scans int32
	var smu sync.Mutex
	Register(&Kind{Name: "t_scan", Every: 10 * time.Millisecond, Scan: func(ctx context.Context, e *Env) error {
		smu.Lock()
		scans++
		smu.Unlock()
		return errors.New("logged only")
	}})
	sk, _ := Lookup("t_scan")
	f := newFakeInternal(t)
	c, _ := testCourier(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	c.runScanner(ctx, sk)
	smu.Lock()
	defer smu.Unlock()
	if scans < 3 {
		t.Fatalf("scanner ran %d times", scans)
	}
	if due, _ := (&courier{kinds: []*Kind{sk}, last: map[string]time.Time{}}).due(time.Now()); len(due) != 0 {
		t.Fatal("scanner kind polled as an outbox kind")
	}

	// Env: same-site URLs, quota, secrets.
	e := testEnv(t, f.srv).e
	for u, ok := range map[string]bool{"https://agents.example/kb/a": true, "https://AGENTS.example/kb/a": true, "http://agents.example/x": false,
		"https://evil.example/": false, "https://agents.example:8443/": false, "https://u@agents.example/": false, "https://agents.example/#f": false,
		"https://agents.example/a b": false, "": false, "https://agents.example/" + strings.Repeat("x", 2100): false} {
		if e.SameSite(u) != ok {
			t.Fatalf("SameSite(%q) = %v", u, !ok)
		}
	}
	if !e.Take("q", 3, 5) || !e.Take("q", 2, 5) || e.Take("q", 1, 5) {
		t.Fatal("quota arithmetic")
	}
	if e.Secret("../etc/passwd") != "" || e.Secret("missing") != "" {
		t.Fatal("secret names")
	}
}

func TestHealthcheckAndConfig(t *testing.T) {
	hb := filepath.Join(t.TempDir(), "alive")
	t.Setenv("HEARTBEAT_FILE", hb)
	if healthcheck() != 1 {
		t.Fatal("missing heartbeat healthy")
	}
	os.WriteFile(hb, []byte("x"), 0o600)
	if healthcheck() != 0 {
		t.Fatal("fresh heartbeat unhealthy")
	}
	old := time.Now().Add(-10 * time.Minute)
	os.Chtimes(hb, old, old)
	if healthcheck() != 1 {
		t.Fatal("stale heartbeat healthy")
	}

	t.Setenv("COURIER_TOKEN", testToken)
	t.Setenv("EGRESS_KINDS", "indexnow, libmeta")
	t.Setenv("INTERNAL_URL", "http://gateway:8081/")
	cfg, err := loadConfig()
	if err != nil || cfg.InternalURL != "http://gateway:8081" || len(cfg.Kinds) != 2 || cfg.Wait != 55 || cfg.Token != testToken {
		t.Fatalf("config %+v %v", cfg, err)
	}
	t.Setenv("EGRESS_KINDS", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("empty EGRESS_KINDS accepted")
	}
	t.Setenv("EGRESS_KINDS", "indexnow")
	t.Setenv("COURIER_TOKEN", "short")
	if _, err := loadConfig(); err == nil {
		t.Fatal("short token accepted")
	}
	t.Setenv("COURIER_TOKEN", testToken)
	t.Setenv("INTERNAL_URL", "gateway:8081")
	if _, err := loadConfig(); err == nil {
		t.Fatal("bad INTERNAL_URL accepted")
	}
	t.Setenv("INTERNAL_URL", "http://gateway:8081")
	t.Setenv("POLL_WAIT", "90")
	if _, err := loadConfig(); err == nil {
		t.Fatal("POLL_WAIT 90 accepted")
	}
	if s3Host("minio.example.org") != "minio.example.org" || s3Host("https://s3.eu.example.net:9000") != "s3.eu.example.net" || s3Host("") != "" {
		t.Fatal("s3Host")
	}
}
