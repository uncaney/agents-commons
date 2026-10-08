package mcpsse

// Acceptance tests of P123 (SPEC-v2 27.9). They drive the real HTTP surface with an SSE client:
// GET /sse mints a signed session, POST /messages?s= bridges to the in-process /mcp handler, the
// response is returned inline and pushed onto the open stream, streams are bounded by d.Waiters,
// the stream keepalives and closes hard with retry:1000, and a forged session id is refused.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		fmt.Println("TEST_DATABASE_URL unset: skipping mcpsse DB tests")
		os.Exit(0)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		panic(err)
	}
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		panic(err)
	}
	if err := core.Migrate(ctx, pool); err != nil {
		panic(err)
	}
	testPool = pool
	code := m.Run()
	pool.Close()
	os.Exit(code)
}

const testSecret = "test-secret-0123456789"

type env struct {
	t   *testing.T
	d   *core.Deps
	srv *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte(testSecret), PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, RegPerHour: 1 << 20, PublicURL: "https://t.example"}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(func() { srv.Close(); d.Close() })
	return &env{t: t, d: d, srv: srv}
}

var ipSeq = func() *uint32 { var n uint32 = 1000; return &n }()

func randIP() string {
	n := atomic.AddUint32(ipSeq, 1)
	return fmt.Sprintf("10.%d.%d.%d", (n>>8)&0xff, n&0xff, 1+int(n)%250)
}

// --- SSE client ---------------------------------------------------------------------------------

type streamConn struct {
	resp   *http.Response
	r      *bufio.Reader
	cancel context.CancelFunc
}

// openSSE opens GET /sse from ip and returns the live connection once the headers have arrived.
func (e *env) openSSE(ip string) (*streamConn, int) {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+"/sse", nil)
	req.Header.Set("CF-Connecting-IP", ip)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		e.t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		cancel()
		return nil, resp.StatusCode
	}
	return &streamConn{resp: resp, r: bufio.NewReader(resp.Body), cancel: cancel}, 200
}

func (c *streamConn) close() {
	c.cancel()
	c.resp.Body.Close()
}

// frame reads one SSE frame (the lines up to the next blank line). nil at EOF.
func (c *streamConn) frame(t *testing.T) []string {
	t.Helper()
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if line = strings.TrimRight(line, "\n"); line == "" {
			if len(lines) > 0 {
				return lines
			}
			if err != nil {
				return nil
			}
			continue
		}
		lines = append(lines, line)
		if err != nil {
			return lines
		}
	}
}

// field returns the value of the "k:" line (trimming one optional leading space) in a frame.
func field(frame []string, k string) (string, bool) {
	for _, l := range frame {
		if v, ok := strings.CutPrefix(l, k+":"); ok {
			return strings.TrimPrefix(v, " "), true
		}
	}
	return "", false
}

// endpoint reads the first frame and returns the session id from its endpoint event.
func (c *streamConn) endpoint(t *testing.T) string {
	t.Helper()
	fr := c.frame(t)
	if ev, _ := field(fr, "event"); ev != "endpoint" {
		t.Fatalf("first event = %q, want endpoint (%v)", ev, fr)
	}
	data, ok := field(fr, "data")
	if !ok || !strings.HasPrefix(data, "/messages?s=") {
		t.Fatalf("endpoint data = %q, want /messages?s=...", data)
	}
	return strings.TrimPrefix(data, "/messages?s=")
}

// post sends a JSON-RPC body to /messages?s= and returns (status, body).
func (e *env) post(s string, body any) (int, string) {
	e.t.Helper()
	j, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/messages?s="+s, bytes.NewReader(j))
	req.Header.Set("CF-Connecting-IP", randIP())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b))
}

func rpc(id int, method string, params any) map[string]any {
	m := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	return m
}

// --- tests --------------------------------------------------------------------------------------

func TestEndpointEventAndHMAC(t *testing.T) {
	e := newEnv(t)
	c, st := e.openSSE(randIP())
	if st != 200 {
		t.Fatalf("GET /sse status %d", st)
	}
	defer c.close()
	if ct := c.resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type %q", ct)
	}
	s := c.endpoint(t)
	if !validSession([]byte(testSecret), s) {
		t.Fatalf("minted session %q does not validate", s)
	}
	// A tampered tag must not validate.
	nonce, _, _ := strings.Cut(s, ".")
	if validSession([]byte(testSecret), nonce+".AAAAAAAAAAAAAAAAAAAAAA") {
		t.Fatal("forged tag validated")
	}
	// A different key must not validate the same session.
	if validSession([]byte("another-secret-9876543210"), s) {
		t.Fatal("session validated under the wrong key")
	}
}

func TestMessagesInlineAndPushed(t *testing.T) {
	e := newEnv(t)
	c, _ := e.openSSE(randIP())
	defer c.close()
	s := c.endpoint(t)

	// initialize, inline.
	st, body := e.post(s, rpc(1, "initialize", map[string]any{"protocolVersion": "2025-06-18"}))
	if st != 200 {
		t.Fatalf("POST /messages status %d: %s", st, body)
	}
	if !strings.Contains(body, `"serverInfo"`) || !strings.Contains(body, "agents.ekaii.fr") {
		t.Fatalf("inline initialize result missing serverInfo: %s", body)
	}
	// The same response is pushed as a message event onto the open stream.
	fr := c.frame(t)
	if ev, _ := field(fr, "event"); ev != "message" {
		t.Fatalf("pushed event = %q, want message (%v)", ev, fr)
	}
	data, _ := field(fr, "data")
	var got struct {
		ID     int             `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(data), &got); err != nil {
		t.Fatalf("pushed data not JSON-RPC: %v (%q)", err, data)
	}
	if got.ID != 1 || !bytes.Contains(got.Result, []byte("serverInfo")) {
		t.Fatalf("pushed message mismatch: %q", data)
	}

	// tools/list over the same transport returns the single cx tool.
	st, body = e.post(s, rpc(2, "tools/list", nil))
	if st != 200 || !strings.Contains(body, `"cx"`) {
		t.Fatalf("tools/list inline = %d %s", st, body)
	}
	fr = c.frame(t)
	if data, _ := field(fr, "data"); !strings.Contains(data, `"cx"`) {
		t.Fatalf("tools/list not pushed: %v", fr)
	}
}

func TestBoundedStreamRetry(t *testing.T) {
	defer swapTimings(40*time.Millisecond, 160*time.Millisecond)()
	e := newEnv(t)
	c, _ := e.openSSE(randIP())
	defer c.close()
	_ = c.endpoint(t)

	var keepalives int
	var sawRetry bool
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		fr := c.frame(t)
		if fr == nil {
			break // stream closed after the hard cap
		}
		if len(fr) == 1 && strings.HasPrefix(fr[0], ": ") {
			keepalives++
		}
		if r, ok := field(fr, "retry"); ok {
			if r != "1000" {
				t.Fatalf("retry = %q, want 1000", r)
			}
			sawRetry = true
		}
	}
	if keepalives == 0 {
		t.Fatal("no keepalive comments seen before the hard cap")
	}
	if !sawRetry {
		t.Fatal("stream did not close with retry:1000")
	}
}

func TestWaitersCap(t *testing.T) {
	e := newEnv(t)
	ip := "203.0.113.7" // one IP => one group; anonymous streams cap at 4 per group
	var open []*streamConn
	defer func() {
		for _, c := range open {
			c.close()
		}
	}()
	for i := 0; i < core.MaxWaitersPerGrp; i++ {
		c, st := e.openSSE(ip)
		if st != 200 {
			t.Fatalf("stream %d: status %d, want 200", i, st)
		}
		_ = c.endpoint(t)
		open = append(open, c)
	}
	// The next stream from the same group is refused.
	if _, st := e.openSSE(ip); st != http.StatusTooManyRequests {
		t.Fatalf("over-cap stream status %d, want 429", st)
	}
	// A different group is still admitted.
	c, st := e.openSSE("198.51.100.9")
	if st != 200 {
		t.Fatalf("other-group stream status %d, want 200", st)
	}
	c.close()
}

func TestBadSessionRejected(t *testing.T) {
	e := newEnv(t)
	cases := []string{"", "garbage", "nodot", "nonce.badtag", mintSession([]byte("wrong-secret-1111111111"))}
	for _, s := range cases {
		st, body := e.post(s, rpc(1, "ping", nil))
		if st != http.StatusForbidden {
			t.Fatalf("POST /messages?s=%q status %d, want 403 (%s)", s, st, body)
		}
	}
	// Tampering the tag of a valid session is also refused.
	e2 := e
	c, _ := e2.openSSE(randIP())
	defer c.close()
	s := c.endpoint(t)
	nonce, _, _ := strings.Cut(s, ".")
	if st, _ := e.post(nonce+".AAAAAAAAAAAAAAAAAAAAAA", rpc(1, "ping", nil)); st != http.StatusForbidden {
		t.Fatalf("tampered session status %d, want 403", st)
	}
}

// swapTimings overrides the stream timings for a test and returns a restore func.
func swapTimings(ka, hard time.Duration) func() {
	ok, oh := keepaliveInterval, maxStreamDur
	keepaliveInterval, maxStreamDur = ka, hard
	return func() { keepaliveInterval, maxStreamDur = ok, oh }
}
