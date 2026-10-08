package egress

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
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
	} else if pool, done := testdb.Open("egress", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping egress DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

const (
	testSecret = "test-secret-0123456789"
	testToken  = "courier-token-abc"
)

func newDeps(t *testing.T, courierToken string) *core.Deps {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte(testSecret), AdminToken: "adm-token", CourierToken: courierToken, PowBits: 6,
		DataDir: t.TempDir(), PublicURL: "https://agents.example", RegPerHour: 1 << 20, TrustCF: true}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	if _, err := testPool.Exec(context.Background(), `DELETE FROM egress_outbox`); err != nil {
		t.Fatal(err)
	}
	return d
}

func internalServer(t *testing.T, d *core.Deps) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(InternalHandler(d))
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, method, url, token, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func enqueue(t *testing.T, kind string, payload any) {
	t.Helper()
	if err := core.Egress(context.Background(), testPool, kind, payload); err != nil {
		t.Fatal(err)
	}
}

func TestInternalServerAuth(t *testing.T) {
	d := newDeps(t, testToken)
	srv := internalServer(t, d)
	for _, tok := range []string{"", "wrong", testToken + "x", "courier-token-ab"} {
		code, body := call(t, "GET", srv.URL+"/internal/egress?kinds=indexnow", tok, "")
		if code != 401 {
			t.Fatalf("token %q: got %d %s want 401", tok, code, body)
		}
	}
	// Scheme word is case-insensitive; the token itself is not.
	req, _ := http.NewRequest("GET", srv.URL+"/internal/egress?kinds=indexnow", nil)
	req.Header.Set("Authorization", "bearer "+testToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatalf("valid token on empty queue: got %d want 204", resp.StatusCode)
	}
	for _, p := range []string{"/internal/egress/1/ack", "/internal/egress/1/fail"} {
		if code, _ := call(t, "POST", srv.URL+p, "", `{}`); code != 401 {
			t.Fatalf("%s without bearer: %d", p, code)
		}
	}
	if code, _ := call(t, "GET", srv.URL+"/internal/config", "", ""); code != 401 {
		t.Fatalf("config without bearer: %d", code)
	}
	// Unset token: fail closed, even for an empty bearer.
	d2 := newDeps(t, "")
	srv2 := internalServer(t, d2)
	for _, tok := range []string{"", testToken} {
		if code, _ := call(t, "GET", srv2.URL+"/internal/egress?kinds=indexnow", tok, ""); code != 401 {
			t.Fatalf("unset COURIER_TOKEN, bearer %q: got %d want 401", tok, code)
		}
	}
}

func TestPublicMuxNeverServesInternal(t *testing.T) {
	d := newDeps(t, testToken)
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	RegisterInternal("GET /internal/render", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "render") })
	pub := httptest.NewServer(d.Handler(mux))
	defer pub.Close()
	paths := []struct{ method, path string }{
		{"GET", "/internal/egress?kinds=indexnow"}, {"POST", "/internal/egress/1/ack"}, {"POST", "/internal/egress/1/fail"},
		{"GET", "/internal/config"}, {"GET", "/internal/render?url=https://agents.example/"}, {"GET", "/internal/"}, {"GET", "/internal"},
	}
	n := 0
	for _, host := range []string{"gateway:8080", "agents.ekaii.fr", "127.0.0.1:8081", "localhost"} {
		for _, p := range paths {
			n++
			req, _ := http.NewRequest(p.method, pub.URL+p.path, strings.NewReader(`{}`))
			req.Host = host
			req.Header.Set("CF-Connecting-IP", fmt.Sprintf("203.0.113.%d", n)) // one anonymous budget per probe
			req.Header.Set("Authorization", "Bearer "+testToken)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 404 {
				t.Fatalf("public mux Host=%s %s %s: got %d want 404", host, p.method, p.path, resp.StatusCode)
			}
		}
	}
	// The one public route: the IndexNow key file, whose body is the key.
	key := IndexNowKey([]byte(testSecret))
	if len(key) != 32 {
		t.Fatalf("key %q", key)
	}
	resp, err := http.Get(pub.URL + "/" + key + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != key || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("key file: %d %q %s", resp.StatusCode, b, resp.Header.Get("Content-Type"))
	}
	// A different key file is not served.
	resp, err = http.Get(pub.URL + "/" + strings.Repeat("0", 32) + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("foreign key file: %d", resp.StatusCode)
	}
	// The same RegisterInternal route IS served on the internal listener, behind the bearer.
	in := internalServer(t, d)
	if code, _ := call(t, "GET", in.URL+"/internal/render?url=x", "", ""); code != 401 {
		t.Fatalf("internal render without bearer: %d", code)
	}
	if code, body := call(t, "GET", in.URL+"/internal/render?url=x", testToken, ""); code != 200 || body != "render" {
		t.Fatalf("internal render: %d %q", code, body)
	}
	code, body := call(t, "GET", in.URL+"/internal/config", testToken, "")
	var cfg struct {
		PublicURL string `json:"public_url"`
		Key       string `json:"indexnow_key"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &cfg) != nil || cfg.Key != key || cfg.PublicURL != "https://agents.example" {
		t.Fatalf("config: %d %s", code, body)
	}
}

func TestPollAckFailFlow(t *testing.T) {
	d := newDeps(t, testToken)
	srv := internalServer(t, d)
	ctx := context.Background()
	var mu sync.Mutex
	var got []string
	ResultFn["libmeta"] = func(ctx context.Context, d *core.Deps, q core.Q, payload, result json.RawMessage) error {
		var p struct{ Key string }
		var r struct{ Latest string }
		if err := json.Unmarshal(payload, &p); err != nil {
			return err
		}
		if err := json.Unmarshal(result, &r); err != nil {
			return err
		}
		if r.Latest == "boom" {
			return fmt.Errorf("handler refused")
		}
		mu.Lock()
		got = append(got, p.Key+"="+r.Latest)
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() { delete(ResultFn, "libmeta") })

	enqueue(t, "libmeta", map[string]string{"key": "pypi:requests"})
	enqueue(t, "libmeta", map[string]string{"key": "npm:left-pad"})
	enqueue(t, "indexnow", map[string]any{"urls": []string{"https://agents.example/kb/abc"}})

	// kinds filter and validation
	if code, _ := call(t, "GET", srv.URL+"/internal/egress", testToken, ""); code != 400 {
		t.Fatalf("missing kinds: %d", code)
	}
	if code, _ := call(t, "GET", srv.URL+"/internal/egress?kinds=Bad-Kind", testToken, ""); code != 400 {
		t.Fatalf("bad kind: %d", code)
	}
	if code, _ := call(t, "GET", srv.URL+"/internal/egress?kinds=hf,cf_purge", testToken, ""); code != 204 {
		t.Fatalf("no rows of these kinds: %d", code)
	}
	code, body := call(t, "GET", srv.URL+"/internal/egress?kinds=libmeta,hf", testToken, "")
	var r1, r2 Row
	if code != 200 || json.Unmarshal([]byte(body), &r1) != nil || r1.Kind != "libmeta" || r1.Attempts != 1 || !strings.Contains(string(r1.Payload), "pypi:requests") {
		t.Fatalf("first poll: %d %s", code, body)
	}
	code, body = call(t, "GET", srv.URL+"/internal/egress?kinds=libmeta", testToken, "")
	if code != 200 || json.Unmarshal([]byte(body), &r2) != nil || r2.ID == r1.ID || !strings.Contains(string(r2.Payload), "left-pad") {
		t.Fatalf("second poll: %d %s", code, body)
	}
	// Both rows are leased: nothing left for libmeta.
	if code, _ := call(t, "GET", srv.URL+"/internal/egress?kinds=libmeta", testToken, ""); code != 204 {
		t.Fatalf("leased rows re-served: %d", code)
	}
	// ack with a result dispatches to ResultFn in the same tx
	code, body = call(t, "POST", fmt.Sprintf("%s/internal/egress/%d/ack", srv.URL, r1.ID), testToken, `{"result":{"latest":"2.32.3"}}`)
	if code != 200 {
		t.Fatalf("ack: %d %s", code, body)
	}
	mu.Lock()
	if len(got) != 1 || got[0] != "pypi:requests=2.32.3" {
		t.Fatalf("result handler got %v", got)
	}
	mu.Unlock()
	var done bool
	if err := testPool.QueryRow(ctx, `SELECT done_at IS NOT NULL FROM egress_outbox WHERE id = $1`, r1.ID).Scan(&done); err != nil || !done {
		t.Fatalf("row not done: %v %v", done, err)
	}
	// second ack of the same row: 404; unknown id: 404; bad id: 404
	if code, _ := call(t, "POST", fmt.Sprintf("%s/internal/egress/%d/ack", srv.URL, r1.ID), testToken, `{}`); code != 404 {
		t.Fatalf("double ack: %d", code)
	}
	if code, _ := call(t, "POST", srv.URL+"/internal/egress/999999/ack", testToken, `{}`); code != 404 {
		t.Fatalf("unknown ack: %d", code)
	}
	if code, _ := call(t, "POST", srv.URL+"/internal/egress/abc/fail", testToken, `{"err":"x"}`); code != 404 {
		t.Fatalf("bad id: %d", code)
	}
	// a refusing handler rolls the ack back: row stays live (leased)
	code, _ = call(t, "POST", fmt.Sprintf("%s/internal/egress/%d/ack", srv.URL, r2.ID), testToken, `{"result":{"latest":"boom"}}`)
	if code != 500 {
		t.Fatalf("refused result: %d", code)
	}
	if err := testPool.QueryRow(ctx, `SELECT done_at IS NOT NULL FROM egress_outbox WHERE id = $1`, r2.ID).Scan(&done); err != nil || done {
		t.Fatalf("row done despite rollback: %v %v", done, err)
	}
	// fail: backoff, last_err cleaned to one line
	code, body = call(t, "POST", fmt.Sprintf("%s/internal/egress/%d/fail", srv.URL, r2.ID), testToken, `{"err":"npm: status 503\nfake: line x"}`)
	if code != 200 {
		t.Fatalf("fail: %d %s", code, body)
	}
	var lastErr string
	var secs float64
	if err := testPool.QueryRow(ctx, `SELECT last_err, EXTRACT(EPOCH FROM next_at - now()) FROM egress_outbox WHERE id = $1`, r2.ID).Scan(&lastErr, &secs); err != nil {
		t.Fatal(err)
	}
	if lastErr != "npm: status 503 fake: line x" || secs < 50 || secs > 70 {
		t.Fatalf("after fail: last_err=%q backoff=%.0fs", lastErr, secs)
	}
	// Second failure doubles the backoff.
	if _, err := testPool.Exec(ctx, `UPDATE egress_outbox SET next_at = now() WHERE id = $1`, r2.ID); err != nil {
		t.Fatal(err)
	}
	code, body = call(t, "GET", srv.URL+"/internal/egress?kinds=libmeta", testToken, "")
	var r3 Row
	if code != 200 || json.Unmarshal([]byte(body), &r3) != nil || r3.ID != r2.ID || r3.Attempts != 2 {
		t.Fatalf("re-poll after backoff: %d %s", code, body)
	}
	call(t, "POST", fmt.Sprintf("%s/internal/egress/%d/fail", srv.URL, r2.ID), testToken, `{"err":"again"}`)
	if err := testPool.QueryRow(ctx, `SELECT EXTRACT(EPOCH FROM next_at - now()) FROM egress_outbox WHERE id = $1`, r2.ID).Scan(&secs); err != nil {
		t.Fatal(err)
	}
	if secs < 110 || secs > 130 {
		t.Fatalf("second backoff %.0fs want ~120", secs)
	}
	// Dead-letter at MaxAttempts.
	if _, err := testPool.Exec(ctx, `UPDATE egress_outbox SET next_at = now(), attempts = $2 WHERE id = $1`, r2.ID, MaxAttempts-1); err != nil {
		t.Fatal(err)
	}
	code, _ = call(t, "GET", srv.URL+"/internal/egress?kinds=libmeta", testToken, "")
	if code != 200 {
		t.Fatalf("poll at attempt %d: %d", MaxAttempts, code)
	}
	call(t, "POST", fmt.Sprintf("%s/internal/egress/%d/fail", srv.URL, r2.ID), testToken, `{"err":"final"}`)
	if err := testPool.QueryRow(ctx, `SELECT last_err, done_at IS NOT NULL FROM egress_outbox WHERE id = $1`, r2.ID).Scan(&lastErr, &done); err != nil {
		t.Fatal(err)
	}
	if !done || lastErr != "dead-letter: final" {
		t.Fatalf("dead-letter: done=%v last_err=%q", done, lastErr)
	}
	if code, _ := call(t, "POST", fmt.Sprintf("%s/internal/egress/%d/fail", srv.URL, r2.ID), testToken, `{"err":"x"}`); code != 404 {
		t.Fatalf("fail on dead row: %d", code)
	}
	// A row that reached MaxAttempts without any report is never served and the sweep dead-letters it.
	enqueue(t, "libmeta", map[string]string{"key": "gem:rails"})
	if _, err := testPool.Exec(ctx, `UPDATE egress_outbox SET attempts = $1, next_at = now() - interval '1 minute' WHERE done_at IS NULL AND kind = 'libmeta'`, MaxAttempts); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, "GET", srv.URL+"/internal/egress?kinds=libmeta", testToken, ""); code != 204 {
		t.Fatalf("exhausted row served: %d", code)
	}
	if err := Sweep(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM egress_outbox WHERE last_err = 'dead-letter: no report' AND done_at IS NOT NULL`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("sweep dead-letter: n=%d err=%v", n, err)
	}
	// Result size cap and invalid JSON.
	big := `{"result":"` + strings.Repeat("x", MaxResult) + `"}`
	if code, _ := call(t, "POST", srv.URL+"/internal/egress/1/ack", testToken, big); code != 413 {
		t.Fatalf("oversize result: %d", code)
	}
	if code, _ := call(t, "POST", srv.URL+"/internal/egress/1/ack", testToken, `{"result":`); code != 400 {
		t.Fatalf("invalid json: %d", code)
	}
	// freeze:egress pauses the queue (indexnow row still pending) and ack/fail keep working.
	if err := d.SetFreeze(ctx, "freeze:egress", true); err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, "GET", srv.URL+"/internal/egress?kinds=indexnow&wait=2", testToken, ""); code != 204 {
		t.Fatalf("frozen poll: %d", code)
	}
	if err := d.SetFreeze(ctx, "freeze:egress", false); err != nil {
		t.Fatal(err)
	}
	code, body = call(t, "GET", srv.URL+"/internal/egress?kinds=indexnow", testToken, "")
	var r4 Row
	if code != 200 || json.Unmarshal([]byte(body), &r4) != nil || r4.Kind != "indexnow" {
		t.Fatalf("after unfreeze: %d %s", code, body)
	}
	// ack without a result and without a ResultFn
	if code, _ := call(t, "POST", fmt.Sprintf("%s/internal/egress/%d/ack", srv.URL, r4.ID), testToken, ""); code != 200 {
		t.Fatalf("plain ack: %d", code)
	}
}

func TestPollWaitsForNewRows(t *testing.T) {
	d := newDeps(t, testToken)
	srv := internalServer(t, d)
	// Empty queue with wait=1: 204 after about a second.
	start := time.Now()
	if code, _ := call(t, "GET", srv.URL+"/internal/egress?kinds=cf_purge&wait=1", testToken, ""); code != 204 {
		t.Fatalf("empty wait: %d", code)
	}
	if el := time.Since(start); el < 900*time.Millisecond || el > 5*time.Second {
		t.Fatalf("wait=1 took %s", el)
	}
	// A row enqueued during the wait is returned before the deadline.
	go func() {
		time.Sleep(300 * time.Millisecond)
		core.Egress(context.Background(), testPool, "cf_purge", map[string]any{"urls": []string{"https://agents.example/export/"}})
	}()
	start = time.Now()
	code, body := call(t, "GET", srv.URL+"/internal/egress?kinds=cf_purge&wait=10", testToken, "")
	if code != 200 || !strings.Contains(body, "cf_purge") {
		t.Fatalf("wait poll: %d %s", code, body)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("row delivered after %s", el)
	}
	// wait is clamped to MaxWait and rejected when negative.
	if code, _ := call(t, "GET", srv.URL+"/internal/egress?kinds=cf_purge&wait=-1", testToken, ""); code != 400 {
		t.Fatalf("negative wait: %d", code)
	}
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, fmt.Sprintf("k%d", i))
	}
	if _, err := ParseKinds(strings.Join(many, ",")); err == nil {
		t.Fatal("too many kinds accepted")
	}
	if ks, err := ParseKinds(" hf, hf ,cf_purge,"); err != nil || len(ks) != 2 || ks[0] != "hf" || ks[1] != "cf_purge" {
		t.Fatalf("ParseKinds dedupe: %v %v", ks, err)
	}
}

// TestServeRealListener is the curl acceptance on a real socket: no bearer -> 401, the key route
// is absent from the internal server, and Serve returns once ctx is cancelled.
func TestServeRealListener(t *testing.T) {
	d := newDeps(t, testToken)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, d, addr) }()
	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = http.Get("http://" + addr + "/internal/egress")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
		t.Fatalf("no bearer: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	resp, err = http.Get("http://" + addr + "/" + IndexNowKey([]byte(testSecret)) + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("public route on the internal server: %d", resp.StatusCode)
	}
	if code, _ := call(t, "GET", "http://"+addr+"/internal/egress?kinds=hf", testToken, ""); code != 204 {
		t.Fatalf("with bearer: %d", code)
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

func TestRegisterInternalValidation(t *testing.T) {
	for _, bad := range []string{"GET /render", "/public/x", "GET internal/x"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("pattern %q accepted", bad)
				}
			}()
			RegisterInternal(bad, func(http.ResponseWriter, *http.Request) {})
		}()
	}
	RegisterInternal("GET /internal/probe-once", func(w http.ResponseWriter, r *http.Request) {})
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("duplicate pattern accepted")
			}
		}()
		RegisterInternal("GET /internal/probe-once", func(w http.ResponseWriter, r *http.Request) {})
	}()
}

func TestOneLine(t *testing.T) {
	if got := oneLine("a\r\nb\tc\x00d", 100); got != "a  b c d" {
		t.Fatalf("%q", got)
	}
	if got := oneLine(strings.Repeat("é", 10), 4); got != "éééé" {
		t.Fatalf("%q", got)
	}
}
