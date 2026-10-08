package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/events"
	"ekaii.fr/commons/internal/swarm"
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
	} else if pool, done := testdb.Open("webhook", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL unset: skipping webhook DB tests")
		os.Exit(0)
	}
	// Every test root is treated as L1+ so the hook routes are reachable.
	core.LevelFn = func(context.Context, core.Q, string) int { return 2 }
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type env struct {
	d   *core.Deps
	h   *handlers
	srv *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.ekaii.fr", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(ctx0(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	Register(mux, d)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{d: d, h: &handlers{d}, srv: srv}
}

func ctx0() context.Context { return context.Background() }

var rootN int64

func (e *env) root(t *testing.T) (string, string) {
	t.Helper()
	var id, tok string
	n := atomic.AddInt64(&rootN, 1)
	err := core.Tx(ctx0(), testPool, func(tx pgx.Tx) (err error) {
		id, tok, err = core.CreateRoot(ctx0(), tx, fmt.Sprintf("r%d-%d", n, time.Now().UnixNano()%1_000_000), "10.1.2.3")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func (e *env) urlToken(t *testing.T, parentTok string) string {
	t.Helper()
	parent, err := e.d.LookupToken(ctx0(), parentTok)
	if err != nil {
		t.Fatal(err)
	}
	var tok string
	if err := core.Tx(ctx0(), testPool, func(tx pgx.Tx) (err error) {
		_, tok, err = core.CreateSubkeyV2(ctx0(), tx, parent, core.SubkeyOpts{Name: "u", Exp: time.Now().Add(time.Hour), Class: "url"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return tok
}

func (e *env) ident(t *testing.T, tok string) *core.Ident {
	t.Helper()
	id, err := e.d.LookupToken(ctx0(), tok)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) do(t *testing.T, method, path, tok string, body string) (*http.Response, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// createHook makes one standard hook for a fresh root via the HTTP route and returns the hook id,
// the printed whsec secret and the owner token.
func (e *env) createHook(t *testing.T, format, url string, kinds []string) (string, string, string) {
	t.Helper()
	_, tok := e.root(t)
	body, _ := json.Marshal(CreateIn{URL: url, Fmt: format, Kinds: kinds})
	resp, b := e.do(t, "POST", "/v1/hook", tok, string(body))
	if resp.StatusCode != 201 {
		t.Fatalf("create hook: %d %s", resp.StatusCode, b)
	}
	id := field(b, "ok ")
	secret := field(b, "secret: ")
	if !strings.HasPrefix(secret, "whsec_") {
		t.Fatalf("secret not shown: %q", b)
	}
	return id, secret, tok
}

// field pulls the token right after a marker from a plain-text reply.
func field(body, marker string) string {
	i := strings.Index(body, marker)
	if i < 0 {
		return ""
	}
	rest := body[i+len(marker):]
	for j := 0; j < len(rest); j++ {
		if rest[j] == '\n' || rest[j] == ' ' || rest[j] == '\r' {
			return rest[:j]
		}
	}
	return rest
}

func sampleRow() events.Row {
	return events.Row{Seq: 42, At: time.Unix(1700000000, 0).UTC(), Kind: "kb", Ref: "k123", Title: "timeout on connect"}
}

// --- TestStandardWebhooksSignature ---

func TestStandardWebhooksSignature(t *testing.T) {
	secret := []byte("0123456789abcdef01234567")
	row := sampleRow()
	env := renderEnvelope("standard", "https://x.example/hook", secret, row, "https://agents.ekaii.fr", time.Unix(1700000000, 0))
	if env.Method != "POST" || env.URL != "https://x.example/hook" {
		t.Fatalf("method/url: %+v", env)
	}
	id := env.Headers["webhook-id"]
	ts := env.Headers["webhook-timestamp"]
	sig := env.Headers["webhook-signature"]
	if !strings.HasPrefix(id, "msg_") || ts == "" || !strings.HasPrefix(sig, "v1,") {
		t.Fatalf("headers: %+v", env.Headers)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(id + "." + ts + "." + env.Body))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if strings.TrimPrefix(sig, "v1,") != want {
		t.Fatalf("signature mismatch: got %s want v1,%s", sig, want)
	}
	// Body is a Standard Webhooks payload carrying the event.
	var p struct {
		Type string `json:"type"`
		Data struct {
			Ref string `json:"ref"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(env.Body), &p) != nil || p.Type != "kb" || p.Data.Ref != "k123" {
		t.Fatalf("body = %s", env.Body)
	}
}

// --- TestFormatsSlackDiscordNtfyA2A ---

func TestFormatsSlackDiscordNtfyA2A(t *testing.T) {
	secret := []byte("0123456789abcdef01234567")
	row := sampleRow()
	now := time.Unix(1700000000, 0)
	slack := renderEnvelope("slack", "https://s", secret, row, "https://agents.ekaii.fr", now)
	if v := jget(t, slack.Body, "text"); !strings.Contains(v, "k123") {
		t.Fatalf("slack text=%q", v)
	}
	disc := renderEnvelope("discord", "https://d", secret, row, "https://agents.ekaii.fr", now)
	if v := jget(t, disc.Body, "content"); !strings.Contains(v, "k123") {
		t.Fatalf("discord content=%q", v)
	}
	ntfy := renderEnvelope("ntfy", "https://n", secret, row, "https://agents.ekaii.fr", now)
	if ntfy.Headers["Title"] == "" || ntfy.Headers["Click"] == "" || !strings.HasPrefix(ntfy.Headers["content-type"], "text/plain") {
		t.Fatalf("ntfy headers=%+v", ntfy.Headers)
	}
	if !strings.Contains(ntfy.Body, "k123") {
		t.Fatalf("ntfy body=%q", ntfy.Body)
	}
	a2a := renderEnvelope("a2a", "https://a", []byte("tok-xyz"), events.Row{Seq: 7, Kind: "t", Ref: "t5", At: now}, "https://agents.ekaii.fr", now)
	if a2a.Headers["X-A2A-Notification-Token"] != "tok-xyz" {
		t.Fatalf("a2a token header=%q", a2a.Headers["X-A2A-Notification-Token"])
	}
	if jget(t, a2a.Body, "kind") != "task" {
		t.Fatalf("a2a body=%s", a2a.Body)
	}
}

func jget(t *testing.T, body, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("body not json: %s", body)
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return fmt.Sprintf("%v", m[key])
}

// appendEvent appends a public event and returns its seq.
func (e *env) appendEvent(t *testing.T, kind, ref, title string) int64 {
	t.Helper()
	if err := core.Tx(ctx0(), testPool, func(tx pgx.Tx) error {
		return core.Event(ctx0(), tx, kind, ref, "", title)
	}); err != nil {
		t.Fatal(err)
	}
	seq, _ := events.Head(ctx0(), e.d.DB)
	return seq
}

// --- TestOutPollAndAck ---

func TestOutPollAndAck(t *testing.T) {
	e := newEnv(t)
	hid, _, tok := e.createHook(t, "standard", "https://receiver.example/x", []string{"kb"})
	e.appendEvent(t, "kb", "k1", "first")
	e.appendEvent(t, "t", "9", "ignored kind")
	e.appendEvent(t, "kb", "k2", "second")
	if err := e.h.deliverPass(ctx0()); err != nil {
		t.Fatal(err)
	}
	resp, b := e.do(t, "GET", "/v1/hook/"+hid+"/out", tok, "")
	if resp.StatusCode != 200 {
		t.Fatalf("out: %d %s", resp.StatusCode, b)
	}
	var rows []outRow
	if err := json.Unmarshal([]byte(b), &rows); err != nil {
		t.Fatalf("decode out: %v %s", err, b)
	}
	if len(rows) != 2 { // only the two kb events matched
		t.Fatalf("want 2 rows, got %d: %s", len(rows), b)
	}
	upto := rows[len(rows)-1].ID
	_, ab := e.do(t, "POST", "/v1/hook/"+hid+"/ack", tok, fmt.Sprintf(`{"upto":%d}`, upto))
	if !strings.Contains(ab, "acked=2") {
		t.Fatalf("ack = %q", ab)
	}
	// After ack the poll is empty.
	_, b2 := e.do(t, "GET", "/v1/hook/"+hid+"/out", tok, "")
	if strings.TrimSpace(b2) != "null" && strings.TrimSpace(b2) != "[]" {
		t.Fatalf("expected empty poll, got %q", b2)
	}
}

// --- TestCurlLinesShellSafe + integration curl | sh against an httptest receiver ---

func TestCurlLinesShellSafe(t *testing.T) {
	// A body with a single quote must be escaped so the line stays one safe argument.
	env := Envelope{Method: "POST", URL: "https://x/y", Headers: map[string]string{"content-type": "application/json"},
		Body: `{"text":"it's a 'test'"}`}
	line := env.curlLine()
	if strings.Count(line, `'\''`) < 3 {
		t.Fatalf("single quotes not escaped: %s", line)
	}
	if !strings.Contains(line, "--data-binary") || !strings.HasPrefix(line, "curl -sS -X POST") {
		t.Fatalf("curl line shape: %s", line)
	}
}

func TestCurlDeliversVerifiableSignature(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh unavailable")
	}
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl unavailable")
	}
	e := newEnv(t)
	var gotOK atomic.Bool
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		id := r.Header.Get("webhook-id")
		ts := r.Header.Get("webhook-timestamp")
		sig := strings.TrimPrefix(r.Header.Get("webhook-signature"), "v1,")
		w.WriteHeader(204)
		// The receiver is configured out-of-band with the secret via the env below.
		key := recvKey.Load()
		if key == nil {
			return
		}
		mac := hmac.New(sha256.New, *key)
		mac.Write([]byte(id + "." + ts + "." + string(body)))
		if hmac.Equal([]byte(base64.StdEncoding.EncodeToString(mac.Sum(nil))), []byte(sig)) {
			gotOK.Store(true)
		}
	}))
	t.Cleanup(recv.Close)

	hid, secret, tok := e.createHook(t, "standard", recv.URL, []string{"kb"})
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		t.Fatal(err)
	}
	recvKey.Store(&raw)
	e.appendEvent(t, "kb", "k9", "release ready")
	if err := e.h.deliverPass(ctx0()); err != nil {
		t.Fatal(err)
	}
	_, curlText := e.do(t, "GET", "/v1/hook/"+hid+"/out?f=curl", tok, "")
	if !strings.HasPrefix(strings.TrimSpace(curlText), "curl ") {
		t.Fatalf("curl output: %q", curlText)
	}
	cmd := exec.Command("sh", "-c", curlText)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sh curl: %v %s", err, out)
	}
	if !gotOK.Load() {
		t.Fatal("receiver did not verify the webhook-signature")
	}
}

var recvKey atomic.Pointer[[]byte]

// --- TestUrlTokenFeedEnvelopesOnly ---

func TestUrlTokenFeedEnvelopesOnly(t *testing.T) {
	e := newEnv(t)
	hid, _, tok := e.createHook(t, "slack", "https://feed.example/x", []string{"kb"})
	e.appendEvent(t, "kb", "k7", "feed event")
	if err := e.h.deliverPass(ctx0()); err != nil {
		t.Fatal(err)
	}
	ut := e.urlToken(t, tok)
	items, err := e.h.feed(ctx0(), ut, 20)
	if err != nil {
		t.Fatalf("feed: %v", err)
	}
	if len(items) == 0 {
		t.Fatal("feed empty")
	}
	for _, it := range items {
		if strings.Contains(strings.ToLower(it.Summary), "mail") && strings.Contains(it.Summary, "@") {
			t.Fatalf("feed leaked mail: %q", it.Summary)
		}
	}
	_ = hid
	// A non-url token (the full owner token) is rejected as not found.
	if _, err := e.h.feed(ctx0(), tok, 20); err == nil {
		t.Fatal("full token accepted by url-token feed")
	}
	// A garbage token is the same not found.
	if _, err := e.h.feed(ctx0(), "cx_notarealtoken", 20); err == nil {
		t.Fatal("garbage token accepted")
	}
}

// --- TestUrlNeverFetchedAndMasked ---

func TestUrlNeverFetchedAndMasked(t *testing.T) {
	e := newEnv(t)
	var fetched atomic.Bool
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fetched.Store(true); w.WriteHeader(204) }))
	t.Cleanup(recv.Close)
	secretURL := recv.URL + "/secret/path?token=abc"
	hid, _, tok := e.createHook(t, "standard", secretURL, []string{"kb"})
	e.appendEvent(t, "kb", "k1", "x")
	if err := e.h.deliverPass(ctx0()); err != nil {
		t.Fatal(err)
	}
	// The gateway never fetches the url: the receiver was never hit by rendering/polling.
	_, _ = e.do(t, "GET", "/v1/hook/"+hid+"/out", tok, "")
	if fetched.Load() {
		t.Fatal("gateway fetched the hook url")
	}
	// The list masks the url (path and query hidden).
	_, lb := e.do(t, "GET", "/v1/hook", tok, "")
	if strings.Contains(lb, "/secret/path") || strings.Contains(lb, "token=abc") {
		t.Fatalf("list leaked the url: %s", lb)
	}
	if !strings.Contains(lb, "…") {
		t.Fatalf("url not masked: %s", lb)
	}
	// But the owner's own out row carries the full url (to deliver with its own egress).
	_, ob := e.do(t, "GET", "/v1/hook/"+hid+"/out", tok, "")
	if !strings.Contains(ob, "/secret/path") {
		t.Fatalf("out row missing full url: %s", ob)
	}
}

// --- Inbound helpers ---

func (e *env) createInHook(t *testing.T, kind, sink, target string) (string, string, string) {
	t.Helper()
	_, tok := e.root(t)
	body, _ := json.Marshal(InCreateIn{Kind: kind, Sink: sink, Target: target})
	resp, b := e.do(t, "POST", "/v1/inhook", tok, string(body))
	if resp.StatusCode != 201 {
		t.Fatalf("create inhook: %d %s", resp.StatusCode, b)
	}
	id := field(b, "ok ")
	secret := field(b, "secret: ")
	if id == "" || secret == "" {
		t.Fatalf("inhook reply: %s", b)
	}
	return id, secret, tok
}

func ghSig(secretB64url string, body []byte) string {
	key, _ := base64.RawURLEncoding.DecodeString(secretB64url)
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (e *env) postIn(t *testing.T, id string, headers map[string]string, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/in/"+id, strings.NewReader(string(body)))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp
}

// --- TestInboundSignatureConstantTimeAnd404 ---

func TestInboundSignatureConstantTimeAnd404(t *testing.T) {
	e := newEnv(t)
	id, secret, _ := e.createInHook(t, "github", "ps", "g:cisig")
	body := []byte(`{"zen":"x"}`)
	// Unknown id -> 404.
	if r := e.postIn(t, "inotarealid0000000000000000", map[string]string{"X-GitHub-Event": "ping"}, body); r.StatusCode != 404 {
		t.Fatalf("unknown id status %d", r.StatusCode)
	}
	// Bad signature -> the SAME 404.
	bad := e.postIn(t, id, map[string]string{"X-GitHub-Event": "ping", "X-Hub-Signature-256": "sha256=deadbeef"}, body)
	if bad.StatusCode != 404 {
		t.Fatalf("bad signature status %d (want 404)", bad.StatusCode)
	}
	// Valid signature -> 204.
	ok := e.postIn(t, id, map[string]string{"X-GitHub-Event": "ping", "X-Hub-Signature-256": ghSig(secret, body), "X-GitHub-Delivery": "d-ok-1"}, body)
	if ok.StatusCode != 204 {
		t.Fatalf("valid signature status %d (want 204)", ok.StatusCode)
	}
}

// --- TestInboundExtractorsAndSinks ---

func TestInboundExtractorsAndSinks(t *testing.T) {
	rel := []byte(`{"action":"published","repository":{"full_name":"a/b"},"release":{"tag_name":"v1.2.0","html_url":"https://h/r"}}`)
	if got := extract("github", "release", rel); got != "release published a/b v1.2.0 https://h/r" {
		t.Fatalf("release: %q", got)
	}
	push := []byte(`{"ref":"refs/heads/main","after":"abcdef1234567","commits":[{},{}]}`)
	if got := extract("github", "push", push); got != "push refs/heads/main abcdef1 2" {
		t.Fatalf("push: %q", got)
	}
	wf := []byte(`{"workflow_run":{"conclusion":"success","name":"CI"}}`)
	if got := extract("github", "workflow_run", wf); got != "workflow_run success CI" {
		t.Fatalf("workflow_run: %q", got)
	}
	iss := []byte(`{"action":"opened","issue":{"number":7,"title":"bug"}}`)
	if got := extract("github", "issues", iss); got != "issues opened #7 bug" {
		t.Fatalf("issues: %q", got)
	}
	gen := []byte(`{"text":"hello world"}`)
	if got := extract("generic", "deploy", gen); got != "deploy hello world" {
		t.Fatalf("generic: %q", got)
	}

	// And the sink receives the extracted, scrubbed line.
	e := newEnv(t)
	rootID, tok := e.root(t)
	topic := "a:" + rootID + ".ci"
	body, _ := json.Marshal(InCreateIn{Kind: "github", Sink: "ps", Target: topic})
	resp, b := e.do(t, "POST", "/v1/inhook", tok, string(body))
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	id := field(b, "ok ")
	secret := field(b, "secret: ")
	payload := []byte(`{"action":"published","repository":{"full_name":"ekaii/commons"},"release":{"tag_name":"v2","html_url":"https://x/y"}}`)
	r := e.postIn(t, id, map[string]string{"X-GitHub-Event": "release", "X-Hub-Signature-256": ghSig(secret, payload), "X-GitHub-Delivery": "rel-1"}, payload)
	if r.StatusCode != 204 {
		t.Fatalf("deliver status %d", r.StatusCode)
	}
	msgs, err := swarm.Pull(ctx0(), e.d.DB, topic, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || !strings.Contains(msgs[0].Text, "release published ekaii/commons v2") {
		t.Fatalf("published msgs: %+v", msgs)
	}
}

// --- TestInboundReplayAndRates ---

func TestInboundReplayAndRates(t *testing.T) {
	e := newEnv(t)
	old := InPerHour
	InPerHour = 2
	t.Cleanup(func() { InPerHour = old })
	rootID, tok := e.root(t)
	topic := "a:" + rootID + ".ci"
	body, _ := json.Marshal(InCreateIn{Kind: "generic", Sink: "ps", Target: topic})
	resp, b := e.do(t, "POST", "/v1/inhook", tok, string(body))
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %s", resp.StatusCode, b)
	}
	id := field(b, "ok ")
	secret := field(b, "secret: ")
	send := func(delivery, text string) int {
		payload := []byte(`{"text":"` + text + `"}`)
		return e.postIn(t, id, map[string]string{"X-Hook-Event": "ev", "X-Hook-Signature": ghSig(secret, payload), "X-Hook-Delivery": delivery}, payload).StatusCode
	}
	if s := send("d1", "one"); s != 204 {
		t.Fatalf("first %d", s)
	}
	// Same delivery id -> replayed, no second publish.
	if s := send("d1", "one"); s != 204 {
		t.Fatalf("replay %d", s)
	}
	msgs, _ := swarm.Pull(ctx0(), e.d.DB, topic, 0, 10)
	if len(msgs) != 1 {
		t.Fatalf("replay duplicated: %d msgs", len(msgs))
	}
	// New deliveries until the hourly cap, then dropped (still 204, no publish).
	send("d2", "two")
	send("d3", "three") // this one is over InPerHour=2
	msgs, _ = swarm.Pull(ctx0(), e.d.DB, topic, 0, 10)
	if len(msgs) != 2 {
		t.Fatalf("rate cap not enforced: %d msgs", len(msgs))
	}
}

// --- TestDisableAfterBadSignatures ---

func TestDisableAfterBadSignatures(t *testing.T) {
	e := newEnv(t)
	old := BadDisable
	BadDisable = 3
	t.Cleanup(func() { BadDisable = old })
	id, secret, _ := e.createInHook(t, "github", "mb", "")
	body := []byte(`{"zen":"x"}`)
	for i := 0; i < 3; i++ {
		if r := e.postIn(t, id, map[string]string{"X-GitHub-Event": "ping", "X-Hub-Signature-256": "sha256=bad"}, body); r.StatusCode != 404 {
			t.Fatalf("bad %d status %d", i, r.StatusCode)
		}
	}
	// Now disabled: even a VALID signature is the same 404.
	good := e.postIn(t, id, map[string]string{"X-GitHub-Event": "ping", "X-Hub-Signature-256": ghSig(secret, body), "X-GitHub-Delivery": "later"}, body)
	if good.StatusCode != 404 {
		t.Fatalf("disabled hook should 404 even with a valid signature, got %d", good.StatusCode)
	}
	var disabled bool
	if err := e.d.DB.QueryRow(ctx0(), `SELECT disabled FROM in_hooks WHERE id = $1`, id).Scan(&disabled); err != nil {
		t.Fatal(err)
	}
	if !disabled {
		t.Fatal("hook not disabled after bad signatures")
	}
}
