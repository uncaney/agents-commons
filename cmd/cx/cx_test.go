package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"ekaii.fr/commons/internal/pow"
)

const testBits = 8

// fakeServer is a minimal stand-in for the gateway covering what the CLI tests need.
type fakeServer struct {
	mu        sync.Mutex
	secret    []byte
	blobs     map[string][]byte
	jobPolls  int
	jobOut    string
	auths     []string // Authorization headers seen on /mcp
	mcpBodies []string
	lastQuery string
}

func newFake(t *testing.T) (*fakeServer, *httptest.Server) {
	t.Helper()
	f := &fakeServer{secret: []byte("test-secret"), blobs: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/challenge", func(w http.ResponseWriter, r *http.Request) {
		c := pow.Mint(f.secret, time.Now().Add(10*time.Minute))
		json.NewEncoder(w).Encode(map[string]any{"c": c, "bits": testBits, "exp": time.Now().Add(10 * time.Minute).Unix()})
	})
	mux.HandleFunc("POST /v1/register", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ C, Nonce, Name string }
		json.NewDecoder(r.Body).Decode(&in)
		if _, err := pow.Verify(f.secret, in.C, time.Now()); err != nil || !pow.Check(in.C, in.Nonce, testBits) {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"err": "pow", "msg": "bad proof of work"})
			return
		}
		if in.Name == "" {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"err": "bad", "msg": "name"})
			return
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(map[string]any{"id": "a" + in.Name[:1] + "bcdefg", "token": "cx_" + strings.Repeat("x", 43), "credits": 100})
	})
	mux.HandleFunc("GET /v1/kb", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.lastQuery = r.URL.RawQuery
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			io.WriteString(w, "err auth invalid token\n")
			return
		}
		io.WriteString(w, "k1111111 0.92 fix Foo bar baz\nk2222222 0.40 note Other\n")
	})
	mux.HandleFunc("POST /v1/b", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h := sha256hex(b)
		f.mu.Lock()
		f.blobs[h] = b
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"hash": h, "size": len(b)})
	})
	mux.HandleFunc("GET /v1/b/{hash}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		b, ok := f.blobs[r.PathValue("hash")]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, "err notfound not found\n")
			return
		}
		w.Write(b)
	})
	mux.HandleFunc("POST /v1/j", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Wasm, In string
			Ms, Mb   int
		}
		json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		_, okW := f.blobs[in.Wasm]
		_, okI := f.blobs[in.In]
		f.mu.Unlock()
		if !okW || !okI || in.Ms != 2000 {
			w.WriteHeader(400)
			json.NewEncoder(w).Encode(map[string]string{"err": "bad", "msg": "blobs or ms"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "jabcdefg", "ids": []string{"jabcdefg"}})
	})
	mux.HandleFunc("GET /v1/j/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.jobPolls++
		n := f.jobPolls
		out := f.jobOut
		f.mu.Unlock()
		if r.URL.Query().Get("wait") != "85" {
			w.WriteHeader(400)
			io.WriteString(w, `{"err":"bad","msg":"wait"}`)
			return
		}
		if n == 1 {
			json.NewEncoder(w).Encode(map[string]any{"id": "jabcdefg", "status": "running"})
			return
		}
		if out == "" {
			json.NewEncoder(w).Encode(map[string]any{"id": "jabcdefg", "status": "failed", "reason": "noconsensus"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "jabcdefg", "status": "done", "out": out, "ms": 12, "code": 0})
	})
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		f.mcpBodies = append(f.mcpBodies, string(b))
		f.mu.Unlock()
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		json.Unmarshal(b, &m)
		if len(m.ID) == 0 {
			w.WriteHeader(202)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc": "2.0", "id": `+string(m.ID)+`, "result": {"echo": "`+m.Method+`"}}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return f, srv
}

func testCLI(t *testing.T, srv *httptest.Server, token string) (*cli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	cfg := t.TempDir()
	env := map[string]string{"CX_URL": srv.URL, "XDG_CONFIG_HOME": cfg, "CX_TOKEN": token}
	c := newCLI(func(k string) string { return env[k] })
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	c.stdout, c.stderr = out, errb
	return c, out, errb
}

func TestJoin(t *testing.T) {
	_, srv := newFake(t)
	c, out, _ := testCLI(t, srv, "")
	if err := c.run(context.Background(), []string{"join", "bot"}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "id=abbcdefg\n" {
		t.Fatalf("stdout %q", got)
	}
	p := c.tokenPath()
	if !strings.HasPrefix(p, c.getenv("XDG_CONFIG_HOME")) {
		t.Fatalf("token path %s", p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != "cx_"+strings.Repeat("x", 43) {
		t.Fatalf("token file %q", b)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("token perm %o", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Dir(p))
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("dir perm %o", dst.Mode().Perm())
	}
	// a fresh CLI without CX_TOKEN picks the saved token up
	env := map[string]string{"CX_URL": srv.URL, "XDG_CONFIG_HOME": c.getenv("XDG_CONFIG_HOME")}
	c2 := newCLI(func(k string) string { return env[k] })
	if c2.token != c.token {
		t.Fatal("saved token not loaded")
	}
}

func TestSolveParallel(t *testing.T) {
	c := pow.Mint([]byte("k"), time.Now().Add(time.Minute))
	n := solve(context.Background(), c, 12)
	if !pow.Check(c, n, 12) {
		t.Fatalf("bad nonce %q", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := solve(ctx, c, 60); got != "" {
		t.Fatalf("cancelled solve returned %q", got)
	}
}

func TestSearch(t *testing.T) {
	f, srv := newFake(t)
	c, out, _ := testCLI(t, srv, "tok")
	if err := c.run(context.Background(), []string{"s", "foo", "bar", "-k", "3", "-kind", "fix"}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "k1111111 0.92 fix Foo bar baz\nk2222222 0.40 note Other\n" {
		t.Fatalf("stdout %q", got)
	}
	if f.lastQuery != "k=3&kind=fix&q=foo+bar" {
		t.Fatalf("query %q", f.lastQuery)
	}
	c, _, _ = testCLI(t, srv, "bad")
	err := c.run(context.Background(), []string{"s", "x"})
	var ee *exitErr
	if !asExit(err, &ee) || ee.code != 1 || ee.msg != "err auth invalid token" {
		t.Fatalf("want exit 1 with server err line, got %v", err)
	}
}

func asExit(err error, ee **exitErr) bool {
	e, ok := err.(*exitErr)
	if ok {
		*ee = e
	}
	return ok
}

func TestRunHappyPath(t *testing.T) {
	f, srv := newFake(t)
	dir := t.TempDir()
	wasm := filepath.Join(dir, "m.wasm")
	os.WriteFile(wasm, []byte("\x00asm fake module"), 0o644)
	output := []byte("hello from job\n")
	f.jobOut = sha256hex(output)
	f.blobs[f.jobOut] = output

	c, out, errb := testCLI(t, srv, "tok")
	c.stdin = strings.NewReader("input bytes")
	if err := c.run(context.Background(), []string{"run", wasm, "-", "--ms", "2000"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), output) {
		t.Fatalf("stdout %q", out.Bytes())
	}
	if _, ok := f.blobs[sha256hex([]byte("input bytes"))]; !ok {
		t.Fatal("input blob not uploaded")
	}
	if f.jobPolls != 2 {
		t.Fatalf("polls %d", f.jobPolls)
	}
	if !strings.Contains(errb.String(), "job jabcdefg") {
		t.Fatalf("stderr %q", errb.String())
	}

	// failed job -> exit 3 with reason
	f.jobPolls, f.jobOut = 0, ""
	c, out, _ = testCLI(t, srv, "tok")
	err := c.run(context.Background(), []string{"run", wasm, "--ms", "2000"})
	var ee *exitErr
	if !asExit(err, &ee) || ee.code != 3 || ee.msg != "err failed noconsensus" {
		t.Fatalf("want exit 3, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("stdout should be empty, got %q", out.String())
	}

	// tampered blob is rejected
	f.blobs["0000000000000000000000000000000000000000000000000000000000000000"] = []byte("x")
	c, _, _ = testCLI(t, srv, "tok")
	err = c.run(context.Background(), []string{"get", strings.Repeat("0", 64)})
	if !asExit(err, &ee) || !strings.Contains(ee.msg, "integrity") {
		t.Fatalf("want integrity error, got %v", err)
	}
}

func TestMCPProxy(t *testing.T) {
	f, srv := newFake(t)
	c, out, _ := testCLI(t, srv, "tok")
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		``,
		`{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"cx","arguments":{"op":"s","a":{"q":"x"}}}}`,
	}, "\n") + "\n"
	pr, pw := io.Pipe()
	c.stdin = pr
	done := make(chan error, 1)
	go func() { done <- c.run(context.Background(), []string{"mcp"}) }()
	io.WriteString(pw, in)
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 reply lines, got %d: %q", len(lines), out.String())
	}
	if lines[0] != `{"jsonrpc":"2.0","id":1,"result":{"echo":"initialize"}}` {
		t.Fatalf("line0 %q", lines[0])
	}
	if lines[1] != `{"jsonrpc":"2.0","id":"abc","result":{"echo":"tools/call"}}` {
		t.Fatalf("line1 %q", lines[1])
	}
	if len(f.auths) != 3 {
		t.Fatalf("server saw %d messages", len(f.auths))
	}
	for _, a := range f.auths {
		if a != "Bearer tok" {
			t.Fatalf("auth header %q", a)
		}
	}
	if !strings.Contains(f.mcpBodies[1], "notifications/initialized") {
		t.Fatalf("notification not forwarded: %q", f.mcpBodies[1])
	}
}

func TestMCPJoinIntercept(t *testing.T) {
	f, srv := newFake(t)
	c, out, _ := testCLI(t, srv, "")
	c.stdin = strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"cx","arguments":{"op":"join","a":{"name":"zed"}}}}` + "\n" +
		`{"jsonrpc":"2.0","id":8,"method":"ping"}` + "\n")
	if err := c.run(context.Background(), []string{"mcp"}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines %q", out.String())
	}
	var r struct {
		ID     int `json:"id"`
		Result struct {
			Content []struct{ Type, Text string } `json:"content"`
			IsError bool                          `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &r); err != nil {
		t.Fatal(err)
	}
	if r.ID != 7 || r.Result.IsError || len(r.Result.Content) != 1 || r.Result.Content[0].Text != "id=azbcdefg saved" {
		t.Fatalf("join result %q", lines[0])
	}
	if b, err := os.ReadFile(c.tokenPath()); err != nil || !strings.HasPrefix(string(b), "cx_") {
		t.Fatalf("token not saved: %v %q", err, b)
	}
	// the join never reached the server; the following ping used the fresh token
	if len(f.auths) != 1 || f.auths[0] != "Bearer cx_"+strings.Repeat("x", 43) {
		t.Fatalf("auths %v", f.auths)
	}
}

// A prompt-injected "join" over MCP must never silently replace the saved identity.
func TestMCPJoinRefusesOverwrite(t *testing.T) {
	f, srv := newFake(t)
	c, out, _ := testCLI(t, srv, "")
	// Token only on disk (no CX_TOKEN, nothing in memory yet): still refused.
	if err := os.MkdirAll(filepath.Dir(c.tokenPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.tokenPath(), []byte("cx_old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.token = ""
	join := func(a string) (string, bool) {
		t.Helper()
		out.Reset()
		c.stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cx","arguments":{"op":"join","a":` + a + `}}}` + "\n")
		if err := c.run(context.Background(), []string{"mcp"}); err != nil {
			t.Fatal(err)
		}
		var r struct {
			Result struct {
				Content []struct{ Text string } `json:"content"`
				IsError bool                    `json:"isError"`
			} `json:"result"`
		}
		if err := json.Unmarshal(out.Bytes(), &r); err != nil || len(r.Result.Content) != 1 {
			t.Fatalf("reply %q (%v)", out.String(), err)
		}
		return r.Result.Content[0].Text, r.Result.IsError
	}
	txt, isErr := join(`{"name":"zed"}`)
	if !isErr || !strings.HasPrefix(txt, "err exists ") {
		t.Fatalf("join with existing token file: %q isErr=%v", txt, isErr)
	}
	if b, _ := os.ReadFile(c.tokenPath()); strings.TrimSpace(string(b)) != "cx_old" {
		t.Fatalf("token file overwritten: %q", b)
	}
	if len(f.auths) != 0 {
		t.Fatalf("join reached the server: %v", f.auths)
	}
	// Token in memory (CX_TOKEN): refused too; force:false is not force.
	c.token = "cx_env"
	if txt, isErr := join(`{"name":"zed","force":false}`); !isErr || !strings.HasPrefix(txt, "err exists ") {
		t.Fatalf("join with env token: %q isErr=%v", txt, isErr)
	}
	if c.token != "cx_env" {
		t.Fatalf("in-memory token replaced: %q", c.token)
	}
	// Explicit force replaces it.
	txt, isErr = join(`{"name":"zed","force":true}`)
	if isErr || txt != "id=azbcdefg saved" {
		t.Fatalf("forced join: %q isErr=%v", txt, isErr)
	}
	if b, _ := os.ReadFile(c.tokenPath()); strings.TrimSpace(string(b)) != "cx_"+strings.Repeat("x", 43) || c.token != "cx_"+strings.Repeat("x", 43) {
		t.Fatalf("forced join did not save: file=%q mem=%q", b, c.token)
	}
}

func TestParseArgs(t *testing.T) {
	var k, tags string
	var force bool
	pos, err := parseArgs([]string{"fix", "--title=T", "-k", "3", "--force", "x", "--tags", "a,b", "--", "-y"},
		map[string]*string{"title": &k, "k": &k, "tags": &tags}, map[string]*bool{"force": &force})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(pos, "|") != "fix|x|-y" || k != "3" || tags != "a,b" || !force {
		t.Fatalf("pos=%v k=%q tags=%q force=%v", pos, k, tags, force)
	}
	if _, err := parseArgs([]string{"--nope"}, nil, nil); err == nil {
		t.Fatal("unknown flag accepted")
	}
}
