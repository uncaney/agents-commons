package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBotKeysKindFetchAndAck(t *testing.T) {
	const dir = `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}`
	var mu sync.Mutex
	mode := "ok"
	var calls []recorded
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, recorded{host: r.Header.Get("X-Egress-Host"), method: r.Method, path: r.URL.Path, ctype: r.Header.Get("Accept")})
		m := mode
		mu.Unlock()
		if r.Header.Get("X-Egress-Host") != "chatgpt.com" || r.URL.Path != botDirPath {
			w.WriteHeader(404)
			return
		}
		switch m {
		case "ok":
			w.Header().Set("Content-Type", "application/http-message-signatures-directory+json")
			io.WriteString(w, dir)
		case "nokeys":
			io.WriteString(w, `{"purpose":"rag"}`)
		case "html":
			io.WriteString(w, "<html>busy</html>")
		case "huge":
			io.WriteString(w, `{"keys":[`+strings.Repeat(" ", botDirMax)+`]}`)
		case "gone":
			w.WriteHeader(410)
		default:
			w.WriteHeader(500)
			io.WriteString(w, "upstream sad")
		}
	}))
	defer fake.Close()
	e := testEnv(t, fake).e
	run := func(host string) (botResult, error) {
		b, _ := json.Marshal(map[string]string{"host": host})
		raw, err := runBotkeys(context.Background(), e, &Job{ID: 1, Kind: "botkeys", Payload: b})
		var r botResult
		if err == nil {
			if uerr := json.Unmarshal(raw, &r); uerr != nil {
				t.Fatal(uerr)
			}
		}
		return r, err
	}
	r, err := run("chatgpt.com")
	if err != nil || r.Host != "chatgpt.com" || r.Status != 200 || r.Err != "" || string(r.JWKS) != dir || r.Fetched == "" {
		t.Fatalf("ok: %+v %v", r, err)
	}
	mu.Lock()
	if len(calls) != 1 || calls[0].method != "GET" || calls[0].path != botDirPath || !strings.Contains(calls[0].ctype, "http-message-signatures-directory+json") {
		t.Fatalf("request: %+v", calls)
	}
	mu.Unlock()
	// The origin form of the payload host is accepted; anything outside the compiled-in list fails
	// the row before any request.
	if r, err := run(`https://chatgpt.com`); err != nil || r.Host != "chatgpt.com" {
		t.Fatalf("origin form: %+v %v", r, err)
	}
	for _, bad := range []string{"evil.example", "chatgpt.com.evil.example", "", "https://chatgpt.com/x", "10.0.0.1"} {
		mu.Lock()
		n := len(calls)
		mu.Unlock()
		if _, err := run(bad); err == nil || !strings.Contains(err.Error(), "compiled in") {
			t.Fatalf("host %q: %v", bad, err)
		}
		mu.Lock()
		if len(calls) != n {
			t.Fatalf("host %q was fetched", bad)
		}
		mu.Unlock()
	}
	if _, err := runBotkeys(context.Background(), e, &Job{ID: 2, Kind: "botkeys", Payload: json.RawMessage(`{"host":1}`)}); err == nil {
		t.Fatal("bad payload accepted")
	}
	// Definitive bad answers are acked with err (the gateway marks ok=false); 404 for a listed host too.
	for _, c := range []struct{ mode, want string }{{"nokeys", "malformed directory"}, {"html", "malformed directory"}, {"huge", "too large"}, {"gone", "not found"}} {
		mu.Lock()
		mode = c.mode
		mu.Unlock()
		r, err := run("chatgpt.com")
		if err != nil || r.Err != c.want || len(r.JWKS) != 0 || r.Host != "chatgpt.com" {
			t.Fatalf("%s: %+v %v", c.mode, r, err)
		}
	}
	if r, err := run("openai.com"); err != nil || r.Err != "not found" || r.Status != 404 {
		t.Fatalf("404: %+v %v", r, err)
	}
	// Transient upstream failures fail the row (retry with backoff), never an ack.
	mu.Lock()
	mode = "500"
	mu.Unlock()
	if _, err := run("chatgpt.com"); err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("500: %v", err)
	}

	// Full loop against the fake gateway: poll -> fetch -> ack carries the directory; a 500 -> fail.
	mu.Lock()
	mode = "ok"
	mu.Unlock()
	fi := newFakeInternal(t)
	k, ok := Lookup("botkeys")
	if !ok || len(k.Hosts) != 2 || k.Run == nil {
		t.Fatalf("kind: %+v", k)
	}
	cfg := config{InternalURL: fi.srv.URL, GatewayURL: fi.srv.URL, PublicURL: "https://agents.example", Token: testToken, SecretsDir: t.TempDir()}
	env := newEnv(cfg, newClient(rewriteTransport{base: mustURL(fake.URL), next: http.DefaultTransport}), discard)
	c := &courier{e: env, kinds: []*Kind{k}, last: map[string]time.Time{}, sleep: func(ctx context.Context, d time.Duration) bool { return ctx.Err() == nil }}
	fi.mu.Lock()
	fi.queue = append(fi.queue, Job{ID: 41, Kind: "botkeys", Payload: json.RawMessage(`{"host":"chatgpt.com"}`), Attempts: 1},
		Job{ID: 42, Kind: "botkeys", Payload: json.RawMessage(`{"host":"openai.com"}`), Attempts: 1})
	fi.mu.Unlock()
	for i := 0; i < 2; i++ {
		if n, err := c.cycle(context.Background()); err != nil || n != 1 {
			t.Fatalf("cycle %d: %d %v", i, n, err)
		}
	}
	fi.mu.Lock()
	acked, missing := fi.acks[41], fi.acks[42]
	kinds := fi.kinds
	fi.mu.Unlock()
	var got, got2 botResult
	if json.Unmarshal(acked, &got) != nil || string(got.JWKS) != dir || got.Host != "chatgpt.com" {
		t.Fatalf("ack 41: %s", acked)
	}
	if json.Unmarshal(missing, &got2) != nil || got2.Err != "not found" || got2.Host != "openai.com" {
		t.Fatalf("ack 42: %s", missing)
	}
	if len(kinds) == 0 || kinds[0] != "botkeys" {
		t.Fatalf("polled kinds %v", kinds)
	}
	mu.Lock()
	mode = "500"
	mu.Unlock()
	fi.mu.Lock()
	fi.queue = append(fi.queue, Job{ID: 43, Kind: "botkeys", Payload: json.RawMessage(`{"host":"chatgpt.com"}`), Attempts: 2})
	fi.mu.Unlock()
	if n, err := c.cycle(context.Background()); err != nil || n != 1 {
		t.Fatalf("cycle fail: %d %v", n, err)
	}
	fi.mu.Lock()
	defer fi.mu.Unlock()
	if _, acked := fi.acks[43]; acked || !strings.Contains(fi.fails[43], "status 500") {
		t.Fatalf("500 handling: acks=%v fails=%v", fi.acks, fi.fails)
	}
}
