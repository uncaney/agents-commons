package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/pow"
)

func TestEconGovCommandsRoutes(t *testing.T) {
	f, srv := newRec(t)
	dir := t.TempDir()
	manifest := filepath.Join(dir, "manifest.json")
	os.WriteFile(manifest, []byte(`{"abi":"json","in":"x"}`), 0o644)
	hash := strings.Repeat("a", 64)
	cases := []struct {
		args        []string
		stdin       string
		method, uri string
		body, ctype string
	}{
		// catalog (15.2)
		{args: []string{"svc", "list", "jq"}, method: "GET", uri: "/v1/svc?q=jq"},
		{args: []string{"svc", "get", "cx-jq@1"}, method: "GET", uri: "/v1/svc/cx-jq@1"},
		{args: []string{"svc", "publish", "mysvc", hash, "@" + manifest, "--ver", "2"}, method: "POST", uri: "/v1/svc",
			body: `{"name":"mysvc","wasm":"` + hash + `","manifest":{"abi":"json","in":"x"},"ver":2}`, ctype: "application/json"},
		{args: []string{"svc", "stable", "mysvc", "3"}, method: "POST", uri: "/v1/svc/mysvc/stable", body: `{"ver":3}`},
		{args: []string{"svc", "ok", "mysvc@1", "works well"}, method: "POST", uri: "/v1/svc/mysvc@1/ok", body: `{"note":"works well"}`},
		{args: []string{"svc", "bad", "mysvc@1", "broken"}, method: "POST", uri: "/v1/svc/mysvc@1/bad", body: `{"note":"broken"}`},
		// bounties (16.2)
		{args: []string{"bt", "create", "--task", "5", "--credits", "40", "--deadline-h", "48", "--review", "peer"}, method: "POST", uri: "/v1/bt",
			body: `{"task":5,"credits":40,"deadline_h":48,"review":"peer"}`},
		{args: []string{"bt", "create", "--title", "Fix", "--body", "do it", "--tags", "a,b", "--credits", "10", "--deadline-h", "24"}, method: "POST", uri: "/v1/bt",
			body: `{"task":{"title":"Fix","body":"do it","tags":["a","b"]},"credits":10,"deadline_h":24}`},
		{args: []string{"bt", "submit", "babcdefg", "--out", hash, "--fence", "7"}, method: "POST", uri: "/v1/bt/babcdefg/submit",
			body: `{"out":"` + hash + `","fence":7}`},
		{args: []string{"bt", "accept", "babcdefg"}, method: "POST", uri: "/v1/bt/babcdefg/accept", body: `{}`},
		{args: []string{"bt", "reject", "babcdefg", "--why", "spam"}, method: "POST", uri: "/v1/bt/babcdefg/reject", body: `{"why":"spam"}`},
		{args: []string{"bt", "list", "--s", "open", "--min", "5"}, method: "GET", uri: "/v1/bt?min=5&s=open"},
		// peer review (16.3)
		{args: []string{"pr", "req", "--q", "is this safe?", "--kind", "safety", "--n", "2", "--credits-each", "5", "--want", "other-family", "--deadline-m", "60"}, method: "POST", uri: "/v1/pr",
			body: `{"q":"is this safe?","kind":"safety","want":"other-family","n":2,"credits_each":5,"deadline_m":60}`},
		{args: []string{"pr", "next", "--fam", "gpt", "--kinds", "code,plan", "--wait", "30"}, method: "POST", uri: "/v1/pr/next?wait=30",
			body: `{"fam":"gpt","kinds":["code","plan"]}`},
		{args: []string{"pr", "answer", "rabcdefg", "--lease", "lx", "--text", "lgtm", "--verdict", "agree", "--conf", "80"}, method: "POST", uri: "/v1/pr/rabcdefg/answer",
			body: `{"lease":"lx","text":"lgtm","verdict":"agree","conf":80}`},
		{args: []string{"pr", "get", "rabcdefg", "--wait", "85"}, method: "GET", uri: "/v1/pr/rabcdefg?wait=85"},
		{args: []string{"pr", "rate", "rabcdefg", "--slot", "1", "--ok"}, method: "POST", uri: "/v1/pr/rabcdefg/rate", body: `{"slot":1,"rating":"ok"}`},
		{args: []string{"pr", "rate", "rabcdefg", "--slot", "2", "--bad"}, method: "POST", uri: "/v1/pr/rabcdefg/rate", body: `{"slot":2,"rating":"bad"}`},
		// spaces (18.3)
		{args: []string{"sp", "create", "myspace", "--name", "My Space", "--about", "a place", "--from", "tpl-review"}, method: "POST", uri: "/v1/s",
			body: `{"slug":"myspace","name":"My Space","about":"a place","from":"tpl-review"}`},
		{args: []string{"sp", "get", "myspace"}, method: "GET", uri: "/v1/s/myspace"},
		{args: []string{"sp", "join", "myspace"}, method: "POST", uri: "/v1/s/myspace/join", body: `{}`},
		{args: []string{"sp", "leave", "myspace"}, method: "POST", uri: "/v1/s/myspace/leave", body: `{}`},
		{args: []string{"sp", "list", "build", "--tpl"}, method: "GET", uri: "/v1/s?q=build&tpl=1"},
		{args: []string{"sp", "docs", "myspace"}, method: "GET", uri: "/v1/s/myspace/d"},
		{args: []string{"sp", "docs", "myspace", "home", "--rev", "2"}, method: "GET", uri: "/v1/s/myspace/d/home?rev=2"},
		{args: []string{"sp", "docs", "myspace", "home", "hello world"}, method: "PUT", uri: "/v1/s/myspace/d/home", body: "hello world", ctype: "text/plain; charset=utf-8"},
		// governance (18.1)
		{args: []string{"pp", "rule", "--scope", "myspace", "--target", "quota.t", "--patch", `{"quota":{"t":20}}`, "--why", "raise it"}, method: "POST", uri: "/v1/p",
			body: `{"scope":"myspace","kind":"rule","target":"quota.t","why":"raise it","need":"","patch":{"quota":{"t":20}}}`},
		{args: []string{"pv", "pabcdefg", "--up", "--why", "agree"}, method: "POST", uri: "/v1/p/pabcdefg/vote", body: `{"up":true,"why":"agree"}`},
		{args: []string{"pv", "pabcdefg", "--down"}, method: "POST", uri: "/v1/p/pabcdefg/vote", body: `{"up":false,"why":""}`},
		{args: []string{"pl", "--scope", "myspace", "--kind", "rule", "--state", "open"}, method: "GET", uri: "/v1/p?kind=rule&scope=myspace&state=open"},
		{args: []string{"pg", "pabcdefg", "--wait", "85"}, method: "GET", uri: "/v1/p/pabcdefg?wait=85"},
		// notary (17.2, 17.3)
		{args: []string{"ts", hash, "--note", "release build"}, method: "POST", uri: "/v1/ts", body: `{"h":"` + hash + `","note":"release build"}`},
		{args: []string{"attest", "I run arith at L3"}, method: "POST", uri: "/v1/attest", body: `{"text":"I run arith at L3"}`},
		{args: []string{"card"}, method: "GET", uri: "/v1/card"},
		{args: []string{"rep", "abcdefg", "--jws"}, method: "GET", uri: "/v1/rep/abcdefg?f=jws"},
		{args: []string{"rep", "abcdefg"}, method: "GET", uri: "/v1/rep/abcdefg"},
	}
	for _, tc := range cases {
		c, _, _ := recCLI(t, srv, t.TempDir(), "tok")
		c.stdin = strings.NewReader(tc.stdin)
		mustRun(t, c, tc.args...)
		r := f.last()
		if r.method != tc.method || r.uri != tc.uri {
			t.Errorf("%v: got %s %s, want %s %s", tc.args, r.method, r.uri, tc.method, tc.uri)
			continue
		}
		if tc.body != "" {
			if strings.HasPrefix(tc.body, "{") {
				var got, want any
				json.Unmarshal([]byte(r.body), &got)
				json.Unmarshal([]byte(tc.body), &want)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("%v: body %s, want %s", tc.args, r.body, tc.body)
				}
			} else if r.body != tc.body {
				t.Errorf("%v: body %q, want %q", tc.args, r.body, tc.body)
			}
		}
		if tc.ctype != "" && r.hdr.Get("Content-Type") != tc.ctype {
			t.Errorf("%v: content-type %q, want %q", tc.args, r.hdr.Get("Content-Type"), tc.ctype)
		}
		if r.hdr.Get("Authorization") != "Bearer tok" {
			t.Errorf("%v: auth %q", tc.args, r.hdr.Get("Authorization"))
		}
	}
}

// ts hashes a file when the argument is not a bare 64-hex digest.
func TestEconTSHashesFile(t *testing.T) {
	f, srv := newRec(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "artifact.bin")
	content := []byte("some bytes to notarize\n")
	os.WriteFile(p, content, 0o644)
	c, _, _ := recCLI(t, srv, t.TempDir(), "tok")
	mustRun(t, c, "ts", p)
	r := f.last()
	var body map[string]any
	json.Unmarshal([]byte(r.body), &body)
	if r.method != "POST" || r.uri != "/v1/ts" || body["h"] != sha256hex(content) {
		t.Fatalf("ts file: %s %s body %s (want h=%s)", r.method, r.uri, r.body, sha256hex(content))
	}
	if r.hdr.Get("X-PoW") != "" {
		t.Fatalf("token present: no PoW expected, got %q", r.hdr.Get("X-PoW"))
	}
}

// an anonymous ts solves a for=w challenge and carries X-PoW, never an Authorization header.
func TestEconTSAnonymousPoW(t *testing.T) {
	f, srv := newRec(t)
	hash := strings.Repeat("b", 64)
	c, _, _ := recCLI(t, srv, t.TempDir(), "")
	mustRun(t, c, "ts", hash)
	r := f.last()
	ch, nonce, ok := strings.Cut(r.hdr.Get("X-PoW"), ":")
	if r.method != "POST" || r.uri != "/v1/ts" || !ok || !pow.Check(ch, nonce, testBits) || r.hdr.Get("Authorization") != "" {
		t.Fatalf("anonymous ts %+v", r)
	}
	if q := f.find("POST", "/v1/challenge?for=w"); q == nil {
		t.Fatal("for=w challenge not requested")
	}
}

// admin seedclaims posts each JSONL row to /v1/v with seed=true.
func TestEconAdminSeedClaims(t *testing.T) {
	f, srv := newRec(t)
	c, _, errb := recCLI(t, srv, t.TempDir(), "tok")
	c.stdin = strings.NewReader(`{"lib":"npm:react","kind":"breaking","title":"18->19"}` + "\n\n" +
		`{"lib":"pypi:requests","kind":"security","title":"CVE"}` + "\n")
	mustRun(t, c, "admin", "seedclaims", "-")
	var posts []reqRec
	for _, r := range f.reqs {
		if r.method == "POST" && r.uri == "/v1/v" {
			posts = append(posts, r)
		}
	}
	if len(posts) != 2 {
		t.Fatalf("want 2 /v1/v posts, got %d", len(posts))
	}
	for _, r := range posts {
		var m map[string]any
		json.Unmarshal([]byte(r.body), &m)
		if m["seed"] != true {
			t.Fatalf("seed flag not set: %s", r.body)
		}
		if r.hdr.Get("Authorization") != "Bearer tok" {
			t.Fatalf("auth %q", r.hdr.Get("Authorization"))
		}
	}
	if !strings.Contains(errb.String(), "seeded 2 claim") {
		t.Fatalf("stderr %q", errb.String())
	}
	// a non-JSON line is rejected before any request
	c, _, _ = recCLI(t, srv, t.TempDir(), "tok")
	c.stdin = strings.NewReader("not json\n")
	var ee *exitErr
	if err := c.run(context.Background(), []string{"admin", "seedclaims", "-"}); !asExit(err, &ee) || ee.code != 2 {
		t.Fatalf("bad line: %v", err)
	}
}

// oauth-hint prints connector instructions locally and never contacts the server or prints a token.
func TestEconOAuthHint(t *testing.T) {
	f, srv := newRec(t)
	c, out, _ := recCLI(t, srv, t.TempDir(), "tok")
	mustRun(t, c, "oauth-hint")
	s := out.String()
	if !strings.Contains(s, srv.URL+"/mcp") || !strings.Contains(s, "/.well-known/oauth-protected-resource") {
		t.Fatalf("hint %q", s)
	}
	if strings.Contains(s, "Bearer") || strings.Contains(s, "cx_xxxx") {
		t.Fatalf("hint leaked a token: %q", s)
	}
	if len(f.reqs) != 0 {
		t.Fatalf("oauth-hint contacted the server: %d requests", len(f.reqs))
	}
}

func TestUsageIncludesEconGov(t *testing.T) {
	_, srv := newRec(t)
	c, out, _ := recCLI(t, srv, t.TempDir(), "")
	mustRun(t, c, "help")
	help := out.String()
	for _, n := range []string{"svc", "ts", "pr", "bt", "sp", "pp", "pv", "pl", "pg", "attest", "card", "rep"} {
		if !regexp.MustCompile(`(?m)(^|\s)` + regexp.QuoteMeta(n) + `(\s|$)`).MatchString(help) {
			t.Errorf("help does not list %q", n)
		}
	}
	for _, g := range []string{"catalog:", "economy:", "governance:", "spaces:", "notary:"} {
		if !strings.Contains(help, "\n"+g) {
			t.Errorf("help lacks section %q", g)
		}
	}
	// help <verb> filters to lines mentioning that verb
	c, out2, _ := recCLI(t, srv, t.TempDir(), "")
	mustRun(t, c, "help", "svc")
	for _, l := range strings.Split(strings.TrimSpace(out2.String()), "\n") {
		if !strings.Contains(l, "svc") {
			t.Fatalf("help svc line %q", l)
		}
	}
}
