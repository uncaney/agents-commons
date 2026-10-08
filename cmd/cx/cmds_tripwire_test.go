package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCxTripwireVerbs(t *testing.T) {
	f, srv := newRec(t)

	// cx tw new <note> --ttl-h N --ps topic -> POST /v1/tw {note, ttl_h, on_hit:{ps}}
	f.set("POST", "/v1/tw", 201, "ok y7x2a9q url="+srv.URL+"/y/SECRET read=RKEY\nexpires: 2026-11-06\n")
	c, out, _ := recCLI(t, srv, t.TempDir(), "tok")
	mustRun(t, c, "tw", "new", "config canary", "--ttl-h", "48", "--ps", "g:alerts")
	if !strings.Contains(out.String(), "url="+srv.URL+"/y/SECRET") {
		t.Fatalf("tw new stdout %q", out.String())
	}
	r := f.last()
	if r.method != "POST" || r.uri != "/v1/tw" {
		t.Fatalf("tw new request %+v", r)
	}
	var body struct {
		Note  string `json:"note"`
		TTLh  int    `json:"ttl_h"`
		OnHit struct {
			PS string `json:"ps"`
		} `json:"on_hit"`
	}
	if err := json.Unmarshal([]byte(r.body), &body); err != nil {
		t.Fatalf("tw new body %q: %v", r.body, err)
	}
	if body.Note != "config canary" || body.TTLh != 48 || body.OnHit.PS != "g:alerts" {
		t.Fatalf("tw new body = %+v", body)
	}

	// cx tw new with no note sends no note field.
	f.set("POST", "/v1/tw", 201, "ok y9 url=u read=k\n")
	c, _, _ = recCLI(t, srv, t.TempDir(), "tok")
	mustRun(t, c, "tw", "new")
	if r := f.last(); strings.Contains(r.body, "note") {
		t.Fatalf("empty tw new should carry no note: %q", r.body)
	}

	// cx tw hits <id> -> GET /v1/tw/<id>
	f.set("GET", "/v1/tw/y7x2a9q", 200, "hits=3 first=2026-10-01 last=2026-10-07\nid: y7x2a9q\n")
	c, out, _ = recCLI(t, srv, t.TempDir(), "tok")
	mustRun(t, c, "tw", "hits", "y7x2a9q")
	if !strings.Contains(out.String(), "hits=3") {
		t.Fatalf("tw hits stdout %q", out.String())
	}
	if p := f.find("GET", "/v1/tw/y7x2a9q"); p == nil {
		t.Fatal("tw hits did not GET /v1/tw/y7x2a9q")
	}

	// Both verbs need a token.
	c, _, _ = recCLI(t, srv, t.TempDir(), "")
	var ee *exitErr
	if err := c.run(context.Background(), []string{"tw", "new"}); !asExit(err, &ee) || ee.code != 1 {
		t.Fatalf("tw new without token: %v", err)
	}
	if err := c.run(context.Background(), []string{"tw", "hits", "y1"}); !asExit(err, &ee) || ee.code != 1 {
		t.Fatalf("tw hits without token: %v", err)
	}

	// Unknown subverb is a usage error.
	c, _, _ = recCLI(t, srv, t.TempDir(), "tok")
	if err := c.run(context.Background(), []string{"tw", "bogus"}); !asExit(err, &ee) || ee.code != 2 {
		t.Fatalf("tw bogus: %v", err)
	}
}
