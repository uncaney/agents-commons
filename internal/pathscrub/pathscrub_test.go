package pathscrub

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
)

// newSrv wraps a recording downstream handler with the middleware (d is unused, so nil is fine).
func newSrv(t *testing.T, ct, body string) (*httptest.Server, *bool) {
	t.Helper()
	called := new(bool)
	down := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		io.WriteString(w, body)
	})
	srv := httptest.NewServer(Middleware(nil, down))
	t.Cleanup(srv.Close)
	return srv, called
}

func get(t *testing.T, srv *httptest.Server, path string) (int, string) {
	t.Helper()
	// Build the URL without re-encoding the path so a literal secret reaches the server.
	resp, err := srv.Client().Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b)
}

func TestPathScrubRejectsBeforeHandler(t *testing.T) {
	srv, called := newSrv(t, "text/plain", "ok")

	// An AWS key in an /e/ path is a tier-1 hit: 400 before the handler, kind "key".
	st, body := get(t, srv, "/e/AKIAABCDEFGHIJKLMNOP")
	if st != 400 {
		t.Fatalf("status %d body %q", st, body)
	}
	if !strings.Contains(body, "err scrub query key") {
		t.Fatalf("body = %q", body)
	}
	if !strings.Contains(body, "POST /v1/q") {
		t.Fatalf("body lacks the guidance: %q", body)
	}
	if *called {
		t.Fatal("handler ran despite a secret in the path")
	}

	// A secret in ?q= on /v1/kb is rejected too.
	*called = false
	st, _ = get(t, srv, "/v1/kb?q=AKIAABCDEFGHIJKLMNOP")
	if st != 400 || *called {
		t.Fatalf("/v1/kb?q=<secret> status %d called %v", st, *called)
	}

	// A clean search passes through untouched.
	*called = false
	st, _ = get(t, srv, "/q/how%20to%20parse%20json")
	if st != 200 || !*called {
		t.Fatalf("clean query status %d called %v", st, *called)
	}

	// A path outside the scan list is never scanned, even with a key-looking segment.
	*called = false
	st, _ = get(t, srv, "/k/AKIAABCDEFGHIJKLMNOP")
	if st != 200 || !*called {
		t.Fatalf("unscanned path status %d called %v", st, *called)
	}
}

func TestMaskedLogLine(t *testing.T) {
	in := "/e/AKIAABCDEFGHIJKLMNOP?q=hello"
	masked := MaskPath(in)
	if strings.Contains(masked, "AKIAABCDEFGHIJKLMNOP") {
		t.Fatalf("masked path still contains the secret: %q", masked)
	}
	if masked == in {
		t.Fatalf("masked path unchanged: %q", masked)
	}

	// Truncation to 200 bytes.
	long := "/q/" + strings.Repeat("a", 400)
	if got := MaskPath(long); len(got) > 200 {
		t.Fatalf("MaskPath did not truncate: len %d", len(got))
	}

	// A clean path is returned as-is.
	if got := MaskPath("/q/plain"); got != "/q/plain" {
		t.Fatalf("clean path changed: %q", got)
	}
}

func TestNoReferrerOnHTML(t *testing.T) {
	srv, _ := newSrv(t, "text/html; charset=utf-8", "<html></html>")
	resp, err := srv.Client().Get(srv.URL + "/anything")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy on HTML = %q", got)
	}

	// A non-HTML reply is left alone by this middleware.
	srv2, _ := newSrv(t, "application/json", "{}")
	resp2, err := srv2.Client().Get(srv2.URL + "/anything")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if got := resp2.Header.Get("Referrer-Policy"); got != "" {
		t.Fatalf("non-HTML reply got Referrer-Policy = %q", got)
	}
}

func TestLogPathFnInstalled(t *testing.T) {
	// The init hook wires MaskPath as the request-log formatter when nothing else has, so the
	// gateway's log lines are masked and truncated like MaskPath.
	if core.LogPathFn == nil {
		t.Fatal("core.LogPathFn was not installed")
	}
	if got := core.LogPathFn("/e/AKIAABCDEFGHIJKLMNOP"); strings.Contains(got, "AKIAABCDEFGHIJKLMNOP") {
		t.Fatalf("installed formatter does not mask: %q", got)
	}
}
