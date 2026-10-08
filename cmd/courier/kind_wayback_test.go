package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// waybackCapture is one request the fake Internet Archive saw.
type waybackCapture struct {
	method, path, host string
}

// fakeWayback serves web.archive.org/save/<url>, answering with a Content-Location snapshot header
// (or Location when loc is "cl=false") so the kind can ack a witness.
func fakeWayback(t *testing.T, calls *[]waybackCapture, mu *sync.Mutex, header string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*calls = append(*calls, waybackCapture{method: r.Method, path: r.RequestURI, host: r.Header.Get("X-Egress-Host")})
		mu.Unlock()
		if header != "" {
			// The saved snapshot location; path form, resolved against web.archive.org by the kind.
			w.Header().Set(header, "/web/20261007000000/https://agents.example"+strings.TrimPrefix(r.RequestURI, "/save/https://agents.example"))
		}
		w.WriteHeader(200)
		w.Write([]byte("archived"))
	}))
}

func TestWaybackKindAckStoresWitness(t *testing.T) {
	for _, hdr := range []string{"Content-Location", "Location"} {
		var mu sync.Mutex
		var calls []waybackCapture
		fake := fakeWayback(t, &calls, &mu, hdr)
		te := testEnv(t, fake)
		e := te.e

		body, _ := json.Marshal(waybackJob{URL: "/ts/roots.txt", Kind: "ts", Day: "2026-10-07"})
		res, err := runWayback(context.Background(), e, &Job{ID: 1, Kind: "wayback", Payload: body})
		fake.Close()
		if err != nil {
			t.Fatalf("[%s] runWayback: %v", hdr, err)
		}
		var out struct{ Path, Witness string }
		if err := json.Unmarshal(res, &out); err != nil {
			t.Fatalf("[%s] ack json: %v (%s)", hdr, err, res)
		}
		want := "https://web.archive.org/web/20261007000000/https://agents.example/ts/roots.txt"
		if out.Witness != want {
			t.Fatalf("[%s] witness = %q, want %q", hdr, out.Witness, want)
		}
		mu.Lock()
		n := len(calls)
		var c waybackCapture
		if n == 1 {
			c = calls[0]
		}
		mu.Unlock()
		if n != 1 {
			t.Fatalf("[%s] archive requests = %d, want 1", hdr, n)
		}
		if c.method != http.MethodGet || c.host != "web.archive.org" {
			t.Fatalf("[%s] request = %+v, want GET to web.archive.org", hdr, c)
		}
		if !strings.HasPrefix(c.path, "/save/https://agents.example/ts/roots.txt") {
			t.Fatalf("[%s] save path = %q", hdr, c.path)
		}
	}
}

func TestWaybackFixedURLsOnly(t *testing.T) {
	var mu sync.Mutex
	var calls []waybackCapture
	fake := fakeWayback(t, &calls, &mu, "Content-Location")
	defer fake.Close()
	te := testEnv(t, fake)
	e := te.e

	// Every fixed path is accepted and reaches the Archive.
	fixed := []string{"/ts/roots.txt", "/export/manifest.json", "/export/SHA256SUMS.sig",
		"/.well-known/cx-key", "/.well-known/did.json", "/changelog"}
	for i, p := range fixed {
		if !waybackPaths[p] {
			t.Fatalf("waybackPaths missing %q", p)
		}
		body, _ := json.Marshal(waybackJob{URL: p, Kind: "export", File: "f"})
		res, err := runWayback(context.Background(), e, &Job{ID: int64(i + 1), Payload: body})
		if err != nil {
			t.Fatalf("fixed %s: %v", p, err)
		}
		if strings.Contains(string(res), "skipped") {
			t.Fatalf("fixed %s was skipped: %s", p, res)
		}
	}
	mu.Lock()
	fixedHits := len(calls)
	calls = nil
	mu.Unlock()
	if fixedHits != len(fixed) {
		t.Fatalf("fixed paths made %d archive requests, want %d", fixedHits, len(fixed))
	}

	// Anything outside the set is dropped before any egress.
	for _, p := range []string{"/", "/svc/evil/proof", "/export/../etc/passwd", "/ts/roots.txtx", "https://evil.example"} {
		body, _ := json.Marshal(waybackJob{URL: p})
		res, err := runWayback(context.Background(), e, &Job{Payload: body})
		if err != nil {
			t.Fatalf("off-set %q err = %v, want nil (dropped)", p, err)
		}
		if !strings.Contains(string(res), `"skipped":"path"`) {
			t.Fatalf("off-set %q ack = %s, want a path skip", p, res)
		}
	}
	mu.Lock()
	offHits := len(calls)
	mu.Unlock()
	if offHits != 0 {
		t.Fatalf("off-set paths made %d archive requests, want 0", offHits)
	}
}
