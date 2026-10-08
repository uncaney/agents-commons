package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestEOLFetchAndNormalise: the kind fetches endoflife.date and normalises each cycle's eol field
// (a bool or a date) into "", a date, or the "eol" marker.
func TestEOLFetchAndNormalise(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Egress-Host") != "endoflife.date" {
			w.WriteHeader(421)
			return
		}
		if r.URL.Path != "/api/node.json" {
			w.WriteHeader(404)
			return
		}
		io.WriteString(w, `[
			{"cycle":"21","releaseDate":"2023-10-17","eol":false,"latest":"21.6.0","lts":false},
			{"cycle":"18","releaseDate":"2022-04-19","eol":"2025-04-30","latest":"18.19.0","lts":"2022-10-25"},
			{"cycle":"14","releaseDate":"2020-04-21","eol":true,"latest":"14.21.3"}
		]`)
	}))
	defer fake.Close()
	e := testEnv(t, fake).e

	payload, _ := json.Marshal(map[string]string{"product": "node", "lib": "docker:node"})
	res, err := runEOL(context.Background(), e, &Job{ID: 1, Kind: "eol", Payload: payload})
	if err != nil {
		t.Fatalf("runEOL: %v", err)
	}
	var out eolResultOut
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if out.Product != "node" || out.Lib != "docker:node" || len(out.Cycles) != 3 {
		t.Fatalf("result = %+v", out)
	}
	want := map[string]string{"21": "", "18": "2025-04-30", "14": "eol"}
	for _, c := range out.Cycles {
		if want[c.Cycle] != c.EOL {
			t.Fatalf("cycle %s eol = %q, want %q", c.Cycle, c.EOL, want[c.Cycle])
		}
	}
	if out.Cycles[1].ReleaseDate != "2022-04-19" || out.Cycles[1].Latest != "18.19.0" {
		t.Fatalf("cycle 18 = %+v", out.Cycles[1])
	}
}

// TestEOLBadProductAndUnknown: a bad product name is a soft error; a 404 is an empty definitive ack.
func TestEOLBadProductAndUnknown(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer fake.Close()
	e := testEnv(t, fake).e

	payload, _ := json.Marshal(map[string]string{"product": "../etc/passwd", "lib": "docker:x"})
	if _, err := runEOL(context.Background(), e, &Job{ID: 1, Payload: payload}); err == nil {
		t.Fatal("expected a soft error for a bad product")
	}
	payload, _ = json.Marshal(map[string]string{"product": "unknownthing", "lib": "docker:unknownthing"})
	res, err := runEOL(context.Background(), e, &Job{ID: 2, Payload: payload})
	if err != nil {
		t.Fatalf("unknown product: %v", err)
	}
	var out eolResultOut
	json.Unmarshal(res, &out)
	if len(out.Cycles) != 0 {
		t.Fatalf("unknown product cycles = %+v", out.Cycles)
	}
}
