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
)

// TestOSVQueryBatchAndFetch: the kind posts a validated querybatch to api.osv.dev, fetches each
// matched vulnerability record once, and returns the vulnerabilities per queried (lib, version).
func TestOSVQueryBatchAndFetch(t *testing.T) {
	var mu sync.Mutex
	var batchBody []byte
	var vulnGets []string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Egress-Host") != "api.osv.dev" {
			w.WriteHeader(421)
			return
		}
		switch {
		case r.URL.Path == "/v1/querybatch":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			batchBody = b
			mu.Unlock()
			io.WriteString(w, `{"results":[{"vulns":[{"id":"GHSA-j8r2-6x86-q33q"}]},{}]}`)
		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			mu.Lock()
			vulnGets = append(vulnGets, r.URL.Path)
			mu.Unlock()
			io.WriteString(w, `{"id":"GHSA-j8r2-6x86-q33q","summary":"Proxy-Authorization leak",
				"details":"leaks on redirect","affected":[{"package":{"ecosystem":"PyPI","name":"requests"},
				"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.31.0"}]}]}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer fake.Close()
	e := testEnv(t, fake).e

	payload, _ := json.Marshal(map[string]any{"queries": []map[string]string{
		{"lib": "pypi:requests", "eco": "PyPI", "name": "requests", "version": "2.30.0"},
		{"lib": "pypi:safe", "eco": "PyPI", "name": "safe", "version": "9.9.9"},
		{"lib": "docker:node", "eco": "Docker", "name": "node", "version": "20"}, // unknown eco: dropped
	}})
	res, err := runOSV(context.Background(), e, &Job{ID: 1, Kind: "osv", Payload: payload})
	if err != nil {
		t.Fatalf("runOSV: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	// The batch body carries only the two validated entries, in OSV shape.
	var sent struct {
		Queries []struct {
			Package struct{ Ecosystem, Name string } `json:"package"`
			Version string                           `json:"version"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(batchBody, &sent); err != nil {
		t.Fatalf("batch body: %v (%s)", err, batchBody)
	}
	if len(sent.Queries) != 2 || sent.Queries[0].Package.Ecosystem != "PyPI" || sent.Queries[0].Package.Name != "requests" {
		t.Fatalf("batch queries = %+v", sent.Queries)
	}
	if len(vulnGets) != 1 {
		t.Fatalf("vuln record GETs = %v, want one", vulnGets)
	}
	var out osvResultOut
	if err := json.Unmarshal(res, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 1 || out.Items[0].Lib != "pypi:requests" || out.Items[0].V != "2.30.0" {
		t.Fatalf("items = %+v", out.Items)
	}
	v := out.Items[0].Vulns
	if len(v) != 1 || v[0].ID != "GHSA-j8r2-6x86-q33q" || len(v[0].Affected) != 1 {
		t.Fatalf("vulns = %+v", v)
	}
	ev := v[0].Affected[0].Ranges[0].Events
	if ev[len(ev)-1].Fixed != "2.31.0" {
		t.Fatalf("events = %+v", ev)
	}
}

// TestOSVNoQueriesNoCall: a payload with no valid entries never calls out.
func TestOSVNoQueriesNoCall(t *testing.T) {
	var calls int
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer fake.Close()
	e := testEnv(t, fake).e
	payload, _ := json.Marshal(map[string]any{"queries": []map[string]string{{"lib": "docker:node", "eco": "Docker", "name": "node", "version": "20"}}})
	res, err := runOSV(context.Background(), e, &Job{ID: 1, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("made %d calls, want 0", calls)
	}
	var out osvResultOut
	json.Unmarshal(res, &out)
	if len(out.Items) != 0 {
		t.Fatalf("items = %+v", out.Items)
	}
}

// TestOSVIDValidation guards the id regex used before an id reaches a URL.
func TestOSVIDValidation(t *testing.T) {
	for _, id := range []string{"GHSA-j8r2-6x86-q33q", "CVE-2023-1234", "PYSEC-2021-1", "GO-2023-1234"} {
		if !osvIDReC.MatchString(id) {
			t.Fatalf("rejected valid id %q", id)
		}
	}
	for _, id := range []string{"../etc", "ghsa-lower", "", "x/y", "A B"} {
		if osvIDReC.MatchString(id) {
			t.Fatalf("accepted bad id %q", id)
		}
	}
}
