package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// wayback (SPEC-v2 27.6, 20): archives the fixed set of public transparency/export files on the
// Internet Archive after each day seal. One outbox row carries a public path; the courier GETs
// https://web.archive.org/save/<public-url> (same-host redirects only, enforced by the egress
// client), discards the body and acks {witness: <Content-Location|Location>} so the gateway can
// store the snapshot URL in ts_days.witness_url / export_witness. 10/day with 20 of reserved
// headroom; the path is re-validated here against the exact set even though the janitor generates
// it. The gateway's own URL is never guessed: it is rebuilt from the courier's PublicURL.
const (
	waybackDaily  = 10
	waybackHead   = 20
	waybackPrefix = "https://web.archive.org/save/"
	waybackHost   = "web.archive.org"
)

// waybackPaths is the exact set of public paths the kind will snapshot (the Worker/exports the log
// anchors): nothing else is ever submitted to the Archive.
var waybackPaths = map[string]bool{
	"/ts/roots.txt":          true,
	"/export/manifest.json":  true,
	"/export/SHA256SUMS.sig": true,
	"/.well-known/cx-key":    true,
	"/.well-known/did.json":  true,
	"/changelog":             true,
}

func init() {
	Register(&Kind{Name: "wayback", Hosts: []string{waybackHost}, Run: runWayback})
}

type waybackJob struct {
	URL  string `json:"url"`  // public path, e.g. /ts/roots.txt
	Kind string `json:"kind"` // ts | export (ignored here; the gateway's ResultFn reads it back)
	Day  string `json:"day"`
	File string `json:"file"`
}

func runWayback(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	var p waybackJob
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		return nil, fmt.Errorf("wayback: payload: %w", err)
	}
	if !waybackPaths[p.URL] {
		// Not an allowed path: drop it, never submit an arbitrary URL to the Archive.
		e.Log.Warn("wayback: path not in the fixed set, dropped", "path", oneLine(p.URL, 200))
		return json.Marshal(map[string]string{"skipped": "path", "path": oneLine(p.URL, 200)})
	}
	// 10/day cap (20 of reserved headroom): beyond it, drop without retrying.
	if !e.Take("wayback", 1, waybackDaily) {
		e.Log.Warn("wayback: daily cap reached, dropped", "path", p.URL)
		return json.Marshal(map[string]string{"skipped": "cap", "path": p.URL})
	}
	target := e.PublicURL + p.URL
	if !e.SameSite(target) {
		return nil, fmt.Errorf("wayback: %q is not a public-host URL", oneLine(target, 200))
	}
	save := waybackPrefix + target
	req, err := http.NewRequest(http.MethodGet, save, nil)
	if err != nil {
		return nil, err
	}
	// The egress client follows only same-host (web.archive.org) https redirects; the body is read
	// and discarded (bounded), only the snapshot-location header is kept.
	code, _, hdr, err := e.Do(ctx, req, readCap, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("wayback: GET %s: %w", oneLine(save, 120), err)
	}
	if code/100 != 2 && code != 302 && code != 301 {
		return nil, statusErr("wayback", code, nil)
	}
	witness := waybackWitness(hdr)
	if witness == "" {
		// A snapshot without a location header is not an error worth retrying forever: ack empty.
		return json.Marshal(map[string]any{"path": p.URL, "witness": ""})
	}
	e.Log.Info("wayback archived", "path", p.URL, "witness", witness)
	return json.Marshal(map[string]any{"path": p.URL, "witness": witness})
}

// waybackWitness resolves the snapshot URL from the response: Content-Location (preferred) then
// Location, made absolute against web.archive.org and accepted only when it stays on that host.
func waybackWitness(hdr http.Header) string {
	raw := strings.TrimSpace(hdr.Get("Content-Location"))
	if raw == "" {
		raw = strings.TrimSpace(hdr.Get("Location"))
	}
	if raw == "" {
		return ""
	}
	base := &url.URL{Scheme: "https", Host: waybackHost}
	u, err := base.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() != waybackHost {
		return ""
	}
	u.Fragment = "" // keep the query (snapshot timestamp), drop any fragment
	s := u.String()
	if len(s) > 2048 {
		return ""
	}
	return s
}
