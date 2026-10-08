package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
)

// cf_purge (SPEC-v2 9.4, 9.5, 20): Cloudflare purge-by-URL of /export/*, /kb/<id>, /k/<id> and hub
// pages after removals, 30 URLs per call, with the cache-purge-only token (secret cf_token) and the
// zone id from CF_ZONE_ID.
const cfPurgeMax = 30

var (
	cfZoneRe      = regexp.MustCompile(`^[a-f0-9]{32}$`)
	cfPurgeAPI    = "https://api.cloudflare.com/client/v4/zones/%s/purge_cache"
	errCFNoConfig = errors.New("cf_purge: CF_ZONE_ID (32 hex) and secret cf_token required")
)

func init() {
	Register(&Kind{Name: "cf_purge", Hosts: []string{"api.cloudflare.com"}, Run: runCFPurge})
}

type cfPurgePayload struct {
	URLs []string `json:"urls"`
}

func runCFPurge(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	var p cfPurgePayload
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		return nil, fmt.Errorf("cf_purge: payload: %w", err)
	}
	zone, token := e.Getenv("CF_ZONE_ID"), e.Secret("cf_token")
	if !cfZoneRe.MatchString(zone) || token == "" {
		return nil, errCFNoConfig
	}
	seen := map[string]bool{}
	var urls []string
	for _, u := range p.URLs {
		if e.SameSite(u) && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	calls := 0
	for _, part := range chunk(urls, cfPurgeMax) {
		req, err := JSONRequest(http.MethodPost, fmt.Sprintf(cfPurgeAPI, zone), map[string]any{"files": part})
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		code, body, _, err := e.Do(ctx, req, readCap, dialTimeout)
		if err != nil {
			return nil, err
		}
		var out struct {
			Success bool `json:"success"`
			Errors  []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
		}
		json.Unmarshal(body, &out)
		if code/100 != 2 || !out.Success {
			msg := ""
			if len(out.Errors) > 0 {
				msg = fmt.Sprintf(" %d %s", out.Errors[0].Code, oneLine(out.Errors[0].Message, 120))
			}
			return nil, fmt.Errorf("cf_purge: status %d%s", code, msg)
		}
		calls++
	}
	return json.Marshal(map[string]int{"purged": len(urls), "calls": calls, "dropped": len(p.URLs) - len(urls)})
}
