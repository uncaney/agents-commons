package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// botkeys (SPEC-v2 27.1, 20): the Web Bot Auth key directory of one compiled-in host, fetched
// daily at GET https://<host>/.well-known/http-message-signatures-directory and posted back through
// the ack for core.BotKeysResult. The host list is compiled in on both sides: a payload naming any
// other host fails the row without a request. Directory text is untrusted: the body is read up to
// 64 KiB and only the JSON shape is checked here (the gateway validates the keys themselves).
const (
	botDirPath   = "/.well-known/http-message-signatures-directory"
	botDirMax    = 64 << 10
	botDirAccept = "application/http-message-signatures-directory+json, application/json;q=0.9"
)

var botHosts = []string{"chatgpt.com", "openai.com"}

func init() {
	Register(&Kind{Name: "botkeys", Hosts: botHosts, Run: runBotkeys})
}

type botResult struct {
	Host    string          `json:"host"`
	Status  int             `json:"status,omitempty"`
	JWKS    json.RawMessage `json:"jwks,omitempty"`
	Err     string          `json:"err,omitempty"`
	Fetched string          `json:"fetched"`
}

// botHost maps a payload host (optionally quoted or as an https origin) to a compiled-in host.
func botHost(v string) string {
	s := normHost(strings.Trim(strings.TrimSpace(v), `"`))
	s = strings.TrimSuffix(strings.TrimPrefix(s, "https://"), "/")
	for _, h := range botHosts {
		if s == h {
			return h
		}
	}
	return ""
}

// runBotkeys fetches one directory. Definitive answers (404/410, a body over 64 KiB, non-JSON, no
// keys array) are acked with err so the gateway marks the host ok=false; transport errors and other
// statuses fail the row for a retry.
func runBotkeys(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	var p struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		return nil, fmt.Errorf("botkeys: payload: %w", err)
	}
	host := botHost(p.Host)
	if host == "" {
		return nil, errors.New("botkeys: host not compiled in")
	}
	res := botResult{Host: host, Fetched: e.Now().UTC().Format(time.RFC3339)}
	req, err := http.NewRequest(http.MethodGet, "https://"+host+botDirPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", botDirAccept)
	code, body, _, err := e.Do(ctx, req, botDirMax, dialTimeout)
	res.Status = code
	switch {
	case errors.Is(err, errTooLarge):
		res.Err = "too large"
	case err != nil:
		return nil, fmt.Errorf("botkeys %s: %w", host, err)
	case code == 404 || code == 410:
		res.Err = "not found"
	case code != 200:
		return nil, statusErr("botkeys "+host, code, body)
	default:
		var dir struct {
			Keys []json.RawMessage `json:"keys"`
		}
		if json.Unmarshal(body, &dir) != nil || dir.Keys == nil {
			res.Err = "malformed directory"
		} else {
			res.JWKS = json.RawMessage(body)
		}
	}
	return json.Marshal(res)
}
