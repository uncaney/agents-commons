package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// bing_content (SPEC-v2 27.1, 20): one outbox row carries {url}, a page the platform indexed. The
// courier fetches the exact rendition from the gateway's bearer-only GET /internal/render?url= and
// pushes it to Bing's SubmitContent API as a base64 full HTTP/1.1 response. The URL is server-
// generated but re-checked against the public host here, and the rendition is never altered.
const (
	bingEndpoint    = "https://ssl.bing.com/webmaster/api.svc/json/SubmitContent"
	bingRenderCap   = 1 << 20 // the rendition the gateway returns is at most this
	bingDialTimeout = 20 * time.Second
)

var errBingNoKey = errors.New("bing_content: bing_api_key secret unset")

func init() {
	Register(&Kind{Name: "bing_content", Hosts: []string{"ssl.bing.com"}, Run: runBingContent})
}

type bingJob struct {
	URL string `json:"url"`
}

// bingPayload builds the SubmitContent body: the siteUrl, the page url, the base64 of the full
// HTTP/1.1 rendition, an empty structuredData and dynamicServing 0 (SPEC 27.1).
func bingPayload(siteURL, pageURL string, rendition []byte) map[string]any {
	return map[string]any{
		"siteUrl":        siteURL,
		"url":            pageURL,
		"httpMessage":    base64.StdEncoding.EncodeToString(rendition),
		"structuredData": "",
		"dynamicServing": 0,
	}
}

func runBingContent(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	var j bingJob
	if err := json.Unmarshal(job.Payload, &j); err != nil {
		return nil, err
	}
	if !e.SameSite(j.URL) {
		// A URL off the public host is dropped, not retried (nothing downstream depends on it).
		e.Log.Warn("bing_content: url not on public host, dropped", "url", oneLine(j.URL, 200))
		return nil, nil
	}
	key := e.Secret("bing_api_key")
	if key == "" {
		return nil, errBingNoKey
	}
	rendition, err := e.renderInternal(ctx, j.URL)
	if err != nil {
		return nil, err
	}
	req, err := JSONRequest(http.MethodPost, bingEndpoint+"?apikey="+url.QueryEscape(key), bingPayload(e.PublicURL, j.URL, rendition))
	if err != nil {
		return nil, err
	}
	code, body, _, err := e.Do(ctx, req, readCap, bingDialTimeout)
	if err != nil {
		return nil, err
	}
	if code/100 != 2 {
		return nil, statusErr("bing_content", code, body)
	}
	e.Log.Info("bing_content submitted", "url", oneLine(j.URL, 200), "bytes", len(rendition))
	return nil, nil
}

// renderInternal fetches the exact full HTTP/1.1 rendition of url from the gateway's internal render
// route (bearer-protected, never public). The gateway validates that url is under PUBLIC_URL.
func (e *Env) renderInternal(ctx context.Context, pageURL string) ([]byte, error) {
	code, body, err := e.Internal(ctx, http.MethodGet, "/internal/render?url="+url.QueryEscape(pageURL), nil, bingRenderCap)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, statusErr("bing_content render", code, body)
	}
	return body, nil
}
