package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// indexnow (SPEC-v2 9.6, 20): rows {urls} are drained every 10 min and POSTed in batches of
// <= 10k URLs as {host, key, keyLocation, urlList}; 10k URLs/day. URLs are server-generated and
// still re-checked against the public host here.
var (
	indexNowDailyCap = 10_000
	indexNowPerPost  = 10_000
	indexNowBatch    = 500 // outbox rows per drain (a row carries a permalink and its hubs)
	indexNowEndpoint = "https://api.indexnow.org/indexnow"
	errIndexNowQuota = errors.New("indexnow: daily cap reached")
)

func init() {
	Register(&Kind{Name: "indexnow", Hosts: []string{"api.indexnow.org"}, Every: 10 * time.Minute,
		Batch: indexNowBatch, RunBatch: runIndexNow})
}

type indexNowPayload struct {
	URLs []string `json:"urls"`
}

// indexNowURLs flattens and dedupes the URLs of a batch, dropping anything off the public host.
func indexNowURLs(e *Env, jobs []*Job) []string {
	seen := map[string]bool{}
	var out []string
	for _, j := range jobs {
		var p indexNowPayload
		if err := json.Unmarshal(j.Payload, &p); err != nil {
			continue
		}
		for _, u := range p.URLs {
			if !e.SameSite(u) || seen[u] {
				continue
			}
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

func runIndexNow(ctx context.Context, e *Env, jobs []*Job) error {
	urls := indexNowURLs(e, jobs)
	if len(urls) == 0 {
		return nil
	}
	if e.IndexNowKey == "" {
		return errors.New("indexnow: key unknown (gateway /internal/config not loaded)")
	}
	if !e.Take("indexnow", len(urls), indexNowDailyCap) {
		return errIndexNowQuota
	}
	host := e.PublicHost()
	for _, part := range chunk(urls, indexNowPerPost) {
		req, err := JSONRequest(http.MethodPost, indexNowEndpoint, map[string]any{
			"host": host, "key": e.IndexNowKey, "keyLocation": e.PublicURL + "/" + e.IndexNowKey + ".txt", "urlList": part})
		if err != nil {
			return err
		}
		code, body, _, err := e.Do(ctx, req, readCap, dialTimeout)
		if err != nil {
			return err
		}
		if code/100 != 2 {
			return statusErr("indexnow", code, body)
		}
	}
	e.Log.Info("indexnow submitted", "urls", len(urls), "rows", len(jobs))
	return nil
}
