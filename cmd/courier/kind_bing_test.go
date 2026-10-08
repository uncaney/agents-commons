package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestBingContentPayloadShape(t *testing.T) {
	rendition := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html>hi</html>")
	p := bingPayload("https://agents.example", "https://agents.example/kb/a", rendition)
	if p["siteUrl"] != "https://agents.example" {
		t.Fatalf("siteUrl = %v", p["siteUrl"])
	}
	if p["url"] != "https://agents.example/kb/a" {
		t.Fatalf("url = %v", p["url"])
	}
	if p["structuredData"] != "" {
		t.Fatalf("structuredData = %q, want empty", p["structuredData"])
	}
	if p["dynamicServing"] != 0 {
		t.Fatalf("dynamicServing = %v, want 0", p["dynamicServing"])
	}
	msg, _ := base64.StdEncoding.DecodeString(p["httpMessage"].(string))
	if string(msg) != string(rendition) {
		t.Fatalf("httpMessage decodes to %q, want the full HTTP/1.1 rendition", msg)
	}
}

func TestBingContentPayload(t *testing.T) {
	rendition := "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nX-Robots-Tag: all\r\n\r\n<html><body>pydantic fix</body></html>"
	var mu sync.Mutex
	var submitted map[string]any
	var apikey string
	var renderURL string
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/internal/render":
			mu.Lock()
			renderURL = r.URL.Query().Get("url")
			mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer "+testToken {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "message/http")
			io.WriteString(w, rendition)
		case strings.HasSuffix(r.URL.Path, "/SubmitContent"):
			if r.Header.Get("X-Egress-Host") != "ssl.bing.com" {
				w.WriteHeader(421)
				return
			}
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			apikey = r.URL.Query().Get("apikey")
			json.Unmarshal(body, &submitted)
			mu.Unlock()
			io.WriteString(w, `{"d":null}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer fake.Close()

	te := testEnv(t, fake)
	e := te.e
	if err := os.WriteFile(filepath.Join(te.dir, "bing_api_key"), []byte("BING-KEY-123"), 0o600); err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(map[string]string{"url": "https://agents.example/kb/a"})
	res, err := runBingContent(context.Background(), e, &Job{ID: 1, Kind: "bing_content", Payload: payload})
	if err != nil {
		t.Fatalf("runBingContent: %v", err)
	}
	if res != nil {
		t.Fatalf("ack result = %s, want nil", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if renderURL != "https://agents.example/kb/a" {
		t.Fatalf("render asked for %q", renderURL)
	}
	if apikey != "BING-KEY-123" {
		t.Fatalf("apikey = %q", apikey)
	}
	if submitted["siteUrl"] != "https://agents.example" || submitted["url"] != "https://agents.example/kb/a" {
		t.Fatalf("submitted siteUrl/url wrong: %+v", submitted)
	}
	if submitted["structuredData"] != "" {
		t.Fatalf("structuredData = %v", submitted["structuredData"])
	}
	if submitted["dynamicServing"].(float64) != 0 {
		t.Fatalf("dynamicServing = %v", submitted["dynamicServing"])
	}
	msg, _ := base64.StdEncoding.DecodeString(submitted["httpMessage"].(string))
	if string(msg) != rendition {
		t.Fatalf("httpMessage = %q, want the exact rendition", msg)
	}
}

func TestBingContentDropsOffsiteAndNeedsKey(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer fake.Close()
	e := testEnv(t, fake).e
	// Off-site URL: dropped (no error, no ack result).
	payload, _ := json.Marshal(map[string]string{"url": "https://evil.example/x"})
	if res, err := runBingContent(context.Background(), e, &Job{ID: 1, Payload: payload}); err != nil || res != nil {
		t.Fatalf("offsite url: res=%v err=%v, want both nil", res, err)
	}
	// On-site URL but no bing_api_key: a retryable error, nothing posted.
	payload, _ = json.Marshal(map[string]string{"url": "https://agents.example/kb/a"})
	if _, err := runBingContent(context.Background(), e, &Job{ID: 2, Payload: payload}); err == nil {
		t.Fatal("expected an error when bing_api_key is unset")
	}
}
