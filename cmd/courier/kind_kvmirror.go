package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
)

// kv_mirror (SPEC-v2 27.1, 20): one outbox row carries a single static crawl file to mirror into the
// edge Cloudflare Worker KV namespace so robots/sitemaps/llms.txt/index.md/.well-known keep
// answering 200 while the home box is unreachable. The courier PUTs it to
// api.cloudflare.com/client/v4/accounts/{acct}/storage/kv/namespaces/{ns}/values/{path} as a
// multipart write (value + a tiny metadata JSON {ct, last_modified} the Worker reads back) with the
// secret cf_kv_token scoped to that one namespace. The value is capped at 64 KiB: a larger body is
// dead-lettered with a note rather than written (llms-full is never mirrored). The Worker never
// proxies writes, so this is the only path by which KV is populated, and the path is re-validated
// here against the exact mirror route set even though the janitor generates it.
const (
	cfKVValuesAPI   = "https://api.cloudflare.com/client/v4/accounts/%s/storage/kv/namespaces/%s/values/%s"
	kvMirrorMaxBody = 64 << 10
)

var (
	cfIDRe        = regexp.MustCompile(`^[a-f0-9]{32}$`)
	kvKeyRe       = regexp.MustCompile(`^[0-9a-f]{32}\.txt$`)
	errKVNoConfig = errors.New("kv_mirror: CF_ACCOUNT_ID, CF_KV_NAMESPACE_ID (32 hex each) and secret cf_kv_token required")
)

func init() {
	Register(&Kind{Name: "kv_mirror", Hosts: []string{"api.cloudflare.com"}, Run: runKvMirror})
}

type kvMirrorPayload struct {
	Path         string `json:"path"`
	CT           string `json:"ct"`
	Body         string `json:"body"` // base64 of the raw bytes
	LastModified string `json:"last_modified"`
}

// kvMirrorPath reports whether path is one of the exact routes the edge Worker falls back to (the
// same seven shapes the Worker matches): the Worker only reads KV for those, so the courier only
// ever writes those keys.
func kvMirrorPath(path string) bool {
	switch {
	case path == "/robots.txt", path == "/sitemap.xml", path == "/llms.txt", path == "/index.md":
		return true
	case len(path) > len("/sitemaps/") && path[:len("/sitemaps/")] == "/sitemaps/":
		return !hasDotDot(path)
	case len(path) > len("/.well-known/") && path[:len("/.well-known/")] == "/.well-known/":
		return !hasDotDot(path)
	default:
		return len(path) > 1 && path[0] == '/' && kvKeyRe.MatchString(path[1:])
	}
}

func hasDotDot(p string) bool { return bytes.Contains([]byte(p), []byte("..")) }

func runKvMirror(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	var p kvMirrorPayload
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		return nil, fmt.Errorf("kv_mirror: payload: %w", err)
	}
	if !kvMirrorPath(p.Path) {
		// Not a mirror route: drop it, do not retry (nothing downstream depends on it).
		e.Log.Warn("kv_mirror: path is not a mirror route, dropped", "path", oneLine(p.Path, 200))
		return json.Marshal(map[string]string{"skipped": "path", "path": oneLine(p.Path, 200)})
	}
	body, err := base64.StdEncoding.DecodeString(p.Body)
	if err != nil {
		return nil, fmt.Errorf("kv_mirror: body: %w", err)
	}
	if len(body) > kvMirrorMaxBody {
		// Over the value cap: dead-letter with a note, never written (llms-full lands here too).
		e.Log.Warn("kv_mirror: value over 64 KiB, skipped", "path", p.Path, "bytes", len(body))
		return json.Marshal(map[string]any{"skipped": "too large", "path": p.Path, "bytes": len(body)})
	}
	acct, ns := e.Getenv("CF_ACCOUNT_ID"), e.Getenv("CF_KV_NAMESPACE_ID")
	token := e.Secret("cf_kv_token")
	if !cfIDRe.MatchString(acct) || !cfIDRe.MatchString(ns) || token == "" {
		return nil, errKVNoConfig
	}

	ct := p.CT
	if ct == "" {
		ct = "application/octet-stream"
	}
	meta := map[string]string{"ct": ct}
	if p.LastModified != "" {
		meta["last_modified"] = p.LastModified
	}
	buf, boundary, err := kvMultipart(body, meta)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf(cfKVValuesAPI, acct, ns, url.PathEscape(p.Path))
	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	req.Header.Set("Authorization", "Bearer "+token)
	code, respBody, _, err := e.Do(ctx, req, readCap, dialTimeout)
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
	json.Unmarshal(respBody, &out)
	if code/100 != 2 || !out.Success {
		msg := ""
		if len(out.Errors) > 0 {
			msg = fmt.Sprintf(" %d %s", out.Errors[0].Code, oneLine(out.Errors[0].Message, 120))
		}
		return nil, fmt.Errorf("kv_mirror: status %d%s", code, msg)
	}
	e.Log.Info("kv_mirror written", "path", p.Path, "bytes", len(body), "ct", ct)
	return json.Marshal(map[string]any{"path": p.Path, "bytes": len(body), "ct": ct})
}

// kvMultipart builds the Cloudflare KV write body: a `value` part carrying the raw bytes and a
// `metadata` part carrying the JSON the Worker reads back for Content-Type and Last-Modified.
func kvMultipart(body []byte, meta map[string]string) ([]byte, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return nil, "", err
	}
	if err := mw.WriteField("metadata", string(metaJSON)); err != nil {
		return nil, "", err
	}
	vw, err := mw.CreateFormField("value")
	if err != nil {
		return nil, "", err
	}
	if _, err := vw.Write(body); err != nil {
		return nil, "", err
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), mw.Boundary(), nil
}
