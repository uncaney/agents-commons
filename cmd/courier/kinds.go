package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

// Job is one outbox row as served by GET /internal/egress.
type Job struct {
	ID       int64           `json:"id"`
	Kind     string          `json:"kind"`
	Payload  json.RawMessage `json:"payload"`
	Attempts int             `json:"attempts"`
	Created  time.Time       `json:"created"`
}

// Kind is one egress job type. Exactly one of Run, RunBatch or Scan is set:
//   - Run handles one outbox row and returns the JSON result to ack (nil for none);
//   - RunBatch handles up to Batch rows drained together (all acked without result on nil, all
//     failed with the error otherwise); Every then throttles drains (indexnow: every 10 min);
//   - Scan runs every Every without outbox rows (wal_ship): the Scanner hook.
//
// Hosts are added to the allowlist when the kind is enabled through EGRESS_KINDS. Kinds register
// themselves from init() so later packages add a file and nothing else.
type Kind struct {
	Name     string
	Hosts    []string
	Every    time.Duration
	Batch    int
	Run      func(ctx context.Context, e *Env, job *Job) (json.RawMessage, error)
	RunBatch func(ctx context.Context, e *Env, jobs []*Job) error
	Scan     func(ctx context.Context, e *Env) error
}

var (
	regMu    sync.Mutex
	registry = map[string]*Kind{}
	kindRe   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// Register adds a kind to the registry (init time); invalid definitions panic.
func Register(k *Kind) {
	if k == nil || !kindRe.MatchString(k.Name) {
		panic("courier: invalid kind name")
	}
	n := 0
	for _, set := range []bool{k.Run != nil, k.RunBatch != nil, k.Scan != nil} {
		if set {
			n++
		}
	}
	if n != 1 {
		panic("courier: kind " + k.Name + " must set exactly one of Run, RunBatch, Scan")
	}
	if k.RunBatch != nil && k.Batch < 1 {
		k.Batch = 1
	}
	if k.Scan != nil && k.Every <= 0 {
		panic("courier: scanner kind " + k.Name + " needs Every")
	}
	for _, h := range k.Hosts {
		if !validHost(normHost(h)) {
			panic("courier: kind " + k.Name + " has invalid host " + h)
		}
	}
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[k.Name]; dup {
		panic("courier: duplicate kind " + k.Name)
	}
	registry[k.Name] = k
}

// Lookup returns a registered kind.
func Lookup(name string) (*Kind, bool) {
	regMu.Lock()
	defer regMu.Unlock()
	k, ok := registry[name]
	return k, ok
}

// Names lists the registered kinds, sorted.
func Names() []string {
	regMu.Lock()
	defer regMu.Unlock()
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// enabledKinds resolves EGRESS_KINDS names to kinds (duplicates folded, unknown names refused).
func enabledKinds(names []string) ([]*Kind, error) {
	var out []*Kind
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		k, ok := Lookup(n)
		if !ok {
			return nil, fmt.Errorf("EGRESS_KINDS: unknown kind %q (known: %s)", n, strings.Join(Names(), ", "))
		}
		seen[n] = true
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, errors.New("EGRESS_KINDS: no kind enabled")
	}
	return out, nil
}

// Env is the runtime kinds share: the allowlisted egress client, the internal/gateway clients,
// secrets as files, the public URL the gateway reports and daily quotas.
type Env struct {
	Client      *http.Client // allowlisted egress client (https only)
	Log         *slog.Logger
	Secret      func(name string) string // /run/secrets/<name> (trimmed), "" when absent
	Getenv      func(name string) string
	PublicURL   string // https://agents.ekaii.fr (from GET /internal/config, else PUBLIC_URL)
	IndexNowKey string // from GET /internal/config
	Now         func() time.Time

	internal    *http.Client // INTERNAL_URL + GATEWAY_URL only (plain http on the courier network)
	internalURL string
	gatewayURL  string
	token       string

	qmu    sync.Mutex
	quotas map[string]*dayQuota
}

type dayQuota struct {
	day  string
	used int
}

func newEnv(cfg config, egress *http.Client, log *slog.Logger) *Env {
	e := &Env{Client: egress, Log: log, Getenv: os.Getenv, PublicURL: cfg.PublicURL, Now: time.Now,
		internalURL: cfg.InternalURL, gatewayURL: cfg.GatewayURL, token: cfg.Token, quotas: map[string]*dayQuota{}}
	dir := cfg.SecretsDir
	e.Secret = func(name string) string {
		if !secretNameRe.MatchString(name) {
			return ""
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	iu, _ := url.Parse(cfg.InternalURL)
	gu, _ := url.Parse(cfg.GatewayURL)
	hosts := []string{}
	for _, u := range []*url.URL{iu, gu} {
		if u != nil {
			hosts = append(hosts, u.Hostname())
		}
	}
	e.internal = &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{Proxy: nil,
		DialContext: lockedDialer(hosts...), MaxIdleConns: 4, IdleConnTimeout: 90 * time.Second,
		ResponseHeaderTimeout: 70 * time.Second, MaxResponseHeaderBytes: 64 << 10},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("internal: redirects refused") }}
	return e
}

var secretNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Take consumes n units of a per-day quota (UTC day); false when cap would be exceeded.
func (e *Env) Take(name string, n, cap int) bool {
	day := e.Now().UTC().Format("2006-01-02")
	e.qmu.Lock()
	defer e.qmu.Unlock()
	q := e.quotas[name]
	if q == nil || q.day != day {
		q = &dayQuota{day: day}
		e.quotas[name] = q
	}
	if q.used+n > cap {
		return false
	}
	q.used += n
	return true
}

// PublicHost is the host of PublicURL.
func (e *Env) PublicHost() string {
	u, err := url.Parse(e.PublicURL)
	if err != nil {
		return ""
	}
	return normHost(u.Hostname())
}

// SameSite reports whether raw is an absolute https URL on the public host (<= 2 KiB). Kinds
// only ever send such URLs outside; payloads are server-generated but checked again here.
func (e *Env) SameSite(raw string) bool {
	if len(raw) > 2048 || !utf8.ValidString(raw) || strings.ContainsAny(raw, " \t\r\n<>\"'\\") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	h := e.PublicHost()
	return h != "" && normHost(u.Hostname()) == h && u.Port() == ""
}

// Do sends req through the egress client with a timeout and returns status, body (<= cap) and
// headers; non-2xx statuses are returned, not errors. The User-Agent is always ours.
func (e *Env) Do(ctx context.Context, req *http.Request, cap int64, timeout time.Duration) (int, []byte, http.Header, error) {
	if timeout <= 0 {
		timeout = dialTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req = req.WithContext(ctx)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", userAgent)
	}
	resp, err := e.Client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := readAll(resp.Body, cap)
	if err != nil {
		return resp.StatusCode, nil, resp.Header, err
	}
	return resp.StatusCode, b, resp.Header, nil
}

// JSONRequest builds a request with a JSON body.
func JSONRequest(method, u string, v any) (*http.Request, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// Internal calls the gateway's INTERNAL_LISTEN server (bearer, JSON) and returns status + body.
func (e *Env) Internal(ctx context.Context, method, path string, body io.Reader, cap int64) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, e.internalURL+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.internal.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := readAll(resp.Body, cap)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, b, nil
}

// GatewayGet opens a public-mux path on the gateway through the courier network (export files);
// the caller reads and closes the body and bounds what it reads.
func (e *Env) GatewayGet(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.gatewayURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := e.internal.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("gateway %s: status %d", path, resp.StatusCode)
	}
	return resp, nil
}

// loadInternalConfig fetches /internal/config (IndexNow key, public URL); retried by the caller.
func (e *Env) loadInternalConfig(ctx context.Context) error {
	code, b, err := e.Internal(ctx, http.MethodGet, "/internal/config", nil, 64<<10)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("/internal/config: status %d", code)
	}
	var c struct {
		PublicURL string `json:"public_url"`
		Key       string `json:"indexnow_key"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}
	if c.PublicURL != "" {
		e.PublicURL = strings.TrimRight(c.PublicURL, "/")
	}
	if len(c.Key) == 32 {
		e.IndexNowKey = c.Key
	}
	return nil
}

// oneLine makes s a single safe line of at most max runes for error reports and logs.
func oneLine(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if max > 0 && utf8.RuneCountInString(s) > max {
		s = strings.TrimSpace(string([]rune(s)[:max]))
	}
	return s
}

// statusErr formats an upstream status with a trimmed body excerpt.
func statusErr(what string, status int, body []byte) error {
	return fmt.Errorf("%s: status %d %s", what, status, oneLine(string(body), 160))
}

// chunk splits a slice into pieces of at most n.
func chunk[T any](s []T, n int) [][]T {
	if n < 1 {
		n = 1
	}
	var out [][]T
	for len(s) > n {
		out = append(out, s[:n])
		s = s[n:]
	}
	if len(s) > 0 {
		out = append(out, s)
	}
	return out
}
