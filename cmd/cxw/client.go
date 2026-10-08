package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/sandbox"
)

const (
	maxBlob  = 16 << 20        // inputs, outputs and unpinned fs zips (POST /v1/b keeps this cap)
	maxWasm  = sandbox.MaxWasm // unpinned job modules are refused before download completes
	leaseVer = 2               // lease protocol version this donor speaks (14.4)
	capWasm  = "wasm4m"        // caps
	capPin   = "pin"
	capNew   = "new"
	capL0    = "l0"
)

// ErrTooBig is returned by GetBlobMax when the blob exceeds the given cap.
var ErrTooBig = errors.New("blob too big")

// LeaseReq is the donor's offer (14.4, 27.6): a ver 2 donor negotiates caps and lists the
// pinned modules it has warmed.
type LeaseReq struct {
	MaxMs int      `json:"max_ms"`
	MaxMb int      `json:"max_mb"`
	Ver   int      `json:"ver,omitempty"`
	Caps  []string `json:"caps,omitempty"`
	Pins  []string `json:"pins,omitempty"`
	Lanes []string `json:"lanes,omitempty"` // public, own (own: this token is a subkey of the submitter root)
}

// Lease is the JSON reply of POST /v1/w/lease.
type Lease struct {
	Lease    string `json:"lease"`
	Job      string `json:"job"`
	Wasm     string `json:"wasm"`
	In       string `json:"in"`
	FS       string `json:"fs,omitempty"` // zip blob mounted read-only at / (27.6)
	Ms       int    `json:"ms"`
	Mb       int    `json:"mb"`
	Lane     string `json:"lane,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Deadline int64  `json:"deadline,omitempty"`
	Upgrade  string `json:"upgrade,omitempty"` // set for a ver < 2 donor, logged once a day
	Sunset   string `json:"sunset,omitempty"`
}

// DoneCode is the exit code (status exit) or, with status error, a code word such as
// compile-timeout (27.6). It marshals as a JSON number or string accordingly.
type DoneCode struct {
	N    int
	Word string
}

func (c DoneCode) MarshalJSON() ([]byte, error) {
	if c.Word != "" {
		return json.Marshal(c.Word)
	}
	return json.Marshal(c.N)
}

func (c *DoneCode) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		return json.Unmarshal(b, &c.Word)
	}
	return json.Unmarshal(b, &c.N)
}

// Diag is the failure diagnostics of a report (27.6), stored by the gateway and never
// fingerprinted.
type Diag struct {
	Stderr    string `json:"stderr,omitempty"` // base64url of the stderr tail (<= 4 KiB)
	Trace     string `json:"trace,omitempty"`  // wasm stack trace (<= 2 KiB)
	CompileMs int    `json:"compile_ms,omitempty"`
	MemPages  int    `json:"mem_pages,omitempty"`
}

// Done is the JSON body of POST /v1/w/done.
type Done struct {
	Lease  string   `json:"lease"`
	Status string   `json:"status"`
	Out    string   `json:"out,omitempty"`
	Code   DoneCode `json:"code"`
	Ms     int      `json:"ms"`
	Diag   *Diag    `json:"diag,omitempty"`
	Dsig   string   `json:"dsig,omitempty"` // base64url ed25519 over the donor signature message
}

// Pin is one line of GET /v1/pins: a module donors may warm (14.4).
type Pin struct {
	Hash string `json:"hash"`
	Name string `json:"name"`
	Ver  string `json:"ver"`
	Size int64  `json:"size"`
	By   string `json:"by,omitempty"`
}

// ErrNoLease is returned by Lease on 204.
var ErrNoLease = errors.New("no lease")

// Client talks to the gateway. It never logs the token.
type Client struct {
	base  string
	token string
	http  *http.Client
}

func NewClient(base, token string) *Client {
	return &Client{base: base, token: token, http: &http.Client{Timeout: 90 * time.Second}}
}

func (c *Client) req(ctx context.Context, method, path string, body io.Reader, ctype string) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Accept", "application/json")
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	return r, nil
}

func (c *Client) do(r *http.Request, want ...int) (*http.Response, error) {
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, err
	}
	for _, w := range want {
		if resp.StatusCode == w {
			return resp, nil
		}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return nil, &HTTPError{r.Method, r.URL.Path, resp.StatusCode, string(bytes.TrimSpace(b))}
}

// HTTPError is a non-2xx reply.
type HTTPError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s %s: %d %s", e.Method, e.Path, e.Status, e.Body)
}

// Lease long-polls for work for up to wait seconds with the v1 offer (no pins, no optional
// caps). Returns ErrNoLease on 204.
func (c *Client) Lease(ctx context.Context, wait, maxMs, maxMb int) (*Lease, error) {
	return c.LeaseV2(ctx, wait, LeaseReq{MaxMs: maxMs, MaxMb: maxMb, Ver: leaseVer, Caps: []string{capWasm}})
}

// LeaseV2 long-polls for work for up to wait seconds with a negotiated offer (14.4).
func (c *Client) LeaseV2(ctx context.Context, wait int, req LeaseReq) (*Lease, error) {
	body, _ := json.Marshal(req)
	r, err := c.req(ctx, "POST", "/v1/w/lease?wait="+strconv.Itoa(wait), bytes.NewReader(body), "application/json")
	if err != nil {
		return nil, err
	}
	resp, err := c.do(r, 200, 204)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 {
		return nil, ErrNoLease
	}
	var l Lease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&l); err != nil {
		return nil, fmt.Errorf("lease decode: %w", err)
	}
	if l.Lease == "" || len(l.Lease) > 64 || !isHash(l.Wasm) || !isHash(l.In) || l.Ms <= 0 || l.Mb <= 0 || (l.FS != "" && !isHash(l.FS)) {
		return nil, fmt.Errorf("lease: malformed reply")
	}
	return &l, nil
}

// isHash reports whether s is a lowercase sha256 hex (hashes name files under CACHE_DIR).
func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// GetBlob downloads a blob (<= 16 MiB) and verifies its sha256.
func (c *Client) GetBlob(ctx context.Context, hash string) ([]byte, error) {
	return c.fetch(ctx, hash, maxBlob, "")
}

// GetBlobMax downloads a blob of at most max bytes (ErrTooBig beyond) and verifies its sha256.
func (c *Client) GetBlobMax(ctx context.Context, hash string, max int) ([]byte, error) {
	return c.fetch(ctx, hash, max, "")
}

// fetch is GetBlobMax with the lease the blob is read under (X-Lease, 27.6: job blobs are
// readable by the donor holding a live lease on them; pinned modules need no lease).
func (c *Client) fetch(ctx context.Context, hash string, max int, lease string) ([]byte, error) {
	if !isHash(hash) {
		return nil, fmt.Errorf("blob: bad hash %q", hash)
	}
	r, err := c.req(ctx, "GET", "/v1/b/"+hash, nil, "")
	if err != nil {
		return nil, err
	}
	if lease != "" {
		r.Header.Set("X-Lease", lease)
	}
	resp, err := c.do(r, 200)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ContentLength > int64(max) {
		return nil, fmt.Errorf("blob %s: %d bytes: %w", hash[:12], resp.ContentLength, ErrTooBig)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, fmt.Errorf("blob %s: over %d bytes: %w", hash[:12], max, ErrTooBig)
	}
	if got := sha256hex(b); got != hash {
		return nil, fmt.Errorf("blob %s: sha256 mismatch (got %s)", hash[:12], got[:12])
	}
	return b, nil
}

// PutBlob uploads raw bytes and checks the returned hash. A non-empty lease is sent as
// X-Lease so a job output is stored for the submitter, outside the worker's quota.
func (c *Client) PutBlob(ctx context.Context, data []byte, lease string) (string, error) {
	r, err := c.req(ctx, "POST", "/v1/b", bytes.NewReader(data), "application/octet-stream")
	if err != nil {
		return "", err
	}
	if lease != "" {
		r.Header.Set("X-Lease", lease)
	}
	resp, err := c.do(r, 200, 201)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	got := parseHash(b)
	if want := sha256hex(data); got != want {
		return "", fmt.Errorf("upload: server hash %q != local %s", got, want[:12])
	}
	return got, nil
}

// parseHash accepts a bare hash line or {"hash":"…"}.
func parseHash(b []byte) string {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '{' {
		var v struct {
			Hash string `json:"hash"`
		}
		_ = json.Unmarshal(b, &v)
		return v.Hash
	}
	return string(b)
}

// Done reports a finished lease.
func (c *Client) Done(ctx context.Context, d Done) error {
	body, _ := json.Marshal(d)
	r, err := c.req(ctx, "POST", "/v1/w/done", bytes.NewReader(body), "application/json")
	if err != nil {
		return err
	}
	resp, err := c.do(r, 200)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Pins lists the pinned modules (GET /v1/pins), as JSON or as `<hash> <name>@<ver> <size>` lines.
func (c *Client) Pins(ctx context.Context) ([]Pin, error) {
	r, err := c.req(ctx, "GET", "/v1/pins", nil, "")
	if err != nil {
		return nil, err
	}
	resp, err := c.do(r, 200)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return nil, err
	}
	var pins []Pin
	if t := bytes.TrimSpace(b); len(t) > 0 && t[0] == '[' {
		if err := json.Unmarshal(t, &pins); err != nil {
			return nil, fmt.Errorf("pins decode: %w", err)
		}
	} else {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 3 {
				continue
			}
			name, ver, _ := strings.Cut(f[1], "@")
			size, _ := strconv.ParseInt(f[2], 10, 64)
			pins = append(pins, Pin{Hash: f[0], Name: name, Ver: ver, Size: size})
		}
	}
	out := pins[:0]
	for _, p := range pins {
		if isHash(p.Hash) && p.Size > 0 {
			out = append(out, p)
		}
	}
	return out, nil
}

// PutPub registers the donor's ed25519 public key (PUT /v1/me {pub}, 27.6) and returns the key
// the gateway now holds for the root (hex), so the caller signs only when it matches.
func (c *Client) PutPub(ctx context.Context, pubHex string) (string, error) {
	body, _ := json.Marshal(map[string]string{"pub": pubHex})
	r, err := c.req(ctx, "PUT", "/v1/me", bytes.NewReader(body), "application/json")
	if err != nil {
		return "", err
	}
	resp, err := c.do(r, 200)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var v struct {
		Pub string `json:"pub"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if json.Unmarshal(b, &v) != nil { // text reply: "ok … pub=<hex>"
		if _, after, ok := strings.Cut(string(b), "pub="); ok {
			v.Pub = strings.Fields(after)[0]
		}
	}
	return strings.ToLower(v.Pub), nil
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
