// Package svcget serves cached WASM-service results over plain GET and drives their demand-driven
// precomputation (SPEC-v2 27.6). GET /svc/{name}/{in...} resolves the stable version, looks the
// input up in the global result cache and serves a hit as cacheable text/plain; a miss answers 402
// with the POST recipe and records the demand. An anonymous GET never runs compute: the hourly
// svc_precompute janitor is the only path that turns demand into a system job, from the faucet and
// under a daily cap. Inputs are bounded, secret-looking inputs are refused, and only services whose
// manifest opts in (get_ok, default true for abi:text) are GET-readable.
package svcget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/know"
	"ekaii.fr/commons/internal/scrub"
)

const (
	maxInput    = 2 << 10 // 2 KiB input cap (27.6)
	defMb       = 64      // compute's default mb when a manifest sets no mb_hint
	missGroups  = 3       // distinct day-HMAC'd super-groups in the window before a precompute
	missWindowD = 7
)

// precomputeCap is the faucet's daily ceiling on system precomputes (27.6: <= 100/day). A var so
// tests can lower it.
var precomputeCap = 100

// Op is an MCP operation (same shape as compute/catalog).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

type svc struct{ d *core.Deps }

// Register mounts GET /svc/{name}/{in...} and the hourly precompute janitor.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}
	mux.HandleFunc("GET /svc/{name}/{in...}", s.hGet)
	d.RegisterScope("GET /svc/{name}/{in...}", "*")
	d.RegisterOpenAPI(openAPI)
	d.Janitor.Add("svc_precompute", s.janitor)
}

// Ops returns the MCP op of this package (merged by the integration package).
func Ops(d *core.Deps) map[string]Op {
	s := &svc{d: d}
	return map[string]Op{"svcg": s.opSvcg}
}

// OpMeta describes Ops for the registry (3.5).
var OpMeta = map[string]core.OpMeta{"svcg": {Scope: "", Cost: 0.2}}

// Help is the help{t:svcg} text (<= 200 tokens).
const Help = `svcg{name,in} read a cached WASM-service result without a token: a global cache hit returns the stored stdout, a miss returns 402 and records demand so the service is precomputed. GET /svc/<name>/<url-encoded input> is the same (public, max-age=3600). Inputs <= 2 KiB, secret-looking inputs refused; only get_ok services are readable.`

var openAPI = json.RawMessage(`{"paths":{
"/svc/{name}/{in...}":{"get":{"operationId":"svcg","summary":"Serve a cached WASM-service result for an input (global cache hit as text/plain, public max-age=3600; miss -> 402 with the POST recipe + records demand). Never computes.","parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}},{"name":"in","in":"path","required":true,"schema":{"type":"string","description":"url-encoded input text, <= 2 KiB"}},{"name":"v","in":"query","schema":{"type":"string","enum":["2"]},"description":"v=2 prepends the head line"},{"name":"raw","in":"query","schema":{"type":"string","enum":["1"]}}],"responses":{"200":{"description":"stdout, Cache-Control public, Link rel=describedby"},"400":{"description":"err scrub (secret-looking input) | err bad (service not GET-readable)"},"402":{"description":"miss: POST /v1/svc/<name> {\"in_text\":\"…\"}"},"404":{"description":"err notfound (no such service / no stable version)"},"413":{"description":"err size (input over 2 KiB)"}}}}
}}`)

func (s *svc) hGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	in := r.PathValue("in")
	if strings.Contains(in, "%") {
		if dec, err := url.PathUnescape(in); err == nil {
			in = dec
		}
	}
	root := ""
	if id, err := s.d.AuthOpt(r); err == nil && id != nil {
		root = id.Root
	}
	text, j, hdr, status, err := s.read(r.Context(), name, in, r.URL.Query(), root)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	for k, v := range hdr {
		w.Header().Set(k, v)
	}
	core.Text(w, r, status, text, j)
}

func (s *svc) opSvcg(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	var q struct {
		Name string `json:"name"`
		In   string `json:"in"`
	}
	if len(a) > 0 && string(a) != "null" {
		if err := json.Unmarshal(a, &q); err != nil {
			return "", core.Bad("a: " + err.Error())
		}
	}
	root := ""
	if id != nil {
		root = id.Root
	}
	text, _, _, status, err := s.read(ctx, q.Name, q.In, nil, root)
	if err != nil {
		return "", err
	}
	if status == http.StatusPaymentRequired {
		return "", core.E(402, "miss", text)
	}
	return text, nil
}

// read resolves the stable version, serves a global cache hit or answers 402 and records the miss.
// It performs no compute. The returned headers/status go to the HTTP path; the op reads the text.
func (s *svc) read(ctx context.Context, name, in string, q url.Values, root string) (string, map[string]any, map[string]string, int, error) {
	if len(in) == 0 {
		return "", nil, nil, 0, core.ErrNotFound
	}
	if len(in) > maxInput {
		return "", nil, nil, 0, core.E(413, "size", "input over 2 KiB: POST /v1/svc/"+doc.SafeLine(name)+` {"in_text":"…"}`)
	}
	// Secret-looking inputs never reach donors (27.6): a tier-1 finding is refused outright.
	norm := scrub.Normalize(in)
	for _, f := range scrub.Scan("in", norm) {
		if f.Tier == 1 {
			return "", nil, nil, 0, core.E(400, "scrub", f.Kind+" in@"+itoa(f.Off))
		}
	}
	v, err := catalog.Stable(ctx, s.d.DB, name)
	if err != nil {
		return "", nil, nil, 0, err
	}
	if !v.Manifest.GetOKValue() {
		return "", nil, nil, 0, core.Bad("service " + v.Name + " is not GET-readable; POST /v1/svc/" + v.Name)
	}
	sha := sha256hex(in)
	mb := resolveMb(v)
	view, ok, err := compute.CacheLookup(ctx, s.d.DB, v.Wasm, sha, v.FS, mb)
	if err != nil {
		return "", nil, nil, 0, err
	}
	hdr := map[string]string{"Link": "</svc/" + v.Name + `>; rel="describedby"`}
	if ok {
		out, got, err := compute.BlobBytes(ctx, s.d, view.Out)
		if err != nil {
			return "", nil, nil, 0, err
		}
		if !got { // the output blob was GC'd under the cache row: treat as a miss
			return s.miss(ctx, v, in, sha, hdr, root)
		}
		hdr["Cache-Control"] = "public, max-age=3600"
		body := string(out)
		if q.Get("v") == "2" && q.Get("raw") != "1" {
			body = headLine(v.Name, view) + "\n" + body
		}
		return body, map[string]any{"name": v.Name, "out": view.Out, "ms": view.Ms, "stdout": string(out), "cached": true}, hdr, http.StatusOK, nil
	}
	return s.miss(ctx, v, in, sha, hdr, root)
}

// miss records the demand (and stores the input so a precompute can reference it by hash) and
// returns the 402 recipe. No compute happens here.
func (s *svc) miss(ctx context.Context, v *catalog.Version, in, sha string, hdr map[string]string, root string) (string, map[string]any, map[string]string, int, error) {
	if _, err := compute.PutSystemBlob(ctx, s.d, []byte(in), maxInput); err != nil {
		return "", nil, nil, 0, err
	}
	_, _, super := core.ClientFrom(ctx)
	if err := know.RecordMiss(ctx, s.d.DB, "svc", v.Name+"\x00"+sha, super, root); err != nil {
		return "", nil, nil, 0, err
	}
	body := "no cached result; compute it: POST /v1/svc/" + v.Name + ` {"in_text":"…"} (needs a token; join at /join.py)`
	j := map[string]any{"name": v.Name, "miss": true, "compute": "POST /v1/svc/" + v.Name}
	return body, j, hdr, http.StatusPaymentRequired, nil
}

func headLine(name string, v *compute.JobView) string {
	return fmt.Sprintf("%s done out=%s ms=%d cached", name, v.Out, v.Ms)
}

func resolveMb(v *catalog.Version) int {
	if v.Manifest.MbHint > 0 {
		return v.Manifest.MbHint
	}
	return defMb
}

func sha256hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func itoa(n int) string { return fmt.Sprintf("%d", n) }
