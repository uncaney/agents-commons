// Package gointerp wires the Go-native interpreters built in the wasip1 seed
// stage (cx-starlark, cx-goja, cx-expr; SPEC-v2 27.6) into the catalog: the op
// aliases star{}, jsg{} and expr{} call them through catalog.Call with the 15.4
// {code,stdin} framing, GET /wasm/sizes serves the measured size table
// descriptively, and py{}'s not-yet-published error gains a "try star{}" hint.
// The three interpreters live in the separate catalog-go module and are
// published under the system root by catalog.SeedSystem at boot; this package
// never imports that module (the gateway's stdlib+pgx+wazero rule is untouched).
package gointerp

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Op is an MCP operation (same shape as catalog.Op).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

const (
	maxCode   = 64 << 10
	maxStdin  = 64 << 10
	sizesPath = "catalog/SIZES.md" // written by catalog-go/build.sh on the server
)

// defaultSizes is the descriptive table served when the server has not written
// a measured catalog/SIZES.md yet (tests, pre-build).
//
//go:embed sizes.md
var defaultSizes []byte

// interp maps each op alias to its catalog service name (27.6).
var interp = map[string]string{"star": "cx-starlark", "jsg": "cx-goja", "expr": "cx-expr"}

// Hint is the line appended to py{}'s not-yet-published error.
const Hint = "try star{} (cx-starlark, a deterministic Python dialect)"

type h struct {
	d     *core.Deps
	sizes []byte
	mod   time.Time
}

// Register mounts GET /wasm/sizes, its scope and OpenAPI fragment, and installs
// the nil-safe py{} hint seam. A later integration package wires Ops/OpMeta.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &h{d: d, sizes: defaultSizes, mod: time.Now().UTC()}
	if b, err := os.ReadFile(sizesPath); err == nil && len(b) > 0 {
		s.sizes = b
		if fi, err := os.Stat(sizesPath); err == nil {
			s.mod = fi.ModTime().UTC()
		}
	}
	for _, pat := range []string{"GET /wasm/sizes", "GET /wasm/sizes.md", "GET /wasm/sizes.txt"} {
		mux.HandleFunc(pat, s.hSizes)
		d.RegisterScope(pat, "*")
	}
	d.RegisterOpenAPI(openAPI)
	catalog.PyHintFn = func() string { return Hint }
}

// Ops returns the interpreter op aliases.
func Ops(d *core.Deps) map[string]Op {
	s := &h{d: d}
	m := make(map[string]Op, len(interp))
	for alias, svc := range interp {
		m[alias] = s.opInterp(svc)
	}
	return m
}

// OpMeta describes the ops for the MCP registry (3.5): same scope/cost/mutating
// as the catalog interpreter framing they stand in for.
var OpMeta = map[string]core.OpMeta{
	"star": {Scope: "svc", Cost: 1, Mutating: true},
	"jsg":  {Scope: "svc", Cost: 1, Mutating: true},
	"expr": {Scope: "svc", Cost: 1, Mutating: true},
}

// Help is the help{t:gointerp} text.
const Help = `go-native interpreters (deterministic, built in the wasip1 seed stage; SPEC 27.6):
star{code,stdin} run a Starlark (Python dialect) program through cx-starlark | jsg{code,stdin} goja (ES5.1+) | expr{code,stdin} one expr-lang expression
each builds the 15.4 {code,stdin} framing and calls the catalog service: done ms= out= + stdout indented. py{} not-yet-published hints "try star{}".
GET /wasm/sizes lists the measured wasip1 module sizes. Outputs are untrusted program text.`

// frame builds the 15.4 launcher input {"code","stdin"} (JSON), size-capped.
func frame(code, stdin string) (string, error) {
	if code == "" {
		return "", core.Bad("code required")
	}
	if len(code) > maxCode {
		return "", core.E(413, "size", "code over 64 KiB")
	}
	if len(stdin) > maxStdin {
		return "", core.E(413, "size", "stdin over 64 KiB")
	}
	b, err := json.Marshal(map[string]string{"code": code, "stdin": stdin})
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// opInterp is star{}, jsg{}, expr{}: frame the code/stdin and call the catalog
// service through catalog.Call, rendering the same line as run{}.
func (s *h) opInterp(svc string) Op {
	return func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			Code  string `json:"code"`
			Stdin string `json:"stdin,omitempty"`
			FS    string `json:"fs,omitempty"`
			Wait  int    `json:"wait,omitempty"`
		}
		if len(a) > 0 {
			if err := json.Unmarshal(a, &in); err != nil {
				return "", core.Bad("bad op args")
			}
		}
		text, err := frame(in.Code, in.Stdin)
		if err != nil {
			return "", err
		}
		view, out, err := catalog.Call(ctx, s.d, id, svc, "", text, in.FS, in.Wait)
		if err != nil {
			return "", err
		}
		return render(view, out), nil
	}
}

// render matches catalog's call rendering: `done ms= out=<hash> [code=] [cached]
// job=<id>` then stdout indented by two spaces.
func render(v *compute.JobView, out string) string {
	switch v.Status {
	case "done":
		var b strings.Builder
		fmt.Fprintf(&b, "done ms=%d out=%s", v.Ms, v.Out)
		if v.Code != 0 {
			fmt.Fprintf(&b, " code=%d", v.Code)
		}
		if v.Cached {
			b.WriteString(" cached")
		}
		b.WriteString(" job=" + v.ID)
		if out != "" {
			b.WriteString("\n  " + doc.Indent(out))
		}
		return b.String()
	case "failed":
		return v.ID + " failed " + doc.SafeLine(v.Reason)
	}
	return v.ID + " " + v.Status
}

// hSizes serves catalog/SIZES.md (measured on the server, else the embedded
// descriptive default). Noindex: it is operational detail, not a crawl surface.
func (s *h) hSizes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Robots-Tag", "noindex")
	doc.ServeStatic(w, r, s.mod, s.sizes, "text/markdown; charset=utf-8")
}

var openAPI = json.RawMessage(`{"paths":{
"/wasm/sizes":{"get":{"operationId":"wasmSizes","summary":"Measured wasip1 module sizes for the Go-native interpreters (cx-starlark, cx-goja, cx-expr) plus the reference table of other runtimes; descriptive (.md/.txt)","responses":{"200":{"description":"the size table as Markdown"}}}}
}}`)
