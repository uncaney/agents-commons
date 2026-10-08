package sign

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation: compact text result, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Help is the op list line merged into the MCP help.
const Help = `sig: verify{s,sig} check a signed statement line | key{} server key (also GET /.well-known/cx-key, GET /verify?s=&sig=)`

type handlers struct {
	d *core.Deps
	s *Signer
}

// Register derives the server key from d.Cfg (installing it as the package default) and mounts
// GET /.well-known/cx-key and GET /verify (anonymous, limiter cost 1) with their OpenAPI fragment.
func Register(mux *http.ServeMux, d *core.Deps) {
	s, err := Init(d.Cfg)
	if err != nil {
		panic(err)
	}
	h := &handlers{d, s}
	mux.HandleFunc("GET /.well-known/cx-key", h.key)
	mux.HandleFunc("GET /verify", h.verify)
	d.RegisterCost("GET /verify", 1)
	d.RegisterCost("GET /.well-known/cx-key", 1)
	d.RegisterOpenAPI(openapi)
}

// Ops returns the MCP ops owned by this package: verify{s,sig} and key{} (anonymous reads).
func Ops(d *core.Deps) map[string]Op {
	s := MustNew(d.Cfg)
	return map[string]Op{
		"verify": func(_ context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
			var in struct{ S, Sig string }
			if len(a) > 0 {
				if err := json.Unmarshal(a, &in); err != nil {
					return "", core.Bad("a: " + err.Error())
				}
			}
			kid, typ, err := s.check(in.S, in.Sig)
			if err != nil {
				return "", err
			}
			if typ == "" {
				return "invalid", nil
			}
			return fmt.Sprintf("valid kid=%d type=%s", kid, typ), nil
		},
		"key": func(context.Context, *core.Ident, json.RawMessage) (string, error) { return s.text(), nil },
	}
}

func (h *handlers) key(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	core.JSON(w, 200, h.s.WellKnown())
}

func (h *handlers) verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Robots-Tag", "noindex")
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	kid, typ, err := h.s.check(q.Get("s"), q.Get("sig"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if typ == "" {
		core.OK(w, r, "invalid", map[string]any{"valid": false})
		return
	}
	core.OK(w, r, fmt.Sprintf("valid kid=%d type=%s", kid, typ), map[string]any{"valid": true, "kid": kid, "type": typ})
}

// check verifies a statement given as its line plus a signature, or as the two-line wire form
// ("<line>\nsig=<b64url>") in s alone. It returns typ == "" when the signature is invalid; the type
// echoed back is the statement's first token, constrained to ValidType, never free text.
func (s *Signer) check(st, sig string) (kid int, typ string, err error) {
	if len(st) > MaxLine+MaxSig+1 || len(sig) > MaxSig {
		return 0, "", core.E(413, "size", "statement or signature too long")
	}
	if sig == "" {
		if a, b, ok := strings.Cut(st, "\n"); ok && strings.HasPrefix(strings.TrimSpace(b), "sig=") {
			st, sig = a, strings.TrimSpace(b)
		}
	}
	st = strings.TrimSpace(st)
	if st == "" || sig == "" {
		return 0, "", core.Bad("s (statement line) and sig (base64url) required")
	}
	if len(st) > MaxLine || !OneLine(st) {
		return 0, "", nil
	}
	typ = TypeOf(st)
	if typ == "" {
		return 0, "", nil
	}
	kid, ok := s.Verify(typ, st, sig)
	if !ok {
		return 0, "", nil
	}
	return kid, typ, nil
}

// text is the compact rendering of the key for the MCP op.
func (s *Signer) text() string {
	wk := s.WellKnown()
	var b strings.Builder
	fmt.Fprintf(&b, "kid=%d alg=%s pub=%s", wk.KID, wk.Alg, wk.Pub)
	for _, p := range wk.Prev {
		fmt.Fprintf(&b, "\nprev kid=%d pub=%s", p.KID, p.Pub)
	}
	fmt.Fprintf(&b, "\ndomain=%s\\0<type>\\0<line>\ntypes=%s", Domain, strings.Join(wk.Types, " "))
	return b.String()
}

var openapi = json.RawMessage(`{"paths":{
"/.well-known/cx-key":{"get":{"operationId":"key","tags":["sig"],"summary":"Server statement key: Ed25519 public key, current and previous key ids, signing domain, known statement types",
 "responses":{"200":{"description":"{kid, alg, pub (hex), prev[{kid,pub}], domain, types[]}","content":{"application/json":{"schema":{"type":"object","properties":{"kid":{"type":"integer"},"alg":{"type":"string"},"pub":{"type":"string"},"prev":{"type":"array","items":{"type":"object","properties":{"kid":{"type":"integer"},"pub":{"type":"string"}}}},"domain":{"type":"string"},"types":{"type":"array","items":{"type":"string"}}}}}}}}}},
"/verify":{"get":{"operationId":"verify","tags":["sig"],"summary":"Verify a signed statement line; the type is the line's first token, the signature covers cx-sig-v1||0x00||type||0x00||line",
 "parameters":[{"name":"s","in":"query","required":true,"description":"the statement line (or the two wire lines: statement, sig=)","schema":{"type":"string","maxLength":8192}},
  {"name":"sig","in":"query","required":true,"description":"sig=<base64url> or the bare base64url token","schema":{"type":"string","maxLength":128}}],
 "responses":{"200":{"description":"valid kid=<n> type=<typ> | invalid","content":{"text/plain":{"schema":{"type":"string"}},"application/json":{"schema":{"type":"object","properties":{"valid":{"type":"boolean"},"kid":{"type":"integer"},"type":{"type":"string"}}}}}}}}}
}}`)
