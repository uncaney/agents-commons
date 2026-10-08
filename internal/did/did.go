// Package did serves the commons' did:web documents (SPEC-v2 27.7, 27.1 signed provenance):
//
//   - GET /.well-known/did.json: did:web:<host>, the server statement key (sign) as a
//     JsonWebKey2020 verification method (#k<kid>, previous key ids as further methods),
//     assertionMethod, and the A2A/MCP/LinkedDomains services.
//   - GET /a/{id}/did.json: did:web:<host>:a:<id>, whose verification method is the agent's own
//     published identity key from the key directory (26, P64) — never server-minted. 404 when the
//     identity published no bundle; a "tofu" note when the bundle is unwitnessed.
//
// It also installs sign.JWSHeaderExtraFn so ?f=jws statements carry a jku pointing at the JWKS.
// The server holds no key here; the signing key is internal/sign's.
package did

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
	"ekaii.fr/commons/internal/sign"
)

// Seams set by the integration package; every document renders without them (nil-safe).
var (
	// HasCardFn reports whether the identity published an A2A card, so the agent DID lists its
	// service endpoints (P110 agent_cards). nil → no service entries.
	HasCardFn func(ctx context.Context, root string) bool
	// WitnessedFn reports whether the identity's current key bundle is covered by an external
	// witness (26.6). nil or false → the DID carries the "tofu" note (trust on first use).
	WitnessedFn func(ctx context.Context, root string) bool
)

const didContentType = "application/did+json"

type handlers struct {
	d    *core.Deps
	base string // public URL without trailing slash
	host string // authority of the public URL (the did:web method-specific id)
}

// Help is the op-list line merged into the MCP help (reads only).
const Help = `did: GET /.well-known/did.json server did:web document | GET /a/{id}/did.json agent did:web document (from the published key)`

// Register mounts the two DID documents (anonymous reads), installs the JWS jku header seam and
// registers the OpenAPI fragment. Both documents are listed in /.well-known/api-catalog (P44a).
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d: d, base: strings.TrimRight(d.Cfg.PublicURL, "/")}
	h.host = authorityOf(h.base)
	sign.JWSHeaderExtraFn = h.jwsHeaders
	mux.HandleFunc("GET /.well-known/did.json", h.serverDID)
	mux.HandleFunc("GET /a/{id}/did.json", h.agentDID)
	d.RegisterCost("GET /.well-known/did.json", 1)
	d.RegisterCost("GET /a/{id}/did.json", 1)
	d.RegisterOpenAPI(openapi)
}

// jwsHeaders is sign.JWSHeaderExtraFn: it adds jku (the JWKS URL) to a ?f=jws protected header. It
// never sets alg, kid or cty (the JWS helper owns those and overrides any attempt).
func (h *handlers) jwsHeaders(kid int) map[string]any {
	return map[string]any{"jku": h.base + "/.well-known/jwks.json"}
}

// jwk is the OKP Ed25519 public key JWK embedded in a verification method.
func jwk(pub []byte) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

func (h *handlers) serverDID(w http.ResponseWriter, r *http.Request) {
	did := "did:web:" + h.host
	s := sign.Default()
	var methods []map[string]any
	var assertion []string
	add := func(kid int, pub []byte) {
		id := did + "#k" + strconv.Itoa(kid)
		methods = append(methods, map[string]any{
			"id": id, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk(pub),
		})
		assertion = append(assertion, id)
	}
	add(s.KID(), s.Public())
	for _, p := range s.Prev() {
		if pub, err := hex.DecodeString(p.Pub); err == nil {
			add(p.KID, pub)
		}
	}
	doc := map[string]any{
		"@context":           []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		"id":                 did,
		"verificationMethod": methods,
		"assertionMethod":    assertion,
		"authentication":     assertion,
		"service": []map[string]any{
			{"id": did + "#a2a", "type": "A2A", "serviceEndpoint": h.base + "/a2a"},
			{"id": did + "#mcp", "type": "MCP", "serviceEndpoint": h.base + "/mcp"},
			{"id": did + "#ld", "type": "LinkedDomains", "serviceEndpoint": h.base},
		},
	}
	h.write(w, r, doc)
}

func (h *handlers) agentDID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !e2e.ValidID(id) {
		core.Err(w, r, 404, "notfound", "no key published")
		return
	}
	b, ok, err := keys.Bundle(r.Context(), h.d.DB, id)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if !ok {
		core.Err(w, r, 404, "notfound", "no key published")
		return
	}
	did := "did:web:" + h.host + ":a:" + id
	vmID := did + "#ik"
	doc := map[string]any{
		"@context":    []string{"https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"},
		"id":          did,
		"alsoKnownAs": []string{h.base + "/a/" + id},
		"verificationMethod": []map[string]any{{
			"id": vmID, "type": "JsonWebKey2020", "controller": did, "publicKeyJwk": jwk(b.IK),
		}},
		"assertionMethod": []string{vmID},
		"authentication":  []string{vmID},
	}
	if svc := h.agentServices(r.Context(), did, id); len(svc) > 0 {
		doc["service"] = svc
	}
	if !h.witnessed(r.Context(), id) {
		doc["note"] = "tofu: this identity key is trusted on first use; it is not witnessed by an external log"
	}
	h.write(w, r, doc)
}

// agentServices lists the agent's A2A endpoint and agent card when a card exists.
func (h *handlers) agentServices(ctx context.Context, did, id string) []map[string]any {
	if HasCardFn == nil || !HasCardFn(ctx, id) {
		return nil
	}
	return []map[string]any{
		{"id": did + "#a2a", "type": "A2A", "serviceEndpoint": h.base + "/a2a/" + id},
		{"id": did + "#agent", "type": "A2ACard", "serviceEndpoint": h.base + "/a/" + id + "/agent.json"},
	}
}

func (h *handlers) witnessed(ctx context.Context, id string) bool {
	return WitnessedFn != nil && WitnessedFn(ctx, id)
}

// write emits a DID document with an ETag and a one-hour public cache (27.7).
func (h *handlers) write(w http.ResponseWriter, r *http.Request, doc map[string]any) {
	body, err := json.Marshal(doc)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:])[:16] + `"`
	h2 := w.Header()
	h2.Set("Content-Type", didContentType)
	h2.Set("Cache-Control", "public, max-age=3600")
	h2.Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(200)
	w.Write(body)
}

// authorityOf is the host[:port] of a base URL (the did:web method-specific id).
func authorityOf(base string) string {
	b := strings.TrimPrefix(strings.TrimPrefix(base, "https://"), "http://")
	if i := strings.IndexByte(b, '/'); i >= 0 {
		b = b[:i]
	}
	return b
}

var openapi = json.RawMessage(`{"paths":{
"/.well-known/did.json":{"get":{"operationId":"did","tags":["sig"],"summary":"Server did:web document: the signing key as a verification method, with A2A/MCP/LinkedDomains services",
 "responses":{"200":{"description":"a did:web DID document","content":{"application/did+json":{"schema":{"type":"object"}}}}}}},
"/a/{id}/did.json":{"get":{"operationId":"agentDid","tags":["sig"],"summary":"Agent did:web document from the identity's own published key; 404 when no key was published",
 "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],
 "responses":{"200":{"description":"a did:web DID document","content":{"application/did+json":{"schema":{"type":"object"}}}},
  "404":{"description":"err notfound no key published"}}}}
}}`)
