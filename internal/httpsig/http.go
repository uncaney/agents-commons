package httpsig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/web"
)

const maxVerifyBody = 1 << 20

// Help is the op-list line merged into the MCP help (reads only).
const Help = `httpsig: GET /.well-known/jwks.json server signing keys (JWKS) | GET /revoked-kids.txt | POST /verify check a signed rendition (body + Content-Digest/Signature-Input/Signature)`

type handlers struct{ d *core.Deps }

// Register installs the card signer (web.CardSigFn) and the signature cache, and mounts
// GET /.well-known/jwks.json, GET /revoked-kids.txt and POST /verify (anonymous reads). The
// provenance Middleware is installed separately by the integration package (P60a).
func Register(mux *http.ServeMux, d *core.Deps) {
	if sigCache == nil {
		sigCache = core.NewByteLRU(1 << 20)
	}
	// Serve cards signed with the server key (A2A AgentCardSignature, x-signature), unless another
	// package already claimed the seam.
	if web.CardSigFn == nil {
		web.CardSigFn = CardSig
	}
	h := &handlers{d}
	mux.HandleFunc("GET /.well-known/jwks.json", h.jwks)
	mux.HandleFunc("GET /revoked-kids.txt", h.revoked)
	mux.HandleFunc("POST /verify", h.verify)
	d.RegisterCost("GET /.well-known/jwks.json", 1)
	d.RegisterCost("GET /revoked-kids.txt", 1)
	d.RegisterCost("POST /verify", 1)
	d.RegisterOpenAPI(openapi)
}

// CardSig implements web.CardSigFn: a detached JWS over the card bytes with the server key. protected
// is base64url({alg:"EdDSA",kid,typ:"JOSE"}); signature is base64url of ed25519(protected "." payload).
// The A2A AgentCardSignature and the x-signature of mcp.json/server.json share this shape (27.1).
func CardSig(card json.RawMessage) (protected, signature string) {
	s := sign.Default()
	hdr, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": kidString(s.KID()), "typ": "JOSE"})
	ue := base64.RawURLEncoding
	protected = ue.EncodeToString(hdr)
	input := protected + "." + ue.EncodeToString(card)
	signature = ue.EncodeToString(s.SignBytes([]byte(input)))
	return protected, signature
}

// jwkOf renders one Ed25519 public key as a JWK (RFC 8037 OKP).
func jwkOf(kid int, pub ed25519.PublicKey) map[string]any {
	return map[string]any{
		"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
		"kid": kidString(kid), "x": base64.RawURLEncoding.EncodeToString(pub),
	}
}

func (h *handlers) jwks(w http.ResponseWriter, r *http.Request) {
	s := sign.Default()
	keys := []map[string]any{jwkOf(s.KID(), s.Public())}
	for _, p := range s.Prev() {
		pub, err := hex.DecodeString(p.Pub)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		keys = append(keys, jwkOf(p.KID, ed25519.PublicKey(pub)))
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	core.JSON(w, 200, map[string]any{"keys": keys})
}

// revoked serves GET /revoked-kids.txt: one revoked key id per line, from flag httpsig:revoked-kids
// (space- or comma-separated), empty by default. Verifiers drop a Signature whose keyid is listed.
func (h *handlers) revoked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Robots-Tag", "noindex")
	var b strings.Builder
	for _, f := range strings.FieldsFunc(h.d.FlagStr("httpsig:revoked-kids"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if _, err := strconv.Atoi(f); err == nil {
			b.WriteString(f)
			b.WriteByte('\n')
		}
	}
	w.WriteHeader(200)
	w.Write([]byte(b.String()))
}

// verifyIn is the JSON body form of POST /verify; the header form carries the body as the raw request
// body and the signature in the Content-Digest/Signature-Input/Signature headers.
type verifyIn struct {
	Body      string `json:"body"`
	Sig       string `json:"sig"`       // the Signature value (cx=:…: or the bare base64)
	Input     string `json:"input"`     // the Signature-Input value (cx=…); carries created/keyid
	Path      string `json:"path"`      // the @path the rendition was served at
	CT        string `json:"ct"`        // the content-type the rendition carried
	Authority string `json:"authority"` // defaults to the server host
	Kid       string `json:"kid"`       // ignored; the keyid comes from Signature-Input
}

func (h *handlers) verify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Robots-Tag", "noindex")
	w.Header().Set("Cache-Control", "no-store")
	core.MaxBytes(w, r, maxVerifyBody)
	var in verifyIn
	ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	if strings.TrimSpace(ct) == "application/json" {
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			core.Fail(w, r, core.Bad("body: "+err.Error()))
			return
		}
	} else {
		body, err := core.ReadAll(w, r, maxVerifyBody)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		q := r.URL.Query()
		in = verifyIn{
			Body:      string(body),
			Sig:       r.Header.Get("Signature"),
			Input:     r.Header.Get("Signature-Input"),
			Path:      q.Get("path"),
			CT:        r.Header.Get("Content-Type"),
			Authority: q.Get("authority"),
		}
	}
	created, ok := h.check(r, in)
	if !ok {
		core.OK(w, r, "bad", map[string]any{"ok": false})
		return
	}
	core.OK(w, r, "ok type=page kid="+kidOf(in.Input)+" created="+core.Date(time.Unix(created, 0)),
		map[string]any{"ok": true, "type": "page", "kid": kidOf(in.Input), "created": created})
}

// check verifies a signed rendition: it rebuilds the RFC 9421 base from the supplied body (digest
// recomputed and thus bound to the exact bytes), the @path and content-type the caller gives, the
// authority (the server host by default), and the @signature-params taken verbatim from the
// Signature-Input value, then checks the signature against the keyid's published key.
func (h *handlers) check(r *http.Request, in verifyIn) (created int64, ok bool) {
	params := stripLabel(in.Input)
	if params == "" || in.Path == "" || in.CT == "" {
		return 0, false
	}
	rawSig, err := decodeSig(in.Sig)
	if err != nil {
		return 0, false
	}
	kid, err := strconv.Atoi(kidOf(in.Input))
	if err != nil {
		return 0, false
	}
	pub, found := sign.Default().PublicOf(kid)
	if !found {
		return 0, false
	}
	authority := in.Authority
	if authority == "" {
		authority = serverHost(h.d)
	}
	digest := Digest([]byte(in.Body))
	base := SignatureBase(authority, in.Path, digest, in.CT, params)
	if !ed25519.Verify(pub, base, rawSig) {
		return 0, false
	}
	return createdOf(in.Input), true
}

// serverHost is the authority of the configured public URL (so a caller may omit it).
func serverHost(d *core.Deps) string {
	b := strings.TrimPrefix(strings.TrimPrefix(d.Cfg.PublicURL, "https://"), "http://")
	if i := strings.IndexAny(b, "/"); i >= 0 {
		b = b[:i]
	}
	return b
}

// stripLabel drops a leading "cx=" from a Signature-Input value, leaving the @signature-params text.
func stripLabel(v string) string {
	v = strings.TrimSpace(v)
	if p := Label + "="; strings.HasPrefix(v, p) {
		return strings.TrimSpace(v[len(p):])
	}
	return ""
}

// decodeSig decodes a Signature value (cx=:<base64>: or the bare base64, padded or not) to 64 bytes.
func decodeSig(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if p := Label + "="; strings.HasPrefix(v, p) {
		v = v[len(p):]
	}
	v = strings.TrimPrefix(v, ":")
	v = strings.TrimSuffix(v, ":")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(v); err == nil && len(raw) == ed25519.SignatureSize {
			return raw, nil
		}
	}
	return nil, core.Bad("signature")
}

// kidOf extracts the keyid of a Signature-Input value: ;keyid="<kid>".
func kidOf(input string) string { return param(input, "keyid") }

// createdOf extracts the created unix seconds of a Signature-Input value.
func createdOf(input string) int64 {
	n, _ := strconv.ParseInt(param(input, "created"), 10, 64)
	return n
}

// param reads a Signature-Input parameter value, with or without the surrounding quotes.
func param(input, name string) string {
	i := strings.Index(input, ";"+name+"=")
	if i < 0 {
		return ""
	}
	v := input[i+len(name)+2:]
	if strings.HasPrefix(v, `"`) {
		v = v[1:]
		if j := strings.IndexByte(v, '"'); j >= 0 {
			return v[:j]
		}
		return ""
	}
	j := strings.IndexAny(v, ";, ")
	if j >= 0 {
		v = v[:j]
	}
	return v
}

var openapi = json.RawMessage(`{"paths":{
"/.well-known/jwks.json":{"get":{"operationId":"jwks","tags":["sig"],"summary":"Server signing keys as a JWKS (RFC 8037 OKP Ed25519): the current key and previous key ids",
 "responses":{"200":{"description":"{keys:[{kty,crv,kid,alg,use,x}]}","content":{"application/json":{"schema":{"type":"object","properties":{"keys":{"type":"array","items":{"type":"object"}}}}}}}}}},
"/revoked-kids.txt":{"get":{"operationId":"revokedKids","tags":["sig"],"summary":"Revoked signing key ids, one per line (empty by default)",
 "responses":{"200":{"description":"text, one kid per line","content":{"text/plain":{"schema":{"type":"string"}}}}}}},
"/verify":{"post":{"operationId":"verifyPage","tags":["sig"],"summary":"Verify a signed rendition: the body plus its Content-Digest, Signature-Input and Signature headers (RFC 9421)",
 "parameters":[{"name":"path","in":"query","required":true,"description":"the @path the rendition was served at","schema":{"type":"string"}}],
 "requestBody":{"description":"the raw rendition bytes; Content-Type is the rendition content-type; the three signature headers carry the signature","content":{"text/plain":{"schema":{"type":"string"}},"application/json":{"schema":{"type":"object","properties":{"body":{"type":"string"},"sig":{"type":"string"},"input":{"type":"string"},"path":{"type":"string"},"ct":{"type":"string"}}}}},
 "responses":{"200":{"description":"ok type=page kid=<k> created=<date> | bad","content":{"text/plain":{"schema":{"type":"string"}}}}}}}
}}`)
