// Package httpsig signs the machine renditions of the commons with RFC 9421 HTTP Message
// Signatures and the matching Content-Digest, and publishes the server's signing key as a JWKS
// (SPEC-v2 27.1 signed provenance, 27.7 did:web).
//
// Middleware (installed by the integration package P60a for the path classes .md/.txt/.jsonld,
// /export/*, /sitemaps/*, /llms*.txt, /index.md) adds, over the response body:
//
//	Content-Digest: sha-256=:<b64>:
//	Signature-Input: cx=("@authority" "@path" "content-digest" "content-type");created=<unix>;keyid="<kid>";alg="ed25519"
//	Signature:       cx=:<b64>:
//
// The signature covers the RFC 9421 signature base built in the standard library. Static bytes are
// signed once per (ETag, authority, path, content-type) and the result is kept in a ByteLRU; renditions
// without an ETag are signed per request. Signing is skipped under shed:anon-search. CardSig signs the
// agent and server cards (web.CardSigFn). The key is the server statement key (internal/sign); nothing
// here holds a private key of its own.
package httpsig

import (
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/sign"
)

// Label is the RFC 9421 signature label this server uses for its provenance signatures.
const Label = "cx"

// Alg is the signature algorithm name carried in Signature-Input (RFC 9421 registry).
const Alg = "ed25519"

// coveredComponents is the ordered inner list of the signature: the two derived components and the
// two content headers every signed rendition carries.
var coveredComponents = []string{"@authority", "@path", "content-digest", "content-type"}

// b64 is standard base64 with padding, the serialization of sf-binary (:…:) values in RFC 9421 and
// RFC 9530 (Content-Digest).
var b64 = base64.StdEncoding

// KIDString is the current signing key id as the string used in keyid="…", JWKS kid and the card
// JWS protected header, so a verifier maps one to the other.
func KIDString() string { return strconv.Itoa(sign.KID()) }

// kidString renders any key id the same way.
func kidString(kid int) string { return strconv.Itoa(kid) }

// Digest is the Content-Digest header value for body: sha-256=:<base64>:.
func Digest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha-256=:" + b64.EncodeToString(sum[:]) + ":"
}

// Params is the @signature-params value: the covered inner list followed by created, keyid and alg.
// It is both the Signature-Input value (prefixed with the label) and the last signature-base line.
func Params(created int64, kid string) string {
	var b strings.Builder
	b.WriteByte('(')
	for i, c := range coveredComponents {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteByte('"')
		b.WriteString(c)
		b.WriteByte('"')
	}
	b.WriteString(");created=")
	b.WriteString(strconv.FormatInt(created, 10))
	b.WriteString(`;keyid="`)
	b.WriteString(kid)
	b.WriteString(`";alg="`)
	b.WriteString(Alg)
	b.WriteString(`"`)
	return b.String()
}

// SignatureBase builds the RFC 9421 signature base for the four covered components plus the
// @signature-params line (§2.5). Component identifiers are lowercase and quoted; the value of each
// derived component and header is one line; lines are joined by "\n" with no trailing newline.
// authority is lowercased (host is case-insensitive); path is the request target path as sent.
func SignatureBase(authority, path, contentDigest, contentType, params string) []byte {
	var b strings.Builder
	line := func(id, val string) {
		b.WriteByte('"')
		b.WriteString(id)
		b.WriteString(`": `)
		b.WriteString(val)
		b.WriteByte('\n')
	}
	line("@authority", strings.ToLower(authority))
	line("@path", path)
	line("content-digest", contentDigest)
	line("content-type", contentType)
	// @signature-params closes the base and carries no trailing newline.
	b.WriteString(`"@signature-params": `)
	b.WriteString(params)
	return []byte(b.String())
}

// signatureHeader is the Signature value for a raw 64-byte ed25519 signature: cx=:<base64>:.
func signatureHeader(raw []byte) string {
	return Label + "=:" + b64.EncodeToString(raw) + ":"
}

// inputHeader is the Signature-Input value: cx=<params>.
func inputHeader(params string) string { return Label + "=" + params }
