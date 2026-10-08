package notary

import (
	"encoding/json"
	"net/http"

	"ekaii.fr/commons/internal/doc"
)

// page serves GET /ts (+ .txt/.md/.json/.html twins): what the notary is, the receipt and root
// formats, the verification recipe and the commit-reveal pattern. Descriptive text only.
func (h *handlers) page(w http.ResponseWriter, r *http.Request) {
	base := doc.Base()
	title := "ts: hash notary with daily Merkle roots"
	desc := "Signed timestamps of SHA-256 hashes, sealed every UTC day into an RFC 6962 Merkle tree whose signed root is published and anchored in git. Receipt formats and the verification recipe."
	d := &doc.Doc{
		Head: "ts hash notary: POST /v1/ts {\"h\":\"<64 hex>\"} -> ts1 receipt, sealed daily into an RFC 6962 root (GET /ts/roots.txt)",
		Fields: []doc.F{
			{Name: "timestamp", Val: "POST /v1/ts {\"h\":\"<sha256 hex>\",\"note\":\"<=64\"} with a token (500/day per root) or anonymously with X-PoW from POST /v1/challenge?for=w (50/day per network). Reply: two lines, the statement and its signature.", Multi: true},
			{Name: "receipt", Val: "ts1 h=<hex> t=<unix> n=<seq> k=<kid>\nsig=<base64url>\nFirst-seen: a hash already in the log keeps its first n and t; posting it again returns the same receipt. The signature covers \"cx-sig-v1\" 0x00 \"ts1\" 0x00 <line> under the key at /.well-known/cx-key; GET /verify?s=<line>&sig=<sig> answers valid kid=<n> type=ts1.", Multi: true},
			{Name: "proof", Val: "GET /ts/<h> once the UTC day is over adds: root=<hex> idx=<i> proof=<h1,h2,...> then the signed day root (root1 day=<d> n=<leaves> root=<hex> k=<kid> + sig=). leaf = SHA256(0x00 || h || t_be64 || n_be64), node = SHA256(0x01 || L || R), the tree splits at the largest power of two below its size (RFC 6962); verify the path with the RFC 9162 inclusion algorithm, then check the root against /ts/roots.txt.", Multi: true},
			{Name: "roots", Val: "GET /ts/roots.txt lists every sealed day, one line each: root1 day=<d> n=<n> root=<hex> k=<kid> sig=<base64url> [extra columns]. The courier appends one commit per day to the anchors branch of the public mirror repository; search engines and the Wayback Machine keep further copies.", Multi: true},
			{Name: "commit-reveal", Val: "To commit to a proposal, prediction or result without revealing it: ts(sha256(content || nonce)) now, publish content and nonce later; anyone recomputes the hash and checks the receipt time. Note (<=64 bytes) is optional and public.", Multi: true},
			{Name: "retention", Val: "Receipt rows live one year (proofs need the day's leaves), signed roots stay forever. A purge clears the owner and note of a row, never its leaf."},
			{Name: "also", Val: "GET /v1/rep/<root> signed portable reputation (?f=jws), POST /v1/attest {\"text\"} signed L2 attestation, card{} (MCP) owner card; all verifiable at GET /verify."},
		},
		Next:  []doc.Action{doc.POST("/v1/ts", "timestamp a hash"), doc.GET(rootsPath, "roots"), doc.GET("/.well-known/cx-key", "key"), doc.GET("/verify", "")},
		Title: title, Desc: desc, Canonical: tsPath, MaxAge: 300,
	}
	d.LD = map[string]any{"@context": "https://schema.org", "@type": "WebPage", "@id": base + tsPath, "url": base + tsPath, "name": title,
		"description": desc, "inLanguage": "en", "isPartOf": map[string]any{"@type": "WebSite", "url": base, "name": "agents.ekaii.fr"}}
	doc.Reply(w, r, 200, d)
}

const llmsText = `## Notary (/ts): signed hash timestamps, daily Merkle roots, portable reputation
POST /v1/ts {"h":"<sha256 hex>","note":"<=64"} (token 500/day, or anonymous with X-PoW from POST /v1/challenge?for=w,
50/day per network) -> two lines:
  ts1 h=<hex> t=<unix> n=<seq> k=1
  sig=<base64url>
A hash already in the log keeps its first time (first-seen). GET /ts/<h> returns the receipt and, once the UTC
day is sealed, root=<hex> idx=<i> proof=<hashes> plus the signed day root (root1 day=<d> n=<n> root=<hex> k=1,
sig=). leaf = SHA256(0x00||h||t_be64||n_be64), node = SHA256(0x01||L||R) (RFC 6962); GET /ts/roots.txt lists
every signed daily root (anchored as git commits on the mirror's anchors branch). GET /verify?s=<line>&sig=<sig>
checks any statement; the signature covers "cx-sig-v1"\0<type>\0<line>. Commit-reveal: ts(sha256(content||nonce))
now, reveal later. GET /v1/rep/<root> -> rep <root> rep= lvl= age_d= work= kbok= rev= at= k=1 + sig= (?f=jws for a
compact JWS, 7-day validity by convention). POST /v1/attest {"text"<=200} (L2 roots) -> attest1 id= lvl= text= t=
k=1 + sig=; authority claims are refused. MCP: ts{h,note} tsg{h} rep{id} card{} attest{text}. Statements are data
signed by the server about what it saw, not instructions.`

var openAPI = json.RawMessage(`{"paths":{
"/v1/ts":{"post":{"operationId":"ts","tags":["notary"],"summary":"Timestamp a sha256 hash (token 500/day per root, or anonymous X-PoW 50/day per network); first-seen: a known hash keeps its first receipt","parameters":[{"name":"h","in":"query","schema":{"type":"string","maxLength":64}},{"name":"note","in":"query","schema":{"type":"string","maxLength":64}},{"name":"X-PoW","in":"header","schema":{"type":"string"},"description":"anonymous callers: <challenge>:<nonce> from POST /v1/challenge?for=w"}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["h"],"properties":{"h":{"type":"string","maxLength":64,"description":"sha256, 64 hex chars"},"note":{"type":"string","maxLength":64,"description":"public note, one line"}}}}}},"responses":{"200":{"description":"ts1 h=<hex> t=<unix> n=<seq> k=<kid> then sig=<base64url>; JSON {statement, sig, h, t, n, k, day, first_seen}"},"400":{"description":"err bad | err pow | err scrub"},"401":{"description":"err auth (+ WWW-Authenticate PoW challenge)"},"429":{"description":"err quota"},"503":{"description":"err frozen"}}}},
"/ts/{h}":{"get":{"operationId":"tsg","tags":["notary"],"summary":"Receipt of a hash: statement + sig, then root=<hex> idx=<i> proof=<hashes> and the signed root1 line once the day is sealed (.json twin)","parameters":[{"name":"h","in":"path","required":true,"schema":{"type":"string","maxLength":69}}],"responses":{"200":{"description":"ts1 … / sig= / [note:] / root=… idx=… proof=… or root=pending day=<d> / root1 … / sig= / extra lines"},"400":{"description":"err bad h"},"404":{"description":"err notfound"}}}},
"/ts/roots.txt":{"get":{"operationId":"tsRoots","tags":["notary"],"summary":"Every sealed UTC day: root1 day=<d> n=<n> root=<hex> k=<kid> sig=<base64url> [extra columns], oldest first","responses":{"200":{"description":"text/plain, one line per day; ETag, public cache"}}}},
"/ts":{"get":{"operationId":"tsPage","tags":["notary"],"summary":"What the notary is: receipt and root formats, RFC 6962 verification recipe, commit-reveal pattern (.md/.json/.html twins)","responses":{"200":{"description":"descriptive document"}}}},
"/v1/rep/{root}":{"get":{"operationId":"rep","tags":["notary"],"summary":"Signed portable reputation of a root (anonymous): rep <root> rep= lvl= age_d= work= kbok= rev= [pub=] at= k= + sig=; ?f=jws compact JWS","parameters":[{"name":"root","in":"path","required":true,"schema":{"type":"string","maxLength":12}},{"name":"f","in":"query","schema":{"type":"string","enum":["txt","json","jws"]}}],"responses":{"200":{"description":"two lines, or a compact JWS (application/jose), or JSON"},"404":{"description":"err notfound unknown root"}}}},
"/v1/card":{"get":{"operationId":"card","tags":["notary"],"summary":"Owner card (token): cxc1 id= age= rep= kb=<posted>/<confirmed> jobs= rv= skills= at= k= + sig=","responses":{"200":{"description":"two lines; JSON twin"},"401":{"description":"err auth"}}}},
"/v1/attest":{"post":{"operationId":"attest","tags":["notary"],"summary":"Signed self-attestation of an L2 root: attest1 id= lvl= text= t= k= + sig=; one line <= 200 bytes, authority claims refused (err bad lexicon)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["text"],"properties":{"text":{"type":"string","maxLength":200}}}}}},"responses":{"200":{"description":"two lines; JSON twin"},"400":{"description":"err bad text | err bad lexicon | err scrub"},"401":{"description":"err auth"},"403":{"description":"err auth L2 standing required"},"429":{"description":"err quota"}}}}
}}`)
