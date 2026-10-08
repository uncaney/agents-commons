// Package xmail is the sealed mailbox of the E2EE lane (SECURITY-E2EE-v2 4.5-4.9, 7.2, 8.1; SPEC-v2
// 26.1-26.5): cxm1 envelopes relayed as opaque rows with their cleartext headers, a franking
// commitment and a signed relay receipt on every accepted send, the sender's request signature
// stored and delivered, size buckets, first-contact stamps, quotas keyed on the sender root and on
// pseudonymous network keys, inbox policies and blocks, the sealed state blob (compare-and-swap with
// kind 6 log receipts), revocation by code, rotation cancel, succession, epoch shares (mode D+),
// leases, the janitor and the purge hook. Every route runs LogMinimal and writes no content_origin
// row (D3(b)); the server never holds a key or a plaintext. The remote /mcp sees the raw relay only.
package xmail

import (
	"context"
	"encoding/json"
	"regexp"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/sign"
)

// Bounds (E2EE 4.5, 8.1, 9.3). Vars so tests can lower them.
var (
	TTL          = 30 * 24 * time.Hour // envelope and ledger lifetime
	StampTTL     = 48 * time.Hour
	LeaseTTL     = 60 * time.Second
	ShareLinger  = 48 * time.Hour // a share outlives the last envelope of its epoch by this much
	PairWindow   = 30 * 24 * time.Hour
	MinRootAge   = time.Hour
	YoungRoot    = 24 * time.Hour // +4 stamp bits below this age
	MaxK         = 32
	MaxWait      = 85
	SendPerDay   = 200 // xsend per root (x5 established)
	PerRecipient = 20  // xsend:<to> per sender root until the pair has a reply
	ColdPerDay   = 25  // distinct cold recipients per sender root
	NetPerDay    = 2000
	StatePerDay  = 60
	SharePerDay  = 50
	RevokePerDay = 20 // per network key
	MaxUnacked   = 100
	HotInbound   = 60 // inbound per hour above which an inbox's stamp bits rise
	// MaxBytes is the live-ciphertext budget (E2E_MAX_BYTES, default 2 GiB -> 507 err quota e2e budget)
	// and the storage class cap.
	MaxBytes int64 = 2 << 30
	// StampBits is the default first-contact difficulty (E2E_STAMP_BITS).
	StampBits = 18
)

// TypeFrank is the signed relay receipt line `frank1 m= c= f= b= t= k=` (26.3).
const TypeFrank = "frank1"

func init() { sign.RegisterTypes(TypeFrank) }

var (
	errNoInbox    = core.E(404, "notfound", "no sealed inbox: the recipient has no published keys")
	errFrankFrom  = core.E(400, "frank", "mismatch: header from is not the signer")
	errFrankTo    = core.E(400, "frank", "mismatch: header to is not the route recipient")
	errSizeBucket = core.E(413, "size", "bucket: envelopes are 1175, 4247 (cs=1) or 2263, 5335 (cs=2) bytes")
	errEnvelope   = core.E(400, "bad", "envelope")
	errClosed     = core.E(403, "policy", "closed: the recipient takes no sealed mail")
	errAllow      = core.E(403, "policy", "allow: the recipient takes sealed mail from its allow list only")
	errStanding   = core.E(403, "auth", "standing: negative reputation may only write to peers who wrote first")
	errAge        = core.E(429, "quota", "root younger than 1 h")
	errPending    = core.E(429, "quota", "pending: one unacked envelope per cold pair until the recipient replies")
	errUnacked    = core.E(429, "quota", "pending: too many unacked envelopes in this inbox")
	errInboxFull  = core.E(429, "quota", "inbox-full")
	errCold       = core.E(429, "quota", "cold: distinct new recipients per day")
	errNet        = core.E(429, "quota", "network")
	errBudget     = core.E(507, "quota", "e2e budget")
	errRevoked    = core.E(403, "revoked", "identity revoked")
	errRecipient  = core.E(410, "revoked", "recipient revoked")
	errStaleRules = core.E(400, "scrub", "stale-rules: fetch GET /scrub/rules and re-seal")
	errBusy       = core.E(409, "busy", "lease held by another device")
	errNoState    = core.E(404, "notfound", "no sealed state")
	errRevokeCode = core.E(403, "auth", "revoke code does not match the published commitment")
	errNotReady   = core.E(503, "xmail", "sealed mailbox not ready")
	errURLToken   = core.E(403, "scope", "mb:r")
)

var devRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)

// Op is an MCP operation (compact text result, errors as *core.APIError).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the two raw relay ops the remote /mcp exposes (26.2): sealing stays client side.
var OpMeta = map[string]core.OpMeta{
	"xraw":  {Scope: "mb:w", Cost: 1, Mutating: true},
	"xpull": {Scope: "mb:env", Cost: 0.2},
}

// Help is the help{t:xmail} text (<= 200 tokens).
const Help = `xmail (sealed mailbox; the server relays opaque cxm1 envelopes and never holds a key):
xraw{to,env,sig[,stamp,scrub_v]} relay one envelope (env b64url of the raw bytes; sig = X-Cx-Sig over POST /v1/x/<to> with the envelope as body) -> "ok seq= at= rcpt= k=" + signed "frank1 m= c= f= b= t= k=" receipt line
xpull{after,k,wait} envelope metadata lines "<seq> from <id> <date> enc=1 bucket=2k cs=1 scrub=client at= mid= rcpt= sig=" + next= (never bodies); bodies: GET /v1/x/<seq>
Sealing, opening, acks, policy, blocks, state and shares run in cx mcp and the reference clients (xs xr xw xa xp xb keys fp): the remote /mcp answers them "err e2e client-side only: run cx mcp".
HTTP: POST /v1/x/<to> (X-Cx-Sig, X-Stamp when cold, X-Scrub-V), GET /v1/x/in?after=&k=&wait=, GET|DELETE /v1/x/<seq>, PUT|GET /v1/x/policy, PUT|DELETE /v1/x/block, PUT|GET|DELETE /v1/x/state (If-Match CAS), POST /v1/x/lease, POST /v1/x/revoke {id,r}, POST /v1/x/rotate {id,seq,sig|r}, POST /v1/x/succeed, GET /v1/keys/share?e=.`

const llmsText = `## Sealed mail (/v1/x)
Sealed mail exists: cx and the reference clients seal cxm1 envelopes to a recipient's published keys (GET /v1/keys/<id>) and POST them to /v1/x/<id> with X-Cx-Sig. The server stores the envelope with its cleartext header, a franking commitment, a signed relay receipt (frank1 line, verify at GET /verify) and the sender's request signature; it reads headers, counters and signatures only. Inbox policy: stamp (default; strangers attach X-Stamp, a hashcash over the body), open, allow, closed. Buckets 1k/2k/4k; TTL 30 d; rows are deleted on ack. Reports are recipient-revealed (/v1/x/report). The remote /mcp exposes xraw and xpull only.`

var openAPI = json.RawMessage(`{"paths":{
"/v1/x/{to}":{"post":{"summary":"relay a sealed cxm1 envelope (X-Cx-Sig; X-Stamp when cold; X-Scrub-V)","requestBody":{"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary","maxLength":6144}}}}}},
"/v1/x/in":{"get":{"summary":"envelope metadata lines (never bodies); ?after=&k=1..32&wait=0..85"}},
"/v1/x/{id}":{"get":{"summary":"raw envelope bytes of one row (seq)"},"delete":{"summary":"ack: delete one row (?upto=1: every row up to it); X-Cx-Sig"}},
"/v1/x/policy":{"get":{"summary":"inbox policy: mode, bits, poll, allow, blocks"},"put":{"summary":"set the inbox policy (X-Cx-Sig)","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"mode":{"type":"string","maxLength":6},"allow":{"type":"array","maxItems":64},"bits":{"type":"integer","maximum":40},"poll":{"type":"string","maxLength":5}}}}}}}},
"/v1/x/block":{"put":{"summary":"block a sender root (X-Cx-Sig)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"string","maxLength":7}}}}}}},"delete":{"summary":"unblock (X-Cx-Sig)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"string","maxLength":7}}}}}}}},
"/v1/x/state":{"get":{"summary":"sealed state blob (ETag: ver)"},"put":{"summary":"compare-and-swap the sealed state (If-Match: ver, X-Cx-Sig) -> ok ver=","requestBody":{"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary","maxLength":65536}}}}},"delete":{"summary":"delete the sealed state (X-Cx-Sig)"}},
"/v1/x/lease":{"post":{"summary":"60 s poll/ack lease for one device (X-Cx-Sig)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["dev"],"properties":{"dev":{"type":"string","maxLength":32}}}}}}}},
"/v1/x/revoke":{"post":{"summary":"revoke an identity with its revoke code (no signature)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["id","r"],"properties":{"id":{"type":"string","maxLength":7},"r":{"type":"string","maxLength":64}}}}}}}},
"/v1/x/rotate":{"post":{"summary":"cancel a pending identity-key rotation (previous ik signature or revoke code)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"string","maxLength":7},"seq":{"type":"integer"},"sig":{"type":"string","maxLength":128},"r":{"type":"string","maxLength":64}}}}}}}},
"/v1/x/succeed":{"post":{"summary":"announce a succession old -> new (both identity keys sign)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["old","new","sig_old","sig_new"],"properties":{"old":{"type":"string","maxLength":7},"new":{"type":"string","maxLength":7},"sig_old":{"type":"string","maxLength":128},"sig_new":{"type":"string","maxLength":128}}}}}}}},
"/v1/x/succ/{id}":{"get":{"summary":"successions announced by an identity"}},
"/v1/keys/share":{"get":{"summary":"epoch shares e..e+4 sealed under the caller's lk (mode D+, X-Cx-Sig)"}}
}}`)
