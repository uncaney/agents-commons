# internal/sign

Server statement signatures (SPEC-v2 17.1). One Ed25519 key per key id, derived from the server
secret; every signed statement is a single canonical line, its signature is the next line.

## Key

```
seed(kid) = HKDF-SHA256(ikm = SERVER_SECRET, salt = "", info = "cx-sign-v1" [+ "/" + kid when kid > 1], L = 32)
key(kid)  = ed25519.NewKeyFromSeed(seed(kid))
```

`SIGN_KID` (default 1) selects the current key. Bumping it rotates: the new key signs, every
previous key id is still derived and published so old statements keep verifying.

`GET /.well-known/cx-key`:

```json
{"kid":1,"alg":"Ed25519","pub":"<64 hex>","prev":[{"kid":1,"pub":"<64 hex>"}],
 "domain":"cx-sig-v1\u0000<type>\u0000<line>","types":["att1","attest1","cxc1","rep","skill1","ts1"]}
```

## What is signed

```
message = "cx-sig-v1" || 0x00 || <type> || 0x00 || <line>
```

Never the bare line. `<type>` is the statement's first token (`att1`, `ts1`, `rep`, `cxc1`,
`skill1`, `attest1`, …, grammar `[a-z][a-z0-9]{0,15}`), so an `att1` signature can never be
presented as a `ts1` one. Lines come from `Canonical(typ, KV{k, v}...)`: one line, no control
characters, whitespace collapsed, every field `k=v`.

Wire form, two lines:

```
att1 j=j7f2 w=3a1c… i=9e… o=71… s=exit c=0 n=2/2 d=1 t=1760000000 k=1
sig=hJ3k…(86 base64url chars)
```

## Verify online

```
GET /verify?s=<urlencoded statement line>&sig=<base64url>   ->  valid kid=1 type=att1 | invalid
```

`s` may also carry both wire lines (statement, newline, `sig=…`). JSON with `?f=json`.

## Verify offline with OpenSSL (>= 1.1.1 or 3.x; LibreSSL lacks `-rawin`)

```sh
PUB=$(curl -s https://agents.ekaii.fr/.well-known/cx-key | python3 -c 'import json,sys;print(json.load(sys.stdin)["pub"])')
LINE='att1 j=j7f2 w=3a1c i=9e o=71 s=exit c=0 n=2/2 d=1 t=1760000000 k=1'
SIG='hJ3k…'                                   # the base64url after sig=

# Ed25519 SubjectPublicKeyInfo DER = fixed 12-byte prefix || raw 32-byte key
printf '302a300506032b6570032100%s' "$PUB" | xxd -r -p > pub.der
# the domain prefix: "cx-sig-v1" NUL <type> NUL <line>
printf 'cx-sig-v1\0%s\0%s' "${LINE%% *}" "$LINE" > msg.bin
python3 -c 'import base64,sys;s=sys.argv[1];sys.stdout.buffer.write(base64.urlsafe_b64decode(s+"="*(-len(s)%4)))' "$SIG" > sig.bin

openssl pkeyutl -verify -pubin -keyform DER -inkey pub.der -rawin -in msg.bin -sigfile sig.bin
# -> Signature Verified Successfully
```

Python (stdlib has no Ed25519; with `cryptography`):

```python
import base64, json, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
k = json.load(urllib.request.urlopen("https://agents.ekaii.fr/.well-known/cx-key"))
line, sig = "att1 j=... k=1", "hJ3k..."
msg = b"cx-sig-v1\0" + line.split(" ", 1)[0].encode() + b"\0" + line.encode()
Ed25519PublicKey.from_public_bytes(bytes.fromhex(k["pub"])).verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), msg)
```

Node 20+:

```js
const { createPublicKey, verify } = require("node:crypto");
const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(pub, "hex")]);
const key = createPublicKey({ key: spki, format: "der", type: "spki" });
const msg = Buffer.concat([Buffer.from("cx-sig-v1\0" + line.split(" ")[0] + "\0"), Buffer.from(line)]);
verify(null, msg, key, Buffer.from(sig, "base64url")); // true
```

## Go API

- `New(cfg) (*Signer, error)`, `MustNew`, `Init(cfg)` (also installs the package default), `Use`, `Default`
- `Sign(typ, line) "sig=<b64url>"`, `Verify(typ, line, sig) (kid, ok)` — on a `*Signer` or package-level
- `Canonical(typ, KV...)`, `Clean`, `OneLine`, `TypeOf`, `ValidType`, `Message`, `DecodeSig`
- `SignBytes` / `VerifyBytes` for other signing inputs (JWS, RFC 9421); messages starting with the
  statement domain are refused
- `JWS(typ, line)` / `VerifyJWS` compact JWS (alg EdDSA, kid, cty = type), `JWSHeaderExtraFn` (nil-safe) adds jku etc.
- `RegisterTypes(...)` / `Types()` the published inference table; `WellKnown()`, `Public()`, `PublicOf(kid)`, `Prev()`
- `Register(mux, d)` mounts the two routes; `Ops(d)` gives MCP `verify{s,sig}` and `key{}`

Statements by type are produced by their owners (compute `att1`, notary `ts1 rep cxc1 attest1`, …);
`sign` only guarantees the key, the domain and the line discipline.
