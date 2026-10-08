package keys

import "encoding/json"

// llmsText is the /llms-full.txt section of the key directory.
const llmsText = `## keys: key directory and transparency log (sealed lane)
The first key bundle is born inside POST /v1/register {"bundle": "<base64 canonical||sigs>"} for the id announced by POST /v1/challenge (id=). Later bundles: PUT /v1/keys (raw bytes, X-Cx-Sig under the current rk, seq+1, prev_hash = sha256 of the current canonical bundle); a changed ik needs sig_prev and stays pending 24 h.
GET /v1/keys/<id> -> "id= seq= iat= ik= rk= ak= cs= ek= lk_ok= pol= fp= leaf= size= head= pending=" then the raw bundle (base64url): verify the bytes, never the parse. GET /v1/keys/<id>/hist, GET /v1/keys/<id>?leaf=<idx>, GET /v1/keys/server (online key, cert, witness keys: check them against the mirror).
Log (RFC 6962): GET /v1/log/sth "size= root= at= sig= cert=" + cosign lines; GET /v1/log/incl?leaf=&size=; GET /v1/log/cons?from=&to=; GET /v1/log?from=&n=; GET /v1/log/id/<id>. Every /v1 reply carries CX-STH: <size>:<root16>; keys, log and policy replies carry X-Cx-Sig-Server (t=,s=) over the body.
GET /v1/pk/<id> -> "pk1 id= ik= n= t= k=1" + sig= (verify at GET /verify); each publication is stamped into /ts (h = sha256("pk\0"||id||"\0"||bundle_hash)) and published as an event of kind pk. GET /v1/policy is the signed policy pack (secret patterns, buckets, caps, batch hours), its hash logged as a kind 5 leaf.
Writes on the sealed lane carry X-Cx-Sig: v1,<ts>,<nonce>,<sig> = Ed25519(rk, "cx1/req"||0||METHOD||\n||path?query||\n||u64(ts)||nonce||sha256(body)); nonces are single-use, |now-ts| <= 300 s (X-Now tells the server clock).`

var openAPI = json.RawMessage(`{"paths":{
"/v1/keys":{"put":{"operationId":"keysPut","tags":["keys"],"summary":"Publish the next key bundle (raw canonical||sigs, X-Cx-Sig under the current rk, seq+1); seq 1 without any bundle is the 24 h pending legacy path",
 "requestBody":{"required":true,"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary","maxLength":16384}}}},
 "responses":{"200":{"description":"ok seq=<n> leaf=<idx> bundle=<sha256 hex> head=<hex16> (X-Cx-Sig-Server)"},"202":{"description":"pending=1 until=<rfc3339>"},"400":{"description":"err bad seq want=<n> | err bad prev_hash | err sig"},"401":{"description":"err sig X-Cx-Sig required | err skew now=<unix>"},"409":{"description":"err keys contested | err sig nonce replayed"}}},
 "get":{"operationId":"keysOwn","tags":["keys"],"summary":"Your current bundle (token)","responses":{"200":{"description":"directory line + raw bundle"}}}},
"/v1/keys/{id}":{"get":{"operationId":"keysGet","tags":["keys"],"summary":"Current bundle of an id (anonymous, 5/s per network); ?leaf=<idx> an older one",
 "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string","pattern":"^[a-z][a-z2-7]{6}$"}},{"name":"leaf","in":"query","schema":{"type":"integer"}}],
 "responses":{"200":{"description":"id= seq= iat= ik= rk= ak= cs= ek= lk_ok= pol= fp= leaf= size= head= pending= then raw base64url; JSON with ?f=json"},"404":{"description":"err notfound no keys published"},"409":{"description":"err keys contested"},"410":{"description":"err revoked at=<date>"}}}},
"/v1/keys/{id}/hist":{"get":{"operationId":"keysHist","tags":["keys"],"summary":"Every bundle version logged for an id","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"seq= leaf= iat= fp= state= lines"}}}},
"/v1/keys/server":{"get":{"operationId":"keysServer","tags":["keys"],"summary":"Server keys: root=, online=, cert=, exp=, w1=, w2=, mirror= (check against the mirror; not a trust root)","responses":{"200":{"description":"one line"}}}},
"/v1/log/sth":{"get":{"operationId":"logSTH","tags":["log"],"summary":"Signed tree head: size= root= at= sig= cert= then cosign lines","parameters":[{"name":"size","in":"query","schema":{"type":"integer"}}],"responses":{"200":{"description":"head"}}}},
"/v1/log/incl":{"get":{"operationId":"logIncl","tags":["log"],"summary":"RFC 6962 audit path: idx= leaf= path=<hex,...> size=","parameters":[{"name":"leaf","in":"query","required":true,"schema":{"type":"integer"}},{"name":"size","in":"query","schema":{"type":"integer"}}],"responses":{"200":{"description":"path"}}}},
"/v1/log/cons":{"get":{"operationId":"logCons","tags":["log"],"summary":"RFC 6962 consistency path between two sizes: path=<hex,...> from= to=","parameters":[{"name":"from","in":"query","required":true,"schema":{"type":"integer"}},{"name":"to","in":"query","schema":{"type":"integer"}}],"responses":{"200":{"description":"path"}}}},
"/v1/log":{"get":{"operationId":"logDelta","tags":["log"],"summary":"Leaves from an index: <idx> <kind> <id> <item_hash> <leaf> lines (<= 500) then next=","parameters":[{"name":"from","in":"query","schema":{"type":"integer"}},{"name":"n","in":"query","schema":{"type":"integer","maximum":500}}],"responses":{"200":{"description":"lines"}}}},
"/v1/log/id/{id}":{"get":{"operationId":"logID","tags":["log"],"summary":"Every leaf of an id: <idx> <kind> <seq> <item_hash> <at>","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"lines"}}}},
"/v1/log/cosign":{"post":{"operationId":"logCosign","tags":["log"],"summary":"Cosign a head: an established root (token + X-Cx-Sig, signature by its ik) once per hour, or a configured witness (w)",
 "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["size","sig"],"properties":{"size":{"type":"integer"},"sig":{"type":"string","maxLength":128},"w":{"type":"string","maxLength":16}}}}}},
 "responses":{"200":{"description":"ok size= root="},"403":{"description":"err auth established roots only"},"429":{"description":"err quota cosign: 1 per hour"}}}},
"/v1/policy":{"get":{"operationId":"policy","tags":["keys"],"summary":"Signed policy pack {v, rules_v, secret_regexes, buckets, caps, banner, min_cs, batch_hours, stamp_bits}; X-Cx-Policy: v= hash= leaf=","responses":{"200":{"description":"JSON (X-Cx-Sig-Server)"}}}},
"/v1/pk/{id}":{"get":{"operationId":"pk","tags":["keys"],"summary":"Signed key line: pk1 id= ik= n= t= k=1 then sig= (verify at /verify)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"two lines"},"404":{"description":"err notfound"}}}},
"/admin/online-key":{"post":{"operationId":"adminOnlineKey","tags":["admin"],"summary":"Install a root-signed online certificate (admin token)",
 "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["cert"],"properties":{"cert":{"type":"string","maxLength":256}}}}}},
 "responses":{"200":{"description":"ok seq= exp="}}}}
}}`)
