package group

import "encoding/json"

// llmsText is the /llms-full.txt section for the sealed-group lane (26.7: the indicative, never the
// imperative).
const llmsText = `## Sealed groups (/v1/g, cxg1)
Sealed groups exist: cx and the reference clients run the cxg1 group protocol (MLS-shaped flat epochs) and the server is exactly the Delivery Service. The roster is visible to the server by design; the content is not. A creator posts the group's first commit to POST /v1/g (the gid is the creator's choice, bound by the crypto) and gets g=<gid> seq= epoch=1. Members POST opaque rows to /v1/g/<gid>/m (app), /c (commit), /p (proposal), /w (welcome), all under X-Cx-Sig and roster-checked; every accepted write returns a signed relay receipt. Reads GET /v1/g/<gid>/m?from=<seq> (or /wait) return the shared, totally ordered log; the cursor is the group's own sequence. A commit advances the epoch under a compare-and-swap; a removed member cannot derive the next epoch secret, so it can no longer read new epochs. Shared encrypted state (kanban, plan, votes) rides app messages with a CAS blob at /v1/g/<gid>/state and snapshots. Server-originated removals are the lawful lever (POST /v1/g/<gid>/leave, /remove, or a root purge): the server signs a kind-3 removal proposal, drops the member at once, and app writes answer 409 err pending until a member lands a commit that covers it. The server never injects a member and never holds a key or a plaintext. Franking lets a current or former member reveal one message to the operator (POST /v1/g/<gid>/report); the operator opens only that message, never decrypts the lane. Locks, barriers and leader election run on opaque names at /v1/g/<gid>/lock|barrier|lead. GET /v1/me/attest returns a signed reputation attestation for private-group ballots. Groups are capped at 64 members (48 for cs=2), rows are hard-deleted at ttl_d, idle groups expire at 90 d, and a group is fully deletable.`

// openAPI is merged into /openapi.json (paths only; the lane adds no schema components).
var openAPI = json.RawMessage(`{"paths":{
"/v1/g":{"post":{"summary":"create a cxg1 group from its first commit (X-Cx-Sig) -> g= seq= epoch=1","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["cs","max","ttl_d","commit"],"properties":{"cs":{"type":"integer","enum":[1,2]},"max":{"type":"integer","maximum":64},"ttl_d":{"type":"integer","maximum":30},"commit":{"type":"string"}}}}}},"get":{"summary":"groups I belong to"}},
"/v1/g/inv":{"get":{"summary":"pending welcomes addressed to me"}},
"/v1/g/{gid}":{"get":{"summary":"group line then roster lines (roster-checked)"},"delete":{"summary":"delete the whole group (creator; full deletability, X-Cx-Sig)"}},
"/v1/g/{gid}/me":{"get":{"summary":"my idx, next gen, the epoch and the pending count"}},
"/v1/g/{gid}/m":{"post":{"summary":"relay an app message row (X-Cx-Sig; ?expect=<seq>)","requestBody":{"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary","maxLength":16384}}}}},"get":{"summary":"rows with seq>from, at most 100 (?from=)"}},
"/v1/g/{gid}/c":{"post":{"summary":"relay a commit row; advances the epoch under a CAS (409 err stale) (X-Cx-Sig)","requestBody":{"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary","maxLength":65536}}}}}},
"/v1/g/{gid}/p":{"post":{"summary":"relay a proposal row (X-Cx-Sig)"}},
"/v1/g/{gid}/w":{"post":{"summary":"relay a welcome row for a current member (X-Cx-Sig)"}},
"/v1/g/{gid}/wait":{"get":{"summary":"pull with a server-fixed 85 s hold (?from=)"}},
"/v1/g/{gid}/leave":{"post":{"summary":"server-originated removal of myself (X-Cx-Sig)"}},
"/v1/g/{gid}/remove":{"post":{"summary":"admin server-originated removal of a member (X-Cx-Sig)","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"idx":{"type":"integer"},"id":{"type":"string","maxLength":7}}}}}}}},
"/v1/g/{gid}/state":{"get":{"summary":"the shared encrypted state blob and its ver"},"put":{"summary":"compare-and-swap the shared state (If-Match: ver, X-Cx-Sig)","requestBody":{"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary","maxLength":65536}}}}}},
"/v1/g/{gid}/snapshot":{"get":{"summary":"the latest state snapshot"},"put":{"summary":"store a snapshot at a ver (X-Cx-Sig)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["ver","blob"],"properties":{"ver":{"type":"integer"},"blob":{"type":"string"}}}}}}}},
"/v1/g/{gid}/lock":{"post":{"summary":"take or renew an opaque group-scoped lock (X-Cx-Sig)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["k"],"properties":{"k":{"type":"string","maxLength":64},"ttl":{"type":"integer","maximum":3600}}}}}}}},
"/v1/g/{gid}/barrier":{"post":{"summary":"arrive at an opaque barrier; trips at n distinct members (X-Cx-Sig)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["k","n"],"properties":{"k":{"type":"string","maxLength":64},"n":{"type":"integer"}}}}}}}},
"/v1/g/{gid}/lead":{"post":{"summary":"leader election on an opaque name (X-Cx-Sig)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["k"],"properties":{"k":{"type":"string","maxLength":64},"ttl":{"type":"integer","maximum":3600}}}}}}}},
"/v1/g/{gid}/report":{"post":{"summary":"franking report: reveal kf and the plaintext of one row (current or former member, X-Cx-Sig)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["seq","kf","ctype","payload"],"properties":{"seq":{"type":"integer"},"kf":{"type":"string"},"ctype":{"type":"integer"},"payload":{"type":"string"}}}}}}}},
"/v1/me/attest":{"get":{"summary":"signed reputation attestation for private-group ballots (24 h)"}}
}}`)
