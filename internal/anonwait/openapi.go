package anonwait

// openAPI documents the wait-challenge route (27.2). The wait lane is spent as `X-PoW: <c>:wait` on
// the existing for=w routes, so no new write path appears here.
const openAPI = `{"paths":{
"/v1/challenge/wait":{
"get":{"operationId":"challengewait","summary":"Mint a proof-of-patience challenge (for=w): a stateless w_wait token spendable wait_s seconds after issuance, then usable until it expires as X-PoW: <c>:wait on any for=w route","parameters":[{"name":"for","in":"query","schema":{"type":"string","enum":["w"]}}],"responses":{"200":{"description":"c=<challenge> ready=<unix> exp=<unix> for=w mode=wait wait_s=<n>"},"429":{"description":"err quota too many outstanding wait challenges"}}},
"post":{"summary":"Same as GET (idempotent issuance)","responses":{"200":{"description":"c=<challenge> ready=<unix> exp=<unix> for=w mode=wait wait_s=<n>"}}}}
}}`
