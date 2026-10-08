package libwatch

import "encoding/json"

// llmsText is the /llms-full.txt section for libwatch (8.6).
const llmsText = `libwatch (environment manifests, drift, cutoff probe)
POST /v1/env?fmt=pkg|req|gomod|cargo|env&name= — body is your raw manifest (<= 64 KiB, <= 400 libs).
  Reply: 'env <name> libs=N known=K drift=D' then one line per drifting lib
  'npm:react have=18.2.0 latest=19.1.0 brk=3 sec=1 eol=- newest=2026-09-30' (security first). ?all=1 lists every lib.
GET /v1/env — your manifests. GET /v1/env/{name} — re-check one. PUT /v1/env/{name} {"alerts":false} — mute digests.
GET /v/env?libs=a@1,b@2 — anonymous drift check (<= 20 libs, nothing stored).
GET /cutoff/probe?seed=<s>&n=10..20 — a deterministic sample of real releases (no dates) + 2 decoys.
  Answer in the same call: GET /cutoff/probe?seed=<s>&a=1:y,2:n,3:u,… -> 'cutoff~YYYY-MM conf=… known=k/n decoys_yes=d/2 window=…'.
Ops: env{body,fmt,name}, envg{name}, cutoffp{seed,a,save}.`

// openAPI is the libwatch fragment merged into /openapi.json (27.2).
var openAPI = json.RawMessage(`{
"/v1/env":{"post":{"operationId":"env","summary":"Store an environment manifest and get a drift report","parameters":[{"name":"fmt","in":"query","schema":{"type":"string","enum":["pkg","req","gomod","cargo","env"]}},{"name":"name","in":"query","schema":{"type":"string","maxLength":32}},{"name":"all","in":"query","schema":{"type":"string","enum":["1"]}}],"requestBody":{"content":{"text/plain":{"schema":{"type":"string","maxLength":65536}}}},"responses":{"200":{"description":"env <name> libs=N known=K drift=D then per-lib drift lines"},"400":{"description":"err bad (fmt, name)"},"409":{"description":"err quota (too many manifests)"}}},"get":{"operationId":"envs","summary":"List your environment manifests","responses":{"200":{"description":"manifest rows"}}}},
"/v1/env/{name}":{"get":{"operationId":"envg","summary":"Re-check one manifest's drift","parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}},{"name":"all","in":"query","schema":{"type":"string","enum":["1"]}}],"responses":{"200":{"description":"drift report"},"404":{"description":"err notfound"}}},"put":{"operationId":"envset","summary":"Toggle a manifest's alert subscription","parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"alerts":{"type":"boolean"}},"required":["alerts"]}}}},"responses":{"200":{"description":"ok <name> alerts=on|off"},"404":{"description":"err notfound"}}}},
"/v/env":{"get":{"operationId":"venv","summary":"Anonymous drift check (nothing stored)","parameters":[{"name":"libs","in":"query","required":true,"schema":{"type":"string"},"description":"a@1,b@2 (<= 20 libs)"}],"responses":{"200":{"description":"drift report"},"400":{"description":"err bad"}}}},
"/cutoff/probe":{"get":{"operationId":"cutoffp","summary":"Deterministic knowledge-cutoff probe: a seeded sample of real releases + 2 decoys, scored from your yes/no/unsure answers","parameters":[{"name":"seed","in":"query","required":true,"schema":{"type":"string","maxLength":128}},{"name":"n","in":"query","schema":{"type":"integer","minimum":10,"maximum":20}},{"name":"a","in":"query","schema":{"type":"string"},"description":"answers 1:y,2:n,3:u,…"},{"name":"save","in":"query","schema":{"type":"string","enum":["1"]}}],"responses":{"200":{"description":"the sample list, or cutoff~YYYY-MM conf=… known=k/n decoys_yes=d/2 window=…"},"400":{"description":"err bad (seed, n)"},"409":{"description":"err sparse (too few releases)"}}}}
}`)
