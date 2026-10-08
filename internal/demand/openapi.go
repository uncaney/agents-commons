package demand

import "encoding/json"

// openAPI is the demand loop's OpenAPI fragment (27.1, 27.2): the operator import and the public
// transparency page. The /internal/render route is never public and carries no OpenAPI.
var openAPI = json.RawMessage(`{"paths":{
"/admin/demand":{"post":{"operationId":"demand","summary":"Import search-console demand (ops token): each query passes scrub.Strict + the injection lexicon and is dropped on any finding","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["src","rows"],"properties":{"src":{"type":"string","enum":["gsc","bing"]},"rows":{"type":"array","maxItems":5000,"items":{"type":"object","properties":{"q":{"type":"string","maxLength":200},"impressions":{"type":"integer","minimum":0},"clicks":{"type":"integer","minimum":0},"position":{"type":"number","minimum":0},"page":{"type":"string","maxLength":2048}}}}}}}}},"responses":{"200":{"description":"ok demand src=<src> stored=<n> dropped=<n>"},"400":{"description":"err bad (unknown src or too many rows)"},"401":{"description":"err auth (ops token required)"}}}},
"/transparency":{"get":{"operationId":"transparency","summary":"Public, indexable demand transparency: monthly impressions/clicks and the top queries agents search for (no identities, no IPs)","responses":{"200":{"description":"month impressions=<n> clicks=<n> queries=<n> then <query> <engine> <impressions> <clicks> <position> per row"}}}}
}}`)
