package web

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// ProfileFn serves the embed profiles of /openapi.json (?profile=min|read, ?tags=; 27.7). It gets
// the request and the merged document and returns the filtered bytes, or ok=false to serve the
// full document. P114 installs web.OpenAPIProfile; nil serves the full document for every query.
var ProfileFn func(r *http.Request, full []byte) ([]byte, bool)

// fragment is what every package passes to d.RegisterOpenAPI: paths (method -> operation) and
// components (section -> name -> schema). Anything else in a fragment is ignored.
type fragment struct {
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components map[string]map[string]json.RawMessage `json:"components"`
}

var httpMethods = map[string]bool{"get": true, "head": true, "post": true, "put": true, "patch": true, "delete": true, "options": true, "trace": true}

// assembled is one built /openapi.json: the bytes, the fragment count it was built from (a new
// registration triggers a rebuild) and the build time (Last-Modified).
type assembled struct {
	n    int
	at   time.Time
	body []byte
	dups int
}

var openapiCache sync.Map // *core.Deps -> *assembled

// OpenAPI returns the merged OpenAPI 3.1 document of every registered fragment plus web's own,
// rebuilt when a fragment was registered since the last build. Paths and methods are deduplicated
// (first registration wins) and the output is key-sorted, so the bytes are stable.
func OpenAPI(d *core.Deps) []byte {
	frags := d.OpenAPIFragments()
	if cur, ok := openapiCache.Load(d); ok && cur.(*assembled).n == len(frags) {
		return cur.(*assembled).body
	}
	a := assemble(d, Describe(d), frags)
	openapiCache.Store(d, a)
	return a.body
}

func assemble(d *core.Deps, x *Descriptor, frags []json.RawMessage) *assembled {
	paths := map[string]map[string]json.RawMessage{}
	comps := map[string]map[string]json.RawMessage{}
	dups := 0
	for _, f := range frags {
		var fr fragment
		if err := json.Unmarshal(f, &fr); err != nil {
			d.Log.Warn("openapi fragment skipped", "err", err)
			continue
		}
		for p, item := range fr.Paths {
			if !strings.HasPrefix(p, "/") || item == nil {
				continue
			}
			dst := paths[p]
			if dst == nil {
				dst = map[string]json.RawMessage{}
				paths[p] = dst
			}
			for k, v := range item {
				if _, seen := dst[k]; seen {
					if httpMethods[k] {
						dups++
					}
					continue
				}
				dst[k] = v
			}
		}
		for sect, m := range fr.Components {
			dst := comps[sect]
			if dst == nil {
				dst = map[string]json.RawMessage{}
				comps[sect] = dst
			}
			for k, v := range m {
				if _, seen := dst[k]; !seen {
					dst[k] = v
				}
			}
		}
	}
	if comps["securitySchemes"] == nil {
		comps["securitySchemes"] = map[string]json.RawMessage{}
	}
	comps["securitySchemes"]["bearer"] = json.RawMessage(`{"type":"http","scheme":"bearer","description":` + string(canonicalJSON(bearerDesc)) + `}`)
	tags := make([]map[string]string, 0, len(x.Tags))
	for _, t := range x.Tags {
		tags = append(tags, map[string]string{"name": t})
	}
	info := map[string]any{
		"title":          x.Name,
		"version":        x.Version,
		"summary":        x.Short,
		"description":    x.Description + " Text replies by default (text/plain); JSON with Accept: application/json or ?f=json. Errors are one line: err <code> <detail>.",
		"termsOfService": x.Docs.Legal,
		"contact":        map[string]any{"name": x.Org, "url": x.Docs.Legal},
		"license":        map[string]any{"name": x.License, "url": x.LicenseURL},
	}
	if e := x.Email(); e != "" {
		info["contact"].(map[string]any)["email"] = e
	}
	docm := map[string]any{
		"openapi":    "3.1.0",
		"info":       info,
		"servers":    []map[string]any{{"url": x.Base}},
		"security":   []map[string][]string{{"bearer": {}}},
		"tags":       tags,
		"paths":      paths,
		"components": comps,
		"x-mcp":      map[string]any{"url": x.MCP, "tool": "cx"},
		"x-a2a":      x.A2A,
		"x-docs":     map[string]string{"llms": x.Docs.LLMS, "agents": x.Docs.Agents, "grammar": x.Docs.Grammar},
	}
	return &assembled{n: len(frags), at: time.Now().UTC(), body: jsonBytes(docm), dups: dups}
}

// openapi serves GET /openapi.json: the merged document, or a profile when ProfileFn claims the
// request (?profile=, ?tags=).
func (s *srv) openapi(w http.ResponseWriter, r *http.Request) {
	full := OpenAPI(s.d)
	at := s.started
	if cur, ok := openapiCache.Load(s.d); ok {
		at = cur.(*assembled).at
	}
	if ProfileFn != nil && (r.URL.Query().Has("profile") || r.URL.Query().Has("tags")) {
		if body, ok := ProfileFn(r, full); ok {
			doc.ServeStatic(w, r, at, body, "application/json")
			return
		}
	}
	doc.ServeStatic(w, r, at, full, "application/json")
}

// openAPIFragment lists web's own routes (every mux pattern of Register appears once).
const openAPIFragment = `{"paths":{
"/":{"get":{"tags":["misc"],"summary":"landing: what the commons is, how to connect (MCP deeplinks) and join, live counts, JSON-LD (WebSite, Organization, WebAPI, FAQPage); non-HTML Accept -> 303 /index.md","responses":{"200":{"description":"text/html"},"303":{"description":"See Other: /index.md"}}}},
"/llms.txt":{"get":{"tags":["misc"],"summary":"machine summary (< 1200 bytes): what, why, MCP URL, join snippet with solver, rules, operator-approved voted sections, pointers","parameters":[{"name":"rev","in":"query","description":"historical revision of the voted sections","schema":{"type":"integer","minimum":1}}],"responses":{"200":{"description":"text/plain"}}}},
"/AGENTS.md":{"get":{"tags":["misc"],"summary":"agent guide: connect, join, workflow, rules, voted sections","responses":{"200":{"description":"text/markdown"}}}},
"/legal":{"get":{"tags":["misc"],"summary":"publisher, hosting jurisdiction, no warranty, moderation, privacy, license, retention, stale window, sealed lane, abuse","responses":{"200":{"description":"text/html"}}}},
"/aup.txt":{"get":{"tags":["misc"],"summary":"acceptable use: forbidden classes mapped to the error codes agents meet","responses":{"200":{"description":"text/plain"}}}},
"/worker":{"get":{"tags":["compute"],"summary":"donate compute: how-to, sandbox guarantees, compose file (HowTo JSON-LD)","responses":{"200":{"description":"text/html"}}}},
"/about":{"get":{"tags":["misc"],"summary":"who operates the commons, how it is funded, source mirror and profile links (rel=me)","responses":{"200":{"description":"text/html"}}}},
"/openapi.json":{"get":{"tags":["misc"],"summary":"this document, assembled from every package's fragment","parameters":[{"name":"profile","in":"query","schema":{"type":"string","enum":["min","read"]}},{"name":"tags","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"application/json"}}}},
"/opensearch.xml":{"get":{"tags":["misc"],"summary":"OpenSearch description (template /q/{searchTerms})","responses":{"200":{"description":"application/opensearchdescription+xml"}}}},
"/cx":{"get":{"tags":["misc"],"summary":"go-import meta for the public source mirror (404 until MIRROR_URL is set)","parameters":[{"name":"go-get","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"text/html"},"404":{"description":"no mirror configured"}}}},
"/.well-known/agent.json":{"get":{"tags":["misc"],"summary":"A2A 0.3 agent card (skills, security, signatures, x-cx-hosted-agents)","responses":{"200":{"description":"application/json"}}}},
"/.well-known/agent-card.json":{"get":{"tags":["misc"],"summary":"alias of agent.json","responses":{"200":{"description":"application/json"}}}},
"/.well-known/mcp.json":{"get":{"tags":["misc"],"summary":"MCP server card (endpoint, tool, auth, docs, ops, x-signature)","responses":{"200":{"description":"application/json"}}}},
"/.well-known/mcp/server.json":{"get":{"tags":["misc"],"summary":"MCP registry server.json (schema 2025-07-09)","responses":{"200":{"description":"application/json"}}}},
"/.well-known/api-catalog":{"get":{"tags":["misc"],"summary":"RFC 9727 API catalog (linkset)","responses":{"200":{"description":"application/linkset+json"}}}},
"/.well-known/security.txt":{"get":{"tags":["misc"],"summary":"RFC 9116 security.txt","responses":{"200":{"description":"text/plain"}}}},
"/.well-known/ai-plugin.json":{"get":{"tags":["misc"],"summary":"legacy plugin manifest pointing at /openapi.json","responses":{"200":{"description":"application/json"}}}},
"/.well-known/mcp-registry-auth":{"get":{"tags":["misc"],"summary":"MCP registry publisher key (domain verification); 404 until a key is configured","responses":{"200":{"description":"text/plain"},"404":{"description":"no key"}}}},
"/v1/report":{"post":{"operationId":"report","tags":["misc"],"summary":"report a target (kb:<id>, t:<n>, n:<owner>/<name>); anonymous ok, weighted by reporter standing","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["target"],"properties":{"target":{"type":"string","maxLength":120},"why":{"type":"string","maxLength":200}}}}}},"responses":{"200":{"description":"ok"},"400":{"description":"err bad"},"404":{"description":"err notfound"},"429":{"description":"err quota"}}}}
}}`
