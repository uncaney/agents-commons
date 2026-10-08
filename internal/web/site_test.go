package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/gov"
)

func TestWellKnownBundle(t *testing.T) {
	e := newEnv(t)
	// Every document the Descriptor says web serves answers with its declared media type; the
	// listed-only ones (other packages) are absent from this mux.
	for _, wk := range wellKnownDocs {
		st, h, body := e.do(t, "GET", wk.Path, "", nil)
		switch {
		case wk.Owner != "web":
			if st != 404 {
				t.Fatalf("%s owned by %s answered %d here", wk.Path, wk.Owner, st)
			}
		case wk.Path == "/.well-known/mcp-registry-auth":
			if st != 404 || !strings.Contains(body, "err notfound") {
				t.Fatalf("registry-auth without a key: %d %s", st, body)
			}
		default:
			if st != 200 || h.Get("Content-Type") != wk.Type {
				t.Fatalf("%s: %d %q", wk.Path, st, h.Get("Content-Type"))
			}
			if h.Get("Access-Control-Allow-Origin") != "*" {
				t.Fatalf("%s: no CORS", wk.Path)
			}
		}
	}
	// api-catalog: application/linkset+json whose anchors cover REST, MCP and A2A and list every
	// document of the bundle (ours and the other packages') by absolute URL.
	_, h, body := e.do(t, "GET", "/.well-known/api-catalog", "", nil)
	if h.Get("Content-Type") != "application/linkset+json" {
		t.Fatalf("api-catalog content-type %q", h.Get("Content-Type"))
	}
	var cat struct {
		Linkset []struct {
			Anchor      string              `json:"anchor"`
			ServiceDesc []map[string]string `json:"service-desc"`
			ServiceDoc  []map[string]string `json:"service-doc"`
			Status      []map[string]string `json:"status"`
			ServiceMeta []map[string]string `json:"service-meta"`
		} `json:"linkset"`
	}
	if err := json.Unmarshal([]byte(body), &cat); err != nil || len(cat.Linkset) != 3 {
		t.Fatalf("linkset: %v %s", err, body)
	}
	anchors := map[string]bool{}
	for _, l := range cat.Linkset {
		anchors[l.Anchor] = true
		if len(l.ServiceDesc) == 0 || len(l.Status) == 0 {
			t.Fatalf("anchor %s lacks service-desc/status", l.Anchor)
		}
	}
	for _, a := range []string{"https://agents.test/v1", "https://agents.test/mcp", "https://agents.test/a2a"} {
		if !anchors[a] {
			t.Fatalf("anchor %s missing: %s", a, body)
		}
	}
	for _, p := range []string{"/.well-known/jwks.json", "/.well-known/did.json", "/.well-known/tdmrep.json", "/ai.txt", "/.well-known/cx-key", "/.well-known/security.txt", "/.well-known/oauth-protected-resource", "/openapi.json", "/llms.txt", "/healthz", "/status"} {
		if !strings.Contains(body, `"https://agents.test`+p+`"`) {
			t.Fatalf("api-catalog lacks %s", p)
		}
	}
	if strings.Contains(body, "/q/") || strings.Contains(body, "/v1/kb") {
		t.Fatalf("api-catalog lists search or API paths: %s", body)
	}
	// agent-card.json is a byte-for-byte alias of agent.json.
	_, _, a1 := e.do(t, "GET", "/.well-known/agent.json", "", nil)
	_, _, a2 := e.do(t, "GET", "/.well-known/agent-card.json", "", nil)
	if a1 != a2 || strings.Contains(a1, `"signatures"`) {
		t.Fatal("agent-card alias differs or is signed without CardSigFn")
	}
	// server.json: registry schema, reverse-DNS name, remote, 100-char description.
	_, _, body = e.do(t, "GET", "/.well-known/mcp/server.json", "", nil)
	var sj struct {
		Schema      string `json:"$schema"`
		Name        string
		Description string
		Version     string
		WebsiteURL  string `json:"websiteUrl"`
		Remotes     []struct{ Type, URL string }
	}
	if err := json.Unmarshal([]byte(body), &sj); err != nil || sj.Schema != serverSchema || sj.Name != "fr.ekaii.agents/commons" || len(sj.Description) > 100 ||
		sj.Version == "" || sj.WebsiteURL != "https://agents.test" || len(sj.Remotes) != 1 || sj.Remotes[0].Type != "streamable-http" || sj.Remotes[0].URL != "https://agents.test/mcp" {
		t.Fatalf("server.json: %v %s", err, body)
	}
	// Seams: A2ACardFn fields are merged (and win), CardSigFn signs agent.json (signatures) and the
	// MCP cards (x-signature) over the document without the signature member.
	A2ACardFn = func() map[string]any {
		return map[string]any{"url": "https://agents.test/a2a", "capabilities": map[string]any{"streaming": true, "pushNotifications": false, "stateTransitionHistory": true}, "x-from-a2a": 1}
	}
	var signedPayload string
	CardSigFn = func(card json.RawMessage) (string, string) {
		signedPayload = string(card)
		return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"1","typ":"JOSE"}`)), "c2ln"
	}
	t.Cleanup(func() { A2ACardFn, CardSigFn = nil, nil })
	_, _, body = e.do(t, "GET", "/.well-known/agent.json", "", nil)
	var card map[string]any
	if err := json.Unmarshal([]byte(body), &card); err != nil {
		t.Fatal(err)
	}
	sigs, _ := card["signatures"].([]any)
	if card["x-from-a2a"] != float64(1) || len(sigs) != 1 || card["capabilities"].(map[string]any)["streaming"] != true {
		t.Fatalf("seams not merged: %s", body)
	}
	if strings.Contains(signedPayload, "signatures") || !strings.Contains(signedPayload, `"x-from-a2a":1`) || !json.Valid([]byte(signedPayload)) {
		t.Fatalf("signed payload: %s", signedPayload)
	}
	for _, p := range []string{"/.well-known/mcp.json", "/.well-known/mcp/server.json"} {
		_, _, body = e.do(t, "GET", p, "", nil)
		if !strings.Contains(body, `"x-signature": {`) || !strings.Contains(body, `"signature": "c2ln"`) {
			t.Fatalf("%s unsigned: %s", p, body)
		}
	}
	// mcp-registry-auth: a 32-byte key (flag or env) in, the MCPv1 record out; garbage stays 404.
	ctx := context.Background()
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	if err := e.d.SetFlag(ctx, "mcp_registry_key", true, key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.d.SetFlag(ctx, "mcp_registry_key", false, "") })
	e.d.RefreshFlags(ctx)
	st, h, body := e.do(t, "GET", "/.well-known/mcp-registry-auth", "", nil)
	if st != 200 || h.Get("Content-Type") != "text/plain; charset=utf-8" || strings.TrimSpace(body) != "v=MCPv1; k=ed25519; p="+key {
		t.Fatalf("registry-auth: %d %s", st, body)
	}
	if _, ok := Describe(e.d).RegistryAuth("not-a-key"); ok {
		t.Fatal("garbage key accepted")
	}
}

func TestOpenAPIAssembledParsesAndDedupes(t *testing.T) {
	e := newEnv(t)
	// A duplicate of an existing path+method and a brand-new path registered after boot: the
	// document is rebuilt, the duplicate collapses, the new path appears.
	e.d.RegisterOpenAPI(json.RawMessage(`{"paths":{"/llms.txt":{"get":{"summary":"DUPLICATE"}},"/v1/zz-test":{"post":{"operationId":"zztest","summary":"new"}}},"components":{"schemas":{"ZZ":{"type":"object"}}}}`))
	e.d.RegisterOpenAPI(json.RawMessage(`not json`))
	st, h, body := e.do(t, "GET", "/openapi.json", "", nil)
	if st != 200 || h.Get("Content-Type") != "application/json" {
		t.Fatalf("openapi: %d %q", st, h.Get("Content-Type"))
	}
	var spec struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Title, Version, TermsOfService string
			License                        struct{ Name, URL string }
		}
		Servers    []struct{ URL string }
		Security   []map[string][]string
		Tags       []struct{ Name string }
		Paths      map[string]map[string]json.RawMessage
		Components struct {
			SecuritySchemes map[string]struct{ Type, Scheme string } `json:"securitySchemes"`
			Schemas         map[string]json.RawMessage
		}
		XMCP struct{ URL, Tool string } `json:"x-mcp"`
	}
	if err := json.Unmarshal([]byte(body), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.OpenAPI != "3.1.0" || spec.Info.Title == "" || spec.Info.Version == "" || spec.Info.TermsOfService != "https://agents.test/legal" || spec.Info.License.Name != "CC0-1.0" ||
		len(spec.Servers) != 1 || spec.Servers[0].URL != "https://agents.test" || len(spec.Security) != 1 || len(spec.Tags) != len(openAPITags) ||
		spec.Components.SecuritySchemes["bearer"].Scheme != "bearer" || spec.XMCP.URL != "https://agents.test/mcp" || spec.XMCP.Tool != "cx" {
		t.Fatalf("document head: %s", body[:min(len(body), 1200)])
	}
	if strings.Contains(body, "DUPLICATE") {
		t.Fatal("later duplicate replaced the first registration")
	}
	var zz struct{ Type string }
	if _, ok := spec.Paths["/v1/zz-test"]["post"]; !ok || json.Unmarshal(spec.Components.Schemas["ZZ"], &zz) != nil || zz.Type != "object" {
		t.Fatalf("late fragment missing: %v %s", spec.Paths["/v1/zz-test"], spec.Components.Schemas["ZZ"])
	}
	// Every web route appears exactly once (path+method), with a valid operation object.
	for _, p := range []string{"/", "/llms.txt", "/AGENTS.md", "/legal", "/aup.txt", "/worker", "/about", "/openapi.json", "/opensearch.xml", "/cx",
		"/.well-known/agent.json", "/.well-known/agent-card.json", "/.well-known/mcp.json", "/.well-known/mcp/server.json", "/.well-known/api-catalog",
		"/.well-known/security.txt", "/.well-known/ai-plugin.json", "/.well-known/mcp-registry-auth"} {
		item := spec.Paths[p]
		if item == nil {
			t.Fatalf("path %s missing", p)
		}
		var op struct {
			Summary   string
			Responses map[string]any
		}
		if err := json.Unmarshal(item["get"], &op); err != nil || op.Summary == "" || len(op.Responses) == 0 {
			t.Fatalf("path %s get: %v %s", p, err, item["get"])
		}
		if strings.Count(body, `"`+p+`": {`) != 1 {
			t.Fatalf("path %s appears %d times", p, strings.Count(body, `"`+p+`": {`))
		}
	}
	var rep struct {
		OperationID string `json:"operationId"`
		RequestBody struct {
			Content map[string]struct{ Schema json.RawMessage }
		} `json:"requestBody"`
	}
	if err := json.Unmarshal(spec.Paths["/v1/report"]["post"], &rep); err != nil || rep.OperationID != "report" || rep.RequestBody.Content["application/json"].Schema == nil {
		t.Fatalf("/v1/report: %v %s", err, spec.Paths["/v1/report"]["post"])
	}
	// Stable: two renders are byte-identical and the ETag matches.
	_, h2, body2 := e.do(t, "GET", "/openapi.json", "", nil)
	if body2 != body || h2.Get("ETag") != h.Get("ETag") {
		t.Fatal("unstable document")
	}
	// Profiles delegate through ProfileFn only when asked.
	ProfileFn = func(r *http.Request, full []byte) ([]byte, bool) {
		if r.URL.Query().Get("profile") == "min" {
			return []byte(`{"openapi":"3.1.0","paths":{}}`), true
		}
		return nil, false
	}
	t.Cleanup(func() { ProfileFn = nil })
	if _, _, b := e.do(t, "GET", "/openapi.json?profile=min", "", nil); b != `{"openapi":"3.1.0","paths":{}}` {
		t.Fatalf("profile: %s", b)
	}
	if _, _, b := e.do(t, "GET", "/openapi.json?profile=other", "", nil); b != body {
		t.Fatal("unknown profile should serve the full document")
	}
	// The exported accessor returns the same bytes P114 builds its profiles from.
	if string(OpenAPI(e.d)) != body {
		t.Fatal("OpenAPI(d) differs from the served document")
	}
}

var ldRe = regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`)

func TestLandingJSONLD(t *testing.T) {
	HubsFn = func(context.Context) []string {
		return []string{"/err/ECONNREFUSED", "TypeError", "../etc/passwd", "<script>", "/err/E_FAIL.1"}
	}
	StatusFn = func(context.Context) string { return "ok\nnot a second line" }
	t.Cleanup(func() { HubsFn, StatusFn = nil, nil })
	e := newEnv(t)
	st, h, body := e.do(t, "GET", "/", "", nil)
	if st != 200 {
		t.Fatalf("landing: %d", st)
	}
	// Link trio on / (3.7) plus license, and the head links (canonical, search, markdown twin).
	link := strings.Join(h.Values("Link"), ", ")
	for _, rel := range []string{`</openapi.json>; rel="service-desc"`, `</llms.txt>; rel="service-doc"`, `</.well-known/api-catalog>; rel="api-catalog"`, `rel="license"`, `rel="canonical"`} {
		if !strings.Contains(link, rel) {
			t.Fatalf("Link lacks %s: %s", rel, link)
		}
	}
	// (html/template writes + as &#43; inside attributes.)
	for _, tag := range []string{`<link rel="canonical" href="https://agents.test/">`, `rel="search" href="/opensearch.xml" type="application/opensearchdescription&#43;xml"`, `rel="alternate" href="/index.md" type="text/markdown"`,
		`<meta name="robots" content="index,follow`} {
		if !strings.Contains(body, tag) {
			t.Fatalf("head lacks %s", tag)
		}
	}
	// JSON-LD graph: WebSite with SearchAction, Organization, WebAPI, FAQPage with 5 Q/As.
	m := ldRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no ld+json")
	}
	var ld struct {
		Graph []map[string]any `json:"@graph"`
	}
	if err := json.Unmarshal([]byte(m[1]), &ld); err != nil {
		t.Fatalf("ld+json: %v\n%s", err, m[1])
	}
	types := map[string]map[string]any{}
	for _, n := range ld.Graph {
		types[n["@type"].(string)] = n
	}
	for _, typ := range []string{"WebSite", "Organization", "WebAPI", "FAQPage"} {
		if types[typ] == nil {
			t.Fatalf("graph lacks %s", typ)
		}
	}
	sa := types["WebSite"]["potentialAction"].(map[string]any)
	if sa["@type"] != "SearchAction" || sa["target"].(map[string]any)["urlTemplate"] != "https://agents.test/q/{search_term_string}" || sa["query-input"] != "required name=search_term_string" {
		t.Fatalf("SearchAction: %v", sa)
	}
	if types["Organization"]["name"] != "ekaii.fr" {
		t.Fatalf("Organization: %v", types["Organization"])
	}
	api := types["WebAPI"]
	if api["documentation"] != "https://agents.test/openapi.json" || api["termsOfService"] != "https://agents.test/legal" || api["url"] != "https://agents.test/v1" {
		t.Fatalf("WebAPI: %v", api)
	}
	if qa, _ := types["FAQPage"]["mainEntity"].([]any); len(qa) != 5 {
		t.Fatalf("FAQPage: %d questions", len(qa))
	}
	// Deeplinks carry the public endpoint only (no token), hubs are validated, status is one line.
	cfg := base64.StdEncoding.EncodeToString([]byte(`{"url":"https://agents.test/mcp"}`))
	for _, s := range []string{"claude mcp add --transport http cx https://agents.test/mcp", `href="cursor://anysphere.cursor-deeplink/mcp/install?name=cx&amp;config=` + cfg + `"`,
		`href="vscode:mcp/install?`, `<a href="/err/ECONNREFUSED">ECONNREFUSED</a>`, `<a href="/err/TypeError">TypeError</a>`, `<a href="/err/E_FAIL.1">E_FAIL.1</a>`, "status: ok not a second line"} {
		if !strings.Contains(body, s) {
			t.Fatalf("landing lacks %s", s)
		}
	}
	if strings.Contains(body, "passwd") || strings.Contains(body, "<script>") || strings.Contains(body, "cx_") {
		t.Fatalf("unsafe hub or token leaked: %s", body)
	}
	// Non-HTML Accept -> 303 to /index.md (27.1); browser-style and empty Accepts get the HTML.
	st, h, _ = e.do(t, "GET", "/", "", nil, "Accept", "text/plain")
	if st != 303 || h.Get("Location") != "/index.md" || h.Get("Vary") != "Accept" {
		t.Fatalf("Accept text/plain: %d %s %s", st, h.Get("Location"), h.Get("Vary"))
	}
	if st, _, _ = e.do(t, "GET", "/", "", nil, "Accept", "text/html,application/xhtml+xml,*/*;q=0.8"); st != 200 {
		t.Fatalf("browser Accept: %d", st)
	}
	// /worker carries the HowTo graph.
	_, _, body = e.do(t, "GET", "/worker", "", nil)
	if m = ldRe.FindStringSubmatch(body); m == nil || !strings.Contains(m[1], `"@type":"HowTo"`) || !strings.Contains(m[1], `"HowToStep"`) {
		t.Fatalf("worker ld: %v", m)
	}
}

func TestLegalAupSecurityTxt(t *testing.T) {
	t.Setenv("LEGAL_JURISDICTION", "Hosted in Testland; Testland law applies.")
	t.Setenv("ORIGIN_RETENTION_DAYS", "200")
	t.Setenv("SAME_AS", "https://example.org/@commons, javascript:alert(1), http://plain.example/x https://codeberg.org/ekaii")
	e := newEnv(t, func(c *core.Config) {
		c.LegalPublisher = "Ekaii SASU\n12 rue Test, 75000 Paris\nSIREN 000 000 000"
		c.MirrorURL = "https://github.com/ekaii/commons"
	})
	st, _, body := e.do(t, "GET", "/legal", "", nil)
	if st != 200 {
		t.Fatalf("legal: %d", st)
	}
	for _, s := range []string{"Ekaii SASU<br>12 rue Test, 75000 Paris<br>", "Hosted in Testland; Testland law applies.", "not required", "200 days",
		"stale-if-error=604800", "7 days old", `href="/legal/e2ee"`, "never by decryption", "<code>?t=</code>", "<code>/q/</code>", "<code>/e/</code>", "24 hours",
		`rel="license">CC0-1.0</a>`, "seven dailies", "abuse@agents.test", `href="mailto:abuse@agents.test"`, "POST /notice", "security.txt"} {
		if !strings.Contains(body, s) {
			t.Fatalf("/legal lacks %q", s)
		}
	}
	// /aup.txt: every forbidden class names the code an agent meets; <= 200 tokens.
	st, h, aup := e.do(t, "GET", "/aup.txt", "", nil)
	if st != 200 || h.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("aup: %d %q", st, h.Get("Content-Type"))
	}
	for _, code := range []string{"err scrub", "err hazard", "err dup", "err quota", "err rate", "err size", "err frozen", "err auth", "err bad", "quarantine", "CC0-1.0", "abuse@agents.test"} {
		if !strings.Contains(aup, code) {
			t.Fatalf("/aup.txt lacks %q:\n%s", code, aup)
		}
	}
	if n := len(strings.Fields(aup)); n > 200 {
		t.Fatalf("aup.txt %d words", n)
	}
	for _, l := range strings.Split(strings.TrimSpace(aup), "\n") {
		if strings.HasPrefix(l, "next:") || strings.HasPrefix(l, "err ") {
			t.Fatalf("aup line could be mistaken for a reply line: %q", l)
		}
	}
	// security.txt (RFC 9116): required fields, Expires about a year out, Contact as a URI.
	_, _, sec := e.do(t, "GET", "/.well-known/security.txt", "", nil)
	fields := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(sec), "\n") {
		k, v, _ := strings.Cut(l, ": ")
		fields[k] = v
	}
	if fields["Contact"] != "mailto:abuse@agents.test" || !strings.HasPrefix(fields["Expires"], "202") || !strings.HasSuffix(fields["Expires"], "Z") ||
		fields["Canonical"] != "https://agents.test/.well-known/security.txt" || fields["Policy"] != "https://agents.test/legal" || fields["Preferred-Languages"] != "en, fr" {
		t.Fatalf("security.txt: %s", sec)
	}
	// No abuse address: Contact falls back to the legal page URI.
	e2 := newEnv(t, func(c *core.Config) { c.AbuseContact = "" })
	if _, _, sec = e2.do(t, "GET", "/.well-known/security.txt", "", nil); !strings.Contains(sec, "Contact: https://agents.test/legal\n") {
		t.Fatalf("security.txt without abuse contact: %s", sec)
	}
	// /about: rel="me" only on the valid https SAME_AS links; Organization sameAs mirrors them.
	_, h, about := e.do(t, "GET", "/about", "", nil)
	for _, s := range []string{`<a href="https://example.org/@commons" rel="me noreferrer">`, `<a href="https://codeberg.org/ekaii" rel="me noreferrer">`, "https://github.com/ekaii/commons", "go get agents.test/cx"} {
		if !strings.Contains(about, s) {
			t.Fatalf("/about lacks %q", s)
		}
	}
	if strings.Contains(about, "javascript:") || strings.Contains(about, "plain.example") {
		t.Fatalf("/about kept an unsafe sameAs: %s", about)
	}
	if link := strings.Join(h.Values("Link"), ", "); !strings.Contains(link, `<https://example.org/@commons>; rel="me"`) {
		t.Fatalf("Link rel=me missing: %s", link)
	}
	if m := ldRe.FindStringSubmatch(about); m == nil || !strings.Contains(m[1], `"sameAs":["https://example.org/@commons","https://codeberg.org/ekaii"]`) {
		t.Fatalf("about ld: %v", m)
	}
	// server.json carries the GitHub mirror as its repository.
	_, _, sj := e.do(t, "GET", "/.well-known/mcp/server.json", "", nil)
	if !strings.Contains(sj, `"repository": {`) || !strings.Contains(sj, `"source": "github"`) {
		t.Fatalf("server.json repository: %s", sj)
	}
}

func TestOpenSearchGoGet(t *testing.T) {
	e := newEnv(t)
	st, h, body := e.do(t, "GET", "/opensearch.xml", "", nil)
	if st != 200 || h.Get("Content-Type") != "application/opensearchdescription+xml" {
		t.Fatalf("opensearch: %d %q", st, h.Get("Content-Type"))
	}
	var osd struct {
		XMLName   xml.Name `xml:"OpenSearchDescription"`
		ShortName string
		URLs      []struct {
			Type     string `xml:"type,attr"`
			Rel      string `xml:"rel,attr"`
			Template string `xml:"template,attr"`
		} `xml:"Url"`
	}
	if err := xml.Unmarshal([]byte(body), &osd); err != nil || osd.XMLName.Space != "http://a9.com/-/spec/opensearch/1.1/" || len(osd.ShortName) > 16 || len(osd.URLs) != 2 ||
		osd.URLs[0].Type != "text/html" || osd.URLs[0].Template != "https://agents.test/q/{searchTerms}" || osd.URLs[1].Rel != "self" {
		t.Fatalf("opensearch: %v %s", err, body)
	}
	// /cx: 404 until MIRROR_URL is set, then the go-import meta in <head>.
	if st, _, body = e.do(t, "GET", "/cx?go-get=1", "", nil); st != 404 || !strings.Contains(body, "err notfound") {
		t.Fatalf("/cx without mirror: %d %s", st, body)
	}
	e2 := newEnv(t, func(c *core.Config) { c.MirrorURL = "https://forgejo.example/ekaii/commons.git" })
	st, h, body = e2.do(t, "GET", "/cx?go-get=1", "", nil)
	if st != 200 || h.Get("Content-Type") != "text/html; charset=utf-8" || h.Get("Content-Security-Policy") == "" || h.Get("X-Robots-Tag") != "noindex" {
		t.Fatalf("/cx: %d %v", st, h)
	}
	head := body[:strings.Index(body, "</head>")]
	if !strings.Contains(head, `<meta name="go-import" content="agents.test/cx git https://forgejo.example/ekaii/commons.git">`) {
		t.Fatalf("go-import meta missing from head: %s", body)
	}
	if st, _, _ = e2.do(t, "GET", "/cx", "", nil); st != 200 {
		t.Fatalf("/cx plain: %d", st)
	}
}

func TestLLMSVotedSectionsApproved(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	defer func() {
		testPool.Exec(ctx, `DELETE FROM site_docs WHERE section LIKE 'zz%'`)
		testPool.Exec(ctx, `DELETE FROM site_doc_revs WHERE path = 'llms' AND pid = 'pzztest'`)
		gov.LoadDocs(ctx, testPool)
	}()
	// An operator-approved section, an unapproved one and an agents section: only the first
	// reaches /llms.txt; AGENTS.md gets its own approved section.
	for _, row := range [][]string{{"llms", "zzapproved", "1", "ZZ approved: /q/<text> answers most retries.", "operator"},
		{"llms", "zzpending", "2", "ZZ PENDING must never be served.", ""}, {"llms", "zzother", "3", "ZZ OTHER approved by nobody known.", "a3fz9qk"},
		{"agents", "zzagents", "1", "ZZ agents section: a worked example lives at /brief.", "operator"}} {
		if _, err := testPool.Exec(ctx, `INSERT INTO site_docs (path, section, ord, text, approved_by) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (path, section) DO UPDATE SET text = EXCLUDED.text, approved_by = EXCLUDED.approved_by`, row[0], row[1], row[2], row[3], row[4]); err != nil {
			t.Fatal(err)
		}
	}
	if err := gov.LoadDocs(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	_, _, body := e.do(t, "GET", "/llms.txt", "", nil)
	if !strings.Contains(body, "ZZ approved: /q/<text> answers most retries.") || strings.Contains(body, "PENDING") || strings.Contains(body, "ZZ OTHER") {
		t.Fatalf("voted sections: %s", body)
	}
	if len(body) >= llmsBudget {
		t.Fatalf("llms.txt with a section: %d bytes", len(body))
	}
	if i, j := strings.Index(body, "ZZ approved"), strings.Index(body, "## Optional"); i > j {
		t.Fatal("voted section after the fixed footer")
	}
	_, _, agents := e.do(t, "GET", "/AGENTS.md", "", nil)
	if !strings.Contains(agents, "## From the commons (voted, operator-approved)") || !strings.Contains(agents, "ZZ agents section") || strings.Contains(agents, "ZZ approved") {
		t.Fatalf("AGENTS.md sections: %s", agents)
	}
	// Over-budget approved sections are left out, in order, and the file stays under the cap.
	big := strings.Repeat("ZZ big section filler text. ", 15) // ~420 B
	for i, sec := range []string{"zzbig1", "zzbig2", "zzbig3"} {
		if _, err := testPool.Exec(ctx, `INSERT INTO site_docs (path, section, ord, text, approved_by) VALUES ('llms', $1, $2, $3, 'operator')`, sec, 10+i, big+sec); err != nil {
			t.Fatal(err)
		}
	}
	if err := gov.LoadDocs(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	_, _, body = e.do(t, "GET", "/llms.txt", "", nil)
	if len(body) > llmsBudget || !strings.Contains(body, "ZZ approved") || strings.Contains(body, "zzbig3") || !strings.HasSuffix(body, "/legal\n") ||
		!strings.Contains(body, "more: /llms.txt?full=1 (+3 voted sections)\n## Optional") {
		t.Fatalf("budget with big sections: %d bytes\n%s", len(body), body)
	}
	// ?full=1 serves every approved section, unbudgeted, and nothing unapproved.
	if _, _, full := e.do(t, "GET", "/llms.txt?full=1", "", nil); len(full) <= llmsBudget || !strings.Contains(full, "zzbig3") || strings.Contains(full, "more:") || strings.Contains(full, "PENDING") {
		t.Fatalf("full: %d bytes\n%s", len(full), full)
	}
	// ?rev= serves a snapshot from site_doc_revs; unknown revs are 404, garbage 400.
	if _, err := testPool.Exec(ctx, `INSERT INTO site_doc_revs (path, rev, sections, pid) VALUES ('llms', 7777, '["ZZ revision seven."]', 'pzztest')`); err != nil {
		t.Fatal(err)
	}
	if st, _, body := e.do(t, "GET", "/llms.txt?rev=7777", "", nil); st != 200 || !strings.Contains(body, "ZZ revision seven.") || strings.Contains(body, "ZZ approved") {
		t.Fatalf("rev: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/llms.txt?rev=7778", "", nil); st != 404 {
		t.Fatalf("unknown rev: %d", st)
	}
	if st, _, _ := e.do(t, "GET", "/llms.txt?rev=x", "", nil); st != 400 {
		t.Fatalf("bad rev: %d", st)
	}
	// The llms-full 'site' section is registered and carries both documents.
	names, fns := e.d.LLMSFull()
	for i, n := range names {
		if n == "site" {
			if s := fns[i](ctx); !strings.Contains(s, "# agents.ekaii.fr") || !strings.Contains(s, "# AGENTS.md") {
				t.Fatalf("site section: %s", s)
			}
			return
		}
	}
	t.Fatal("llms-full section 'site' not registered")
}
