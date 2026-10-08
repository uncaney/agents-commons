package web

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/kb"
)

// newEnvP114 is newEnv plus the P114 registrations (RegisterTDM, RegisterProfiles) so the tdmrep,
// ai.txt, openapi profile and help/err routes are mounted.
func newEnvP114(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, PowBitsW: 16, DataDir: t.TempDir(), TrustCF: true, RegPerHour: 1 << 20,
		ForgejoURL: "http://127.0.0.1:1", ForgejoToken: "x", PublicURL: "https://agents.test", AbuseContact: "abuse@agents.test", LicenseContent: "CC0-1.0"}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	kb.Register(mux, d)
	Register(mux, d)
	RegisterTDM(mux, d)
	RegisterProfiles(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	var ip [1]byte
	ip[0] = byte(len(t.Name()))
	return &tenv{d, srv, "10.7.3." + itoa(int(ip[0]))}
}

func TestTdmrepAndAiTxtFromDescriptor(t *testing.T) {
	e := newEnvP114(t)

	// tdmrep.json: a W3C TDMRep array; "/" is open (reservation 0 + policy), the reserved classes 1.
	st, h, body := e.do(t, "GET", "/.well-known/tdmrep.json", "", nil)
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/json") {
		t.Fatalf("tdmrep: %d %q", st, h.Get("Content-Type"))
	}
	var entries []map[string]any
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		t.Fatalf("tdmrep not JSON array: %v\n%s", err, body)
	}
	got := map[string]map[string]any{}
	for _, e := range entries {
		loc, _ := e["location"].(string)
		got[loc] = e
	}
	root, ok := got["/"]
	if !ok || root["tdm-reservation"].(float64) != 0 || root["tdm-policy"] != "https://agents.test/legal" {
		t.Fatalf("root entry wrong: %v", root)
	}
	for _, loc := range []string{"/d/", "/v1/", "/quarantine", "/wanted", "/mcp"} {
		e, ok := got[loc]
		if !ok || e["tdm-reservation"].(float64) != 1 {
			t.Fatalf("%s must be reserved: %v", loc, e)
		}
		if _, has := e["tdm-policy"]; has {
			t.Fatalf("%s reserved entry must not carry a policy", loc)
		}
	}

	// ai.txt: Spawning format, Allow: / and Disallow of the reserved classes.
	st, h, body = e.do(t, "GET", "/ai.txt", "", nil)
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/plain") {
		t.Fatalf("ai.txt: %d %q", st, h.Get("Content-Type"))
	}
	for _, want := range []string{"User-Agent: *", "Allow: /", "Disallow: /d/", "Disallow: /v1/", "Disallow: /mcp", "Disallow: /quarantine", "Disallow: /wanted"} {
		if !strings.Contains(body, want) {
			t.Fatalf("ai.txt missing %q:\n%s", want, body)
		}
	}
	// Both are edge-cached static docs with an ETag.
	if cc := h.Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=300") || h.Get("ETag") == "" {
		t.Fatalf("ai.txt cache headers: %q etag=%q", h.Get("Cache-Control"), h.Get("ETag"))
	}
}

// TestSignalParityPerPathClass asserts the four machine-readable signals agree per path class: the
// TDM bundle, ai.txt, the robots Disallow list and the robots Content-Signal opt-in.
func TestSignalParityPerPathClass(t *testing.T) {
	base := "https://agents.test"
	tdm := TDMRepJSON(base)
	ai := AITxt(base)
	var entries []map[string]any
	if err := json.Unmarshal(tdm, &entries); err != nil {
		t.Fatal(err)
	}
	reservedInTDM := map[string]bool{}
	for _, e := range entries {
		loc, _ := e["location"].(string)
		reservedInTDM[loc] = e["tdm-reservation"].(float64) == 1
	}
	robots := string(buildRobots(base))
	if !strings.Contains(robots, "Content-Signal: search=yes, ai-input=yes, ai-train=yes") {
		t.Fatal("robots.txt Content-Signal opt-in missing (open class must allow AI)")
	}
	inRobotsDisallow := func(prefix string) bool {
		for _, p := range robotsDisallow {
			if p == prefix || strings.HasPrefix(prefix, p) {
				return true
			}
		}
		return false
	}
	aiDisallows := func(prefix string) bool {
		return strings.Contains(ai, "Disallow: "+prefix+"\n")
	}
	for _, c := range signalClasses {
		switch c.Reserved {
		case false:
			if reservedInTDM[c.Prefix] {
				t.Fatalf("%s: open in the descriptor but reserved in tdmrep", c.Prefix)
			}
			if aiDisallows(c.Prefix) {
				t.Fatalf("%s: open class disallowed in ai.txt", c.Prefix)
			}
			if inRobotsDisallow(c.Prefix) {
				t.Fatalf("%s: open class in robots Disallow", c.Prefix)
			}
		case true:
			if !reservedInTDM[c.Prefix] {
				t.Fatalf("%s: reserved class not reserved in tdmrep", c.Prefix)
			}
			if !aiDisallows(c.Prefix) {
				t.Fatalf("%s: reserved class not disallowed in ai.txt", c.Prefix)
			}
			if !inRobotsDisallow(c.Prefix) {
				t.Fatalf("%s: reserved class not in robots Disallow", c.Prefix)
			}
		}
	}
}

// TestTDMHeadersOnPageAndReserved checks P01's per-response header table: a KB content page carries
// tdm-reservation 0, the tdm-policy and the license Link; a /v1/ route is reserved (1) and noindex.
func TestTDMHeadersOnPageAndReserved(t *testing.T) {
	e := newEnvP114(t)
	_, tok := e.register(t, "tdmhdr")
	kid := e.kbEntry(t, tok, "tdmx")

	_, h, _ := e.do(t, "GET", "/kb/"+kid, "", nil)
	if h.Get("tdm-reservation") != "0" {
		t.Fatalf("kb page tdm-reservation %q want 0", h.Get("tdm-reservation"))
	}
	if h.Get("tdm-policy") != "https://agents.test/legal" {
		t.Fatalf("kb page tdm-policy %q", h.Get("tdm-policy"))
	}
	if lic := `<https://creativecommons.org/publicdomain/zero/1.0/>; rel="license"`; !strings.Contains(strings.Join(h.Values("Link"), ", "), lic) {
		t.Fatalf("kb page missing license Link: %v", h.Values("Link"))
	}

	_, h, _ = e.do(t, "GET", "/v1/me", "", nil)
	if h.Get("tdm-reservation") != "1" {
		t.Fatalf("/v1/me tdm-reservation %q want 1", h.Get("tdm-reservation"))
	}
	if h.Get("tdm-policy") != "" {
		t.Fatalf("/v1/me reserved route must not carry a policy")
	}
	if !strings.Contains(h.Get("X-Robots-Tag"), "noindex") {
		t.Fatalf("/v1/me X-Robots-Tag %q want noindex", h.Get("X-Robots-Tag"))
	}
}
