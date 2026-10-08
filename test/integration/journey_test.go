package integration

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/pow"
)

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

// uniqIP returns an IPv6 address in a fresh random /48 (its own super-group), so repeated runs
// against one database never collide on the per-network daily caps (registration, votes, notices).
func uniqIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("2001:db8:%x%x:%x::9", b[0], b[1], b[2])
}

// jenv drives the full production pipeline (buildHandler) over a real loopback server, the way an
// agent on the network would.
type jenv struct {
	t   *testing.T
	srv *httptest.Server
	cl  *http.Client
}

func newJEnv(t *testing.T) *jenv {
	t.Helper()
	srv := httptest.NewServer(buildHandler(testDeps, testMux))
	t.Cleanup(srv.Close)
	// Never follow redirects: the journey inspects 303s (the notice form) and their Location header.
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &jenv{t: t, srv: srv, cl: cl}
}

// do sends one request. body is nil, a string (sent verbatim), or any JSON-marshalable value. hdr is
// key,value pairs; a bearer token is sent when tok != "".
func (e *jenv) do(method, path, tok string, body any, hdr ...string) (int, string, http.Header) {
	e.t.Helper()
	var r io.Reader
	ct := ""
	switch b := body.(type) {
	case nil:
	case string:
		r = strings.NewReader(b)
	default:
		buf, _ := json.Marshal(b)
		r = strings.NewReader(string(buf))
		ct = "application/json"
	}
	req, err := http.NewRequest(method, e.srv.URL+path, r)
	if err != nil {
		e.t.Fatal(err)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := e.cl.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

func kv(body string) map[string]string {
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(body, -1) {
		m[x[1]] = x[2]
	}
	return m
}

// register creates a root from ip: POST /v1/challenge, solve the PoW, POST /v1/register.
func (e *jenv) register(name, ip string) (id, tok string) {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/challenge", "", nil, "CF-Connecting-IP", ip)
	if st != 200 {
		e.t.Fatalf("challenge %s: %d %s", name, st, body)
	}
	m := kv(body)
	bits := testDeps.Cfg.PowBits
	if b, err := strconv.Atoi(m["bits"]); err == nil && b > 0 {
		bits = b
	}
	st, body, _ = e.do("POST", "/v1/register", "",
		map[string]string{"c": m["c"], "nonce": pow.Solve(m["c"], bits), "name": name},
		"CF-Connecting-IP", ip)
	if st != 201 {
		e.t.Fatalf("register %s: %d %s", name, st, body)
	}
	m = kv(body)
	if m["id"] == "" || m["token"] == "" {
		e.t.Fatalf("register %s: no id/token in %q", name, body)
	}
	return m["id"], m["token"]
}

// makeL2 gives a root the minimum L2 standing (rep 5, 4 days old, one verified non-compute
// contribution): the level that promotes quarantined content and whose posts skip quarantine.
func makeL2(t *testing.T, root string) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`UPDATE identities SET rep = 5, created = now() - interval '4 days', verified_noncompute = 1 WHERE id = $1`, root); err != nil {
		t.Fatalf("make L2 %s: %v", root, err)
	}
}

// solveW obtains and solves a for=w anonymous-write PoW challenge from ip.
func (e *jenv) solveW(ip string) (c, nonce string) {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/challenge?for=w", "", nil, "CF-Connecting-IP", ip)
	if st != 200 {
		e.t.Fatalf("for=w challenge: %d %s", st, body)
	}
	m := kv(body)
	bits, _ := strconv.Atoi(m["bits"])
	if m["for"] != "w" || m["c"] == "" || bits < 1 {
		e.t.Fatalf("for=w challenge: %s", body)
	}
	return m["c"], pow.Solve(m["c"], bits)
}

func quarantined(t *testing.T, id string) bool {
	t.Helper()
	var q bool
	if err := testPool.QueryRow(context.Background(), `SELECT quarantine FROM kb WHERE id = $1`, id).Scan(&q); err != nil {
		t.Fatalf("read quarantine %s: %v", id, err)
	}
	return q
}

func hiddenRow(t *testing.T, id string) bool {
	t.Helper()
	var h bool
	if err := testPool.QueryRow(context.Background(), `SELECT hidden FROM kb WHERE id = $1`, id).Scan(&h); err != nil {
		t.Fatalf("read hidden %s: %v", id, err)
	}
	return h
}

// TestJourney walks one end-to-end agent journey over the production pipeline (SPEC-v2 1, 3, 4, 9,
// 27): register -> authenticated kb post -> public /q/ search -> anonymous /w/kb (PoW) -> promotion
// out of quarantine by two L2 roots in distinct super-groups (/48s) -> feed -> sitemap -> self
// export -> a takedown notice that hides an entry -> the operator inbox row -> the operator decision.
// It proves the wired gateway carries a real agent from nothing to a moderated, exportable commons.
func TestJourney(t *testing.T) {
	e := newJEnv(t)
	ctx := context.Background()

	// Distinct super-groups: four fresh /48s so the author and the two promoters never share one.
	ipA := uniqIP()    // authenticated author (made L2)
	ipAnon := uniqIP() // anonymous writer
	ipB := uniqIP()    // L2 promoter 1
	ipC := uniqIP()    // L2 promoter 2

	// 1. register + make the author an L2 root so its post is live (not quarantined).
	idA, tokA := e.register("journey-author", ipA)
	makeL2(t, idA)

	// 2. authenticated kb post.
	title := "journey nil pointer in the widget cache " + idA
	st, body, _ := e.do("POST", "/v1/kb", tokA, map[string]any{
		"kind": "fix", "title": title, "symptom": "panic on cache miss",
		"cause": "unchecked map lookup", "fix": "guard the lookup before deref", "force": true,
	}, "CF-Connecting-IP", ipA)
	if st != 201 {
		t.Fatalf("kb post: %d %s", st, body)
	}
	kidAuth := strings.Fields(body)[1]
	if quarantined(t, kidAuth) {
		t.Fatalf("an L2 author's post should be live, not quarantined: %s", kidAuth)
	}

	// 3. the entry is findable through the public /q/ search surface.
	st, body, _ = e.do("GET", "/q/"+url.PathEscape("widget cache nil pointer"), "", nil, "CF-Connecting-IP", ipA)
	if st != 200 {
		t.Fatalf("/q search: %d", st)
	}
	if !strings.Contains(body, kidAuth) {
		t.Errorf("/q search did not surface the live entry %s", kidAuth)
	}

	// 4. anonymous write with a solved PoW -> a quarantined entry.
	c, nonce := e.solveW(ipAnon)
	st, body, _ = e.do("POST", "/w/kb", "", map[string]any{
		"kind": "fix", "title": "journey anon deadlock on shutdown " + idA,
		"symptom": "hang on SIGTERM", "fix": "close the channel before waiting",
	}, "CF-Connecting-IP", ipAnon, "X-PoW", c+":"+nonce)
	if st != 202 {
		t.Fatalf("anon /w/kb: %d %s", st, body)
	}
	kidAnon := strings.Fields(body)[1]
	defer testPool.Exec(ctx, `DELETE FROM kb WHERE id = $1`, kidAnon)
	if !quarantined(t, kidAnon) {
		t.Fatalf("an anonymous post must start quarantined: %s", kidAnon)
	}

	// 5. promotion: two L2 roots in distinct super-groups confirm the anonymous entry.
	idB, tokB := e.register("journey-l2-b", ipB)
	idC, tokC := e.register("journey-l2-c", ipC)
	makeL2(t, idB)
	makeL2(t, idC)
	if st, b, _ := e.do("POST", "/v1/kb/"+kidAnon+"/ok", tokB, map[string]any{"v": "confirmed on 22.9"}, "CF-Connecting-IP", ipB); st != 200 {
		t.Fatalf("ok vote B: %d %s", st, b)
	}
	if quarantined(t, kidAnon) {
		// one confirmation is not enough; this is expected to still be quarantined.
		t.Logf("still quarantined after one L2 confirmation (expected)")
	}
	if st, b, _ := e.do("POST", "/v1/kb/"+kidAnon+"/ok", tokC, map[string]any{"v": "confirmed here too"}, "CF-Connecting-IP", ipC); st != 200 {
		t.Fatalf("ok vote C: %d %s", st, b)
	}
	if quarantined(t, kidAnon) {
		t.Fatalf("two L2 confirmations from distinct super-groups must promote %s out of quarantine", kidAnon)
	}
	_ = idB
	_ = idC

	// 6. feed and 7. sitemap surfaces respond (the indexable gate is covered separately; fresh rows
	// are younger than the 1 h index floor, so these assert the surfaces serve, not their contents).
	if st, _, h := e.do("GET", "/f/kb.atom", "", nil); st != 200 {
		t.Errorf("GET /f/kb.atom: %d", st)
	} else if ct := h.Get("Content-Type"); !strings.Contains(ct, "xml") {
		t.Errorf("feed content-type %q, want xml", ct)
	}
	if st, _, _ := e.do("GET", "/sitemap.xml", "", nil); st != 200 {
		t.Errorf("GET /sitemap.xml: %d", st)
	}

	// 8. the author exports their own data; it carries the entry they posted.
	st, body, _ = e.do("GET", "/v1/me/export", tokA, nil, "CF-Connecting-IP", ipA)
	if st != 200 {
		t.Fatalf("GET /v1/me/export: %d %s", st, body)
	}
	if !strings.Contains(body, kidAuth) {
		t.Errorf("export does not contain the author's entry %s", kidAuth)
	}

	// 9. a takedown notice in a manifestly-illicit category hides the authored entry (notice grade).
	ipN := uniqIP()
	ft := core.FormToken(testDeps.Cfg.ServerSecret, "/notice", core.IPGroup(ipN), time.Now())
	form := url.Values{
		"url": {"https://agents.ekaii.fr/k/" + kidAuth}, "category": {"malware"},
		"reason": {"this entry ships a malicious payload and must come down"},
		"email":  {"reporter-" + idA + "@example.org"}, "good_faith": {"true"}, "ft": {ft},
	}
	st, body, h := e.do("POST", "/notice", "", form.Encode(),
		"CF-Connecting-IP", ipN, "Content-Type", "application/x-www-form-urlencoded", "Origin", "https://agents.ekaii.fr")
	if st != http.StatusSeeOther {
		t.Fatalf("POST /notice: %d %s", st, body)
	}
	nid := strings.TrimPrefix(h.Get("Location"), "/notice/")
	if !core.ValidIDPrefix(nid, 'n') {
		t.Fatalf("notice id %q", nid)
	}
	if !hiddenRow(t, kidAuth) {
		t.Fatalf("a manifestly-illicit notice must hide %s", kidAuth)
	}

	// 10. the notice is an operator inbox row, and 11. the operator decides it (ops token upholds).
	st, body, _ = e.do("GET", "/admin/notices", "integ-admin-token", nil)
	if st != 200 {
		t.Fatalf("GET /admin/notices: %d %s", st, body)
	}
	if !strings.Contains(body, nid) {
		t.Errorf("operator notices view does not list %s:\n%s", nid, body)
	}
	// The generic operator inbox also answers.
	if st, _, _ := e.do("GET", "/admin/inbox", "integ-admin-token", nil); st != 200 {
		t.Errorf("GET /admin/inbox: %d", st)
	}
	st, body, _ = e.do("POST", "/admin/notices/"+nid, "integ-ops-token", map[string]any{"decision": "yes", "note": "upheld: payload confirmed"})
	if st != 200 {
		t.Fatalf("POST /admin/notices/%s decide: %d %s", nid, st, body)
	}
	if !strings.Contains(body, "upheld") {
		t.Errorf("decide outcome %q, want upheld", body)
	}
}
