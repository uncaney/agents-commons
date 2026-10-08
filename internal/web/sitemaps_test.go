package web

import (
	"context"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
)

const smBase = "https://agents.test"

type smEnv struct {
	d    *core.Deps
	sm   *smap
	srv  *httptest.Server
	root string
	ip   string
}

func newSMEnv(t *testing.T) *smEnv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, RegPerHour: 1 << 20, PublicURL: smBase + "/", AbuseContact: "abuse@agents.test", LicenseContent: "CC0-1.0"}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	kb.Register(mux, d)
	sm := RegisterSitemaps(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	var b [2]byte
	rand.Read(b[:])
	ip := fmt.Sprintf("10.7.%d.%d", b[0], b[1])
	root, _, err := core.CreateRoot(context.Background(), testPool, "sitemap-test", ip)
	if err != nil {
		t.Fatal(err)
	}
	return &smEnv{d: d, sm: sm, srv: srv, root: root, ip: ip}
}

func (e *smEnv) get(t *testing.T, path string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Header.Set("CF-Connecting-IP", e.ip)
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(body)
}

const smB32 = "abcdefghijklmnopqrstuvwxyz234567"

func smKID() string {
	var b [6]byte
	rand.Read(b[:])
	out := []byte{'k'}
	for _, c := range b {
		out = append(out, smB32[int(c)%32])
	}
	return string(out)
}

// seed inserts a seed KB entry created 2 h ago (indexable) and returns its id; quarantine plants a
// row the sitemaps must never list. Rows are removed when the test ends.
func (e *smEnv) seed(t *testing.T, title string, quarantine bool) string {
	t.Helper()
	id := smKID()
	_, err := testPool.Exec(context.Background(), `INSERT INTO kb (id, kind, title, symptom, cause, fix, tags, author, author_root, expires_at, created, confirmed_at, seed, quarantine)
		VALUES ($1, 'fix', $2, 'a symptom', 'because', 'the fix', '{}', $3, $3, now() + interval '30 days', now() - interval '2 hours' + ($4 || ' microseconds')::interval, now() - interval '1 hour', true, $5)`,
		id, title, e.root, fmt.Sprint(time.Now().UnixMicro()%1_800_000_000), quarantine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM kb WHERE id = $1`, id) })
	return id
}

type xmlURLset struct {
	URLs []struct {
		Loc     string `xml:"loc"`
		LastMod string `xml:"lastmod"`
	} `xml:"url"`
}

type xmlIndex struct {
	Sitemaps []struct {
		Loc     string `xml:"loc"`
		LastMod string `xml:"lastmod"`
	} `xml:"sitemap"`
}

func TestRobotsV2(t *testing.T) {
	e := newSMEnv(t)
	st, h, body := e.get(t, "/robots.txt")
	if st != 200 {
		t.Fatalf("robots: %d", st)
	}
	if h.Get("Content-Type") != "text/plain; charset=utf-8" || h.Get("ETag") == "" {
		t.Fatalf("robots headers: ct=%q etag=%q", h.Get("Content-Type"), h.Get("ETag"))
	}
	must := []string{
		"# agents.ekaii.fr", smBase + "/llms.txt", smBase + "/grammar", // 3-line descriptive header
		"User-agent: *", "Allow: /",
		"Disallow: /wanted", "Disallow: /quarantine", "Disallow: /admin/", "Disallow: /mcp",
		"Disallow: /inj/", "Disallow: /rand/", "Disallow: /room/", "Disallow: /anchor/", "Disallow: /pc", // REV3
		"Content-Signal: search=yes, ai-input=yes, ai-train=yes",
		"User-agent: GPTBot", "User-agent: ClaudeBot", "User-agent: DuckAssistBot",
		"Sitemap: " + smBase + "/sitemap.xml",
	}
	for _, w := range must {
		if !strings.Contains(body, w) {
			t.Fatalf("robots lacks %q:\n%s", w, body)
		}
	}
	// A conditional request round-trips to 304.
	if st, _, _ := e.get304(t, "/robots.txt", h.Get("ETag")); st != 304 {
		t.Fatalf("robots If-None-Match -> %d", st)
	}
}

func (e *smEnv) get304(t *testing.T, path, etag string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Header.Set("CF-Connecting-IP", e.ip)
	req.Header.Set("If-None-Match", etag)
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(body)
}

func TestSitemapIndexAndMonthly(t *testing.T) {
	e := newSMEnv(t)
	id := e.seed(t, "indexable sitemap entry", false)
	if err := e.sm.rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	// /sitemap.xml is a sitemapindex; every child answers 200 under /sitemaps/.
	st, h, body := e.get(t, "/sitemap.xml")
	if st != 200 {
		t.Fatalf("sitemap.xml: %d", st)
	}
	if !strings.Contains(body, "<sitemapindex") || h.Get("ETag") == "" {
		t.Fatalf("not a sitemapindex: %s", body)
	}
	var idx xmlIndex
	if err := xml.Unmarshal([]byte(body), &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Sitemaps) < 2 {
		t.Fatalf("expected >= 2 children (pages + kb month), got %d", len(idx.Sitemaps))
	}
	sawKB := false
	loc := smBase + "/kb/" + id
	for _, c := range idx.Sitemaps {
		if !strings.HasPrefix(c.Loc, smBase+"/sitemaps/") {
			t.Fatalf("child loc not under /sitemaps/: %q", c.Loc)
		}
		if c.LastMod == "" {
			t.Fatalf("child %q has no lastmod", c.Loc)
		}
		path := strings.TrimPrefix(c.Loc, smBase)
		cst, _, cbody := e.get(t, path)
		if cst != 200 {
			t.Fatalf("child %s: %d", path, cst)
		}
		if strings.HasPrefix(path, "/sitemaps/kb-") && strings.Contains(cbody, loc) {
			sawKB = true
			var us xmlURLset
			if err := xml.Unmarshal([]byte(cbody), &us); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, u := range us.URLs {
				if u.Loc == loc {
					found = true
					if u.LastMod == "" {
						t.Fatalf("kb entry %s has no lastmod", loc)
					}
				}
			}
			if !found {
				t.Fatalf("kb child missing %s", loc)
			}
		}
	}
	if !sawKB {
		t.Fatalf("no kb-YYYY-MM child carried %s", loc)
	}
	// Re-create the v1 assertion: pages.xml lists >= 6 URLs, each with a lastmod.
	pst, _, pbody := e.get(t, "/sitemaps/pages.xml")
	if pst != 200 {
		t.Fatalf("pages.xml: %d", pst)
	}
	var pages xmlURLset
	if err := xml.Unmarshal([]byte(pbody), &pages); err != nil {
		t.Fatal(err)
	}
	if len(pages.URLs) < 6 {
		t.Fatalf("pages.xml has %d URLs, want >= 6", len(pages.URLs))
	}
	for _, u := range pages.URLs {
		if u.LastMod == "" {
			t.Fatalf("pages URL %s has no lastmod", u.Loc)
		}
	}
	// /sitemap.txt is the plain URL list of the pages child.
	tst, th, tbody := e.get(t, "/sitemap.txt")
	if tst != 200 || th.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("sitemap.txt: %d %q", tst, th.Get("Content-Type"))
	}
	if !strings.Contains(tbody, smBase+"/kb/") || !strings.Contains(tbody, smBase+"/llms.txt") {
		t.Fatalf("sitemap.txt missing page URLs:\n%s", tbody)
	}
	// Unknown files are 404; a file without the .xml suffix is 404.
	for _, p := range []string{"/sitemaps/nope.xml", "/sitemaps/pages"} {
		if st, _, _ := e.get(t, p); st != 404 {
			t.Fatalf("%s -> %d, want 404", p, st)
		}
	}
}

func TestSitemapChildrenFromRegistry(t *testing.T) {
	e := newSMEnv(t)
	now := time.Now().UTC().Truncate(time.Second)
	e.d.RegisterSitemap("libs", func(context.Context) ([]core.SitemapURL, error) {
		return []core.SitemapURL{{Loc: smBase + "/lib/pg", LastMod: now}}, nil
	})
	e.d.RegisterSitemap("answers", func(context.Context) ([]core.SitemapURL, error) {
		return []core.SitemapURL{{Loc: smBase + "/qa/abc", LastMod: now.Add(-time.Hour)}}, nil
	})
	if err := e.sm.rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, body := e.get(t, "/sitemap.xml")
	var idx xmlIndex
	if err := xml.Unmarshal([]byte(body), &idx); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{smBase + "/sitemaps/libs.xml": false, smBase + "/sitemaps/answers.xml": false}
	for _, c := range idx.Sitemaps {
		if _, ok := want[c.Loc]; ok {
			want[c.Loc] = true
		}
	}
	for loc, ok := range want {
		if !ok {
			t.Fatalf("registry child %s missing from index", loc)
		}
	}
	// The registered child serves its URLs with 200 and carries the lastmod.
	st, _, cbody := e.get(t, "/sitemaps/libs.xml")
	if st != 200 || !strings.Contains(cbody, smBase+"/lib/pg") || !strings.Contains(cbody, now.Format(time.RFC3339)) {
		t.Fatalf("libs.xml: %d %s", st, cbody)
	}
}

func TestSitemapsOnlyIndexable(t *testing.T) {
	e := newSMEnv(t)
	good := e.seed(t, "visible entry", false)
	bad := e.seed(t, "quarantined entry", true)
	if err := e.sm.rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, body := e.get(t, "/sitemap.xml")
	var idx xmlIndex
	xml.Unmarshal([]byte(body), &idx)
	var all strings.Builder
	for _, c := range idx.Sitemaps {
		if strings.HasPrefix(c.Loc, smBase+"/sitemaps/kb-") {
			_, _, cbody := e.get(t, strings.TrimPrefix(c.Loc, smBase))
			all.WriteString(cbody)
		}
	}
	dump := all.String()
	if !strings.Contains(dump, smBase+"/kb/"+good) {
		t.Fatalf("indexable entry %s absent from kb sitemaps", good)
	}
	if strings.Contains(dump, smBase+"/kb/"+bad) {
		t.Fatalf("quarantined entry %s leaked into a sitemap", bad)
	}
}

func TestSitemapNoWanted(t *testing.T) {
	e := newSMEnv(t)
	if err := e.sm.rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The pages child and the index must never reference /wanted or /quarantine.
	for _, p := range []string{"/sitemaps/pages.xml", "/sitemap.xml", "/sitemap.txt"} {
		_, _, body := e.get(t, p)
		if strings.Contains(body, "/wanted") || strings.Contains(body, "/quarantine") {
			t.Fatalf("%s references /wanted or /quarantine:\n%s", p, body)
		}
	}
	// robots.txt, by contrast, disallows both.
	_, _, robots := e.get(t, "/robots.txt")
	if !strings.Contains(robots, "Disallow: /wanted") || !strings.Contains(robots, "Disallow: /quarantine") {
		t.Fatalf("robots must disallow /wanted and /quarantine:\n%s", robots)
	}
}
