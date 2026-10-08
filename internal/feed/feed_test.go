package feed

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("feed", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping feed DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d     *core.Deps
	s     *svc
	srv   *httptest.Server
	ip    string
	root  string
	token string
	// noFollow keeps 301s visible.
	noFollow *http.Client
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	kb.Register(mux, d)
	s := newSvc(d)
	s.register(mux)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	e := &tenv{d: d, s: s, srv: srv, ip: randIP(), noFollow: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	e.root, e.token, err = core.CreateRoot(context.Background(), testPool, "feed-test", e.ip)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func randIP() string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.7", 20+int(b[0])%200, b[1])
}

const b32 = "abcdefghijklmnopqrstuvwxyz234567"

// newKID returns a fresh KB id (k + six base32 chars).
func newKID() string {
	var b [6]byte
	rand.Read(b[:])
	out := []byte{'k'}
	for _, c := range b {
		out = append(out, b32[int(c)%32])
	}
	return string(out)
}

func uniq() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("zq%x", b)
}

// get fetches path from a fresh anonymous network each time (the per-IP limiter never bites);
// 301s are returned, not followed; hdr are header pairs.
func (e *tenv) get(t *testing.T, path string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	return e.do(t, http.MethodGet, path, hdr...)
}

func (e *tenv) do(t *testing.T, method, path string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, nil)
	req.Header.Set("CF-Connecting-IP", randIP())
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// seed inserts a seed KB entry (created 2 h ago: indexable) and returns its id; rows are removed
// when the test ends. kind/quarantine let a test plant rows feeds must never show.
func (e *tenv) seed(t *testing.T, title, symptom, fix string, tags []string, mod ...string) string {
	t.Helper()
	id := newKID()
	kind, quarantine := "fix", false
	for _, m := range mod {
		switch m {
		case "status":
			kind = "status"
		case "quarantine":
			quarantine = true
		}
	}
	if tags == nil {
		tags = []string{}
	}
	_, err := testPool.Exec(context.Background(), `INSERT INTO kb (id, kind, title, symptom, cause, fix, tags, author, author_root, expires_at, created, confirmed_at, seed, quarantine)
		VALUES ($1, $2, $3, $4, 'because', $5, $6, $7, $7, now() + interval '30 days', now() - interval '2 hours' + ($8 || ' microseconds')::interval, now() - interval '1 hour', true, $9)`,
		id, kind, title, symptom, fix, tags, e.root, fmt.Sprint(time.Now().UnixMicro()%1_800_000_000), quarantine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM kb WHERE id = $1`, id) })
	return id
}

// parsed is the Atom shape the tests read back (namespace-checked by the root element).
type parsed struct {
	XMLName xml.Name `xml:"http://www.w3.org/2005/Atom feed"`
	Title   string   `xml:"title"`
	ID      string   `xml:"id"`
	Updated string   `xml:"updated"`
	Links   []struct {
		Rel  string `xml:"rel,attr"`
		Type string `xml:"type,attr"`
		Href string `xml:"href,attr"`
	} `xml:"link"`
	Entries []struct {
		ID      string `xml:"id"`
		Title   string `xml:"title"`
		Summary struct {
			Type string `xml:"type,attr"`
			Text string `xml:",chardata"`
		} `xml:"summary"`
		Links []struct {
			Rel  string `xml:"rel,attr"`
			Href string `xml:"href,attr"`
		} `xml:"link"`
		Author struct {
			Name string `xml:"name"`
			URI  string `xml:"uri"`
		} `xml:"author"`
		Categories []struct {
			Term string `xml:"term,attr"`
		} `xml:"category"`
		Updated   string `xml:"updated"`
		Published string `xml:"published"`
	} `xml:"entry"`
}

func parseAtom(t *testing.T, body string) parsed {
	t.Helper()
	var p parsed
	if err := xml.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("atom does not parse: %v\n%s", err, body)
	}
	return p
}

// xmllint validates body when the tool exists (skipped otherwise, as the acceptance allows).
func xmllint(t *testing.T, body string) {
	t.Helper()
	bin, err := exec.LookPath("xmllint")
	if err != nil {
		t.Log("xmllint missing: well-formedness checked with encoding/xml only")
		return
	}
	f := filepath.Join(t.TempDir(), "feed.atom")
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "--noout", f).CombinedOutput(); err != nil {
		t.Fatalf("xmllint: %v %s", err, out)
	}
}

func TestAtomValidAndEscaped(t *testing.T) {
	e := newEnv(t)
	title := `Fix <script>alert(1)</script> & "quotes" in title ` + uniq()
	id := e.seed(t, title, "dial tcp: connection refused & <retry>", "restart the daemon", []string{"go", "net/http"})
	st, body, h := e.get(t, "/f/kb.atom?n=50")
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/atom+xml") {
		t.Fatalf("GET /f/kb.atom: %d %s %s", st, h.Get("Content-Type"), body)
	}
	if !strings.HasPrefix(body, xml.Header) {
		t.Errorf("missing xml declaration: %q", body[:40])
	}
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#34;quotes&#34;") {
		t.Errorf("title not escaped: %s", body)
	}
	xmllint(t, body)
	p := parseAtom(t, body)
	if p.Title != "agents.example: kb" || p.ID != "tag:agents.example,2026:f/kb" {
		t.Errorf("feed head: %+v", p)
	}
	var self, alt, jsonAlt string
	for _, l := range p.Links {
		switch {
		case l.Rel == "self":
			self = l.Href
		case l.Rel == "alternate" && l.Type == "text/html":
			alt = l.Href
		case l.Rel == "alternate" && l.Type == "application/feed+json":
			jsonAlt = l.Href
		}
	}
	if self != "https://agents.example/f/kb.atom?n=50" || alt != "https://agents.example/kb/" || jsonAlt != "https://agents.example/f/kb.json?n=50" {
		t.Errorf("feed links self=%q alt=%q json=%q", self, alt, jsonAlt)
	}
	found := false
	for _, en := range p.Entries {
		if en.ID != "tag:agents.example,2026:kb/"+id {
			continue
		}
		found = true
		if en.Title != title {
			t.Errorf("title round trip: %q", en.Title)
		}
		if len(en.Links) != 1 || en.Links[0].Rel != "alternate" || en.Links[0].Href != "https://agents.example/k/"+id {
			t.Errorf("entry link: %+v", en.Links)
		}
		if en.Summary.Type != "text" || en.Summary.Text != "dial tcp: connection refused & <retry>" {
			t.Errorf("summary: %+v", en.Summary)
		}
		if en.Author.Name != "seed" || en.Author.URI != "" {
			t.Errorf("author: %+v", en.Author)
		}
		if len(en.Categories) != 2 || en.Categories[0].Term != "go" || en.Categories[1].Term != "net/http" {
			t.Errorf("categories: %+v", en.Categories)
		}
		for _, ts := range []string{en.Updated, en.Published, p.Updated} {
			if _, err := time.Parse(time.RFC3339, ts); err != nil {
				t.Errorf("time %q: %v", ts, err)
			}
		}
	}
	if !found {
		t.Fatalf("entry %s missing from feed:\n%s", id, body)
	}
	// A source item with a control character and a '<' in the title still yields a parseable feed.
	e.d.RegisterFeed("ctl", func(context.Context, string, int) ([]core.FeedItem, error) {
		return []core.FeedItem{{ID: "c1", URL: "/x/c1", Title: "a\x01b<c\n>d", Summary: "s\x00\x1fum", Updated: time.Now()}}, nil
	})
	st, body, _ = e.get(t, "/f/ctl.atom")
	if st != 200 {
		t.Fatalf("ctl feed: %d %s", st, body)
	}
	xmllint(t, body)
	if p := parseAtom(t, body); len(p.Entries) != 1 || p.Entries[0].Title != "a b<c >d" || p.Entries[0].Summary.Text != "s  um" {
		t.Errorf("control chars: %+v", p.Entries)
	}
}

func TestJSONFeedShape(t *testing.T) {
	e := newEnv(t)
	title := "JSON shape " + uniq()
	id := e.seed(t, title, "symptom <b>here</b>", "the fix body", []string{"json"})
	st, body, h := e.get(t, "/f/kb.json?n=50")
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/feed+json") {
		t.Fatalf("GET /f/kb.json: %d %s %s", st, h.Get("Content-Type"), body)
	}
	var f struct {
		Version     string           `json:"version"`
		Title       string           `json:"title"`
		HomePageURL string           `json:"home_page_url"`
		FeedURL     string           `json:"feed_url"`
		Items       []map[string]any `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &f); err != nil {
		t.Fatalf("json: %v\n%s", err, body)
	}
	if f.Version != "https://jsonfeed.org/version/1.1" || f.Title != "agents.example: kb" || f.HomePageURL != "https://agents.example/kb/" || f.FeedURL != "https://agents.example/f/kb.json?n=50" {
		t.Errorf("feed head: %+v", f)
	}
	var it map[string]any
	for _, x := range f.Items {
		if x["id"] == id {
			it = x
		}
	}
	if it == nil {
		t.Fatalf("item %s missing:\n%s", id, body)
	}
	for _, k := range []string{"id", "url", "title", "summary", "content_text", "date_published", "date_modified", "tags", "authors"} {
		if _, ok := it[k]; !ok {
			t.Errorf("item lacks %s: %v", k, it)
		}
	}
	if it["url"] != "https://agents.example/k/"+id || it["title"] != title || it["summary"] != "symptom <b>here</b>" {
		t.Errorf("item fields: %v", it)
	}
	if _, err := time.Parse(time.RFC3339, it["date_modified"].(string)); err != nil {
		t.Errorf("date_modified: %v", err)
	}
	if tags, _ := it["tags"].([]any); len(tags) != 1 || tags[0] != "json" {
		t.Errorf("tags: %v", it["tags"])
	}
	if as, _ := it["authors"].([]any); len(as) != 1 || as[0].(map[string]any)["name"] != "seed" {
		t.Errorf("authors: %v", it["authors"])
	}
	if strings.Contains(body, "the fix body") {
		t.Error("fix body leaked into the JSON feed")
	}
	// An agent author links to its page; an empty tag list is an array, not null.
	e.d.RegisterFeed("au", func(context.Context, string, int) ([]core.FeedItem, error) {
		return []core.FeedItem{{ID: "x1", URL: "https://agents.example/x/x1", Title: "t", Summary: "s", Author: "a3fz2qk", Updated: time.Now()}}, nil
	})
	st, body, _ = e.get(t, "/f/au.json")
	if st != 200 || !strings.Contains(body, `"authors":[{"name":"a3fz2qk","url":"https://agents.example/a/a3fz2qk"}]`) || !strings.Contains(body, `"tags":[]`) {
		t.Errorf("author link / empty tags: %d %s", st, body)
	}
}

func demoItems(prefix string, n int) []core.FeedItem {
	out := make([]core.FeedItem, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, core.FeedItem{ID: fmt.Sprintf("%s%d", prefix, i), URL: fmt.Sprintf("/x/%s%d", prefix, i), Title: "Demo " + prefix,
			Summary: "summary " + prefix, Updated: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC).Add(-time.Duration(i) * time.Hour), Tags: []string{"demo"}, Author: "seed"})
	}
	return out
}

func TestRegistryRouting(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	calls := map[string][]string{}
	ns := map[string]int{}
	src := func(name string) core.FeedFn {
		return func(_ context.Context, sub string, n int) ([]core.FeedItem, error) {
			mu.Lock()
			calls[name] = append(calls[name], sub)
			ns[name] = n
			mu.Unlock()
			return demoItems("d", 3), nil
		}
	}
	e.d.RegisterFeed("demo", src("demo"))
	e.d.RegisterFeed("demo/sub", src("demo/sub"))
	last := func(name string) (string, int) {
		mu.Lock()
		defer mu.Unlock()
		c := calls[name]
		if len(c) == 0 {
			return "<none>", 0
		}
		return c[len(c)-1], ns[name]
	}
	st, body, h := e.get(t, "/f/demo.atom")
	if st != 200 {
		t.Fatalf("/f/demo.atom: %d %s", st, body)
	}
	if sub, n := last("demo"); sub != "" || n != DefaultN {
		t.Errorf("demo sub=%q n=%d", sub, n)
	}
	p := parseAtom(t, body)
	if len(p.Entries) != 3 || p.Entries[0].ID != "tag:agents.example,2026:demo/d0" || p.Entries[0].Links[0].Href != "https://agents.example/x/d0" {
		t.Errorf("demo entries: %+v", p.Entries)
	}
	if !strings.Contains(strings.Join(h.Values("Link"), " "), `<https://agents.example/f/demo.json>; rel="alternate"; type="application/feed+json"`) {
		t.Errorf("alternate Link header: %v", h.Values("Link"))
	}
	// The remainder after the registered prefix is the sub-feed key; the longest prefix wins.
	if st, body, h = e.get(t, "/f/demo/a/b.json"); st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/feed+json") {
		t.Fatalf("/f/demo/a/b.json: %d %s", st, body)
	}
	if sub, _ := last("demo"); sub != "a/b" {
		t.Errorf("demo sub=%q", sub)
	}
	if !strings.Contains(body, `"feed_url":"https://agents.example/f/demo/a/b.json"`) || !strings.Contains(body, `"title":"agents.example: demo/a/b"`) {
		t.Errorf("sub feed head: %s", body)
	}
	if st, body, _ = e.get(t, "/f/demo/sub/z.atom"); st != 200 {
		t.Fatalf("/f/demo/sub/z.atom: %d %s", st, body)
	}
	if sub, _ := last("demo/sub"); sub != "z" {
		t.Errorf("demo/sub sub=%q", sub)
	}
	if st, _, _ = e.get(t, "/f/demo/sub.atom"); st != 200 {
		t.Fatalf("/f/demo/sub.atom: %d", st)
	}
	if sub, _ := last("demo/sub"); sub != "" {
		t.Errorf("demo/sub bare sub=%q", sub)
	}
	// The tag sub-feed of the real kb source resolves too (empty is fine).
	if st, body, _ = e.get(t, "/f/kb/react.atom"); st != 200 || !strings.Contains(body, "<title>agents.example: kb/react</title>") || !strings.Contains(body, `href="https://agents.example/tag/react"`) {
		t.Errorf("/f/kb/react.atom: %d %s", st, body)
	}
	// Unknown names are 404; malformed ones 400.
	if st, body, _ = e.get(t, "/f/nope.atom"); st != 404 || !strings.HasPrefix(body, "err notfound no feed nope") {
		t.Errorf("unknown feed: %d %s", st, body)
	}
	if st, body, _ = e.get(t, "/f/"+strings.Repeat("a", 600)+".atom"); st != 400 || !strings.HasPrefix(body, "err bad feed name") {
		t.Errorf("long name: %d %s", st, body)
	}
	if st, body, _ = e.get(t, "/f/demo//x.atom"); st != 400 && st/100 != 3 { // the mux may clean the path first
		t.Errorf("empty segment: %d %s", st, body)
	}
	// Bare names and .xml/.rss redirect to the Atom twin, keeping the query; /f/ goes to the KB feed.
	for in, want := range map[string]string{"/f/demo": "/f/demo.atom", "/f/demo?n=3": "/f/demo.atom?n=3", "/f/demo.xml": "/f/demo.atom", "/f/demo/a%20b.rss": "/f/demo/a%20b.atom", "/f/": "/f/kb.atom"} {
		st, _, h := e.get(t, in)
		if st != 301 || h.Get("Location") != want || h.Get("Cache-Control") != "public, max-age=86400" {
			t.Errorf("%s: %d Location=%q cc=%q", in, st, h.Get("Location"), h.Get("Cache-Control"))
		}
	}
	// n: clamp above 50, 400 below 1 or non-numeric; since: RFC3339 only, filters by Updated.
	if st, body, _ = e.get(t, "/f/demo.atom?n=2"); st != 200 || len(parseAtom(t, body).Entries) != 2 {
		t.Errorf("n=2: %d", st)
	}
	if st, _, _ = e.get(t, "/f/demo.atom?n=999"); st != 200 {
		t.Errorf("n=999: %d", st)
	}
	if _, n := last("demo"); n != MaxItems {
		t.Errorf("n=999 reached the source as %d", n)
	}
	for _, q := range []string{"n=0", "n=-1", "n=abc", "since=yesterday", "since=2026-10-01"} {
		if st, body, _ = e.get(t, "/f/demo.atom?"+q); st != 400 || !strings.HasPrefix(body, "err bad") {
			t.Errorf("%s: %d %s", q, st, body)
		}
	}
	st, body, _ = e.get(t, "/f/demo.json?since=2026-10-01T10:30:00Z")
	if st != 200 || strings.Count(body, `"id":"d`) != 2 || !strings.Contains(body, `"feed_url":"https://agents.example/f/demo.json?since=2026-10-01T10%3A30%3A00Z"`) {
		t.Errorf("since: %d %s", st, body)
	}
	if _, n := last("demo"); n != MaxItems {
		t.Errorf("since fetches the full window, got n=%d", n)
	}
	if st, body, _ = e.get(t, "/f/demo.atom?since=2030-01-01T00:00:00Z"); st != 200 || len(parseAtom(t, body).Entries) != 0 {
		t.Errorf("future since: %d %s", st, body)
	}
	// Source errors map to the wire; HEAD has no body.
	e.d.RegisterFeed("gone", func(context.Context, string, int) ([]core.FeedItem, error) { return nil, core.ErrNotFound })
	if st, body, _ = e.get(t, "/f/gone/x.atom"); st != 404 {
		t.Errorf("source notfound: %d %s", st, body)
	}
	if st, body, h = e.do(t, http.MethodHead, "/f/demo.atom"); st != 200 || body != "" || h.Get("ETag") == "" {
		t.Errorf("HEAD: %d %q %v", st, body, h)
	}
	// Autodiscovery links for page heads.
	ls := Links("kb/net http")
	if len(ls) != 2 || ls[0].Href != "/f/kb/net%20http.atom" || ls[0].Type != "application/atom+xml" || ls[1].Href != "/f/kb/net%20http.json" || ls[1].Type != "application/feed+json" || ls[0].Rel != "alternate" {
		t.Errorf("Links: %+v", ls)
	}
	// q is registered by this package, so d.Feeds() routes it like any source; saved searches cost
	// like searches (2) and both patterns are open to scoped tokens like any public read.
	if _, ok := e.d.Feeds()["q"]; !ok {
		t.Error("q source not registered")
	}
	if c := e.d.CostOf("GET /f/q/{query...}"); c != 2 {
		t.Errorf("q cost %v", c)
	}
	for _, pat := range []string{"GET /f/{name...}", "GET /f/q/{query...}"} {
		if sc, ok := e.d.ScopeOf(pat); !ok || sc != "*" {
			t.Errorf("scope of %s: %q %v", pat, sc, ok)
		}
	}
}

func TestItemsAreSummariesOnly(t *testing.T) {
	e := newEnv(t)
	secret := "FIX-BODY-MUST-NOT-LEAK-" + uniq()
	cause := "CAUSE-MUST-NOT-LEAK-" + uniq()
	sym := strings.TrimSpace(strings.Repeat("symptom words that go on ", 60)) // ~1500 bytes
	id := e.seed(t, "long symptom "+uniq(), sym, secret, nil)
	testPool.Exec(context.Background(), `UPDATE kb SET cause = $2 WHERE id = $1`, id, cause)
	for _, path := range []string{"/f/kb.atom?n=50", "/f/kb.json?n=50"} {
		st, body, _ := e.get(t, path)
		if st != 200 {
			t.Fatalf("%s: %d %s", path, st, body)
		}
		if strings.Contains(body, secret) || strings.Contains(body, cause) {
			t.Errorf("%s leaks a body field", path)
		}
		if !strings.Contains(body, "https://agents.example/k/"+id) {
			t.Errorf("%s lacks the permalink", path)
		}
	}
	_, body, _ := e.get(t, "/f/kb.atom?n=50")
	for _, en := range parseAtom(t, body).Entries {
		if en.ID == "tag:agents.example,2026:kb/"+id {
			if n := len(en.Summary.Text); n > MaxSummary || n < 400 {
				t.Errorf("summary is %d bytes", n)
			}
			if !strings.HasPrefix(sym, en.Summary.Text) {
				t.Errorf("summary is not a prefix of the symptom: %q", en.Summary.Text)
			}
		}
	}
	// The renderer caps every source: a 2000-byte summary is cut on a rune boundary, items without
	// a summary or with an unusable link are dropped, titles fall back to the id.
	long := strings.Repeat("é", 1000)
	e.d.RegisterFeed("big", func(context.Context, string, int) ([]core.FeedItem, error) {
		return []core.FeedItem{
			{ID: "b1", URL: "/x/b1", Title: "", Summary: long, Updated: time.Now()},
			{ID: "b2", URL: "/x/b2", Title: "no summary", Summary: "  ", Updated: time.Now()},
			{ID: "b3", URL: "javascript:alert(1)", Title: "bad link", Summary: "s", Updated: time.Now()},
			{ID: "", URL: "/x/b4", Title: "no id", Summary: "s", Updated: time.Now()},
		}, nil
	})
	st, body, _ := e.get(t, "/f/big.atom")
	if st != 200 {
		t.Fatalf("big: %d %s", st, body)
	}
	p := parseAtom(t, body)
	if len(p.Entries) != 1 || p.Entries[0].Title != "b1" || len(p.Entries[0].Summary.Text) > MaxSummary || len(p.Entries[0].Summary.Text) < MaxSummary-1 || !strings.HasPrefix(long, p.Entries[0].Summary.Text) {
		t.Errorf("big entries: %d %+v", len(p.Entries), p.Entries)
	}
}

func TestSavedSearchUsesSemaphoreAndShed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w := uniq()
	var ids []string
	for i := 0; i < 3; i++ {
		ids = append(ids, e.seed(t, fmt.Sprintf("connection refused %s %d", w, i), "dial tcp "+w+": connection refused", "fix", []string{"net"}))
	}
	statusID := e.seed(t, "connection refused "+w+" status", "status row "+w, "", nil, "status")
	quarID := e.seed(t, "connection refused "+w+" pending", "quarantined row "+w, "", nil, "quarantine")
	path := "/f/q/connection%20refused%20" + w + ".atom"
	// Every slot of the trigram semaphore taken: the feed answers 503 busy instead of queueing.
	for i := 0; i < cap(kb.SearchSem); i++ {
		kb.SearchSem <- struct{}{}
	}
	st, body, h := e.get(t, path)
	for i := 0; i < cap(kb.SearchSem); i++ {
		<-kb.SearchSem
	}
	if st != 503 || !strings.HasPrefix(body, "err busy search busy") || h.Get("Retry-After") != "2" {
		t.Fatalf("semaphore full: %d %s retry=%q", st, body, h.Get("Retry-After"))
	}
	// shed:feeds refuses saved searches before any work.
	if err := e.d.SetFreeze(ctx, "shed:feeds", true); err != nil {
		t.Fatal(err)
	}
	if st, body, h = e.get(t, path); st != 503 || !strings.Contains(body, "err busy retry shed:feeds") || h.Get("Retry-After") != "30" {
		t.Fatalf("shed: %d %s retry=%q", st, body, h.Get("Retry-After"))
	}
	e.d.SetFreeze(ctx, "shed:feeds", false)
	st, body, _ = e.get(t, path)
	if st != 200 {
		t.Fatalf("saved search: %d %s", st, body)
	}
	xmllint(t, body)
	p := parseAtom(t, body)
	if p.Title != "agents.example: q/connection refused "+w {
		t.Errorf("title %q", p.Title)
	}
	got := map[string]bool{}
	for _, en := range p.Entries {
		got[strings.TrimPrefix(en.ID, "tag:agents.example,2026:kb/")] = true
	}
	for _, id := range ids {
		if !got[id] {
			t.Errorf("entry %s missing from the saved search: %v", id, got)
		}
	}
	if got[statusID] || got[quarID] {
		t.Errorf("status/quarantine rows leaked: %v", got)
	}
	var self string
	for _, l := range p.Links {
		if l.Rel == "self" {
			self = l.Href
		}
	}
	if self != "https://agents.example/f/q/connection%20refused%20"+w+".atom" {
		t.Errorf("self %q", self)
	}
	// A warm non-search feed keeps answering under shed; the saved search does not, even cached.
	if st, _, _ = e.get(t, "/f/kb.atom"); st != 200 {
		t.Fatalf("kb warm-up: %d", st)
	}
	e.d.SetFreeze(ctx, "shed:feeds", true)
	if st, _, _ = e.get(t, "/f/kb.atom"); st != 200 {
		t.Errorf("cached kb feed under shed: %d", st)
	}
	if st, _, _ = e.get(t, "/f/kb.json"); st != 503 {
		t.Errorf("cold kb feed under shed: %d", st)
	}
	if st, _, _ = e.get(t, path); st != 503 {
		t.Errorf("cached saved search under shed: %d", st)
	}
	e.d.SetFreeze(ctx, "shed:feeds", false)
	// Empty and oversized queries are 400; the JSON twin shares the ranking.
	if st, body, _ = e.get(t, "/f/q.atom"); st != 400 || !strings.HasPrefix(body, "err bad q: query required") {
		t.Errorf("empty q: %d %s", st, body)
	}
	if st, body, _ = e.get(t, "/f/q/"+strings.Repeat("a", 300)+".atom"); st != 400 {
		t.Errorf("long q: %d %s", st, body)
	}
	st, body, _ = e.get(t, "/f/q/connection%20refused%20"+w+".json")
	if st != 200 || strings.Count(body, `"id":"k`) < 3 || strings.Contains(body, statusID) || strings.Contains(body, quarID) {
		t.Errorf("json saved search: %d %s", st, body)
	}
	for _, id := range ids {
		if !strings.Contains(body, `"id":"`+id+`"`) {
			t.Errorf("json saved search lacks %s", id)
		}
	}
}

func TestByteLRUBound(t *testing.T) {
	e := newEnv(t)
	w := uniq()
	filler := strings.TrimSpace(strings.Repeat("refused "+w+" ", 40)) // ~480 bytes, all matching the query
	var tags []string
	for i := 0; i < 10; i++ {
		tags = append(tags, fmt.Sprintf("%s-tag-%d-%s", w, i, strings.Repeat("x", 40)))
	}
	for i := 0; i < 12; i++ { // ~20 KB per rendered feed: 1000 of them overflow the 16 MiB cache
		e.seed(t, fmt.Sprintf("refused %s entry %d", w, i), filler, "fix", tags)
	}
	total := 0
	for i := 0; i < 1000; i++ {
		ip := fmt.Sprintf("10.%d.%d.1", 100+i/250, i%250) // one /24 per request: the anonymous limiter never bites
		st, body, _ := e.get(t, fmt.Sprintf("/f/q/refused%%20%s%%20%d.atom", w, i), "CF-Connecting-IP", ip)
		if st != 200 {
			t.Fatalf("request %d: %d %s", i, st, body)
		}
		total += len(body)
	}
	if b := e.s.cache.Bytes(); b > CacheBytes || b == 0 {
		t.Fatalf("cache holds %d bytes (cap %d)", b, CacheBytes)
	}
	if total <= CacheBytes {
		t.Fatalf("rendered only %d bytes: the bound was never exercised", total)
	}
	if n := e.s.cache.Len(); n >= 1000 || n == 0 {
		t.Errorf("cache keeps %d feeds of 1000 (expected eviction)", n)
	}
	t.Logf("rendered %d bytes over 1000 feeds; cache %d bytes, %d entries", total, e.s.cache.Bytes(), e.s.cache.Len())
}

func TestETag304(t *testing.T) {
	e := newEnv(t)
	e.seed(t, "etag entry "+uniq(), "a symptom", "a fix", nil)
	st, body, h := e.get(t, "/f/kb.atom")
	if st != 200 || body == "" {
		t.Fatalf("GET: %d", st)
	}
	et, lm := h.Get("ETag"), h.Get("Last-Modified")
	if et == "" || lm == "" || !strings.HasPrefix(h.Get("Cache-Control"), "public, max-age=300") {
		t.Fatalf("headers: etag=%q lm=%q cc=%q", et, lm, h.Get("Cache-Control"))
	}
	if st, body, h = e.get(t, "/f/kb.atom", "If-None-Match", et); st != 304 || body != "" || h.Get("ETag") != et {
		t.Errorf("If-None-Match: %d %q etag=%q", st, body, h.Get("ETag"))
	}
	if st, body, _ = e.get(t, "/f/kb.atom", "If-Modified-Since", lm); st != 304 || body != "" {
		t.Errorf("If-Modified-Since: %d %q", st, body)
	}
	if st, _, h = e.get(t, "/f/kb.atom", "If-None-Match", `"nope"`); st != 200 || h.Get("ETag") != et {
		t.Errorf("stale validator: %d etag=%q", st, h.Get("ETag"))
	}
	if _, _, h = e.get(t, "/f/kb.json"); h.Get("ETag") == et || h.Get("ETag") == "" {
		t.Errorf("json twin shares the etag: %q", h.Get("ETag"))
	}
	// A token on the request makes the reply private.
	if st, _, h = e.get(t, "/f/kb.atom", "Authorization", "Bearer "+e.token); st != 200 || h.Get("Cache-Control") != "private, no-store" {
		t.Errorf("token request: %d cc=%q", st, h.Get("Cache-Control"))
	}
	// The ETag is the body hash: a new visible entry changes it once the cache turns over.
	e.seed(t, "etag entry two "+uniq(), "b symptom", "b fix", nil)
	e.s.cache.Delete("/f/kb.atom\x00")
	if _, _, h = e.get(t, "/f/kb.atom"); h.Get("ETag") == et {
		t.Error("etag unchanged after a new entry")
	}
}

func TestAliasesRedirect(t *testing.T) {
	e := newEnv(t)
	for in, want := range map[string]string{"/feed.xml": "/f/kb.atom", "/feed.json": "/f/kb.json", "/feed.json?n=5": "/f/kb.json?n=5"} {
		st, body, h := e.get(t, in)
		if st != 301 || h.Get("Location") != want || h.Get("Cache-Control") != "public, max-age=86400" || body != "" {
			t.Errorf("%s: %d Location=%q cc=%q body=%q", in, st, h.Get("Location"), h.Get("Cache-Control"), body)
		}
	}
	// Following the alias lands on the live feed.
	resp, err := http.Get(e.srv.URL + "/feed.xml")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/atom+xml") {
		t.Errorf("followed alias: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string]struct {
		name string
		f    Format
	}{"kb.atom": {"kb", Atom}, "kb/react.json": {"kb/react", JSON}, "v/npm:a.b.atom": {"v/npm:a.b", Atom}, "kb": {"kb", ""}, "kb.xml": {"kb", ""}, "a.b/c": {"a.b/c", ""}, ".atom": {".atom", ""}} {
		if name, f := splitFormat(in); name != want.name || f != want.f {
			t.Errorf("splitFormat(%q) = %q %q, want %q %q", in, name, f, want.name, want.f)
		}
	}
	if got := tagURI("kb", "k7x2a9q"); got != "tag:agents.example,2026:kb/k7x2a9q" {
		t.Errorf("tagURI kb: %q", got)
	}
	if got := tagURI("t", "t/42"); got != "tag:agents.example,2026:t/42" {
		t.Errorf("tagURI t: %q", got)
	}
	if got := Path("q/a b/c", JSON); got != "/f/q/a%20b/c.json" {
		t.Errorf("Path: %q", got)
	}
	if got := cutBytes("héllo", 2); got != "h" {
		t.Errorf("cutBytes: %q", got)
	}
	mod, body := unpack(pack(time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC), []byte("x")))
	if !mod.Equal(time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)) || string(body) != "x" {
		t.Errorf("pack/unpack: %v %q", mod, body)
	}
	if mod, _ := unpack(pack(time.Time{}, nil)); !mod.IsZero() {
		t.Errorf("zero time round trip: %v", mod)
	}
	if !json.Valid(openAPI) {
		t.Error("openAPI fragment is not valid JSON")
	}
	if len(Help) > 600 {
		t.Errorf("Help is %d bytes", len(Help))
	}
}
