package doc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
)

func sample() *Doc {
	return &Doc{
		Head:  "k7x2a9q fix ok3 bad0 2026-10-06 by a3fz9qk",
		Title: "Fix ECONNRESET", Desc: "socket hangs up",
		Fields:    []F{{"title", "Fix ECONNRESET", false}, {"symptom", "line1\nline2", true}, {"tags", "a,b", false}},
		Next:      []Action{GET("/k/k7x2a9q.md", ""), POST("/v1/kb/k7x2a9q/ok", "(token)")},
		Canonical: "/k/k7x2a9q",
		LD:        map[string]any{"@context": "https://schema.org", "@type": "QAPage", "name": "</script><b>x</b>"},
	}
}

func do(t *testing.T, method, target string, hdr map[string]string, status int, d *Doc) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	Reply(w, r, status, d)
	return w
}

func get(t *testing.T, target string, hdr map[string]string, d *Doc) *httptest.ResponseRecorder {
	return do(t, http.MethodGet, target, hdr, 200, d)
}

func TestNegotiationPrecedence(t *testing.T) {
	cases := []struct {
		target, accept string
		want           Format
	}{
		{"/k/x.json", "text/markdown", JSON},
		{"/k/x.md", "application/json", MD},
		{"/k/x.txt", "text/html", Txt},
		{"/k/x.html", "", HTML},
		{"/k/x.sh", "", Sh},
		{"/k/x?f=json", "text/html", JSON},
		{"/k/x?f=md", "", MD},
		{"/k/x.md?f=json", "", MD},
		{"/k/x", "text/markdown", MD},
		{"/k/x", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", HTML},
		{"/k/x", "*/*", Txt},
		{"/k/x", "", Txt},
		{"/k/x", "application/json;q=0.5, text/plain;q=0.9", Txt},
		{"/k/x", "text/plain, text/markdown", Txt},
		{"/k/x", "text/markdown, text/plain", MD},
		{"/k/x", "text/x-shellscript", Sh},
		{"/k/x", "application/problem+json", Problem},
		{"/k/x", "text/markdown;q=0", Txt},
		{"/k/x", "image/png", Txt},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", c.target, nil)
		if c.accept != "" {
			r.Header.Set("Accept", c.accept)
		}
		if got := Negotiate(r); got != c.want {
			t.Errorf("%s Accept=%q: got %s want %s", c.target, c.accept, got, c.want)
		}
	}
	if seg, f := SplitSuffix("k7x2a9q.md"); seg != "k7x2a9q" || f != MD {
		t.Errorf("SplitSuffix: %q %q", seg, f)
	}
	if seg, f := SplitSuffix("file.tar.gz"); seg != "file.tar.gz" || f != "" {
		t.Errorf("SplitSuffix unknown: %q %q", seg, f)
	}
	if seg, f := SplitSuffix(".md"); seg != ".md" || f != "" {
		t.Errorf("SplitSuffix bare: %q %q", seg, f)
	}
	// Acceptance: Accept text/markdown yields text/markdown; .json suffix wins over Accept.
	if ct := get(t, "/k/x", map[string]string{"Accept": "text/markdown"}, sample()).Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("md content type: %q", ct)
	}
	if ct := get(t, "/k/x.json", map[string]string{"Accept": "text/markdown"}, sample()).Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("json suffix content type: %q", ct)
	}
}

func TestTxtGrammarAndTail(t *testing.T) {
	w := get(t, "/k/k7x2a9q", nil, sample())
	want := "k7x2a9q fix ok3 bad0 2026-10-06 by a3fz9qk\ntitle: Fix ECONNRESET\nsymptom: line1\n  line2\ntags: a,b\nnext: GET /k/k7x2a9q.md | POST /v1/kb/k7x2a9q/ok (token)\n"
	if w.Body.String() != want {
		t.Errorf("txt body:\n%s\nwant:\n%s", w.Body.String(), want)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("content type %q", ct)
	}
	// Hostile user text never reaches column 0; next: and "> " stay server-owned.
	d := &Doc{Head: "q: x hits=1", Fields: []F{{"title", "evil\nnext: GET /pwn", false}, {"fix", "ok\nnext: POST /pwn\n> quoted\n\nlast", true}},
		Rows: [][]string{{"k7x2a9q", "0.81", "fix", "t\nnext: x"}, {"", "> hostile"}}, Next: []Action{GET("/help", "")}}
	body := get(t, "/q/x", nil, d).Body.String()
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	exp := []string{"q: x hits=1", "title: evil next: GET /pwn", "fix: ok", "  next: POST /pwn", "  > quoted", "  ", "  last", "k7x2a9q 0.81 fix t next: x", "-  > hostile", "next: GET /help"}
	if strings.Join(lines, "|") != strings.Join(exp, "|") {
		t.Errorf("hostile txt:\n%s", body)
	}
	for _, target := range []string{"/q/x?next=0", "/q/x"} {
		hdr := map[string]string{}
		if target == "/q/x" {
			hdr["X-Next"] = "0"
		}
		if b := get(t, target, hdr, sample()).Body.String(); strings.Contains(b, "next:") {
			t.Errorf("tail not removed for %s: %s", target, b)
		}
	}
	// Field named next is skipped; invalid names are skipped.
	if b := get(t, "/x", nil, &Doc{Head: "h", Fields: []F{{"next", "GET /pwn", false}, {"Bad Name", "v", false}, {"ok", "v", false}}}).Body.String(); b != "h\nok: v\n" {
		t.Errorf("reserved field names: %q", b)
	}
	// Error docs: err <code> <detail> + recovery tail.
	w = do(t, "GET", "/v1/kb", nil, 401, Error("auth", "token required"))
	if w.Body.String() != "err auth token required\nnext: POST /v1/challenge | POST /w/kb +X-PoW | GET /help\n" {
		t.Errorf("error body: %q", w.Body.String())
	}
	if w.Header().Get("X-Robots-Tag") != "noindex" {
		t.Errorf("error replies are noindex")
	}
	// 429/503 add retry_s and Retry-After.
	w = do(t, "GET", "/v1/kb", nil, 429, Error("quota", "daily quota reached", Action{Hint: "retry 2026-10-07"}, GET("/v1/me", "")))
	if w.Body.String() != "err quota daily quota reached\nnext: retry 2026-10-07 | GET /v1/me | retry_s=60\n" || w.Header().Get("Retry-After") != "60" {
		t.Errorf("429 body: %q retry-after %q", w.Body.String(), w.Header().Get("Retry-After"))
	}
	w = do(t, "GET", "/v1/kb", nil, 503, &Doc{Code: "busy", Head: "try later", RetryS: 7, Next: []Action{GET("/status", "")}})
	if !strings.HasSuffix(w.Body.String(), "next: GET /status | retry_s=7\n") || w.Header().Get("Retry-After") != "7" {
		t.Errorf("503 body: %q", w.Body.String())
	}
	// Fail maps APIError like core.Fail.
	r := httptest.NewRequest("GET", "/v1/kb/zzz", nil)
	rec := httptest.NewRecorder()
	Fail(rec, r, core.ErrNotFound)
	if rec.Code != 404 || !strings.HasPrefix(rec.Body.String(), "err notfound not found\nnext: GET /grammar | GET /help") {
		t.Errorf("Fail: %d %q", rec.Code, rec.Body.String())
	}
	// Tail for v1 hand-built text.
	r = httptest.NewRequest("GET", "/v1/t/12", nil)
	rec = httptest.NewRecorder()
	Tail(rec, r, "t12 open 2026-10-06\ntitle: x\n", POST("/v1/t/12/claim", "claim"))
	if rec.Body.String() != "t12 open 2026-10-06\ntitle: x\nnext: POST /v1/t/12/claim claim\n" {
		t.Errorf("Tail: %q", rec.Body.String())
	}
	if rec.Header().Get("ETag") == "" || rec.Header().Get("Cache-Control") != ccAPI {
		t.Errorf("Tail headers: %v", rec.Header())
	}
	// Grammar helpers.
	if Indent("a\r\nb\x00c\n\n") != "a\n  bc" || SafeLine("a\nb\tc") != "a b c" || OneLine("a\tb") || !OneLine("plain") {
		t.Errorf("grammar helpers")
	}
	if CleanMulti("a\u2028b\x7fc\td") != "abc\td" {
		t.Errorf("CleanMulti: %q", CleanMulti("a\u2028b\x7fc\td"))
	}
}

func TestMarkdownFencesAndEscape(t *testing.T) {
	d := sample()
	d.Title = "![x](https://e/p)"
	d.Fields = append(d.Fields, F{"fix", "run:\n```\nnpm i\n```\n", true})
	w := get(t, "/k/k7x2a9q.md", nil, d)
	b := w.Body.String()
	if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/markdown") {
		t.Errorf("content type %q", w.Header().Get("Content-Type"))
	}
	if !strings.HasPrefix(b, "# \\!\\[x\\]\\(https://e/p\\)\n") || strings.Contains(b, "![x](") {
		t.Errorf("title not escaped:\n%s", b)
	}
	if !strings.Contains(b, "**fix**:\n````\nrun:\n```\nnpm i\n```\n````\n") {
		t.Errorf("fence not longer than content:\n%s", b)
	}
	if !strings.Contains(b, "**symptom**:\n```\nline1\nline2\n```\n") {
		t.Errorf("multi-line fence:\n%s", b)
	}
	if !strings.Contains(b, "\nnext:\n- GET https://agents.ekaii.fr/k/k7x2a9q.md\n- POST https://agents.ekaii.fr/v1/kb/k7x2a9q/ok (token)\n") {
		t.Errorf("md next bullets with auto-absolute paths:\n%s", b)
	}
	if !strings.HasSuffix(b, "\npermalink: https://agents.ekaii.fr/k/k7x2a9q\n") {
		t.Errorf("permalink line:\n%s", b)
	}
	if !strings.Contains(b, "\nk7x2a9q fix ok3 bad0 2026-10-06 by a3fz9qk\n") {
		t.Errorf("head meta line:\n%s", b)
	}
	// Inline values are escaped too; rows are list items.
	d2 := &Doc{Head: "q: x hits=1", Fields: []F{{"title", "[a](b) *c* _d_ #e <f>", false}}, Rows: [][]string{{"k7x2a9q", "0.81", "fix", "[t](u)"}}}
	b = get(t, "/q/x.md", nil, d2).Body.String()
	if !strings.Contains(b, "**title**: \\[a\\]\\(b\\) \\*c\\* \\_d\\_ \\#e \\<f\\>\n") || !strings.Contains(b, "\n- k7x2a9q 0.81 fix \\[t\\]\\(u\\)\n") {
		t.Errorf("inline escaping:\n%s", b)
	}
	for in, want := range map[string]string{"plain": "plain", `a\b`: `a\\b`, "# h": `\# h`, "x\ny": "x y"} {
		if got := MDEscape(in); got != want {
			t.Errorf("MDEscape(%q) = %q want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"": "```", "a``b": "```", "````": "`````", "x\n```\ny": "````"} {
		if got := MarkdownFence(in); got != want {
			t.Errorf("MarkdownFence(%q) = %q want %q", in, got, want)
		}
	}
}

func TestJSONObjectNextArrayUntouched(t *testing.T) {
	d := sample()
	d.Fields = append(d.Fields, F{"fails", "one", false}, F{"fails", "two", false})
	w := get(t, "/k/k7x2a9q.json", nil, d)
	raw := w.Body.String()
	if !strings.HasPrefix(raw, `{"head":"k7x2a9q fix ok3 bad0 2026-10-06 by a3fz9qk","title":"Fix ECONNRESET","symptom":"line1\nline2","tags":"a,b","fails":["one","two"],"next":[`) {
		t.Errorf("json order/shape: %s", raw)
	}
	var obj struct {
		Head string `json:"head"`
		Next []struct{ Method, Path, Hint string }
	}
	if err := json.Unmarshal([]byte(raw), &obj); err != nil || len(obj.Next) != 2 || obj.Next[1].Hint != "(token)" || obj.Next[0].Path != "/k/k7x2a9q.md" {
		t.Errorf("json next: %v %s", err, raw)
	}
	if b := get(t, "/k/k7x2a9q.json?next=0", nil, sample()).Body.String(); strings.Contains(b, `"next"`) {
		t.Errorf("next=0 json: %s", b)
	}
	// Rows: arrays without Cols, objects with Cols.
	hits := &Doc{Head: "q: x hits=2", Rows: [][]string{{"k1aaaaa", "0.9", "fix", "t1"}, {"k2aaaaa", "0.5", "note", "t2 <b>"}}}
	b := get(t, "/q/x.json", nil, hits).Body.String()
	if !strings.Contains(b, `"rows":[["k1aaaaa","0.9","fix","t1"],["k2aaaaa","0.5","note","t2 <b>"]]`) {
		t.Errorf("rows arrays: %s", b)
	}
	hits.Cols = []string{"id", "score", "kind", "title"}
	b = get(t, "/q/x.json", nil, hits).Body.String()
	if !strings.Contains(b, `"rows":[{"id":"k1aaaaa","score":"0.9","kind":"fix","title":"t1"},`) {
		t.Errorf("rows objects: %s", b)
	}
	// Errors: v1 shape plus next.
	b = do(t, "GET", "/v1/kb?f=json", nil, 401, Error("auth", "token required")).Body.String()
	if !strings.HasPrefix(b, `{"err":"auth","msg":"token required","next":[{"method":"POST","path":"/v1/challenge"}`) {
		t.Errorf("json error: %s", b)
	}
	// Array-shaped v1 replies are untouched.
	r := httptest.NewRequest("GET", "/v1/kb?q=x", nil)
	rec := httptest.NewRecorder()
	ReplyJSONArray(rec, r, 200, []map[string]any{{"id": "k1aaaaa", "score": 0.9}})
	if rec.Body.String() != "[{\"id\":\"k1aaaaa\",\"score\":0.9}]\n" || rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("array: %q", rec.Body.String())
	}
	if rec.Header().Get("ETag") == "" || rec.Header().Get("Vary") != "Accept" {
		t.Errorf("array headers: %v", rec.Header())
	}
}

func TestHTMLLayoutCSPAndLD(t *testing.T) {
	d := sample()
	d.Forms = []Form{{Action: "/w/kb", Legend: "Post", Token: "tok123", Fields: []Field{{Name: "title", Max: 160}, {Name: "fix", Multi: true}, {Name: "hp", Hidden: true}}}}
	w := get(t, "/k/k7x2a9q", map[string]string{"Accept": "text/html"}, d)
	b := w.Body.String()
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("content type %q", ct)
	}
	if csp := w.Header().Get("Content-Security-Policy"); csp != "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'" {
		t.Errorf("csp %q", csp)
	}
	for _, want := range []string{
		"<title>Fix ECONNRESET</title>",
		`<meta name="robots" content="index,follow,max-snippet:-1,max-image-preview:large">`,
		`<link rel="canonical" href="https://agents.ekaii.fr/k/k7x2a9q">`,
		`<link rel="alternate" href="/k/k7x2a9q.md" type="text/markdown">`,
		`<link rel="alternate" href="/k/k7x2a9q.json" type="application/json">`,
		`<link rel="license" href="https://creativecommons.org/publicdomain/zero/1.0/">`,
		"<pre>k7x2a9q fix ok3 bad0 2026-10-06 by a3fz9qk\ntitle: Fix ECONNRESET\nsymptom: line1\n  line2\ntags: a,b</pre>",
		`<a href="/k/k7x2a9q.md">/k/k7x2a9q.md</a>`,
		`<code>POST /v1/kb/k7x2a9q/ok</code> <span class="meta">(token)</span>`,
		`<form method="post" action="/w/kb">`, `<input type="hidden" name="ft" value="tok123">`,
		`<input type="text" name="title" value="" maxlength="160">`, `<textarea name="fix" rows="4"></textarea>`,
		`<input type="hidden" name="hp" value="">`,
		`<script type="application/ld+json">`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("missing %q in:\n%s", want, b)
		}
	}
	// JSON-LD is valid JSON and cannot close the script element.
	m := regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`).FindStringSubmatch(b)
	if m == nil {
		t.Fatalf("no ld+json")
	}
	var ld map[string]any
	if err := json.Unmarshal([]byte(m[1]), &ld); err != nil || ld["name"] != "</script><b>x</b>" || strings.Contains(m[1], "</script") {
		t.Errorf("ld+json: %v %q", err, m[1])
	}
	if strings.Count(b, "</script>") != 1 {
		t.Errorf("script elements: %d", strings.Count(b, "</script>"))
	}
	// NoIndex pages: meta noindex + X-Robots-Tag.
	d.NoIndex = true
	w = get(t, "/k/k7x2a9q", map[string]string{"Accept": "text/html"}, d)
	if !strings.Contains(w.Body.String(), `<meta name="robots" content="noindex">`) || w.Header().Get("X-Robots-Tag") != "noindex" {
		t.Errorf("noindex page: %v", w.Header())
	}
	// Hostile title is escaped in <title>, <h1> and <pre>.
	h := &Doc{Head: "x", Title: "<script>alert(1)</script>", Fields: []F{{"title", "<img src=x onerror=alert(1)>", false}}}
	b = get(t, "/k/x.html", nil, h).Body.String()
	if strings.Contains(b, "<script>alert") || strings.Contains(b, "<img src") || !strings.Contains(b, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Errorf("html escaping:\n%s", b)
	}
	// Umami: script tag and CSP origin only when configured.
	SetSite(Site{Base: "https://agents.ekaii.fr", UmamiSrc: "https://u.example/script.js", UmamiID: "abc"})
	defer SetSite(Site{Base: "https://agents.ekaii.fr"})
	w = get(t, "/k/x.html", nil, sample())
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src https://u.example; connect-src https://u.example") || !strings.Contains(w.Body.String(), `<script defer src="https://u.example/script.js" data-website-id="abc"></script>`) {
		t.Errorf("umami: %q", w.Header().Get("Content-Security-Policy"))
	}
	if got := CSP(&core.Config{UmamiSrc: "https://u.example/script.js", UmamiID: "abc"}); got != w.Header().Get("Content-Security-Policy") {
		t.Errorf("CSP(cfg) = %q", got)
	}
	// Layout renders a custom body in the shell.
	r := httptest.NewRequest("GET", "/oauth/authorize", nil)
	rec := httptest.NewRecorder()
	Layout(rec, r, 200, Page{Title: "Consent", NoIndex: true, Body: "<h1>Allow?</h1>"})
	if !strings.Contains(rec.Body.String(), "<h1>Allow?</h1>") || !strings.Contains(rec.Body.String(), "<title>Consent</title>") || rec.Header().Get("Content-Security-Policy") == "" {
		t.Errorf("Layout: %s", rec.Body.String())
	}
	if lt := string(LinkTags([]Link{{Rel: "alternate", Href: "/f/kb.atom", Type: "application/atom+xml", Title: `a"b`}})); lt != "<link rel=\"alternate\" href=\"/f/kb.atom\" type=\"application/atom+xml\" title=\"a&#34;b\">\n" {
		t.Errorf("LinkTags: %q", lt)
	}
}

func TestETag304AndHEAD(t *testing.T) {
	w := get(t, "/k/k7x2a9q", nil, sample())
	et := w.Header().Get("ETag")
	if !regexp.MustCompile(`^W/"[0-9a-f]{16}"$`).MatchString(et) {
		t.Fatalf("etag %q", et)
	}
	for _, inm := range []string{et, strings.TrimPrefix(et, "W/"), `"other", ` + et, "*"} {
		w2 := get(t, "/k/k7x2a9q", map[string]string{"If-None-Match": inm}, sample())
		if w2.Code != 304 || w2.Body.Len() != 0 || w2.Header().Get("ETag") != et {
			t.Errorf("If-None-Match %q: %d %d", inm, w2.Code, w2.Body.Len())
		}
	}
	if w2 := get(t, "/k/k7x2a9q", map[string]string{"If-None-Match": `W/"0000000000000000"`}, sample()); w2.Code != 200 {
		t.Errorf("mismatch should be 200")
	}
	h := do(t, http.MethodHead, "/k/k7x2a9q", nil, 200, sample())
	if h.Code != 200 || h.Body.Len() != 0 || h.Header().Get("ETag") != et || h.Header().Get("Content-Length") != strconv.Itoa(w.Body.Len()) {
		t.Errorf("HEAD: %d body=%d etag=%q cl=%q", h.Code, h.Body.Len(), h.Header().Get("ETag"), h.Header().Get("Content-Length"))
	}
	if h2 := do(t, http.MethodHead, "/k/k7x2a9q", map[string]string{"If-None-Match": et}, 200, sample()); h2.Code != 304 {
		t.Errorf("HEAD 304: %d", h2.Code)
	}
	// Different formats have different ETags; non-200 and non-GET have none.
	if get(t, "/k/k7x2a9q.md", nil, sample()).Header().Get("ETag") == et {
		t.Errorf("md and txt share an etag")
	}
	if do(t, "GET", "/k/zzz", nil, 404, Error("notfound", "x")).Header().Get("ETag") != "" || do(t, "POST", "/v1/kb", nil, 201, sample()).Header().Get("ETag") != "" {
		t.Errorf("etag on non-200/non-GET")
	}
	if ETag([]byte("a")) == ETag([]byte("b")) {
		t.Errorf("ETag collision")
	}
}

func TestCacheControlTokenPrivate(t *testing.T) {
	cases := []struct {
		method, target, auth string
		status               int
		d                    *Doc
		want                 string
	}{
		{"GET", "/k/x", "", 200, sample(), ccPage},
		{"GET", "/v1/kb/x", "", 200, sample(), ccAPI},
		{"GET", "/v1/kb/x", "Bearer cx_abc", 200, sample(), "private, no-store"},
		{"GET", "/k/x", "Bearer cx_abc", 200, sample(), "private, no-store"},
		{"GET", "/v1/me?t=cx_abc", "", 200, sample(), "private, no-store"},
		{"POST", "/v1/kb", "", 201, sample(), "no-store"},
		{"GET", "/k/x", "", 404, Error("notfound", "x"), "public, max-age=60"},
		{"GET", "/k/x", "", 410, Error("gone", "x"), "public, max-age=60"},
		{"GET", "/k/x", "", 500, Error("internal", "x"), "no-store"},
		{"GET", "/k/x", "", 200, &Doc{Head: "h", MaxAge: 3600}, "public, max-age=3600, stale-while-revalidate=43200, stale-if-error=604800"},
		{"GET", "/k/x", "", 200, &Doc{Head: "h", MaxAge: -1}, "no-store"},
		{"GET", "/k/x", "Bearer cx_abc", 200, &Doc{Head: "h", MaxAge: 3600}, "private, no-store"},
	}
	for _, c := range cases {
		hdr := map[string]string{}
		if c.auth != "" {
			hdr["Authorization"] = c.auth
		}
		w := do(t, c.method, c.target, hdr, c.status, c.d)
		if got := w.Header().Get("Cache-Control"); got != c.want {
			t.Errorf("%s %s auth=%q %d: Cache-Control %q want %q", c.method, c.target, c.auth, c.status, got, c.want)
		}
		if w.Header().Get("Vary") != "Accept" {
			t.Errorf("Vary missing on %s %s", c.method, c.target)
		}
	}
	// Link headers: canonical, license on content, caller links; license not duplicated.
	w := get(t, "/k/k7x2a9q", nil, &Doc{Head: "h", Canonical: "/k/k7x2a9q", Links: []Link{{Rel: "alternate", Href: "/f/kb.atom", Type: "application/atom+xml"}}})
	links := strings.Join(w.Header().Values("Link"), "\n")
	for _, want := range []string{`</k/k7x2a9q>; rel="canonical"`, `</f/kb.atom>; rel="alternate"; type="application/atom+xml"`, `<https://creativecommons.org/publicdomain/zero/1.0/>; rel="license"`} {
		if !strings.Contains(links, want) {
			t.Errorf("Link %q missing in %q", want, links)
		}
	}
	r := httptest.NewRequest("GET", "/k/x", nil)
	rec := httptest.NewRecorder()
	rec.Header().Add("Link", `<https://x/>; rel="license"`)
	Reply(rec, r, 200, sample())
	if n := strings.Count(strings.Join(rec.Header().Values("Link"), " "), `rel="license"`); n != 1 {
		t.Errorf("license link duplicated: %d", n)
	}
	if do(t, "GET", "/k/x", nil, 404, Error("notfound", "x")).Header().Get("Link") != "" {
		t.Errorf("errors carry no license link")
	}
}

func bigDoc(n int) *Doc {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = "line " + strconv.Itoa(i) + " " + strings.Repeat("x", 40)
	}
	return &Doc{Head: "k7x2a9q fix", Fields: []F{{"title", "t", false}, {"fix", strings.Join(lines, "\n"), true}}, Next: []Action{GET("/help", "")}}
}

func TestBudgetOnlyWithFlag(t *testing.T) {
	d := bigDoc(600) // ~27 KB body, above the 4000-token cap
	full := get(t, "/k/k7x2a9q", nil, d).Body.String()
	if strings.Contains(full, "… +") || !strings.Contains(full, "line 599 ") {
		t.Errorf("v1 default must be unbounded")
	}
	for _, c := range []struct {
		target string
		hdr    map[string]string
		max    int
	}{{"/k/k7x2a9q?v=2", nil, 3200}, {"/k/k7x2a9q", map[string]string{"X-CX-V": "2"}, 3200}, {"/k/k7x2a9q?b=100", nil, 400}, {"/k/k7x2a9q?b=99999&v=2", nil, 16000}} {
		b := get(t, c.target, c.hdr, d).Body.String()
		if len(b) > c.max {
			t.Errorf("%s: %d bytes > %d", c.target, len(b), c.max)
		}
		if !strings.Contains(b, "\n… +") || !strings.HasSuffix(b, "next: GET /help\n") {
			t.Errorf("%s: cursor line or tail missing (%d bytes)", c.target, len(b))
		}
		for _, l := range strings.Split(strings.TrimRight(b, "\n"), "\n")[1:] {
			if !strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "title: ") && !strings.HasPrefix(l, "fix: ") && !strings.HasPrefix(l, "… +") && !strings.HasPrefix(l, "next: ") {
				t.Errorf("%s: partial line %q", c.target, l)
			}
		}
	}
	more := regexp.MustCompile(`… \+(\d+) more: (\S+)`).FindStringSubmatch(get(t, "/k/k7x2a9q?v=2", nil, d).Body.String())
	if more == nil || more[2] != "/k/k7x2a9q?b=0&v=2" {
		t.Errorf("continuation url: %v", more)
	}
	if b := get(t, "/k/k7x2a9q?v=2&b=0", nil, d).Body.String(); strings.Contains(b, "… +") {
		t.Errorf("b=0 means unbounded")
	}
	for target, want := range map[string]int{"/x": 0, "/x?v=2": 800, "/x?b=100": 100, "/x?b=0": 0, "/x?b=99999": 4000, "/x?b=junk&v=2": 800, "/x?b=-5": 800} {
		r := httptest.NewRequest("GET", target, nil)
		if got := Budget(r); got != want {
			t.Errorf("Budget(%s) = %d want %d", target, got, want)
		}
	}
	r := httptest.NewRequest("GET", "/x?v=2", nil)
	if BudgetFor(r, 400) != 400 || !V2(r) {
		t.Errorf("BudgetFor/V2")
	}
	// A list doc declares its own v2 default (400 tokens = 1600 bytes).
	d.Budget = 400
	if b := get(t, "/k/k7x2a9q?v=2", nil, d).Body.String(); len(b) > 1600 || !strings.Contains(b, "… +") {
		t.Errorf("Doc.Budget default: %d bytes", len(b))
	}
	// Tail honours budgets too; JSON truncates rows and adds more.
	r = httptest.NewRequest("GET", "/v1/kb/x?b=50", nil)
	rec := httptest.NewRecorder()
	Tail(rec, r, "head\n"+strings.Repeat("row xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n", 50), GET("/help", ""))
	if len(rec.Body.String()) > 200 || !strings.Contains(rec.Body.String(), "… +") {
		t.Errorf("Tail budget: %d", len(rec.Body.String()))
	}
}

func TestBudgetTruncationCursor(t *testing.T) {
	rows := make([][]string, 200)
	ts := make([]time.Time, 200)
	for i := range rows {
		ts[i] = time.Date(2026, 10, 6, 0, 0, i, 0, time.UTC)
		rows[i] = []string{"k" + strings.Repeat(strconv.Itoa(i%10), 6), "0.5", "fix", "title " + strconv.Itoa(i)}
	}
	d := &Doc{Head: "q: x hits=200", Rows: rows, Next: []Action{GET("/q/x?k=20", "")}, Cursor: func(i int) string { return Cursor(ts[i], rows[i][0]) }}
	b := get(t, "/q/x?b=100&k=20", nil, d).Body.String()
	if len(b) > 400 {
		t.Errorf("body %d bytes exceeds budget", len(b))
	}
	lines := strings.Split(strings.TrimRight(b, "\n"), "\n")
	more := lines[len(lines)-2]
	m := regexp.MustCompile(`^… \+(\d+) more: /q/x\?(\S+)$`).FindStringSubmatch(more)
	if m == nil {
		t.Fatalf("more line: %q in\n%s", more, b)
	}
	kept := len(lines) - 3
	if n, _ := strconv.Atoi(m[1]); n != 200-kept || kept < 2 {
		t.Errorf("kept %d more %s", kept, m[1])
	}
	q := m[2]
	if !strings.Contains(q, "b=100") || !strings.Contains(q, "k=20") || !strings.Contains(q, "after=") {
		t.Errorf("continuation query %q", q)
	}
	cur := regexp.MustCompile(`after=([^&]+)`).FindStringSubmatch(q)[1]
	gotTS, gotID, ok := DecodeCursor(cur)
	if !ok || !gotTS.Equal(ts[kept-1]) || gotID != rows[kept-1][0] {
		t.Errorf("cursor decodes to %v %q %v, want row %d", gotTS, gotID, ok, kept-1)
	}
	r := httptest.NewRequest("GET", "/q/x?after="+cur, nil)
	if ats, aid, ok := After(r); !ok || aid != gotID || !ats.Equal(gotTS) {
		t.Errorf("After()")
	}
	for _, bad := range []string{"", "!!!", strings.Repeat("A", 200), "YWJj"} {
		if _, _, ok := DecodeCursor(bad); ok {
			t.Errorf("DecodeCursor(%q) accepted", bad)
		}
	}
	if lines[len(lines)-1] != "next: GET /q/x?k=20" {
		t.Errorf("tail after cursor: %q", lines[len(lines)-1])
	}
	// Without a Cursor the continuation is the unbounded rendering.
	d.Cursor = nil
	if b := get(t, "/q/x?b=100", nil, d).Body.String(); !strings.Contains(b, "more: /q/x?b=0\n") {
		t.Errorf("no-cursor continuation:\n%s", b)
	}
	// JSON: rows truncated, more object.
	d.Cursor = func(i int) string { return Cursor(ts[i], rows[i][0]) }
	var obj struct {
		Rows [][]string
		More struct {
			N   int
			URL string
		}
	}
	if err := json.Unmarshal(get(t, "/q/x.json?b=100", nil, d).Body.Bytes(), &obj); err != nil || len(obj.Rows) == 0 || obj.More.N != 200-len(obj.Rows) || !strings.Contains(obj.More.URL, "after=") {
		t.Errorf("json more: %v %+v", err, obj)
	}
}

func TestFieldSelection(t *testing.T) {
	b := get(t, "/k/k7x2a9q?s=title", nil, sample()).Body.String()
	if b != "k7x2a9q fix ok3 bad0 2026-10-06 by a3fz9qk\ntitle: Fix ECONNRESET\nnext: GET /k/k7x2a9q.md | POST /v1/kb/k7x2a9q/ok (token)\n" {
		t.Errorf("?s=title:\n%s", b)
	}
	if b := get(t, "/k/k7x2a9q?s=tags,title", nil, sample()).Body.String(); !strings.Contains(b, "\ntitle: Fix ECONNRESET\ntags: a,b\n") {
		t.Errorf("doc order kept:\n%s", b)
	}
	hits := &Doc{Head: "q: x hits=2", Cols: []string{"id", "score", "kind", "title"}, Rows: [][]string{{"k1aaaaa", "0.9", "fix", "t1"}, {"k2aaaaa", "0.5", "note", "t2"}}}
	if b := get(t, "/q/x?s=id", nil, hits).Body.String(); b != "q: x hits=2\nk1aaaaa\nk2aaaaa\n" {
		t.Errorf("?s=id one id per line:\n%s", b)
	}
	if b := get(t, "/q/x?s=id,title", nil, hits).Body.String(); !strings.Contains(b, "\nk1aaaaa t1\n") {
		t.Errorf("?s=id,title:\n%s", b)
	}
	if b := get(t, "/q/x.json?s=id", nil, hits).Body.String(); !strings.Contains(b, `"rows":[{"id":"k1aaaaa"},{"id":"k2aaaaa"}]`) {
		t.Errorf("json ?s=id: %s", b)
	}
	if b := get(t, "/q/x?s=nope", nil, hits).Body.String(); b != "q: x hits=2\n- \n- \n" {
		t.Errorf("unknown column selection:\n%q", b)
	}
	r := httptest.NewRequest("GET", "/x?s=id,Bad,title,,a-b", nil)
	if got := Fields(r); strings.Join(got, ",") != "id,title,a-b" {
		t.Errorf("Fields: %v", got)
	}
}

func TestNextValidation(t *testing.T) {
	long := "/q/" + strings.Repeat("a", 170)
	acts := Next(
		GET("/k/k7x2a9q", ""),
		Action{"GET", "https://evil.example/x", ""},
		Action{"GET", "//evil.example/x", ""},
		Action{"GET", "/q/a b", ""},
		Action{"GET", "/q/%zz", ""},
		Action{"GET", "/q/a%20b?k=5&x=%C3%A9", "one two three four five"},
		Action{"FETCH", "/x", ""},
		Action{"GET", long, ""},
		Action{Hint: "retry 2026-10-07"},
		Action{"POST", "/w/kb", "+X-PoW\nnext: evil"},
		Action{"GET", "/q/x", "a|b"},
		GET("/five", ""),
	)
	want := []string{"GET /k/k7x2a9q", "GET /q/a%20b?k=5&x=%C3%A9 one two three", "retry 2026-10-07", "POST /w/kb +X-PoW next: evil"}
	got := make([]string, 0, len(acts))
	for _, a := range acts {
		got = append(got, a.String())
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("Next() = %q", got)
	}
	if len(Next(GET("/1", ""), GET("/2", ""), GET("/3", ""), GET("/4", ""), GET("/5", ""))) != MaxActions {
		t.Errorf("more than %d actions", MaxActions)
	}
	// The separator never survives inside a hint.
	if s := Next(Action{Hint: "a | b"}, Action{"GET", "/q/x", "a|b"}); s[0].String() != "a b" || s[1].Hint != "a b" {
		t.Errorf("separator in hints: %+v", s)
	}
	for _, bad := range []Action{{"GET", "", ""}, {"GET", "k/x", ""}, {"GET", "/x\n", ""}, {"GET", "/x<y>", ""}, {"GET", "/é", ""}, {"GET", "/x\"y", ""}, {Hint: ""}, {"GET", long, ""}} {
		if CheckAction(bad) == nil {
			t.Errorf("CheckAction accepted %+v", bad)
		}
	}
	for _, ok := range []Action{{"GET", "/k/x", ""}, {"DELETE", "/v1/subkey/a1", "revoke"}, {"GET", "/q/%E2%9C%93?k=5", ""}, {"GET", "/x?a=b&c=d#frag", ""}} {
		if err := CheckAction(ok); err != nil {
			t.Errorf("CheckAction(%+v): %v", ok, err)
		}
	}
	// Rendered line: hints are at most three words, actions joined by " | ".
	if l := tailLine(Next(GET("/a", "x y z w"), POST("/b", "")), false, 0); l != "next: GET /a x y z | POST /b" {
		t.Errorf("tailLine %q", l)
	}
}

func TestRawActionsHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/n/a3fz9qk/notes", nil)
	rec := httptest.NewRecorder()
	RawActions(rec, r, Action{"PUT", "/v1/n/a3fz9qk/notes", "edit"}, GET("/v1/n/a3fz9qk", ""), Action{"PATCH", "/v1/n/a3fz9qk/notes", ""})
	if rec.Header().Get("X-Next") != "PUT /v1/n/a3fz9qk/notes edit | GET /v1/n/a3fz9qk | PATCH /v1/n/a3fz9qk/notes" {
		t.Errorf("X-Next %q", rec.Header().Get("X-Next"))
	}
	if links := rec.Header().Values("Link"); len(links) != 1 || links[0] != `</v1/n/a3fz9qk/notes>; rel="edit"` {
		t.Errorf("Link %v", links)
	}
	rec = httptest.NewRecorder()
	RawActions(rec, httptest.NewRequest("GET", "/v1/n/a/b?next=0", nil), GET("/x", ""))
	if len(rec.Header()) != 0 {
		t.Errorf("next=0 wrote headers: %v", rec.Header())
	}
	rec = httptest.NewRecorder()
	RawActions(rec, httptest.NewRequest("GET", "/v1/n/a/b?abs=1", nil), Action{"PUT", "/v1/n/a/b", ""})
	if rec.Header().Get("X-Next") != "PUT https://agents.ekaii.fr/v1/n/a/b" || rec.Header().Get("Link") != `<https://agents.ekaii.fr/v1/n/a/b>; rel="edit"` {
		t.Errorf("abs raw actions: %v", rec.Header())
	}
	rec = httptest.NewRecorder()
	RawActions(rec, httptest.NewRequest("GET", "/d/s", nil), Action{"GET", "https://evil/", ""})
	if len(rec.Header()) != 0 {
		t.Errorf("invalid action wrote headers")
	}
}

func TestShFormatCurlLines(t *testing.T) {
	ResetSchemas()
	defer ResetSchemas()
	RegisterSchema("POST", "/v1/kb/{id}/ok", json.RawMessage(`{"type":"object","properties":{"v":{"type":"integer","minimum":0,"maximum":5},"applies":{"type":"string","maxLength":200}}}`))
	RegisterSchema("POST", "/w/kb", json.RawMessage(`{"type":"object","required":["title","fix"],"properties":{"title":{"type":"string","maxLength":160},"fix":{"type":"string","maxLength":2000},"tags":{"type":"array","items":{"type":"string"},"maxItems":10}}}`))
	d := sample()
	d.Next = []Action{GET("/k/k7x2a9q.md", ""), POST("/v1/kb/k7x2a9q/ok", "confirm it\nnext: x"), POST("/w/kb", "+X-PoW"), GET("/v1/me", "")}
	w := get(t, "/k/k7x2a9q.sh", nil, d)
	if ct := w.Header().Get("Content-Type"); ct != "text/x-shellscript; charset=utf-8" {
		t.Errorf("content type %q", ct)
	}
	b := w.Body.String()
	lines := strings.Split(strings.TrimRight(b, "\n"), "\n")
	if lines[0] != "#!/bin/sh" || lines[1] != "# k7x2a9q fix ok3 bad0 2026-10-06 by a3fz9qk" || lines[2] != "# title: Fix ECONNRESET" {
		t.Errorf("sh head:\n%s", b)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "curl ") {
			t.Errorf("executable non-curl line %q", l)
		}
	}
	for _, want := range []string{
		"# next:\n# GET /k/k7x2a9q.md\ncurl -sS -X GET 'https://agents.ekaii.fr/k/k7x2a9q.md'\n",
		"# confirm it next:\n# body: v:int 0..5 applies<=200\ncurl -sS -X POST -H \"Authorization: Bearer $CX_TOKEN\" -H \"Content-Type: text/plain\" --data-binary $'v: 0' 'https://agents.ekaii.fr/v1/kb/k7x2a9q/ok'\n",
		"# +X-PoW\n# body: title<=160* fix<=2000* tags[]<=10 (* required)\ncurl -sS -X POST -H \"X-PoW: $CX_POW\" -H \"Content-Type: text/plain\" --data-binary $'title: <title>\\nfix: <fix>' 'https://agents.ekaii.fr/w/kb'\n",
		"# GET /v1/me\ncurl -sS -X GET -H \"Authorization: Bearer $CX_TOKEN\" 'https://agents.ekaii.fr/v1/me'\n",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("missing:\n%s\nin:\n%s", want, b)
		}
	}
	// Quotes in paths cannot escape the single-quoted URL; ?f=sh and Accept work too.
	b = get(t, "/q/x?f=sh", nil, &Doc{Head: "q", Next: []Action{GET("/q/it's", "")}}).Body.String()
	if !strings.Contains(b, "'https://agents.ekaii.fr/q/it%27s'") || strings.Contains(b, "it's'") {
		t.Errorf("quote escaping:\n%s", b)
	}
	if ct := get(t, "/q/x", map[string]string{"Accept": "text/x-shellscript"}, sample()).Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Errorf("Accept sh: %q", ct)
	}
}

func TestAbsRewrite(t *testing.T) {
	rel := get(t, "/k/k7x2a9q", nil, sample())
	if !strings.HasSuffix(rel.Body.String(), "next: GET /k/k7x2a9q.md | POST /v1/kb/k7x2a9q/ok (token)\n") || rel.Header().Get("Link") != `</k/k7x2a9q>; rel="canonical"` {
		t.Errorf("relative by default: %q %v", rel.Body.String(), rel.Header().Values("Link"))
	}
	for _, c := range []struct {
		target string
		hdr    map[string]string
	}{{"/k/k7x2a9q?abs=1", nil}, {"/k/k7x2a9q", map[string]string{"X-CX-Abs": "1"}}, {"/k/k7x2a9q", map[string]string{"Accept": "text/markdown"}}} {
		w := get(t, c.target, c.hdr, sample())
		if !strings.Contains(w.Body.String(), "GET https://agents.ekaii.fr/k/k7x2a9q.md") || !strings.Contains(w.Body.String(), "POST https://agents.ekaii.fr/v1/kb/k7x2a9q/ok") {
			t.Errorf("%s %v: paths not absolute:\n%s", c.target, c.hdr, w.Body.String())
		}
		if w.Header().Values("Link")[0] != `<https://agents.ekaii.fr/k/k7x2a9q>; rel="canonical"` {
			t.Errorf("%s: Link %v", c.target, w.Header().Values("Link"))
		}
	}
	b := get(t, "/k/k7x2a9q.json?abs=1", nil, sample()).Body.String()
	if !strings.Contains(b, `"path":"https://agents.ekaii.fr/k/k7x2a9q.md"`) {
		t.Errorf("json abs: %s", b)
	}
}

func TestRedirectTwin303(t *testing.T) {
	try := func(method, target, accept string) (*httptest.ResponseRecorder, bool) {
		r := httptest.NewRequest(method, target, nil)
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		w := httptest.NewRecorder()
		return w, RedirectTwin(w, r)
	}
	cases := []struct {
		method, target, accept, loc string
	}{
		{"GET", "/k/k7x2a9q", "text/markdown", "/k/k7x2a9q.md"},
		{"GET", "/k/k7x2a9q", "text/plain", "/k/k7x2a9q.txt"},
		{"GET", "/k/k7x2a9q", "text/plain;q=0.8, text/markdown", "/k/k7x2a9q.md"},
		{"GET", "/k/k7x2a9q", "application/json", "/k/k7x2a9q.json"},
		{"GET", "/k/k7x2a9q?quarantine=1", "text/markdown", "/k/k7x2a9q.md?quarantine=1"},
		{"HEAD", "/", "text/markdown", "/index.md"},
		{"GET", "/kb/", "text/plain", "/kb/index.txt"},
		{"GET", "/k/k7x2a9q", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", ""},
		{"GET", "/k/k7x2a9q", "text/markdown, text/html;q=0.5", ""},
		{"GET", "/k/k7x2a9q", "*/*", ""},
		{"GET", "/k/k7x2a9q", "", ""},
		{"GET", "/k/k7x2a9q.md", "text/markdown", ""},
		{"GET", "/k/k7x2a9q?f=json", "text/markdown", ""},
		{"POST", "/k/k7x2a9q", "text/markdown", ""},
		{"GET", "/k/k7x2a9q", "image/png", ""},
	}
	for _, c := range cases {
		w, ok := try(c.method, c.target, c.accept)
		if (c.loc != "") != ok {
			t.Errorf("%s %s Accept=%q: redirected=%v", c.method, c.target, c.accept, ok)
			continue
		}
		if !ok {
			if w.Code != 200 || len(w.Header()) != 0 {
				t.Errorf("%s %s: wrote without redirecting", c.method, c.target)
			}
			continue
		}
		if w.Code != 303 || w.Header().Get("Location") != c.loc || w.Header().Get("Vary") != "Accept" {
			t.Errorf("%s %s Accept=%q: %d %q vary=%q", c.method, c.target, c.accept, w.Code, w.Header().Get("Location"), w.Header().Get("Vary"))
		}
	}
}

func TestStaleIfErrorHeaders(t *testing.T) {
	mod := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	body := []byte("<urlset/>")
	serve := func(method string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/sitemaps/pages.xml", nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		ServeStatic(w, r, mod, body, "application/xml")
		return w
	}
	w := serve("GET", nil)
	if w.Code != 200 || w.Body.String() != "<urlset/>" || w.Header().Get("Content-Type") != "application/xml" {
		t.Fatalf("static: %d %q", w.Code, w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != "public, max-age=300, stale-while-revalidate=3600, stale-if-error=604800" {
		t.Errorf("Cache-Control %q", cc)
	}
	if w.Header().Get("Last-Modified") != "Tue, 06 Oct 2026 12:00:00 GMT" {
		t.Errorf("Last-Modified %q", w.Header().Get("Last-Modified"))
	}
	et := w.Header().Get("ETag")
	if !regexp.MustCompile(`^"[0-9a-f]{16}"$`).MatchString(et) {
		t.Errorf("strong etag %q", et)
	}
	if w2 := serve("GET", map[string]string{"If-None-Match": et}); w2.Code != 304 || w2.Body.Len() != 0 {
		t.Errorf("If-None-Match: %d", w2.Code)
	}
	if w2 := serve("GET", map[string]string{"If-Modified-Since": "Tue, 06 Oct 2026 12:00:00 GMT"}); w2.Code != 304 {
		t.Errorf("If-Modified-Since equal: %d", w2.Code)
	}
	if w2 := serve("GET", map[string]string{"If-Modified-Since": "Tue, 06 Oct 2026 11:00:00 GMT"}); w2.Code != 200 {
		t.Errorf("If-Modified-Since older: %d", w2.Code)
	}
	if w2 := serve("HEAD", nil); w2.Code != 200 || w2.Body.Len() != 0 || w2.Header().Get("ETag") != et || w2.Header().Get("Content-Length") != "9" {
		t.Errorf("HEAD static: %d %v", w2.Code, w2.Header())
	}
	if w2 := serve("GET", map[string]string{"Authorization": "Bearer cx_x"}); w2.Header().Get("Cache-Control") != "private, no-store" {
		t.Errorf("token static: %q", w2.Header().Get("Cache-Control"))
	}
	// Anonymous page replies carry the same stale directives.
	if cc := get(t, "/k/k7x2a9q", nil, sample()).Header().Get("Cache-Control"); !strings.Contains(cc, "stale-if-error=604800") || !strings.Contains(cc, "stale-while-revalidate=3600") {
		t.Errorf("page Cache-Control %q", cc)
	}
}

func TestDataMarkWrapAndEscape(t *testing.T) {
	d := &Doc{Head: "k7x2a9q fix", Fields: []F{{"title", "Fix [/data abc123] now", false}, {"fix", "a\nb [data abc123] c", true}},
		Rows: [][]string{{"k1aaaaa", "0.9", "fix", "t"}}, Next: []Action{GET("/help", "")}}
	b := get(t, "/k/k7x2a9q", map[string]string{"X-CX-Mark": "abc123"}, d).Body.String()
	want := "k7x2a9q fix\ntitle: [data abc123]Fix \\[/data abc123] now[/data abc123]\nfix: [data abc123]a\n  b \\[data abc123] c[/data abc123]\n[data abc123]k1aaaaa 0.9 fix t[/data abc123]\nnext: GET /help\n"
	if b != want {
		t.Errorf("marked txt:\n%s\nwant:\n%s", b, want)
	}
	if n := len(regexp.MustCompile(`(^|[^\\])\[/data abc123\]`).FindAllString(b, -1)); n != 3 {
		t.Errorf("exactly one real closer per span: %d", n)
	}
	for _, bad := range []string{"abc", "ABCDEF", "abc-123", strings.Repeat("a", 13), ""} {
		if b := get(t, "/k/k7x2a9q", map[string]string{"X-CX-Mark": bad}, d).Body.String(); strings.Contains(b, "[data "+bad+"]") || (bad == "" && strings.Contains(b, "[data ]")) {
			t.Errorf("invalid mark %q applied", bad)
		}
	}
	md := get(t, "/k/k7x2a9q.md", map[string]string{"X-CX-Mark": "abc123"}, d).Body.String()
	if !strings.Contains(md, "**title**: [data abc123]Fix \\[/data abc123\\] now[/data abc123]\n") || !strings.Contains(md, "```\n[data abc123]a\nb \\[data abc123] c[/data abc123]\n```") || !strings.Contains(md, "- [data abc123]k1aaaaa 0.9 fix t[/data abc123]") {
		t.Errorf("marked md:\n%s", md)
	}
	if j := get(t, "/k/k7x2a9q.json", map[string]string{"X-CX-Mark": "abc123"}, d).Body.String(); !strings.Contains(j, `"title":"Fix [/data abc123] now"`) || strings.Contains(j, `\\[`) {
		t.Errorf("json must not carry marks or escapes: %s", j)
	}
	if h := get(t, "/k/k7x2a9q.html", map[string]string{"X-CX-Mark": "abc123"}, d).Body.String(); !strings.Contains(h, "<pre>k7x2a9q fix\ntitle: [data abc123]Fix") {
		t.Errorf("html pre carries marks")
	}
}

func TestProblemJSON(t *testing.T) {
	d := Error("auth", "token required")
	for _, c := range []struct {
		target string
		hdr    map[string]string
	}{{"/v1/kb", map[string]string{"Accept": "application/problem+json"}}, {"/v1/kb?f=problem", nil}, {"/v1/kb", map[string]string{"Accept": "application/json;q=0.5, application/problem+json"}}} {
		w := do(t, "POST", c.target, c.hdr, 401, d)
		if ct := w.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("%s: content type %q", c.target, ct)
		}
		var p struct {
			Type, Title, Detail, Instance string
			Status                        int
			Next                          []map[string]string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatalf("problem json: %v %s", err, w.Body.String())
		}
		if p.Type != "https://agents.ekaii.fr/help/err/auth" || p.Title != "auth" || p.Status != 401 || p.Detail != "token required" || p.Instance != "/v1/kb" || len(p.Next) != 3 || p.Next[0]["path"] != "/v1/challenge" {
			t.Errorf("problem fields: %+v", p)
		}
	}
	if b := do(t, "POST", "/v1/kb", map[string]string{"Accept": "application/problem+json"}, 401, d).Body.String(); !strings.HasPrefix(b, `{"type":"https://agents.ekaii.fr/help/err/auth","title":"auth","status":401,"detail":"token required","instance":"/v1/kb","next":[`) {
		t.Errorf("member order: %s", b)
	}
	// Non-error docs fall back to plain JSON; retry_s and extension members are carried.
	if w := get(t, "/k/k7x2a9q?f=problem", nil, sample()); w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("non-error problem: %q", w.Header().Get("Content-Type"))
	}
	q := Error("quota", "daily quota reached")
	q.Fields = []F{{"expect", "title<=160*", false}}
	b := do(t, "POST", "/v1/kb?f=problem", nil, 429, q).Body.String()
	if !strings.Contains(b, `"expect":"title<=160*"`) || !strings.Contains(b, `"retry_s":60`) {
		t.Errorf("problem extensions: %s", b)
	}
}

func TestExpectExampleLines(t *testing.T) {
	ResetSchemas()
	defer ResetSchemas()
	RegisterFragment(json.RawMessage(`{"paths":{"/v1/kb":{"post":{"operationId":"p","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["title","fix"],
		"properties":{"kind":{"type":"string","enum":["fix","status","note"]},"title":{"type":"string","maxLength":160},"symptom":{"type":"string","maxLength":1000},
		"fix":{"type":"string","maxLength":2000},"tags":{"type":"array","items":{"type":"string"},"maxItems":10},"force":{"type":"boolean"},"k":{"type":"integer","minimum":1,"maximum":20}}}}}}},
		"get":{"operationId":"s"}},"/v1/kb/{id}/ok":{"post":{"operationId":"ok","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"v":{"type":"integer"}}}}}}}}}}`))
	want := []string{
		"expect: kind:(fix|status|note) title<=160* symptom<=1000 fix<=2000* tags[]<=10 force:bool k:int 1..20 (* required)",
		`example: {"title":"<title>","fix":"<fix>"}`,
	}
	if got := Expect("POST /v1/kb"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Expect:\n%s", strings.Join(got, "\n"))
	}
	if got := Expect("/v1/kb"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Expect default method:\n%s", strings.Join(got, "\n"))
	}
	if got := ExpectCT("POST /v1/kb", "text/plain; charset=utf-8"); got[1] != "example: title: <title>\n  fix: <fix>" {
		t.Errorf("text example: %q", got[1])
	}
	if got := ExpectCT("POST /v1/kb", "application/x-www-form-urlencoded"); got[1] != "example: fix=%3Cfix%3E&title=%3Ctitle%3E" {
		t.Errorf("form example: %q", got[1])
	}
	if got := Expect("POST /v1/kb/k7x2a9q/ok"); len(got) != 2 || got[0] != "expect: v:int" || got[1] != `example: {"v":1}` {
		t.Errorf("template route: %q", got)
	}
	if got := Expect("GET /v1/kb"); got != nil {
		t.Errorf("no body schema: %q", got)
	}
	if got := Expect("POST /nope"); got != nil {
		t.Errorf("unknown route: %q", got)
	}
	// Err appends the lines on decoding errors of a known route, in the request's content type.
	r := httptest.NewRequest("POST", "/v1/kb", nil)
	r.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	Err(rec, r, 422, "bad", "field foo")
	if rec.Body.String() != "err bad field foo\nexpect: kind:(fix|status|note) title<=160* symptom<=1000 fix<=2000* tags[]<=10 force:bool k:int 1..20 (* required)\nexample: title: <title>\n  fix: <fix>\nnext: GET /help | GET /openapi.json\n" {
		t.Errorf("Err body:\n%s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	Err(rec, httptest.NewRequest("POST", "/v1/kb", nil), 401, "auth", "token required")
	if strings.Contains(rec.Body.String(), "expect:") {
		t.Errorf("401 must not carry expect lines")
	}
}
