package know

import (
	"context"
	"strings"
	"testing"
)

// seedReact posts the npm:react claims the delta-read tests share (one env per test, distinct libs
// per test file keep the trigram dedup out of the way).
func seedLib(t *testing.T, e *tenv, lib string) (tok string, ids map[string]string) {
	t.Helper()
	_, tok = e.registerL(t, "r-author", 1)
	ids = map[string]string{}
	for _, c := range []map[string]any{
		{"kind": "release", "v_to": "17.0.0", "effective": "2020-10-20", "title": "17.0.0 released with the new jsx transform", "sev": 0},
		{"kind": "new", "v_to": "18.3.0", "effective": "2024-04-25", "title": "18.3 adds warnings for the apis removed in 19", "sev": 1},
		{"kind": "breaking", "v_from": "18.3.0", "v_to": "19.0.0", "effective": "2024-12-05", "title": "19 removes legacy context and string refs", "sev": 2,
			"scope": "api", "migrate": "before: use string refs\nafter: use createRef or callback refs"},
		{"kind": "breaking", "v_from": "18.3.0", "v_to": "19.0.0", "effective": "2024-12-05", "title": "19 makes ref a regular prop on function components", "sev": 1, "scope": "api"},
		{"kind": "new", "v_to": "19.1.0", "effective": "2025-03-28", "title": "19.1 adds owner stacks for debugging", "sev": 0},
		{"kind": "release", "v_to": "19.1.0", "effective": "2025-03-28", "title": "19.1.0 released on the stable channel", "sev": 0},
	} {
		c["lib"] = lib
		c["source_url"] = "https://blog.example.net/" + strings.ReplaceAll(c["title"].(string), " ", "-")
		ids[c["title"].(string)] = e.claim(t, tok, c)
	}
	return tok, ids
}

func TestVersionRangePage(t *testing.T) {
	e := newEnv(t)
	seedLib(t, e, "npm:react")
	// hub
	st, body, _ := e.do(t, "GET", "/v/npm%3Areact", "", nil)
	if st != 200 || !strings.HasPrefix(first(body), "v: npm:react claims=6 versions=4 fixes=0") {
		t.Fatalf("hub: %d %s", st, body)
	}
	if !strings.Contains(body, "19.1.0 n=2 latest=2025-03-28") || !strings.Contains(body, "17.0.0 n=1 latest=2020-10-20") {
		t.Fatalf("hub version lines: %s", body)
	}
	// everything after 18.3.0, breaking first
	st, body, _ = e.do(t, "GET", "/v/npm%3Areact/18.3.0", "", nil)
	if st != 200 || !strings.HasPrefix(first(body), "v: npm:react after 18.3.0 claims=4") {
		t.Fatalf("version page: %d %s", st, body)
	}
	ls := lines(body)
	if !strings.Contains(ls[1], " unverified breaking npm:react 18.3.0->19.0.0 ") || !strings.Contains(ls[2], " breaking ") {
		t.Fatalf("breaking must come first: %q", ls)
	}
	if strings.Contains(body, "17.0.0 released") || strings.Contains(body, "18.3 adds warnings") {
		t.Fatalf("claims at or before 18.3.0 must be excluded:\n%s", body)
	}
	// range 18..19 (18.3.0 and both 19.0.0 claims; 19.1.0 excluded)
	st, body, _ = e.do(t, "GET", "/v/npm%3Areact/18..19", "", nil)
	if st != 200 || !strings.HasPrefix(first(body), "v: npm:react 18..19 claims=3") {
		t.Fatalf("range page: %d %s", st, body)
	}
	if strings.Contains(body, "19.1") {
		t.Fatalf("19.1.0 is outside 18..19:\n%s", body)
	}
	// kind filter
	st, body, _ = e.do(t, "GET", "/v/npm%3Areact/18..19?kind=new", "", nil)
	if st != 200 || !strings.HasPrefix(first(body), "v: npm:react 18..19 claims=1") {
		t.Fatalf("kind filter: %d %s", st, body)
	}
	// unknown version: 404 + miss
	st, body, _ = e.do(t, "GET", "/v/npm%3Areact/99.0.0", "", nil)
	if st != 404 || !strings.Contains(body, "no entries yet; gap listed on /wanted") {
		t.Fatalf("unknown version: %d %s", st, body)
	}
	if n := queryInt(t, `SELECT n FROM wanted WHERE kind = 'v' AND key = 'npm:react@99.0.0'`); n != 1 {
		t.Fatalf("miss recorded n=%d", n)
	}
	// a bad range is a 400, a bare alias resolves
	if st, _, _ = e.do(t, "GET", "/v/npm%3Areact/18..latest", "", nil); st != 400 {
		t.Fatalf("bad range: %d", st)
	}
	if st, body, _ = e.do(t, "GET", "/v/react/18.3.0", "", nil); st != 200 || !strings.HasPrefix(first(body), "v: npm:react after 18.3.0") {
		t.Fatalf("alias page: %d %s", st, body)
	}
	// ClaimsAfter export
	ls2, err := ClaimsAfter(context.Background(), testPool, "react", "18.3.0", []string{"breaking"})
	if err != nil || len(ls2) != 2 || ls2[0].Kind != "breaking" || ls2[0].VTo != "19.0.0" {
		t.Fatalf("ClaimsAfter: %+v %v", ls2, err)
	}
}

func TestBreakingChecklist(t *testing.T) {
	e := newEnv(t)
	_, ids := seedLib(t, e, "npm:chklib")
	st, body, _ := e.do(t, "GET", "/v/npm%3Achklib/18..19?kind=breaking", "", nil)
	if st != 200 || !strings.HasPrefix(first(body), "brk: npm:chklib 18..19 steps=2") {
		t.Fatalf("checklist: %d %s", st, body)
	}
	ls := lines(body)
	if !strings.HasPrefix(ls[1], "1. 19.0.0 unverified ") || !strings.HasPrefix(ls[2], "2. 19.0.0 unverified ") {
		t.Fatalf("ordered steps: %q", ls)
	}
	if !strings.Contains(ls[1], "sev2") || !strings.Contains(ls[1], "removes legacy context") || !strings.Contains(ls[1], ids["19 removes legacy context and string refs"]) {
		t.Fatalf("higher severity first with its id: %q", ls[1])
	}
	if strings.Contains(body, "migrate:") {
		t.Fatalf("migrate text only with full=1:\n%s", body)
	}
	st, body, _ = e.do(t, "GET", "/v/npm%3Achklib/18..19?kind=breaking&full=1", "", nil)
	if st != 200 || !strings.Contains(body, "migrate: before: use string refs") || !strings.Contains(body, "after: use createRef") {
		t.Fatalf("full checklist: %d %s", st, body)
	}
	if !strings.Contains(body, "next: ") || !strings.Contains(body, "GET /v/npm%3Achklib/18..19") {
		t.Fatalf("next tail: %s", body)
	}
	// op brk renders the same, tail-free
	out, err := Ops(e.d)["brk"](context.Background(), nil, []byte(`{"lib":"npm:chklib","from":"18","to":"19"}`))
	if err != nil || !strings.HasPrefix(out, "brk: npm:chklib 18..19 steps=2") || strings.Contains(out, "next:") {
		t.Fatalf("brk op: %q %v", out, err)
	}
	// no breaking changes in range -> 404
	if st, _, _ = e.do(t, "GET", "/v/npm%3Achklib/19..20?kind=breaking", "", nil); st != 404 {
		t.Fatalf("empty checklist: %d", st)
	}
}

func TestSinceAndCutoffLadder(t *testing.T) {
	e := newEnv(t)
	tok, _ := seedLib(t, e, "npm:sincelib")
	e.claim(t, tok, map[string]any{"lib": "pypi:otherlib", "kind": "release", "v_to": "3.2.0", "effective": "2025-05-01", "title": "otherlib 3.2.0 shipped with wheels for py313", "source_url": "https://blog.example.net/otherlib"})
	st, body, _ := e.do(t, "GET", "/since/2025-01?libs=npm:sincelib", "", nil)
	if st != 200 || !strings.HasPrefix(first(body), "since: 2025-01 claims=2 libs=npm:sincelib") {
		t.Fatalf("since: %d %s", st, body)
	}
	ls := lines(body)
	if !strings.HasPrefix(ls[1], "2025-03-28 ") || !strings.HasPrefix(ls[2], "2025-03-28 ") || strings.Contains(body, "2024-12-05") {
		t.Fatalf("since lines: %q", ls)
	}
	if st, body, _ = e.do(t, "GET", "/since/2024-06?libs=npm:sincelib,pypi:otherlib&k=2", "", nil); st != 200 || !strings.HasPrefix(first(body), "since: 2024-06 claims=2 ") {
		t.Fatalf("since k: %d %s", st, body)
	}
	if st, _, _ = e.do(t, "GET", "/since/not-a-date", "", nil); st != 400 {
		t.Fatalf("bad cutoff: %d", st)
	}
	// since{} bare uses identities.cutoff
	_, mtok := e.registerL(t, "cut-user", 0)
	me := e.ident(t, mtok)
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET cutoff = '2025-01' WHERE id = $1`, me.Root); err != nil {
		t.Fatal(err)
	}
	out, err := Ops(e.d)["since"](context.Background(), me, []byte(`{"libs":"npm:sincelib"}`))
	if err != nil || !strings.HasPrefix(out, "since: 2025-01 claims=2") {
		t.Fatalf("since op from identities.cutoff: %q %v", out, err)
	}
	// cutoff ladder: newest first, <date> <lib> <ver>, under 160 tokens
	st, body, _ = e.do(t, "GET", "/cutoff", "", nil)
	if st != 200 || !strings.HasPrefix(first(body), "cutoff: ") {
		t.Fatalf("cutoff: %d %s", st, body)
	}
	if len(body)/4 >= 160 {
		t.Fatalf("cutoff is %d bytes (~%d tokens), must stay under 160 tokens", len(body), len(body)/4)
	}
	ls = lines(body)
	var prev string
	seen := 0
	for _, l := range ls[1:] {
		f := strings.Fields(l)
		if len(f) != 3 || len(f[0]) != 10 {
			t.Fatalf("ladder line %q", l)
		}
		if prev != "" && f[0] > prev {
			t.Fatalf("ladder not newest first: %q", ls)
		}
		prev = f[0]
		if f[1] == "npm:sincelib" || f[1] == "pypi:otherlib" {
			seen++
		}
	}
	if seen < 2 {
		t.Fatalf("ladder lacks this test's releases: %q", ls)
	}
}

func TestPagesNegotiation(t *testing.T) {
	e := newEnv(t)
	seedLib(t, e, "npm:neglib")
	st, body, h := e.do(t, "GET", "/v/npm%3Aneglib/18.3.0", "", nil, "Accept", "text/html")
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/html") {
		t.Fatalf("html: %d %s %s", st, h.Get("Content-Type"), body)
	}
	for _, want := range []string{"<h1>npm:neglib 18.3.0: known changes and fixes</h1>", `application/ld+json`, `"TechArticle"`, `"ItemList"`, `rel="canonical" href="https://agents.example/v/npm%3Aneglib/18.3.0"`, "/f/v/npm%3Aneglib.atom"} {
		if !strings.Contains(body, want) {
			t.Fatalf("html lacks %q:\n%s", want, body)
		}
	}
	if !strings.Contains(h.Get("X-Robots-Tag"), "noindex") || !strings.Contains(body, `content="noindex"`) {
		t.Fatalf("unconfirmed L1 claims must not be indexable: %s", h.Get("X-Robots-Tag"))
	}
	st, body, h = e.do(t, "GET", "/v/npm%3Aneglib/18.3.0.md", "", nil)
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/markdown") || !strings.HasPrefix(body, "# npm:neglib 18.3.0: known changes and fixes") || !strings.Contains(body, "permalink: https://agents.example/v/npm%3Aneglib/18.3.0") {
		t.Fatalf("md: %d %s %s", st, h.Get("Content-Type"), body)
	}
	st, body, h = e.do(t, "GET", "/v/npm%3Aneglib/18.3.0", "", nil)
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/plain") || !strings.HasPrefix(body, "v: npm:neglib after 18.3.0 claims=4") || !strings.Contains(body, "\nnext: ") {
		t.Fatalf("txt: %d %s %s", st, h.Get("Content-Type"), body)
	}
	if cc := h.Get("Cache-Control"); !strings.HasPrefix(cc, "public") || h.Get("ETag") == "" {
		t.Fatalf("anonymous page caching: %q etag=%q", cc, h.Get("ETag"))
	}
	st, body, h = e.do(t, "GET", "/v/npm%3Aneglib/18.3.0?f=json", "", nil)
	if st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/json") || !strings.Contains(body, `"head":"v: npm:neglib after 18.3.0`) {
		t.Fatalf("json: %d %s %s", st, h.Get("Content-Type"), body)
	}
	// the hub negotiates too, and /wanted is noindex everywhere
	if st, body, h = e.do(t, "GET", "/v/npm%3Aneglib.md", "", nil); st != 200 || !strings.HasPrefix(body, "# npm:neglib: known changes and fixes") {
		t.Fatalf("hub md: %d %s", st, body)
	}
	if _, _, h = e.do(t, "GET", "/wanted", "", nil); !strings.Contains(h.Get("X-Robots-Tag"), "noindex") {
		t.Fatalf("/wanted X-Robots-Tag = %q", h.Get("X-Robots-Tag"))
	}
	// once confirmed by L2 roots from other networks the page becomes indexable (age permitting)
	_, l2a := e.registerL(t, "n-l2a", 2)
	_, l2b := e.registerL(t, "n-l2b", 2)
	st, body, _ = e.do(t, "GET", "/v1/v?lib=npm:neglib&kind=breaking", "", nil)
	id := strings.Fields(lines(body)[1])[0]
	e.mustVote(t, l2a, id, true, nil)
	e.mustVote(t, l2b, id, true, nil)
	if _, err := testPool.Exec(context.Background(), `UPDATE claims SET created = now() - interval '2 hours' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	_, body, h = e.do(t, "GET", "/v/npm%3Aneglib/18.3.0", "", nil, "Accept", "text/html")
	if h.Get("X-Robots-Tag") != "" || !strings.Contains(body, `content="index,follow`) {
		t.Fatalf("confirmed page should be indexable: %q", h.Get("X-Robots-Tag"))
	}
}
