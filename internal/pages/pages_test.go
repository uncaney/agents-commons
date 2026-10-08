package pages

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
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
	} else if pool, done := testdb.Open("pages", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping pages DB tests")
		os.Exit(0)
	}
	core.LevelFn = trust.LevelOf
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d     *core.Deps
	srv   *httptest.Server
	mux   *http.ServeMux
	roots []string
	ips   map[string]string
	kbs   []string
	tasks []int64
}

var (
	ipSeq  atomic.Int64
	ipBase = func() int64 {
		var b [1]byte
		rand.Read(b[:])
		return 16 + int64(b[0])%200
	}()
)

// nextIP hands every root its own /24 so super-group collapse never merges two test voters.
func nextIP() string {
	n := ipSeq.Add(1)
	return fmt.Sprintf("10.%d.%d.7", (ipBase+n/200)%256, 1+n%200)
}

func uniq(prefix string) string {
	var b [4]byte
	rand.Read(b[:])
	return prefix + " " + hex.EncodeToString(b[:])
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	ctx := context.Background()
	for _, sql := range []string{`TRUNCATE search_log, answer_pages, e_pages`, `TRUNCATE wanted, wanted_grp`} {
		if _, err := testPool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, PowBitsW: 4, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(ctx, cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	core.Register(mux, d)
	kb.Register(mux, d)
	Register(mux, d)
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	e := &tenv{d: d, srv: srv, mux: mux, ips: map[string]string{}}
	t.Cleanup(func() {
		testPool.Exec(ctx, `DELETE FROM kb_votes WHERE kb_id = ANY($1)`, e.kbs)
		testPool.Exec(ctx, `DELETE FROM kb WHERE id = ANY($1)`, e.kbs)
		testPool.Exec(ctx, `DELETE FROM tasks WHERE n = ANY($1)`, e.tasks)
		testPool.Exec(ctx, `DELETE FROM identities WHERE id = ANY($1) OR root = ANY($1)`, e.roots)
	})
	return e
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// get performs a request without following redirects; hdr are header pairs.
func (e *tenv) get(t *testing.T, method, path string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("CF-Connecting-IP", "10.250.0.9")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

// mkRoot inserts a root identity at standing level lvl (4.1 minimums) from its own /24.
func (e *tenv) mkRoot(t *testing.T, name string, lvl int) string {
	t.Helper()
	id := core.NewID('a')
	var th [32]byte
	rand.Read(th[:])
	rep, days, vnc := 0, 0, 0
	switch lvl {
	case 1:
		rep, days = 1, 4
	case 2:
		rep, days, vnc = 5, 4, 1
	case 3:
		rep, days, vnc = 20, 31, 1
	}
	ip := nextIP()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, root, token_hash, credits, rep, reg_ip, created, verified_noncompute, cohort)
		VALUES ($1, $2, $1, $3, 100, $4, $5, now() - $6 * interval '1 day', $7, $1)`, id, name, th[:], rep, ip, days, vnc); err != nil {
		t.Fatal(err)
	}
	e.roots = append(e.roots, id)
	e.ips[id] = ip
	return id
}

// mkSubkey inserts a subkey of root.
func (e *tenv) mkSubkey(t *testing.T, root string) string {
	t.Helper()
	id := core.NewID('a')
	var th [32]byte
	rand.Read(th[:])
	if _, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits) VALUES ($1, 'sub', $2, $2, $3, 0)`, id, root, th[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

type entryOpts struct {
	title, symptom, fix string
	tags                []string
	okW                 float32
	age                 time.Duration
	kind                string
}

// mkEntry inserts a kb row by root (visible, not quarantined) created age ago.
func (e *tenv) mkEntry(t *testing.T, root string, o entryOpts) string {
	t.Helper()
	id := core.NewID('k')
	if o.tags == nil {
		o.tags = []string{}
	}
	if o.kind == "" {
		o.kind = "fix"
	}
	if o.age == 0 {
		o.age = 2 * time.Hour
	}
	if _, err := testPool.Exec(context.Background(), `INSERT INTO kb (id, kind, title, symptom, cause, fix, versions, tags, author, author_root, ok_w, created, confirmed_at, expires_at)
		VALUES ($1, $2, $3, $4, '', $5, '', $6, $7, $7, $8::real, now() - $9 * interval '1 second', CASE WHEN $8::real > 0 THEN now() - interval '1 hour' END, now() + interval '180 days')`,
		id, o.kind, o.title, o.symptom, o.fix, o.tags, root, o.okW, int(o.age.Seconds())); err != nil {
		t.Fatal(err)
	}
	e.kbs = append(e.kbs, id)
	return id
}

// vote inserts an up vote by voter on kbID with weight w and saved tokens.
func (e *tenv) vote(t *testing.T, kbID, voter string, w float32, saved int) {
	t.Helper()
	ip := e.ips[voter]
	if _, err := testPool.Exec(context.Background(), `INSERT INTO kb_votes (kb_id, root, up, w, note, ip_group, ip_super, saved) VALUES ($1, $2, true, $3, '', $4, $5, $6)`,
		kbID, voter, w, core.IPGroup(ip), core.IPSuper(ip), saved); err != nil {
		t.Fatal(err)
	}
}

// mkTask inserts a task by root in state (open|done) created 2 h ago.
func (e *tenv) mkTask(t *testing.T, root, title, body, state string) int64 {
	t.Helper()
	var n int64
	if err := testPool.QueryRow(context.Background(), `INSERT INTO tasks (n, id, root, title, body, tags, state, created, closed_at)
		VALUES (nextval('task_n_seq'), $1, $1, $2, $3, '{}', $4, now() - interval '2 hours', CASE WHEN $4 = 'done' THEN now() END) RETURNING n`, root, title, body, state).Scan(&n); err != nil {
		t.Fatal(err)
	}
	e.tasks = append(e.tasks, n)
	return n
}

func (e *tenv) note(t *testing.T, n int64, by, text, kind string) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `INSERT INTO task_notes (n, by, root, text, kind) VALUES ($1, $2, $2, $3, $4)`, n, by, text, kind); err != nil {
		t.Fatal(err)
	}
}

func wantIn(t *testing.T, body string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(body, w) {
			t.Fatalf("missing %q in:\n%s", w, body)
		}
	}
}

func wantNotIn(t *testing.T, body string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(body, n) {
			t.Fatalf("unexpected %q in:\n%s", n, body)
		}
	}
}

var ldRe = regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`)

func ldOf(t *testing.T, body string) (string, map[string]any) {
	t.Helper()
	m := ldRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no ld+json in:\n%s", body)
	}
	var ld map[string]any
	if err := json.Unmarshal([]byte(m[1]), &ld); err != nil {
		t.Fatalf("ld+json does not parse: %v\n%s", err, m[1])
	}
	return m[1], ld
}

func firstLine(s string) string { return strings.SplitN(s, "\n", 2)[0] }

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}

// --- acceptance tests ------------------------------------------------------------------------

func TestGrammarEverywhere(t *testing.T) {
	e := newEnv(t)
	if Grammar() == "" || len(grammarLines()) < 5 {
		t.Fatal("grammar table missing")
	}
	for _, p := range []string{"/grammar", "/nonexistent-page", "/index.md", "/llms-full.txt", "/grammar.md", "/"} {
		st, body, hd := e.get(t, "GET", p, "Accept", "*/*")
		if p == "/nonexistent-page" && st != 404 || p != "/nonexistent-page" && st != 200 {
			t.Fatalf("%s: status %d\n%s", p, st, body)
		}
		for _, l := range grammarLines() {
			if p == "/grammar.md" {
				l = doc.MDEscape(l) // the markdown twin escapes link/heading characters (section 2)
			}
			if !strings.Contains(body, l) {
				t.Fatalf("%s lacks grammar line %q:\n%s", p, l, body)
			}
		}
		if p == "/grammar" && !strings.HasPrefix(hd.Get("Content-Type"), "text/plain") {
			t.Fatalf("/grammar content type %s", hd.Get("Content-Type"))
		}
	}
	st, body, _ := e.get(t, "GET", "/grammar.json")
	var j map[string]any
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || j["rows"] == nil {
		t.Fatalf("grammar.json: %d %s", st, body)
	}
	st, body, _ = e.get(t, "GET", "/help")
	if st != 200 || !strings.HasPrefix(body, "help:") {
		t.Fatalf("help: %d %s", st, body)
	}
	HelpFn = func() string { return "cx ops: s{q} search | g{id} read" }
	t.Cleanup(func() { HelpFn = nil })
	_, body, _ = e.get(t, "GET", "/help")
	wantIn(t, body, "cx ops: s{q} search", "next: GET /grammar")
	st, body, hd := e.get(t, "GET", "/now")
	if st != 200 || !strings.HasPrefix(body, "now=") || hd.Get("Cache-Control") != "no-store" {
		t.Fatalf("now: %d %s %s", st, body, hd.Get("Cache-Control"))
	}
	st, body, _ = e.get(t, "GET", "/v1")
	wantIn(t, body, "v1: ", "GET /v1/kb", "next: GET /openapi.json")
	if st != 200 {
		t.Fatalf("/v1: %d", st)
	}
}

func TestCatchAll404Grammar(t *testing.T) {
	e := newEnv(t)
	st, body, hd := e.get(t, "GET", "/nonexistent-page")
	if st != 404 || firstLine(body) != "err notfound /nonexistent-page" {
		t.Fatalf("404: %d %q", st, firstLine(body))
	}
	wantIn(t, body, "grammar: /q/<text>", "next: GET /grammar | GET /help")
	if hd.Get("X-Robots-Tag") != "noindex" {
		t.Fatalf("404 robots: %q", hd.Get("X-Robots-Tag"))
	}
	st, body, _ = e.get(t, "GET", "/no%0Aline%09here")
	if st != 404 || strings.Count(firstLine(body), "\n") != 0 || !strings.HasPrefix(body, "err notfound /no line here") {
		t.Fatalf("control chars in path not neutralised: %q", firstLine(body))
	}
	long := "/" + strings.Repeat("a", 300)
	_, body, _ = e.get(t, "GET", long)
	if l := firstLine(body); len(l) > len("err notfound ")+120 {
		t.Fatalf("path not cut to 120: %d", len(l))
	}
	st, body, _ = e.get(t, "HEAD", "/nonexistent-page")
	if st != 404 || body != "" {
		t.Fatalf("HEAD 404: %d %q", st, body)
	}
	// 405 helper: a path with a GET route answers other methods with Allow + the right method.
	st, body, hd = e.get(t, "POST", "/k/kabcdefg")
	if st != 405 || !strings.Contains(hd.Get("Allow"), "GET") {
		t.Fatalf("405: %d allow=%q\n%s", st, hd.Get("Allow"), body)
	}
	wantIn(t, body, "err method POST not allowed on /k/kabcdefg", "next: GET /k/kabcdefg")
	st, body, hd = e.get(t, "GET", "/mcp")
	if st != 405 || hd.Get("Allow") != "POST, OPTIONS" {
		t.Fatalf("GET /mcp: %d allow=%q", st, hd.Get("Allow"))
	}
	wantIn(t, body, "mcp: POST /mcp JSON-RPC 2.0, tool cx {op,a}, op=help")
	st, body, hd = e.get(t, "OPTIONS", "/")
	if st != 200 || !strings.Contains(hd.Get("Allow"), "GET") {
		t.Fatalf("OPTIONS /: %d %q", st, hd.Get("Allow"))
	}
	wantIn(t, body, "grammar:")
	st, _, hd = e.get(t, "OPTIONS", "/k/kabcdefg")
	if st != 204 || !strings.Contains(hd.Get("Allow"), "GET") {
		t.Fatalf("OPTIONS /k/: %d %q", st, hd.Get("Allow"))
	}
	// Did-you-mean suggestions from the router come first in next:.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/gramar", nil).WithContext(WithSuggestions(context.Background(), []string{"/grammar", "/help", "/ignored"}))
	NotFound(rec, req)
	if rec.Code != 404 {
		t.Fatalf("NotFound: %d", rec.Code)
	}
	wantIn(t, rec.Body.String(), "next: GET /grammar did you mean | GET /help did you mean | GET /grammar | GET /help")
}

func TestQSearchPageAndZeroHitMiss(t *testing.T) {
	e := newEnv(t)
	root := e.mkRoot(t, "qauthor", 2)
	title := uniq("ECONNREFUSED 127.0.0.1:5432 connecting to postgres from the pool")
	id := e.mkEntry(t, root, entryOpts{title: title, symptom: "connect ECONNREFUSED 127.0.0.1:5432", fix: "start postgres before the app"})
	q := "ECONNREFUSED 127.0.0.1:5432 " + title[len(title)-8:]
	st, body, hd := e.get(t, "GET", "/q/"+url.PathEscape(q))
	if st != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/plain") {
		t.Fatalf("/q: %d %s\n%s", st, hd.Get("Content-Type"), body)
	}
	if fl := firstLine(body); fl != "q: "+q+" hits=1" {
		t.Fatalf("head %q", fl)
	}
	wantIn(t, body, id+" ")
	if ll := lastLine(body); !strings.HasPrefix(ll, "next: GET /k/"+id+" | GET /q/") || !strings.Contains(ll, "POST /w/kb +X-PoW") {
		t.Fatalf("tail %q", ll)
	}
	if hd.Get("X-Robots-Tag") != "noindex" {
		t.Fatalf("robots %q", hd.Get("X-Robots-Tag"))
	}
	var n, days, supers int
	var top string
	if err := testPool.QueryRow(context.Background(), `SELECT n, days, cardinality(supers_h), top_id FROM search_log WHERE qn = $1`, normQ(q)).Scan(&n, &days, &supers, &top); err != nil {
		t.Fatalf("search_log row: %v", err)
	}
	if n != 1 || days != 1 || supers != 1 || top != id {
		t.Fatalf("search_log n=%d days=%d supers=%d top=%s", n, days, supers, top)
	}
	// ?q= fallback and ?k=.
	st, body, _ = e.get(t, "GET", "/q/?q="+url.QueryEscape(q)+"&k=20")
	if st != 200 || !strings.Contains(body, id) {
		t.Fatalf("?q= fallback: %d %s", st, body)
	}
	st, _, _ = e.get(t, "GET", "/q/")
	if st != 400 {
		t.Fatalf("empty q: %d", st)
	}
	// Zero hits: 404 with the error-page pointer and a demand record under the signature.
	zq := uniq("zzqx nothing here 4242")
	st, body, _ = e.get(t, "GET", "/q/"+url.PathEscape(zq))
	if st != 404 || firstLine(body) != "err notfound no entry for: "+zq {
		t.Fatalf("zero hit: %d %q", st, firstLine(body))
	}
	wantIn(t, body, "next: POST /v1/kb post a fix | GET /e/"+url.PathEscape(zq)+" error page")
	var wn int
	if err := testPool.QueryRow(context.Background(), `SELECT n FROM wanted WHERE kind = 'e' AND key = $1`, kb.ErrSig(zq)).Scan(&wn); err != nil || wn != 1 {
		t.Fatalf("wanted row: %v n=%d", err, wn)
	}
	// HTML rendering of the search page is noindex.
	st, body, _ = e.get(t, "GET", "/q/"+url.PathEscape(q), "Accept", "text/html")
	if st != 200 || !strings.Contains(body, `<meta name="robots" content="noindex">`) {
		t.Fatalf("html /q: %d", st)
	}
}

func TestErrSigNormalisation(t *testing.T) {
	e := newEnv(t)
	root := e.mkRoot(t, "eauthor", 2)
	tag := uniq("sigtest")[8:]
	title := "connect ECONNREFUSED 127.0.0.1:5432 " + tag
	id := e.mkEntry(t, root, entryOpts{title: title, symptom: "the pool starts before postgres", fix: "wait for the socket"})
	raw1 := "connect ECONNREFUSED 127.0.0.1:5432 " + tag
	raw2 := "connect ECONNREFUSED 10.0.0.1:6543 " + tag // numbers of >= 2 digits normalise to N
	sig := kb.ErrSig(raw1)
	if sig != kb.ErrSig(raw2) || strings.Contains(sig, "5432") {
		t.Fatalf("sig mismatch %q vs %q", sig, kb.ErrSig(raw2))
	}
	sum := sha256.Sum256([]byte(sig))
	hx := hex.EncodeToString(sum[:])
	for _, raw := range []string{raw1, raw2} {
		st, body, hd := e.get(t, "GET", "/e/"+url.PathEscape(raw)+".txt")
		if st != 200 {
			t.Fatalf("/e/%s: %d\n%s", raw, st, body)
		}
		if fl := firstLine(body); fl != fmt.Sprintf("e: %s hits=1 raw=%d", sig, len([]rune(raw))) {
			t.Fatalf("head %q", fl)
		}
		wantIn(t, body, "h: "+hx[:12], id+" ", "GET /h/"+hx, "GET /k/"+id)
		if lk := strings.Join(hd.Values("Link"), ", "); !strings.Contains(lk, "/e/"+url.PathEscape(sig)+`>; rel="canonical"`) {
			t.Fatalf("canonical link missing: %s", lk)
		}
		if hd.Get("X-Robots-Tag") != "noindex, follow" {
			t.Fatalf("robots %q", hd.Get("X-Robots-Tag"))
		}
	}
	// An Accept without text/html redirects to the escaped canonical twin, never the raw path.
	st, _, hd := e.get(t, "GET", "/e/"+url.PathEscape(raw2), "Accept", "text/plain")
	if st != 303 || hd.Get("Location") != "/e/"+url.PathEscape(sig)+".txt" {
		t.Fatalf("twin redirect: %d %q", st, hd.Get("Location"))
	}
	// Zero hits -> 404 with the hash pointer and a wanted row keyed by the signature.
	zraw := uniq("ZZNOSUCH failure 0xdeadbeef at /tmp/x/y.go:12:4")
	st, body, _ := e.get(t, "GET", "/e/"+url.PathEscape(zraw)+".txt")
	zsig := kb.ErrSig(zraw)
	if st != 404 || firstLine(body) != "err notfound no fix for: "+zsig {
		t.Fatalf("zero hit: %d %q", st, firstLine(body))
	}
	var wn int
	if err := testPool.QueryRow(context.Background(), `SELECT n FROM wanted WHERE kind = 'e' AND key = $1`, zsig).Scan(&wn); err != nil || wn != 1 {
		t.Fatalf("wanted: %v %d", err, wn)
	}
}

func TestEPageHitInlineFixAndSitemapTable(t *testing.T) {
	e := newEnv(t)
	l2 := e.mkRoot(t, "fixer", 2)
	title := uniq("TypeError: Cannot read properties of undefined (reading 'map') in render")
	id := e.mkEntry(t, l2, entryOpts{title: title, symptom: "items is undefined on first render", fix: "Guard the array: (items ?? []).map(...)\nsecond line of the fix", okW: 2})
	st, body, _ := e.get(t, "GET", "/e/"+url.PathEscape(title)+".txt")
	if st != 200 {
		t.Fatalf("/e: %d\n%s", st, body)
	}
	wantIn(t, body, "top: "+id+" ", "fix: Guard the array: (items ?? []).map(...)", "\n  second line of the fix")
	sig := kb.ErrSig(title)
	var kbID string
	if err := testPool.QueryRow(context.Background(), `SELECT kb_id FROM e_pages WHERE sig = $1`, sig).Scan(&kbID); err != nil || kbID != id {
		t.Fatalf("e_pages row: %v %q", err, kbID)
	}
	urls, err := e.sitemap(t, "answers")
	if err != nil || !urls[doc.Base()+"/e/"+url.PathEscape(sig)] {
		t.Fatalf("answers sitemap lacks /e/ page: %v %v", err, urls)
	}
	// HTML carries the signature as title and the index meta (indexable hit).
	st, body, _ = e.get(t, "GET", "/e/"+url.PathEscape(title), "Accept", "text/html")
	if st != 200 || !strings.Contains(body, "<title>"+html.EscapeString(sig)+"</title>") || !strings.Contains(body, `content="index,follow`) {
		t.Fatalf("html /e: %d\n%s", st, body)
	}
	// A hit that is not indexable renders but never enters e_pages.
	l0 := e.mkRoot(t, "newbie", 0)
	t2 := uniq("ZZTOP unique nonindexable error 77")
	e.mkEntry(t, l0, entryOpts{title: t2, fix: "some fix"})
	st, body, _ = e.get(t, "GET", "/e/"+url.PathEscape(t2)+".txt")
	if st != 200 || !strings.HasPrefix(body, "e: ") {
		t.Fatalf("/e L0: %d %s", st, body)
	}
	var n int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM e_pages WHERE sig = $1`, kb.ErrSig(t2)).Scan(&n)
	if n != 0 {
		t.Fatal("non-indexable hit entered e_pages")
	}
	// The daily prune drops rows whose entry stopped being indexable.
	testPool.Exec(context.Background(), `UPDATE kb SET hidden = true WHERE id = $1`, id)
	h := active.Load()
	h.lastEPrune = time.Time{}
	if err := h.pruneEPages(context.Background()); err != nil {
		t.Fatal(err)
	}
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM e_pages WHERE sig = $1`, sig).Scan(&n)
	if n != 0 {
		t.Fatal("prune kept a hidden entry's row")
	}
}

// sitemap runs a registered sitemap child and returns its locations.
func (e *tenv) sitemap(t *testing.T, name string) (map[string]bool, error) {
	t.Helper()
	fn := e.d.Sitemaps()[name]
	if fn == nil {
		t.Fatalf("sitemap %s not registered", name)
	}
	urls, err := fn(context.Background())
	out := map[string]bool{}
	for _, u := range urls {
		out[u.Loc] = true
	}
	return out, err
}

func TestPermalinksNegotiated(t *testing.T) {
	e := newEnv(t)
	root := e.mkRoot(t, "author", 2)
	title := uniq("Permalink entry title for negotiation")
	id := e.mkEntry(t, root, entryOpts{title: title, symptom: "sym", fix: "fix it", tags: []string{"go"}})
	st, _, hd := e.get(t, "GET", "/k/"+id, "Accept", "text/plain")
	if st != 303 || hd.Get("Location") != "/k/"+id+".txt" {
		t.Fatalf("twin: %d %q", st, hd.Get("Location"))
	}
	st, body, hd := e.get(t, "GET", "/k/"+id+".txt")
	if st != 200 || !strings.HasPrefix(body, id+" fix ok0 bad0 ") {
		t.Fatalf("txt: %d %s", st, body)
	}
	wantIn(t, body, "title: "+title, "url: https://agents.example/k/"+id, "next: POST /v1/kb/"+id+"/ok | POST /v1/kb/"+id+"/bad | GET /k/"+id+".md")
	if lk := strings.Join(hd.Values("Link"), ", "); !strings.Contains(lk, "/kb/"+id+`>; rel="canonical"`) {
		t.Fatalf("canonical: %s", lk)
	}
	st, body, hd = e.get(t, "GET", "/k/"+id+".md")
	if st != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/markdown") || !strings.HasPrefix(body, "# "+doc.MDEscape(title)) || !strings.Contains(body, "\nnext:\n- POST /v1/kb/"+id+"/ok") {
		t.Fatalf("md: %d %s\n%s", st, hd.Get("Content-Type"), body)
	}
	st, body, hd = e.get(t, "GET", "/k/"+id+".json")
	var j map[string]any
	if st != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "application/json") || json.Unmarshal([]byte(body), &j) != nil || j["id"] != id || j["next"] == nil {
		t.Fatalf("json: %d %s", st, body)
	}
	for _, acc := range []string{"text/html", ""} {
		st, _, hd = e.get(t, "GET", "/k/"+id, "Accept", acc)
		if st != 301 || hd.Get("Location") != "/kb/"+id {
			t.Fatalf("html -> canonical: %d %q", st, hd.Get("Location"))
		}
	}
	st, body, _ = e.get(t, "GET", "/k/kzzzzzz.txt")
	if st != 404 || firstLine(body) != "err notfound no entry kzzzzzz" {
		t.Fatalf("unknown: %d %q", st, firstLine(body))
	}
	// KbNextFn replaces the default actions for anonymous callers (27.2).
	KbNextFn = func(kid string, anon bool) []doc.Action { return []doc.Action{doc.POST("/w/k/"+kid+"/ok", "+X-PoW")} }
	_, body, _ = e.get(t, "GET", "/k/"+id+".txt")
	KbNextFn = nil
	wantIn(t, body, "next: POST /w/k/"+id+"/ok +X-PoW")
	// Tasks: text with next:, HTML with DiscussionForumPosting + Comment (L1+ authors only).
	creator := e.mkRoot(t, "creator", 2)
	l1 := e.mkRoot(t, "noter", 1)
	l0 := e.mkRoot(t, "lurker", 0)
	n := e.mkTask(t, creator, "Fix the flaky CI job", "the job fails on\nalternate runs", "open")
	e.note(t, n, l1, "I can take this one", "note")
	e.note(t, n, l0, "spam note from a fresh root", "note")
	ns := fmt.Sprint(n)
	st, body, _ = e.get(t, "GET", "/t/"+ns)
	if st != 200 || !strings.HasPrefix(body, "#"+ns+" open by "+creator+" ") {
		t.Fatalf("task txt: %d %s", st, body)
	}
	wantIn(t, body, "title: Fix the flaky CI job", "body: the job fails on\n  alternate runs", "notes: 2", "note: "+l1+" ", "url: https://agents.example/t/"+ns,
		"next: POST /v1/t/"+ns+"/claim | POST /v1/t/"+ns+"/note | POST /v1/t/"+ns+"/done | GET /f/t.atom")
	st, body, _ = e.get(t, "GET", "/t/"+ns, "Accept", "text/html")
	if st != 200 {
		t.Fatalf("task html: %d", st)
	}
	raw, ld := ldOf(t, body)
	if ld["@type"] != "DiscussionForumPosting" || ld["interactionStatistic"] == nil {
		t.Fatalf("task ld: %s", raw)
	}
	comments, _ := ld["comment"].([]any)
	if len(comments) != 1 || !strings.Contains(raw, "I can take this one") || strings.Contains(raw, "spam note") {
		t.Fatalf("comments from L1+ only: %s", raw)
	}
	if !strings.Contains(raw, `"userInteractionCount":2`) {
		t.Fatalf("interaction count: %s", raw)
	}
	st, _, _ = e.get(t, "GET", "/t/999999999")
	if st != 404 {
		t.Fatalf("missing task: %d", st)
	}
	testPool.Exec(context.Background(), `UPDATE tasks SET state = 'hidden' WHERE n = $1`, n)
	if st, _, _ = e.get(t, "GET", "/t/"+ns); st != 404 {
		t.Fatalf("hidden task visible: %d", st)
	}
}

func TestProfileAggregatesOnlyAndNameGate(t *testing.T) {
	e := newEnv(t)
	root := e.mkRoot(t, "nice-agent", 2)
	voter := e.mkRoot(t, "voter", 2)
	id1 := e.mkEntry(t, root, entryOpts{title: uniq("profile fix one"), fix: "a"})
	e.mkEntry(t, root, entryOpts{title: uniq("profile fix two"), fix: "b"})
	e.vote(t, id1, voter, 1.5, 12400)
	e.mkTask(t, root, "done task", "", "done")
	ProfileExtraFn = append(ProfileExtraFn, func(context.Context, core.Q, string) []string { return []string{"confirmers=1 nets=1"} })
	t.Cleanup(func() { ProfileExtraFn = nil })
	st, body, _ := e.get(t, "GET", "/a/"+root)
	if st != 200 {
		t.Fatalf("/a: %d %s", st, body)
	}
	if fl := firstLine(body); !strings.HasPrefix(fl, root+" nice-agent lvl=L2 rep=5 since=") || !strings.Contains(fl, " fixes=2 confirmed=1 tasks_done=1 saved=12.4k") {
		t.Fatalf("head %q", fl)
	}
	wantIn(t, body, "confirmers=1 nets=1", "next: GET /f/a/"+root+".atom | GET /b/a/"+root+".svg")
	wantNotIn(t, body, e.ips[root], e.ips[voter], voter)
	st, body, _ = e.get(t, "GET", "/a/"+root, "Accept", "text/html")
	raw, ld := ldOf(t, body)
	if st != 200 || ld["@type"] != "ProfilePage" || !strings.Contains(raw, `"name":"nice-agent"`) || !strings.Contains(body, `content="index,follow`) {
		t.Fatalf("profile html: %d %s", st, raw)
	}
	// Reserved names never show; the id does.
	res := e.mkRoot(t, "anthropic", 0)
	_, body, _ = e.get(t, "GET", "/a/"+res)
	if fl := firstLine(body); !strings.HasPrefix(fl, res+" lvl=L0 rep=0 ") || strings.Contains(body, "anthropic") {
		t.Fatalf("reserved name shown: %q", fl)
	}
	// Subkeys and unknown ids are absent.
	sub := e.mkSubkey(t, root)
	if st, _, _ = e.get(t, "GET", "/a/"+sub); st != 404 {
		t.Fatalf("subkey profile: %d", st)
	}
	if st, _, _ = e.get(t, "GET", "/a/azzzzzz"); st != 404 {
		t.Fatalf("unknown profile: %d", st)
	}
}

func TestResolver(t *testing.T) {
	e := newEnv(t)
	root := e.mkRoot(t, "res", 2)
	title := uniq("Resolver entry")
	id := e.mkEntry(t, root, entryOpts{title: title, fix: "x"})
	st, body, _ := e.get(t, "GET", "/x/"+id)
	if st != 200 || firstLine(body) != "kb "+title+" https://agents.example/k/"+id {
		t.Fatalf("/x kb: %d %q", st, firstLine(body))
	}
	wantIn(t, body, "next: GET /k/"+id)
	e.d.RegisterResolver('t', func(_ context.Context, id string) (string, string, string, bool) {
		if id == "t:12" {
			return "task", "A task title", "/t/12", true
		}
		return "", "", "", false
	})
	st, body, _ = e.get(t, "GET", "/x/t:12")
	if st != 200 || firstLine(body) != "task A task title /t/12" {
		t.Fatalf("/x task: %d %q", st, firstLine(body))
	}
	wantIn(t, body, "next: GET /t/12")
	if st, _, _ = e.get(t, "GET", "/x/t:13"); st != 404 {
		t.Fatalf("unknown task: %d", st)
	}
	if st, _, _ = e.get(t, "GET", "/x/not-an-id"); st != 400 {
		t.Fatalf("bad id: %d", st)
	}
	if st, _, _ = e.get(t, "GET", "/x/kzzzzzz"); st != 404 {
		t.Fatalf("unknown id: %d", st)
	}
	if st, _, _ = e.get(t, "GET", "/x/"+strings.Repeat("ab", 32)); st != 404 {
		t.Fatalf("hash without resolver: %d", st)
	}
}

func TestTagPage(t *testing.T) {
	e := newEnv(t)
	root := e.mkRoot(t, "tagger", 2)
	tag := "pgtag" + uniq("")[1:5]
	id1 := e.mkEntry(t, root, entryOpts{title: uniq("tagged one"), fix: "a", tags: []string{tag, "pool"}, okW: 1})
	id2 := e.mkEntry(t, root, entryOpts{title: uniq("tagged two"), fix: "b", tags: []string{tag}})
	l0 := e.mkRoot(t, "l0tagger", 0)
	id3 := e.mkEntry(t, l0, entryOpts{title: uniq("tagged nonindexable"), fix: "c", tags: []string{tag}})
	st, body, _ := e.get(t, "GET", "/tag/"+tag+".txt")
	if st != 200 || firstLine(body) != "tag: "+tag+" n=2" {
		t.Fatalf("tag txt: %d %q\n%s", st, firstLine(body), body)
	}
	wantIn(t, body, id1+" ok1 ", id2+" ok0 ", "next: GET /f/kb/"+tag+".atom")
	wantNotIn(t, body, id3)
	st, body, hd := e.get(t, "GET", "/tag/"+tag, "Accept", "text/html")
	raw, ld := ldOf(t, body)
	if st != 200 || ld["@type"] != "CollectionPage" || !strings.Contains(raw, `"numberOfItems":2`) {
		t.Fatalf("tag html: %d %s", st, raw)
	}
	wantIn(t, body, `<link rel="canonical" href="https://agents.example/tag/`+tag+`">`, `href="/f/kb/`+tag+`.atom"`)
	if lk := strings.Join(hd.Values("Link"), ", "); !strings.Contains(lk, "/tag/"+tag+`>; rel="canonical"`) {
		t.Fatalf("canonical header: %s", lk)
	}
	st, _, hd = e.get(t, "GET", "/tag/"+tag, "Accept", "text/markdown")
	if st != 303 || hd.Get("Location") != "/tag/"+tag+".md" {
		t.Fatalf("tag twin: %d %q", st, hd.Get("Location"))
	}
	TagCanonFn = func(a string) (string, bool) {
		if a == tag+"ql" {
			return tag, true
		}
		return "", false
	}
	t.Cleanup(func() { TagCanonFn = nil })
	st, _, hd = e.get(t, "GET", "/tag/"+tag+"ql.txt")
	if st != 301 || hd.Get("Location") != "/tag/"+tag+".txt" {
		t.Fatalf("alias: %d %q", st, hd.Get("Location"))
	}
	if st, _, _ = e.get(t, "GET", "/tag/nothing-here-"+tag+".txt"); st != 404 {
		t.Fatalf("empty tag: %d", st)
	}
	if st, _, _ = e.get(t, "GET", "/tag/Bad%20Tag"); st != 404 {
		t.Fatalf("invalid tag: %d", st)
	}
	urls, err := e.sitemap(t, "tags")
	if err != nil || !urls[doc.Base()+"/tag/"+tag] || !urls[doc.Base()+"/tag/pool"] {
		t.Fatalf("tags sitemap: %v %v", err, urls)
	}
}

func TestAnswerPagesTopTitleAndSuperThreshold(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	author := e.mkRoot(t, "pgxpert", 2)
	v1, v2 := e.mkRoot(t, "v1", 2), e.mkRoot(t, "v2", 2)
	title := "Pool exhausted: increase max connections for pgx under load " + uniq("")[1:5]
	id := e.mkEntry(t, author, entryOpts{title: title, symptom: "pgx pool timeout: all connections busy", fix: "Set MaxConns on the pool config\nand close rows", okW: 3})
	e.vote(t, id, v1, 1.5, 0)
	e.vote(t, id, v2, 1.5, 0)
	rel := e.mkEntry(t, author, entryOpts{title: uniq("Related pool entry"), fix: "related fix", okW: 1})
	kb.RelatedFn = func(_ context.Context, _ core.Q, kid string) []string {
		if kid == id {
			return []string{rel}
		}
		return nil
	}
	t.Cleanup(func() { kb.RelatedFn = nil })
	qn := "pgx pool timeout under load " + uniq("")[1:5]
	h1, h2, h3 := make([]byte, 16), make([]byte, 16), make([]byte, 16)
	rand.Read(h1)
	rand.Read(h2)
	rand.Read(h3)
	if _, err := testPool.Exec(ctx, `INSERT INTO search_log (qn, n, days, last_day, top_id, supers_h) VALUES ($1, 12, 5, current_date, $2, $3)`, qn, id, [][]byte{h1, h2}); err != nil {
		t.Fatal(err)
	}
	if n, err := mintAnswers(ctx, testPool, time.Now()); err != nil || n != 0 {
		t.Fatalf("2 supers minted %d (%v)", n, err)
	}
	var cnt int
	testPool.QueryRow(ctx, `SELECT count(*) FROM answer_pages WHERE qn = $1`, qn).Scan(&cnt)
	if cnt != 0 {
		t.Fatal("page minted below the super-group threshold")
	}
	testPool.Exec(ctx, `UPDATE search_log SET supers_h = $2 WHERE qn = $1`, qn, [][]byte{h1, h2, h3})
	if n, err := mintAnswers(ctx, testPool, time.Now()); err != nil || n != 1 {
		t.Fatalf("3 supers minted %d (%v)", n, err)
	}
	var slug string
	var ids []string
	if err := testPool.QueryRow(ctx, `SELECT slug, kb_ids FROM answer_pages WHERE qn = $1`, qn).Scan(&slug, &ids); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(slug, "pool-exhausted-increase-max-connections-for-pgx-under-load-") || len(ids) != 2 || ids[0] != id || ids[1] != rel {
		t.Fatalf("slug %q ids %v", slug, ids)
	}
	if n, _ := mintAnswers(ctx, testPool, time.Now()); n != 0 {
		t.Fatalf("re-mint created %d", n)
	}
	st, body, _ := e.get(t, "GET", "/qa/"+slug, "Accept", "text/html")
	if st != 200 {
		t.Fatalf("/qa html: %d\n%s", st, body)
	}
	wantIn(t, body, "<h1>"+title+"</h1>", "<title>"+title+"</title>", `data-nosnippet>asked as: `+qn+" (agents, 5 days)", "Set MaxConns on the pool config", `href="/k/`+rel+`"`, `content="index,follow`)
	raw, ld := ldOf(t, body)
	if ld["@type"] != "QAPage" || strings.Contains(raw, qn) || !strings.Contains(raw, `"acceptedAnswer"`) || !strings.Contains(raw, `"suggestedAnswer"`) {
		t.Fatalf("qa ld: %s", raw)
	}
	if tt := regexp.MustCompile(`<title>([^<]*)</title>`).FindStringSubmatch(body); tt == nil || strings.Contains(tt[1], qn) {
		t.Fatalf("query leaked into title: %v", tt)
	}
	st, body, _ = e.get(t, "GET", "/qa/"+slug+".txt")
	if st != 200 || firstLine(body) != "qa: "+title {
		t.Fatalf("/qa txt: %d %q", st, firstLine(body))
	}
	wantIn(t, body, "asked-as: "+qn+" (agents, 5 days)", "fix: Set MaxConns on the pool config\n  and close rows", "next: GET /k/"+id+" | POST /v1/kb/"+id+"/ok")
	if st, _, _ = e.get(t, "GET", "/qa/"+slug+".md"); st != 200 {
		t.Fatalf("/qa md: %d", st)
	}
	st, _, hd := e.get(t, "GET", "/q/"+url.PathEscape(qn))
	if st != 301 || hd.Get("Location") != "/qa/"+slug {
		t.Fatalf("/q -> /qa: %d %q", st, hd.Get("Location"))
	}
	st, _, hd = e.get(t, "GET", "/e/"+url.PathEscape(qn)+".txt")
	if st != 301 || hd.Get("Location") != "/qa/"+slug+".txt" {
		t.Fatalf("/e -> /qa: %d %q", st, hd.Get("Location"))
	}
	urls, err := e.sitemap(t, "answers")
	if err != nil || !urls[doc.Base()+"/qa/"+slug] {
		t.Fatalf("answers sitemap: %v %v", err, urls)
	}
	// Top entry gone -> re-pointed to the related entry; everything gone -> 410.
	testPool.Exec(ctx, `UPDATE kb SET hidden = true WHERE id = $1`, id)
	st, body, _ = e.get(t, "GET", "/qa/"+slug+".txt")
	if st != 200 || !strings.Contains(body, "entry: "+rel+" ") {
		t.Fatalf("re-point: %d %s", st, body)
	}
	testPool.Exec(ctx, `UPDATE kb SET hidden = true WHERE id = $1`, rel)
	st, body, _ = e.get(t, "GET", "/qa/"+slug+".txt")
	if st != 410 || !strings.HasPrefix(body, "err gone ") {
		t.Fatalf("gone: %d %s", st, body)
	}
	var gone bool
	testPool.QueryRow(ctx, `SELECT gone FROM answer_pages WHERE slug = $1`, slug).Scan(&gone)
	if !gone {
		t.Fatal("page not marked gone")
	}
	if st, _, _ = e.get(t, "GET", "/qa/no-such-page-1234.txt"); st != 404 {
		t.Fatalf("unknown slug: %d", st)
	}
}

func TestBadgesSVGSafeFilePattern(t *testing.T) {
	e := newEnv(t)
	root := e.mkRoot(t, "badger", 2)
	id := e.mkEntry(t, root, entryOpts{title: uniq("badge entry"), fix: "f", okW: 2})
	st, body, hd := e.get(t, "GET", "/b/k/"+id+".svg")
	if st != 200 || hd.Get("Content-Type") != "image/svg+xml" || hd.Get("Content-Security-Policy") != badgeCSP || hd.Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("svg: %d %s %s %s", st, hd.Get("Content-Type"), hd.Get("Content-Security-Policy"), hd.Get("Cache-Control"))
	}
	wantIn(t, body, "<svg xmlns=", "agents.example", "fix · ok 2 · ")
	wantNotIn(t, body, "<script", "href", "foreignObject")
	et := hd.Get("ETag")
	if st, _, _ = e.get(t, "GET", "/b/k/"+id+".svg", "If-None-Match", et); st != 304 {
		t.Fatalf("badge 304: %d", st)
	}
	st, body, hd = e.get(t, "GET", "/b/k/"+id+".json")
	var j map[string]any
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || j["schemaVersion"] != float64(1) || j["color"] != "green" || !strings.HasPrefix(j["message"].(string), "fix · ok 2 · ") {
		t.Fatalf("shields json: %d %s", st, body)
	}
	for _, bad := range []string{"/b/k/" + id + ".png", "/b/k/" + id, "/b/k/x%22%3E%3Cscript%3E.svg", "/b/k/" + root + ".svg", "/b/a/" + id + ".svg", "/b/t/abc.svg", "/b/t/0.svg", "/b/s/ab.svg", "/b/k/..%2Fx.svg"} {
		if st, _, _ = e.get(t, "GET", bad); st != 404 {
			t.Fatalf("%s: %d, want 404", bad, st)
		}
	}
	// Unknown ids and hidden entries answer gray badges (the acceptance curl is an unknown id).
	st, body, hd = e.get(t, "GET", "/b/k/k7x2a9q.svg")
	if st != 200 || hd.Get("Content-Type") != "image/svg+xml" || !strings.Contains(body, ">unknown<") {
		t.Fatalf("unknown badge: %d %s", st, body)
	}
	testPool.Exec(context.Background(), `UPDATE kb SET hidden = true WHERE id = $1`, id)
	_, body, _ = e.get(t, "GET", "/b/k/"+id+".svg")
	wantIn(t, body, ">gone<", cGray.hex)
	_, body, _ = e.get(t, "GET", "/b/a/"+root+".svg")
	wantIn(t, body, "rep 5 · 0 fixes")
	n := e.mkTask(t, root, "badge task", "", "open")
	_, body, _ = e.get(t, "GET", fmt.Sprintf("/b/t/%d.svg", n))
	wantIn(t, body, ">open<")
	_, body, _ = e.get(t, "GET", fmt.Sprintf("/b/t/%d.json", n))
	wantIn(t, body, `"message":"open"`)
	st, body, hd = e.get(t, "GET", "/b/live.svg")
	if st != 200 || hd.Get("Content-Type") != "image/svg+xml" || !strings.Contains(body, " agents · ") {
		t.Fatalf("live: %d %s", st, body)
	}
	// A title with XML-hostile characters never reaches the SVG unescaped.
	if svg := string(renderBadge("agents.example", `fix <x> "y" & z`, cGreen)); strings.Contains(svg, `<x>`) || !strings.Contains(svg, "unknown") {
		t.Fatalf("message validation: %s", svg)
	}
}

func TestOEmbedOwnHostOnly(t *testing.T) {
	e := newEnv(t)
	root := e.mkRoot(t, "embedder", 2)
	title := uniq("oEmbed entry <b>")
	id := e.mkEntry(t, root, entryOpts{title: title, fix: "f", okW: 1})
	st, body, hd := e.get(t, "GET", "/oembed?url="+url.QueryEscape("https://agents.example/k/"+id)+"&format=json")
	var j map[string]any
	if st != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "application/json") || json.Unmarshal([]byte(body), &j) != nil {
		t.Fatalf("oembed: %d %s", st, body)
	}
	if j["type"] != "rich" || j["version"] != "1.0" || j["title"] != title || j["provider_name"] != "agents.example" {
		t.Fatalf("oembed fields: %v", j)
	}
	if h := j["html"].(string); !strings.Contains(h, `href="https://agents.example/k/`+id+`"`) || !strings.Contains(h, "&lt;b&gt;") || !strings.Contains(h, "fix ok 1") {
		t.Fatalf("oembed html: %s", h)
	}
	if st, _, _ = e.get(t, "GET", "/oembed?url="+url.QueryEscape("https://agents.example/kb/"+id+".md")); st != 200 {
		t.Fatalf("kb path: %d", st)
	}
	for p, want := range map[string]int{
		"/oembed?url=" + url.QueryEscape("https://evil.example/k/"+id): 404,
		"/oembed?url=" + url.QueryEscape("/k/"+id):                     400,
		"/oembed": 400,
		"/oembed?url=" + url.QueryEscape("https://agents.example/k/"+id) + "&format=xml": 501,
		"/oembed?url=" + url.QueryEscape("https://agents.example/t/1"):                   404,
		"/oembed?url=" + url.QueryEscape("https://agents.example/k/kzzzzzz"):             404,
	} {
		if st, body, _ = e.get(t, "GET", p); st != want {
			t.Fatalf("%s: %d want %d\n%s", p, st, want, body)
		}
	}
}

func TestLLMSFullBudgetAndFirstLine(t *testing.T) {
	e := newEnv(t)
	root := e.mkRoot(t, "corpus", 2)
	title := uniq("Corpus entry title")
	e.mkEntry(t, root, entryOpts{title: title, fix: "f", okW: 4})
	for i := 0; i < 6; i++ {
		e.d.RegisterLLMSFull(fmt.Sprintf("zz-huge-%d", i), func(context.Context) string { return strings.Repeat("filler line for the corpus budget test\n", 4000) })
	}
	st, body, hd := e.get(t, "GET", "/llms-full.txt")
	if st != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/plain") {
		t.Fatalf("llms-full: %d %s", st, hd.Get("Content-Type"))
	}
	if len(body) > 512<<10 {
		t.Fatalf("body %d bytes > 512 KiB", len(body))
	}
	if !regexp.MustCompile(`^# agents\.ekaii\.fr \(full\) ~[0-9]+ tokens; prefer /llms\.txt unless you need the corpus$`).MatchString(firstLine(body)) {
		t.Fatalf("first line %q", firstLine(body))
	}
	wantIn(t, body, "## grammar", "## reply formats", "## api", "## zz-huge-0", "truncated at 512 KiB")
	if hd.Get("ETag") == "" || hd.Get("Last-Modified") == "" {
		t.Fatal("validators missing")
	}
	if st, _, _ = e.get(t, "GET", "/llms-full.txt", "If-None-Match", hd.Get("ETag")); st != 304 {
		t.Fatalf("304: %d", st)
	}
	// Without the filler the corpus lists the top indexable entries.
	e2 := newEnv(t)
	e2.mkEntry(t, e2.mkRoot(t, "corpus2", 2), entryOpts{title: title, fix: "f", okW: 4})
	_, body, _ = e2.get(t, "GET", "/llms-full.txt")
	wantIn(t, body, "## top entries", doc.MDEscape(title))
}

func TestJoinPyRuns(t *testing.T) {
	e := newEnv(t)
	st, body, hd := e.get(t, "GET", "/join.py")
	if st != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/x-python") || !strings.Contains(body, "def solve(") || !strings.Contains(body, `"https://agents.example"`) {
		t.Fatalf("join.py: %d %s", st, hd.Get("Content-Type"))
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "join.py")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// The test server registers from 127.0.0.1: clear the registration counters of earlier runs.
	testPool.Exec(ctx, `DELETE FROM reg_ips WHERE ip = '127.0.0.1'`)
	testPool.Exec(ctx, `DELETE FROM reg_supers WHERE super = '127.0.0.0/24'`)
	cmd := exec.Command(py, "-I", path, "joinbot")
	cmd.Env = append(os.Environ(), "CX_URL="+e.srv.URL)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("join.py failed: %v\n%s", err, stderr.String())
	}
	tok := strings.TrimSpace(string(out))
	if !regexp.MustCompile(`^cx_[A-Za-z0-9_-]{43}$`).MatchString(tok) {
		t.Fatalf("stdout %q (stderr %s)", tok, stderr.String())
	}
	if !strings.Contains(stderr.String(), "id=a") {
		t.Fatalf("stderr %q", stderr.String())
	}
	var id string
	if err := testPool.QueryRow(ctx, `SELECT id FROM identities WHERE token_hash = $1`, core.HashToken(tok)).Scan(&id); err != nil {
		t.Fatalf("registered identity not found: %v", err)
	}
	e.roots = append(e.roots, id)
	st, body, _ = e.get(t, "GET", "/v1/me", "Authorization", "Bearer "+tok)
	if st != 200 || !strings.Contains(body, "name=joinbot") {
		t.Fatalf("token does not work: %d %s", st, body)
	}
}
