package kb

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/pow"
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
	} else if pool, done := testdb.Open("kb", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping kb DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d     *core.Deps
	srv   *httptest.Server
	ip    string
	cfg   core.Config
	roots []string
}

// ipSeq hands every registration its own /24 so super-group collapse never merges two test voters;
// the second octet is random per process because registration counters persist in the database.
var (
	ipSeq  atomic.Int64
	ipBase = func() int64 {
		var b [1]byte
		rand.Read(b[:])
		return 16 + int64(b[0])%200
	}()
)

func nextIP() string {
	n := ipSeq.Add(1)
	return fmt.Sprintf("10.%d.%d.7", (ipBase+n/200)%256, 1+n%200)
}

func newEnv(t *testing.T, mod ...func(*core.Config)) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example",
		RegPerHour: 1 << 20} // the global hourly registration counter is shared with other packages' tests
	for _, f := range mod {
		f(&cfg)
	}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	e := &tenv{d: d, srv: srv, ip: nextIP(), cfg: cfg}
	// Remove only rows authored by this env's identities (the database is this package's own).
	t.Cleanup(func() {
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM forge_outbox WHERE kind = 'kb' AND ref IN (SELECT id FROM kb WHERE author_root = ANY($1))`, e.roots)
		testPool.Exec(ctx, `DELETE FROM kb_votes WHERE root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM kb WHERE author_root = ANY($1)`, e.roots)
	})
	return e
}

func (e *tenv) do(t *testing.T, method, path, token string, body any, hdr ...string) (int, string, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rd = strings.NewReader(b)
		default:
			j, _ := json.Marshal(b)
			rd = bytes.NewReader(j)
		}
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", e.ip)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

// register creates a root from a fresh IP (its own /24).
func (e *tenv) register(t *testing.T, name string) (id, tok string) {
	t.Helper()
	return e.registerIP(t, name, nextIP())
}

// registerIP creates a root registered from ip (reg_ip decides the super-group of its votes).
func (e *tenv) registerIP(t *testing.T, name, ip string) (id, tok string) {
	t.Helper()
	st, body, _ := e.do(t, "POST", "/v1/challenge", "", nil, "CF-Connecting-IP", ip)
	if st != 200 {
		t.Fatalf("challenge: %d %s", st, body)
	}
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(body, -1) {
		m[x[1]] = x[2]
	}
	c, bits := m["c"], e.d.Cfg.PowBits
	if b, err := strconv.Atoi(m["bits"]); err == nil && b > 0 { // the reg curve raises bits under load (3.1)
		bits = b
	}
	st, body, _ = e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, bits), "name": name}, "CF-Connecting-IP", ip)
	if st != 201 {
		t.Fatalf("register: %d %s", st, body)
	}
	m = map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(body, -1) {
		m[x[1]] = x[2]
	}
	e.roots = append(e.roots, m["id"])
	return m["id"], m["token"]
}

// registerL registers a root and gives it standing level lvl.
func (e *tenv) registerL(t *testing.T, name string, lvl int) (id, tok string) {
	t.Helper()
	id, tok = e.register(t, name)
	e.setLevel(t, id, lvl)
	return id, tok
}

// setRep sets a root's reputation; the root is also made 4 days old (Established needs 72 h).
func (e *tenv) setRep(t *testing.T, root string, rep int) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET rep = $2, created = now() - interval '4 days' WHERE id = $1`, root, rep); err != nil {
		t.Fatal(err)
	}
}

// setLevel gives a root the minimum standing of level lvl (4.1): L1 rep 1 + 4 d; L2 rep 5 + 4 d +
// one verified non-compute contribution; L3 rep 20 + 31 d.
func (e *tenv) setLevel(t *testing.T, root string, lvl int) {
	t.Helper()
	rep, days, vnc := 0, 0, 0
	switch lvl {
	case 1:
		rep, days = 1, 4
	case 2:
		rep, days, vnc = 5, 4, 1
	case 3:
		rep, days, vnc = 20, 31, 1
	}
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET rep = $2, created = now() - $3 * interval '1 day', verified_noncompute = $4 WHERE id = $1`, root, rep, days, vnc); err != nil {
		t.Fatal(err)
	}
}

func (e *tenv) rep(t *testing.T, root string) int {
	t.Helper()
	r, err := core.Rep(context.Background(), testPool, root)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var uniqSeq atomic.Int64

// uniq appends a random suffix (random, not sequential: sequential suffixes share trigrams and
// make unrelated test rows similar).
func uniq(s string) string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("%s %x%02x", s, b, uniqSeq.Add(1)%256)
}

// first is the head line of a reply; lines are the body lines without the trailing next: tail.
func first(body string) string { return strings.SplitN(body, "\n", 2)[0] }

func lines(body string) []string {
	ls := strings.Split(body, "\n")
	if n := len(ls); n > 0 && strings.HasPrefix(ls[n-1], "next: ") {
		ls = ls[:n-1]
	}
	return ls
}

func noTail(body string) string { return strings.Join(lines(body), "\n") }

func (e *tenv) post(t *testing.T, tok string, in map[string]any) string {
	t.Helper()
	st, body, _ := e.do(t, "POST", "/v1/kb", tok, in)
	if st != 201 || !strings.HasPrefix(body, "ok k") {
		t.Fatalf("post: %d %s", st, body)
	}
	return strings.Fields(body)[1]
}

func TestCreateSearchGet(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register(t, "a")
	errStr := "pnpm: ERR_PNPM_UNSUPPORTED_ENGINE node 20.11.1"
	tag := uniq("eng")
	title := uniq("pnpm install fails with ERR_PNPM_UNSUPPORTED_ENGINE on old node")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": title,
		"symptom": "pnpm: ERR_PNPM_UNSUPPORTED_ENGINE  Unsupported environment (bad pnpm and/or Node.js version)\nnode 20.11.1 wanted >=22",
		"cause":   "engines.node in package.json requires node 22", "fix": "nvm use 22 && pnpm install", "versions": "pnpm 10, node 20.11.1",
		"tags": []string{"pnpm", "node", strings.ReplaceAll(tag, " ", "")}})
	// Noise entry that should rank lower.
	e.post(t, tok, map[string]any{"kind": "note", "title": uniq("docker compose v2 network name gotcha"), "symptom": "containers cannot resolve each other", "fix": "set project name"})

	st, body, _ := e.do(t, "GET", "/v1/kb?q="+urlq(errStr)+"&k=3", "", nil)
	if st != 200 {
		t.Fatalf("search: %d %s", st, body)
	}
	ls := lines(body)
	if !strings.HasPrefix(ls[0], id+" ") || !strings.HasSuffix(ls[0], " fix "+title) {
		t.Fatalf("exact error string did not rank first:\n%s", body)
	}
	if m, _ := regexp.MatchString(`^k[a-z2-7]{6} \d+\.\d\d fix `, ls[0]); !m {
		t.Fatalf("line format: %q", ls[0])
	}
	for _, l := range ls {
		if strings.Contains(l, "docker compose") {
			t.Fatalf("unrelated entry matched: %s", l)
		}
	}
	if !strings.HasPrefix(strings.Split(body, "\n")[len(strings.Split(body, "\n"))-1], "next: GET /v1/kb/"+id) {
		t.Fatalf("search tail:\n%s", body)
	}
	// Partial words still match via tsv.
	st, body, _ = e.do(t, "GET", "/v1/kb?q=unsupported+engine+pnpm&kind=fix", "", nil)
	if st != 200 || !strings.Contains(body, id) {
		t.Fatalf("word search: %d %s", st, body)
	}
	// JSON output: the v1 array shape, unchanged.
	st, body, _ = e.do(t, "GET", "/v1/kb?q="+urlq(errStr)+"&f=json", "", nil)
	var hits []Hit
	if err := json.Unmarshal([]byte(body), &hits); err != nil || len(hits) == 0 || hits[0].ID != id || hits[0].Score <= 0 {
		t.Fatalf("json search: %d %s", st, body)
	}
	// Get text: v1 header prefix, appended v2 fields, url: then next: last.
	st, body, hdr := e.do(t, "GET", "/v1/kb/"+id, "", nil)
	if st != 200 {
		t.Fatalf("get: %d %s", st, body)
	}
	ls = strings.Split(body, "\n")
	if m, _ := regexp.MatchString(`^`+id+` fix ok0 bad0 \d{4}-\d\d-\d\d by a[a-z2-7]{6} lvl=L0 age=0h rev1 flags:-$`, ls[0]); !m {
		t.Fatalf("header: %q", ls[0])
	}
	if ls[1] != "title: "+title || !strings.Contains(body, "\nfix: nvm use 22 && pnpm install\n") || !strings.Contains(body, "\ntags: pnpm,node,"+strings.ReplaceAll(tag, " ", "")+"\n") {
		t.Fatalf("get body:\n%s", body)
	}
	if ls[len(ls)-2] != "url: https://agents.example/k/"+id || !strings.HasPrefix(ls[len(ls)-1], "next: POST /v1/kb/"+id+"/ok | POST /v1/kb/"+id+"/bad | GET /k/"+id+".md") {
		t.Fatalf("url/next tail:\n%s", body)
	}
	if !strings.Contains(hdr.Get("Link"), `<https://agents.example/k/`+id+`>; rel="canonical"`) {
		t.Fatalf("canonical link header: %q", hdr.Values("Link"))
	}
	// Get JSON.
	st, body, _ = e.do(t, "GET", "/v1/kb/"+id, "", nil, "Accept", "application/json")
	var en Entry
	if err := json.Unmarshal([]byte(body), &en); err != nil || en.ID != id || en.Fix != "nvm use 22 && pnpm install" || len(en.Tags) != 3 || en.URL != "https://agents.example/k/"+id {
		t.Fatalf("json get: %d %s", st, body)
	}
	if !strings.Contains(body, `"next":["POST /v1/kb/`+id+`/ok"`) {
		t.Fatalf("json next: %s", body)
	}
	// Outbox row with the text rendering.
	var payload []byte
	if err := testPool.QueryRow(context.Background(), `SELECT payload FROM forge_outbox WHERE kind='kb' AND ref=$1 ORDER BY id DESC LIMIT 1`, id).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(payload), id+" fix ok0 bad0") {
		t.Fatalf("outbox payload: %q", payload)
	}
	// Empty q => latest.
	st, body, _ = e.do(t, "GET", "/v1/kb?k=2", "", nil)
	if st != 200 || len(lines(body)) != 2 {
		t.Fatalf("latest: %d %s", st, body)
	}
	// ?s=id => one id per line.
	if _, body, _ = e.do(t, "GET", "/v1/kb?k=2&s=id", "", nil); len(lines(body)) != 2 || !core.ValidID(lines(body)[0]) {
		t.Fatalf("s=id: %s", body)
	}
	// Unknown / malformed ids.
	if st, _, _ := e.do(t, "GET", "/v1/kb/kzzzzzz", "", nil); st != 404 {
		t.Fatalf("unknown id: %d", st)
	}
	if st, _, _ := e.do(t, "GET", "/v1/kb/not-an-id", "", nil); st != 404 {
		t.Fatalf("bad id: %d", st)
	}
}

func urlq(s string) string { return strings.NewReplacer(" ", "+", ":", "%3A").Replace(s) }

func TestDupAndForce(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register(t, "a")
	title := uniq("git push rejected: remote contains work you do not have")
	in := map[string]any{"kind": "fix", "title": title, "symptom": "! [rejected] main -> main (fetch first)", "fix": "git pull --rebase"}
	id := e.post(t, tok, in)
	st, body, _ := e.do(t, "POST", "/v1/kb", tok, in)
	if st != 409 || first(body) != "err dup "+id+" "+title || !strings.Contains(body, "\nnext: ") {
		t.Fatalf("dup: %d %s", st, body)
	}
	st, body, _ = e.do(t, "POST", "/v1/kb", tok, in, "Accept", "application/json")
	if st != 409 || !strings.Contains(body, `"err":"dup"`) {
		t.Fatalf("dup json: %d %s", st, body)
	}
	in["force"] = true
	if id2 := e.post(t, tok, in); id2 == id {
		t.Fatal("force returned same id")
	}
}

func TestCapsAndValidation(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register(t, "a")
	cases := []struct {
		name string
		in   map[string]any
		st   int
		code string
	}{
		{"kind", map[string]any{"kind": "bug", "title": "x"}, 400, "bad"},
		{"title empty", map[string]any{"kind": "fix", "title": " "}, 400, "bad"},
		{"title long", map[string]any{"kind": "fix", "title": strings.Repeat("a", 161)}, 400, "bad"},
		{"symptom long", map[string]any{"kind": "fix", "title": "t", "symptom": strings.Repeat("a", 1001)}, 400, "bad"},
		{"fix long", map[string]any{"kind": "fix", "title": "t", "fix": strings.Repeat("a", 3001)}, 400, "bad"},
		{"versions long", map[string]any{"kind": "fix", "title": "t", "versions": strings.Repeat("a", 201)}, 400, "bad"},
		{"why_safe long", map[string]any{"kind": "fix", "title": "t", "why_safe": strings.Repeat("a", 501)}, 400, "bad"},
		{"too many tags", map[string]any{"kind": "fix", "title": "t", "tags": []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}}, 400, "bad"},
		{"bad tag upper", map[string]any{"kind": "fix", "title": "t", "tags": []string{"Node"}}, 400, "bad"},
		{"bad tag space", map[string]any{"kind": "fix", "title": "t", "tags": []string{"a b"}}, 400, "bad"},
		{"bad tag long", map[string]any{"kind": "fix", "title": "t", "tags": []string{strings.Repeat("a", 33)}}, 400, "bad"},
		{"bad space", map[string]any{"kind": "fix", "title": "t", "space": "Bad Space"}, 400, "bad"},
		{"bad att", map[string]any{"kind": "fix", "title": "t", "att": "nope"}, 400, "bad"},
		{"bad applies", map[string]any{"kind": "fix", "title": "t", "applies": "node ???"}, 400, "bad"},
		{"unknown field", map[string]any{"kind": "fix", "title": "t", "zzz": 1}, 400, "bad"},
		{"body too large", map[string]any{"kind": "fix", "title": "t", "fix": strings.Repeat("a", 17<<10)}, 413, "size"},
	}
	for _, c := range cases {
		st, body, _ := e.do(t, "POST", "/v1/kb", tok, c.in)
		if st != c.st || !strings.HasPrefix(body, "err "+c.code) {
			t.Fatalf("%s: %d %s", c.name, st, body)
		}
	}
	if st, body, _ := e.do(t, "POST", "/v1/kb", tok, "{not json"); st != 400 || !strings.HasPrefix(body, "err bad json") {
		t.Fatalf("malformed: %d %s", st, body)
	}
	// Valid tags, antipattern kind and applies accepted.
	e.post(t, tok, map[string]any{"kind": "note", "title": uniq("tags ok"), "tags": []string{"c++", "node.js", "go-1.27"}})
	e.post(t, tok, map[string]any{"kind": "antipattern", "title": uniq("do not pin latest"), "fix": "pin a version", "applies": "npm:react >=18 <19; node 22.x"})
}

func TestAnonymous(t *testing.T) {
	e := newEnv(t)
	if st, body, _ := e.do(t, "GET", "/v1/kb?q=anything", "", nil); st != 200 {
		t.Fatalf("anon search: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/v1/kb", "", map[string]any{"kind": "fix", "title": "x"}); st != 401 || first(body) != "err auth token required" || !strings.Contains(body, "next: POST /v1/challenge | POST /w/kb +X-PoW") {
		t.Fatalf("anon post: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "POST", "/v1/kb/kaaaaaa/ok", "", nil); st != 401 {
		t.Fatal("anon vote")
	}
	if st, _, _ := e.do(t, "GET", "/v1/kb", "cx_"+strings.Repeat("A", 43), nil); st != 401 {
		t.Fatal("bad token on read should be refused")
	}
	// Ops: nil ident on write.
	ops := Ops(e.d)
	if _, err := ops["p"](context.Background(), nil, json.RawMessage(`{"kind":"fix","title":"x"}`)); err != core.ErrAuth {
		t.Fatalf("op p anon: %v", err)
	}
	if _, err := ops["s"](context.Background(), nil, json.RawMessage(`{"q":"x"}`)); err != nil {
		t.Fatalf("op s anon: %v", err)
	}
}

func TestVotes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	author, atok := e.register(t, "author")
	_, v1tok := e.registerL(t, "v1", 2)  // L2, rep 5 -> weight 1.5
	v2, v2tok := e.registerL(t, "v2", 2) // L2, rep 10 -> weight 2
	e.setRep(t, v2, 10)
	testPool.Exec(ctx, `UPDATE identities SET verified_noncompute = 1 WHERE id = $1`, v2)
	id := e.post(t, atok, map[string]any{"kind": "fix", "title": uniq("vote target"), "symptom": uniq("sym"), "fix": "do it"})

	// Self vote refused.
	if st, body, _ := e.do(t, "POST", "/v1/kb/"+id+"/ok", atok, nil); st != 403 || first(body) != "err auth no self vote" {
		t.Fatalf("self vote: %d %s", st, body)
	}
	// Subkey of the author shares the root: still a self vote.
	_, body, _ := e.do(t, "POST", "/v1/subkey", atok, map[string]any{"credits": 1})
	subtok := kvRe.FindStringSubmatch(regexp.MustCompile(`token=\S+`).FindString(body))[2]
	if st, _, _ := e.do(t, "POST", "/v1/kb/"+id+"/ok", subtok, nil); st != 403 {
		t.Fatalf("subkey self vote: %d", st)
	}
	st, body, _ := e.do(t, "POST", "/v1/kb/"+id+"/ok", v1tok, map[string]any{"v": "works on node 22"})
	if st != 200 || first(body) != "ok ok1.5" {
		t.Fatalf("ok: %d %s", st, body)
	}
	if e.rep(t, author) != 1 {
		t.Fatalf("author rep after confirm: %d", e.rep(t, author))
	}
	// Once per root.
	if st, body, _ := e.do(t, "POST", "/v1/kb/"+id+"/ok", v1tok, nil); st != 409 || first(body) != "err dup already voted" {
		t.Fatalf("double vote: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/v1/kb/"+id+"/bad", v1tok, map[string]any{"why": "x"}); st != 409 {
		t.Fatalf("ok then bad: %d %s", st, body)
	}
	// Weighted vote: rep 10 -> 2; sums collapse per super-group (distinct here) -> 3.5.
	st, body, _ = e.do(t, "POST", "/v1/kb/"+id+"/ok", v2tok, nil, "Accept", "application/json")
	if st != 200 || !strings.Contains(body, `"ok_w":3.5`) {
		t.Fatalf("weighted: %d %s", st, body)
	}
	st, body, _ = e.do(t, "GET", "/v1/kb/"+id, "", nil)
	if !strings.Contains(body, " fix ok3.5 bad0 ") || !strings.Contains(body, "\nworks: 2 confirmations (works on node 22)\n") {
		t.Fatalf("header after votes: %s", body)
	}
	var confirmed bool
	testPool.QueryRow(ctx, `SELECT confirmed_at IS NOT NULL AND expires_at > now() + interval '179 days' FROM kb WHERE id=$1`, id).Scan(&confirmed)
	if !confirmed {
		t.Fatal("confirmed_at/expires_at not updated")
	}
	// Daily cap on rep per author (rep:kbin 2/day across voters): a third L2 confirm yields no rep.
	if e.rep(t, author) != 2 {
		t.Fatalf("rep after two L2 confirms: %d", e.rep(t, author))
	}
	id2 := e.post(t, atok, map[string]any{"kind": "note", "title": uniq("second"), "symptom": uniq("s2")})
	e.do(t, "POST", "/v1/kb/"+id2+"/ok", v1tok, nil)
	if e.rep(t, author) != 2 {
		t.Fatalf("rep cap: %d", e.rep(t, author))
	}
	// Vote note too long.
	if st, body, _ := e.do(t, "POST", "/v1/kb/"+id2+"/ok", v2tok, map[string]any{"v": strings.Repeat("x", 121)}); st != 400 {
		t.Fatalf("long v: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "POST", "/v1/kb/kzzzzzz/ok", v2tok, nil); st != 404 {
		t.Fatal("vote on missing entry")
	}
}

func TestHideRule(t *testing.T) {
	e := newEnv(t)
	author, atok := e.register(t, "author")
	_, b1 := e.registerL(t, "b1", 1) // L1: weight 1.1 (L0 weights never hide, 24.4)
	_, b2 := e.registerL(t, "b2", 1)
	id := e.post(t, atok, map[string]any{"kind": "status", "title": uniq("flaky thing"), "symptom": uniq("sym")})
	st, body, _ := e.do(t, "POST", "/v1/kb/"+id+"/bad", b1, map[string]any{"why": "wrong"})
	if st != 200 || first(body) != "ok" {
		t.Fatalf("bad1: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/v1/kb/"+id, "", nil); st != 200 {
		t.Fatal("hidden too early (bad_w 1.1 < ok_w 0 + 2)")
	}
	if st, body, _ := e.do(t, "POST", "/v1/kb/"+id+"/bad", b2, map[string]any{"why": strings.Repeat("x", 201)}); st != 400 {
		t.Fatalf("long why: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/v1/kb/"+id+"/bad", b2, map[string]any{"why": "also wrong"}); st != 200 || first(body) != "ok hidden" {
		t.Fatalf("bad2: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/v1/kb/"+id, "", nil); st != 404 {
		t.Fatal("should be hidden after bad_w >= ok_w + 2")
	}
	// Hidden rows stay readable through the appeal window with ?inc=h.
	if st, body, _ := e.do(t, "GET", "/v1/kb/"+id+"?inc=h", "", nil); st != 200 || !strings.Contains(first(body), " [hidden]") || !strings.Contains(body, "\nfails: 2 reports (wrong; also wrong)\n") {
		t.Fatalf("inc=h: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/kb/"+id, "", nil); st != 404 {
		t.Fatal("html page of hidden entry")
	}
	if e.rep(t, author) != -1 {
		t.Fatalf("author rep after hide: %d", e.rep(t, author))
	}
	// Hidden entries never appear in search, and voting on them is notfound below L2.
	if _, body, _ := e.do(t, "GET", "/v1/kb?q=flaky+thing", "", nil); strings.Contains(body, id) {
		t.Fatal("hidden in search")
	}
	if st, _, _ := e.do(t, "POST", "/v1/kb/"+id+"/ok", b1, nil); st != 404 {
		t.Fatal("vote on hidden")
	}
	// Mirror told to drop it.
	var payload []byte
	testPool.QueryRow(context.Background(), `SELECT payload FROM forge_outbox WHERE kind='kb' AND ref=$1 ORDER BY id DESC LIMIT 1`, id).Scan(&payload)
	if len(payload) != 0 {
		t.Fatalf("outbox after hide: %q", payload)
	}
	// Hide() service (votes semantics): idempotent, rep -1 once.
	id2 := e.post(t, atok, map[string]any{"kind": "note", "title": uniq("reported"), "symptom": uniq("s")})
	for i := 0; i < 2; i++ {
		if err := Hide(context.Background(), testPool, id2); err != nil {
			t.Fatal(err)
		}
	}
	if st, _, _ := e.do(t, "GET", "/v1/kb/"+id2, "", nil); st != 404 {
		t.Fatal("Hide() not applied")
	}
	if e.rep(t, author) != -2 {
		t.Fatalf("rep after Hide(): %d", e.rep(t, author))
	}
}

func TestExpiryJanitor(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, tok := e.register(t, "a")
	st := e.post(t, tok, map[string]any{"kind": "status", "title": uniq("status now"), "symptom": uniq("s")})
	fix := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("fix now"), "symptom": uniq("s"), "fix": "f"})
	var statusTTLOK, fixTTLOK bool
	testPool.QueryRow(ctx, `SELECT expires_at BETWEEN now() + interval '71 hours' AND now() + interval '73 hours' FROM kb WHERE id=$1`, st).Scan(&statusTTLOK)
	testPool.QueryRow(ctx, `SELECT expires_at BETWEEN now() + interval '179 days' AND now() + interval '181 days' FROM kb WHERE id=$1`, fix).Scan(&fixTTLOK)
	if !statusTTLOK || !fixTTLOK {
		t.Fatalf("ttl: status=%v fix=%v", statusTTLOK, fixTTLOK)
	}
	// Simulate time passing.
	testPool.Exec(ctx, `UPDATE kb SET expires_at = now() - interval '1 second' WHERE id = ANY($1)`, []string{st, fix})
	if s, _, _ := e.do(t, "GET", "/v1/kb/"+st, "", nil); s != 404 {
		t.Fatal("expired visible before janitor")
	}
	e.d.Janitor.RunOnce(ctx)
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM kb WHERE id = ANY($1)`, []string{st, fix}).Scan(&n)
	if n != 0 {
		t.Fatalf("janitor left %d expired rows", n)
	}
	var ob int
	testPool.QueryRow(ctx, `SELECT count(*) FROM forge_outbox WHERE kind='kb' AND ref = ANY($1) AND length(payload) = 0`, []string{st, fix}).Scan(&ob)
	if ob != 2 {
		t.Fatalf("outbox drop rows: %d", ob)
	}
}

func TestPurgeHook(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root, tok := e.registerL(t, "p", 2)
	_, vtok := e.register(t, "v")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("to purge"), "symptom": uniq("s"), "fix": "x"})
	other := e.post(t, vtok, map[string]any{"kind": "fix", "title": uniq("voted by purged"), "symptom": uniq("s"), "fix": "x"})
	if st, body, _ := e.do(t, "POST", "/v1/kb/"+other+"/ok", tok, nil); st != 200 || first(body) != "ok ok1.5" {
		t.Fatalf("vote: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/admin/purge", "adm-token", map[string]any{"id": root}); st != 200 {
		t.Fatalf("purge: %d %s", st, body)
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM kb WHERE id=$1`, id).Scan(&n)
	if n != 0 {
		t.Fatal("purged author's entry remains")
	}
	testPool.QueryRow(ctx, `SELECT count(*) FROM kb_votes WHERE root=$1`, root).Scan(&n)
	if n != 0 {
		t.Fatal("purged root's votes remain")
	}
	// Tombstone purge and the collapsed sum of the entry it had voted on recomputed.
	if tb, ok := Gone(ctx, testPool, id); !ok || tb.Reason != "purge" {
		t.Fatalf("tombstone: %+v %v", tb, ok)
	}
	var okw float32
	testPool.QueryRow(ctx, `SELECT ok_w FROM kb WHERE id=$1`, other).Scan(&okw)
	if okw != 0 {
		t.Fatalf("ok_w after purging the voter: %v", okw)
	}
}

func TestQuota(t *testing.T) {
	e := newEnv(t)
	root, tok := e.register(t, "q")
	// Pre-fill today's counter to the limit minus one.
	if _, err := testPool.Exec(context.Background(), `INSERT INTO counters (scope, kind, day, n) VALUES ($1, 'kb', current_date, $2)`, root, kbQuota-1); err != nil {
		t.Fatal(err)
	}
	e.post(t, tok, map[string]any{"kind": "note", "title": uniq("last allowed"), "symptom": uniq("s")})
	st, body, _ := e.do(t, "POST", "/v1/kb", tok, map[string]any{"kind": "note", "title": uniq("over"), "symptom": uniq("s")})
	if st != 429 || !strings.HasPrefix(body, "err quota") {
		t.Fatalf("quota: %d %s", st, body)
	}
	// Established (L2) roots get the 150 column of trust.Caps.
	e.setLevel(t, root, 2)
	e.post(t, tok, map[string]any{"kind": "note", "title": uniq("established"), "symptom": uniq("s")})
}

func TestFreezeAndBan(t *testing.T) {
	e := newEnv(t)
	root, tok := e.register(t, "f")
	e.d.SetFreeze(context.Background(), "write", true)
	t.Cleanup(func() { e.d.SetFreeze(context.Background(), "write", false) })
	if st, body, _ := e.do(t, "POST", "/v1/kb", tok, map[string]any{"kind": "note", "title": "x"}); st != 503 || first(body) != "err frozen write" {
		t.Fatalf("frozen: %d %s", st, body)
	}
	if _, err := Ops(e.d)["p"](context.Background(), &core.Ident{ID: root, Root: root}, json.RawMessage(`{"kind":"note","title":"x"}`)); err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("op frozen: %v", err)
	}
	e.d.SetFreeze(context.Background(), "write", false)
	e.setRep(t, root, -10)
	if st, body, _ := e.do(t, "POST", "/v1/kb", tok, map[string]any{"kind": "note", "title": "x"}); st != 403 || first(body) != "err auth banned" {
		t.Fatalf("banned: %d %s", st, body)
	}
}

func TestOpsMatchHTTP(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, tok := e.register(t, "o")
	_, vtok := e.registerL(t, "ov", 2)
	id, _ := e.d.LookupToken(ctx, tok)
	vid, _ := e.d.LookupToken(ctx, vtok)
	ops := Ops(e.d)
	title := uniq("ops entry: ECONNREFUSED 127.0.0.1:5432")
	out, err := ops["p"](ctx, id, json.RawMessage(fmt.Sprintf(`{"kind":"fix","title":%q,"symptom":"dial tcp 127.0.0.1:5432: connect: connection refused","fix":"start postgres","tags":["postgres"]}`, title)))
	if err != nil || !strings.HasPrefix(out, "ok k") {
		t.Fatalf("op p: %q %v", out, err)
	}
	kid := strings.Fields(out)[1]
	_, err = ops["p"](ctx, id, json.RawMessage(fmt.Sprintf(`{"kind":"fix","title":%q,"symptom":"dial tcp 127.0.0.1:5432: connect: connection refused"}`, title)))
	var ae *core.APIError
	if !asAPI(err, &ae) || ae.Status != 409 || ae.Code != "dup" {
		t.Fatalf("op dup: %v", err)
	}
	// Op text == HTTP text minus the next: tail (MCP results carry no tail).
	out, err = ops["s"](ctx, nil, json.RawMessage(`{"q":"connect: connection refused 127.0.0.1:5432","k":3}`))
	_, httpOut, _ := e.do(t, "GET", "/v1/kb?q=connect%3A+connection+refused+127.0.0.1%3A5432&k=3", "", nil)
	if err != nil || strings.TrimSpace(out) != noTail(httpOut) || !strings.HasPrefix(out, kid+" ") {
		t.Fatalf("op s:\n%q\nhttp:\n%q\n%v", out, httpOut, err)
	}
	out, err = ops["g"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"id":%q}`, kid)))
	_, httpOut, _ = e.do(t, "GET", "/v1/kb/"+kid, "", nil)
	if err != nil || strings.TrimSpace(out) != noTail(httpOut) || !strings.HasSuffix(strings.TrimSpace(out), "\nurl: https://agents.example/k/"+kid) {
		t.Fatalf("op g:\n%q\nhttp:\n%q", out, httpOut)
	}
	if out, err = ops["ok"](ctx, vid, json.RawMessage(fmt.Sprintf(`{"id":%q,"v":"yes"}`, kid))); err != nil || out != "ok ok1.5" {
		t.Fatalf("op ok: %q %v", out, err)
	}
	if _, err = ops["ok"](ctx, vid, json.RawMessage(fmt.Sprintf(`{"id":%q}`, kid))); !asAPI(err, &ae) || ae.Code != "dup" {
		t.Fatalf("op ok twice: %v", err)
	}
	if _, err = ops["bad"](ctx, id, json.RawMessage(fmt.Sprintf(`{"id":%q,"why":"x"}`, kid))); !asAPI(err, &ae) || ae.Status != 403 {
		t.Fatalf("op bad self: %v", err)
	}
	if _, err = ops["g"](ctx, nil, json.RawMessage(`{"id":"kzzzzzz"}`)); err != core.ErrNotFound {
		t.Fatalf("op g missing: %v", err)
	}
	if _, err = ops["g"](ctx, nil, json.RawMessage(`[1]`)); !asAPI(err, &ae) || ae.Code != "bad" {
		t.Fatalf("op g bad args: %v", err)
	}
}

func asAPI(err error, ae **core.APIError) bool {
	a, ok := err.(*core.APIError)
	if ok {
		*ae = a
	}
	return ok
}

func TestHTML(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register(t, "h")
	title := `<script>alert(1)</script> ` + uniq("xss title")
	symptom := strings.Repeat("s", 200) + " <b>bold</b>"
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": title, "symptom": symptom, "fix": "echo '<x>' && rm -rf \"$y\"", "tags": []string{"xss"}})

	st, body, hdr := e.do(t, "GET", "/kb/"+id, "", nil)
	if st != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "text/html") {
		t.Fatalf("page: %d %s", st, hdr.Get("Content-Type"))
	}
	if strings.Contains(body, "<script") {
		t.Fatal("unescaped script in page")
	}
	if !strings.Contains(body, "<title>&lt;script&gt;alert(1)&lt;/script&gt; ") {
		t.Fatalf("title not exact/escaped:\n%s", body)
	}
	if !strings.Contains(body, `<meta name="description" content="`+strings.Repeat("s", 155)+`">`) {
		t.Fatal("meta description should be the first 155 chars of symptom")
	}
	if !strings.Contains(body, "<pre>echo &#39;&lt;x&gt;&#39; &amp;&amp; rm -rf &#34;$y&#34;</pre>") {
		t.Fatalf("pre block escaping:\n%s", body)
	}
	if !strings.Contains(body, "Machine API: <a href=\"/llms.txt\">/llms.txt</a> · MCP: https://agents.example/mcp") {
		t.Fatal("footer")
	}
	csp := hdr.Get("Content-Security-Policy")
	if !strings.HasPrefix(csp, "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'") || strings.Contains(csp, "script-src") {
		t.Fatalf("csp: %s", csp)
	}
	if !strings.Contains(body, "prefers-color-scheme:dark") {
		t.Fatal("dark mode css")
	}
	// Index: latest + search form; search results page.
	st, body, _ = e.do(t, "GET", "/kb/", "", nil)
	if st != 200 || !strings.Contains(body, `<form method="get" action="/kb/">`) || !strings.Contains(body, `href="/kb/`+id+`"`) || strings.Contains(body, "<script") {
		t.Fatalf("index: %d\n%s", st, body)
	}
	st, body, _ = e.do(t, "GET", "/kb/?q=xss+title+alert", "", nil)
	if st != 200 || !strings.Contains(body, `href="/kb/`+id+`"`) || !strings.Contains(body, "result(s) for") {
		t.Fatalf("index search: %d\n%s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/kb/kzzzzzz", "", nil); st != 404 {
		t.Fatal("html 404")
	}
	// Umami configured: script tag + CSP origins.
	e2 := newEnv(t, func(c *core.Config) { c.UmamiSrc, c.UmamiID = "https://stats.example/script.js", "abc-123" })
	_, body, hdr = e2.do(t, "GET", "/kb/", "", nil)
	if !strings.Contains(body, `<script defer src="https://stats.example/script.js" data-website-id="abc-123"></script>`) {
		t.Fatalf("umami tag:\n%s", body)
	}
	if csp := hdr.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src https://stats.example; connect-src https://stats.example") {
		t.Fatalf("umami csp: %s", csp)
	}
}

func TestSitemapEntries(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register(t, "s")
	id := e.post(t, tok, map[string]any{"kind": "note", "title": uniq("sitemap"), "symptom": uniq("s")})
	hid := e.post(t, tok, map[string]any{"kind": "note", "title": uniq("sitemap hidden"), "symptom": uniq("s")})
	Hide(context.Background(), testPool, hid)
	ents, err := SitemapEntries(context.Background(), testPool)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, s := range ents {
		seen[s.ID] = true
		if s.Mod.IsZero() {
			t.Fatal("zero mod")
		}
	}
	if !seen[id] || seen[hid] {
		t.Fatalf("sitemap: visible=%v hidden=%v", seen[id], seen[hid])
	}
}
