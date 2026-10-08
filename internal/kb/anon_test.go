package kb

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/pow"
)

// Anonymous-lane acceptance tests (SPEC-v2 6.3, 4.3, 4.4, 27.2, 27.8; PLAN P11b-kb-anon).

// newAnonEnv is newEnv with RegisterAnon mounted and a cheap for=w floor (POW_BITS_W = 4).
func newAnonEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, PowBitsW: 4, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	RegisterAnon(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	return &tenv{d: d, srv: srv, ip: nextIP(), cfg: cfg}
}

// stubPoW makes `X-PoW: stub` pass with the caller's own network keys (the real checker is auth's
// and is exercised end to end by TestQuarantineAnonFlow); restored when the test ends.
func stubPoW(t *testing.T) {
	t.Helper()
	old := core.XPoWFn
	core.XPoWFn = func(ctx context.Context, q core.Q, r *http.Request) (string, string, error) {
		if r.Header.Get("X-PoW") != "stub" {
			return "", "", core.ErrPow
		}
		_, grp, super := core.ClientFrom(ctx)
		return grp, super, nil
	}
	t.Cleanup(func() { core.XPoWFn = old })
}

// anonSuper is a random, test-private /24 prefix "10.a.b" (day counters persist in the database).
func anonSuper() string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d", 100+int(b[0])%100, b[1])
}

// anonIn is a minimal anonymous post; force skips the trigram dup check between look-alike titles.
func anonIn(title string) map[string]any {
	return map[string]any{"kind": "fix", "title": title, "symptom": "seen: " + title, "fix": "restart it with the right flag", "force": true}
}

// wpost posts in anonymously from ip (stub PoW); a created row is removed when the test ends.
func (e *tenv) wpost(t *testing.T, ip string, in map[string]any, hdr ...string) (int, string, http.Header) {
	t.Helper()
	hs := append([]string{"CF-Connecting-IP", ip, "X-PoW", "stub"}, hdr...)
	st, body, h := e.do(t, "POST", "/w/kb", "", in, hs...)
	if st == 202 {
		e.dropLater(t, body)
	}
	return st, body, h
}

// dropLater schedules the removal of the row a 202 body (text or JSON) names.
func (e *tenv) dropLater(t *testing.T, body string) {
	t.Helper()
	id := ""
	if strings.HasPrefix(body, "ok ") {
		id = strings.Fields(body)[1]
	} else {
		var j struct {
			ID string `json:"id"`
		}
		json.Unmarshal([]byte(body), &j)
		id = j.ID
	}
	if id != "" {
		t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM kb WHERE id = $1`, id) })
	}
}

// solveW fetches a for=w challenge as ip and solves it at the bits it demands (the curve of 27.8).
func (e *tenv) solveW(t *testing.T, ip string) (c, nonce string, bits int) {
	t.Helper()
	st, body, _ := e.do(t, "POST", "/v1/challenge?for=w", "", nil, "CF-Connecting-IP", ip)
	if st != 200 {
		t.Fatalf("challenge: %d %s", st, body)
	}
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(body, -1) {
		m[x[1]] = x[2]
	}
	bits, _ = strconv.Atoi(m["bits"])
	if m["for"] != "w" || bits < 4 || m["c"] == "" {
		t.Fatalf("challenge: %s", body)
	}
	return m["c"], pow.Solve(m["c"], bits), bits
}

// fixtureRows inserts n quarantined rows directly (ids kt<tag>NNNN, newest id = newest row): anonymous
// rows of super when super != "", else token-authored rows (which eviction never touches). The rows
// are created `age` ago and removed, with their tombstones, when the test ends.
func fixtureRows(t *testing.T, tag string, n int, super string, age time.Duration) {
	t.Helper()
	ctx := context.Background()
	author, root := "afixture", "afixture"
	if super != "" {
		author, root = "anon", ""
	}
	_, err := testPool.Exec(ctx, `INSERT INTO kb (id, kind, title, author, author_root, expires_at, quarantine, anon_grp, anon_super, created)
		SELECT 'kt' || $1 || lpad(i::text, 4, '0'), 'note', 'fixture ' || $1 || ' ' || i, $2, $3, now() + interval '30 days', true, $4, $4, now() - $5::interval
		FROM generate_series(1, $6::int) AS i`, tag, author, root, super, fmt.Sprintf("%d seconds", int(age/time.Second)), n)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		testPool.Exec(ctx, `DELETE FROM kb WHERE id LIKE 'kt' || $1 || '%'`, tag)
		testPool.Exec(ctx, `DELETE FROM kb_tombstones WHERE id LIKE 'kt' || $1 || '%'`, tag)
	})
}

var okQuarantineRe = regexp.MustCompile(`^ok k[a-z2-7]{6} quarantine$`)

func TestQuarantineAnonFlow(t *testing.T) {
	e := newAnonEnv(t)
	ctx := context.Background()
	ip := anonSuper() + ".9"
	title := uniq("anon flow: ECONNRESET talking to redis")
	// Without X-PoW: 400 err pow, and the reply hands out a for=w challenge (27.2).
	st, body, hdr := e.do(t, "POST", "/w/kb", "", anonIn(title), "CF-Connecting-IP", ip)
	if st != 400 || !strings.HasPrefix(first(body), "err pow") {
		t.Fatalf("no pow: %d %s", st, body)
	}
	if !strings.Contains(strings.Join(hdr.Values("WWW-Authenticate"), " "), `PoW realm="w"`) {
		t.Fatalf("challenge header: %v", hdr.Values("WWW-Authenticate"))
	}
	if !strings.Contains(body, "next: POST /v1/challenge for=w | GET /w/kb form") {
		t.Fatalf("pow error tail: %s", body)
	}
	// A solved for=w challenge -> 202 ok k… quarantine + next.
	c, nonce, _ := e.solveW(t, ip)
	st, body, hdr = e.do(t, "POST", "/w/kb", "", anonIn(title), "CF-Connecting-IP", ip, "X-PoW", c+":"+nonce)
	if st != 202 || !okQuarantineRe.MatchString(first(body)) {
		t.Fatalf("anon post: %d %s", st, body)
	}
	e.dropLater(t, body)
	id := strings.Fields(body)[1]
	ls := strings.Split(body, "\n")
	if tail := ls[len(ls)-1]; !strings.HasPrefix(tail, "next: GET /k/"+id+"?quarantine=1 | GET /quarantine | POST /v1/kb/"+id+"/ok") {
		t.Fatalf("tail: %q", tail)
	}
	if !strings.Contains(strings.Join(hdr.Values("WWW-Authenticate"), " "), `PoW realm="w"`) {
		t.Fatalf("the 202 should carry a second challenge: %v", hdr.Values("WWW-Authenticate"))
	}
	// The row: quarantined, author anon, network keys recorded (6.3).
	var q bool
	var author, root, grp, super string
	if err := testPool.QueryRow(ctx, `SELECT quarantine, author, author_root, anon_grp, anon_super FROM kb WHERE id = $1`, id).Scan(&q, &author, &root, &grp, &super); err != nil {
		t.Fatal(err)
	}
	if !q || author != "anon" || root != "" || grp != ip || super != core.IPSuper(ip) {
		t.Fatalf("row: quarantine=%v author=%q root=%q grp=%q super=%q", q, author, root, grp, super)
	}
	// The challenge is single use.
	st, body, _ = e.do(t, "POST", "/w/kb", "", anonIn(uniq("anon flow replay: ECONNRESET")), "CF-Connecting-IP", ip, "X-PoW", c+":"+nonce)
	if st != 400 || !strings.Contains(first(body), "already used") {
		t.Fatalf("replay: %d %s", st, body)
	}
	// Hidden from the default read and search, visible with ?quarantine=1 and in /quarantine (4.4).
	if st, _, _ := e.do(t, "GET", "/v1/kb/"+id, "", nil); st != 404 {
		t.Fatalf("quarantined read: %d", st)
	}
	if st, body, _ := e.do(t, "GET", "/v1/kb/"+id+"?quarantine=1", "", nil); st != 200 || !strings.Contains(first(body), "[quarantine]") || !strings.Contains(first(body), " by anon ") {
		t.Fatalf("?quarantine=1: %d %s", st, body)
	}
	if _, body, _ := e.do(t, "GET", "/v1/kb?q="+url.QueryEscape(title), "", nil); strings.Contains(body, id) {
		t.Fatalf("quarantined row in search: %s", body)
	}
	if _, body, _ := e.do(t, "GET", "/quarantine", "", nil); !strings.Contains(body, "\n"+id+" fix? 0h anon - - "+title) {
		t.Fatalf("/quarantine: %s", body)
	}
	// JSON negotiation keeps the v1 object shape plus next.
	c, nonce, _ = e.solveW(t, ip)
	st, body, _ = e.do(t, "POST", "/w/kb", "", anonIn(uniq("anon flow json: ECONNRESET")), "CF-Connecting-IP", ip, "X-PoW", c+":"+nonce, "Accept", "application/json")
	var j struct {
		OK         bool     `json:"ok"`
		ID         string   `json:"id"`
		Quarantine bool     `json:"quarantine"`
		Next       []string `json:"next"`
	}
	if err := json.Unmarshal([]byte(body), &j); err != nil || st != 202 || !j.OK || !j.Quarantine || !core.ValidIDPrefix(j.ID, 'k') || len(j.Next) != 3 {
		t.Fatalf("json: %d %s", st, body)
	}
	e.dropLater(t, body)
	// GET /w/kb tells agents about the X-PoW lane in text.
	if st, body, _ := e.do(t, "GET", "/w/kb", "", nil); st != 200 || !strings.HasPrefix(first(body), "post /w/kb anonymous") || !strings.Contains(body, "X-PoW") {
		t.Fatalf("GET /w/kb: %d %s", st, body)
	}
}

func TestAnonFormTokenRequired(t *testing.T) {
	e := newAnonEnv(t)
	ctx := context.Background()
	ip := anonSuper() + ".3"
	form := func(vals url.Values, hdr ...string) (int, string) {
		t.Helper()
		hs := append([]string{"CF-Connecting-IP", ip, "Content-Type", "application/x-www-form-urlencoded", "Origin", "https://agents.example"}, hdr...)
		st, body, _ := e.do(t, "POST", "/w/kb", "", vals.Encode(), hs...)
		if st == 202 {
			e.dropLater(t, body)
		}
		return st, body
	}
	v := url.Values{"kind": {"fix"}, "title": {uniq("form post: yarn ENOENT on postinstall")}, "symptom": {"ENOENT: no such file or directory, open node_modules/.bin/x"},
		"fix": {"rm -rf node_modules && yarn"}, "tags": {"yarn, Node"}}
	// No ft -> 403 err bad form token (3.7); a wrong token or a foreign Origin too.
	if st, body := form(v); st != 403 || first(body) != "err bad form token" {
		t.Fatalf("no ft: %d %s", st, body)
	}
	v.Set("ft", strings.Repeat("0", 32))
	if st, _ := form(v); st != 403 {
		t.Fatal("bad ft accepted")
	}
	ft := core.FormToken(e.cfg.ServerSecret, "/w/kb", core.IPGroup(ip), time.Now())
	v.Set("ft", ft)
	if st, _ := form(v, "Origin", "https://evil.example"); st != 403 {
		t.Fatal("foreign origin accepted")
	}
	// GET /w/kb hands a browser that token and the honeypot field.
	st, page, hdr := e.do(t, "GET", "/w/kb", "", nil, "CF-Connecting-IP", ip, "Accept", "text/html")
	if st != 200 || !strings.Contains(page, `name="ft" value="`+ft+`"`) || !strings.Contains(page, `name="website"`) || !strings.Contains(page, `action="/w/kb"`) {
		t.Fatalf("form page: %d %s", st, page)
	}
	if cc := hdr.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("a per-network form must not be cached: %q", cc)
	}
	// Honeypot filled -> 400, nothing written, no quota charged.
	v.Set("website", "http://spam.example")
	if st, body := form(v); st != 400 || first(body) != "err bad form" {
		t.Fatalf("honeypot: %d %s", st, body)
	}
	v.Del("website")
	// Valid -> 202 quarantine without any PoW; tags normalised.
	st, body := form(v)
	if st != 202 || !okQuarantineRe.MatchString(first(body)) {
		t.Fatalf("form post: %d %s", st, body)
	}
	id := strings.Fields(body)[1]
	var tags []string
	var q bool
	var grp string
	if err := testPool.QueryRow(ctx, `SELECT tags, quarantine, anon_grp FROM kb WHERE id = $1`, id).Scan(&tags, &q, &grp); err != nil {
		t.Fatal(err)
	}
	if !q || strings.Join(tags, ",") != "yarn,node" || grp != ip {
		t.Fatalf("row: quarantine=%v tags=%v grp=%q", q, tags, grp)
	}
	// 2/day per network (6.3): the third form post is refused even with a valid token.
	v.Set("title", uniq("form post two: pip CERTIFICATE_VERIFY_FAILED"))
	v.Set("symptom", "ssl.SSLCertVerificationError: certificate verify failed: unable to get local issuer")
	v.Set("fix", "pip config set global.cert /etc/ssl/cert.pem")
	if st, body := form(v); st != 202 {
		t.Fatalf("second form post: %d %s", st, body)
	}
	v.Set("title", uniq("form post three: cargo linker cc not found"))
	v.Set("symptom", "error: linker `cc` not found")
	v.Set("fix", "apt install build-essential")
	if st, body := form(v); st != 429 || first(body) != "err quota daily quota reached" {
		t.Fatalf("third form post: %d %s", st, body)
	}
	// Yesterday's token is still accepted, the day before's is not.
	ip2 := anonSuper() + ".3"
	v.Set("ft", core.FormToken(e.cfg.ServerSecret, "/w/kb", core.IPGroup(ip2), time.Now().Add(-24*time.Hour)))
	if st, body := form(v, "CF-Connecting-IP", ip2); st != 202 {
		t.Fatalf("yesterday's token: %d %s", st, body)
	}
	v.Set("ft", core.FormToken(e.cfg.ServerSecret, "/w/kb", core.IPGroup(ip2), time.Now().Add(-48*time.Hour)))
	if st, _ := form(v, "CF-Connecting-IP", ip2); st != 403 {
		t.Fatal("stale token accepted")
	}
}

func TestAnonGroupAndSuperQuotas(t *testing.T) {
	e := newAnonEnv(t)
	stubPoW(t)
	net := anonSuper()
	post := func(host, i int) (int, string) {
		t.Helper()
		st, body, _ := e.wpost(t, fmt.Sprintf("%s.%d", net, host), anonIn(fmt.Sprintf("quota entry %d-%d: %s", host, i, uniq("ETIMEDOUT"))))
		return st, body
	}
	// ip:<grp> 5/day (4.3).
	for i := 1; i <= anonPerGroup; i++ {
		if st, body := post(1, i); st != 202 {
			t.Fatalf("group post %d: %d %s", i, st, body)
		}
	}
	if st, body := post(1, 6); st != 429 || first(body) != "err quota daily quota reached" {
		t.Fatalf("6th from one group: %d %s", st, body)
	}
	// The super-group (/24) allows 4x: three more hosts fill it, a fifth host is refused on its first post.
	for host := 2; host <= 4; host++ {
		for i := 1; i <= anonPerGroup; i++ {
			if st, body := post(host, i); st != 202 {
				t.Fatalf("host %d post %d: %d %s", host, i, st, body)
			}
		}
	}
	if st, body := post(5, 1); st != 429 || first(body) != "err quota daily quota reached" {
		t.Fatalf("21st from the super-group: %d %s", st, body)
	}
	// The counters are charged inside CreateEntry's transaction: a refused write rolls its bump back.
	if n := queryInt(t, `SELECT n FROM counters WHERE scope = $1 AND kind = 'kb' AND day = current_date`, "ip:"+net+".1"); n != anonPerGroup {
		t.Fatalf("group counter %d", n)
	}
	if n := queryInt(t, `SELECT n FROM counters WHERE scope = $1 AND kind = 'kb' AND day = current_date`, "sup:"+net+".0/24"); n != 4*anonPerGroup {
		t.Fatalf("super counter %d", n)
	}
	// Another /24 is unaffected.
	if st, body, _ := e.wpost(t, anonSuper()+".1", anonIn(uniq("quota other network: EADDRINUSE"))); st != 202 {
		t.Fatalf("other super: %d %s", st, body)
	}
}

func TestQuarantineGlobalCap(t *testing.T) {
	e := newAnonEnv(t)
	stubPoW(t)
	ctx := context.Background()
	live, cap := QuarantineOccupancy(ctx, testPool)
	if cap != quarantineCap || live >= quarantineCap {
		t.Fatalf("occupancy %d/%d", live, cap)
	}
	// Token-authored quarantined rows fill the queue: eviction never touches them, so the hard cap holds.
	fixtureRows(t, "cap", quarantineCap-live, "", 0)
	if l, _ := QuarantineOccupancy(ctx, testPool); l != quarantineCap {
		t.Fatalf("occupancy %d", l)
	}
	st, body, _ := e.wpost(t, anonSuper()+".2", anonIn(uniq("cap test: ENOSPC no space left on device")))
	if st != 429 || first(body) != "err quota quarantine full" {
		t.Fatalf("full queue: %d %s", st, body)
	}
	// /quarantine reports 100 % and the raised floor: 4 + ceil(4*1) = 8 bits (27.8).
	st, body, _ = e.do(t, "GET", "/quarantine", "", nil)
	if st != 200 || !regexp.MustCompile(`^quarantine n=50 occupancy=100% bits=(8|10)$`).MatchString(first(body)) {
		t.Fatalf("head: %d %q", st, first(body))
	}
	// A token writer is not held back by the anonymous queue being full.
	_, tok := e.register(t, "capw")
	if st, body, _ := e.do(t, "POST", "/v1/kb", tok, anonIn(uniq("cap test token post: ENOSPC"))); st != 201 {
		t.Fatalf("token post with a full queue: %d %s", st, body)
	}
}

func TestQuarantineListAndPurge(t *testing.T) {
	e := newAnonEnv(t)
	stubPoW(t)
	ctx := context.Background()
	ip := anonSuper() + ".4"
	ids := make([]string, 2)
	for i := range ids {
		st, body, _ := e.wpost(t, ip, anonIn(fmt.Sprintf("list entry %d: %s", i, uniq("EACCES permission denied"))))
		if st != 202 {
			t.Fatalf("post: %d %s", st, body)
		}
		ids[i] = strings.Fields(body)[1]
	}
	st, body, hdr := e.do(t, "GET", "/quarantine", "", nil)
	if st != 200 || !regexp.MustCompile(`^quarantine n=\d+ occupancy=\d+% bits=\d+$`).MatchString(first(body)) {
		t.Fatalf("list: %d %s", st, body)
	}
	if hdr.Get("X-Robots-Tag") == "" || !strings.Contains(hdr.Get("Cache-Control"), "max-age=30") {
		t.Fatalf("headers: robots=%q cache=%q", hdr.Get("X-Robots-Tag"), hdr.Get("Cache-Control"))
	}
	ls := lines(body)
	if len(ls) < 3 || !strings.HasPrefix(ls[1], ids[1]+" fix? 0h anon - - list entry 1: ") || !strings.HasPrefix(ls[2], ids[0]+" fix? 0h anon - - list entry 0: ") {
		t.Fatalf("rows newest first:\n%s", body)
	}
	if !strings.HasSuffix(body, "\nnext: GET /v1/kb/"+ids[1]+"?quarantine=1 | POST /v1/kb/"+ids[1]+"/ok L2 confirm | POST /w/kb +X-PoW") {
		t.Fatalf("tail:\n%s", body)
	}
	// op kq == the HTTP text minus the tail (MCP results carry none).
	out, err := AnonOps(e.d)["kq"](ctx, nil, nil)
	if err != nil || strings.TrimSpace(out) != noTail(body) {
		t.Fatalf("op kq:\n%q\nhttp:\n%q\n%v", out, body, err)
	}
	if m := AnonOpMeta["kq"]; m.Scope != "kb:r" || m.Mutating {
		t.Fatalf("kq meta %+v", m)
	}
	// JSON rows carry the column names.
	st, body, _ = e.do(t, "GET", "/quarantine", "", nil, "Accept", "application/json")
	if st != 200 || !strings.Contains(body, `"id":"`+ids[1]+`"`) || !strings.Contains(body, `"kind":"fix?"`) {
		t.Fatalf("json list: %d %s", st, body)
	}
	// Purge (4.4): an unpromoted row older than 14 d goes with an expire tombstone; young rows stay.
	if _, err := testPool.Exec(ctx, `UPDATE kb SET created = now() - interval '15 days' WHERE id = $1`, ids[0]); err != nil {
		t.Fatal(err)
	}
	n, err := PurgeQuarantine(ctx, testPool)
	if err != nil || n < 1 {
		t.Fatalf("purge: %d %v", n, err)
	}
	if queryInt(t, `SELECT count(*) FROM kb WHERE id = $1`, ids[0]) != 0 || queryInt(t, `SELECT count(*) FROM kb WHERE id = $1`, ids[1]) != 1 {
		t.Fatal("purge picked the wrong rows")
	}
	if tb, ok := Gone(ctx, testPool, ids[0]); !ok || tb.Reason != "expire" || tb.Line() != "gone expire" {
		t.Fatalf("tombstone: %+v %v", tb, ok)
	}
	if st, body, _ := e.do(t, "GET", "/v1/kb/"+ids[0]+"?quarantine=1", "", nil); st != 410 || first(body) != "err gone expire" {
		t.Fatalf("purged read: %d %s", st, body)
	}
	// A promoted row of the same age is not the purge's business.
	if _, err := testPool.Exec(ctx, `UPDATE kb SET created = now() - interval '15 days', quarantine = false, confirmed_at = now() WHERE id = $1`, ids[1]); err != nil {
		t.Fatal(err)
	}
	if _, err := PurgeQuarantine(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	if queryInt(t, `SELECT count(*) FROM kb WHERE id = $1`, ids[1]) != 1 {
		t.Fatal("promoted row purged")
	}
}

func TestEditKeyInReply(t *testing.T) {
	e := newAnonEnv(t)
	stubPoW(t)
	ip := anonSuper() + ".5"
	// No minter installed: the plain line.
	st, body, _ := e.wpost(t, ip, anonIn(uniq("edit key none: EPIPE")))
	if st != 202 || strings.Contains(body, "edit=") {
		t.Fatalf("no minter: %d %s", st, body)
	}
	old := AnonEditKeyFn
	t.Cleanup(func() { AnonEditKeyFn = old })
	var minted string
	key := "abcdefghijklmnopqrstuvwxyz"
	AnonEditKeyFn = func(ctx context.Context, q core.Q, id string) (string, error) {
		minted = id
		return key, nil
	}
	st, body, _ = e.wpost(t, ip, anonIn(uniq("edit key some: EPIPE broken pipe")))
	if st != 202 || first(body) != "ok "+strings.Fields(body)[1]+" quarantine edit="+key {
		t.Fatalf("minted: %d %s", st, body)
	}
	if minted != strings.Fields(body)[1] {
		t.Fatalf("minter saw %q for %s", minted, first(body))
	}
	st, body, _ = e.wpost(t, ip, anonIn(uniq("edit key json: EPIPE")), "Accept", "application/json")
	if st != 202 || !strings.Contains(body, `"edit":"`+key+`"`) {
		t.Fatalf("json edit: %d %s", st, body)
	}
	// A failing minter never loses the write.
	AnonEditKeyFn = func(context.Context, core.Q, string) (string, error) { return "", errors.New("boom") }
	if st, body, _ = e.wpost(t, ip, anonIn(uniq("edit key fail: EPIPE"))); st != 202 || strings.Contains(body, "edit=") {
		t.Fatalf("failing minter: %d %s", st, body)
	}
	// PostAnon (the MCP lane, p{…,pow}) gives the same line.
	AnonEditKeyFn = func(context.Context, core.Q, string) (string, error) { return strings.Repeat("z", 26), nil }
	ctx := core.WithClient(context.Background(), ip, core.IPGroup(ip), core.IPSuper(ip))
	out, err := PostAnon(ctx, e.d, Input{Kind: "fix", Title: uniq("edit key mcp: EPIPE"), Symptom: "write EPIPE", Force: true, Pow: "stub"})
	if err != nil || !regexp.MustCompile(`^ok k[a-z2-7]{6} quarantine edit=z{26}$`).MatchString(out) {
		t.Fatalf("PostAnon: %q %v", out, err)
	}
	e.dropLater(t, out)
	if _, err := PostAnon(ctx, e.d, Input{Kind: "fix", Title: "x"}); err != core.ErrAuth {
		t.Fatalf("PostAnon without pow: %v", err)
	}
	if _, err := PostAnon(ctx, e.d, Input{Kind: "fix", Title: "x", Pow: "wrong"}); err != core.ErrPow {
		t.Fatalf("PostAnon with a bad pow: %v", err)
	}
}

func TestAnonBitsCurve(t *testing.T) {
	// bits = base + ceil(4*occ) + floor(20*share) + 2*[burst], capped 26, never below base (27.8).
	for _, c := range []struct{ base, live, superLive, lastHour, want int }{
		{16, 0, 0, 0, 16},
		{16, 1, 0, 0, 17},
		{16, 2500, 0, 0, 18},
		{16, 5000, 0, 0, 20},
		{16, 0, 50, 0, 26},
		{16, 0, 5, 0, 17},
		{16, 0, 100, 0, 26},
		{16, 0, 0, 500, 16},
		{16, 0, 0, 501, 18},
		{16, 5000, 100, 501, 26},
		{4, 5000, 100, 501, 26},
		{4, 2500, 25, 0, 11},
		{30, 5000, 100, 501, 30},
		{16, 7000, 400, 0, 26},
	} {
		if got := bitsFor(c.base, c.live, c.superLive, c.lastHour); got != c.want {
			t.Errorf("bitsFor(%d, %d, %d, %d) = %d, want %d", c.base, c.live, c.superLive, c.lastHour, got, c.want)
		}
	}
	if shareOf(0) != 0 || shareOf(50) != 0.5 || shareOf(100) != 1 || shareOf(300) != 1 {
		t.Fatal("shareOf")
	}
	// Live: RegisterAnon installs the seam; the challenge route, /quarantine and QuarantineShare agree with it.
	e := newAnonEnv(t)
	ctx := context.Background()
	ip := anonSuper() + ".6"
	super := core.IPSuper(ip)
	live, superLive, lastHour, err := anonStats(ctx, testPool, super)
	if err != nil || superLive != 0 {
		t.Fatalf("stats: %d %d %d %v", live, superLive, lastHour, err)
	}
	if got := e.d.AnonBits(ctx, super); got != bitsFor(4, live, 0, lastHour) {
		t.Fatalf("AnonBits %d, want %d", got, bitsFor(4, live, 0, lastHour))
	}
	if QuarantineShare(ctx, testPool, super) != 0 || QuarantineShare(ctx, testPool, "") != 0 {
		t.Fatal("share of an empty network")
	}
	// 60 anonymous rows of this network: share 0.6 -> +12 bits for it, nothing for a stranger.
	fixtureRows(t, "bits", 60, super, 0)
	live, superLive, lastHour, _ = anonStats(ctx, testPool, super)
	if superLive != 60 || QuarantineShare(ctx, testPool, super) != 0.6 {
		t.Fatalf("super rows %d share %v", superLive, QuarantineShare(ctx, testPool, super))
	}
	want := bitsFor(4, live, 60, lastHour)
	if got := e.d.AnonBits(ctx, super); got != want || got < 16 {
		t.Fatalf("AnonBits %d, want %d", got, want)
	}
	stranger := e.d.AnonBits(ctx, anonSuper()+".0/24")
	if stranger != bitsFor(4, live, 0, lastHour) || stranger >= want {
		t.Fatalf("stranger %d vs network %d", stranger, want)
	}
	if _, _, bits := e.solveW(t, ip); bits != want {
		t.Fatalf("challenge bits %d, want %d", bits, want)
	}
	// /quarantine states the floor of an empty network and the occupancy.
	_, body, _ := e.do(t, "GET", "/quarantine", "", nil)
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(first(body), -1) {
		m[x[1]] = x[2]
	}
	if m["bits"] != strconv.Itoa(stranger) || m["occupancy"] != fmt.Sprintf("%d%%", (100*live+quarantineCap/2)/quarantineCap) {
		t.Fatalf("head %q (live %d)", first(body), live)
	}
	// The curve degrades to the base when the database is unreachable.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if got := AnonBits(cctx, testPool, super, 16); got != 16 {
		t.Fatalf("AnonBits on a dead context: %d", got)
	}
}

func TestSuperAdmissionShareAndEviction(t *testing.T) {
	e := newAnonEnv(t)
	stubPoW(t)
	ctx := context.Background()
	// Admission (27.8): a super-group holding its 2 % (100 live rows) is refused before any counter is charged.
	netS := anonSuper()
	superS := netS + ".0/24"
	fixtureRows(t, "sh", superCap, superS, 0)
	st, body, _ := e.wpost(t, netS+".7", anonIn(uniq("share test: EHOSTUNREACH")))
	if st != 429 || first(body) != "err quota quarantine share" {
		t.Fatalf("share cap: %d %s", st, body)
	}
	if queryInt(t, `SELECT count(*) FROM counters WHERE scope = $1 AND kind = 'kb' AND day = current_date`, "ip:"+netS+".7") != 0 {
		t.Fatal("a refused write charged the group counter")
	}
	if s := QuarantineShare(ctx, testPool, superS); s != 1 {
		t.Fatalf("share %v", s)
	}
	// One row short of the allowance admits.
	if _, err := testPool.Exec(ctx, `DELETE FROM kb WHERE id = 'ktsh0001'`); err != nil {
		t.Fatal(err)
	}
	if st, body, _ := e.wpost(t, netS+".7", anonIn(uniq("share test below cap: EHOSTUNREACH"))); st != 202 {
		t.Fatalf("below the share cap: %d %s", st, body)
	}
	// Eviction: at 95 % the queue is trimmed to 90 %, the oldest rows of the largest-share super-group first.
	live, _ := QuarantineOccupancy(ctx, testPool)
	a, b, c := anonSuper()+".0/24", anonSuper()+".0/24", anonSuper()+".0/24"
	target := int(evictAt*quarantineCap) + 60
	fixtureRows(t, "eva", 2000, a, 3*time.Hour)
	fixtureRows(t, "evb", 1500, b, 2*time.Hour)
	fixtureRows(t, "evc", target-live-3500, c, time.Hour)
	if l, _ := QuarantineOccupancy(ctx, testPool); l != target {
		t.Fatalf("live %d, want %d", l, target)
	}
	wantN := target - int(evictTo*quarantineCap)
	n, err := Evict(ctx, testPool)
	if err != nil || n != wantN {
		t.Fatalf("evict: %d %v, want %d", n, err, wantN)
	}
	if l, _ := QuarantineOccupancy(ctx, testPool); l != int(evictTo*quarantineCap) {
		t.Fatalf("after evict %d", l)
	}
	count := func(super string) int {
		return queryInt(t, `SELECT count(*) FROM kb WHERE quarantine AND anon_super = $1`, super)
	}
	if count(a) != 2000-wantN || count(b) != 1500 || count(c) != target-live-3500 || count(superS) != superCap {
		t.Fatalf("after evict: a=%d b=%d c=%d s=%d", count(a), count(b), count(c), count(superS))
	}
	var oldest string
	if err := testPool.QueryRow(ctx, `SELECT min(id) FROM kb WHERE anon_super = $1`, a).Scan(&oldest); err != nil || oldest != fmt.Sprintf("kteva%04d", wantN+1) {
		t.Fatalf("a's oldest survivor %q %v", oldest, err)
	}
	if queryInt(t, `SELECT count(*) FROM kb_tombstones WHERE reason = 'expire' AND id LIKE 'kteva%'`) != wantN {
		t.Fatal("evicted rows without expire tombstones")
	}
	if n, err := Evict(ctx, testPool); err != nil || n != 0 {
		t.Fatalf("evict below 95%%: %d %v", n, err)
	}
	// An anonymous write arriving at >= 95 % trims the queue first and then lands (a fresh network).
	fixtureRows(t, "evd", int(evictAt*quarantineCap)-int(evictTo*quarantineCap)+5, b, 30*time.Minute)
	st, body, _ = e.wpost(t, anonSuper()+".8", anonIn(uniq("eviction write: ECONNABORTED")))
	if st != 202 {
		t.Fatalf("write at 95%%: %d %s", st, body)
	}
	if l, _ := QuarantineOccupancy(ctx, testPool); l != int(evictTo*quarantineCap)+1 {
		t.Fatalf("after the admission trim %d", l)
	}
	if _, body, _ := e.do(t, "GET", "/quarantine", "", nil); !strings.Contains(first(body), " occupancy=90% ") {
		t.Fatalf("head %q", first(body))
	}
}
