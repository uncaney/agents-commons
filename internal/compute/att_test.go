package compute

// Acceptance tests of P13b-compute-att (SPEC-v2 14.2 pages, 14.4 admin blob, 27.6 donor tuples).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/sign"
)

// newAttEnv is newEnv plus the attestation routes (RegisterAtt) on the same Deps.
func newAttEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, false)
	e.srv.Close()
	mux := http.NewServeMux()
	core.Register(mux, e.d)
	e.s.register(mux)
	e.s.registerAtt(mux)
	e.srv = httptest.NewServer(e.d.Handler(mux))
	t.Cleanup(e.srv.Close)
	return e
}

// txtFields parses a txt page body into its "name: value" fields (multi-line values joined with
// \n, repeated names appended) and returns the head and next: lines.
func txtFields(body string) (head string, fields map[string][]string, next string) {
	fields = map[string][]string{}
	lines := strings.Split(body, "\n")
	head = lines[0]
	last := ""
	for _, l := range lines[1:] {
		switch {
		case strings.HasPrefix(l, "next: "):
			next = l
		case strings.HasPrefix(l, "  ") && last != "":
			v := fields[last]
			v[len(v)-1] += "\n" + l[2:]
		default:
			name, val, ok := strings.Cut(l, ": ")
			if !ok {
				continue
			}
			fields[name] = append(fields[name], val)
			last = name
		}
	}
	return
}

func first(fields map[string][]string, name string) string {
	if v := fields[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// agreeSigned runs a fresh job through two agreeing workers; worker 0 signs its report with priv.
func (e *env) agreeSigned(stok string, w []string, wasm, in string, outData []byte, priv ed25519.PrivateKey) (jid, out, lease0, lease1, dsig string) {
	e.t.Helper()
	jid = e.submit(stok, wasm, in, 2000)
	out = e.put(w[0], outData)
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	dsig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, dsigMessage(jid, l0.Lease, "ok:0:"+out)))
	if st, body, _ := e.do("POST", "/v1/w/done", w[0], map[string]any{"lease": l0.Lease, "status": "ok", "out": out, "ms": 1000, "dsig": dsig}); st != 200 {
		e.t.Fatalf("signed done: %d %s", st, body)
	}
	e.mustDone(w[1], l1.Lease, "ok", out, 0, 1000)
	if got := e.job(stok, jid, 0); !strings.HasPrefix(got, jid+" done out="+out) {
		e.t.Fatalf("agree: %s", got)
	}
	return jid, out, l0.Lease, l1.Lease, dsig
}

func TestPublishAttPageAndVerifyLines(t *testing.T) {
	e := newAttEnv(t)
	ctx := context.Background()
	sid, stok, wasm, in, w, wid := e.setup(2)
	_, otok := e.register("o")
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	testPool.Exec(ctx, `UPDATE identities SET pub = $2 WHERE id = $1`, wid[0], []byte(pub))
	queued := e.submit(stok, wasm, in, 2000)
	if st, body, _ := e.do("POST", "/v1/j/"+queued+"/publish", stok, nil); st != 409 || !strings.HasPrefix(body, "err bad "+queued+" queued") {
		t.Fatalf("publish before finalization: %d %s", st, body)
	}
	testPool.Exec(ctx, cancelSQL(` AND id = '`+queued+`'`), []string(nil))
	jid, out, lease0, lease1, dsig := e.agreeSigned(stok, w, wasm, in, []byte("receipt "+sid), priv)
	// Unknown and unpublished receipts are the same 404; anonymous readers learn nothing.
	st, body404, _ := e.do("GET", "/att/"+jid, "", nil)
	st2, bodyUnknown, _ := e.do("GET", "/att/jzzzzzz", "", nil)
	if st != 404 || st2 != 404 || body404 != bodyUnknown || !strings.HasPrefix(body404, "err notfound") {
		t.Fatalf("unpublished page: %d %q vs %d %q", st, body404, st2, bodyUnknown)
	}
	if st, _, _ := e.do("GET", "/att/not-an-id", "", nil); st != 404 {
		t.Fatalf("bad id: %d", st)
	}
	if st, _, _ := e.do("POST", "/v1/j/"+jid+"/publish", otok, nil); st != 404 {
		t.Fatalf("stranger publish: %d", st)
	}
	if st, _, _ := e.do("POST", "/v1/j/"+jid+"/publish", "", nil); st != 401 {
		t.Fatalf("anonymous publish: %d", st)
	}
	if st, body, _ := e.do("POST", "/v1/j/zzz/publish", stok, nil); st != 400 || body != "err bad bad job id" {
		t.Fatalf("bad job id: %d %s", st, body)
	}
	want := "ok published " + jid + " /att/" + jid
	for i := 0; i < 2; i++ { // idempotent
		if st, body, _ := e.do("POST", "/v1/j/"+jid+"/publish", stok, nil); st != 200 || body != want {
			t.Fatalf("publish #%d: %d %s", i, st, body)
		}
	}
	var published bool
	testPool.QueryRow(ctx, `SELECT published FROM jobs WHERE id = $1`, jid).Scan(&published)
	if !published {
		t.Fatal("jobs.published not set")
	}
	if _, _, u, ok := e.d.Resolve(ctx, jid); !ok || u != "/att/"+jid {
		t.Fatalf("resolver: %q %v", u, ok)
	}
	// txt page.
	st, body, hd := e.do("GET", "/att/"+jid, "", nil)
	if st != 200 || !strings.HasPrefix(hd.Get("Content-Type"), "text/plain") {
		t.Fatalf("page: %d %s %v", st, body, hd)
	}
	head, f, next := txtFields(body)
	if head != "att "+jid+" done n=2/2 d=1 repro=0/0" {
		t.Fatalf("head: %q", head)
	}
	line, sig := first(f, "line"), first(f, "sig")
	if !strings.HasPrefix(line, "att1 j="+jid+" w="+wasm+" i="+in+" o="+out+" s=ok c=0 n=2/2 d=1 t=") || !strings.Contains(line, " k=1") || !strings.HasSuffix(line, " ds=1") {
		t.Fatalf("line: %q", line)
	}
	signer := sign.MustNew(e.d.Cfg)
	if kid, ok := signer.Verify("att1", line, sig); !ok || kid != 1 {
		t.Fatalf("page line does not verify: %q %q", line, sig)
	}
	if first(f, "pubkey") != hex.EncodeToString(signer.Public()) || first(f, "kid") != "1" || first(f, "key") != "/.well-known/cx-key" {
		t.Fatalf("key fields: %v", f)
	}
	if first(f, "by") != sid+" lvl=L2" || first(f, "repro") != "0/0" || first(f, "public") != "-" {
		t.Fatalf("by/repro/public: %q %q %q", first(f, "by"), first(f, "repro"), first(f, "public"))
	}
	donors := f["donor"]
	if len(donors) != 2 || donors[0] != wid[0]+" pub="+hex.EncodeToString(pub)+" dsig="+dsig+" lease="+lease0 || donors[1] != wid[1]+" pub=- dsig=- lease="+lease1 {
		t.Fatalf("donor lines: %q", donors)
	}
	for name, needle := range map[string]string{
		"verify_openssl":      `printf 'cx-sig-v1\0att1\0%s' "$LINE" > msg.bin`,
		"verify_node":         `Buffer.from("cx-sig-v1\0att1\0")`,
		"verify_python":       `msg = b"cx-sig-v1\0att1\0" + line.encode()`,
		"verify_dsig_openssl": `printf 'cx-dsig-v1\0` + jid + `\0%s\0ok:0:` + out + `' "$LEASE"`,
		"verify_dsig_node":    `"cx-dsig-v1\0" + job + "\0" + lease + "\0" + fp`,
	} {
		if v := first(f, name); !strings.Contains(v, needle) || !strings.Contains(v, "openssl pkeyutl") && strings.HasSuffix(name, "openssl") {
			t.Fatalf("%s: %q", name, v)
		}
	}
	if !strings.Contains(first(f, "verify_openssl"), "LINE='"+line+"'") || !strings.Contains(first(f, "verify_node"), `sig = "`+strings.TrimPrefix(sig, "sig=")+`"`) {
		t.Fatalf("snippets must carry the real line and signature: %q", first(f, "verify_openssl"))
	}
	if !strings.Contains(first(f, "note"), "replication receipt observed by agents.ekaii.fr, not a cryptographic proof of execution") {
		t.Fatalf("note: %q", first(f, "note"))
	}
	if next != "next: POST /v1/j/"+jid+"/reproduce same wasm+in | GET /att/"+jid+".json | GET /.well-known/cx-key server key | GET /att/revoked.txt" {
		t.Fatalf("next: %q", next)
	}
	if !strings.HasPrefix(hd.Get("Cache-Control"), "public") || hd.Get("X-Robots-Tag") != "noindex" || hd.Get("ETag") == "" {
		t.Fatalf("fresh receipt headers: %v", hd)
	}
	if st, _, hd := e.do("GET", "/att/"+jid, stok, nil); st != 200 || hd.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("token read: %d %v", st, hd)
	}
	// JSON exposes the verifiable tuples.
	st, body, _ = e.do("GET", "/att/"+jid+".json", "", nil)
	var j struct {
		Head, Line, Sig, Pubkey, Repro string
		Rows                           []struct{ Donor, Pub, Dsig, Lease string }
	}
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || j.Head != head || j.Line != line || j.Sig != sig || j.Repro != "0/0" || len(j.Rows) != 2 {
		t.Fatalf("json: %d %s", st, body)
	}
	tup := j.Rows[0]
	pubBytes, _ := hex.DecodeString(tup.Pub)
	dsigBytes, _ := base64.RawURLEncoding.DecodeString(tup.Dsig)
	if tup.Donor != wid[0] || tup.Lease != lease0 || !ed25519.Verify(ed25519.PublicKey(pubBytes), dsigMessage(jid, tup.Lease, "ok:0:"+out), dsigBytes) {
		t.Fatalf("tuple does not verify: %+v", tup)
	}
	if j.Rows[1].Donor != wid[1] || j.Rows[1].Pub != "-" || j.Rows[1].Dsig != "-" {
		t.Fatalf("unsigned donor tuple: %+v", j.Rows[1])
	}
	// md and html renditions.
	if st, body, _ := e.do("GET", "/att/"+jid+".md", "", nil); st != 200 || !strings.HasPrefix(body, "# compute receipt "+jid) || !strings.Contains(body, "permalink: "+doc.Base()+"/att/"+jid) {
		t.Fatalf("md: %d %s", st, body)
	}
	st, body, hd = e.do("GET", "/att/"+jid+".html", "", nil)
	if st != 200 || !strings.Contains(body, "<title>compute receipt "+jid+"</title>") || !strings.Contains(body, `<meta name="robots" content="noindex">`) ||
		!strings.Contains(body, `"@type":"DigitalDocument"`) || !strings.Contains(body, "cx-sig-v1") || hd.Get("Content-Security-Policy") == "" {
		t.Fatalf("html: %d %s", st, body)
	}
	// Indexable once an hour old with an L2 author; the sitemap follows the same predicate.
	if sm, err := e.d.Sitemaps()["att"](ctx); err != nil || containsLoc(sm, doc.Base()+"/att/"+jid) {
		t.Fatalf("fresh receipt in sitemap: %v %v", sm, err)
	}
	testPool.Exec(ctx, `UPDATE jobs SET finished_at = now() - interval '2 hours' WHERE id = $1`, jid)
	if st, body, hd := e.do("GET", "/att/"+jid+".html", "", nil); st != 200 || hd.Get("X-Robots-Tag") != "" || !strings.Contains(body, `content="index,follow`) {
		t.Fatalf("aged L2 receipt must be indexable: %d %v", st, hd)
	}
	sm, err := e.d.Sitemaps()["att"](ctx)
	if err != nil || !containsLoc(sm, doc.Base()+"/att/"+jid) {
		t.Fatalf("sitemap: %v %v", sm, err)
	}
	// An L0 author's receipt stays noindex and out of the sitemap.
	l0id, l0tok := e.register("l0")
	wasm2, in2 := e.put(l0tok, minWasm("l0 "+l0id)), e.put(l0tok, []byte("in "+l0id))
	jid2, _ := e.agree(l0tok, w, wasm2, in2, []byte("l0 receipt "+l0id), 1000)
	if st, _, _ := e.do("POST", "/v1/j/"+jid2+"/publish", l0tok, nil); st != 200 {
		t.Fatalf("l0 publish: %d", st)
	}
	testPool.Exec(ctx, `UPDATE jobs SET finished_at = now() - interval '2 hours' WHERE id = $1`, jid2)
	if st, _, hd := e.do("GET", "/att/"+jid2, "", nil); st != 200 || hd.Get("X-Robots-Tag") != "noindex" {
		t.Fatalf("l0 receipt: %d %v", st, hd)
	}
	if sm, _ := e.d.Sitemaps()["att"](ctx); containsLoc(sm, doc.Base()+"/att/"+jid2) {
		t.Fatal("l0 receipt in sitemap")
	}
	// Ops and registry metadata.
	me, _ := e.d.LookupToken(ctx, stok)
	if got, err := OpsAtt(e.d)["jpub"](ctx, me, json.RawMessage(`{"id":"`+jid+`"}`)); err != nil || got != want {
		t.Fatalf("jpub: %q %v", got, err)
	}
	if _, err := OpsAtt(e.d)["jpub"](ctx, nil, json.RawMessage(`{"id":"`+jid+`"}`)); err == nil || err.Error() != "err auth token required" {
		t.Fatalf("anon jpub: %v", err)
	}
	if OpMetaAtt["jpub"].Scope != "j" || !OpMetaAtt["jrepro"].Mutating {
		t.Fatalf("op meta: %v", OpMetaAtt)
	}
	if sc, _ := e.d.ScopeOf("POST /v1/j/{id}/publish"); sc != "j" {
		t.Fatalf("scope: %q", sc)
	}
	// Own-lane jobs never publish.
	testPool.Exec(ctx, `UPDATE jobs SET lane = 'own' WHERE id = $1`, jid2)
	if st, body, _ := e.do("POST", "/v1/j/"+jid2+"/publish", l0tok, nil); st != 400 || body != "err bad own-lane jobs are private" {
		t.Fatalf("own lane publish: %d %s", st, body)
	}
	if st, _, _ := e.do("GET", "/att/"+jid2, "", nil); st != 200 {
		t.Fatalf("already published page: %d", st)
	}
	var auditN int
	testPool.QueryRow(ctx, `SELECT count(*) FROM audit WHERE root = $1 AND op = 'jpub' AND ref = $2`, sid, jid).Scan(&auditN)
	if auditN != 1 {
		t.Fatalf("audit rows for one publish: %d", auditN)
	}
}

func containsLoc(sm []core.SitemapURL, loc string) bool {
	for _, u := range sm {
		if u.Loc == loc {
			return true
		}
	}
	return false
}

func TestReproduceCountsMatches(t *testing.T) {
	e := newAttEnv(t)
	ctx := context.Background()
	sid, stok, wasm, in, w, _ := e.setup(2)
	jid, out := e.agree(stok, w, wasm, in, []byte("original "+sid), 2000)
	bid, btok := e.register("b")
	if st, _, _ := e.do("POST", "/v1/j/"+jid+"/reproduce", btok, nil); st != 404 {
		t.Fatalf("reproduce of an unpublished job by a stranger: %d", st)
	}
	if st, body, _ := e.do("POST", "/v1/j/zzz/reproduce", btok, nil); st != 400 || body != "err bad bad job id" {
		t.Fatalf("bad id: %d %s", st, body)
	}
	if st, _, _ := e.do("POST", "/v1/j/"+jid+"/publish", stok, nil); st != 200 {
		t.Fatalf("publish: %d", st)
	}
	st, body, _ := e.do("POST", "/v1/j/"+jid+"/reproduce", btok, nil)
	rid := firstField(body)
	if (st != 200 && st != 202) || !core.ValidIDPrefix(rid, 'j') || rid == jid || !strings.HasSuffix(body, "\nrepro of="+jid) {
		t.Fatalf("reproduce: %d %s", st, body)
	}
	if e.credits(bid) != 94 {
		t.Fatalf("the reproducer pays for the new job: %d", e.credits(bid))
	}
	var rw, ri, rroot, cached string
	var rms, rmb int
	testPool.QueryRow(ctx, `SELECT wasm, input, ms, mb, root, cached_from FROM jobs WHERE id = $1`, rid).Scan(&rw, &ri, &rms, &rmb, &rroot, &cached)
	if rw != wasm || ri != in || rms != 2000 || rmb != 64 || rroot != bid || cached != "" {
		t.Fatalf("reproduction spec: %s %s %d %d %s %q", rw, ri, rms, rmb, rroot, cached)
	}
	l0, l1 := e.mustLease(w[0]), e.mustLease(w[1])
	e.mustDone(w[0], l0.Lease, "ok", out, 0, 500)
	e.mustDone(w[1], l1.Lease, "ok", out, 0, 500)
	if got := e.job(btok, rid, 0); !strings.HasPrefix(got, rid+" done out="+out) {
		t.Fatalf("reproduction: %s", got)
	}
	for i := 0; i < 2; i++ { // the janitor pass is idempotent
		if err := settleRepros(ctx, testPool, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := settleRepros(ctx, testPool, jid); err != nil {
		t.Fatal(err)
	}
	st, body, _ = e.do("GET", "/att/"+jid, "", nil)
	if head, _, _ := txtFields(body); st != 200 || head != "att "+jid+" done n=2/2 d=1 repro=1/1" {
		t.Fatalf("page after one match: %d %q", st, body)
	}
	var byRoot string
	var match bool
	var n int
	testPool.QueryRow(ctx, `SELECT count(*), min(by_root), bool_and(match) FROM reproductions WHERE job = $1`, jid).Scan(&n, &byRoot, &match)
	if n != 1 || byRoot != bid || !match {
		t.Fatalf("reproductions rows: n=%d by=%s match=%v", n, byRoot, match)
	}
	// A second reproducer waits for its result, which disagrees: recorded as a mismatch.
	cid, ctok := e.register("c")
	other := e.put(w[0], []byte("different "+sid))
	go func() {
		time.Sleep(300 * time.Millisecond)
		a, b := e.mustLease(w[0]), e.mustLease(w[1])
		e.mustDone(w[0], a.Lease, "ok", other, 0, 500)
		e.mustDone(w[1], b.Lease, "ok", other, 0, 500)
	}()
	start := time.Now()
	st, body, _ = e.do("POST", "/v1/j/"+jid+"/reproduce?wait=10", ctok, nil)
	lines := strings.Split(body, "\n")
	rid2 := firstField(body)
	if st != 200 || len(lines) != 2 || !strings.HasPrefix(lines[0], rid2+" done out="+other+" ms=500") || lines[1] != "repro of="+jid+" match=0" || time.Since(start) > 5*time.Second {
		t.Fatalf("waited reproduce: %d %q after %v", st, body, time.Since(start))
	}
	st, body, _ = e.do("GET", "/att/"+jid+".json", "", nil)
	var j struct{ Head, Repro string }
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || j.Repro != "1/2" || !strings.HasSuffix(j.Head, " repro=1/2") {
		t.Fatalf("page after a mismatch: %d %s", st, body)
	}
	if err := settleRepros(ctx, testPool, ""); err != nil {
		t.Fatal(err)
	}
	testPool.QueryRow(ctx, `SELECT count(*) FROM reproductions WHERE job = $1`, jid).Scan(&n)
	testPool.QueryRow(ctx, `SELECT match FROM reproductions WHERE job = $1 AND by_root = $2`, jid, cid).Scan(&match)
	if n != 2 || match {
		t.Fatalf("after mismatch: n=%d c-match=%v", n, match)
	}
	// The JSON reply of a waited reproduce carries the comparison.
	st, body, _ = e.do("POST", "/v1/j/"+jid+"/reproduce?wait=0&f=json", ctok, nil)
	var jr map[string]any
	if (st != 200 && st != 202) || json.Unmarshal([]byte(body), &jr) != nil || jr["repro_of"] != jid || jr["id"] == nil {
		t.Fatalf("json reproduce: %d %s", st, body)
	}
	// The op mirrors the route; the submitter may reproduce its own job too.
	me, _ := e.d.LookupToken(ctx, stok)
	if got, err := OpsAtt(e.d)["jrepro"](ctx, me, json.RawMessage(`{"id":"`+jid+`"}`)); err != nil || !strings.HasSuffix(got, "\nrepro of="+jid) {
		t.Fatalf("jrepro: %q %v", got, err)
	}
	if _, err := OpsAtt(e.d)["jrepro"](ctx, nil, nil); err == nil || err.Error() != "err auth token required" {
		t.Fatalf("anon jrepro: %v", err)
	}
	// Organic re-runs that finished before the receipt existed are not reproductions of it.
	testPool.QueryRow(ctx, `SELECT count(*) FROM reproductions WHERE job = $1`, rid).Scan(&n)
	if n != 0 {
		t.Fatalf("unpublished reproduction got reproductions of its own: %d", n)
	}
}

func TestBlobPublishAnonymousRead(t *testing.T) {
	e := newAttEnv(t)
	sid, stok := e.register("p")
	text := []byte("public receipt input " + sid)
	clean := e.put(stok, text)
	if st, body, _ := e.do("GET", "/v1/b/"+clean, "", nil); st != 401 || body != "err auth token required" {
		t.Fatalf("anonymous read before publish: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/b/"+clean+"/publish", stok, nil); st != 200 || body != "ok public "+clean+" /v1/b/"+clean {
		t.Fatalf("publish: %d %s", st, body)
	}
	st, body, hd := e.do("GET", "/v1/b/"+clean, "", nil)
	if st != 200 || body != string(text) || hd.Get("Cache-Control") != "public, max-age=31536000, immutable" || hd.Get("ETag") != `"`+clean+`"` {
		t.Fatalf("anonymous read: %d %q %v", st, body, hd)
	}
	if st, body, hd := e.do("HEAD", "/v1/b/"+clean, "", nil); st != 200 || body != "" || hd.Get("Content-Length") != fmt.Sprint(len(text)) {
		t.Fatalf("anonymous head: %d %q %v", st, body, hd)
	}
	// Exactly 1 MiB of text publishes; one byte more is opaque and never becomes public.
	exact := append([]byte(sid+" "), bytes.Repeat([]byte("b"), maxText-len(sid)-1)...)
	h1 := e.put(stok, exact)
	if st, body, _ := e.do("POST", "/v1/b/"+h1+"/publish", stok, nil); st != 200 {
		t.Fatalf("publish 1 MiB text: %d %s", st, body)
	}
	if st, body, _ := e.do("GET", "/v1/b/"+h1, "", nil); st != 200 || len(body) != maxText {
		t.Fatalf("anonymous read of 1 MiB text: %d len=%d", st, len(body))
	}
	over := append([]byte(sid+" "), bytes.Repeat([]byte("c"), maxText-len(sid))...)
	h2 := e.put(stok, over)
	if st, body, _ := e.do("POST", "/v1/b/"+h2+"/publish", stok, nil); st != 400 || !strings.HasPrefix(body, "err bad") {
		t.Fatalf("publish over 1 MiB: %d %s", st, body)
	}
	if st, _, _ := e.do("GET", "/v1/b/"+h2, "", nil); st != 401 {
		t.Fatalf("anonymous read of a refused blob: %d", st)
	}
	var kind string
	var public bool
	testPool.QueryRow(context.Background(), `SELECT kind, public FROM blobs WHERE hash = $1`, h2).Scan(&kind, &public)
	if kind != "opaque" || public {
		t.Fatalf("over-sized text: kind=%s public=%v", kind, public)
	}
	// A scanned module publishes and is served to anonymous readers as bytes.
	wasm := e.put(stok, minWasm("anon "+sid))
	if st, _, _ := e.do("POST", "/v1/b/"+wasm+"/publish", stok, nil); st != 200 {
		t.Fatalf("publish wasm: %d", st)
	}
	if st, body, hd := e.do("GET", "/v1/b/"+wasm, "", nil); st != 200 || body != strings.TrimSpace(string(minWasm("anon "+sid))) || hd.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("anonymous wasm read: %d %v", st, hd)
	}
}

func TestAdminBlobUploadCapAndOwner(t *testing.T) {
	e := newAttEnv(t)
	ctx := context.Background()
	uid, utok := e.register("u")
	small := minWasm("admin small " + uid)
	if st, body, _ := e.do("PUT", "/admin/blob", utok, small); st != 401 || body != "err auth admin" {
		t.Fatalf("user token on /admin/blob: %d %s", st, body)
	}
	if st, _, _ := e.do("PUT", "/admin/blob", "", small); st != 401 {
		t.Fatalf("anonymous /admin/blob: %d", st)
	}
	if st, body := e.adminDo("PUT", "/admin/blob?name=bad%20name", small); st != 400 || !strings.HasPrefix(body, "err bad name") {
		t.Fatalf("bad pin name: %d %s", st, body)
	}
	// The cap is ADMIN_BLOB_MAX: 2 MiB against a 1 MiB cap is 413.
	e.d.Cfg.AdminBlobMax = 1 << 20
	padded := append(minWasm("admin cap "+uid), customSection("pad", strings.Repeat("x", 2<<20))...)
	if st, body := e.adminDo("PUT", "/admin/blob", padded); st != 413 || body != "err size body too large" {
		t.Fatalf("over the admin cap: %d %s", st, body)
	}
	e.d.Cfg.AdminBlobMax = 0 // default 64 MiB
	big := append(minWasm("admin big "+uid), customSection("pad", strings.Repeat("x", 40<<20))...)
	h := sha(big)
	t.Cleanup(func() {
		testPool.Exec(ctx, `DELETE FROM pins WHERE hash = $1`, h)
		testPool.Exec(ctx, `DELETE FROM blobs WHERE hash = $1`, h)
		testPool.Exec(ctx, `DELETE FROM blob_meta WHERE hash = $1`, h)
	})
	st, body := e.adminDo("PUT", "/admin/blob?name=cx-big&ver=1.0&note=forty", big)
	if st != 200 || body != fmt.Sprintf("ok blob %s size=%d kind=wasm owner=%s pinned_by=admin pin=cx-big@1.0", h, len(big), core.SystemID) {
		t.Fatalf("admin upload: %d %s", st, body)
	}
	var owner, by, mkind string
	var usedAt *time.Time
	testPool.QueryRow(ctx, `SELECT b.owner_root, b.pinned_by, b.used_at, coalesce(m.kind, '') FROM blobs b LEFT JOIN blob_meta m ON m.hash = b.hash WHERE b.hash = $1`, h).Scan(&owner, &by, &usedAt, &mkind)
	if owner != core.SystemID || by != "admin" || usedAt == nil || mkind != "wasm" {
		t.Fatalf("row: owner=%s pinned_by=%s used_at=%v meta=%s", owner, by, usedAt, mkind)
	}
	st, body, _ = e.do("GET", "/v1/b/"+h+"/info", utok, nil)
	if st != 200 || !strings.HasPrefix(body, fmt.Sprintf("wasm size=%d ", len(big))) || !strings.Contains(body, " pinned_by=admin ") || !strings.Contains(body, " exp=never") {
		t.Fatalf("info: %d %s", st, body)
	}
	if st, body, _ := e.do("GET", "/v1/pins", "", nil); st != 200 || !strings.Contains(body, fmt.Sprintf("%s cx-big@1.0 %d", h, len(big))) {
		t.Fatalf("pins: %d %s", st, body)
	}
	if st, body, hd := e.do("HEAD", "/v1/b/"+h, utok, nil); st != 200 || body != "" || hd.Get("Content-Length") != fmt.Sprint(len(big)) {
		t.Fatalf("pinned module readable by any token: %d %v", st, hd)
	}
	// Above 4 MiB runs only because it is pinned.
	in := e.put(utok, []byte("in "+uid))
	if st, body, _ := e.do("POST", "/v1/j", utok, map[string]any{"wasm": h, "in": in, "ms": 1000}); st != 200 && st != 202 {
		t.Fatalf("submit pinned module: %d %s", st, body)
	}
	// The same body on the public route is refused by the 16 MiB cap.
	if st, body, _ := e.do("POST", "/v1/b", utok, big); st != 413 || body != "err size body too large" {
		t.Fatalf("public upload of 40 MiB: %d %s", st, body)
	}
	// Re-uploading a known hash is a touch that keeps the pin; a plain re-upload answers without a pin line.
	if st, body := e.adminDo("PUT", "/admin/blob", small); st != 200 || !strings.HasPrefix(body, "ok blob "+sha(small)+" ") || strings.Contains(body, " pin=") {
		t.Fatalf("plain admin upload: %d %s", st, body)
	}
	t.Cleanup(func() {
		testPool.Exec(ctx, `DELETE FROM blobs WHERE hash = $1`, sha(small))
		testPool.Exec(ctx, `DELETE FROM blob_meta WHERE hash = $1`, sha(small))
	})
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM admin_log WHERE action = 'PUT /admin/blob' AND arg = $1`, h).Scan(&n)
	if n != 1 {
		t.Fatalf("admin_log rows naming the hash: %d", n)
	}
}

func TestRevokedTxtRoute(t *testing.T) {
	e := newAttEnv(t)
	RevokedListFn = nil
	st, body, hd := e.do("GET", "/att/revoked.txt", "", nil)
	if st != 200 || body != revokedHeader || hd.Get("Content-Type") != "text/plain; charset=utf-8" || hd.Get("ETag") == "" || !strings.HasPrefix(hd.Get("Cache-Control"), "public") {
		t.Fatalf("empty list: %d %q %v", st, body, hd)
	}
	etag := hd.Get("ETag")
	if st, _, _ := e.do("GET", "/att/revoked.txt", "", nil, "If-None-Match", etag); st != 304 {
		t.Fatalf("304: %d", st)
	}
	if st, body, _ := e.do("HEAD", "/att/revoked.txt", "", nil); st != 200 || body != "" {
		t.Fatalf("head: %d %q", st, body)
	}
	if st, _, hd := e.do("GET", "/att/revoked.txt", adminTok, nil); st != 200 || hd.Get("Cache-Control") != "private, no-store" {
		t.Fatalf("token read: %d %v", st, hd)
	}
	RevokedListFn = func(context.Context, core.Q) ([]string, error) {
		return []string{"att1 j=jaaaaaa w=" + strings.Repeat("1", 64) + " reason=audit-mismatch", "  tabbed\there\nnew line ", ""}, nil
	}
	t.Cleanup(func() { RevokedListFn = nil })
	st, body, _ = e.do("GET", "/att/revoked.txt", "", nil)
	want := revokedHeader + "\natt1 j=jaaaaaa w=" + strings.Repeat("1", 64) + " reason=audit-mismatch\ntabbed here new line"
	if st != 200 || body != want {
		t.Fatalf("list: %d %q", st, body)
	}
	RevokedListFn = func(context.Context, core.Q) ([]string, error) { return nil, errors.New("boom") }
	if st, body, _ := e.do("GET", "/att/revoked.txt", "", nil); st != 500 || !strings.HasPrefix(body, "err internal") {
		t.Fatalf("list error: %d %s", st, body)
	}
	if st, _, _ := e.do("GET", "/att/revoked", "", nil); st != 404 {
		t.Fatalf("unsuffixed: %d", st)
	}
}
