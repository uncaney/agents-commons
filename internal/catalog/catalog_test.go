package catalog

// Acceptance tests of P33-catalog-core (SPEC-v2 15.1-15.3, 27.6). They drive the real HTTP
// surface: identities register through the PoW challenge, modules are uploaded as blobs, KATs
// and calls run through compute's lease/done protocol with two donor roots in distinct networks,
// and the janitor's verify step flips states. The seed tests run the built wasm modules in the
// sandbox when testdata/wasm/out/seed exists (sh testdata/wasm/build.sh).

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/sandbox"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
)

const (
	adminTok = "cx-admin-test"
	seedDir  = "../../testdata/wasm/out/seed"
	ghpKey   = "ghp_Ab9Cd8Ef7Gh6Ij5Kl4Mn3Op2Qr1St0Uv9Wx8Y" // tier-1 kind key
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
		if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("catalog", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping catalog DB tests")
		os.Exit(0)
	}
	testPool.Exec(ctx, cancelSQL(` AND created < now() - interval '5 minutes'`), []string(nil))
	testPool.Exec(ctx, `DELETE FROM flags WHERE k IN ('freeze:blobs', 'freeze:blobs_opaque')`)
	core.LevelFn = trust.LevelOf
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// --- fixtures -----------------------------------------------------------------------------------

func uleb(n int) []byte {
	var out []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, c|0x80)
			continue
		}
		return append(out, c)
	}
}

func customSection(name, payload string) []byte {
	body := append(uleb(len(name)), name...)
	body = append(body, payload...)
	out := append([]byte{0}, uleb(len(body))...)
	return append(out, body...)
}

// minWasm is a valid module exporting an empty _start; tag makes each hash distinct.
func minWasm(tag string) []byte {
	b := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0,
		3, 2, 1, 0,
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0,
		10, 4, 1, 2, 0, 0x0b}
	return append(b, customSection("t", tag)...)
}

// wasmWithData is minWasm plus a memory page and an active data segment holding data.
func wasmWithData(tag, data string) []byte {
	b := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0,
		3, 2, 1, 0,
		5, 3, 1, 0, 1,
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0,
		10, 4, 1, 2, 0, 0x0b}
	seg := append([]byte{0, 0x41, 0, 0x0b}, uleb(len(data))...)
	seg = append(seg, data...)
	body := append([]byte{1}, seg...)
	b = append(b, 11)
	b = append(b, uleb(len(body))...)
	b = append(b, body...)
	return append(b, customSection("t", tag)...)
}

func bigWasm(tag string) []byte {
	return append(minWasm(tag), customSection("pad", strings.Repeat("x", unpinnedWasm))...)
}

func buildZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(files[n]))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func cancelSQL(extra string) string {
	return `WITH j AS (UPDATE jobs SET status = 'failed', reason = 'test-cleanup', finished_at = now()
		WHERE status IN ('queued','running') AND ($1::text[] IS NULL OR root = ANY($1))` + extra + ` RETURNING id)
		DELETE FROM replicas WHERE job IN (SELECT id FROM j) AND state <> 'reported'`
}

// kat is one manifest test: inline input and the sha256 of the expected stdout.
func kat(in, out string) map[string]any {
	return map[string]any{"in_text": in, "out_sha256": sha([]byte(out))}
}

func manifest(tests []map[string]any, extra map[string]any) map[string]any {
	m := map[string]any{"desc": "test tool", "usage": "send text", "abi": "text", "in": "text", "out": "text", "ms_hint": 2000, "mb_hint": 32, "tests": tests}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// --- env ----------------------------------------------------------------------------------------

type env struct {
	t     *testing.T
	d     *core.Deps
	s     *svc
	srv   *httptest.Server
	roots []string
	names []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true, RegPerHour: 1 << 20,
		AdminToken: adminTok, PublicURL: "https://t.example", AdminBlobMax: 64 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAdminV2(mux, d)
	compute.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	e := &env{t: t, d: d, s: &svc{d}, srv: srv}
	t.Cleanup(func() {
		srv.Close()
		ctx := context.Background()
		testPool.Exec(ctx, cancelSQL(""), append(e.roots, core.SystemID))
		if len(e.names) > 0 {
			testPool.Exec(ctx, `DELETE FROM services WHERE name = ANY($1)`, e.names)
			testPool.Exec(ctx, `DELETE FROM pins WHERE name = ANY($1)`, e.names)
		}
		testPool.Exec(ctx, `DELETE FROM service_pin_requests WHERE root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `UPDATE blobs SET pinned_by = '' WHERE owner_root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM blob_meta WHERE banned = '' AND hash IN (SELECT hash FROM blobs WHERE owner_root = ANY($1))`, e.roots)
		testPool.Exec(ctx, `DELETE FROM blobs WHERE owner_root = ANY($1)`, e.roots)
		d.Close()
	})
	return e
}

var ipSeq = func() *uint32 {
	var b [4]byte
	rand.Read(b[:])
	n := uint32(b[0])<<8 | uint32(b[1])
	return &n
}()

// randIP returns an address in a /24 no earlier call of this run used (distinct super-groups).
func randIP() string {
	var b [1]byte
	rand.Read(b[:])
	n := atomic.AddUint32(ipSeq, 1)
	return fmt.Sprintf("10.%d.%d.%d", (n>>8)&0xff, n&0xff, 1+int(b[0])%250)
}

func (e *env) do(method, path, token string, body any, hdr ...string) (int, string, http.Header) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", randIP())
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

func (e *env) register(name string) (id, tok string) {
	e.t.Helper()
	return e.registerIP(name, randIP())
}

func (e *env) registerIP(name, ip string) (id, tok string) {
	e.t.Helper()
	_, body, _ := e.do("POST", "/v1/challenge", "", nil, "CF-Connecting-IP", ip)
	c := strings.TrimPrefix(strings.Fields(body)[0], "c=")
	st, body, _ := e.do("POST", "/v1/register", "", map[string]string{"c": c, "nonce": pow.Solve(c, 6), "name": name}, "CF-Connecting-IP", ip)
	if st != 201 {
		e.t.Fatalf("register: %d %s", st, body)
	}
	for _, f := range strings.Fields(body) {
		if v, ok := strings.CutPrefix(f, "id="); ok {
			id = v
		} else if v, ok := strings.CutPrefix(f, "token="); ok {
			tok = v
		}
	}
	e.roots = append(e.roots, id)
	return id, tok
}

// l1 makes root an L1 publisher (24 h old with rep 1); l2 an established root.
func (e *env) l1(root string) {
	e.t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET rep = 1, created = now() - interval '2 days' WHERE id = $1`, root); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) l2(root string) {
	e.t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE identities SET rep = 5, created = now() - interval '4 days', verified_noncompute = 1 WHERE id = $1`, root); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) ident(tok string) *core.Ident {
	e.t.Helper()
	id, err := e.d.LookupToken(context.Background(), tok)
	if err != nil {
		e.t.Fatal(err)
	}
	return id
}

func firstField(body string) string {
	if f := strings.Fields(strings.SplitN(body, "\n", 2)[0]); len(f) > 0 {
		return f[0]
	}
	return ""
}

func (e *env) put(tok string, data []byte) string {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/b", tok, data)
	if st != 200 || firstField(body) != sha(data) {
		e.t.Fatalf("put: %d %s", st, body)
	}
	return firstField(body)
}

// publish posts a service version; the name is remembered for cleanup.
func (e *env) publish(tok, name, wasm string, m map[string]any) (int, string) {
	e.t.Helper()
	e.names = append(e.names, name)
	st, body, _ := e.do("POST", "/v1/svc", tok, map[string]any{"name": name, "wasm": wasm, "manifest": m})
	return st, body
}

func (e *env) mustPublish(tok, name, wasm string, m map[string]any) {
	e.t.Helper()
	if st, body := e.publish(tok, name, wasm, m); st != 201 || !strings.HasPrefix(body, "ok "+name+"@") {
		e.t.Fatalf("publish %s: %d %s", name, st, body)
	}
}

func (e *env) fundSystem() {
	e.t.Helper()
	if st, body, _ := e.do("POST", "/admin/credits", adminTok, map[string]any{"id": core.SystemID, "n": 5000}); st != 200 {
		e.t.Fatalf("fund system: %d %s", st, body)
	}
}

type leaseOut struct {
	Lease, Job, Wasm, In, FS, Kind string
	Ms, Mb                         int
}

func (e *env) lease(tok string) *leaseOut {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/w/lease", tok, map[string]int{"max_ms": 30000, "max_mb": 256})
	if st == 204 {
		return nil
	}
	if st != 200 {
		e.t.Fatalf("lease: %d %s", st, body)
	}
	var l leaseOut
	if err := json.Unmarshal([]byte(body), &l); err != nil || l.Lease == "" {
		e.t.Fatalf("lease body: %s", body)
	}
	return &l
}

func (e *env) done(tok, lease, out string, ms int) {
	e.t.Helper()
	st, body, _ := e.do("POST", "/v1/w/done", tok, map[string]any{"lease": lease, "status": "ok", "out": out, "code": 0, "ms": ms})
	if st != 200 || body != `{"ok":true}` {
		e.t.Fatalf("done: %d %s", st, body)
	}
}

// work makes every worker lease and report until nothing is eligible; outFn maps a lease to the
// stdout the (simulated) module produces. Returns the number of reports.
func (e *env) work(wtoks []string, outFn func(l *leaseOut) []byte) int {
	e.t.Helper()
	n := 0
	for i := 0; i < 50; i++ {
		progressed := false
		for _, tok := range wtoks {
			l := e.lease(tok)
			if l == nil {
				continue
			}
			progressed = true
			out := e.put(tok, outFn(l))
			e.done(tok, l.Lease, out, l.Ms/2)
			n++
		}
		if !progressed {
			break
		}
	}
	return n
}

// constOut is an outFn producing the same bytes for every job.
func constOut(s string) func(*leaseOut) []byte { return func(*leaseOut) []byte { return []byte(s) } }

// byInput is an outFn mapping the input blob hash (sha256 of the in_text) to an output.
func byInput(m map[string]string) func(*leaseOut) []byte {
	return func(l *leaseOut) []byte {
		if out, ok := m[l.In]; ok {
			return []byte(out)
		}
		return []byte("unexpected input")
	}
}

func (e *env) workers(n int) []string {
	e.t.Helper()
	var toks []string
	for i := 0; i < n; i++ {
		_, tok := e.register(fmt.Sprintf("w%d", i))
		toks = append(toks, tok)
	}
	return toks
}

func (e *env) verify() {
	e.t.Helper()
	if err := e.s.verify(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) version(name string, ver int) *Version {
	e.t.Helper()
	v, err := loadVersion(context.Background(), testPool, name, ver)
	if err != nil || v == nil {
		e.t.Fatalf("version %s@%d: %v", name, ver, err)
	}
	return v
}

// verified publishes name with the given tests and runs them through two distinct donors.
func (e *env) verified(tok, name, wasm string, tests []map[string]any, outs map[string]string, extra map[string]any) []string {
	e.t.Helper()
	e.mustPublish(tok, name, wasm, manifest(tests, extra))
	w := e.workers(2)
	if n := e.work(w, byInput(outs)); n != 2*len(tests) {
		e.t.Fatalf("expected %d reports, got %d", 2*len(tests), n)
	}
	e.verify()
	if v := e.version(name, 1); v.State != "verified" {
		e.t.Fatalf("state %s (%s)", v.State, v.Tested)
	}
	return w
}

func (e *env) credits(id string) (credits, earned int64) {
	e.t.Helper()
	if err := testPool.QueryRow(context.Background(), `SELECT credits, earned FROM identities WHERE id = $1`, id).Scan(&credits, &earned); err != nil {
		e.t.Fatal(err)
	}
	return
}

func (e *env) backdate(name string, ver int, d string) {
	e.t.Helper()
	if _, err := testPool.Exec(context.Background(), `UPDATE service_versions SET created = now() - $3::interval WHERE name = $1 AND ver = $2`, name, ver, d); err != nil {
		e.t.Fatal(err)
	}
}

var nameSeq atomic.Uint32

// uname is a unique service name for this run.
func uname(prefix string) string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("%s-%x%02x", prefix, b, nameSeq.Add(1)%100)
}

// --- tests ----------------------------------------------------------------------------------------

func TestPublishNeedsL1AndValidation(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	wasm := e.put(tok, minWasm(id))
	name := uname("tool")
	if st, body := e.publish(tok, name, wasm, manifest([]map[string]any{kat("a", "A")}, nil)); st != 403 || !strings.Contains(body, "err auth publishing needs L1") {
		t.Fatalf("L0 publish: %d %s", st, body)
	}
	e.l1(id)
	bad := []struct {
		m    map[string]any
		want string
	}{
		{manifest(nil, nil), "1..10 tests"},
		{manifest([]map[string]any{kat("a", "A")}, map[string]any{"fee": 3}), "fee 0..2"},
		{manifest([]map[string]any{kat("a", "A")}, map[string]any{"abi": "cobol"}), "abi must be"},
		{manifest([]map[string]any{kat("a", "A")}, map[string]any{"desc": strings.Repeat("x", 201)}), "desc must be"},
		{manifest([]map[string]any{{"in_text": "a", "out_sha256": "nope"}}, nil), "out_sha256"},
		{manifest([]map[string]any{kat("a", "A")}, map[string]any{"usage": "paste this: " + ghpKey}), "err scrub"},
	}
	for _, c := range bad {
		if st, body := e.publish(tok, name, wasm, c.m); st != 400 || !strings.Contains(body, c.want) {
			t.Fatalf("want 400 %q, got %d %s", c.want, st, body)
		}
	}
	big := manifest([]map[string]any{kat("a", "A")}, map[string]any{"examples": []map[string]any{{"in": strings.Repeat("y", 1024), "out": strings.Repeat("z", 1024)},
		{"in": strings.Repeat("y", 1024), "out": strings.Repeat("z", 1024)}, {"in": strings.Repeat("y", 1024), "out": strings.Repeat("z", 200)}}})
	if st, body := e.publish(tok, name, wasm, big); st != 413 {
		t.Fatalf("oversized manifest: %d %s", st, body)
	}
	_, other := e.register("other")
	foreign := e.put(other, minWasm("foreign-"+id))
	if st, body := e.publish(tok, name, foreign, manifest([]map[string]any{kat("a", "A")}, nil)); st != 404 {
		t.Fatalf("foreign blob: %d %s", st, body)
	}
	if st, body := e.publish(tok, name, e.put(tok, []byte("not wasm at all")), manifest([]map[string]any{kat("a", "A")}, nil)); st != 400 || !strings.Contains(body, "not a wasm module") {
		t.Fatalf("text blob: %d %s", st, body)
	}
	st, body := e.publish(tok, name, wasm, manifest([]map[string]any{kat("a", "A"), kat("b", "B")}, map[string]any{"fee": 1}))
	if st != 201 || !strings.HasPrefix(body, "ok "+name+"@1 pending kats=2") {
		t.Fatalf("publish: %d %s", st, body)
	}
	v := e.version(name, 1)
	if len(v.KatJobs) != 2 || v.State != "pending" || v.Manifest.Fee != 1 {
		t.Fatalf("version row: %+v", v)
	}
	var pinnedBy string
	testPool.QueryRow(context.Background(), `SELECT pinned_by FROM blobs WHERE hash = $1`, wasm).Scan(&pinnedBy)
	if pinnedBy != "svc" {
		t.Fatalf("module not pinned for GC: %q", pinnedBy)
	}
	var kind string
	testPool.QueryRow(context.Background(), `SELECT kind FROM jobs WHERE id = $1`, v.KatJobs[0]).Scan(&kind)
	if kind != "kat" {
		t.Fatalf("kat job kind %q", kind)
	}
	if st, body := e.publish(tok, name, wasm, manifest([]map[string]any{kat("a", "A")}, nil)); st != 409 || !strings.Contains(body, "err dup") {
		t.Fatalf("same module twice: %d %s", st, body)
	}
	if st, body := e.publish(other, name, foreign, manifest([]map[string]any{kat("a", "A")}, nil)); st != 403 {
		t.Fatalf("other L0 on taken name: %d %s", st, body)
	}
	e.l1(e.ident(other).Root)
	if st, body := e.publish(other, name, foreign, manifest([]map[string]any{kat("a", "A")}, nil)); st != 409 || !strings.Contains(body, "err taken") {
		t.Fatalf("taken name: %d %s", st, body)
	}
}

func TestNameGuardReservedLevenshtein(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	m := manifest([]map[string]any{kat("a", "A")}, nil)
	for _, n := range []string{"admin", "adnin", "cx-thing", "cxpy", "cxpi", "cxjs", "cxlua", "claude", "0penai"} {
		if st, body := e.publish(tok, n, wasm, m); st != 400 || !strings.Contains(body, "reserved") {
			t.Fatalf("%s: want reserved, got %d %s", n, st, body)
		}
	}
	for _, n := range []string{"x", "-abc", "Abc", "a_b", strings.Repeat("a", 33)} {
		if st, body := e.publish(tok, n, wasm, m); st != 400 || !strings.Contains(body, "name must match") {
			t.Fatalf("%s: want grammar error, got %d %s", n, st, body)
		}
	}
	name := uname("hello-tool")
	e.mustPublish(tok, name, wasm, m)
	oid, otok := e.register("other")
	e.l1(oid)
	owasm := e.put(otok, minWasm(oid))
	near := name[:len(name)-1] + "q"
	if st, body := e.publish(otok, near, owasm, m); st != 409 || !strings.Contains(body, "too close to "+name) {
		t.Fatalf("near name: %d %s", st, body)
	}
	if st, body := e.publish(otok, name+"x", owasm, m); st != 409 || !strings.Contains(body, "too close") {
		t.Fatalf("name+1: %d %s", st, body)
	}
	if st, body := e.publish(otok, uname("other-tool"), owasm, m); st != 201 {
		t.Fatalf("distinct name: %d %s", st, body)
	}
	if !lev1("abc", "abd") || !lev1("abc", "ab") || lev1("abc", "xyz") || lev1("abc", "abcde") {
		t.Fatal("lev1")
	}
}

func TestKATVerifyFlipsVerified(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("kat")
	tests := []map[string]any{kat("one", "ONE\n"), kat("two", "TWO\n")}
	outs := map[string]string{sha([]byte("one")): "ONE\n", sha([]byte("two")): "TWO\n"}
	e.mustPublish(tok, name, wasm, manifest(tests, nil))
	e.verify()
	if v := e.version(name, 1); v.State != "pending" {
		t.Fatalf("before donors: %s", v.State)
	}
	w := e.workers(2)
	if n := e.work(w, byInput(outs)); n != 4 {
		t.Fatalf("reports %d", n)
	}
	e.verify()
	v := e.version(name, 1)
	if v.State != "verified" || v.VerifiedAt == nil || v.Tested != "2/2 tests passed" {
		t.Fatalf("after donors: %s %s", v.State, v.Tested)
	}
	var attD bool
	testPool.QueryRow(context.Background(), `SELECT att_d FROM jobs WHERE id = $1`, v.KatJobs[0]).Scan(&attD)
	if !attD {
		t.Fatal("KAT replication not distinct")
	}
	var n int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE kind = 'svc' AND ref = $1 AND title LIKE '%verified'`, name+"@1").Scan(&n)
	if n != 1 {
		t.Fatalf("verified event %d", n)
	}
	st, body, _ := e.do("GET", "/v1/svc/"+name, "", nil)
	if st != 200 || !strings.Contains(body, "[verified]") || !strings.Contains(body, "call: POST /v1/svc/"+name) {
		t.Fatalf("get: %d %s", st, body)
	}
	st, body, _ = e.do("GET", "/v1/svc?q="+name[:8], "", nil)
	if st != 200 || !strings.Contains(body, name+"@1 "+wasm[:12]+" ok0 7d=0 fail=0% [verified] test tool") {
		t.Fatalf("list: %d %s", st, body)
	}
}

func TestUnderReplicatedStaysPending(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("half")
	e.mustPublish(tok, name, wasm, manifest([]map[string]any{kat("a", "A")}, nil))
	w := e.workers(1)
	if n := e.work(w, constOut("A")); n != 1 {
		t.Fatalf("reports %d", n)
	}
	e.verify()
	v := e.version(name, 1)
	if v.State != "pending" || v.KatRetries != 0 || !strings.HasPrefix(v.Tested, "0/1") {
		t.Fatalf("one replica reported: %s %s retries=%d", v.State, v.Tested, v.KatRetries)
	}
	// Two donors in the same /24 agree but are not distinct (d=0): the KAT is re-queued, never
	// counted as verified.
	ip := randIP()
	_, a := e.registerIP("same-a", ip)
	_, b := e.registerIP("same-b", ip[:strings.LastIndex(ip, ".")]+".77")
	name2 := uname("nodist")
	e.mustPublish(tok, name2, e.put(tok, minWasm(id+"2")), manifest([]map[string]any{kat("a", "A")}, nil))
	e.work([]string{a, b}, constOut("A"))
	e.verify()
	v = e.version(name2, 1)
	if v.State != "pending" || v.KatRetries != 1 {
		t.Fatalf("d=0: %s retries=%d (%s)", v.State, v.KatRetries, v.Tested)
	}
}

func TestWrongHashRejected(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("wrong")
	e.mustPublish(tok, name, wasm, manifest([]map[string]any{kat("a", "A")}, nil))
	e.work(e.workers(2), constOut("B"))
	e.verify()
	v := e.version(name, 1)
	if v.State != "rejected" || !strings.Contains(v.Tested, "differs from declared") {
		t.Fatalf("%s %s", v.State, v.Tested)
	}
	var pinnedBy string
	testPool.QueryRow(context.Background(), `SELECT pinned_by FROM blobs WHERE hash = $1`, wasm).Scan(&pinnedBy)
	if pinnedBy != "" {
		t.Fatalf("rejected module still pinned: %q", pinnedBy)
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"@1", tok, map[string]any{"in_text": "x"}); st != 410 || !strings.Contains(body, "err gone") {
		t.Fatalf("call rejected: %d %s", st, body)
	}
	if st, body, _ := e.do("GET", "/v1/svc?q="+name[:8], "", nil); st != 200 || strings.Contains(body, name) {
		t.Fatalf("rejected listed: %d %s", st, body)
	}
}

func TestAdminPublishReservedName(t *testing.T) {
	e := newEnv(t)
	e.fundSystem()
	_, tok := e.register("up")
	wasm := e.put(tok, minWasm("admin-"+uname("x")))
	e.names = append(e.names, "cxjs", "cx-demo")
	st, body, _ := e.do("POST", "/admin/svc", adminTok, map[string]any{"name": "cxjs", "ver": 1, "wasm": wasm, "manifest": manifest([]map[string]any{kat("1+1", "2\n")}, map[string]any{"fs_override": true, "mb_hint": 32})})
	if st != 201 || !strings.HasPrefix(body, "ok cxjs@1 pending kats=1") {
		t.Fatalf("admin publish: %d %s", st, body)
	}
	var owner string
	var stable int
	testPool.QueryRow(context.Background(), `SELECT owner_root, stable_ver FROM services WHERE name = 'cxjs'`).Scan(&owner, &stable)
	if owner != core.SystemID || stable != 1 {
		t.Fatalf("owner=%s stable=%d", owner, stable)
	}
	var root, kind string
	testPool.QueryRow(context.Background(), `SELECT root, kind FROM jobs WHERE svc = 'cxjs@1' LIMIT 1`).Scan(&root, &kind)
	if root != core.SystemID || kind != "kat" {
		t.Fatalf("kat job root=%s kind=%s", root, kind)
	}
	if st, body, _ := e.do("POST", "/admin/svc", "", map[string]any{"name": "cx-demo", "wasm": wasm, "manifest": manifest([]map[string]any{kat("a", "A")}, nil)}); st != 401 {
		t.Fatalf("no admin token: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/admin/svc", adminTok, map[string]any{"name": "cx-demo", "wasm": e.put(tok, minWasm("demo-"+uname("y"))), "manifest": manifest([]map[string]any{kat("a", "A")}, nil)}); st != 201 {
		t.Fatalf("cx- prefix for admin: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/run", tok, map[string]any{"svc": "cxjs", "code": "1+1"}); st != 202 && st != 200 {
		t.Fatalf("js through published interpreter: %d %s", st, body)
	}
}

func TestCallByNameAndStable(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("echo")
	w := e.verified(tok, name, wasm, []map[string]any{kat("a", "A\n")}, map[string]string{sha([]byte("a")): "A\n"}, nil)
	_, caller := e.register("caller")
	if st, body, _ := e.do("POST", "/v1/svc/"+name, caller, map[string]any{"in_text": "hello"}); st != 404 || !strings.Contains(body, "no stable version of "+name) {
		t.Fatalf("no stable yet: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"/stable", tok, map[string]any{"ver": 1}); st != 409 {
		t.Fatalf("fresh version stable: %d %s", st, body)
	}
	e.backdate(name, 1, "25 hours")
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"/stable", tok, map[string]any{"ver": 1}); st != 200 || body != "ok "+name+" stable=1\nnext: GET /v1/svc/"+name+" | GET /svc/"+name {
		t.Fatalf("stable: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"/stable", caller, map[string]any{"ver": 1}); st != 403 {
		t.Fatalf("non-owner stable: %d %s", st, body)
	}
	st, body, _ := e.do("POST", "/v1/svc/"+name, caller, map[string]any{"in_text": "hello"})
	if st != 202 || !strings.HasSuffix(firstField(body), "") || firstField(body)[0] != 'j' || !strings.Contains(body, "queued") {
		t.Fatalf("call: %d %s", st, body)
	}
	jid := firstField(body)
	var svcCol string
	testPool.QueryRow(context.Background(), `SELECT svc FROM jobs WHERE id = $1`, jid).Scan(&svcCol)
	if svcCol != name+"@1" {
		t.Fatalf("jobs.svc = %q", svcCol)
	}
	if n := e.work(w, constOut("HELLO\n")); n != 2 {
		t.Fatalf("reports %d", n)
	}
	st, body, _ = e.do("POST", "/v1/svc/"+name, caller, map[string]any{"in_text": "hello"})
	head := strings.SplitN(body, "\n", 2)[0]
	if st != 200 || !strings.HasPrefix(head, "done ms=0 out="+sha([]byte("HELLO\n"))+" cached pinned="+wasm[:12]+" job=j") {
		t.Fatalf("cached call: %d %s", st, body)
	}
	if !strings.Contains(body, "\n  HELLO\n") {
		t.Fatalf("inline output not indented: %q", body)
	}
	st, body, _ = e.do("POST", "/v1/svc/"+name+"@1", caller, map[string]any{"in_text": "hello"})
	if st != 200 || strings.Contains(body, "pinned=") {
		t.Fatalf("explicit version prints pinned: %d %s", st, body)
	}
	st, body, _ = e.do("POST", "/v1/svc/"+name+"@1?f=json", caller, map[string]any{"in_text": "hello"})
	var j map[string]any
	if json.Unmarshal([]byte(body), &j) != nil || j["out_text"] != "HELLO\n" || j["status"] != "done" {
		t.Fatalf("json call: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+uname("nothere"), caller, map[string]any{"in_text": "x"}); st != 404 || !strings.Contains(body, "err notfound service") {
		t.Fatalf("unknown: %d %s", st, body)
	}
	var calls, other int64
	testPool.QueryRow(context.Background(), `SELECT calls, other_calls FROM services WHERE name = $1`, name).Scan(&calls, &other)
	if calls != 4 || other != 4 {
		t.Fatalf("calls=%d other=%d", calls, other)
	}
	v, err := Stable(context.Background(), testPool, name)
	if err != nil || v.Ver != 1 {
		t.Fatalf("Stable: %v", err)
	}
	if _, err := Resolve(context.Background(), testPool, name+"@9"); err == nil {
		t.Fatal("Resolve of a missing version")
	}
}

func TestFeeEarnedOnlyDistinctRoot(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("fee")
	w := e.verified(tok, name, wasm, []map[string]any{kat("a", "A")}, map[string]string{sha([]byte("a")): "A"}, map[string]any{"fee": 2})
	cid, caller := e.register("caller")
	c0, _ := e.credits(cid)
	_, e0 := e.credits(id)
	// Earlier tests' cancelled fixtures leave a constant ledger delta; the held fee must not move it.
	rep0, err := core.LedgerAudit(context.Background(), testPool, e.d.EscrowSQL())
	if err != nil {
		t.Fatal(err)
	}
	st, body, _ := e.do("POST", "/v1/svc/"+name+"@1", caller, map[string]any{"in_text": "paid"})
	if st != 202 {
		t.Fatalf("call: %d %s", st, body)
	}
	jid := firstField(body)
	var fee int
	var settled bool
	testPool.QueryRow(context.Background(), `SELECT fee, settled FROM service_calls WHERE job = $1`, jid).Scan(&fee, &settled)
	if fee != 2 || settled {
		t.Fatalf("calls row fee=%d settled=%t", fee, settled)
	}
	if c, _ := e.credits(cid); c != c0-6-2 {
		t.Fatalf("caller credits while running: %d want %d", c, c0-8)
	}
	rep, err := core.LedgerAudit(context.Background(), testPool, e.d.EscrowSQL())
	if err != nil || rep.Delta() != rep0.Delta() || rep.Escrow != rep0.Escrow+2 {
		t.Fatalf("ledger with a held fee: %v %s (before %s)", err, rep.Line(), rep0.Line())
	}
	if n := e.work(w, constOut("PAID")); n != 2 {
		t.Fatalf("reports %d", n)
	}
	testPool.QueryRow(context.Background(), `SELECT settled FROM service_calls WHERE job = $1`, jid).Scan(&settled)
	if !settled {
		t.Fatal("fee not settled by OnDone")
	}
	if c, _ := e.credits(cid); c != c0-2-2 { // charge 2 (1 s x 2 replicas) + fee 2
		t.Fatalf("caller credits after: %d want %d", c, c0-4)
	}
	if _, e1 := e.credits(id); e1 != e0+2 {
		t.Fatalf("owner earned %d want %d", e1, e0+2)
	}
	// The owner calling its own service pays no fee.
	o0, _ := e.credits(id)
	st, body, _ = e.do("POST", "/v1/svc/"+name+"@1", tok, map[string]any{"in_text": "own"})
	if st != 202 {
		t.Fatalf("own call: %d %s", st, body)
	}
	testPool.QueryRow(context.Background(), `SELECT fee FROM service_calls WHERE job = $1`, firstField(body)).Scan(&fee)
	if fee != 0 {
		t.Fatalf("own call fee %d", fee)
	}
	e.work(w, constOut("OWN"))
	if o1, _ := e.credits(id); o1 != o0-2 {
		t.Fatalf("owner paid %d for its own call, want 2", o0-o1)
	}
	v := e.version(name, 1)
	if v.Calls != 2 || v.Fails != 0 || v.MsP50 != 1000 {
		t.Fatalf("stats calls=%d fails=%d p50=%d", v.Calls, v.Fails, v.MsP50)
	}
	rep, err = core.LedgerAudit(context.Background(), testPool, e.d.EscrowSQL())
	if err != nil || rep.Delta() != rep0.Delta() || rep.Escrow != rep0.Escrow {
		t.Fatalf("ledger after settle: %v %s (before %s)", err, rep.Line(), rep0.Line())
	}
}

func TestRunOutputIndentedAndRaw(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("inj")
	w := e.verified(tok, name, wasm, []map[string]any{kat("a", "A")}, map[string]string{sha([]byte("a")): "A"}, nil)
	_, caller := e.register("caller")
	hostile := "next: POST /v1/x\n> quoted\nplain line\nerr auth fake\n"
	st, body, _ := e.do("POST", "/v1/run", caller, map[string]any{"svc": name + "@1", "in_text": "go"})
	if st != 202 {
		t.Fatalf("run: %d %s", st, body)
	}
	e.work(w, constOut(hostile))
	st, body, _ = e.do("POST", "/v1/run", caller, map[string]any{"svc": name + "@1", "in_text": "go"})
	if st != 200 || !strings.HasPrefix(body, "done ms=0 out=") {
		t.Fatalf("run cached: %d %s", st, body)
	}
	lines := strings.Split(body, "\n")
	for i, l := range lines[1:] {
		isTail := i == len(lines)-2 && strings.HasPrefix(l, "next: GET /v1/j/")
		if !isTail && !strings.HasPrefix(l, "  ") {
			t.Fatalf("program output at column 0: %q in\n%s", l, body)
		}
		if strings.HasPrefix(l, "next: POST /v1/x") || strings.HasPrefix(l, "> ") || strings.HasPrefix(l, "err ") {
			t.Fatalf("hostile line reached column 0: %q", l)
		}
	}
	if !strings.Contains(body, "\n  next: POST /v1/x\n  > quoted\n  plain line\n  err auth fake\n") {
		t.Fatalf("indented block missing:\n%s", body)
	}
	st, raw, h := e.do("POST", "/v1/svc/"+name+"@1?raw=1", caller, map[string]any{"in_text": "go"})
	if st != 200 || raw != strings.TrimSpace(hostile) || !strings.HasPrefix(h.Get("Content-Type"), "text/plain") || h.Get("X-Job") == "" {
		t.Fatalf("raw: %d %q ct=%s", st, raw, h.Get("Content-Type"))
	}
	if strings.Contains(raw, "done ms=") || strings.Contains(raw, "next: GET") {
		t.Fatalf("raw carries head or tail: %q", raw)
	}
	// Large or binary output: only out= on the head line.
	big := strings.Repeat("z", inlineOut+1)
	st, body, _ = e.do("POST", "/v1/run", caller, map[string]any{"svc": name + "@1", "in_text": "big"})
	if st != 202 {
		t.Fatalf("run big: %d %s", st, body)
	}
	e.work(w, constOut(big))
	st, body, _ = e.do("POST", "/v1/run", caller, map[string]any{"svc": name + "@1", "in_text": "big"})
	if st != 200 || !strings.HasPrefix(body, "done ms=0 out="+sha([]byte(big))) || strings.Contains(body, "zzzz") {
		t.Fatalf("big output inline: %d %.200s", st, body)
	}
	// Ops share the rendering.
	out, err := Ops(e.d)["run"](context.Background(), e.ident(caller), json.RawMessage(`{"svc":"`+name+`@1","in_text":"go"}`))
	if err != nil || !strings.Contains(out, "\n  next: POST /v1/x\n") || strings.Contains(out, "\nnext: ") {
		t.Fatalf("op run: %v %q", err, out)
	}
}

func TestInterpretersNotPublishedError(t *testing.T) {
	e := newEnv(t)
	_, tok := e.register("py")
	for _, body := range []map[string]any{{"svc": "cxpy", "code": "print(1)"}, {"svc": "cxlua", "code": "print(1)"}, {"svc": "cxjs", "in_text": "1"}} {
		st, out, _ := e.do("POST", "/v1/run", tok, body)
		if st != 404 || !strings.HasPrefix(out, "err notfound service not published yet (see /svc)") {
			t.Fatalf("%v: %d %s", body, st, out)
		}
	}
	PyHintFn = func() string { return "try star{} (cx-starlark)" }
	defer func() { PyHintFn = nil }()
	id := e.ident(tok)
	for _, op := range []string{"py", "js", "lua"} {
		_, err := Ops(e.d)[op](context.Background(), id, json.RawMessage(`{"code":"print(1)"}`))
		if err == nil || !strings.Contains(err.Error(), "err notfound service not published yet (see /svc)") {
			t.Fatalf("op %s: %v", op, err)
		}
		if op == "py" && !strings.Contains(err.Error(), "try star{}") {
			t.Fatalf("py hint missing: %v", err)
		}
	}
	if _, err := Ops(e.d)["run"](context.Background(), id, json.RawMessage(`{"svc":"cxpy","code":"x","in_text":"y"}`)); err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("code and in_text: %v", err)
	}
	if st, out, _ := e.do("POST", "/v1/run", tok, map[string]any{"svc": "cxpy", "code": strings.Repeat("x", maxCode+1)}); st != 413 {
		t.Fatalf("oversized code: %d %s", st, out)
	}
}

func TestVotesPerHash(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("vote")
	w := e.verified(tok, name, wasm, []map[string]any{kat("a", "A")}, map[string]string{sha([]byte("a")): "A"}, nil)
	_, voter := e.register("voter")
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"@1/ok", voter, map[string]any{"note": "nice"}); st != 403 || !strings.Contains(body, "vote needs a finalised job") {
		t.Fatalf("vote without job: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"@1", voter, map[string]any{"in_text": "x"}); st != 202 {
		t.Fatalf("call: %d %s", st, body)
	}
	e.work(w, constOut("X"))
	st, body, _ := e.do("POST", "/v1/svc/"+name+"@1/ok", voter, map[string]any{"note": "nice"})
	if st != 200 || !strings.HasPrefix(body, "ok "+name+"@1 ok0.25 bad0") {
		t.Fatalf("vote: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"@1/bad", voter, map[string]any{"note": "again"}); st != 409 || !strings.Contains(body, "err dup") {
		t.Fatalf("double vote: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"@1/ok", tok, nil); st != 403 || !strings.Contains(body, "no self vote") {
		t.Fatalf("self vote: %d %s", st, body)
	}
	if v := e.version(name, 1); v.OkW != 0.25 {
		t.Fatalf("ok_w %v", v.OkW)
	}
	// A second version is a new hash and starts at 0; votes stay with the hash they rated.
	e.mustPublish(tok, name, e.put(tok, minWasm(id+"-v2")), manifest([]map[string]any{kat("a", "A")}, nil))
	e.work(w, constOut("A"))
	e.verify()
	if v := e.version(name, 2); v.State != "verified" || v.OkW != 0 {
		t.Fatalf("v2 %s ok_w=%v", v.State, v.OkW)
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"@2/ok", voter, nil); st != 403 {
		t.Fatalf("vote on unrun v2: %d %s", st, body)
	}
	out, err := Ops(e.d)["svbad"](context.Background(), e.ident(voter), json.RawMessage(`{"name":"`+name+`","ver":1}`))
	if err == nil || !strings.Contains(err.Error(), "err dup") {
		t.Fatalf("op svbad dup: %v %q", err, out)
	}
	st, body, _ = e.do("GET", "/v1/svc/"+name+"@1", "", nil)
	if st != 200 || !strings.Contains(body, " ok0.25 ") {
		t.Fatalf("get v1: %d %s", st, body)
	}
}

// writeSeed writes <dir>/<name>.wasm and <dir>/<name>.json.
func writeSeed(t *testing.T, dir, name string, wasm []byte, m map[string]any) {
	t.Helper()
	mj, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, name+".wasm"), wasm, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), mj, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSeedSystemFromDir(t *testing.T) {
	e := newEnv(t)
	e.fundSystem()
	ctx := context.Background()
	dir := t.TempDir()
	name := uname("cx-seed")
	e.names = append(e.names, name, "cx-nomanifest")
	writeSeed(t, dir, name, minWasm(name), manifest([]map[string]any{kat("a", "A"), kat("b", "B"), kat("c", "C")}, map[string]any{"desc": "seed tool"}))
	os.WriteFile(filepath.Join(dir, "cx-nomanifest.wasm"), minWasm("nomanifest"), 0o644)
	os.WriteFile(filepath.Join(dir, "README"), []byte("x"), 0o644)
	n, err := SeedSystem(ctx, e.d, dir)
	if err != nil || n != 1 {
		t.Fatalf("SeedSystem: n=%d err=%v", n, err)
	}
	v := e.version(name, 1)
	if v.OwnerRoot != core.SystemID || v.StableVer != 1 || v.State != "pending" || len(v.KatJobs) != 3 {
		t.Fatalf("seed version: owner=%s stable=%d state=%s kats=%d", v.OwnerRoot, v.StableVer, v.State, len(v.KatJobs))
	}
	var pinnedBy, owner string
	testPool.QueryRow(ctx, `SELECT pinned_by, owner_root FROM blobs WHERE hash = $1`, v.Wasm).Scan(&pinnedBy, &owner)
	if pinnedBy != "seed" || owner != core.SystemID {
		t.Fatalf("blob pinned_by=%s owner=%s", pinnedBy, owner)
	}
	if n, err := SeedSystem(ctx, e.d, dir); err != nil || n != 0 {
		t.Fatalf("second SeedSystem: n=%d err=%v", n, err)
	}
	if n, err := SeedSystem(ctx, e.d, filepath.Join(dir, "missing")); err != nil || n != 0 {
		t.Fatalf("missing dir: n=%d err=%v", n, err)
	}
	st, body, _ := e.do("GET", "/v1/svc?q="+name, "", nil)
	if st != 200 || !strings.Contains(body, name+"@1 ") || !strings.Contains(body, "[pending] seed tool") {
		t.Fatalf("list: %d %s", st, body)
	}
	// A newer module of the same name becomes version 2; stable stays on 1 until moved.
	writeSeed(t, dir, name, minWasm(name+"-2"), manifest([]map[string]any{kat("a", "A")}, nil))
	if n, err := SeedSystem(ctx, e.d, dir); err != nil || n != 1 {
		t.Fatalf("upgrade: n=%d err=%v", n, err)
	}
	if v2 := e.version(name, 2); v2.StableVer != 1 {
		t.Fatalf("stable moved to %d", v2.StableVer)
	}
	if st, body, _ := e.do("GET", "/svc/"+name+".md", "", nil); st != 200 || !strings.Contains(body, "**by**: asystem") || !strings.Contains(body, "operator") {
		t.Fatalf("page: %d %.300s", st, body)
	}
}

func TestSeedPinsLargeModules(t *testing.T) {
	e := newEnv(t)
	e.fundSystem()
	ctx := context.Background()
	dir := t.TempDir()
	name := uname("cx-big")
	e.names = append(e.names, name)
	big := bigWasm(name)
	writeSeed(t, dir, name, big, manifest([]map[string]any{kat("a", "A")}, nil))
	if n, err := SeedSystem(ctx, e.d, dir); err != nil || n != 1 {
		t.Fatalf("SeedSystem: n=%d err=%v", n, err)
	}
	var note, pname, pver string
	var size int64
	if err := testPool.QueryRow(ctx, `SELECT note, name, ver, size FROM pins WHERE hash = $1`, sha(big)).Scan(&note, &pname, &pver, &size); err != nil {
		t.Fatalf("pins row: %v", err)
	}
	if note != "seed" || pname != name || pver != "1" || size != int64(len(big)) {
		t.Fatalf("pin note=%s name=%s ver=%s size=%d", note, pname, pver, size)
	}
	v := e.version(name, 1)
	if len(v.KatJobs) != 1 || v.Size != int64(len(big)) {
		t.Fatalf("big version kats=%d size=%d", len(v.KatJobs), v.Size)
	}
	st, body, _ := e.do("GET", "/v1/pins", "", nil)
	if st != 200 || !strings.Contains(body, sha(big)) {
		t.Fatalf("pins list: %d %s", st, body)
	}
}

func TestPinRequestL2Weekly(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("l1")
	e.l1(id)
	big := e.put(tok, bigWasm(id))
	m := manifest([]map[string]any{kat("a", "A")}, nil)
	if st, body := e.publish(tok, uname("huge"), big, m); st != 429 || !strings.Contains(body, "err quota pin request") {
		t.Fatalf("L1 big module: %d %s", st, body)
	}
	e.l2(id)
	name := uname("huge")
	st, body := e.publish(tok, name, big, m)
	if st != 202 || !strings.HasPrefix(body, "pin requested "+name+" "+big[:12]+" size=") {
		t.Fatalf("L2 big module: %d %s", st, body)
	}
	var n int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = $1`, "pin:"+big).Scan(&n)
	if n != 1 {
		t.Fatalf("inbox event %d", n)
	}
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM services WHERE name = $1`, name).Scan(&n)
	if n != 0 {
		t.Fatal("service created before the pin")
	}
	if st, body := e.publish(tok, name, big, m); st != 429 || !strings.Contains(body, "err quota pin request") {
		t.Fatalf("second request this week: %d %s", st, body)
	}
	// Once the operator pins it, the publish goes through.
	if st, body, _ := e.do("POST", "/admin/pin", adminTok, map[string]any{"hash": big, "name": name, "ver": "1", "note": "test"}); st != 200 {
		t.Fatalf("admin pin: %d %s", st, body)
	}
	if st, body := e.publish(tok, name, big, m); st != 201 {
		t.Fatalf("publish after pin: %d %s", st, body)
	}
}

func TestPagesJSONLDIndexability(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("page")
	e.mustPublish(tok, name, wasm, manifest([]map[string]any{kat("a", "A")}, map[string]any{"desc": "turns a into A", "usage": "send a\nget A",
		"examples": []map[string]any{{"in": "a", "out": "A"}}, "input_schema": map[string]any{"type": "object", "properties": map[string]any{"input": map[string]any{"type": "string"}}}}))
	st, body, h := e.do("GET", "/svc/"+name, "", nil, "Accept", "text/html")
	if st != 200 || !strings.Contains(h.Get("Content-Type"), "text/html") {
		t.Fatalf("html page: %d %s", st, h.Get("Content-Type"))
	}
	for _, want := range []string{`<script type="application/ld+json">`, `"SoftwareApplication"`, `"SoftwareSourceCode"`, `"sha256:` + wasm + `"`, `content="noindex"`, "turns a into A", "example_in: a"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page missing %q:\n%.1500s", want, body)
		}
	}
	if h.Get("X-Robots-Tag") != "noindex" {
		t.Fatalf("X-Robots-Tag %q for an L1 author", h.Get("X-Robots-Tag"))
	}
	if urls, err := e.s.sitemap(context.Background()); err != nil || containsURL(urls, name) {
		t.Fatalf("non-indexable page in sitemap: %v %v", err, urls)
	}
	// An established (L2) owner with a 2 h old verified stable version is indexable.
	e.l2(id)
	e.backdate(name, 1, "2 hours")
	testPool.Exec(context.Background(), `UPDATE service_versions SET state = 'verified', verified_at = now() WHERE name = $1`, name)
	testPool.Exec(context.Background(), `UPDATE services SET stable_ver = 1 WHERE name = $1`, name)
	st, body, h = e.do("GET", "/svc/"+name+".html", "", nil)
	if st != 200 || strings.Contains(body, `content="noindex"`) || h.Get("X-Robots-Tag") != "" {
		t.Fatalf("L2 page still noindex: %d robots=%q", st, h.Get("X-Robots-Tag"))
	}
	if urls, err := e.s.sitemap(context.Background()); err != nil || !containsURL(urls, name) {
		t.Fatalf("indexable page missing from sitemap: %v", err)
	}
	st, body, _ = e.do("GET", "/svc/"+name+".json", "", nil)
	var j map[string]any
	if st != 200 || json.Unmarshal([]byte(body), &j) != nil || j["wasm"] != wasm {
		t.Fatalf("json twin: %d %.300s", st, body)
	}
	if st, body, _ = e.do("GET", "/svc", "", nil, "Accept", "text/html"); st != 200 || !strings.Contains(body, `"CollectionPage"`) || !strings.Contains(body, name) {
		t.Fatalf("list page: %d %.500s", st, body)
	}
	if st, body, _ = e.do("GET", "/svc.md", "", nil); st != 200 || !strings.HasPrefix(body, "# WASM services") || !strings.Contains(body, "svc hits=") || !strings.Contains(body, name+"@1") {
		t.Fatalf("list md: %d %.200s", st, body)
	}
	if s := e.s.llms(context.Background()); strings.Contains(s, name) {
		t.Fatal("unblessed user service in llms-full")
	}
	BlessedFn = func(context.Context) []string { return []string{name} }
	defer func() { BlessedFn = nil }()
	if s := e.s.llms(context.Background()); !strings.Contains(s, name+"@1: turns a into A") {
		t.Fatalf("blessed service missing from llms-full: %q", s)
	}
	typ, title, url, ok := e.d.Resolve(context.Background(), "w:"+name)
	if !ok || typ != "svc" || !strings.HasPrefix(title, name) || !strings.HasSuffix(url, "/svc/"+name) {
		t.Fatalf("resolver: %v %s %s %s", ok, typ, title, url)
	}
}

func containsURL(urls []core.SitemapURL, name string) bool {
	for _, u := range urls {
		if strings.HasSuffix(u.Loc, "/svc/"+name) {
			return true
		}
	}
	return false
}

func TestManifestFsAndSchema(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	zipHash := e.put(tok, buildZip(t, map[string]string{"lib/a.txt": "hello"}))
	textHash := e.put(tok, []byte("plain text, not a zip"))
	base := []map[string]any{kat("a", "A")}
	if st, body := e.publish(tok, uname("fs"), wasm, manifest(base, map[string]any{"fs": textHash})); st != 400 || !strings.Contains(body, "fs must be a zip blob") {
		t.Fatalf("text fs: %d %s", st, body)
	}
	if st, body := e.publish(tok, uname("fs"), wasm, manifest(base, map[string]any{"input_schema": map[string]any{"type": "string"}})); st != 400 || !strings.Contains(body, `type must be "object"`) {
		t.Fatalf("bad schema: %d %s", st, body)
	}
	if st, body := e.publish(tok, uname("fs"), wasm, manifest(base, map[string]any{"input_schema": map[string]any{"type": "object", "required": []string{"zz"}, "properties": map[string]any{"a": map[string]any{}}}})); st != 400 || !strings.Contains(body, "required name zz") {
		t.Fatalf("required not in properties: %d %s", st, body)
	}
	name := uname("fs")
	e.mustPublish(tok, name, wasm, manifest(base, map[string]any{"fs": zipHash, "input_schema": map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "string"}}}, "get_ok": false}))
	v := e.version(name, 1)
	if v.FS != zipHash || v.Manifest.GetOKValue() || !strings.Contains(string(v.Manifest.InputSchema), `"q"`) {
		t.Fatalf("stored manifest: fs=%s get_ok=%t schema=%s", v.FS, v.Manifest.GetOKValue(), v.Manifest.InputSchema)
	}
	var fs string
	testPool.QueryRow(context.Background(), `SELECT fs FROM jobs WHERE id = $1`, v.KatJobs[0]).Scan(&fs)
	if fs != zipHash {
		t.Fatalf("KAT job fs %q", fs)
	}
	var pinnedBy string
	testPool.QueryRow(context.Background(), `SELECT pinned_by FROM blobs WHERE hash = $1`, zipHash).Scan(&pinnedBy)
	if pinnedBy != "svc" {
		t.Fatalf("fs blob pinned_by %q", pinnedBy)
	}
	_, caller := e.register("caller")
	other := e.put(caller, buildZip(t, map[string]string{"lib/b.txt": "other"}))
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"@1", caller, map[string]any{"in_text": "x", "fs": other}); st != 400 || !strings.Contains(body, "does not allow an fs override") {
		t.Fatalf("override refused: %d %s", st, body)
	}
	name2 := uname("fso")
	e.mustPublish(tok, name2, e.put(tok, minWasm(id+"-fso")), manifest(base, map[string]any{"fs_override": true}))
	st, body, _ := e.do("POST", "/v1/svc/"+name2+"@1", caller, map[string]any{"in_text": "x", "fs": other})
	if st != 202 {
		t.Fatalf("override allowed: %d %s", st, body)
	}
	testPool.QueryRow(context.Background(), `SELECT fs FROM jobs WHERE id = $1`, firstField(body)).Scan(&fs)
	if fs != other {
		t.Fatalf("call job fs %q", fs)
	}
	st, body, _ = e.do("GET", "/v1/svc/"+name, "", nil)
	if st != 200 || !strings.Contains(body, "get_ok=false fs_override=false") || !strings.Contains(body, "input_schema: {") || !strings.Contains(body, "fs: "+zipHash) {
		t.Fatalf("get: %d %s", st, body)
	}
}

func TestStablePointerRule(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("stab")
	e.mustPublish(tok, name, wasm, manifest([]map[string]any{kat("a", "A")}, nil))
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"/stable", tok, map[string]any{"ver": 1}); st != 409 || !strings.Contains(body, "stable needs a verified version") {
		t.Fatalf("pending version: %d %s", st, body)
	}
	e.work(e.workers(2), constOut("A"))
	e.verify()
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"/stable", tok, map[string]any{"ver": 1}); st != 409 || !strings.Contains(body, "must be 24 h old or called by 3 other roots") {
		t.Fatalf("fresh verified: %d %s", st, body)
	}
	for i := 0; i < 2; i++ {
		testPool.Exec(context.Background(), `INSERT INTO service_calls (job, name, ver, caller, root, fee, settled) VALUES ($1, $2, 1, $3, $3, 0, true)`, core.NewID('j'), name, core.NewID('a'))
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"/stable", tok, map[string]any{"ver": 1}); st != 409 {
		t.Fatalf("two other roots: %d %s", st, body)
	}
	testPool.Exec(context.Background(), `INSERT INTO service_calls (job, name, ver, caller, root, fee, settled) VALUES ($1, $2, 1, $3, $3, 0, true)`, core.NewID('j'), name, core.NewID('a'))
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"/stable", tok, map[string]any{"ver": 1}); st != 200 {
		t.Fatalf("three other roots: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"/stable", tok, map[string]any{"ver": 1}); st != 429 || !strings.Contains(body, "once per hour") {
		t.Fatalf("second move within the hour: %d %s", st, body)
	}
	if st, body, _ := e.do("POST", "/v1/svc/"+name+"/stable", tok, map[string]any{"ver": 7}); st != 429 {
		t.Fatalf("rate before lookup: %d %s", st, body)
	}
	var n int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM audit WHERE op = 'svc.stable' AND ref = $1`, name+"@1").Scan(&n)
	if n != 1 {
		t.Fatalf("stable move not logged: %d", n)
	}
}

func TestCallExport(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("exp")
	w := e.verified(tok, name, wasm, []map[string]any{kat("a", "A")}, map[string]string{sha([]byte("a")): "A"}, nil)
	_, caller := e.register("caller")
	cid := e.ident(caller)
	ctx := context.Background()
	view, out, err := Call(ctx, e.d, cid, name+"@1", "", "hi", "", 0)
	if err != nil || view.Status != "queued" || out != "" {
		t.Fatalf("Call: %v %+v %q", err, view, out)
	}
	e.work(w, constOut("HI there\n"))
	view, out, err = Call(ctx, e.d, cid, name+"@1", "", "hi", "", 0)
	if err != nil || view.Status != "done" || !view.Cached || out != "HI there\n" {
		t.Fatalf("Call cached: %v %+v %q", err, view, out)
	}
	if _, _, err := Call(ctx, e.d, cid, name, "", "hi", "", 0); err == nil || !strings.Contains(err.Error(), "no stable version") {
		t.Fatalf("Call without stable: %v", err)
	}
	if _, _, err := Call(ctx, e.d, cid, "cxpy", "", "hi", "", 0); err == nil || !strings.Contains(err.Error(), "not published yet") {
		t.Fatalf("Call interpreter: %v", err)
	}
	if _, _, err := Call(ctx, e.d, nil, name+"@1", "", "hi", "", 0); err == nil {
		t.Fatal("Call without identity")
	}
	// catalog.OnDone is a no-op for jobs outside the catalog.
	if err := OnDone(ctx, testPool, &compute.Job{ID: "jnone", Kind: "job"}); err != nil {
		t.Fatal(err)
	}
}

func TestDataSegmentSecretRefusesPublish(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	st, body, _ := e.do("POST", "/v1/b", tok, wasmWithData(id, "token for the data segment: "+ghpKey+" end"))
	if st != 200 || !strings.Contains(body, "scrub=") {
		t.Fatalf("upload flagged module: %d %s", st, body)
	}
	hash := firstField(body)
	if st, body := e.publish(tok, uname("leaky"), hash, manifest([]map[string]any{kat("a", "A")}, nil)); st != 400 || !strings.HasPrefix(body, "err scrub module data segment ") {
		t.Fatalf("publish flagged module: %d %s", st, body)
	}
	clean := e.put(tok, wasmWithData(id+"-clean", "just a normal string in the data segment"))
	if st, body := e.publish(tok, uname("clean"), clean, manifest([]map[string]any{kat("a", "A")}, nil)); st != 201 {
		t.Fatalf("clean module: %d %s", st, body)
	}
}

// --- seed modules through the sandbox ---------------------------------------------------------

func loadSeed(t *testing.T, name string) ([]byte, Manifest) {
	t.Helper()
	wasm, err := os.ReadFile(filepath.Join(seedDir, name+".wasm"))
	if err != nil {
		t.Skipf("seed module not built (sh testdata/wasm/build.sh): %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(seedDir, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return wasm, m
}

// runKATs executes every manifest test of a built module in the sandbox and checks the hashes.
func runKATs(t *testing.T, name string) {
	t.Helper()
	wasm, m := loadSeed(t, name)
	if len(wasm) > unpinnedWasm {
		t.Fatalf("%s is %d bytes, over the 4 MiB unpinned cap", name, len(wasm))
	}
	if len(m.Tests) != 3 {
		t.Fatalf("%s ships %d KATs, want 3", name, len(m.Tests))
	}
	r, err := sandbox.New("", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	for i, tc := range m.Tests {
		res := r.Run(context.Background(), wasm, []byte(tc.InText), 10000, 64)
		if res.Status != sandbox.StatusOK {
			t.Fatalf("%s test %d: %s %s %s", name, i+1, res.Status, res.Detail, res.Stderr)
		}
		if got := sha(res.Out); got != tc.OutSHA256 {
			t.Fatalf("%s test %d: out %q sha %s, declared %s", name, i+1, res.Out, got[:12], tc.OutSHA256[:12])
		}
	}
}

func TestCxPatchKATs(t *testing.T) {
	runKATs(t, "cx-patch")
	wasm, _ := loadSeed(t, "cx-patch")
	r, _ := sandbox.New("", 2)
	defer r.Close(context.Background())
	res := r.Run(context.Background(), wasm, []byte(`{"base":"one\ntwo\n","diff":"@@ -1,2 +1,2 @@\n one\n-TWO\n+2\n"}`), 10000, 64)
	if res.Status != sandbox.StatusExit || res.Code != 1 || string(res.Out) != "error: hunk 1 does not apply at line 2\n" {
		t.Fatalf("failing hunk: %s code=%d out=%q", res.Status, res.Code, res.Out)
	}
	// Round trip with cx-diff: the diff of a->b applied to a yields b.
	dwasm, _ := loadSeed(t, "cx-diff")
	a, b := "alpha\nbeta\ngamma\ndelta\n", "alpha\nBETA\ngamma\ndelta\nepsilon\n"
	ab, _ := json.Marshal(map[string]string{"a": a, "b": b})
	d := r.Run(context.Background(), dwasm, ab, 10000, 64)
	if d.Status != sandbox.StatusOK {
		t.Fatalf("cx-diff: %s %s", d.Status, d.Stderr)
	}
	in, _ := json.Marshal(map[string]string{"base": a, "diff": string(d.Out)})
	p := r.Run(context.Background(), wasm, in, 10000, 64)
	if p.Status != sandbox.StatusOK || string(p.Out) != b {
		t.Fatalf("round trip: %s %q (diff %q)", p.Status, p.Out, d.Out)
	}
}

func TestSeedModuleKATs(t *testing.T) {
	for _, name := range []string{"cx-jq", "cx-semver", "cx-json-schema", "cx-regex", "cx-diff", "cx-tz", "cx-cron", "cx-tokens", "cx-b64", "cx-uuid"} {
		t.Run(name, func(t *testing.T) { runKATs(t, name) })
	}
}

// TestSeedSemverKATConsensus is the acceptance scenario: the built cx-semver module is seeded
// under the system root, two donors in distinct networks run its KATs in the sandbox and report,
// and the janitor flips it to verified; 'compare 1.2.0 1.10.0' answers '-1'.
func TestSeedSemverKATConsensus(t *testing.T) {
	wasm, m := loadSeed(t, "cx-semver")
	e := newEnv(t)
	e.fundSystem()
	ctx := context.Background()
	dir := t.TempDir()
	mj, _ := os.ReadFile(filepath.Join(seedDir, "cx-semver.json"))
	os.WriteFile(filepath.Join(dir, "cx-semver.wasm"), wasm, 0o644)
	os.WriteFile(filepath.Join(dir, "cx-semver.json"), mj, 0o644)
	e.names = append(e.names, "cx-semver")
	testPool.Exec(ctx, `DELETE FROM services WHERE name = 'cx-semver'`)
	if n, err := SeedSystem(ctx, e.d, dir); err != nil || n != 1 {
		t.Fatalf("SeedSystem: n=%d err=%v", n, err)
	}
	if m.Tests[0].InText != "compare 1.2.0 1.10.0" || m.Tests[0].OutSHA256 != sha([]byte("-1\n")) {
		t.Fatalf("first KAT is %q -> %s", m.Tests[0].InText, m.Tests[0].OutSHA256[:12])
	}
	r, err := sandbox.New("", 2)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)
	inputs := map[string][]byte{}
	for _, tc := range m.Tests {
		inputs[sha([]byte(tc.InText))] = []byte(tc.InText)
	}
	// The system root has no network key, so its KATs count as distinct only through an
	// operator-trusted donor (14.5): the operator's own donor profile.
	w := e.workers(2)
	if st, body, _ := e.do("POST", "/admin/trusted", adminTok, map[string]any{"id": e.ident(w[0]).Root, "on": true}); st != 200 {
		t.Fatalf("trusted: %d %s", st, body)
	}
	n := e.work(w, func(l *leaseOut) []byte {
		in, ok := inputs[l.In]
		if !ok {
			t.Fatalf("unexpected input %s", l.In)
		}
		res := r.Run(ctx, wasm, in, l.Ms, l.Mb)
		if res.Status != sandbox.StatusOK {
			t.Fatalf("module run: %s %s", res.Status, res.Stderr)
		}
		return res.Out
	})
	if n != 6 {
		t.Fatalf("reports %d", n)
	}
	e.verify()
	v := e.version("cx-semver", 1)
	if v.State != "verified" || v.StableVer != 1 {
		t.Fatalf("cx-semver %s stable=%d (%s)", v.State, v.StableVer, v.Tested)
	}
	// A trusted agreeing donor makes the KAT result globally cached (14.1), so the caller's call
	// is served from the cache; without that scope it queues a fresh job the donors run first.
	_, caller := e.register("caller")
	st, body, _ := e.do("POST", "/v1/svc/cx-semver", caller, map[string]any{"in_text": "compare 1.2.0 1.10.0"})
	if st == 202 {
		if n := e.work(w, func(l *leaseOut) []byte { return r.Run(ctx, wasm, []byte("compare 1.2.0 1.10.0"), l.Ms, l.Mb).Out }); n != 2 {
			t.Fatalf("call reports %d", n)
		}
		st, body, _ = e.do("POST", "/v1/svc/cx-semver", caller, map[string]any{"in_text": "compare 1.2.0 1.10.0"})
	}
	if st != 200 || !strings.HasPrefix(body, "done ms=0 out="+sha([]byte("-1\n"))) || !strings.Contains(body, "cached pinned="+sha(wasm)[:12]) || !strings.Contains(body, "\n  -1\n") {
		t.Fatalf("semver call: %d %s", st, body)
	}
	if s := e.s.llms(ctx); !strings.Contains(s, "cx-semver@1") {
		t.Fatalf("seed tool missing from llms-full: %q", s)
	}
}
