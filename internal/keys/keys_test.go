package keys

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/sign"
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
	} else if pool, done := testdb.Open("keys", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping keys DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

const testSecret = "test-secret-0123456789abcdef"

type tenv struct {
	d   *core.Deps
	s   *svc
	srv *httptest.Server
	ip  string
}

// newEnv wires core (challenge/register), sign (/verify) and this package behind core.Handler;
// extra mounts test-only routes before the server starts.
func newEnv(t *testing.T, extra ...func(mux *http.ServeMux)) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte(testSecret), AdminToken: "adm-token", SignKID: 1, PowBits: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", MirrorURL: "https://github.com/example/mirror", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAuthV2(mux, d)
	sign.Register(mux, d)
	Register(mux, d)
	for _, fn := range extra {
		fn(mux)
	}
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	var b [3]byte
	rand.Read(b[:])
	return &tenv{d: d, s: cur.Load(), srv: srv, ip: fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])}
}

// anonIP is a fresh client address: anonymous proof loops must not trip the per-network budget.
func anonIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

func (e *tenv) do(t *testing.T, method, path, token string, body []byte, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("CF-Connecting-IP", e.ip)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if len(body) > 0 && body[0] == '{' {
		req.Header.Set("Content-Type", "application/json")
	} else if len(body) > 0 {
		req.Header.Set("Content-Type", "application/octet-stream")
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
	return res.StatusCode, string(b), res.Header
}

var kvRe = regexp.MustCompile(`(\w+)=(\S+)`)

func kv(s string) map[string]string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(s, -1) {
		m[x[1]] = x[2]
	}
	return m
}

func mkSeed() []byte { return e2e.NewSeed() }

type bopts struct {
	policy  uint8
	ikPrev  ed25519.PrivateKey
	sub     bool
	lkOK    bool
	iatSkew int64
}

// mkBundle builds and signs a mode-D bundle for id from seed (five epochs from the current one).
func mkBundle(t *testing.T, seed []byte, id string, seq uint32, prevHash []byte, o bopts) ([]byte, *e2e.Bundle) {
	t.Helper()
	now := time.Now().Unix() + o.iatSkew
	var rev [32]byte
	rand.Read(rev[:])
	var flags uint8
	if o.sub {
		flags |= e2e.FlagSub
	}
	if o.lkOK {
		flags |= e2e.FlagLKOK
	}
	b, err := e2e.NewBundle(seed, e2e.BundleParams{ID: id, Seq: seq, IAT: uint32(now), Exp: uint32(now + 30*86400), Flags: flags,
		MailPolicy: o.policy, MinCS: uint8(e2e.CS1), E0: e2e.Epoch(now), NEK: 5, RevCommit: rev[:], PrevHash: prevHash})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Sign(e2e.IK(seed), o.ikPrev, nil)
	if err != nil {
		t.Fatal(err)
	}
	return raw, b
}

func canonHash(t *testing.T, b *e2e.Bundle) []byte {
	t.Helper()
	h, err := b.CanonicalHash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// rootWithBundle mints a root the fast way (no PoW) and publishes its seq-1 bundle through the
// registration seam inside one transaction, as core's register does.
func rootWithBundle(t *testing.T, e *tenv, seed []byte, policy uint8) (id, token string, raw []byte, b *e2e.Bundle) {
	t.Helper()
	ctx := context.Background()
	err := core.Tx(ctx, testPool, func(tx pgx.Tx) error {
		var err error
		id, token, err = core.CreateRoot(ctx, tx, "keys-test", e.ip)
		if err != nil {
			return err
		}
		raw, b = mkBundle(t, seed, id, 1, nil, bopts{policy: policy})
		enc, _ := json.Marshal(b64(raw))
		return RegisterBundle(ctx, tx, id, enc)
	})
	if err != nil {
		t.Fatal(err)
	}
	return id, token, raw, b
}

func plainRoot(t *testing.T, e *tenv) (id, token string) {
	t.Helper()
	id, token, err := core.CreateRoot(context.Background(), testPool, "keys-plain", e.ip)
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

// sigHeader signs a request with the seed's rk (fresh nonce, now + skew).
func sigHeader(t *testing.T, seed []byte, method, pathQuery string, body []byte, skew int64) string {
	t.Helper()
	nonce := make([]byte, e2e.NonceSize)
	rand.Read(nonce)
	h, err := e2e.SignReq(e2e.RK(seed), method, pathQuery, uint64(time.Now().Unix()+skew), nonce, body)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (e *tenv) onlinePub(t *testing.T) []byte {
	t.Helper()
	st, body, _ := e.do(t, "GET", "/v1/keys/server", "", nil)
	if st != 200 {
		t.Fatalf("keys/server: %d %s", st, body)
	}
	pub, err := decodeB64(kv(body)["online"])
	if err != nil || len(pub) != 32 {
		t.Fatalf("online key: %v %s", err, body)
	}
	return pub
}

func (e *tenv) verifyReply(t *testing.T, path string, hdr http.Header, body string) {
	t.Helper()
	if _, err := e2e.VerifyResp(e.onlinePub(t), path, hdr.Get("X-Cx-Sig-Server"), []byte(body)); err != nil {
		t.Fatalf("%s: X-Cx-Sig-Server %q does not verify: %v", path, hdr.Get("X-Cx-Sig-Server"), err)
	}
}

func count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// --- tests --------------------------------------------------------------------------------------

func TestBundleBornInRegistration(t *testing.T) {
	e := newEnv(t)
	core.ChallengeIDFn, core.RegisterBundleFn = ChallengeID, RegisterBundle
	t.Cleanup(func() { core.ChallengeIDFn, core.RegisterBundleFn = nil, nil })
	ctx := context.Background()

	st, body, _ := e.do(t, "POST", "/v1/challenge", "", nil)
	if st != 200 {
		t.Fatalf("challenge: %d %s", st, body)
	}
	m := kv(body)
	bits, _ := strconv.Atoi(m["bits"])
	id := m["id"]
	if !core.ValidIDPrefix(id, 'a') || id != ChallengeID(ctx, m["c"]) || ChallengeID(ctx, m["c"]+"x") == id {
		t.Fatalf("challenge id: %s", body)
	}
	seed := mkSeed()
	raw, b := mkBundle(t, seed, id, 1, nil, bopts{policy: e2e.PolicyBoth})
	reg, _ := json.Marshal(map[string]string{"c": m["c"], "nonce": pow.Solve(m["c"], bits), "name": "born", "bundle": b64(raw)})
	st, body, _ = e.do(t, "POST", "/v1/register", "", reg)
	if st != 201 || kv(body)["id"] != id {
		t.Fatalf("register: %d %s", st, body)
	}
	st, body, hdr := e.do(t, "GET", "/v1/keys/"+id, "", nil)
	if st != 200 {
		t.Fatalf("keys: %d %s", st, body)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	dir := kv(lines[0])
	if len(lines) != 2 || dir["seq"] != "1" || dir["pending"] != "0" || dir["pol"] != "1" || dir["fp"] != hex.EncodeToString(b.Fingerprint()) || lines[1] != b64(raw) {
		t.Fatalf("directory: %s", body)
	}
	e.verifyReply(t, "/v1/keys/"+id, hdr, body)
	if hdr.Get("X-Now") == "" || hdr.Get(LogMinimalHeader) != "minimal" {
		t.Fatalf("headers: %v", hdr)
	}
	leaf, _ := strconv.ParseUint(dir["leaf"], 10, 64)
	var kind int16
	var item []byte
	if err := testPool.QueryRow(ctx, `SELECT kind, item_hash FROM klog WHERE idx = $1 AND id = $2`, int64(leaf), id).Scan(&kind, &item); err != nil || kind != KindBundle || !bytes.Equal(item, canonHash(t, b)) {
		t.Fatalf("leaf %d: kind=%d err=%v", leaf, kind, err)
	}
	if n := count(t, `SELECT count(*) FROM events WHERE kind = 'pk' AND ref = $1 AND root_scope IS NULL`, id); n != 1 {
		t.Fatalf("events pk: %d", n)
	}
	if n := count(t, `SELECT count(*) FROM ts WHERE h = $1 AND note = 'pk'`, stampHash(id, canonHash(t, b))); n != 1 {
		t.Fatalf("ts stamp: %d", n)
	}
	// Only the bundle for the announced id is accepted; a mismatch aborts the registration.
	st, body, _ = e.do(t, "POST", "/v1/challenge", "", nil)
	m2 := kv(body)
	bits2, _ := strconv.Atoi(m2["bits"])
	other, _ := mkBundle(t, mkSeed(), id, 1, nil, bopts{})
	reg, _ = json.Marshal(map[string]string{"c": m2["c"], "nonce": pow.Solve(m2["c"], bits2), "name": "born2", "bundle": b64(other)})
	if st, body, _ = e.do(t, "POST", "/v1/register", "", reg); st != 400 || !strings.Contains(body, "is not "+m2["id"]) {
		t.Fatalf("mismatched bundle: %d %s", st, body)
	}
	if st, _, _ = e.do(t, "GET", "/v1/keys/"+m2["id"], "", nil); st != 404 {
		t.Fatalf("aborted registration left keys: %d", st)
	}
	if n := count(t, `SELECT count(*) FROM identities WHERE id = $1`, m2["id"]); n != 0 {
		t.Fatal("aborted registration left an identity")
	}
}

func TestPutKeysRequiresSigAndSeq(t *testing.T) {
	e := newEnv(t)
	seed := mkSeed()
	id, tok, _, b1 := rootWithBundle(t, e, seed, e2e.PolicyBoth)
	raw2, b2 := mkBundle(t, seed, id, 2, canonHash(t, b1), bopts{policy: e2e.PolicyBoth})

	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw2); st != 401 || !strings.Contains(body, "X-Cx-Sig required") {
		t.Fatalf("unsigned: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw2, "X-Cx-Sig", sigHeader(t, mkSeed(), "PUT", "/v1/keys", raw2, 0)); st != 401 || !strings.Contains(body, "invalid") {
		t.Fatalf("foreign rk: %d %s", st, body)
	}
	raw3, _ := mkBundle(t, seed, id, 3, canonHash(t, b2), bopts{policy: e2e.PolicyBoth})
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw3, "X-Cx-Sig", sigHeader(t, seed, "PUT", "/v1/keys", raw3, 0)); st != 400 || !strings.Contains(body, "seq want=2") {
		t.Fatalf("seq gap: %d %s", st, body)
	}
	var wrong [32]byte
	rawBad, _ := mkBundle(t, seed, id, 2, wrong[:], bopts{policy: e2e.PolicyBoth})
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, rawBad, "X-Cx-Sig", sigHeader(t, seed, "PUT", "/v1/keys", rawBad, 0)); st != 400 || !strings.Contains(body, "prev_hash") {
		t.Fatalf("prev_hash: %d %s", st, body)
	}
	hdr := sigHeader(t, seed, "PUT", "/v1/keys", raw2, 0)
	st, body, rh := e.do(t, "PUT", "/v1/keys", tok, raw2, "X-Cx-Sig", hdr)
	if st != 200 {
		t.Fatalf("put: %d %s", st, body)
	}
	m := kv(body)
	if m["seq"] != "2" || m["bundle"] != hex.EncodeToString(e2e.BundleHash(raw2)) || len(m["head"]) != 16 || m["leaf"] == "" {
		t.Fatalf("put reply: %s", body)
	}
	e.verifyReply(t, "/v1/keys", rh, body)
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw2, "X-Cx-Sig", hdr); st != 409 || !strings.Contains(body, "replayed") {
		t.Fatalf("replayed put: %d %s", st, body)
	}
	st, body, _ = e.do(t, "GET", "/v1/keys/"+id, "", nil)
	if st != 200 || kv(body)["seq"] != "2" || kv(body)["leaf"] != m["leaf"] {
		t.Fatalf("after put: %d %s", st, body)
	}
	st, body, _ = e.do(t, "GET", "/v1/keys", tok, nil)
	if st != 200 || kv(body)["seq"] != "2" {
		t.Fatalf("own keys: %d %s", st, body)
	}
	st, body, _ = e.do(t, "GET", "/v1/keys/"+id+"/hist", "", nil)
	if st != 200 || strings.Count(body, "\n") != 2 || !strings.Contains(body, "state=superseded") || !strings.Contains(body, "state=current") {
		t.Fatalf("hist: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "GET", "/v1/keys/"+id+"?leaf="+kv(body)["leaf"], "", nil); st != 200 || kv(body)["seq"] != "1" {
		t.Fatalf("at leaf: %d %s", st, body)
	}
	// A prekey refresh with the same ik and rk is not a key change: no notice, no 24 h lock.
	var changed *time.Time
	if err := testPool.QueryRow(context.Background(), `SELECT keys_changed_at FROM identities WHERE id = $1`, id).Scan(&changed); err != nil || changed != nil {
		t.Fatalf("keys_changed_at after refresh: %v %v", changed, err)
	}
	if st, body, _ := e.do(t, "GET", "/v1/keys/"+id+"?f=json", "", nil); st != 200 || !strings.Contains(body, `"seq":2`) {
		t.Fatalf("json: %d %s", st, body)
	}
}

func TestKlogInclusionAndConsistency(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var ids []string
	for i := 0; i < 6; i++ {
		seed := mkSeed()
		id, tok, _, b1 := rootWithBundle(t, e, seed, e2e.PolicyBoth)
		ids = append(ids, id)
		if i%2 == 0 {
			raw2, _ := mkBundle(t, seed, id, 2, canonHash(t, b1), bopts{policy: e2e.PolicyBoth})
			if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw2, "X-Cx-Sig", sigHeader(t, seed, "PUT", "/v1/keys", raw2, 0)); st != 200 {
				t.Fatalf("put: %d %s", st, body)
			}
		}
	}
	if _, err := e.s.signHead(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := testPool.Query(ctx, `SELECT leaf FROM klog ORDER BY idx`)
	if err != nil {
		t.Fatal(err)
	}
	var tree e2e.Tree
	for rows.Next() {
		var leaf []byte
		if err := rows.Scan(&leaf); err != nil {
			t.Fatal(err)
		}
		tree.Append(leaf)
	}
	rows.Close()
	size := tree.Size()
	if size < 9 {
		t.Fatalf("log too small: %d", size)
	}
	st, body, _ := e.do(t, "GET", "/v1/log/sth", "", nil)
	h, _, err := e2e.ParseSTHLine(body)
	if st != 200 || err != nil || h.Size != size || !bytes.Equal(h.Root, tree.Root()) {
		t.Fatalf("sth: %d %s (%v)", st, body, err)
	}
	lo := uint64(1)
	if size > 20 {
		lo = size - 20
	}
	for n := lo; n <= size; n++ {
		for m := uint64(0); m < n; m++ {
			st, body, _ := e.do(t, "GET", fmt.Sprintf("/v1/log/incl?leaf=%d&size=%d", m, n), "", nil, "CF-Connecting-IP", anonIP())
			idx, leaf, path, err := e2e.ParseInclLine(body)
			if st != 200 || err != nil || idx != m || !bytes.Equal(leaf, tree.Leaf(m)) {
				t.Fatalf("incl %d/%d: %d %s %v", m, n, st, body, err)
			}
			if !e2e.VerifyInclusion(leaf, m, n, path, tree.RootAt(n)) {
				t.Fatalf("inclusion %d in %d does not verify: %s", m, n, body)
			}
			if m+1 < n && e2e.VerifyInclusion(leaf, m+1, n, path, tree.RootAt(n)) {
				t.Fatalf("inclusion %d in %d verifies for the wrong index", m, n)
			}
		}
		for a := lo; a <= n; a++ {
			st, body, _ := e.do(t, "GET", fmt.Sprintf("/v1/log/cons?from=%d&to=%d", a, n), "", nil, "CF-Connecting-IP", anonIP())
			path, err := e2e.ParseConsLine(body)
			if st != 200 || err != nil {
				t.Fatalf("cons %d->%d: %d %s %v", a, n, st, body, err)
			}
			if !e2e.VerifyConsistency(a, n, tree.RootAt(a), tree.RootAt(n), path) {
				t.Fatalf("consistency %d->%d does not verify: %s", a, n, body)
			}
		}
	}
	if st, body, _ := e.do(t, "GET", fmt.Sprintf("/v1/log/incl?leaf=%d&size=%d", size, size), "", nil); st != 400 {
		t.Fatalf("incl out of range: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "GET", fmt.Sprintf("/v1/log/cons?from=%d&to=%d", size+1, size), "", nil); st != 400 {
		t.Fatalf("cons out of range: %d %s", st, body)
	}
	st, body, hdr := e.do(t, "GET", "/v1/log?from=0&n=500", "", nil, "CF-Connecting-IP", anonIP())
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if st != 200 || uint64(len(lines)) != size {
		t.Fatalf("delta: %d lines=%d size=%d", st, len(lines), size)
	}
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) != 5 || f[0] != strconv.Itoa(i) || f[4] != hex.EncodeToString(tree.Leaf(uint64(i))) {
			t.Fatalf("delta line %d: %q", i, l)
		}
	}
	e.verifyReply(t, "/v1/log", hdr, body)
	if got := hdr.Get("CX-STH"); got != e2e.GossipHeader(size, tree.Root()) {
		t.Fatalf("CX-STH %q", got)
	}
	st, body, _ = e.do(t, "GET", "/v1/log/id/"+ids[0], "", nil, "CF-Connecting-IP", anonIP())
	if st != 200 || strings.Count(body, "\n") != 2 || !strings.Contains(body, " 1 1 ") || !strings.Contains(body, " 1 2 ") {
		t.Fatalf("log/id: %d %s", st, body)
	}
}

func TestSTHSignedAndCosign(t *testing.T) {
	wpub, wsk, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("WITNESS_PUBS", "w1:"+b64(wpub))
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.s.signHead(ctx); err != nil {
		t.Fatal(err)
	}
	st, body, hdr := e.do(t, "GET", "/v1/log/sth", "", nil)
	if st != 200 {
		t.Fatalf("sth: %d %s", st, body)
	}
	e.verifyReply(t, "/v1/log/sth", hdr, body)
	h, cert, err := e2e.ParseSTHLine(body)
	if err != nil {
		t.Fatal(err)
	}
	online := e.onlinePub(t)
	if err := e2e.VerifyHead(h, online, nil, 0); err != nil {
		t.Fatalf("head signature: %v", err)
	}
	c, err := ParseCert(cert)
	if err != nil || c.Verify(online, online, time.Now().Unix()) != nil {
		t.Fatalf("self-certified cert: %v", err)
	}
	_, sbody, _ := e.do(t, "GET", "/v1/keys/server", "", nil)
	sm := kv(sbody)
	if sm["root"] != sm["online"] || sm["w1"] != b64(wpub) || sm["mirror"] != "https://github.com/example/mirror" || sm["self"] != "1" {
		t.Fatalf("keys/server: %s", sbody)
	}
	// An established root cosigns with its ik, once per hour.
	seed := mkSeed()
	id, tok, _, _ := rootWithBundle(t, e, seed, e2e.PolicyBoth)
	if _, err := testPool.Exec(ctx, `UPDATE identities SET rep = 5, created = now() - interval '80 hours' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	wb := e2e.WitnessBytes(h.Size, h.Root, h.At)
	cos, _ := json.Marshal(map[string]any{"size": h.Size, "sig": b64(e2e.Sign(e2e.IK(seed), wb))})
	st, body, _ = e.do(t, "POST", "/v1/log/cosign", tok, cos, "X-Cx-Sig", sigHeader(t, seed, "POST", "/v1/log/cosign", cos, 0))
	if st != 200 {
		t.Fatalf("cosign: %d %s", st, body)
	}
	st, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/log/sth?size=%d", h.Size), "", nil)
	var seen bool
	for _, l := range strings.Split(body, "\n")[1:] {
		m := kv(l)
		if !strings.HasPrefix(l, "cosign ") || m["id"] != id {
			continue
		}
		sig, _ := decodeB64(m["sig"])
		at, _ := strconv.ParseUint(m["at"], 10, 64)
		if !e2e.Verify(e2e.IK(seed).Public().(ed25519.PublicKey), e2e.WitnessBytes(h.Size, h.Root, at), sig) {
			t.Fatalf("cosign line does not verify: %s", l)
		}
		seen = true
	}
	if st != 200 || !seen {
		t.Fatalf("sth with cosign: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/v1/log/cosign", tok, cos, "X-Cx-Sig", sigHeader(t, seed, "POST", "/v1/log/cosign", cos, 0)); st != 429 {
		t.Fatalf("second cosign within the hour: %d %s", st, body)
	}
	fresh := mkSeed()
	_, ftok, _, _ := rootWithBundle(t, e, fresh, e2e.PolicyBoth)
	fcos, _ := json.Marshal(map[string]any{"size": h.Size, "sig": b64(e2e.Sign(e2e.IK(fresh), wb))})
	if st, body, _ := e.do(t, "POST", "/v1/log/cosign", ftok, fcos, "X-Cx-Sig", sigHeader(t, fresh, "POST", "/v1/log/cosign", fcos, 0)); st != 403 {
		t.Fatalf("unestablished cosign: %d %s", st, body)
	}
	// A configured witness needs no token: its signature is the credential.
	wcos, _ := json.Marshal(map[string]any{"size": h.Size, "sig": b64(e2e.Sign(wsk, wb)), "w": "w1"})
	if st, body, _ := e.do(t, "POST", "/v1/log/cosign", "", wcos, "CF-Connecting-IP", e.ip); st != 200 {
		t.Fatalf("witness cosign: %d %s", st, body)
	}
	bad, _ := json.Marshal(map[string]any{"size": h.Size, "sig": b64(make([]byte, 64)), "w": "w1"})
	if st, _, _ := e.do(t, "POST", "/v1/log/cosign", "", bad); st != 400 {
		t.Fatalf("bad witness sig: %d", st)
	}
	_, body, _ = e.do(t, "GET", fmt.Sprintf("/v1/log/sth?size=%d", h.Size), "", nil)
	if !strings.Contains(body, "cosign id=w1 ") {
		t.Fatalf("witness cosign missing: %s", body)
	}
	mh, err := e2e.ParseMirrorHead(func() []byte {
		b, _ := e2e.FormatMirrorHead(&e2e.Head{Size: h.Size, Root: h.Root, At: h.At, Sig: h.Sig, Witness: map[string][]byte{"w1": e2e.Sign(wsk, wb)}}, 0)
		return b
	}())
	if err != nil || e2e.VerifyHead(mh, online, map[string][]byte{"w1": wpub}, 1) != nil {
		t.Fatalf("mirror head with the witness signature must verify: %v", err)
	}
}

func TestRequireSigNonceReplay(t *testing.T) {
	e := newEnv(t, func(mux *http.ServeMux) {
		mux.Handle("POST /v1/sigtest", RequireSig(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			sig, ok := SigFrom(r.Context())
			if !ok || !IsLogMinimal(r.Context()) {
				core.Err(w, r, 500, "internal", "no sig in context")
				return
			}
			core.OK(w, r, "ok "+string(body)+" nonce="+b64(sig.Nonce), nil)
		})))
	})
	seed := mkSeed()
	_, tok, _, _ := rootWithBundle(t, e, seed, e2e.PolicyBoth)
	body := []byte(`{"x":1}`)
	path := "/v1/sigtest?q=1"
	hdr := sigHeader(t, seed, "POST", path, body, 0)
	st, out, rh := e.do(t, "POST", path, tok, body, "X-Cx-Sig", hdr)
	if st != 200 || !strings.HasPrefix(out, "ok {\"x\":1} nonce=") || rh.Get("X-Now") == "" {
		t.Fatalf("signed: %d %s %v", st, out, rh)
	}
	if st, out, _ := e.do(t, "POST", path, tok, body, "X-Cx-Sig", hdr); st != 409 || !strings.Contains(out, "replayed") {
		t.Fatalf("replay: %d %s", st, out)
	}
	if st, out, _ := e.do(t, "POST", path, tok, []byte(`{"x":2}`), "X-Cx-Sig", sigHeader(t, seed, "POST", path, body, 0)); st != 401 || !strings.Contains(out, "invalid") {
		t.Fatalf("tampered body: %d %s", st, out)
	}
	if st, out, _ := e.do(t, "POST", "/v1/sigtest?q=2", tok, body, "X-Cx-Sig", sigHeader(t, seed, "POST", path, body, 0)); st != 401 {
		t.Fatalf("other query: %d %s", st, out)
	}
	st, out, rh = e.do(t, "POST", path, tok, body, "X-Cx-Sig", sigHeader(t, seed, "POST", path, body, -1000))
	now, _ := strconv.ParseInt(kv(out)["now"], 10, 64)
	if st != 401 || !strings.HasPrefix(out, "err skew now=") || now < time.Now().Unix()-5 || rh.Get("X-Now") == "" {
		t.Fatalf("skew: %d %s", st, out)
	}
	if st, out, _ := e.do(t, "POST", path, tok, body); st != 401 || !strings.Contains(out, "X-Cx-Sig required") {
		t.Fatalf("missing header: %d %s", st, out)
	}
	if st, out, _ := e.do(t, "POST", path, tok, body, "X-Cx-Sig", "v1,garbage"); st != 401 {
		t.Fatalf("malformed header: %d %s", st, out)
	}
	if st, _, _ := e.do(t, "POST", path, "", body, "X-Cx-Sig", hdr); st != 401 {
		t.Fatalf("no token: %d", st)
	}
	_, ptok := plainRoot(t, e)
	if st, out, _ := e.do(t, "POST", path, ptok, body, "X-Cx-Sig", sigHeader(t, mkSeed(), "POST", path, body, 0)); st != 403 || !strings.Contains(out, "no key published") {
		t.Fatalf("no bundle: %d %s", st, out)
	}
}

func TestPolicyPackSignedAndLogged(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	st, body, hdr := e.do(t, "GET", "/v1/policy", "", nil)
	if st != 200 {
		t.Fatalf("policy: %d %s", st, body)
	}
	e.verifyReply(t, "/v1/policy", hdr, body)
	var p struct {
		V             int      `json:"v"`
		RulesV        int      `json:"rules_v"`
		SecretRegexes []string `json:"secret_regexes"`
		MinCS         int      `json:"min_cs"`
		BatchHours    []int    `json:"batch_hours"`
		Buckets       map[string][]int
		Banner        string
	}
	if err := json.Unmarshal([]byte(body), &p); err != nil || p.V < 1 || p.RulesV != scrub.RulesV || len(p.SecretRegexes) < 3 || p.MinCS != 1 ||
		fmt.Sprint(p.BatchHours) != "[0 6 12 18]" || fmt.Sprint(p.Buckets["pair"]) != "[1024 4096]" || p.Banner == "" {
		t.Fatalf("pack: %v %s", err, body)
	}
	for _, re := range p.SecretRegexes {
		if _, err := regexp.Compile(re); err != nil {
			t.Fatalf("regex %q: %v", re, err)
		}
	}
	pm := kv(hdr.Get("X-Cx-Policy"))
	hash := e2e.Sum([]byte(body))
	if pm["v"] != strconv.Itoa(p.V) || pm["hash"] != hex.EncodeToString(hash) {
		t.Fatalf("X-Cx-Policy %q", hdr.Get("X-Cx-Policy"))
	}
	leaf, _ := strconv.ParseUint(pm["leaf"], 10, 64)
	var kind int16
	var lid string
	var item []byte
	if err := testPool.QueryRow(ctx, `SELECT kind, id, item_hash FROM klog WHERE idx = $1`, int64(leaf)).Scan(&kind, &lid, &item); err != nil || kind != KindPolicy || lid != core.SystemID || !bytes.Equal(item, hash) {
		t.Fatalf("policy leaf %d: kind=%d id=%s err=%v", leaf, kind, lid, err)
	}
	h, err := e.s.signHead(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, ib, _ := e.do(t, "GET", fmt.Sprintf("/v1/log/incl?leaf=%d&size=%d", leaf, h.Size), "", nil)
	idx, lh, path, err := e2e.ParseInclLine(ib)
	if err != nil || idx != leaf || !bytes.Equal(lh, e2e.KlogLeaf(KindPolicy, core.SystemID, hash, leaf)) || !e2e.VerifyInclusion(lh, leaf, h.Size, path, h.Root) {
		t.Fatalf("policy inclusion: %v %s", err, ib)
	}
	// A second Register (restart) keeps the same pack: no new version, no new leaf.
	if n := count(t, `SELECT count(*) FROM policy_pack`); n != 1 {
		t.Fatalf("policy versions: %d", n)
	}
	if n := count(t, `SELECT count(*) FROM klog WHERE kind = 5`); n != 1 {
		t.Fatalf("policy leaves: %d", n)
	}
}

func TestPk1LineVerifies(t *testing.T) {
	e := newEnv(t)
	seed := mkSeed()
	id, _, _, _ := rootWithBundle(t, e, seed, e2e.PolicyE2EE)
	st, body, hdr := e.do(t, "GET", "/v1/pk/"+id, "", nil)
	if st != 200 {
		t.Fatalf("pk: %d %s", st, body)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "pk1 id="+id+" ik=") || !strings.HasPrefix(lines[1], "sig=") {
		t.Fatalf("pk lines: %q", body)
	}
	m := kv(lines[0])
	if m["ik"] != b64(e2e.IK(seed).Public().(ed25519.PublicKey)) || m["n"] != "1" || m["k"] != "1" || m["t"] == "" {
		t.Fatalf("pk fields: %s", lines[0])
	}
	e.verifyReply(t, "/v1/pk/"+id, hdr, body)
	q := url.Values{"s": {lines[0]}, "sig": {lines[1]}}
	st, vbody, _ := e.do(t, "GET", "/verify?"+q.Encode(), "", nil)
	if st != 200 || strings.TrimSpace(vbody) != "valid kid=1 type=pk1" {
		t.Fatalf("verify: %d %s", st, vbody)
	}
	// Cached 60 s: the same bytes come back.
	if _, again, _ := e.do(t, "GET", "/v1/pk/"+id, "", nil); again != body {
		t.Fatalf("pk cache: %q vs %q", again, body)
	}
	if st, _, _ := e.do(t, "GET", "/v1/pk/azzzzzz", "", nil); st != 404 {
		t.Fatalf("unknown pk: %d", st)
	}
}

func TestKeyChangeStampsNotaryAndMail(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var mails []string
	core.SysMailFn = func(_ context.Context, _ core.Q, to, subject, text string) error {
		mails = append(mails, to+"|"+subject+"|"+text)
		return nil
	}
	t.Cleanup(func() { core.SysMailFn = nil })
	seed1, seed2 := mkSeed(), mkSeed()
	id, tok, _, b1 := rootWithBundle(t, e, seed1, e2e.PolicyBoth)
	raw2, b2 := mkBundle(t, seed2, id, 2, canonHash(t, b1), bopts{policy: e2e.PolicyBoth, ikPrev: e2e.IK(seed1)})
	st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw2, "X-Cx-Sig", sigHeader(t, seed1, "PUT", "/v1/keys", raw2, 0))
	if st != 202 || kv(body)["pending"] != "1" || kv(body)["seq"] != "2" {
		t.Fatalf("rotation: %d %s", st, body)
	}
	if len(mails) != 1 || !strings.HasPrefix(mails[0], id+"|key changed n=2|") {
		t.Fatalf("mails: %v", mails)
	}
	var changed *time.Time
	if err := testPool.QueryRow(ctx, `SELECT keys_changed_at FROM identities WHERE id = $1`, id).Scan(&changed); err != nil || changed == nil {
		t.Fatalf("keys_changed_at: %v %v", changed, err)
	}
	for _, b := range []*e2e.Bundle{b1, b2} {
		if n := count(t, `SELECT count(*) FROM ts WHERE h = $1 AND note = 'pk' AND owner = $2`, stampHash(id, canonHash(t, b)), id); n != 1 {
			t.Fatalf("ts stamp for seq %d: %d", b.Seq, n)
		}
	}
	if n := count(t, `SELECT count(*) FROM events WHERE kind = 'pk' AND ref = $1`, id); n != 2 {
		t.Fatalf("events: %d", n)
	}
	// Pending bundles are served as such and never count: the current bundle stays seq 1.
	st, body, _ = e.do(t, "GET", "/v1/keys/"+id, "", nil)
	if st != 200 || kv(body)["seq"] != "1" || kv(body)["pending"] != "0" {
		t.Fatalf("current during rotation: %d %s", st, body)
	}
	_, body, _ = e.do(t, "GET", "/v1/log/id/"+id, "", nil)
	if strings.Count(body, "\n") != 2 || !strings.Contains(body, " 3 2 ") {
		t.Fatalf("log/id: %s", body)
	}
	raw2b, _ := mkBundle(t, seed2, id, 2, canonHash(t, b1), bopts{policy: e2e.PolicyBoth, ikPrev: e2e.IK(seed1)})
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw2b, "X-Cx-Sig", sigHeader(t, seed1, "PUT", "/v1/keys", raw2b, 0)); st != 409 || !strings.Contains(body, "rotation pending") {
		t.Fatalf("second rotation: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/v1/pk/"+id, "", nil); st != 200 {
		t.Fatal("pk during rotation must still serve the current key")
	}
	// Past the window the janitor promotes the rotation: a kind 1 leaf, the new rk signs requests.
	if _, err := testPool.Exec(ctx, `UPDATE key_bundles SET pending_until = now() - interval '1 second' WHERE id = $1 AND seq = 2`, id); err != nil {
		t.Fatal(err)
	}
	if err := e.s.promotePending(ctx); err != nil {
		t.Fatal(err)
	}
	st, body, _ = e.do(t, "GET", "/v1/keys/"+id, "", nil)
	m := kv(body)
	if st != 200 || m["seq"] != "2" || m["pending"] != "0" || m["fp"] != hex.EncodeToString(b2.Fingerprint()) {
		t.Fatalf("promoted: %d %s", st, body)
	}
	leaf, _ := strconv.ParseInt(m["leaf"], 10, 64)
	var kind int16
	if err := testPool.QueryRow(ctx, `SELECT kind FROM klog WHERE idx = $1`, leaf).Scan(&kind); err != nil || kind != KindBundle {
		t.Fatalf("promoted leaf kind: %d %v", kind, err)
	}
	raw3, _ := mkBundle(t, seed2, id, 3, canonHash(t, b2), bopts{policy: e2e.PolicyBoth})
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw3, "X-Cx-Sig", sigHeader(t, seed1, "PUT", "/v1/keys", raw3, 0)); st != 401 {
		t.Fatalf("old rk after promotion: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw3, "X-Cx-Sig", sigHeader(t, seed2, "PUT", "/v1/keys", raw3, 0)); st != 200 {
		t.Fatalf("new rk after promotion: %d %s", st, body)
	}
	if len(mails) != 1 {
		t.Fatalf("a same-key refresh must not notify: %v", mails)
	}
	// One key change per 24 h per root.
	seed3 := mkSeed()
	_, b3 := mkBundle(t, seed2, id, 3, canonHash(t, b2), bopts{policy: e2e.PolicyBoth})
	_ = b3
	cur3, _, err := Bundle(ctx, testPool, id)
	if err != nil {
		t.Fatal(err)
	}
	raw4, _ := mkBundle(t, seed3, id, 4, cur3.Hash, bopts{policy: e2e.PolicyBoth, ikPrev: e2e.IK(seed2)})
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw4, "X-Cx-Sig", sigHeader(t, seed2, "PUT", "/v1/keys", raw4, 0)); st != 429 || !strings.Contains(body, "1 per 24 h") {
		t.Fatalf("second key change within 24 h: %d %s", st, body)
	}
}

func TestTreePullRefused24h(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	seed1, seed2 := mkSeed(), mkSeed()
	id, tok, _, b1 := rootWithBundle(t, e, seed1, e2e.PolicyBoth)
	if ok, err := TreePullAllowed(ctx, testPool, id); err != nil || !ok {
		t.Fatalf("fresh root: %v %v", ok, err)
	}
	raw2, _ := mkBundle(t, seed2, id, 2, canonHash(t, b1), bopts{policy: e2e.PolicyBoth, ikPrev: e2e.IK(seed1)})
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw2, "X-Cx-Sig", sigHeader(t, seed1, "PUT", "/v1/keys", raw2, 0)); st != 202 {
		t.Fatalf("rotation: %d %s", st, body)
	}
	if ok, err := TreePullAllowed(ctx, testPool, id); err != nil || ok {
		t.Fatalf("after key change: %v %v", ok, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE identities SET keys_changed_at = now() - interval '23 hours' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if ok, _ := TreePullAllowed(ctx, testPool, id); ok {
		t.Fatal("23 h after the change must still refuse")
	}
	if _, err := testPool.Exec(ctx, `UPDATE identities SET keys_changed_at = now() - interval '25 hours' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if ok, _ := TreePullAllowed(ctx, testPool, id); !ok {
		t.Fatal("25 h after the change must allow")
	}
	if ok, err := TreePullAllowed(ctx, testPool, "azzzzzz"); err != nil || !ok {
		t.Fatalf("unknown root: %v %v", ok, err)
	}
}

func TestPlainAllowedPolicy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	mail.PolicyFn = PlainAllowed
	t.Cleanup(func() { mail.PolicyFn = nil })
	e2eeID, _, _, _ := rootWithBundle(t, e, mkSeed(), e2e.PolicyE2EE)
	bothID, _, _, _ := rootWithBundle(t, e, mkSeed(), e2e.PolicyBoth)
	plainID, _, _, _ := rootWithBundle(t, e, mkSeed(), e2e.PolicyPlain)
	noneID, noneTok := plainRoot(t, e)
	for _, c := range []struct {
		id   string
		want bool
	}{{e2eeID, false}, {bothID, true}, {plainID, true}, {noneID, true}, {"azzzzzz", true}} {
		if ok, err := mail.PolicyFn(ctx, testPool, c.id); err != nil || ok != c.want {
			t.Fatalf("PlainAllowed(%s) = %v %v, want %v", c.id, ok, err, c.want)
		}
	}
	// A pending (legacy) e2ee bundle never counts.
	raw, _ := mkBundle(t, mkSeed(), noneID, 1, nil, bopts{policy: e2e.PolicyE2EE})
	if st, body, _ := e.do(t, "PUT", "/v1/keys", noneTok, raw); st != 202 {
		t.Fatalf("legacy publish: %d %s", st, body)
	}
	if ok, _ := PlainAllowed(ctx, testPool, noneID); !ok {
		t.Fatal("pending bundle must not refuse plaintext")
	}
	// The sub-key of an e2ee root: the policy is the root's.
	if ok, _ := PlainAllowed(ctx, testPool, e2eeID); ok {
		t.Fatal("e2ee root must refuse plaintext")
	}
}

func TestLegacyPendingPublishContest(t *testing.T) {
	e := newEnv(t, func(mux *http.ServeMux) {
		mux.Handle("POST /v1/sigtest2", RequireSig(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { core.OK(w, r, "ok", nil) })))
	})
	ctx := context.Background()
	id, tok := plainRoot(t, e)
	seedA, seedB := mkSeed(), mkSeed()
	rawA, bA := mkBundle(t, seedA, id, 1, nil, bopts{policy: e2e.PolicyBoth})
	rawB, _ := mkBundle(t, seedB, id, 1, nil, bopts{policy: e2e.PolicyBoth})

	raw2, _ := mkBundle(t, seedA, id, 2, canonHash(t, bA), bopts{policy: e2e.PolicyBoth})
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, raw2); st != 400 || !strings.Contains(body, "seq want=1") {
		t.Fatalf("legacy seq 2: %d %s", st, body)
	}
	st, body, _ := e.do(t, "PUT", "/v1/keys", tok, rawA)
	m := kv(body)
	if st != 202 || m["pending"] != "1" || m["until"] == "" || m["seq"] != "1" {
		t.Fatalf("legacy publish: %d %s", st, body)
	}
	st, body, _ = e.do(t, "GET", "/v1/keys/"+id, "", nil)
	if st != 200 || kv(body)["pending"] != "1" || kv(body)["leaf"] != m["leaf"] || !strings.Contains(body, " until=") {
		t.Fatalf("pending directory: %d %s", st, body)
	}
	if _, found, _ := Bundle(ctx, testPool, id); found {
		t.Fatal("pending must not be the current bundle")
	}
	sb := []byte(`{}`)
	if st, body, _ := e.do(t, "POST", "/v1/sigtest2", tok, sb, "X-Cx-Sig", sigHeader(t, seedA, "POST", "/v1/sigtest2", sb, 0)); st != 403 {
		t.Fatalf("pending rk must not sign: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, rawA); st != 202 || kv(body)["leaf"] != m["leaf"] {
		t.Fatalf("idempotent repeat: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok, rawB); st != 409 || !strings.Contains(body, "err keys contested") {
		t.Fatalf("contest: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "GET", "/v1/keys/"+id, "", nil); st != 409 || !strings.Contains(body, "contested") {
		t.Fatalf("contested directory: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "PUT", "/v1/keys", tok, rawA); st != 409 {
		t.Fatalf("contested identity must stay plaintext-only: %d", st)
	}
	_, body, _ = e.do(t, "GET", "/v1/log/id/"+id, "", nil)
	if strings.Count(body, "\n") != 2 || !strings.Contains(body, " 3 1 ") || !strings.Contains(body, " 2 1 ") {
		t.Fatalf("contest leaves: %s", body)
	}
	if n := count(t, `SELECT count(*) FROM key_bundles WHERE id = $1 AND state = 'void'`, id); n != 1 {
		t.Fatalf("void rows: %d", n)
	}
	// Uncontested for 24 h: the bundle becomes current through a kind 1 leaf.
	id2, tok2 := plainRoot(t, e)
	seedC := mkSeed()
	rawC, bC := mkBundle(t, seedC, id2, 1, nil, bopts{policy: e2e.PolicyE2EE})
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok2, rawC); st != 202 {
		t.Fatalf("legacy publish 2: %d %s", st, body)
	}
	if err := e.s.promotePending(ctx); err != nil {
		t.Fatal(err)
	}
	if st, body, _ := e.do(t, "GET", "/v1/keys/"+id2, "", nil); st != 200 || kv(body)["pending"] != "1" {
		t.Fatalf("promoted before the window: %d %s", st, body)
	}
	if _, err := testPool.Exec(ctx, `UPDATE key_bundles SET pending_until = now() - interval '1 second' WHERE id = $1`, id2); err != nil {
		t.Fatal(err)
	}
	if err := e.s.promotePending(ctx); err != nil {
		t.Fatal(err)
	}
	st, body, _ = e.do(t, "GET", "/v1/keys/"+id2, "", nil)
	if st != 200 || kv(body)["pending"] != "0" || kv(body)["seq"] != "1" || kv(body)["fp"] != hex.EncodeToString(bC.Fingerprint()) {
		t.Fatalf("promoted: %d %s", st, body)
	}
	if ok, _ := PlainAllowed(ctx, testPool, id2); ok {
		t.Fatal("promoted e2ee bundle must refuse plaintext")
	}
	_, body, _ = e.do(t, "GET", "/v1/log/id/"+id2, "", nil)
	if strings.Count(body, "\n") != 2 || !strings.Contains(body, " 3 1 ") || !strings.Contains(body, " 1 1 ") {
		t.Fatalf("promotion leaves: %s", body)
	}
	// From here on the identity is a normal one: seq 2 needs the signature.
	raw2c, _ := mkBundle(t, seedC, id2, 2, canonHash(t, bC), bopts{policy: e2e.PolicyE2EE})
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok2, raw2c); st != 401 {
		t.Fatalf("post-promotion unsigned put: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "PUT", "/v1/keys", tok2, raw2c, "X-Cx-Sig", sigHeader(t, seedC, "PUT", "/v1/keys", raw2c, 0)); st != 200 {
		t.Fatalf("post-promotion signed put: %d %s", st, body)
	}
}

func TestPurgeTombstonesAndRevokedDirectory(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	seed := mkSeed()
	id, _, _, b := rootWithBundle(t, e, seed, e2e.PolicyBoth)
	before, _ := LogSize(ctx, testPool)
	if _, err := e.d.Purge(ctx, id); err != nil {
		t.Fatal(err)
	}
	st, body, _ := e.do(t, "GET", "/v1/keys/"+id, "", nil)
	if st != 410 || !strings.HasPrefix(body, "err revoked at=") {
		t.Fatalf("revoked directory: %d %s", st, body)
	}
	var kind int16
	var item []byte
	if err := testPool.QueryRow(ctx, `SELECT kind, item_hash FROM klog WHERE idx = $1 AND id = $2`, int64(before), id).Scan(&kind, &item); err != nil || kind != KindTombstone || !bytes.Equal(item, canonHash(t, b)) {
		t.Fatalf("tombstone leaf: kind=%d err=%v", kind, err)
	}
	h, err := e.s.latestHead(ctx, testPool)
	if err != nil || h.Size != before+1 {
		t.Fatalf("head after tombstone: %+v %v", h, err)
	}
	if ok, _ := PlainAllowed(ctx, testPool, id); !ok {
		t.Fatal("a revoked e2ee identity has no policy")
	}
}

func TestOnlineKeyCertificate(t *testing.T) {
	rootPub, rootSK, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("SERVER_ROOT_PUB", b64(rootPub))
	e := newEnv(t)
	online := e.onlinePub(t)
	_, body, _ := e.do(t, "GET", "/v1/keys/server", "", nil)
	if kv(body)["root"] != b64(rootPub) || kv(body)["self"] == "1" {
		t.Fatalf("server line: %s", body)
	}
	now := uint64(time.Now().Unix())
	seq := uint32(time.Now().UnixNano()%1_000_000) + 1 // the scratch database persists between runs
	mk := func(seq uint32, nbf, exp uint64, sk ed25519.PrivateKey) string {
		return b64(EncodeCert(online, nbf, exp, seq, e2e.Sign(sk, e2e.CertBytes(online, nbf, exp, seq))))
	}
	post := func(cert string) (int, string) {
		j, _ := json.Marshal(map[string]string{"cert": cert})
		st, body, _ := e.do(t, "POST", "/admin/online-key", "adm-token", j)
		return st, body
	}
	if st, body := post(mk(seq, now, now+86400, ed25519.NewKeyFromSeed(make([]byte, 32)))); st != 400 {
		t.Fatalf("cert under a stranger key: %d %s", st, body)
	}
	if st, body := post(mk(seq, now, now+40*86400, rootSK)); st != 400 || !strings.Contains(body, "30 d") {
		t.Fatalf("overlong cert: %d %s", st, body)
	}
	if st, body := post(mk(seq, now-100, now+30*86400, rootSK)); st != 200 || kv(body)["seq"] != strconv.FormatUint(uint64(seq), 10) {
		t.Fatalf("install: %d %s", st, body)
	}
	if st, _ := post(mk(seq, now-100, now+30*86400, rootSK)); st != 409 {
		t.Fatalf("duplicate seq: %d", st)
	}
	st, body, _ := e.do(t, "GET", "/v1/log/sth", "", nil)
	h, cert, err := e2e.ParseSTHLine(body)
	if st != 200 || err != nil {
		t.Fatalf("sth: %d %s", st, body)
	}
	c, err := ParseCert(cert)
	if err != nil || c.Seq != seq || c.Verify(rootPub, online, time.Now().Unix()) != nil || !e2e.Verify(online, e2e.STHBytes(h.Size, h.Root, h.At), h.Sig) {
		t.Fatalf("root-signed chain: %v", err)
	}
	if st, body, _ := e.do(t, "POST", "/admin/online-key", "", []byte(`{"cert":"x"}`)); st != 401 {
		t.Fatalf("admin gate: %d %s", st, body)
	}
}
