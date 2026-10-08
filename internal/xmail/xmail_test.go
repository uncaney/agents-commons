package xmail

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/pow"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/testdb"
)

var pool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		p, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if _, err := p.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, p); err != nil {
			panic(err)
		}
		pool, cleanup = p, p.Close
	} else if p, done := testdb.Open("xmail", core.Migrate); p != nil {
		pool, cleanup = p, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping xmail DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

const testSecret = "test-secret-0123456789abcdef"

type env struct {
	d      *core.Deps
	srv    *httptest.Server
	ops    map[string]Op
	signer *sign.Signer
	ip     string
}

// newEnv wires core, sign, keys, mail and this package behind core.Handler.
func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte(testSecret), AdminToken: "adm-token", SignKID: 1, PowBits: 6, PowBitsW: 2, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", MirrorURL: "https://github.com/example/mirror", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	core.RegisterAuthV2(mux, d)
	sign.Register(mux, d)
	keys.Register(mux, d)
	mail.Register(mux, d)
	Register(mux, d)
	core.SysMailFn = mail.SendSys
	t.Cleanup(func() { core.SysMailFn = nil })
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	signer, err := sign.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &env{d: d, srv: srv, ops: Ops(d), signer: signer, ip: randIP()}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

func (e *env) do(t *testing.T, method, path, token string, body []byte, hdr ...string) (int, string, http.Header) {
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

func count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// ident is a test identity: a root with its seed, revoke code and seq-1 bundle (five epochs from
// the previous one, so the current and the previous epoch are both listed).
type ident struct {
	id, tok string
	root    string
	seed    []byte
	rev     []byte
	b       *e2e.Bundle
}

func mkBundle(t *testing.T, seed []byte, id string, seq uint32, prevHash []byte, policy uint8, rev []byte, ikPrev ed25519.PrivateKey) ([]byte, *e2e.Bundle) {
	t.Helper()
	now := time.Now().Unix()
	b, err := e2e.NewBundle(seed, e2e.BundleParams{ID: id, Seq: seq, IAT: uint32(now), Exp: uint32(now + 30*86400), Flags: e2e.FlagLKOK,
		MailPolicy: policy, MinCS: uint8(e2e.CS1), E0: e2e.Epoch(now) - 1, NEK: 5, RevCommit: e2e.Sum(rev), PrevHash: prevHash})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Sign(e2e.IK(seed), ikPrev, nil)
	if err != nil {
		t.Fatal(err)
	}
	return raw, b
}

// mkIdent mints a root aged `age` with a published bundle of the given mail policy.
func mkIdent(t *testing.T, policy uint8, age time.Duration) *ident {
	t.Helper()
	ctx := context.Background()
	in := &ident{seed: e2e.NewSeed(), rev: make([]byte, 32)}
	rand.Read(in.rev)
	err := core.Tx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		if in.id, in.tok, err = core.CreateRoot(ctx, tx, "x-test", randIP()); err != nil {
			return err
		}
		in.root = in.id
		if _, err := tx.Exec(ctx, `UPDATE identities SET created = now() - $2::interval WHERE id = $1`, in.id, age.String()); err != nil {
			return err
		}
		raw, b := mkBundle(t, in.seed, in.id, 1, nil, policy, in.rev, nil)
		in.b = b
		enc, _ := json.Marshal(b64(raw))
		return keys.RegisterBundle(ctx, tx, in.id, enc)
	})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func plainRoot(t *testing.T) (id, tok string) {
	t.Helper()
	id, tok, err := core.CreateRoot(context.Background(), pool, "x-plain", randIP())
	if err != nil {
		t.Fatal(err)
	}
	pool.Exec(context.Background(), `UPDATE identities SET created = now() - interval '2 hours' WHERE id = $1`, id)
	return id, tok
}

// sigFor signs a request with the seed's rk (fresh nonce, now).
func sigFor(t *testing.T, seed []byte, method, pathQuery string, body []byte) string {
	t.Helper()
	nonce := make([]byte, e2e.NonceSize)
	rand.Read(nonce)
	h, err := e2e.SignReq(e2e.RK(seed), method, pathQuery, uint64(time.Now().Unix()), nonce, body)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// signed does a request carrying X-Cx-Sig under the caller's rk.
func (e *env) signed(t *testing.T, who *ident, method, path string, body []byte, hdr ...string) (int, string, http.Header) {
	t.Helper()
	return e.do(t, method, path, who.tok, body, append([]string{"X-Cx-Sig", sigFor(t, who.seed, method, path, body)}, hdr...)...)
}

// seal builds a real cxm1 envelope from `from` to `to` with internal/e2e (cs=1, the given epoch).
func seal(t *testing.T, from, to *ident, payload []byte, epoch uint32) []byte {
	t.Helper()
	key, ok := to.b.EK(e2e.CS1, epoch)
	if !ok {
		t.Fatalf("recipient bundle does not list epoch %d", epoch)
	}
	s, err := e2e.Seal(e2e.SealParams{CS: e2e.CS1, From: from.id, To: to.id, Epoch: epoch, Pol: 1, TS: uint32(time.Now().Unix()), Type: e2e.TypeText,
		Payload: payload, RecipientKey: key, SenderAK: e2e.AK(from.seed), RecipientAK: to.b.AK})
	if err != nil {
		t.Fatal(err)
	}
	return s.Envelope
}

// open opens an envelope with the recipient's seed and the sender's directory ak.
func open(to, from *ident, envb []byte) (*e2e.Inner, error) {
	e, err := e2e.ParseEnvelope(envb)
	if err != nil {
		return nil, err
	}
	sk, err := e2e.EK(to.seed, e2e.CS1, e.Epoch, nil)
	if err != nil {
		return nil, err
	}
	return e.Open(e2e.OpenParams{Me: to.id, RecipientKey: sk, RecipientAK: e2e.AK(to.seed), SenderAK: from.b.AK})
}

func curEpoch() uint32 { return e2e.Epoch(time.Now().Unix()) }

func (e *env) send(t *testing.T, from, to *ident, envb []byte, hdr ...string) (int, string) {
	t.Helper()
	st, body, _ := e.signed(t, from, "POST", "/v1/x/"+to.id, envb, hdr...)
	return st, body
}

// openInbox puts the recipient's inbox in open mode (no stamps, no cold rule) for tests about other gates.
func (e *env) openInbox(t *testing.T, who *ident) {
	t.Helper()
	if st, body, _ := e.signed(t, who, "PUT", "/v1/x/policy", []byte(`{"mode":"open"}`)); st != 200 || !strings.Contains(body, "mode=open") {
		t.Fatalf("policy open: %d %s", st, body)
	}
}

// befriend records that b already wrote to a (the reverse pair of 11), so a's sends to b are a
// known pair: no stamp, no one-unacked-per-cold-pair rule.
func befriend(t *testing.T, a, b *ident) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `INSERT INTO mb_pairs (from_root, to_root, sent) VALUES ($1, $2, 1) ON CONFLICT DO NOTHING`, b.root, a.root); err != nil {
		t.Fatal(err)
	}
}

func seqOf(t *testing.T, body string) int64 {
	t.Helper()
	n, err := strconv.ParseInt(kv(body)["seq"], 10, 64)
	if err != nil {
		t.Fatalf("no seq in %q", body)
	}
	return n
}

// --- tests --------------------------------------------------------------------------------------

func TestSendRequiresSigAndBundle(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, bob)
	befriend(t, alice, bob)
	envb := seal(t, alice, bob, []byte("hello bob"), curEpoch())

	// no signature
	if st, body, _ := e.do(t, "POST", "/v1/x/"+bob.id, alice.tok, envb); st != 401 || !strings.Contains(body, "X-Cx-Sig required") {
		t.Fatalf("unsigned: %d %s", st, body)
	}
	// a bearer alone: a signature by another seed
	bad := sigFor(t, e2e.NewSeed(), "POST", "/v1/x/"+bob.id, envb)
	if st, body, _ := e.do(t, "POST", "/v1/x/"+bob.id, alice.tok, envb, "X-Cx-Sig", bad); st != 401 || !strings.Contains(body, "err sig") {
		t.Fatalf("wrong signer: %d %s", st, body)
	}
	// a sender without a published bundle cannot sign at all
	pid, ptok := plainRoot(t)
	pseed := e2e.NewSeed()
	fake := seal(t, &ident{id: pid, seed: pseed, b: alice.b}, bob, []byte("x"), curEpoch())
	if st, body, _ := e.do(t, "POST", "/v1/x/"+bob.id, ptok, fake, "X-Cx-Sig", sigFor(t, pseed, "POST", "/v1/x/"+bob.id, fake)); st != 403 || !strings.Contains(body, "no key published") {
		t.Fatalf("no bundle sender: %d %s", st, body)
	}
	// a recipient without a bundle has no sealed inbox
	toPlain := seal(t, alice, &ident{id: pid, b: bob.b}, []byte("x"), curEpoch())
	if st, body := e.send(t, alice, &ident{id: pid}, toPlain); st != 404 || !strings.Contains(body, "no sealed inbox") {
		t.Fatalf("no bundle recipient: %d %s", st, body)
	}
	// the signed, well-formed send is accepted and the row holds exactly the 8.2 fields
	st, body := e.send(t, alice, bob, envb)
	if st != 201 || !strings.HasPrefix(body, "ok seq=") {
		t.Fatalf("send: %d %s", st, body)
	}
	seq := seqOf(t, body)
	var fromID, fromRoot string
	var size int
	var hdr []byte
	if err := pool.QueryRow(context.Background(), `SELECT from_id, from_root, size, hdr FROM x_env WHERE to_id = $1 AND seq = $2`, bob.id, seq).Scan(&fromID, &fromRoot, &size, &hdr); err != nil {
		t.Fatal(err)
	}
	if fromID != alice.id || fromRoot != alice.id || size != len(envb) || !bytes.Equal(hdr, envb[:e2e.HdrLen]) {
		t.Fatalf("row: from=%s root=%s size=%d", fromID, fromRoot, size)
	}
	if n := count(t, `SELECT count(*) FROM x_ledger WHERE to_id = $1 AND seq = $2 AND length(send_sig) = 64`, bob.id, seq); n != 1 {
		t.Fatalf("ledger rows: %d", n)
	}
	// a replayed request (same nonce) is refused; the same envelope under a fresh signature is a dup
	path := "/v1/x/" + bob.id
	sig := sigFor(t, alice.seed, "POST", path, envb)
	if st, body, _ := e.do(t, "POST", path, alice.tok, envb, "X-Cx-Sig", sig); st != 409 || !strings.Contains(body, "dup") {
		t.Fatalf("dup mid: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", path, alice.tok, envb, "X-Cx-Sig", sig); st != 409 || !strings.Contains(body, "nonce replayed") {
		t.Fatalf("nonce replay: %d %s", st, body)
	}
}

// TestRoundTripAndTamper is the acceptance scenario: a sealed send produced with internal/e2e goes
// through POST /v1/x and GET /v1/x/{seq} and opens with the recipient's seed; a tampered envelope is
// refused at send (frank mismatch: header from/to do not match the signer or the route).
func TestRoundTripAndTamper(t *testing.T) {
	e := newEnv(t)
	alice, bob, carol := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyE2EE, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, bob)
	befriend(t, alice, bob)
	payload := []byte("the quick brown fox, sealed")
	envb := seal(t, alice, bob, payload, curEpoch())
	st, body := e.send(t, alice, bob, envb)
	if st != 201 {
		t.Fatalf("send: %d %s", st, body)
	}
	seq := seqOf(t, body)
	st, raw, hdr := e.do(t, "GET", "/v1/x/"+strconv.FormatInt(seq, 10), bob.tok, nil)
	if st != 200 || hdr.Get("Content-Type") != "application/octet-stream" || !bytes.Equal([]byte(raw), envb) {
		t.Fatalf("get: %d ct=%s len=%d want %d", st, hdr.Get("Content-Type"), len(raw), len(envb))
	}
	if hdr.Get("X-Cx-Rcpt") != kv(body)["rcpt"] || hdr.Get("X-Cx-Send-Sig") == "" || hdr.Get("X-Cx-At") != kv(body)["at"] {
		t.Fatalf("receipt headers: %v vs %s", hdr, body)
	}
	in, err := open(bob, alice, []byte(raw))
	if err != nil || !bytes.Equal(in.Payload, payload) || in.Type != e2e.TypeText {
		t.Fatalf("open: %v", err)
	}
	// the stored send signature verifies as alice's request signature over this envelope
	ss, err := e2e.ParseSendSig(hdr.Get("X-Cx-Send-Sig"))
	if err != nil || !ss.VerifyHash(alice.b.RK, "POST", "/v1/x/"+bob.id, e2e.Sum(envb)) {
		t.Fatalf("send_sig: %v", err)
	}
	// tampered at the wire: a byte of the ciphertext flips -> the recipient's open fails closed
	flip := append([]byte(nil), envb...)
	flip[e2e.HdrLen+32+5] ^= 1
	if _, err := open(bob, alice, flip); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
	// tampered header: `to` says carol but the route says bob -> frank mismatch at send
	wrongTo := seal(t, alice, carol, payload, curEpoch())
	if st, body := e.send(t, alice, bob, wrongTo); st != 400 || !strings.Contains(body, "err frank mismatch") {
		t.Fatalf("to mismatch: %d %s", st, body)
	}
	// header `from` says carol but alice signs -> frank mismatch at send
	wrongFrom := seal(t, carol, bob, payload, curEpoch())
	if st, body := e.send(t, alice, bob, wrongFrom); st != 400 || !strings.Contains(body, "err frank mismatch") {
		t.Fatalf("from mismatch: %d %s", st, body)
	}
	// a patched client that commits to another payload than it seals: relayed (the server cannot
	// know), dropped by the recipient before the agent sees a byte (ErrFrank)
	kf := e2e.Sum([]byte("kf"))
	inner, _ := (&e2e.Inner{KF: kf, TS: uint32(time.Now().Unix()), Type: e2e.TypeText, Payload: payload}).Marshal()
	padded, _ := e2e.Pad(inner, e2e.MailBuckets)
	mid := make([]byte, 16)
	rand.Read(mid)
	h := e2e.Hdr{CS: e2e.CS1, From: alice.id, To: bob.id, Epoch: curEpoch(), Mid: mid, C: e2e.Frank(kf, alice.id, bob.id, mid, e2e.TypeText, []byte("something innocent"))}
	hb := h.Marshal()
	ek, _ := bob.b.EK(e2e.CS1, curEpoch())
	pk, _ := e2e.CS1.NewPublicKey(ek)
	enc, snd, err := hpke.NewSender(pk, e2e.KDF(), e2e.AEAD(), e2e.MailInfo(alice.id, bob.id, curEpoch()))
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := snd.Seal(hb, padded)
	exp, _ := snd.Export(e2e.LabelAuth, 32)
	rpk, _ := ecdh.X25519().NewPublicKey(bob.b.AK)
	ssk, _ := e2e.AK(alice.seed).ECDH(rpk)
	mac := e2e.SenderMAC(e2e.AuthKey(ssk, exp, alice.id, bob.id), hb, enc, ct)
	dishonest := append(append(append(append([]byte(nil), hb...), enc...), ct...), mac...)
	if st, body := e.send(t, alice, bob, dishonest); st != 201 {
		t.Fatalf("dishonest relayed: %d %s", st, body)
	}
	if _, err := open(bob, alice, dishonest); !errors.Is(err, e2e.ErrFrank) {
		t.Fatalf("frank mismatch at open: %v", err)
	}
}

func TestFrankReceiptSigned(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, bob)
	envb := seal(t, alice, bob, []byte("receipt me"), curEpoch())
	st, body := e.send(t, alice, bob, envb)
	if st != 201 {
		t.Fatalf("send: %d %s", st, body)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[1], "frank1 ") || !strings.HasPrefix(lines[2], "sig=") {
		t.Fatalf("reply shape: %q", body)
	}
	m := kv(lines[0])
	seq, _ := strconv.ParseUint(m["seq"], 10, 64)
	at, _ := strconv.ParseUint(m["at"], 10, 64)
	rcpt, err := decodeB64(m["rcpt"])
	if err != nil || len(rcpt) != 64 {
		t.Fatalf("rcpt: %v", err)
	}
	// rcpt = Ed25519(server key, "cx1/rcpt" || hdr || u64(seq) || u64(at))
	if !e2e.VerifyRcpt(e.signer.Public(), envb[:e2e.HdrLen], seq, at, rcpt) {
		t.Fatal("rcpt does not verify over the header")
	}
	if e2e.VerifyRcpt(e.signer.Public(), envb[:e2e.HdrLen], seq+1, at, rcpt) {
		t.Fatal("rcpt verifies for another seq")
	}
	// the frank1 statement names mid, C, from, box, seq, at and verifies under the published key
	f := kv(lines[1])
	env, _ := e2e.ParseEnvelope(envb)
	if f["m"] != b64(env.Mid) || f["c"] != fmt.Sprintf("%x", env.C) || f["f"] != alice.id || f["b"] != bob.id || f["n"] != m["seq"] || f["t"] != m["at"] || f["k"] != "1" {
		t.Fatalf("frank line: %s", lines[1])
	}
	if kid, ok := e.signer.Verify(TypeFrank, lines[1], lines[2]); !ok || kid != 1 {
		t.Fatalf("frank1 signature: ok=%v kid=%d", ok, kid)
	}
	if _, ok := e.signer.Verify(TypeFrank, strings.Replace(lines[1], "n="+m["seq"], "n=1", 1), lines[2]); ok {
		t.Fatal("altered frank line verified")
	}
	// the public verifier of the sign package accepts it too
	st, vbody, _ := e.do(t, "GET", "/verify?s="+strings.ReplaceAll(strings.ReplaceAll(lines[1], " ", "%20"), "=", "%3D")+"&sig="+strings.TrimPrefix(lines[2], "sig="), "", nil)
	if st != 200 || !strings.HasPrefix(vbody, "valid kid=1 type=frank1") {
		t.Fatalf("/verify: %d %s", st, vbody)
	}
	// the ledger carries the same receipt, and the listing shows it
	var lrcpt []byte
	if err := pool.QueryRow(context.Background(), `SELECT rcpt FROM x_ledger WHERE to_id = $1 AND seq = $2`, bob.id, int64(seq)).Scan(&lrcpt); err != nil || !bytes.Equal(lrcpt, rcpt) {
		t.Fatalf("ledger rcpt: %v", err)
	}
	st, list, _ := e.do(t, "GET", "/v1/x/in", bob.tok, nil)
	if st != 200 || !strings.Contains(list, "rcpt="+m["rcpt"]) {
		t.Fatalf("listing: %d %s", st, list)
	}
}

func TestBucketsEnforced(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, bob)
	befriend(t, alice, bob)
	live := count(t, `SELECT n FROM x_bytes WHERE k = 'live'`)
	small := seal(t, alice, bob, []byte("1k"), curEpoch())
	big := seal(t, alice, bob, bytes.Repeat([]byte("x"), 3000), curEpoch())
	if len(small) != e2e.EnvelopeSize(e2e.CS1, 1024) || len(big) != e2e.EnvelopeSize(e2e.CS1, 4096) {
		t.Fatalf("sizes %d %d", len(small), len(big))
	}
	for _, c := range []struct {
		what string
		env  []byte
		want string
	}{
		{"one extra byte", append(append([]byte(nil), small...), 0), "err size bucket"},
		{"one byte short", small[:len(small)-1], "err size bucket"},
		{"cs says 2, enc is 32 bytes", func() []byte { b := append([]byte(nil), small...); b[1] = 2; return b }(), "err size bucket"},
		{"over the cap", bytes.Repeat([]byte{1}, e2e.MailCap+1), "err size"},
	} {
		st, body := e.send(t, alice, bob, c.env)
		if st != 413 || !strings.Contains(body, c.want) {
			t.Fatalf("%s: %d %s", c.what, st, body)
		}
	}
	if st, body := e.send(t, alice, bob, []byte{0x02, 1, 0}); st != 413 && st != 400 {
		t.Fatalf("garbage: %d %s", st, body)
	}
	if st, body := e.send(t, alice, bob, small); st != 201 {
		t.Fatalf("1k: %d %s", st, body)
	}
	st, body := e.send(t, alice, bob, big)
	if st != 201 {
		t.Fatalf("4k: %d %s", st, body)
	}
	st, list, _ := e.do(t, "GET", "/v1/x/in", bob.tok, nil)
	if st != 200 || !strings.Contains(list, "bucket=1k") || !strings.Contains(list, "bucket=4k") {
		t.Fatalf("buckets in listing: %s", list)
	}
	if n := count(t, `SELECT n FROM x_bytes WHERE k = 'live'`); n != live+len(small)+len(big) {
		t.Fatalf("live bytes %d want %d", n, live+len(small)+len(big))
	}
}

func TestEnvelopesNeverBodies(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, bob)
	befriend(t, alice, bob)
	var envs [][]byte
	var seqs []int64
	for i := 0; i < 3; i++ {
		envb := seal(t, alice, bob, []byte(fmt.Sprintf("secret payload %d", i)), curEpoch())
		st, body := e.send(t, alice, bob, envb, "X-Scrub-V", strconv.Itoa(scrub.RulesV))
		if st != 201 {
			t.Fatalf("send %d: %d %s", i, st, body)
		}
		envs = append(envs, envb)
		seqs = append(seqs, seqOf(t, body))
	}
	if seqs[1] != seqs[0]+1 || seqs[2] != seqs[1]+1 || seqs[0] < 2 {
		t.Fatalf("seqs not contiguous from a random offset: %v", seqs)
	}
	st, list, _ := e.do(t, "GET", "/v1/x/in", bob.tok, nil)
	if st != 200 {
		t.Fatalf("in: %d %s", st, list)
	}
	lines := strings.Split(strings.TrimSpace(list), "\n")
	if len(lines) != 4 || lines[3] != "next="+strconv.FormatInt(seqs[2], 10) {
		t.Fatalf("listing: %q", list)
	}
	for i, l := range lines[:3] {
		want := fmt.Sprintf("%d from %s ", seqs[i], alice.id)
		if !strings.HasPrefix(l, want) || !strings.Contains(l, "enc=1 bucket=1k cs=1 scrub=client") || !strings.Contains(l, " sig=") {
			t.Fatalf("line %d: %s", i, l)
		}
		for _, enc := range []string{b64(envs[i]), fmt.Sprintf("%x", envs[i][e2e.HdrLen+32:e2e.HdrLen+64])} {
			if strings.Contains(list, enc) {
				t.Fatal("listing carries ciphertext")
			}
		}
	}
	// after= and k= drive the cursor; the body of one row comes from GET /v1/x/{seq}
	st, list, _ = e.do(t, "GET", fmt.Sprintf("/v1/x/in?after=%d&k=1", seqs[0]), bob.tok, nil)
	if st != 200 || !strings.HasPrefix(list, strconv.FormatInt(seqs[1], 10)+" ") || !strings.HasSuffix(strings.TrimSpace(list), "next="+strconv.FormatInt(seqs[1], 10)) {
		t.Fatalf("after/k: %q", list)
	}
	if st, _, _ := e.do(t, "GET", "/v1/x/in?k=99", bob.tok, nil); st != 400 {
		t.Fatalf("k cap: %d", st)
	}
	st, raw, _ := e.do(t, "GET", "/v1/x/"+strconv.FormatInt(seqs[1], 10), bob.tok, nil)
	if st != 200 || !bytes.Equal([]byte(raw), envs[1]) {
		t.Fatalf("get: %d", st)
	}
	// JSON form of the listing never carries the envelope either
	st, j, _ := e.do(t, "GET", "/v1/x/in?f=json", bob.tok, nil)
	if st != 200 || strings.Contains(j, b64(envs[0])) || !strings.Contains(j, `"bucket":"1k"`) {
		t.Fatalf("json listing: %s", j)
	}
	// another identity never sees bob's rows; a url-class token lists envelopes but reads no body
	if st, _, _ := e.do(t, "GET", "/v1/x/"+strconv.FormatInt(seqs[1], 10), alice.tok, nil); st != 404 {
		t.Fatalf("foreign get: %d", st)
	}
	bobIdent, err := e.d.LookupToken(context.Background(), bob.tok)
	if err != nil {
		t.Fatal(err)
	}
	_, utok, err := core.CreateSubkeyV2(context.Background(), pool, bobIdent, core.SubkeyOpts{Name: "url", Class: "url", Exp: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if st, _, _ := e.do(t, "GET", "/v1/x/in", utok, nil); st != 200 {
		t.Fatalf("url token listing: %d", st)
	}
	if st, _, _ := e.do(t, "GET", "/v1/x/"+strconv.FormatInt(seqs[1], 10), utok, nil); st != 403 {
		t.Fatalf("url token body: %d", st)
	}
	// ack deletes the ciphertext (forward secrecy on the relay); the ledger twin stays
	if st, body, _ := e.do(t, "DELETE", "/v1/x/"+strconv.FormatInt(seqs[0], 10), bob.tok, nil); st != 401 {
		t.Fatalf("unsigned ack: %d %s", st, body)
	}
	st, body, _ := e.signed(t, bob, "DELETE", fmt.Sprintf("/v1/x/%d?upto=1", seqs[1]), nil)
	if st != 200 || body != "ok n=2\n" {
		t.Fatalf("ack upto: %d %s", st, body)
	}
	if n := count(t, `SELECT count(*) FROM x_env WHERE to_id = $1`, bob.id); n != 1 {
		t.Fatalf("rows after ack: %d", n)
	}
	if n := count(t, `SELECT count(*) FROM x_ledger WHERE to_id = $1`, bob.id); n != 3 {
		t.Fatalf("ledger after ack: %d", n)
	}
	if n := count(t, `SELECT rows FROM x_inbox WHERE id = $1`, bob.id); n != 1 {
		t.Fatalf("inbox rows counter: %d", n)
	}
	st, list, _ = e.do(t, "GET", "/v1/x/in", bob.tok, nil)
	if st != 200 || !strings.HasPrefix(list, strconv.FormatInt(seqs[2], 10)+" ") {
		t.Fatalf("listing after ack: %s", list)
	}
	// long-poll: a wait returns on arrival
	e.signed(t, bob, "DELETE", fmt.Sprintf("/v1/x/%d?upto=1", seqs[2]), nil)
	done := make(chan string, 1)
	go func() {
		_, body, _ := e.do(t, "GET", "/v1/x/in?wait=8", bob.tok, nil)
		done <- body
	}()
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	e.send(t, alice, bob, seal(t, alice, bob, []byte("wake"), curEpoch()))
	select {
	case body := <-done:
		if !strings.Contains(body, "from "+alice.id) || time.Since(start) > 5*time.Second {
			t.Fatalf("long-poll: %q after %s", body, time.Since(start))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("long-poll never returned")
	}
	// leases: one poller per identity
	if st, body, _ := e.signed(t, bob, "POST", "/v1/x/lease", []byte(`{"dev":"laptop"}`)); st != 200 || !strings.HasPrefix(body, "ok until=") {
		t.Fatalf("lease: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, bob, "POST", "/v1/x/lease", []byte(`{"dev":"phone"}`)); st != 409 || !strings.Contains(body, "err busy lease=laptop") {
		t.Fatalf("second lease: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "GET", "/v1/x/in", bob.tok, nil, "X-Cx-Dev", "phone"); st != 409 || !strings.Contains(body, "lease=laptop") {
		t.Fatalf("poll under another lease: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/v1/x/in?dev=laptop", bob.tok, nil); st != 200 {
		t.Fatalf("poll as the holder: %d", st)
	}
	if st, body, _ := e.signed(t, bob, "POST", "/v1/x/lease", []byte(`{"dev":"laptop"}`)); st != 200 {
		t.Fatalf("renew: %d %s", st, body)
	}
}

func TestPolicyE2EERefusesPlaintextViaMailPolicyFn(t *testing.T) {
	e := newEnv(t)
	mail.PolicyFn = keys.PlainAllowed
	t.Cleanup(func() { mail.PolicyFn = nil })
	ctx := context.Background()
	alice := mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	sealedOnly, both := mkIdent(t, e2e.PolicyE2EE, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	for _, r := range []*ident{sealedOnly, both} {
		if _, err := pool.Exec(ctx, `INSERT INTO mb_boxes (box, owner_root, mode) VALUES ($1, $1, 'open')`, r.id); err != nil {
			t.Fatal(err)
		}
	}
	st, body, _ := e.do(t, "POST", "/v1/mb/"+sealedOnly.id, alice.tok, []byte(`{"text":"plain hello"}`))
	if st != 403 || !strings.Contains(body, "err policy e2ee") {
		t.Fatalf("plaintext to an e2ee recipient: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/v1/mb/"+both.id, alice.tok, []byte(`{"text":"plain hello"}`)); st != 201 {
		t.Fatalf("plaintext to a both recipient: %d %s", st, body)
	}
	// the sealed lane takes the same recipient
	e.openInbox(t, sealedOnly)
	if st, body := e.send(t, alice, sealedOnly, seal(t, alice, sealedOnly, []byte("sealed hello"), curEpoch())); st != 201 {
		t.Fatalf("sealed to an e2ee recipient: %d %s", st, body)
	}
	// the sealed inbox policy: closed and allow modes
	if st, body, _ := e.signed(t, both, "PUT", "/v1/x/policy", []byte(`{"mode":"closed"}`)); st != 200 {
		t.Fatalf("closed: %d %s", st, body)
	}
	if st, body := e.send(t, alice, both, seal(t, alice, both, []byte("x"), curEpoch())); st != 403 || !strings.Contains(body, "err policy closed") {
		t.Fatalf("send to closed: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, both, "PUT", "/v1/x/policy", []byte(`{"mode":"allow","allow":["`+sealedOnly.id+`"]}`)); st != 200 || !strings.Contains(body, "allow="+sealedOnly.id) {
		t.Fatalf("allow: %d %s", st, body)
	}
	if st, body := e.send(t, alice, both, seal(t, alice, both, []byte("x"), curEpoch())); st != 403 || !strings.Contains(body, "err policy allow") {
		t.Fatalf("send not on allow list: %d %s", st, body)
	}
	if st, body := e.send(t, sealedOnly, both, seal(t, sealedOnly, both, []byte("x"), curEpoch())); st != 201 {
		t.Fatalf("send on allow list: %d %s", st, body)
	}
	st, body, _ = e.do(t, "GET", "/v1/x/policy", both.tok, nil)
	if st != 200 || !strings.HasPrefix(body, "mode=allow bits=") || !strings.Contains(body, "poll=early allow="+sealedOnly.id+" blocks=-") {
		t.Fatalf("policy get: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, both, "PUT", "/v1/x/policy", []byte(`{"mode":"loud"}`)); st != 400 {
		t.Fatalf("bad mode: %d %s", st, body)
	}
}

func TestBlocksPhantomOk(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, bob)
	if st, body, _ := e.do(t, "PUT", "/v1/x/block", bob.tok, []byte(`{"id":"`+alice.id+`"}`)); st != 401 {
		t.Fatalf("unsigned block: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, bob, "PUT", "/v1/x/block", []byte(`{"id":"`+alice.id+`"}`)); st != 200 || body != "ok blocked="+alice.id+"\n" {
		t.Fatalf("block: %d %s", st, body)
	}
	envb := seal(t, alice, bob, []byte("spam"), curEpoch())
	st, body := e.send(t, alice, bob, envb)
	if st != 201 || !strings.HasPrefix(body, "ok seq=") {
		t.Fatalf("phantom: %d %s", st, body)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	m := kv(lines[0])
	seq, _ := strconv.ParseUint(m["seq"], 10, 64)
	at, _ := strconv.ParseUint(m["at"], 10, 64)
	rcpt, _ := decodeB64(m["rcpt"])
	if !e2e.VerifyRcpt(e.signer.Public(), envb[:e2e.HdrLen], seq, at, rcpt) {
		t.Fatal("phantom receipt does not verify: a blocked sender could tell")
	}
	if _, ok := e.signer.Verify(TypeFrank, lines[1], lines[2]); !ok {
		t.Fatal("phantom frank1 line does not verify")
	}
	if n := count(t, `SELECT count(*) FROM x_env WHERE to_id = $1`, bob.id) + count(t, `SELECT count(*) FROM x_ledger WHERE to_id = $1`, bob.id) +
		count(t, `SELECT count(*) FROM mb_pairs WHERE from_root = $1`, alice.id); n != 0 {
		t.Fatalf("phantom stored something: %d", n)
	}
	st, pol, _ := e.do(t, "GET", "/v1/x/policy", bob.tok, nil)
	if st != 200 || !strings.Contains(pol, "blocks="+alice.id) {
		t.Fatalf("policy blocks: %s", pol)
	}
	// unblock: the next send is stored
	if st, body, _ := e.signed(t, bob, "DELETE", "/v1/x/block", []byte(`{"id":"`+alice.id+`"}`)); st != 200 {
		t.Fatalf("unblock: %d %s", st, body)
	}
	if st, body := e.send(t, alice, bob, seal(t, alice, bob, []byte("ok now"), curEpoch())); st != 201 {
		t.Fatalf("after unblock: %d %s", st, body)
	}
	if n := count(t, `SELECT count(*) FROM x_env WHERE to_id = $1`, bob.id); n != 1 {
		t.Fatalf("rows after unblock: %d", n)
	}
	// a plaintext-lane block (mb_blocks) silences the sealed lane too
	bobIdent, _ := e.d.LookupToken(context.Background(), bob.tok)
	if _, _, err := mail.Block(context.Background(), pool, bobIdent, alice.id); err != nil {
		t.Fatal(err)
	}
	if st, body := e.send(t, alice, bob, seal(t, alice, bob, []byte("again"), curEpoch())); st != 201 {
		t.Fatalf("phantom via mb_blocks: %d %s", st, body)
	}
	if n := count(t, `SELECT count(*) FROM x_env WHERE to_id = $1`, bob.id); n != 1 {
		t.Fatalf("mb_blocks not honoured: %d rows", n)
	}
	if st, body, _ := e.signed(t, bob, "PUT", "/v1/x/block", []byte(`{"id":"`+bob.id+`"}`)); st != 400 {
		t.Fatalf("self block: %d %s", st, body)
	}
}

func TestStateCASAndReceipt(t *testing.T) {
	e := newEnv(t)
	alice := mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	ctx := context.Background()
	k := e2e.KState(alice.seed)
	pt1 := []byte(`{"cursor":7,"seen":["a"]}`)
	blob1, err := e2e.SealState(k, alice.id, 1, pt1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st, body, _ := e.do(t, "GET", "/v1/x/state", alice.tok, nil); st != 404 {
		t.Fatalf("empty state: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "PUT", "/v1/x/state", alice.tok, blob1); st != 401 {
		t.Fatalf("unsigned put: %d %s", st, body)
	}
	st, body, hdr := e.signed(t, alice, "PUT", "/v1/x/state", blob1)
	if st != 200 || !strings.HasPrefix(body, "ok ver=1 leaf=") || hdr.Get("ETag") != `"1"` {
		t.Fatalf("put 1: %d %s %v", st, body, hdr)
	}
	leaf, _ := strconv.ParseInt(kv(body)["leaf"], 10, 64)
	var kind int16
	var seq int
	var item []byte
	if err := pool.QueryRow(ctx, `SELECT kind, seq, item_hash FROM klog WHERE idx = $1 AND id = $2`, leaf, alice.id).Scan(&kind, &seq, &item); err != nil {
		t.Fatal(err)
	}
	if kind != keys.KindState || seq != 1 || !bytes.Equal(item, e2e.StateReceipt(alice.id, 1, blob1)) {
		t.Fatalf("kind 6 receipt: kind=%d seq=%d", kind, seq)
	}
	// the tree stays consistent: the keys package's own root computation agrees with the log size
	size, _ := keys.LogSize(ctx, pool)
	if root, err := keys.RootAt(ctx, pool, size); err != nil || len(root) != 32 {
		t.Fatalf("root after kind 6 append: %v", err)
	}
	if _, err := keys.InclusionPath(ctx, pool, uint64(leaf), size); err != nil {
		t.Fatalf("inclusion path: %v", err)
	}
	st, got, hdr := e.do(t, "GET", "/v1/x/state", alice.tok, nil)
	if st != 200 || !bytes.Equal([]byte(got), blob1) || hdr.Get("ETag") != `"1"` {
		t.Fatalf("get: %d etag=%s", st, hdr.Get("ETag"))
	}
	if pt, err := e2e.OpenState(k, alice.id, 1, []byte(got)); err != nil || !bytes.Equal(pt, pt1) {
		t.Fatalf("open state: %v", err)
	}
	if st, _, _ := e.do(t, "GET", "/v1/x/state", alice.tok, nil, "If-None-Match", `"1"`); st != 304 {
		t.Fatalf("if-none-match: %d", st)
	}
	// CAS: the right If-Match advances, a stale one conflicts and names the current version
	blob2, _ := e2e.SealState(k, alice.id, 2, []byte(`{"cursor":9}`), nil)
	if st, body, _ := e.signed(t, alice, "PUT", "/v1/x/state", blob2, "If-Match", "1"); st != 200 || !strings.HasPrefix(body, "ok ver=2") {
		t.Fatalf("put 2: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, alice, "PUT", "/v1/x/state", blob2, "If-Match", "1"); st != 409 || !strings.Contains(body, "err conflict ver=2") {
		t.Fatalf("stale put: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, alice, "PUT", "/v1/x/state", blob2); st != 409 || !strings.Contains(body, "ver=2") {
		t.Fatalf("missing if-match on an existing state: %d %s", st, body)
	}
	if n := count(t, `SELECT count(*) FROM klog WHERE id = $1 AND kind = $2`, alice.id, keys.KindState); n != 2 {
		t.Fatalf("kind 6 leaves: %d", n)
	}
	// a blob served under another version does not open (ver is in the AAD)
	if _, err := e2e.OpenState(k, alice.id, 1, blob2); err == nil {
		t.Fatal("rollback label accepted")
	}
	if st, body, _ := e.signed(t, alice, "PUT", "/v1/x/state", []byte("short"), "If-Match", "2"); st != 400 {
		t.Fatalf("bad blob: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, alice, "DELETE", "/v1/x/state", nil); st != 200 {
		t.Fatalf("delete: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/v1/x/state", alice.tok, nil); st != 404 {
		t.Fatalf("after delete: %d", st)
	}
}

// TestStateFirstWriteRace is the regression for finding #10: the sealed-state CAS must not lose an
// update on the first write (ver 0 -> 1). Many clients race a first write (If-Match absent, want=0)
// against the same empty id; the collision-safe INSERT ... ON CONFLICT DO UPDATE ... WHERE ver=want
// must let exactly one win (ver=1) and 409 every other, so only one kind 6 leaf is appended. The old
// SELECT ... FOR UPDATE could not lock a non-existent row, so several writers all saw ver=0, all
// passed the check and the losing INSERTs silently overwrote the winner's blob.
func TestStateFirstWriteRace(t *testing.T) {
	e := newEnv(t)
	alice := mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	k := e2e.KState(alice.seed)
	const n = 8
	type res struct {
		st   int
		body string
	}
	results := make([]res, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		blob, err := e2e.SealState(k, alice.id, 1, []byte(fmt.Sprintf(`{"w":%d}`, i)), nil)
		if err != nil {
			t.Fatal(err)
		}
		sig := sigFor(t, alice.seed, "PUT", "/v1/x/state", blob)
		wg.Add(1)
		go func(idx int, blob []byte, sig string) {
			defer wg.Done()
			req, _ := http.NewRequest("PUT", e.srv.URL+"/v1/x/state", bytes.NewReader(blob))
			req.Header.Set("CF-Connecting-IP", e.ip)
			req.Header.Set("Authorization", "Bearer "+alice.tok)
			req.Header.Set("Content-Type", "application/octet-stream")
			req.Header.Set("X-Cx-Sig", sig)
			<-start
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				results[idx] = res{-1, err.Error()}
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			results[idx] = res{resp.StatusCode, string(b)}
		}(i, blob, sig)
	}
	close(start)
	wg.Wait()

	won := 0
	for _, r := range results {
		switch r.st {
		case 200:
			won++
			if !strings.HasPrefix(r.body, "ok ver=1 ") {
				t.Fatalf("winner body: %s", r.body)
			}
		case 409:
			if !strings.Contains(r.body, "err conflict") {
				t.Fatalf("loser body: %s", r.body)
			}
		default:
			t.Fatalf("unexpected status %d: %s", r.st, r.body)
		}
	}
	if won != 1 {
		t.Fatalf("exactly one first write must win, got %d", won)
	}
	// the lost-update symptom: the state settled at ver 1 with a single kind 6 leaf, not several.
	if v := count(t, `SELECT ver FROM x_state WHERE id = $1`, alice.id); v != 1 {
		t.Fatalf("state ver after race: %d", v)
	}
	if n := count(t, `SELECT count(*) FROM klog WHERE id = $1 AND kind = $2`, alice.id, keys.KindState); n != 1 {
		t.Fatalf("kind 6 leaves after race: %d", n)
	}
}

// TestSelfSendEnforcesLimits is the regression for finding #4: a self-addressed sealed envelope skips
// the anti-spam gates but must still pass the resource controls of 9.3. Each of the send quota, the
// per-inbox caps and the global live-byte budget must reject a self-send exactly as it rejects mail
// to another root; before the fix relay() jumped straight to insert() when self==true.
func TestSelfSendEnforcesLimits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := mkIdent(t, e2e.PolicyBoth, 3*24*time.Hour)
	self := func(what string) []byte { return seal(t, alice, alice, []byte(what), curEpoch()) }

	// baseline: a self-send is accepted even though alice's inbox is in stamp mode (self skips gates).
	if st, body := e.send(t, alice, alice, self("note to self")); st != 201 {
		t.Fatalf("self send: %d %s", st, body)
	}
	// the per-root daily send quota now binds self-sends.
	if _, err := pool.Exec(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, 'xsend', current_date, $2)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = $2`, alice.id, SendPerDay); err != nil {
		t.Fatal(err)
	}
	if st, body := e.send(t, alice, alice, self("over quota")); st != 429 || !strings.Contains(body, "err quota") {
		t.Fatalf("self daily quota: %d %s", st, body)
	}
	pool.Exec(ctx, `DELETE FROM counters WHERE scope = $1 AND kind = 'xsend'`, alice.id)
	// the per-inbox row cap now binds self-sends (the baseline send left exactly one row).
	if _, err := pool.Exec(ctx, `UPDATE x_inbox SET max_rows = rows WHERE id = $1`, alice.id); err != nil {
		t.Fatal(err)
	}
	if st, body := e.send(t, alice, alice, self("inbox full")); st != 429 || !strings.Contains(body, "err quota inbox-full") {
		t.Fatalf("self inbox full: %d %s", st, body)
	}
	pool.Exec(ctx, `UPDATE x_inbox SET max_rows = 1000 WHERE id = $1`, alice.id)
	// the global live-ciphertext budget now binds self-sends.
	old := MaxBytes
	MaxBytes = int64(count(t, `SELECT n FROM x_bytes WHERE k = 'live'`)) + 10
	if st, body := e.send(t, alice, alice, self("over budget")); st != 507 || !strings.Contains(body, "err quota e2e budget") {
		t.Fatalf("self budget: %d %s", st, body)
	}
	MaxBytes = old
}

func TestRevokeRotateSucceedOldKeyOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice, bob := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, alice)
	e.openInbox(t, bob)
	if st, body := e.send(t, alice, bob, seal(t, alice, bob, []byte("before"), curEpoch())); st != 201 {
		t.Fatalf("send: %d %s", st, body)
	}

	// --- rotation cancel: a pending ik rotation is cancelled by the previous ik only
	seed2 := e2e.NewSeed()
	h1, _ := alice.b.CanonicalHash()
	raw2, _ := mkBundle(t, seed2, alice.id, 2, h1, e2e.PolicyBoth, alice.rev, e2e.IK(alice.seed))
	if st, body, _ := e.signed(t, alice, "PUT", "/v1/keys", raw2); st != 202 || !strings.Contains(body, "pending=1") {
		t.Fatalf("rotation publish: %d %s", st, body)
	}
	newSig := ed25519.Sign(e2e.IK(seed2), cancelBytes(alice.id, 2))
	if st, body, _ := e.do(t, "POST", "/v1/x/rotate", "", []byte(fmt.Sprintf(`{"id":"%s","seq":2,"sig":"%s"}`, alice.id, b64(newSig)))); st != 403 {
		t.Fatalf("cancel by the new key: %d %s", st, body)
	}
	oldSig := ed25519.Sign(e2e.IK(alice.seed), cancelBytes(alice.id, 2))
	if st, body, _ := e.do(t, "POST", "/v1/x/rotate", "", []byte(fmt.Sprintf(`{"id":"%s","seq":3,"sig":"%s"}`, alice.id, b64(oldSig)))); st != 403 {
		t.Fatalf("cancel with the wrong seq: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/v1/x/rotate", "", []byte(fmt.Sprintf(`{"id":"%s","seq":2,"sig":"%s"}`, alice.id, b64(oldSig)))); st != 200 || body != "ok cancelled seq=2\n" {
		t.Fatalf("cancel by the old key: %d %s", st, body)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM key_bundles WHERE id = $1 AND seq = 2`, alice.id).Scan(&state); err != nil || state != "void" {
		t.Fatalf("pending bundle state %q %v", state, err)
	}
	if b, found, _ := keys.Bundle(ctx, pool, alice.id); !found || b.Seq != 1 {
		t.Fatal("current bundle changed")
	}
	if st, body, _ := e.do(t, "POST", "/v1/x/rotate", "", []byte(fmt.Sprintf(`{"id":"%s","r":"%s"}`, alice.id, b64(alice.rev)))); st != 404 {
		t.Fatalf("cancel with nothing pending: %d %s", st, body)
	}

	// --- succession: both current identity keys must sign "cx1/succ" || old || new || ik_new
	carol := mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	stmt := e2e.SuccBytes(alice.id, bob.id, bob.b.IK)
	sigOld, sigNew := ed25519.Sign(e2e.IK(alice.seed), stmt), ed25519.Sign(e2e.IK(bob.seed), stmt)
	succ := func(sO, sN []byte) []byte {
		return []byte(fmt.Sprintf(`{"old":"%s","new":"%s","sig_old":"%s","sig_new":"%s"}`, alice.id, bob.id, b64(sO), b64(sN)))
	}
	if st, body, _ := e.do(t, "POST", "/v1/x/succeed", alice.tok, succ(sigNew, sigNew)); st != 403 || !strings.Contains(body, "err sig") {
		t.Fatalf("succession without the old key: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/v1/x/succeed", alice.tok, succ(sigOld, sigOld)); st != 403 {
		t.Fatalf("succession without the new key: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/v1/x/succeed", carol.tok, succ(sigOld, sigNew)); st != 403 {
		t.Fatalf("succession by a third party's token: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/v1/x/succeed", "", succ(sigOld, sigNew)); st != 401 {
		t.Fatalf("anonymous succession: %d %s", st, body)
	}
	st, body, _ := e.do(t, "POST", "/v1/x/succeed", bob.tok, succ(sigOld, sigNew))
	if st != 200 || !strings.HasPrefix(body, "ok leaf=") {
		t.Fatalf("succession: %d %s", st, body)
	}
	leaf, _ := strconv.ParseInt(kv(body)["leaf"], 10, 64)
	var kind int16
	var item []byte
	if err := pool.QueryRow(ctx, `SELECT kind, item_hash FROM klog WHERE idx = $1 AND id = $2`, leaf, alice.id).Scan(&kind, &item); err != nil || kind != keys.KindSuccession || !bytes.Equal(item, e2e.Sum(stmt)) {
		t.Fatalf("kind 4 leaf: kind=%d err=%v", kind, err)
	}
	if st, body, _ := e.do(t, "POST", "/v1/x/succeed", bob.tok, succ(sigOld, sigNew)); st != 409 {
		t.Fatalf("dup succession: %d %s", st, body)
	}
	st, body, _ = e.do(t, "GET", "/v1/x/succ/"+alice.id, "", nil)
	if st != 200 || !strings.Contains(body, "new="+bob.id) || !strings.Contains(body, "sig_old="+b64(sigOld)) || !strings.Contains(body, "ik_new="+b64(bob.b.IK)) {
		t.Fatalf("succ list: %d %s", st, body)
	}

	// --- revocation by code: no signature, the token dies, the keys are tombstoned, sends freeze
	dave := mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, dave)
	befriend(t, bob, dave)
	if st, body := e.send(t, bob, dave, seal(t, bob, dave, []byte("before"), curEpoch())); st != 201 {
		t.Fatalf("send to dave: %d %s", st, body)
	}
	wrong := make([]byte, 32)
	if st, body, _ := e.do(t, "POST", "/v1/x/revoke", "", []byte(fmt.Sprintf(`{"id":"%s","r":"%s"}`, dave.id, b64(wrong)))); st != 403 || !strings.Contains(body, "revoke code") {
		t.Fatalf("wrong code: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "POST", "/v1/x/revoke", "", []byte(fmt.Sprintf(`{"id":"%s","r":"%s"}`, dave.id, b64(dave.rev)))); st != 200 || body != "ok revoked="+dave.id+"\n" {
		t.Fatalf("revoke: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/v1/me", dave.tok, nil); st != 401 {
		t.Fatalf("revoked token still works: %d", st)
	}
	if st, body, _ := e.do(t, "GET", "/v1/keys/"+dave.id, "", nil); st != 410 || !strings.Contains(body, "err revoked") {
		t.Fatalf("directory after revoke: %d %s", st, body)
	}
	if n := count(t, `SELECT count(*) FROM klog WHERE id = $1 AND kind = $2`, dave.id, keys.KindTombstone); n < 1 {
		t.Fatal("no tombstone leaf")
	}
	// peers cannot seal to a revoked recipient; the owner recovers a token and still reads the inbox, marked revoked
	if st, body := e.send(t, bob, dave, seal(t, bob, dave, []byte("too late"), curEpoch())); st != 410 && st != 404 {
		t.Fatalf("send to revoked: %d %s", st, body)
	}
	tok2, h := core.NewToken()
	if _, err := pool.Exec(ctx, `UPDATE identities SET token_hash = $2 WHERE id = $1`, dave.id, h); err != nil {
		t.Fatal(err)
	}
	st, body, _ = e.do(t, "GET", "/v1/x/in", tok2, nil)
	if st != 200 || !strings.Contains(body, "from "+bob.id) || !strings.Contains(body, "revoked="+core.Date(time.Now())) {
		t.Fatalf("inbox after revoke: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "GET", "/v1/me", tok2, nil); st != 200 || !strings.Contains(body, "sealed: revoked=") {
		t.Fatalf("me after revoke: %d %s", st, body)
	}
	// outbound in dave's name is frozen even with a recovered token (the bundle is gone anyway)
	envb := seal(t, dave, bob, []byte("from the dead"), curEpoch())
	if st, body, _ := e.do(t, "POST", "/v1/x/"+bob.id, tok2, envb, "X-Cx-Sig", sigFor(t, dave.seed, "POST", "/v1/x/"+bob.id, envb)); st != 403 {
		t.Fatalf("send after revoke: %d %s", st, body)
	}
	if n := count(t, `SELECT count(*) FROM mail WHERE box = $1 AND from_id = 'sys' AND subject LIKE 'identity % revoked'`, dave.id); n != 1 {
		t.Fatalf("sys notice: %d", n)
	}
}

func TestEpochSharesSealed(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice, bob := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, bob)
	cur := curEpoch()
	path := fmt.Sprintf("/v1/keys/share?e=%d", cur-1)
	if st, body, _ := e.do(t, "GET", path, bob.tok, nil); st != 401 {
		t.Fatalf("unsigned share: %d %s", st, body)
	}
	st, body, _ := e.signed(t, bob, "GET", path, nil)
	if st != 200 {
		t.Fatalf("share: %d %s", st, body)
	}
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) != e2e.EpochsAhead {
		t.Fatalf("lines: %q", body)
	}
	lk, _ := e2e.LK(bob.seed, e2e.CS1)
	shares := map[uint32][]byte{}
	for i, l := range lines {
		m := kv(l)
		ep, _ := strconv.ParseUint(m["e"], 10, 32)
		if uint32(ep) != cur-1+uint32(i) {
			t.Fatalf("epoch order: %s", l)
		}
		sealed, err := decodeB64(m["share"])
		if err != nil {
			t.Fatal(err)
		}
		share, err := OpenShare(lk, bob.id, uint32(ep), sealed)
		if err != nil || len(share) != 32 {
			t.Fatalf("open share %d: %v", ep, err)
		}
		var stored []byte
		if err := pool.QueryRow(ctx, `SELECT b FROM epoch_shares WHERE root = $1 AND e = $2`, bob.id, int64(ep)).Scan(&stored); err != nil || !bytes.Equal(stored, share) {
			t.Fatalf("stored share %d: %v", ep, err)
		}
		if strings.Contains(body, b64(share)) || strings.Contains(body, fmt.Sprintf("%x", share)) {
			t.Fatal("a raw share left the server")
		}
		if _, err := OpenShare(lk, alice.id, uint32(ep), sealed); err == nil {
			t.Fatal("share opened under another id's info")
		}
		shares[uint32(ep)] = share
	}
	// shares are minted once: a second call returns the same bytes
	_, body2, _ := e.signed(t, bob, "GET", path, nil)
	m := kv(strings.Split(body2, "\n")[0])
	sealed, _ := decodeB64(m["share"])
	if again, err := OpenShare(lk, bob.id, cur-1, sealed); err != nil || !bytes.Equal(again, shares[cur-1]) {
		t.Fatal("share changed between calls")
	}
	// a mode D+ key derived with the share differs from the mode D key and round-trips an envelope
	dplus, _ := e2e.EK(bob.seed, e2e.CS1, cur, shares[cur])
	d, _ := e2e.EK(bob.seed, e2e.CS1, cur, nil)
	if bytes.Equal(dplus.PublicKey().Bytes(), d.PublicKey().Bytes()) {
		t.Fatal("share did not change the epoch key")
	}
	// deletion rule: the share of a finished epoch lingers 48 h after its last envelope is acked
	envb := seal(t, alice, bob, []byte("old epoch"), cur-1)
	st, body = e.send(t, alice, bob, envb)
	if st != 201 {
		t.Fatalf("send to the previous epoch: %d %s", st, body)
	}
	var far bool
	if err := pool.QueryRow(ctx, `SELECT exp > now() + interval '20 days' FROM epoch_shares WHERE root = $1 AND e = $2`, bob.id, int64(cur-1)).Scan(&far); err != nil || !far {
		t.Fatalf("share expiry before ack: far=%v %v", far, err)
	}
	if st, body, _ := e.signed(t, bob, "DELETE", "/v1/x/"+kv(body)["seq"], nil); st != 200 {
		t.Fatalf("ack: %d %s", st, body)
	}
	var soon bool
	if err := pool.QueryRow(ctx, `SELECT exp <= now() + interval '48 hours 1 minute' FROM epoch_shares WHERE root = $1 AND e = $2`, bob.id, int64(cur-1)).Scan(&soon); err != nil || !soon {
		t.Fatalf("share did not start lingering after the ack: %v", err)
	}
	if st, body, _ := e.signed(t, bob, "GET", fmt.Sprintf("/v1/keys/share?e=%d", cur+20), nil); st != 400 {
		t.Fatalf("far epoch: %d %s", st, body)
	}
}

func TestNoOriginRowLogMinimal(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice, bob := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, bob)
	befriend(t, alice, bob)
	before := count(t, `SELECT count(*) FROM content_origin`)
	if st, body := e.send(t, alice, bob, seal(t, alice, bob, []byte("no ip"), curEpoch())); st != 201 {
		t.Fatalf("send: %d %s", st, body)
	}
	e.signed(t, alice, "PUT", "/v1/x/state", func() []byte { b, _ := e2e.SealState(e2e.KState(alice.seed), alice.id, 1, []byte("{}"), nil); return b }())
	if n := count(t, `SELECT count(*) FROM content_origin`); n != before {
		t.Fatalf("sealed writes wrote %d content_origin rows", n-before)
	}
	if n := count(t, `SELECT count(*) FROM content_origin WHERE kind = 'x'`); n != 0 {
		t.Fatal("content_origin has sealed rows")
	}
	// every route this package registers answers with X-Cx-Log: minimal, whatever the status
	if len(Routes) < 17 {
		t.Fatalf("routes: %v", Routes)
	}
	for _, pat := range Routes {
		method, path, _ := strings.Cut(pat, " ")
		path = strings.NewReplacer("{to}", bob.id, "{id}", "1").Replace(path)
		for _, tok := range []string{"", alice.tok} {
			_, _, hdr := e.do(t, method, path, tok, []byte(`{}`))
			if hdr.Get(keys.LogMinimalHeader) != "minimal" || hdr.Get("X-Now") == "" {
				t.Fatalf("%s (token=%v): X-Cx-Log=%q X-Now=%q", pat, tok != "", hdr.Get(keys.LogMinimalHeader), hdr.Get("X-Now"))
			}
		}
	}
	// the raw relay ops of the remote /mcp
	envb := seal(t, alice, bob, []byte("via mcp"), curEpoch())
	a, _ := json.Marshal(map[string]string{"to": bob.id, "env": b64(envb), "sig": sigFor(t, alice.seed, "POST", "/v1/x/"+bob.id, envb)})
	aliceID, _ := e.d.LookupToken(ctx, alice.tok)
	out, err := e.ops["xraw"](ctx, aliceID, a)
	if err != nil || !strings.HasPrefix(out, "ok seq=") || !strings.Contains(out, "\nfrank1 ") {
		t.Fatalf("xraw: %v %q", err, out)
	}
	if _, err := e.ops["xraw"](ctx, aliceID, a); err == nil {
		t.Fatal("xraw replayed")
	}
	if _, err := e.ops["xraw"](ctx, aliceID, []byte(`{"to":"`+bob.id+`","env":"`+b64(envb)+`"}`)); err == nil || !strings.Contains(err.Error(), "sig required") {
		t.Fatalf("xraw without sig: %v", err)
	}
	bobID, _ := e.d.LookupToken(ctx, bob.tok)
	list, err := e.ops["xpull"](ctx, bobID, []byte(`{"k":5}`))
	if err != nil || strings.Count(list, "from "+alice.id) != 2 || !strings.Contains(list, "next=") || strings.Contains(list, b64(envb)) {
		t.Fatalf("xpull: %v %q", err, list)
	}
	if _, err := e.ops["xpull"](ctx, nil, nil); err == nil {
		t.Fatal("anonymous xpull")
	}
	for name, m := range OpMeta {
		if _, ok := e.ops[name]; !ok || (name == "xraw") != m.Mutating {
			t.Fatalf("op meta %s", name)
		}
	}
	// resume and me lines
	st, body, _ := e.do(t, "GET", "/v1/me", bob.tok, nil)
	if st != 200 || !strings.Contains(body, "sealed: unread=2") {
		t.Fatalf("me: %d %s", st, body)
	}
	if lines := e.d.ResumeLines(ctx, bob.id); len(lines) == 0 || lines[len(lines)-1] != "sealed: 2 unread" {
		t.Fatalf("resume: %v", lines)
	}
}

func TestScrubVersionPin(t *testing.T) {
	e := newEnv(t)
	alice, bob := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, bob)
	befriend(t, alice, bob)
	if st, body := e.send(t, alice, bob, seal(t, alice, bob, []byte("stale"), curEpoch()), "X-Scrub-V", strconv.Itoa(scrub.RulesV-2)); st != 400 || !strings.Contains(body, "err scrub stale-rules") {
		t.Fatalf("stale rules: %d %s", st, body)
	}
	if st, body := e.send(t, alice, bob, seal(t, alice, bob, []byte("junk"), curEpoch()), "X-Scrub-V", "latest"); st != 400 {
		t.Fatalf("bad header: %d %s", st, body)
	}
	if st, body := e.send(t, alice, bob, seal(t, alice, bob, []byte("current"), curEpoch()), "X-Scrub-V", strconv.Itoa(scrub.RulesV)); st != 201 {
		t.Fatalf("current rules: %d %s", st, body)
	}
	if st, body := e.send(t, alice, bob, seal(t, alice, bob, []byte("previous"), curEpoch()), "X-Scrub-V", strconv.Itoa(scrub.RulesV-1)); st != 201 {
		t.Fatalf("previous rules: %d %s", st, body)
	}
	if st, body := e.send(t, alice, bob, seal(t, alice, bob, []byte("none"), curEpoch())); st != 201 {
		t.Fatalf("no pin: %d %s", st, body)
	}
	st, list, _ := e.do(t, "GET", "/v1/x/in", bob.tok, nil)
	if st != 200 || strings.Count(list, "scrub=client") != 2 || strings.Count(list, "scrub=none") != 1 {
		t.Fatalf("scrub marks: %s", list)
	}
	if n := count(t, `SELECT count(*) FROM x_env WHERE to_id = $1 AND scrub = 'client'`, bob.id); n != 2 {
		t.Fatalf("scrub column: %d", n)
	}
}

func TestQuotaBudgetAndFreeze(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice, bob := mkIdent(t, e2e.PolicyBoth, 3*24*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	fresh := func(what string) []byte { return seal(t, alice, bob, []byte(what), curEpoch()) }

	// stamp mode (default): a stranger needs X-Stamp; known pairs and allow-listed roots send freely
	st, body := e.send(t, alice, bob, fresh("cold"))
	if st != 429 || !strings.Contains(body, "err pow bits="+strconv.Itoa(StampBits)) {
		t.Fatalf("cold without stamp: %d %s", st, body)
	}
	if st, body, _ := e.signed(t, bob, "PUT", "/v1/x/policy", []byte(`{"bits":4}`)); st != 200 || !strings.Contains(body, "bits=4") {
		t.Fatalf("bits: %d %s", st, body)
	}
	envb := fresh("stamped")
	day := time.Now().UTC().Format("20060102")
	nonce := pow.Solve(e2e.StampPrefix(bob.id, envb, day), 4)
	if st, body := e.send(t, alice, bob, envb, "X-Stamp", "0"); st != 429 || !strings.Contains(body, "err pow bits=4") {
		t.Fatalf("weak stamp: %d %s", st, body)
	}
	if st, body := e.send(t, alice, bob, envb, "X-Stamp", nonce); st != 201 {
		t.Fatalf("stamped: %d %s", st, body)
	}
	if n := count(t, `SELECT count(*) FROM x_stamps WHERE to_id = $1`, bob.id); n != 1 {
		t.Fatalf("spent stamps: %d", n)
	}
	// one unacked envelope per cold pair until the recipient replies
	envb2 := fresh("second cold")
	nonce2 := pow.Solve(e2e.StampPrefix(bob.id, envb2, day), 4)
	if st, body := e.send(t, alice, bob, envb2, "X-Stamp", nonce2); st != 429 || !strings.Contains(body, "err quota pending") {
		t.Fatalf("second cold: %d %s", st, body)
	}
	e.openInbox(t, alice)
	if st, body := e.send(t, bob, alice, seal(t, bob, alice, []byte("reply"), curEpoch())); st != 201 {
		t.Fatalf("reply: %d %s", st, body)
	}
	if st, body := e.send(t, alice, bob, envb2); st != 201 {
		t.Fatalf("known pair, no stamp: %d %s", st, body)
	}
	// daily send quota per root
	if _, err := pool.Exec(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, 'xsend', current_date, $2) ON CONFLICT (scope, kind, day) DO UPDATE SET n = $2`, alice.id, SendPerDay); err != nil {
		t.Fatal(err)
	}
	if st, body := e.send(t, alice, bob, fresh("over")); st != 429 || !strings.Contains(body, "err quota") {
		t.Fatalf("daily quota: %d %s", st, body)
	}
	pool.Exec(ctx, `DELETE FROM counters WHERE scope = $1 AND kind = 'xsend'`, alice.id)
	// inbox capacity never evicts: the sender is refused
	if _, err := pool.Exec(ctx, `UPDATE x_inbox SET max_rows = 2 WHERE id = $1`, bob.id); err != nil {
		t.Fatal(err)
	}
	if st, body := e.send(t, alice, bob, fresh("full")); st != 429 || !strings.Contains(body, "err quota inbox-full") {
		t.Fatalf("inbox full: %d %s", st, body)
	}
	pool.Exec(ctx, `UPDATE x_inbox SET max_rows = 1000 WHERE id = $1`, bob.id)
	// the global live-ciphertext budget
	old := MaxBytes
	MaxBytes = int64(count(t, `SELECT n FROM x_bytes WHERE k = 'live'`)) + 100
	if st, body := e.send(t, alice, bob, fresh("budget")); st != 507 || !strings.Contains(body, "err quota e2e budget") {
		t.Fatalf("budget: %d %s", st, body)
	}
	MaxBytes = old
	// the lane kill switch and a frozen sender
	if err := e.d.SetFreeze(ctx, "freeze:mail", true); err != nil {
		t.Fatal(err)
	}
	if st, body := e.send(t, alice, bob, fresh("frozen lane")); st != 503 || !strings.Contains(body, "err frozen mail") {
		t.Fatalf("lane frozen: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/v1/x/in", bob.tok, nil); st != 200 {
		t.Fatal("reads must continue under the lane freeze")
	}
	e.d.SetFreeze(ctx, "freeze:mail", false)
	if err := Freeze(ctx, pool, alice.id, time.Now().Add(7*24*time.Hour), "reports"); err != nil {
		t.Fatal(err)
	}
	if st, body := e.send(t, alice, bob, fresh("frozen sender")); st != 403 || !strings.Contains(body, "err auth mail-frozen until=") {
		t.Fatalf("frozen sender: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "GET", "/v1/me", alice.tok, nil); st != 200 || !strings.Contains(body, "sealed: mail-frozen until=") {
		t.Fatalf("me frozen: %d %s", st, body)
	}
	pool.Exec(ctx, `DELETE FROM x_frozen WHERE id = $1`, alice.id)
	// negative standing may only answer peers who wrote first; a young root waits an hour
	carol := mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	e.openInbox(t, carol)
	pool.Exec(ctx, `UPDATE identities SET rep = -1 WHERE id = $1`, alice.id)
	if st, body := e.send(t, alice, carol, seal(t, alice, carol, []byte("x"), curEpoch())); st != 403 || !strings.Contains(body, "err auth standing") {
		t.Fatalf("negative rep cold: %d %s", st, body)
	}
	if st, body := e.send(t, alice, bob, fresh("to a peer who wrote")); st != 201 {
		t.Fatalf("negative rep to a peer: %d %s", st, body)
	}
	pool.Exec(ctx, `UPDATE identities SET rep = 0 WHERE id = $1`, alice.id)
	young := mkIdent(t, e2e.PolicyBoth, 10*time.Minute)
	if st, body := e.send(t, young, carol, seal(t, young, carol, []byte("x"), curEpoch())); st != 429 || !strings.Contains(body, "younger than 1 h") {
		t.Fatalf("young root: %d %s", st, body)
	}
	// the janitor: expired rows leave with their counters settled
	if _, err := pool.Exec(ctx, `UPDATE x_env SET exp = now() - interval '1 second' WHERE to_id = $1`, bob.id); err != nil {
		t.Fatal(err)
	}
	if err := Janitor(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if n := count(t, `SELECT count(*) FROM x_env WHERE to_id = $1`, bob.id); n != 0 {
		t.Fatalf("janitor left %d rows", n)
	}
	if n := count(t, `SELECT rows + bytes FROM x_inbox WHERE id = $1`, bob.id); n != 0 {
		t.Fatalf("inbox counters after janitor: %d", n)
	}
}

func TestPurgeDeletesBothDirections(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice, bob, carol := mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour), mkIdent(t, e2e.PolicyBoth, 2*time.Hour)
	for _, who := range []*ident{alice, bob, carol} {
		e.openInbox(t, who)
	}
	for _, s := range []struct{ from, to *ident }{{alice, bob}, {bob, alice}, {carol, bob}, {alice, carol}} {
		if st, body := e.send(t, s.from, s.to, seal(t, s.from, s.to, []byte("hi"), curEpoch())); st != 201 {
			t.Fatalf("send: %d %s", st, body)
		}
	}
	blob, _ := e2e.SealState(e2e.KState(alice.seed), alice.id, 1, []byte("{}"), nil)
	e.signed(t, alice, "PUT", "/v1/x/state", blob)
	e.signed(t, alice, "PUT", "/v1/x/block", []byte(`{"id":"`+carol.id+`"}`))
	e.signed(t, bob, "PUT", "/v1/x/block", []byte(`{"id":"`+alice.id+`"}`))
	e.signed(t, alice, "GET", fmt.Sprintf("/v1/keys/share?e=%d", curEpoch()), nil)
	e.signed(t, alice, "POST", "/v1/x/lease", []byte(`{"dev":"d"}`))
	live := count(t, `SELECT n FROM x_bytes WHERE k = 'live'`)
	aliceBytes := count(t, `SELECT coalesce(sum(size), 0) FROM x_env WHERE to_id = $1 OR from_root = $1`, alice.id)
	if _, err := e.d.Purge(ctx, alice.id); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		what string
		sql  string
	}{
		{"envelopes to alice", `SELECT count(*) FROM x_env WHERE to_id = $1`},
		{"envelopes from alice", `SELECT count(*) FROM x_env WHERE from_root = $1`},
		{"ledger to alice", `SELECT count(*) FROM x_ledger WHERE to_id = $1`},
		{"ledger from alice", `SELECT count(*) FROM x_ledger WHERE from_root = $1`},
		{"inbox", `SELECT count(*) FROM x_inbox WHERE id = $1`},
		{"state", `SELECT count(*) FROM x_state WHERE id = $1`},
		{"blocks by alice", `SELECT count(*) FROM x_block WHERE inbox = $1`},
		{"blocks of alice", `SELECT count(*) FROM x_block WHERE root = $1`},
		{"shares", `SELECT count(*) FROM epoch_shares WHERE root = $1`},
		{"lease", `SELECT count(*) FROM x_lease WHERE id = $1`},
	} {
		if n := count(t, c.sql, alice.id); n != 0 {
			t.Fatalf("%s left %d rows", c.what, n)
		}
	}
	// what did not involve alice stays, with its counters right
	if n := count(t, `SELECT count(*) FROM x_env WHERE to_id = $1 AND from_root = $2`, bob.id, carol.id); n != 1 {
		t.Fatalf("carol->bob row: %d", n)
	}
	if n := count(t, `SELECT rows FROM x_inbox WHERE id = $1`, bob.id); n != 1 {
		t.Fatalf("bob inbox rows: %d", n)
	}
	if n := count(t, `SELECT n FROM x_bytes WHERE k = 'live'`); n != live-aliceBytes {
		t.Fatalf("live bytes %d want %d", n, live-aliceBytes)
	}
	if st, body, _ := e.do(t, "GET", "/v1/keys/"+alice.id, "", nil); st != 410 {
		t.Fatalf("keys after purge: %d %s", st, body)
	}
	// the report target: hide deletes the ciphertext, the ledger keeps the record
	var seq int64
	if err := pool.QueryRow(ctx, `SELECT seq FROM x_env WHERE to_id = $1`, bob.id).Scan(&seq); err != nil {
		t.Fatal(err)
	}
	ref := bob.id + "/" + strconv.FormatInt(seq, 10)
	tgt, ok := e.d.Target("x")
	if !ok {
		t.Fatal("target x not registered")
	}
	if err := tgt.Exists(ctx, pool, ref); err != nil {
		t.Fatal(err)
	}
	if err := tgt.Hide(ctx, pool, ref); err != nil {
		t.Fatal(err)
	}
	if st, body, _ := e.do(t, "GET", "/v1/x/"+strconv.FormatInt(seq, 10), bob.tok, nil); st != 410 {
		t.Fatalf("hidden get: %d %s", st, body)
	}
	if n := count(t, `SELECT count(*) FROM x_env WHERE to_id = $1 AND seq = $2 AND hidden AND length(body) = 0`, bob.id, seq); n != 1 {
		t.Fatal("ciphertext not deleted by hide")
	}
	if err := tgt.Restore(ctx, pool, ref); err == nil {
		t.Fatal("restore must fail: the ciphertext is gone")
	}
	if err := tgt.Exists(ctx, pool, "nope"); !errors.Is(err, core.ErrNotFound) {
		t.Fatalf("bad ref: %v", err)
	}
}
