package main

// e2e_test.go: the sealed-lane regression suite named by the P72 acceptance list. Everything runs
// against httptest fakes (gateway + mirror) and the real internal/e2e primitives; no network, no DB.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/scrub"
)

// --- fake gateway + mirror ---

type fakeIdent struct {
	raw  []byte
	leaf uint64
	seq  uint32
}

type e2eFake struct {
	mu       sync.Mutex
	onlineSK ed25519.PrivateKey
	onlinePK []byte
	wID      string
	wSK      ed25519.PrivateKey
	wPK      []byte
	tree     *e2e.Tree
	dir      map[string]*fakeIdent
	mailbox  map[string][]inMsg
	mkWrap   string
	logLeaf  map[string][]uint64
	forkSTH  bool   // serve a server STH on a forked root at the current tree size
	forkRoot []byte // the forked root

	gw     *httptest.Server
	mirror *httptest.Server
}

type inMsg struct {
	ID, From, Env string
}

func newE2EFake(t *testing.T) *e2eFake {
	t.Helper()
	opk, osk, _ := ed25519.GenerateKey(nil)
	wpk, wsk, _ := ed25519.GenerateKey(nil)
	f := &e2eFake{
		onlineSK: osk, onlinePK: opk, wID: "w1", wSK: wsk, wPK: wpk,
		tree: &e2e.Tree{}, dir: map[string]*fakeIdent{}, mailbox: map[string][]inMsg{},
		logLeaf: map[string][]uint64{}, forkRoot: bytes.Repeat([]byte{0x55}, 32),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/challenge", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"c": "chal", "bits": 0, "id": "abcdefg"})
	})
	mux.HandleFunc("POST /v1/register", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ C, Nonce, Name, Bundle string }
		json.NewDecoder(r.Body).Decode(&in)
		raw, err := base64.RawStdEncoding.DecodeString(in.Bundle)
		if err != nil {
			raw, err = base64.StdEncoding.DecodeString(in.Bundle)
		}
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, "err bad bundle b64\n")
			return
		}
		b, err := e2e.ParseBundle(raw)
		if err != nil || b.Verify() != nil || b.ID != "abcdefg" || b.Seq != 1 {
			w.WriteHeader(400)
			io.WriteString(w, "err bad bundle\n")
			return
		}
		f.addIdent(b.ID, raw)
		json.NewEncoder(w).Encode(map[string]any{"id": b.ID, "token": "cx_" + b.ID})
	})
	mux.HandleFunc("GET /v1/keys/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		ident, ok := f.dir[id]
		if !ok {
			w.WriteHeader(404)
			io.WriteString(w, "err notfound\n")
			return
		}
		size := f.tree.Size()
		e := dirEntry{
			Bundle: base64.RawStdEncoding.EncodeToString(ident.raw),
			Leaf:   ident.leaf,
			STH:    f.sthLine(size, f.tree.Root()),
			Incl:   f.inclLine(ident.leaf, size),
		}
		if f.forkSTH {
			e.Leaf = size
			e.STH = f.sthLine(size, f.forkRoot)
			e.Incl = ""
		}
		json.NewEncoder(w).Encode(e)
	})
	mux.HandleFunc("GET /v1/me/mk", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"wrapped": f.mkWrap})
	})
	mux.HandleFunc("PUT /v1/me/mk", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Wrapped string }
		json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		f.mkWrap = in.Wrapped
		f.mu.Unlock()
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST /v1/x/{to}", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Env string }
		json.NewDecoder(r.Body).Decode(&in)
		to := r.PathValue("to")
		f.mu.Lock()
		n := len(f.mailbox[to])
		f.mailbox[to] = append(f.mailbox[to], inMsg{ID: to + strconv.Itoa(n), From: r.Header.Get("X-From"), Env: in.Env})
		f.mu.Unlock()
		io.WriteString(w, "ok mid="+strconv.Itoa(n)+"\n")
	})
	mux.HandleFunc("GET /v1/x/in", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"msgs": []inMsg{}})
	})
	mux.HandleFunc("GET /v1/log/id/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var b strings.Builder
		for _, l := range f.logLeaf[r.PathValue("id")] {
			b.WriteString("leaf=" + strconv.FormatUint(l, 10) + "\n")
		}
		io.WriteString(w, b.String())
	})
	mux.HandleFunc("GET /scrub/rules", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, scrub.RulesText(""))
	})
	gw := httptest.NewServer(mux)
	t.Cleanup(gw.Close)
	f.gw = gw

	mmux := http.NewServeMux()
	mmux.HandleFunc("GET /sth.jsonl", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		head := f.head(f.tree.Size(), f.tree.Root())
		line, _ := e2e.FormatMirrorHead(head, head.Size)
		w.Write(line)
	})
	mirror := httptest.NewServer(mmux)
	t.Cleanup(mirror.Close)
	f.mirror = mirror
	return f
}

// addIdent appends id's bundle leaf to the log and records the directory entry.
func (f *e2eFake) addIdent(id string, raw []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := e2e.ParseBundle(raw)
	ch, _ := b.CanonicalHash()
	idx := f.tree.Size()
	f.tree.Append(e2e.KlogLeaf(1, id, ch, idx))
	f.dir[id] = &fakeIdent{raw: raw, leaf: idx, seq: b.Seq}
	f.logLeaf[id] = append(f.logLeaf[id], idx)
}

func (f *e2eFake) sthLine(size uint64, root []byte) string {
	at := uint64(time.Now().Unix())
	sig := e2e.Sign(f.onlineSK, e2e.STHBytes(size, root, at))
	return "size=" + strconv.FormatUint(size, 10) + " root=" + hex.EncodeToString(root) +
		" at=" + strconv.FormatUint(at, 10) + " sig=" + base64.RawURLEncoding.EncodeToString(sig)
}

func (f *e2eFake) inclLine(leaf, size uint64) string {
	path := f.tree.Inclusion(leaf, size)
	return "idx=" + strconv.FormatUint(leaf, 10) + " leaf=" + hex.EncodeToString(f.tree.Leaf(leaf)) +
		" path=" + e2e.EncodePath(path)
}

func (f *e2eFake) head(size uint64, root []byte) *e2e.Head {
	at := uint64(time.Now().Unix())
	return &e2e.Head{
		Size: size, Root: root, At: at,
		Sig:     e2e.Sign(f.onlineSK, e2e.STHBytes(size, root, at)),
		Witness: map[string][]byte{f.wID: e2e.Sign(f.wSK, e2e.WitnessBytes(size, root, at))},
	}
}

// e2eCLI returns a CLI configured for one identity against the fake, with its id file written.
func (f *e2eFake) cli(t *testing.T, seed []byte, id, trust string) (*cli, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	cfg := t.TempDir()
	env := map[string]string{
		"CX_URL": f.gw.URL, "XDG_CONFIG_HOME": cfg, "CX_TOKEN": "cx_" + id,
		"CX_MIRROR_URL": f.mirror.URL, "CX_ONLINE_PK": base64.RawURLEncoding.EncodeToString(f.onlinePK),
		"CX_WITNESS": f.wID + ":" + base64.RawURLEncoding.EncodeToString(f.wPK), "CX_TRUST": trust,
	}
	if seed != nil {
		env["CX_SEED"] = e2e.FormatSeed(seed)
	}
	c := newCLI(func(k string) string { return env[k] })
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	c.stdout, c.stderr = out, errb
	if id != "" {
		writeFile0600(c.cxDir()+"/id", []byte(id+"\n"))
	}
	return c, out, errb
}

// --- TestJoinSeedAndBundle ---

func TestJoinSeedAndBundle(t *testing.T) {
	f := newE2EFake(t)
	cfg := t.TempDir()
	env := map[string]string{"CX_URL": f.gw.URL, "XDG_CONFIG_HOME": cfg}
	c := newCLI(func(k string) string { return env[k] })
	out := &bytes.Buffer{}
	c.stdout = out
	c.stderr = &bytes.Buffer{}
	// The integration package wires this handler to the `join` verb (v1 join owns the bare form); here
	// it is driven directly, as a later integration test would through the registry.
	if err := cmdJoinE2E(c, context.Background(), []string{"bot", "--e2e", "--save-seed"}); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "id=abcdefg") {
		t.Fatalf("no id line: %q", s)
	}
	if !strings.Contains(s, "CX_SEED=cxs_") {
		t.Fatalf("CX_SEED not printed once: %q", s)
	}
	// the bundle reached the directory and verifies
	f.mu.Lock()
	ident, ok := f.dir["abcdefg"]
	f.mu.Unlock()
	if !ok {
		t.Fatal("bundle not published in registration")
	}
	b, err := e2e.ParseBundle(ident.raw)
	if err != nil || b.Verify() != nil || b.Seq != 1 {
		t.Fatalf("published bundle invalid: %v", err)
	}
	// the seed was saved 0600 and the recovery wrap was armed
	st, err := os.Stat(c.seedPath())
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("seed file: %v %v", err, st)
	}
	if f.mkWrap == "" {
		t.Fatal("mk recovery wrap not armed at join")
	}
	// a second join refuses (token present)
	if err := cmdJoinE2E(c, context.Background(), []string{"bot2", "--e2e"}); err == nil {
		t.Fatal("second join should refuse")
	}
}

// --- TestDVRForkDetected ---

func TestDVRForkDetected(t *testing.T) {
	f := newE2EFake(t)
	peer := e2e.NewSeed()
	raw, _ := buildRegBundle(peer, "apeer22", e2e.PolicyBoth)
	f.addIdent("apeer22", raw)
	f.forkSTH = true // server STH disagrees with the witnessed head at the same size

	c, _, _ := f.cli(t, e2e.NewSeed(), "asendr2", "mirror") // witnessed mode
	_, err := c.dvr(context.Background(), "apeer22", false)
	if err == nil || !strings.Contains(err.Error(), "err dvr 2") {
		t.Fatalf("want fork detected at step 2, got %v", err)
	}
}

// --- TestPinsTOFU ---

func TestPinsTOFU(t *testing.T) {
	f := newE2EFake(t)
	peerSeed := e2e.NewSeed()
	raw, _ := buildRegBundle(peerSeed, "apeer22", e2e.PolicyBoth)
	f.addIdent("apeer22", raw)

	c, _, _ := f.cli(t, e2e.NewSeed(), "asendr2", "tofu")
	ctx := context.Background()
	if _, err := c.dvr(ctx, "apeer22", false); err != nil {
		t.Fatalf("first contact: %v", err)
	}
	pin, _ := c.loadPin("apeer22")
	if pin == nil {
		t.Fatal("no pin written on first contact")
	}
	firstFP := pin.FP

	// the peer rotates to a brand-new key (not a chained rotation): a changed key must refuse
	newSeed := e2e.NewSeed()
	raw2, _ := buildRegBundle(newSeed, "apeer22", e2e.PolicyBoth)
	f.mu.Lock()
	delete(f.dir, "apeer22")
	f.mu.Unlock()
	f.addIdent("apeer22", raw2)
	if _, err := c.dvr(ctx, "apeer22", false); err == nil || !strings.Contains(err.Error(), "err dvr 3") {
		t.Fatalf("changed key should refuse at step 3, got %v", err)
	}
	// --accept-key re-anchors the pin
	if _, err := c.dvr(ctx, "apeer22", true); err != nil {
		t.Fatalf("--accept-key should succeed: %v", err)
	}
	pin2, _ := c.loadPin("apeer22")
	if pin2 == nil || pin2.FP == firstFP {
		t.Fatalf("pin not re-anchored: %+v", pin2)
	}
}

// --- TestSealedMailRoundTrip ---

func TestSealedMailRoundTrip(t *testing.T) {
	f := newE2EFake(t)
	aSeed, bSeed := e2e.NewSeed(), e2e.NewSeed()
	aRaw, _ := buildRegBundle(aSeed, "asendr2", e2e.PolicyBoth)
	bRaw, _ := buildRegBundle(bSeed, "arecvr2", e2e.PolicyBoth)
	f.addIdent("asendr2", aRaw)
	f.addIdent("arecvr2", bRaw)
	ctx := context.Background()

	// sender A seals to B
	a, _, _ := f.cli(t, aSeed, "asendr2", "tofu")
	res, err := a.dvr(ctx, "arecvr2", false)
	if err != nil {
		t.Fatalf("sender dvr: %v", err)
	}
	sealed, err := e2e.Seal(e2e.SealParams{
		CS: res.CS, From: "asendr2", To: "arecvr2", Epoch: res.Epoch, Pol: res.Bundle.MinPol,
		Type: e2e.TypeText, Payload: []byte("hello sealed world"), RecipientKey: res.Key,
		SenderAK: e2e.AK(aSeed), RecipientAK: res.Bundle.AK,
	})
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	envB64 := base64.RawStdEncoding.EncodeToString(sealed.Envelope)

	// receiver B opens
	b, _, _ := f.cli(t, bSeed, "arecvr2", "tofu")
	marker, body := b.openOne(ctx, bSeed, "arecvr2", "asendr2", envB64)
	if !strings.HasPrefix(marker, "e2ee ") || !strings.Contains(marker, "from=") {
		t.Fatalf("bad marker %q", marker)
	}
	if string(body) != "hello sealed world" {
		t.Fatalf("roundtrip body %q", body)
	}
}

// --- TestSealByDefaultAndPlainOptOut ---

func TestSealByDefaultAndPlainOptOut(t *testing.T) {
	f := newE2EFake(t)
	seed := e2e.NewSeed()
	c, _, _ := f.cli(t, seed, "aownerx", "tofu")
	ctx := context.Background()

	// default: value seals to seal1: and opens back under its aad
	v, err := c.sealValue(ctx, seed, "kv", "k1", []byte("my secret"), false, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v, "seal1:") || !e2e.IsSealed(v) {
		t.Fatalf("not sealed by default: %q", v)
	}
	pt, err := c.openValueAAD(seed, "kv", "k1", v)
	if err != nil || string(pt) != "my secret" {
		t.Fatalf("open sealed: %v %q", err, pt)
	}
	// aad is bound: opening under a different key name fails
	if _, err := c.openValueAAD(seed, "kv", "other", v); err == nil {
		t.Fatal("aad not bound to key name")
	}
	// --plain opts out
	p, err := c.sealValue(ctx, seed, "kv", "k1", []byte("public note"), true, false)
	if err != nil || p != "public note" {
		t.Fatalf("plain opt-out: %v %q", err, p)
	}
}

// --- TestMkWrapAndRecover ---

func TestMkWrapAndRecover(t *testing.T) {
	f := newE2EFake(t)
	seed := e2e.NewSeed()
	c, _, _ := f.cli(t, seed, "aownerx", "tofu")
	ctx := context.Background()
	recovery := e2e.NewSeed()
	if err := c.putMKWrap(ctx, seed, recovery); err != nil {
		t.Fatal(err)
	}
	if f.mkWrap == "" {
		t.Fatal("wrap not stored")
	}
	mk, err := recoverMK(f.mkWrap, recovery)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !bytes.Equal(mk, e2e.MK(seed)) {
		t.Fatal("recovered mk != MK(seed)")
	}
	// the wrong recovery code fails
	if _, err := recoverMK(f.mkWrap, e2e.NewSeed()); err == nil {
		t.Fatal("wrong code should fail")
	}
}

// --- TestPolicyPackHygieneRefusesSecret ---

func TestPolicyPackHygieneRefusesSecret(t *testing.T) {
	f := newE2EFake(t)
	seed := e2e.NewSeed()
	c, _, _ := f.cli(t, seed, "aownerx", "tofu")
	ctx := context.Background()
	secret := "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\n-----END RSA PRIVATE KEY-----"

	// sealing a tier-1 secret refuses
	if _, err := c.sealValue(ctx, seed, "kv", "k1", []byte(secret), false, false); err == nil || !strings.Contains(err.Error(), "err scrub") {
		t.Fatalf("hygiene did not refuse the secret: %v", err)
	}
	// --mask redacts it, then seals
	v, err := c.sealValue(ctx, seed, "kv", "k1", []byte(secret), false, true)
	if err != nil || !e2e.IsSealed(v) {
		t.Fatalf("mask+seal: %v", err)
	}
	pt, _ := c.openValueAAD(seed, "kv", "k1", v)
	if strings.Contains(string(pt), "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("secret survived masking: %q", pt)
	}
	// a clean value passes
	if _, err := c.sealValue(ctx, seed, "kv", "k1", []byte("just text"), false, false); err != nil {
		t.Fatalf("clean value refused: %v", err)
	}
	// the client pins a rules version for X-Scrub-V
	if c.scrubVersion(ctx) == "" {
		t.Fatal("no rules_v pinned")
	}
}

// --- TestProvenanceMarkers ---

func TestProvenanceMarkers(t *testing.T) {
	if sealedMarker("ok", "abcd1234") != "e2ee ok from=abcd1234" {
		t.Fatal("sealed ok marker")
	}
	if sealedMarker("tofu", "abcd1234") != "e2ee tofu from=abcd1234" {
		t.Fatal("sealed tofu marker")
	}
	if plainMarker("asendr2") != "plain from=asendr2" {
		t.Fatal("plain marker")
	}
	// a tampered envelope opens to an "e2ee bad" marker with the body withheld
	f := newE2EFake(t)
	aSeed, bSeed := e2e.NewSeed(), e2e.NewSeed()
	f.addIdent("asendr2", mustBundle(aSeed, "asendr2"))
	f.addIdent("arecvr2", mustBundle(bSeed, "arecvr2"))
	ctx := context.Background()
	a, _, _ := f.cli(t, aSeed, "asendr2", "tofu")
	res, _ := a.dvr(ctx, "arecvr2", false)
	sealed, _ := e2e.Seal(e2e.SealParams{
		CS: res.CS, From: "asendr2", To: "arecvr2", Epoch: res.Epoch, Pol: res.Bundle.MinPol,
		Type: e2e.TypeText, Payload: []byte("secret"), RecipientKey: res.Key,
		SenderAK: e2e.AK(aSeed), RecipientAK: res.Bundle.AK,
	})
	env := sealed.Envelope
	env[len(env)-1] ^= 0xff // tamper the MAC
	b, _, _ := f.cli(t, bSeed, "arecvr2", "tofu")
	marker, body := b.openOne(ctx, bSeed, "arecvr2", "asendr2", base64.RawStdEncoding.EncodeToString(env))
	if !strings.HasPrefix(marker, "e2ee bad") {
		t.Fatalf("tamper not flagged: %q", marker)
	}
	if strings.Contains(string(body), "secret") {
		t.Fatalf("body not withheld: %q", body)
	}
}

func mustBundle(seed []byte, id string) []byte {
	raw, err := buildRegBundle(seed, id, e2e.PolicyBoth)
	if err != nil {
		panic(err)
	}
	return raw
}

// --- TestSelftestVectors ---

func TestSelftestVectors(t *testing.T) {
	n, err := runSelftest()
	if err != nil {
		t.Fatalf("selftest: %v", err)
	}
	if n < 5 {
		t.Fatalf("too few checks: %d", n)
	}
	f := newE2EFake(t)
	c, out, _ := f.cli(t, e2e.NewSeed(), "aownerx", "tofu")
	if err := cmdSelftest(c, context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "selftest ok") {
		t.Fatalf("selftest output %q", out.String())
	}
}

// --- TestSubE2EDerivation ---

func TestSubE2EDerivation(t *testing.T) {
	parent := e2e.NewSeed()
	child := deriveSubSeed(parent, "achild1")
	if !strings.HasPrefix(child, "cxs_") {
		t.Fatalf("child seed form %q", child)
	}
	cb, err := e2e.ParseSeed(child)
	if err != nil || len(cb) != e2e.SeedSize {
		t.Fatalf("child seed parse: %v", err)
	}
	// deterministic, differs from the parent and from a sibling
	if deriveSubSeed(parent, "achild1") != child {
		t.Fatal("not deterministic")
	}
	if bytes.Equal(cb, parent) {
		t.Fatal("child equals parent (climb-back)")
	}
	if deriveSubSeed(parent, "achild2") == child {
		t.Fatal("siblings collide")
	}
}

// --- TestLogWitnessAudit ---

func TestLogWitnessAudit(t *testing.T) {
	f := newE2EFake(t)
	seed := e2e.NewSeed()
	f.addIdent("aownerx", mustBundle(seed, "aownerx"))
	c, out, _ := f.cli(t, seed, "aownerx", "mirror")
	ctx := context.Background()

	// witness: the mirror head verifies under the online + witness keys
	if err := c.logWitness(ctx); err != nil {
		t.Fatalf("log witness: %v", err)
	}
	if !strings.Contains(out.String(), "witnessed size=") {
		t.Fatalf("witness output %q", out.String())
	}

	// audit: our own leaves match the log
	leaf := f.logLeaf["aownerx"][0]
	writeFile0600(c.cxDir()+"/own_leaves", []byte(strconv.FormatUint(leaf, 10)))
	out.Reset()
	if err := c.logAudit(ctx); err != nil {
		t.Fatalf("log audit: %v", err)
	}
	if !strings.Contains(out.String(), "audit ok") {
		t.Fatalf("audit output %q", out.String())
	}
	// a foreign leaf in the log is a key-substitution alert
	f.mu.Lock()
	f.logLeaf["aownerx"] = append(f.logLeaf["aownerx"], 999)
	f.mu.Unlock()
	if err := c.logAudit(ctx); err == nil || !strings.Contains(err.Error(), "key-substituted") {
		t.Fatalf("substitution not detected: %v", err)
	}
}

// --- help lists the sealed verbs and documents the flags (acceptance item 2) ---

func TestHelpListsSealedVerbs(t *testing.T) {
	h := usageText()
	for _, v := range []string{"xs", "xr", "xw", "xa", "xp", "xb", "xrep", "keys", "fp", "pk", "seal", "selftest"} {
		if !strings.Contains(h, "\n  "+v+" ") && !strings.Contains(h, "\n  "+v+"\n") {
			t.Errorf("help missing verb %q", v)
		}
	}
	if !strings.Contains(h, "--plain") || !strings.Contains(h, "--e2e") {
		t.Error("help does not document --plain/--e2e")
	}
}
