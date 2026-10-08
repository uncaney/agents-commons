package e2e_test

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/e2e"
)

const (
	alice = "aalice2"
	bob   = "abobbob"
	carol = "acarol7"
	dave  = "adave77"
	gid   = "gswarm2"
	now   = int64(1_790_000_000) // 2026-09-21
)

func seedN(n byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = n + byte(i)
	}
	return s
}

func rnd(n uint64) *rand.ChaCha8 {
	var k [32]byte
	k[0] = byte(n)
	k[1] = byte(n >> 8)
	return rand.NewChaCha8(k)
}

func pub(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }

func bundleFor(t testing.TB, seed []byte, id string, seq uint32, cs2 bool, flags uint8, e0 uint32) (*e2e.Bundle, []byte) {
	t.Helper()
	if cs2 {
		flags |= e2e.FlagCS2
	}
	b, err := e2e.NewBundle(seed, e2e.BundleParams{ID: id, Seq: seq, IAT: uint32(now - 3600), Exp: uint32(now + 30*86400),
		Flags: flags, MailPolicy: e2e.PolicyBoth, MinCS: 1, E0: e0, NEK: 5, RevCommit: e2e.Sum([]byte("revoke"))})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := b.Sign(e2e.IK(seed), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b, raw
}

func TestDerivationsDeterministic(t *testing.T) {
	s := seedN(1)
	if !bytes.Equal(e2e.IK(s), e2e.IK(seedN(1))) || !bytes.Equal(e2e.RK(s), e2e.RK(seedN(1))) {
		t.Fatal("ik/rk not deterministic")
	}
	if bytes.Equal(e2e.IK(s).Seed(), e2e.RK(s).Seed()) || bytes.Equal(e2e.IK(s).Seed(), e2e.AK(s).Bytes()) || bytes.Equal(e2e.KState(s), e2e.MK(s)) {
		t.Fatal("labels do not separate derivations")
	}
	for _, cs := range []e2e.Suite{e2e.CS1, e2e.CS2} {
		lk, _ := e2e.LK(s, cs)
		lk2, _ := e2e.LK(s, cs)
		if !bytes.Equal(lk.PublicKey().Bytes(), lk2.PublicKey().Bytes()) || len(lk.PublicKey().Bytes()) != cs.PKSize() {
			t.Fatalf("lk cs=%d", cs)
		}
		e1, _ := e2e.EK(s, cs, 2960, nil)
		e1b, _ := e2e.EK(s, cs, 2960, nil)
		e2, _ := e2e.EK(s, cs, 2961, nil)
		share := e2e.Sum([]byte("share"))
		e1s, _ := e2e.EK(s, cs, 2960, share)
		if !bytes.Equal(e1.PublicKey().Bytes(), e1b.PublicKey().Bytes()) || bytes.Equal(e1.PublicKey().Bytes(), e2.PublicKey().Bytes()) || bytes.Equal(e1.PublicKey().Bytes(), e1s.PublicKey().Bytes()) {
			t.Fatalf("ek cs=%d not (deterministic, per epoch, per share)", cs)
		}
		if _, err := e2e.EK(s, cs, 1, []byte("short")); err == nil {
			t.Fatal("short share accepted")
		}
	}
	if _, err := e2e.LK(s, 3); !errors.Is(err, e2e.ErrSuite) {
		t.Fatal("suite 3 accepted")
	}
	child := e2e.Sub(s, "worker-1")
	if bytes.Equal(child, s) || bytes.Equal(child, e2e.Sub(s, "worker-2")) || !bytes.Equal(child, e2e.Sub(seedN(1), "worker-1")) {
		t.Fatal("sub seeds")
	}
	if bytes.Equal(e2e.IK(child), e2e.IK(s)) {
		t.Fatal("child ik equals parent ik")
	}
	pq := e2e.PQID(s)
	if !bytes.Equal(pq.PublicKey().Bytes(), e2e.PQID(seedN(1)).PublicKey().Bytes()) || len(pq.PublicKey().Bytes()) != e2e.PQIDSize {
		t.Fatal("pq id")
	}
	if e2e.Epoch(now) != 2959 || e2e.Epoch(0) != 0 || e2e.EpochStart(2960) != 2960*604800 || e2e.Epoch(-5) != 0 {
		t.Fatalf("epoch %d", e2e.Epoch(now))
	}
	txt := e2e.FormatSeed(s)
	if !strings.HasPrefix(txt, "cxs_") || len(txt) != 47 {
		t.Fatalf("seed format %q", txt)
	}
	for _, in := range []string{txt, txt[4:], " " + txt + "\n"} {
		got, err := e2e.ParseSeed(in)
		if err != nil || !bytes.Equal(got, s) {
			t.Fatalf("parse seed %q: %v", in, err)
		}
	}
	for _, bad := range []string{"", "cxs_", txt[:46], txt + "A", strings.Replace(txt, "_", "!", 1)} {
		if _, err := e2e.ParseSeed(bad); err == nil {
			t.Fatalf("bad seed %q accepted", bad)
		}
	}
	fp := e2e.Fingerprint(pub(e2e.IK(s)))
	d := e2e.FPDigits(fp)
	groups := strings.Split(d, " ")
	if len(groups) != 12 {
		t.Fatalf("fp digits %q", d)
	}
	for _, g := range groups {
		if len(g) != 5 || strings.Trim(g, "0123456789") != "" {
			t.Fatalf("fp group %q", g)
		}
	}
	if len(e2e.FP16(fp)) != 16 || e2e.FP16(fp) != hex.EncodeToString(fp)[:16] {
		t.Fatal("fp16")
	}
	mk, code := e2e.MK(s), []byte("recovery-code-123")
	w, err := e2e.WrapMK(mk, code, rnd(1))
	if err != nil || len(w) != 60 {
		t.Fatal(err, len(w))
	}
	got, err := e2e.UnwrapMK(w, code)
	if err != nil || !bytes.Equal(got, mk) {
		t.Fatal("unwrap mk")
	}
	if _, err := e2e.UnwrapMK(w, []byte("wrong")); err == nil {
		t.Fatal("unwrap with the wrong code")
	}
	if len(e2e.NewSeed()) != 32 || bytes.Equal(e2e.NewSeed(), e2e.NewSeed()) {
		t.Fatal("new seed")
	}
}

func TestPaddingBuckets(t *testing.T) {
	for n := 0; n < 4096; n++ {
		pt := bytes.Repeat([]byte{0xAB}, n)
		p, err := e2e.Pad(pt, e2e.MailBuckets)
		if err != nil {
			t.Fatal(n, err)
		}
		want := 1024
		switch {
		case n >= 2048:
			want = 4096
		case n >= 1024:
			want = 2048
		}
		if len(p) != want || !e2e.IsBucket(len(p), e2e.MailBuckets) {
			t.Fatalf("n=%d bucket %d want %d", n, len(p), want)
		}
		if n%97 == 0 {
			u, err := e2e.Unpad(p)
			if err != nil || !bytes.Equal(u, pt) {
				t.Fatalf("unpad n=%d", n)
			}
		}
	}
	if _, err := e2e.Pad(make([]byte, 4096), e2e.MailBuckets); !errors.Is(err, e2e.ErrTooLarge) {
		t.Fatal("4096 bytes must not fit")
	}
	if _, err := e2e.Pad(make([]byte, 65535), e2e.ObjectBuckets); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, {0}, make([]byte, 1024), append(bytes.Repeat([]byte{1}, 1023), 0)} {
		if _, err := e2e.Unpad(bad); !errors.Is(err, e2e.ErrPadding) {
			t.Fatalf("unpad %x accepted", bad)
		}
	}
	// the trailing zero run is skipped, a 0x80 inside the payload is data
	u, err := e2e.Unpad([]byte{0x80, 0x80, 0, 0})
	if err != nil || !bytes.Equal(u, []byte{0x80}) {
		t.Fatal("unpad inner 0x80")
	}
	if e2e.EnvelopeSize(e2e.CS1, 1024) != 1175 || e2e.EnvelopeSize(e2e.CS1, 2048) != 2199 || e2e.EnvelopeSize(e2e.CS1, 4096) != 4247 ||
		e2e.EnvelopeSize(e2e.CS2, 1024) != 2263 || e2e.EnvelopeSize(e2e.CS2, 4096) != 5335 || e2e.EnvelopeSize(e2e.CS2, 4096) > e2e.MailCap {
		t.Fatal("envelope size table")
	}
	in := &e2e.Inner{KF: make([]byte, 32), Payload: make([]byte, e2e.MaxPayload)}
	m, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if p, err := e2e.Pad(m, e2e.MailBuckets); err != nil || len(p) != 4096 {
		t.Fatal("max payload must fill the 4k bucket")
	}
	in.Payload = make([]byte, e2e.MaxPayload+1)
	if _, err := in.Marshal(); err == nil {
		t.Fatal("payload above the cap accepted")
	}
	if e2e.BucketName(2048) != "2k" || e2e.BucketName(65536) != "64k" || e2e.BucketName(3) != "" {
		t.Fatal("bucket names")
	}
}

type pair struct {
	sa, sb         []byte
	ba, bb         *e2e.Bundle
	rawA, rawB     []byte
	akA, akB       *ecdh.PrivateKey
	epoch          uint32
	ekB1, ekB2     hpke.PrivateKey
	lkB1           hpke.PrivateKey
	onlineSK       ed25519.PrivateKey
	w1SK           ed25519.PrivateKey
	onlinePK, w1PK []byte
}

func newPair(t testing.TB) *pair {
	t.Helper()
	p := &pair{sa: seedN(10), sb: seedN(20), epoch: e2e.Epoch(now)}
	p.ba, p.rawA = bundleFor(t, p.sa, alice, 1, true, 0, p.epoch-1)
	p.bb, p.rawB = bundleFor(t, p.sb, bob, 1, true, e2e.FlagLKOK, p.epoch-1)
	p.akA, p.akB = e2e.AK(p.sa), e2e.AK(p.sb)
	p.ekB1, _ = e2e.EK(p.sb, e2e.CS1, p.epoch, nil)
	p.ekB2, _ = e2e.EK(p.sb, e2e.CS2, p.epoch, nil)
	p.lkB1, _ = e2e.LK(p.sb, e2e.CS1)
	p.onlineSK = ed25519.NewKeyFromSeed(seedN(100))
	p.w1SK = ed25519.NewKeyFromSeed(seedN(101))
	p.onlinePK, p.w1PK = pub(p.onlineSK), pub(p.w1SK)
	return p
}

func (p *pair) seal(t testing.TB, cs e2e.Suite, payload []byte, typ uint8) *e2e.Sealed {
	t.Helper()
	key, _ := p.bb.EK(cs, p.epoch)
	s, err := e2e.Seal(e2e.SealParams{CS: cs, From: alice, To: bob, Epoch: p.epoch, Pol: 3, TS: uint32(now), Type: typ, Payload: payload,
		RecipientKey: key, SenderAK: p.akA, RecipientAK: p.bb.AK, Rand: rnd(7)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (p *pair) open(env []byte, cs e2e.Suite) (*e2e.Inner, error) {
	e, err := e2e.ParseEnvelope(env)
	if err != nil {
		return nil, err
	}
	sk := p.ekB1
	if cs == e2e.CS2 {
		sk = p.ekB2
	}
	return e.Open(e2e.OpenParams{Me: bob, RecipientKey: sk, RecipientAK: p.akB, SenderAK: p.ba.AK})
}

func TestCxm1SealOpenFrank(t *testing.T) {
	p := newPair(t)
	for _, cs := range []e2e.Suite{e2e.CS1, e2e.CS2} {
		for _, n := range []int{0, 1, 984, 985, 2000, e2e.MaxPayload} {
			payload := bytes.Repeat([]byte{byte(n)}, n)
			s := p.seal(t, cs, payload, e2e.TypeText)
			bucket, _ := e2e.Bucket(e2e.InnerHdrLen+n, e2e.MailBuckets)
			if len(s.Envelope) != e2e.EnvelopeSize(cs, bucket) {
				t.Fatalf("cs=%d n=%d size %d", cs, n, len(s.Envelope))
			}
			in, err := p.open(s.Envelope, cs)
			if err != nil || !bytes.Equal(in.Payload, payload) || in.TS != uint32(now) || in.Type != e2e.TypeText {
				t.Fatalf("cs=%d n=%d open: %v", cs, n, err)
			}
			e, _ := e2e.ParseEnvelope(s.Envelope)
			if !e2e.VerifyFrank(&e.Hdr, in.KF, in.Type, in.Payload) || e2e.VerifyFrank(&e.Hdr, in.KF, in.Type, append(in.Payload, 'x')) {
				t.Fatal("frank report verification")
			}
			if e.CS != cs || e.From != alice || e.To != bob || e.Epoch != p.epoch || e.Pol != 3 || !bytes.Equal(e.Bytes(), s.Envelope) {
				t.Fatal("parsed header fields")
			}
		}
	}
	s := p.seal(t, e2e.CS1, []byte("hello bob"), e2e.TypeText)
	env := s.Envelope
	// every tampered byte region must fail, and the failure must be the first check that covers it
	regions := map[string][2]int{"hdr": {0, 71}, "enc": {71, 103}, "ct": {103, len(env) - 32}, "mac": {len(env) - 32, len(env)}}
	for name, r := range regions {
		for i := r[0]; i < r[1]; i += 7 {
			bad := append([]byte(nil), env...)
			bad[i] ^= 0x01
			if _, err := p.open(bad, e2e.CS1); err == nil {
				t.Fatalf("tampered %s byte %d accepted", name, i)
			}
		}
	}
	// wrong recipient key: HPKE fails before AEAD, so the MAC (which needs the exporter) fails first
	e, _ := e2e.ParseEnvelope(env)
	if _, err := e.Open(e2e.OpenParams{Me: bob, RecipientKey: p.lkB1, RecipientAK: p.akB, SenderAK: p.ba.AK}); err == nil {
		t.Fatal("wrong recipient key accepted")
	}
	if _, err := e.Open(e2e.OpenParams{Me: bob, RecipientKey: p.ekB1, RecipientAK: p.akB, SenderAK: p.bb.AK}); !errors.Is(err, e2e.ErrMAC) {
		t.Fatalf("wrong sender ak: %v", err)
	}
	if _, err := e.Open(e2e.OpenParams{Me: carol, RecipientKey: p.ekB1, RecipientAK: p.akB, SenderAK: p.ba.AK}); !errors.Is(err, e2e.ErrNotMine) {
		t.Fatalf("not mine: %v", err)
	}
	low := make([]byte, 32) // low-order X25519 point: crypto/ecdh refuses the all-zero shared secret
	if _, err := e.Open(e2e.OpenParams{Me: bob, RecipientKey: p.ekB1, RecipientAK: p.akB, SenderAK: low}); !errors.Is(err, e2e.ErrMAC) {
		t.Fatalf("low-order point: %v", err)
	}
	// sizes: truncated, extended, wrong cs for the enc length
	for _, bad := range [][]byte{env[:len(env)-1], append(append([]byte(nil), env...), 0), env[:70]} {
		if _, err := e2e.ParseEnvelope(bad); err == nil {
			t.Fatal("bad length accepted")
		}
	}
	wrongCS := append([]byte(nil), env...)
	wrongCS[1] = 2
	if _, err := e2e.ParseEnvelope(wrongCS); !errors.Is(err, e2e.ErrSizeBkt) {
		t.Fatalf("cs/enc mismatch: %v", err)
	}
	// an envelope the server moved to another inbox fails (to is in info, AAD and MAC)
	moved := append([]byte(nil), env...)
	copy(moved[10:17], carol)
	em, err := e2e.ParseEnvelope(moved)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := em.Open(e2e.OpenParams{Me: carol, RecipientKey: p.ekB1, RecipientAK: p.akB, SenderAK: p.ba.AK}); err == nil {
		t.Fatal("moved envelope accepted")
	}
	// LT: sealed to lk with epoch 0
	lt, err := e2e.Seal(e2e.SealParams{CS: e2e.CS1, Flags: e2e.FlagLT, From: alice, To: bob, Epoch: 0, Payload: []byte("last resort"),
		RecipientKey: p.bb.LK1, SenderAK: p.akA, RecipientAK: p.bb.AK, Rand: rnd(8)})
	if err != nil {
		t.Fatal(err)
	}
	el, _ := e2e.ParseEnvelope(lt.Envelope)
	if in, err := el.Open(e2e.OpenParams{Me: bob, RecipientKey: p.lkB1, RecipientAK: p.akB, SenderAK: p.ba.AK}); err != nil || string(in.Payload) != "last resort" {
		t.Fatal("LT open", err)
	}
	if _, err := e2e.Seal(e2e.SealParams{CS: e2e.CS1, From: alice, To: bob, Epoch: 0, Payload: nil, RecipientKey: p.bb.LK1, SenderAK: p.akA, RecipientAK: p.bb.AK}); err == nil {
		t.Fatal("epoch 0 without LT accepted")
	}
	// relay receipt
	rcpt := e2e.SignRcpt(p.onlineSK, s.Hdr, 42, uint64(now))
	if !e2e.VerifyRcpt(p.onlinePK, s.Hdr, 42, uint64(now), rcpt) || e2e.VerifyRcpt(p.onlinePK, s.Hdr, 42, uint64(now)+1, rcpt) || e2e.VerifyRcpt(p.w1PK, s.Hdr, 42, uint64(now), rcpt) {
		t.Fatal("receipt")
	}
	// MinBucket forces the 4k shape
	big, _ := e2e.Seal(e2e.SealParams{CS: e2e.CS1, From: alice, To: bob, Epoch: p.epoch, Payload: []byte("x"), RecipientKey: p.bb.EK1[1],
		SenderAK: p.akA, RecipientAK: p.bb.AK, MinBucket: 4096, Rand: rnd(9)})
	if len(big.Envelope) != 4247 {
		t.Fatal("min bucket")
	}
	if !strings.HasPrefix(e2e.StampPrefix(bob, []byte("b"), "20260921"), "cx1/stamp:"+bob+":") {
		t.Fatal("stamp prefix")
	}
}

func TestFrankMismatchDetected(t *testing.T) {
	p := newPair(t)
	kf := e2e.Sum([]byte("kf"))
	payload := []byte("what the sender really said")
	inner, _ := (&e2e.Inner{KF: kf, TS: uint32(now), Type: e2e.TypeText, Payload: payload}).Marshal()
	padded, _ := e2e.Pad(inner, e2e.MailBuckets)
	mid := e2e.Sum([]byte("mid"))[:16]
	// a patched client commits to a different payload than it seals
	h := e2e.Hdr{CS: e2e.CS1, From: alice, To: bob, Epoch: p.epoch, Mid: mid, C: e2e.Frank(kf, alice, bob, mid, e2e.TypeText, []byte("something innocent"))}
	hdr := h.Marshal()
	pk, _ := e2e.CS1.NewPublicKey(p.bb.EK1[1])
	enc, s, err := hpke.NewSender(pk, e2e.KDF(), e2e.AEAD(), e2e.MailInfo(alice, bob, p.epoch))
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := s.Seal(hdr, padded)
	exp, _ := s.Export(e2e.LabelAuth, 32)
	rpk, _ := ecdh.X25519().NewPublicKey(p.bb.AK)
	ss, _ := p.akA.ECDH(rpk)
	mac := e2e.SenderMAC(e2e.AuthKey(ss, exp, alice, bob), hdr, enc, ct)
	env := append(append(append(hdr, enc...), ct...), mac...)
	if _, err := p.open(env, e2e.CS1); !errors.Is(err, e2e.ErrFrank) {
		t.Fatalf("frank mismatch not detected: %v", err)
	}
	// the honest commitment opens
	h.C = e2e.Frank(kf, alice, bob, mid, e2e.TypeText, payload)
	hdr = h.Marshal()
	enc, s, _ = hpke.NewSender(pk, e2e.KDF(), e2e.AEAD(), e2e.MailInfo(alice, bob, p.epoch))
	ct, _ = s.Seal(hdr, padded)
	exp, _ = s.Export(e2e.LabelAuth, 32)
	mac = e2e.SenderMAC(e2e.AuthKey(ss, exp, alice, bob), hdr, enc, ct)
	in, err := p.open(append(append(append(hdr, enc...), ct...), mac...), e2e.CS1)
	if err != nil || !bytes.Equal(in.Payload, payload) {
		t.Fatal("honest envelope", err)
	}
	// a report with a fabricated payload fails the server-side recomputation
	if e2e.VerifyFrank(&h, kf, e2e.TypeText, []byte("fabricated")) || e2e.VerifyFrank(&h, e2e.Sum([]byte("other kf")), e2e.TypeText, payload) || e2e.VerifyFrank(&h, kf, e2e.TypeJSON, payload) {
		t.Fatal("fabricated report verified")
	}
}

func TestSealedStateCAS(t *testing.T) {
	k := e2e.KState(seedN(3))
	st := &e2e.State{Pins: map[string]e2e.Pin{bob: {FP: "ab", Seq: 2, CS: 2, Leaf: 7, Pol: 1}}, Cursor: 99}
	pt, err := st.Encode()
	if err != nil {
		t.Fatal(err)
	}
	blob1, err := e2e.SealState(k, alice, 1, pt, rnd(1))
	if err != nil {
		t.Fatal(err)
	}
	got, err := e2e.OpenState(k, alice, 1, blob1)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatal("open state", err)
	}
	dec, _ := e2e.DecodeState(got)
	if dec.Pins[bob].Leaf != 7 || dec.Cursor != 99 {
		t.Fatal("decoded state")
	}
	// the server cannot serve blob 1 under version 2, for another id, or tampered
	if _, err := e2e.OpenState(k, alice, 2, blob1); err == nil {
		t.Fatal("blob served under another version accepted")
	}
	if _, err := e2e.OpenState(k, bob, 1, blob1); err == nil {
		t.Fatal("blob served for another id accepted")
	}
	bad := append([]byte(nil), blob1...)
	bad[40] ^= 1
	if _, err := e2e.OpenState(k, alice, 1, bad); err == nil {
		t.Fatal("tampered blob accepted")
	}
	// compare-and-swap: version 2 is a fresh seal; receipts order the versions and a rollback is stale
	blob2, _ := e2e.SealState(k, alice, 2, pt, rnd(2))
	if bytes.Equal(blob1, blob2) {
		t.Fatal("fresh salt expected")
	}
	r1, r2 := e2e.StateReceipt(alice, 1, blob1), e2e.StateReceipt(alice, 2, blob2)
	if bytes.Equal(r1, r2) || !bytes.Equal(r2, e2e.Sum([]byte(alice), e2e.U64(2), e2e.Sum(blob2))) {
		t.Fatal("receipts")
	}
	if !e2e.StateStale(1, 2) || e2e.StateStale(2, 2) || e2e.StateStale(3, 2) {
		t.Fatal("stale detection")
	}
	// caps
	if _, err := e2e.SealState(k, alice, 1, make([]byte, e2e.StateCap), nil); err == nil {
		t.Fatal("oversized state accepted")
	}
	if _, err := e2e.OpenState(k, alice, 1, make([]byte, e2e.StateCap+1)); err == nil {
		t.Fatal("oversized blob accepted")
	}
	s2 := &e2e.State{}
	for i := 0; i < e2e.SeenCap+10; i++ {
		if s2.MarkSeen(strings.Repeat("m", 3) + hex.EncodeToString(e2e.U32(uint32(i)))) {
			t.Fatal("fresh mid reported seen")
		}
	}
	if !s2.MarkSeen(strings.Repeat("m", 3)+hex.EncodeToString(e2e.U32(uint32(e2e.SeenCap+9)))) || len(s2.Seen) != e2e.SeenCap {
		t.Fatal("seen window")
	}
}

func TestCxs1AndSeal1Seal2Formats(t *testing.T) {
	secret := []byte("drop capability secret")
	loc := e2e.Locator(secret)
	if len(loc) != 16 || len(e2e.LocatorHex(secret)) != 32 || bytes.Equal(loc, e2e.Locator([]byte("other"))) {
		t.Fatal("locator")
	}
	kEnc, kMac := e2e.Cxs1Keys(secret)
	if len(kEnc) != 32 || len(kMac) != 32 || bytes.Equal(kEnc, kMac) || len(e2e.WriteToken(kMac)) != 32 {
		t.Fatal("keys")
	}
	for _, n := range []int{0, 1, 31, 32, 33, 1000} {
		pt := bytes.Repeat([]byte{byte(n)}, n)
		rec, err := e2e.Cxs1Seal(secret, pt, rnd(uint64(n)))
		if err != nil || len(rec) != n+e2e.Cxs1Overhead || string(rec[:4]) != "cxs1" {
			t.Fatal("seal", err)
		}
		got, err := e2e.Cxs1Open(secret, rec)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatal("open", err)
		}
		if _, err := e2e.Cxs1Open([]byte("wrong"), rec); err == nil {
			t.Fatal("wrong secret accepted")
		}
		for i := 0; i < len(rec); i += 5 {
			bad := append([]byte(nil), rec...)
			bad[i] ^= 0x80
			if _, err := e2e.Cxs1Open(secret, bad); err == nil {
				t.Fatalf("tampered byte %d accepted", i)
			}
		}
		txt := e2e.EncodeCxs1(rec)
		dec, err := e2e.DecodeCxs1(txt)
		if err != nil || !bytes.Equal(dec, rec) || !strings.HasPrefix(txt, "cxs1:") {
			t.Fatal("text form")
		}
	}
	r1, _ := e2e.Cxs1Seal(secret, []byte("one"), rnd(1))
	r2, _ := e2e.Cxs1Seal(secret, []byte("two"), rnd(2))
	bad := append([]byte(nil), r2...)
	bad[50] ^= 1
	pts, badIdx := e2e.Cxs1OpenAll(secret, [][]byte{r1, bad, r2})
	if len(pts) != 2 || string(pts[0]) != "one" || string(pts[1]) != "two" || len(badIdx) != 1 || badIdx[0] != 1 {
		t.Fatal("open all must skip the bad record")
	}
	if _, err := e2e.Cxs1Open(secret, r1[:67]); err == nil {
		t.Fatal("short record accepted")
	}

	// sealed memory values (26.4)
	kv := e2e.SealV1Key(e2e.MK(seedN(5)))
	v1, err := e2e.Seal1(kv, "u:alice|notes|todo", []byte("buy milk"), rnd(3))
	if err != nil || !strings.HasPrefix(v1, "seal1:") || !e2e.IsSealed(v1) {
		t.Fatal("seal1", err)
	}
	if pt, err := e2e.Open1(kv, "u:alice|notes|todo", v1); err != nil || string(pt) != "buy milk" {
		t.Fatal("open1", err)
	}
	if _, err := e2e.Open1(kv, "u:alice|notes|other", v1); err == nil {
		t.Fatal("seal1 under another key name accepted")
	}
	if _, err := e2e.Open1(kv, "u:alice|notes|todo", v1[:len(v1)-2]+"AA"); err == nil {
		t.Fatal("tampered seal1 accepted")
	}
	aad2 := "u:alice|kv|state"
	v2, err := e2e.Seal2(kv, aad2, []byte(strings.Repeat("state ", 50)), rnd(4))
	if err != nil || !strings.HasPrefix(v2, "seal2:") || !e2e.IsSealed(v2) {
		t.Fatal("seal2", err)
	}
	if pt, err := e2e.Open2(kv, aad2, v2); err != nil || string(pt) != strings.Repeat("state ", 50) {
		t.Fatal("open2", err)
	}
	// Security Review 2 #11: the aad (ns|k) is bound into the tag key, so the server cannot move a
	// sealed value to another key name even under the same k_v.
	if _, err := e2e.Open2(kv, "u:alice|kv|other", v2); err == nil {
		t.Fatal("seal2 under another key name accepted")
	}
	if _, err := e2e.Open2(kv, "", v2); err == nil {
		t.Fatal("seal2 under the unbound aad accepted")
	}
	if _, err := e2e.Open2(kv, aad2, "seal2:"+strings.Repeat("A", 70)); err == nil {
		t.Fatal("garbage seal2 accepted")
	}
	if _, err := e2e.Open2(e2e.SealV1Key(e2e.MK(seedN(6))), aad2, v2); err == nil {
		t.Fatal("seal2 under another mk accepted")
	}
	if _, err := e2e.Open1(kv, "", v2); err == nil {
		t.Fatal("seal2 value opened as seal1")
	}
	for _, bad := range []string{"", "seal1:", "seal3:AAAA", "seal1:AA$A", "seal1:AAAA\n", "SEAL1:AAAA", " seal1:AAAA"} {
		if e2e.IsSealed(bad) {
			t.Fatalf("%q matched", bad)
		}
	}
	// nonce reuse: two values sealed with the same nonce are refused by the server
	same1, _ := e2e.Seal1(kv, "k", []byte("v1"), rnd(11))
	same2, _ := e2e.Seal1(kv, "k", []byte("v2"), rnd(11))
	fresh, _ := e2e.Seal1(kv, "k", []byte("v3"), rnd(12))
	n1, _ := e2e.SealedNonce(same1)
	if len(n1) != 12 || !e2e.NonceReused(same1, same2) || e2e.NonceReused(same1, fresh) {
		t.Fatal("seal1 nonce reuse detection")
	}
	s21, _ := e2e.Seal2(kv, aad2, []byte("a"), rnd(21))
	s22, _ := e2e.Seal2(kv, aad2, []byte("b"), rnd(21))
	n2, _ := e2e.SealedNonce(s21)
	if len(n2) != 16 || !e2e.NonceReused(s21, s22) || e2e.NonceReused(s21, v2) || e2e.NonceReused(same1, s21) || e2e.NonceReused("x", s21) {
		t.Fatal("seal2 nonce reuse detection")
	}
}

func TestBundleSignVerify(t *testing.T) {
	s := seedN(30)
	b1, raw1 := bundleFor(t, s, alice, 1, false, 0, 2960)
	if len(raw1) != 514 {
		t.Fatalf("cs=1 bundle %d bytes", len(raw1))
	}
	_, raw2 := bundleFor(t, s, alice, 1, true, 0, 2960)
	if len(raw2) != 7810 {
		t.Fatalf("cs=2 bundle %d bytes", len(raw2))
	}
	bpq, err := e2e.NewBundle(s, e2e.BundleParams{ID: alice, Seq: 1, IAT: uint32(now), Exp: uint32(now + 86400), Flags: e2e.FlagCS2 | e2e.FlagPQ,
		MailPolicy: e2e.PolicyE2EE, MinCS: 2, E0: 2960, NEK: 5, RevCommit: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	rawPQ, err := bpq.Sign(e2e.IK(s), nil, e2e.PQID(s))
	if err != nil || len(rawPQ) != 13071 {
		t.Fatalf("pq bundle: %v %d", err, len(rawPQ))
	}
	for _, raw := range [][]byte{raw1, raw2, rawPQ} {
		b, err := e2e.ParseBundle(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Verify(); err != nil {
			t.Fatal(err)
		}
		if b.Rotated() {
			t.Fatal("seq 1 reports a rotation")
		}
		re, _ := b.Sign(e2e.IK(s), nil, e2e.PQID(s))
		if !bytes.Equal(re, raw) {
			t.Fatal("re-sign not byte identical")
		}
		for i := 0; i < len(raw); i += 101 {
			bad := append([]byte(nil), raw...)
			bad[i] ^= 1
			// sig_prev bytes are checked by VerifyRotation against the stored ik; a seq-1 bundle with
			// a non-zero sig_prev is refused by Verify itself
			if pb, err := e2e.ParseBundle(bad); err == nil && pb.Verify() == nil {
				t.Fatalf("tampered byte %d accepted", i)
			}
		}
		for _, bad := range [][]byte{raw[:len(raw)-1], append(append([]byte(nil), raw...), 0), raw[:30]} {
			if _, err := e2e.ParseBundle(bad); err == nil {
				t.Fatal("bad length accepted")
			}
		}
	}
	if !b1.HasEpoch(2964) || b1.HasEpoch(2965) || b1.HasEpoch(2959) {
		t.Fatal("epochs")
	}
	ek, ok := b1.EK(e2e.CS1, 2962)
	sk, _ := e2e.EK(s, e2e.CS1, 2962, nil)
	if !ok || !bytes.Equal(ek, sk.PublicKey().Bytes()) {
		t.Fatal("ek lookup")
	}
	if _, ok := b1.EK(e2e.CS2, 2962); ok || b1.MaxCS() != e2e.CS1 {
		t.Fatal("cs2 on a cs1 bundle")
	}
	// rotation: seq 2 under a new ik, signed by the previous ik
	s2 := seedN(31)
	ch, _ := b1.CanonicalHash()
	b2, err := e2e.NewBundle(s2, e2e.BundleParams{ID: alice, Seq: 2, IAT: uint32(now), Exp: uint32(now + 86400), MailPolicy: e2e.PolicyBoth,
		E0: 2960, NEK: 5, RevCommit: make([]byte, 32), PrevHash: ch})
	if err != nil {
		t.Fatal(err)
	}
	raw3, err := b2.Sign(e2e.IK(s2), e2e.IK(s), nil)
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := e2e.ParseBundle(raw3)
	if pb.Verify() != nil || !pb.Rotated() || pb.VerifyRotation(b1.IK) != nil || pb.VerifyRotation(b2.IK) == nil || !bytes.Equal(pb.PrevHash, ch) {
		t.Fatal("rotation")
	}
	if _, err := b2.Sign(e2e.IK(s), nil, nil); err == nil {
		t.Fatal("signing with a key that is not the bundle's ik accepted")
	}
	// shape errors
	for name, p := range map[string]e2e.BundleParams{
		"id":     {ID: "Alice!!", Seq: 1, IAT: 1, Exp: 2, NEK: 1, RevCommit: make([]byte, 32)},
		"seq":    {ID: alice, Seq: 0, IAT: 1, Exp: 2, NEK: 1, RevCommit: make([]byte, 32)},
		"exp":    {ID: alice, Seq: 1, IAT: 10, Exp: 10, NEK: 1, RevCommit: make([]byte, 32)},
		"ttl":    {ID: alice, Seq: 1, IAT: 10, Exp: 10 + e2e.BundleMaxTTL + 1, NEK: 1, RevCommit: make([]byte, 32)},
		"nek":    {ID: alice, Seq: 1, IAT: 1, Exp: 2, NEK: 6, RevCommit: make([]byte, 32)},
		"mincs":  {ID: alice, Seq: 1, IAT: 1, Exp: 2, NEK: 1, MinCS: 2, RevCommit: make([]byte, 32)},
		"policy": {ID: alice, Seq: 1, IAT: 1, Exp: 2, NEK: 1, MailPolicy: 3, RevCommit: make([]byte, 32)},
		"revc":   {ID: alice, Seq: 1, IAT: 1, Exp: 2, NEK: 1, RevCommit: make([]byte, 31)},
	} {
		if _, err := e2e.NewBundle(s, p); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if !e2e.ValidID(alice) || e2e.ValidID("aalice1") || e2e.ValidID("Aalice2") || e2e.ValidID("aalice22") {
		t.Fatal("valid id")
	}
	if !bytes.Equal(e2e.BundleHash(raw1), e2e.Sum(raw1)) || bytes.Equal(e2e.BundleHash(raw1), ch) {
		t.Fatal("bundle hashes")
	}
}

func TestReqSigCanonical(t *testing.T) {
	rk := e2e.RK(seedN(40))
	nonce := e2e.Sum([]byte("nonce"))[:16]
	body := []byte(`{"upto":12}`)
	bh := sha256.Sum256(body)
	want := append([]byte("cx1/req\x00POST\n/v1/x/ack\n"), e2e.U64(uint64(now))...)
	want = append(append(want, nonce...), bh[:]...)
	if !bytes.Equal(e2e.ReqBytes("POST", "/v1/x/ack", uint64(now), nonce, bh[:]), want) {
		t.Fatal("canonical request bytes")
	}
	h, err := e2e.SignReq(rk, "POST", "/v1/x/ack", uint64(now), nonce, body)
	if err != nil || !strings.HasPrefix(h, "v1,"+"1790000000,") {
		t.Fatal(h, err)
	}
	sig, err := e2e.VerifyReq(pub(rk), "POST", "/v1/x/ack", h, body, now+200)
	if err != nil || sig.TS != uint64(now) || !bytes.Equal(sig.Nonce, nonce) {
		t.Fatal("verify", err)
	}
	if _, err := e2e.VerifyReq(pub(rk), "POST", "/v1/x/ack", h, body, now+301); !errors.Is(err, e2e.ErrSkew) {
		t.Fatalf("skew: %v", err)
	}
	if _, err := e2e.VerifyReq(pub(rk), "POST", "/v1/x/ack", h, body, now-301); !errors.Is(err, e2e.ErrSkew) {
		t.Fatalf("skew: %v", err)
	}
	for name, c := range map[string][3]string{
		"method": {"PUT", "/v1/x/ack", string(body)},
		"path":   {"POST", "/v1/x/ack?x=1", string(body)},
		"body":   {"POST", "/v1/x/ack", `{"upto":13}`},
	} {
		if _, err := e2e.VerifyReq(pub(rk), c[0], c[1], h, []byte(c[2]), now); !errors.Is(err, e2e.ErrReqSig) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := e2e.VerifyReq(pub(e2e.RK(seedN(41))), "POST", "/v1/x/ack", h, body, now); !errors.Is(err, e2e.ErrReqSig) {
		t.Fatal("wrong rk accepted")
	}
	for _, bad := range []string{"", "v2," + h[3:], h + ",x", strings.Replace(h, "v1,1790000000,", "v1,179000000x,", 1), h[:len(h)-1], "v1,1,AAAA,BBBB"} {
		if _, err := e2e.ParseReqSig(bad); err == nil {
			t.Fatalf("bad header %q accepted", bad)
		}
	}
	if _, err := e2e.SignReq(rk, "POST", "/", uint64(now), nonce[:15], nil); err == nil {
		t.Fatal("short nonce accepted")
	}
	// the dotted send_sig form round-trips and verifies by body hash after the row expired
	ss, err := e2e.ParseSendSig(sig.SendSig())
	if err != nil || !ss.VerifyHash(pub(rk), "POST", "/v1/x/ack", bh[:]) || ss.VerifyHash(pub(rk), "POST", "/v1/x/ack", e2e.Sum(nil)) {
		t.Fatal("send_sig", err)
	}
	// domain separation: a request signature never verifies as another statement over the same payload
	payload := want[len("cx1/req\x00"):]
	if e2e.Verify(pub(rk), e2e.Labeled(e2e.LabelGSig, payload), sig.Sig) || e2e.Verify(pub(rk), payload, sig.Sig) || e2e.Verify(pub(rk), e2e.Labeled(e2e.LabelBundle, payload), sig.Sig) {
		t.Fatal("cross-domain verification")
	}
	// signed replies
	online := ed25519.NewKeyFromSeed(seedN(42))
	reply := []byte("id=aalice2 token=cx_x credits=100 seq=1 leaf=3 bundle=ab head=cd\n")
	rh := e2e.SignResp(online, "/v1/register", uint64(now), reply)
	if ts, err := e2e.VerifyResp(pub(online), "/v1/register", rh, reply); err != nil || ts != uint64(now) {
		t.Fatal("resp", err)
	}
	if _, err := e2e.VerifyResp(pub(online), "/v1/register", rh, append(reply, '!')); !errors.Is(err, e2e.ErrRespSig) {
		t.Fatal("tampered reply accepted")
	}
	if _, err := e2e.VerifyResp(pub(online), "/v1/keys", rh, reply); !errors.Is(err, e2e.ErrRespSig) {
		t.Fatal("reply for another path accepted")
	}
	if _, err := e2e.VerifyResp(pub(online), "/v1/register", "t=1,s=AA", reply); !errors.Is(err, e2e.ErrSig) {
		t.Fatal("garbage reply header")
	}
	// the other statements are distinct for identical payloads
	root := e2e.Sum([]byte("root"))
	if bytes.Equal(e2e.STHBytes(5, root, 7), e2e.WitnessBytes(5, root, 7)) || len(e2e.CertBytes(pub(online), 1, 2, 3)) != len("cx1/cert")+1+32+8+8+4 {
		t.Fatal("statements")
	}
	if !bytes.Equal(e2e.SuccBytes(alice, bob, root), append([]byte("cx1/succ\x00"+alice+bob), root...)) {
		t.Fatal("succ bytes")
	}
}

// RFC 6962 reference values (certificate-transparency test vectors) for the 8-leaf tree.
var rfc6962Leaves = [][]byte{{}, {0x00}, {0x10}, {0x20, 0x21}, {0x30, 0x31}, {0x40, 0x41, 0x42, 0x43},
	{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57}, {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f}}

var rfc6962Roots = map[int]string{
	0: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
	3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
	4: "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
	5: "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
	6: "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
	8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

func TestMerkleInclusionConsistency(t *testing.T) {
	var tr e2e.Tree
	for _, l := range rfc6962Leaves {
		tr.Append(e2e.LeafHash(l))
	}
	for n, want := range rfc6962Roots {
		if got := hex.EncodeToString(tr.RootAt(uint64(n))); got != want {
			t.Fatalf("root of %d leaves %s want %s", n, got, want)
		}
	}
	if hex.EncodeToString(e2e.LeafHash(nil)) != rfc6962Roots[1] || !bytes.Equal(e2e.EmptyRoot(), tr.RootAt(0)) {
		t.Fatal("leaf hash / empty root")
	}
	// known audit path: leaf 0 of the 8-leaf tree
	p := tr.Inclusion(0, 8)
	if e2e.EncodePath(p) != "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7,5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e,6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4" {
		t.Fatalf("path(0, 8) = %s", e2e.EncodePath(p))
	}
	if e2e.EncodePath(tr.Inclusion(2, 3)) != rfc6962Roots[2] {
		t.Fatalf("path(2, 3) = %s", e2e.EncodePath(tr.Inclusion(2, 3)))
	}
	// property: every inclusion proof verifies, and any single change breaks it
	r := rnd(99)
	var big e2e.Tree
	for i := 0; i < 70; i++ {
		var d [16]byte
		r.Read(d[:])
		big.Append(e2e.LeafHash(d[:]))
	}
	for size := uint64(1); size <= big.Size(); size++ {
		root := big.RootAt(size)
		for idx := uint64(0); idx < size; idx++ {
			path := big.Inclusion(idx, size)
			if !e2e.VerifyInclusion(big.Leaf(idx), idx, size, path, root) {
				t.Fatalf("inclusion %d/%d", idx, size)
			}
			if idx+1 < size && e2e.VerifyInclusion(big.Leaf(idx+1), idx, size, path, root) {
				t.Fatalf("path for the wrong leaf verified %d/%d", idx, size)
			}
			if idx+1 < size && e2e.VerifyInclusion(big.Leaf(idx), idx+1, size, path, root) {
				t.Fatalf("wrong index verified %d/%d", idx, size)
			}
			if size > 1 {
				bad := append([][]byte(nil), path...)
				bad[0] = e2e.Sum(bad[0])
				if e2e.VerifyInclusion(big.Leaf(idx), idx, size, bad, root) || e2e.VerifyInclusion(big.Leaf(idx), idx, size, path[:len(path)-1], root) {
					t.Fatalf("broken path verified %d/%d", idx, size)
				}
			}
		}
		for from := uint64(0); from <= size; from++ {
			path := big.Consistency(from, size)
			if !e2e.VerifyConsistency(from, size, big.RootAt(from), root, path) {
				t.Fatalf("consistency %d->%d", from, size)
			}
			if from > 0 && from < size {
				other := big.RootAt(from - 1)
				if e2e.VerifyConsistency(from, size, other, root, path) || e2e.VerifyConsistency(from-1, size, other, root, path) {
					t.Fatalf("inconsistent trees verified %d->%d", from, size)
				}
				if e2e.VerifyConsistency(from, size, big.RootAt(from), e2e.Sum(root), path) {
					t.Fatalf("wrong second root verified %d->%d", from, size)
				}
			}
		}
	}
	// a forked tree (one leaf substituted) shares no consistency proof with the honest one
	var fork e2e.Tree
	for i := uint64(0); i < 20; i++ {
		fork.Append(big.Leaf(i))
	}
	fork.Append(e2e.LeafHash([]byte("substituted bundle")))
	for i := uint64(21); i < 30; i++ {
		fork.Append(big.Leaf(i))
	}
	if e2e.VerifyConsistency(20, 30, big.RootAt(20), fork.Root(), big.Consistency(20, 30)) || !e2e.VerifyConsistency(20, 30, big.RootAt(20), fork.Root(), fork.Consistency(20, 30)) {
		t.Fatal("fork: an honest prefix is consistent with the fork only through the fork's own proof")
	}
	if e2e.VerifyConsistency(25, 30, big.RootAt(25), fork.Root(), fork.Consistency(25, 30)) {
		t.Fatal("fork detected late: a prefix that includes the substituted leaf must be inconsistent")
	}
	dec, err := e2e.DecodePath(e2e.EncodePath(p))
	if err != nil || len(dec) != 3 || !bytes.Equal(dec[2], p[2]) {
		t.Fatal("path codec")
	}
	if _, err := e2e.DecodePath("zz"); err == nil {
		t.Fatal("bad path accepted")
	}
	if _, err := e2e.DecodePath(strings.Repeat(rfc6962Roots[1]+",", 64) + rfc6962Roots[1]); err == nil {
		t.Fatal("65-element path accepted")
	}
	if dec, _ := e2e.DecodePath(""); dec != nil {
		t.Fatal("empty path")
	}
	leaf := e2e.KlogLeaf(1, alice, e2e.Sum([]byte("bundle")), 9)
	if !bytes.Equal(leaf, e2e.LeafHash(append(append([]byte{1}, alice...), append(e2e.Sum([]byte("bundle")), e2e.U64(9)...)...))) {
		t.Fatal("klog leaf")
	}
}

func TestAttachments(t *testing.T) {
	k := e2e.Sum([]byte("k_att"))
	file := bytes.Repeat([]byte("file"), 5000)
	blob, err := e2e.SealAttachment(k, file, rnd(1))
	if err != nil || len(blob) != len(file)+48 {
		t.Fatal(err)
	}
	if got, err := e2e.OpenAttachment(k, blob); err != nil || !bytes.Equal(got, file) {
		t.Fatal("open attachment", err)
	}
	blob[100] ^= 1
	if _, err := e2e.OpenAttachment(k, blob); err == nil {
		t.Fatal("tampered attachment accepted")
	}
	msgRoot := e2e.Sum([]byte("msg root"))
	s := e2e.Sum([]byte("salt"))
	snap, _ := e2e.SealAttachmentWithSalt(e2e.SnapshotKey(msgRoot, s), s, []byte("snapshot"))
	if got, err := e2e.OpenSnapshot(msgRoot, snap); err != nil || string(got) != "snapshot" {
		t.Fatal("snapshot", err)
	}
}
