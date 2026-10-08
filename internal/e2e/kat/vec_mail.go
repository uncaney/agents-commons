package kat

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"ekaii.fr/commons/internal/e2e"
)

// ---- bundle.json

type bundleParams struct {
	ID         string `json:"id"`
	Seq        uint32 `json:"seq"`
	IAT        uint32 `json:"iat"`
	Exp        uint32 `json:"exp"`
	Flags      uint8  `json:"flags"`
	MailPolicy uint8  `json:"mail_policy"`
	MinCS      uint8  `json:"min_cs"`
	MinPol     uint16 `json:"min_pol"`
	E0         uint32 `json:"e0"`
	NEK        int    `json:"n_ek"`
	RevCommit  string `json:"rev_commit"`
	PrevHash   string `json:"prev_hash"`
}

type bundleVec struct {
	What          string       `json:"what"`
	Seed          string       `json:"seed"`
	PrevSeed      string       `json:"prev_seed,omitempty"` // seed of the previous ik when rotating
	Params        bundleParams `json:"params"`
	Canonical     string       `json:"canonical"`
	SigIK         string       `json:"sig_ik"`
	SigPrev       string       `json:"sig_prev"`
	SigPQ         string       `json:"sig_pq,omitempty"`
	Raw           string       `json:"raw"`
	CanonicalHash string       `json:"canonical_hash"`
	BundleHash    string       `json:"bundle_hash"`
	FP            string       `json:"fp"`
	Size          int          `json:"size"`
}

type bundleNeg struct {
	What   string `json:"what"`
	Raw    string `json:"raw"`
	PrevIK string `json:"prev_ik,omitempty"`
}

type bundleDoc struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Vectors     []bundleVec `json:"vectors"`
	Negative    []bundleNeg `json:"negative"`
}

func toParams(p bundleParams, x *dec) e2e.BundleParams {
	return e2e.BundleParams{ID: p.ID, Seq: p.Seq, IAT: p.IAT, Exp: p.Exp, Flags: p.Flags, MailPolicy: p.MailPolicy, MinCS: p.MinCS, MinPol: p.MinPol,
		E0: p.E0, NEK: p.NEK, RevCommit: x.b(p.RevCommit), PrevHash: x.b(p.PrevHash)}
}

func signBundle(seed, prevSeed []byte, p e2e.BundleParams) (*e2e.Bundle, []byte, error) {
	b, err := e2e.NewBundle(seed, p)
	if err != nil {
		return nil, nil, err
	}
	var prev ed25519.PrivateKey
	if prevSeed != nil {
		prev = e2e.IK(prevSeed)
	}
	raw, err := b.Sign(e2e.IK(seed), prev, e2e.PQID(seed))
	return b, raw, err
}

func (g *gen) bundle() (*bundleDoc, error) {
	d := &bundleDoc{Name: "bundle", Description: "Key bundle canonical bytes and signatures (E2EE 3.1): seq 1 for cs=1 (514 bytes) and cs=2 with pq_id (13071 bytes), seq 2 with sig_prev (ik rotation). sig_ik = Ed25519(ik, \"cx1/bundle\" || 0x00 || canonical), sig_prev = Ed25519(ik_prev, \"cx1/rotate\" || 0x00 || canonical), sig_pq = ML-DSA-65 (deterministic) over the same bundle statement."}
	seedA, seedB := g.seed(), g.seed()
	rev := e2e.Sum(g.d.bytes(32))
	iat, exp := uint32(now-3600), uint32(now+30*86400)
	cases := []struct {
		what     string
		seed     []byte
		prevSeed []byte
		p        bundleParams
	}{
		{"seq 1, cs=1, five epochs", seedA, nil, bundleParams{ID: alice, Seq: 1, IAT: iat, Exp: exp, Flags: 0, MailPolicy: e2e.PolicyBoth, MinCS: 1, E0: 2959, NEK: 5, RevCommit: hx(rev), PrevHash: hx(make([]byte, 32))}},
		{"seq 1, cs=2, lk_ok, pq_id, policy e2ee, min_cs 2", seedA, nil, bundleParams{ID: alice, Seq: 1, IAT: iat, Exp: exp, Flags: e2e.FlagCS2 | e2e.FlagLKOK | e2e.FlagPQ, MailPolicy: e2e.PolicyE2EE, MinCS: 2, MinPol: 4, E0: 2959, NEK: 5, RevCommit: hx(rev), PrevHash: hx(make([]byte, 32))}},
	}
	for _, c := range cases {
		x := &dec{}
		b, raw, err := signBundle(c.seed, c.prevSeed, toParams(c.p, x))
		if err != nil {
			return nil, err
		}
		d.Vectors = append(d.Vectors, bundleVecOf(c.what, c.seed, c.prevSeed, c.p, b, raw))
	}
	// seq 2 under a new ik, signed by the previous one
	ch := mustHex(d.Vectors[0].CanonicalHash)
	rot := bundleParams{ID: alice, Seq: 2, IAT: iat + 60, Exp: exp, Flags: e2e.FlagCS2, MailPolicy: e2e.PolicyBoth, MinCS: 1, E0: 2960, NEK: 5, RevCommit: hx(rev), PrevHash: hx(ch)}
	x := &dec{}
	b, raw, err := signBundle(seedB, seedA, toParams(rot, x))
	if err != nil {
		return nil, err
	}
	d.Vectors = append(d.Vectors, bundleVecOf("seq 2, ik rotated (sig_prev by the seq-1 ik), prev_hash = sha256(seq-1 canonical)", seedB, seedA, rot, b, raw))

	v0 := mustHex(d.Vectors[0].Raw)
	flipSig := append([]byte(nil), v0...)
	flipSig[len(v0)-100] ^= 1 // inside sig_ik
	flipIK := append([]byte(nil), v0...)
	flipIK[30] ^= 1 // inside ik
	withPrev := append([]byte(nil), v0...)
	copy(withPrev[len(v0)-64:], withPrev[len(v0)-128:len(v0)-64])
	cs2flag := append([]byte(nil), v0...)
	cs2flag[23] |= e2e.FlagCS2
	nonCanon := append([]byte(nil), v0...)
	s := nonCanon[len(v0)-96 : len(v0)-64] // s of sig_ik, little-endian
	L, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	si := new(big.Int).SetBytes(reverse(s))
	si.Add(si, L)
	copy(s, reverse(si.FillBytes(make([]byte, 32))))
	rotRaw := mustHex(d.Vectors[2].Raw)
	d.Negative = []bundleNeg{
		{What: "sig_ik flipped", Raw: hx(flipSig)},
		{What: "ik byte flipped (signature no longer verifies under the bundle's own ik)", Raw: hx(flipIK)},
		{What: "truncated", Raw: hx(v0[:len(v0)-1])},
		{What: "one trailing byte", Raw: hx(append(append([]byte(nil), v0...), 0))},
		{What: "flags.cs2 set without lk2/ek2 (length mismatch)", Raw: hx(cs2flag)},
		{What: "non-canonical Ed25519 s (s + L)", Raw: hx(nonCanon)},
		{What: "seq 1 with a non-zero sig_prev", Raw: hx(withPrev)},
		{What: "rotation checked against the wrong previous ik", Raw: hx(rotRaw), PrevIK: hx(pub(e2e.IK(seedB)))},
		{What: "empty", Raw: ""},
	}
	return d, nil
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

func bundleVecOf(what string, seed, prevSeed []byte, p bundleParams, b *e2e.Bundle, raw []byte) bundleVec {
	can, _ := b.Canonical()
	ch, _ := b.CanonicalHash()
	v := bundleVec{What: what, Seed: hx(seed), Params: p, Canonical: hx(can), SigIK: hx(b.SigIK), SigPrev: hx(b.SigPrev), SigPQ: hx(b.SigPQ),
		Raw: hx(raw), CanonicalHash: hx(ch), BundleHash: hx(e2e.BundleHash(raw)), FP: hx(b.Fingerprint()), Size: len(raw)}
	if prevSeed != nil {
		v.PrevSeed = hx(prevSeed)
	}
	return v
}

func checkBundle(data []byte) error {
	var d bundleDoc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	x := &dec{}
	for _, v := range d.Vectors {
		var prevSeed []byte
		if v.PrevSeed != "" {
			prevSeed = x.b(v.PrevSeed)
		}
		b, raw, err := signBundle(x.b(v.Seed), prevSeed, toParams(v.Params, x))
		if err != nil {
			return err
		}
		if err := want("raw", raw, x.b(v.Raw)); err != nil {
			return err
		}
		can, _ := b.Canonical()
		ch, _ := b.CanonicalHash()
		for _, c := range []struct {
			what string
			got  []byte
			exp  string
		}{{"canonical", can, v.Canonical}, {"sig_ik", b.SigIK, v.SigIK}, {"sig_prev", b.SigPrev, v.SigPrev}, {"sig_pq", b.SigPQ, v.SigPQ},
			{"canonical_hash", ch, v.CanonicalHash}, {"bundle_hash", e2e.BundleHash(raw), v.BundleHash}, {"fp", b.Fingerprint(), v.FP}} {
			if err := want(c.what, c.got, x.b(c.exp)); err != nil {
				return err
			}
		}
		pb, err := e2e.ParseBundle(raw)
		if err != nil {
			return err
		}
		if err := pb.Verify(); err != nil {
			return err
		}
		if len(raw) != v.Size {
			return errors.New("size")
		}
		if prevSeed != nil {
			if err := pb.VerifyRotation(pub(e2e.IK(prevSeed))); err != nil || !pb.Rotated() {
				return errors.New("rotation")
			}
		} else if pb.Rotated() {
			return errors.New("unexpected rotation")
		}
	}
	for _, n := range d.Negative {
		pb, err := e2e.ParseBundle(x.b(n.Raw))
		if err != nil {
			continue
		}
		if err := pb.Verify(); err != nil {
			continue
		}
		if n.PrevIK != "" && pb.VerifyRotation(x.b(n.PrevIK)) != nil {
			continue
		}
		return fmt.Errorf("negative %q accepted", n.What)
	}
	return x.err
}

// ---- cxm1.json

type cxm1Vec struct {
	What          string `json:"what"`
	CS            uint8  `json:"cs"`
	SenderSeed    string `json:"sender_seed"`
	RecipientSeed string `json:"recipient_seed"`
	From          string `json:"from"`
	To            string `json:"to"`
	Flags         uint8  `json:"flags"`
	Epoch         uint32 `json:"epoch"`
	Pol           uint16 `json:"pol"`
	Mid           string `json:"mid"`
	KF            string `json:"kf"`
	TS            uint32 `json:"ts"`
	Type          uint8  `json:"type"`
	Payload       string `json:"payload"`
	Inner         string `json:"inner"`
	Padded        string `json:"padded"`
	C             string `json:"c"`
	Hdr           string `json:"hdr"`
	Info          string `json:"info"`      // HPKE info
	AuthInfo      string `json:"auth_info"` // HKDF info of k_auth
	RecipientKey  string `json:"recipient_key"`
	SenderAK      string `json:"sender_ak"`
	RecipientAK   string `json:"recipient_ak"`
	SS            string `json:"ss"`
	Enc           string `json:"enc"`      // recorded (HPKE draws an ephemeral key)
	CT            string `json:"ct"`       // recorded
	MAC           string `json:"mac"`      // recorded
	Exporter      string `json:"exporter"` // recorded: Export("cx1/auth", 32)
	KAuth         string `json:"k_auth"`   // recorded
	Envelope      string `json:"envelope"` // recorded
	Size          int    `json:"size"`
}

type rcptVec struct {
	OnlineSeed string `json:"online_seed"`
	OnlinePK   string `json:"online_pk"`
	Seq        uint64 `json:"seq"`
	At         uint64 `json:"at"`
	Hdr        string `json:"hdr"`
	Statement  string `json:"statement"`
	Rcpt       string `json:"rcpt"`
}

type cxm1Neg struct {
	What     string `json:"what"`
	Vector   int    `json:"vector"` // keys of this vector are used to open
	Envelope string `json:"envelope"`
}

type cxm1Doc struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Vectors     []cxm1Vec `json:"vectors"`
	Rcpt        rcptVec   `json:"rcpt"`
	Negative    []cxm1Neg `json:"negative"`
}

// recipientSK derives the key an envelope was sealed to.
func recipientSK(seed []byte, cs e2e.Suite, flags uint8, epoch uint32) (hpke.PrivateKey, error) {
	if flags&e2e.FlagLT != 0 {
		return e2e.LK(seed, cs)
	}
	return e2e.EK(seed, cs, epoch, nil)
}

func (g *gen) cxm1() (*cxm1Doc, error) {
	d := &cxm1Doc{Name: "cxm1", Description: "Pairwise envelope (E2EE 4): hdr(71) | enc | ct | mac. info = \"cx1/mail\" || 0x00 || from || to || u32(epoch); ct = HPKE Base Seal(aad = hdr, padded inner); exporter = Export(\"cx1/auth\", 32); k_auth = HKDF(X25519(ak_s, ak_r), salt = exporter, \"cx1/auth\" || 0x00 || from || to, 32); mac = HMAC(k_auth, \"cx1/auth-mac\" || 0x00 || hdr || enc || ct); C = HMAC(kf, \"cx1/frank\" || 0x00 || from || to || mid || type || u16(len) || payload). enc/ct/mac/exporter/k_auth are recorded (HPKE encapsulation is randomized); a reimplementation checks them by opening the envelope."}
	var prior cxm1Doc
	hasPrior := g.priorDoc("cxm1.json", &prior)
	sa, sb := g.seed(), g.seed()
	epoch := e2e.Epoch(now)
	cases := []struct {
		what    string
		cs      e2e.Suite
		flags   uint8
		typ     uint8
		payload []byte
	}{
		{"cs=1, text, 1k bucket", e2e.CS1, 0, e2e.TypeText, []byte("hello bob, this is alice")},
		{"cs=1, json, 2k bucket", e2e.CS1, 0, e2e.TypeJSON, []byte(`{"n":"` + hx(g.d.bytes(700)) + `"}`)},
		{"cs=2, text, 1k bucket", e2e.CS2, e2e.FlagTOFU, e2e.TypeText, []byte("post-quantum hello")},
		{"cs=2, max payload, 4k bucket", e2e.CS2, 0, e2e.TypeJSON, g.d.bytes(e2e.MaxPayload)},
		{"cs=1, last resort to lk (LT, epoch 0)", e2e.CS1, e2e.FlagLT, e2e.TypeText, []byte("dormant agent, lk_ok")},
		{"cs=1, control reset", e2e.CS1, e2e.FlagCTRL | e2e.FlagRESET, e2e.TypeCtrl, []byte(`{"t":"reset"}`)},
	}
	for i, c := range cases {
		mid, kf := g.d.bytes(16), g.d.bytes(32)
		ep := epoch
		if c.flags&e2e.FlagLT != 0 {
			ep = 0
		}
		v := cxm1Vec{What: c.what, CS: uint8(c.cs), SenderSeed: hx(sa), RecipientSeed: hx(sb), From: alice, To: bob, Flags: c.flags, Epoch: ep, Pol: 3,
			Mid: hx(mid), KF: hx(kf), TS: uint32(now), Type: c.typ, Payload: hx(c.payload)}
		if err := fillCxm1Det(&v); err != nil {
			return nil, err
		}
		if hasPrior && i < len(prior.Vectors) && prior.Vectors[i].Hdr == v.Hdr && prior.Vectors[i].RecipientKey == v.RecipientKey && prior.Vectors[i].SenderSeed == v.SenderSeed && reopenCxm1(prior.Vectors[i]) == nil {
			p := prior.Vectors[i]
			v.Enc, v.CT, v.MAC, v.Exporter, v.KAuth, v.Envelope, v.Size = p.Enc, p.CT, p.MAC, p.Exporter, p.KAuth, p.Envelope, p.Size
		} else {
			s, err := e2e.Seal(e2e.SealParams{CS: c.cs, Flags: c.flags, From: alice, To: bob, Epoch: ep, Pol: 3, Mid: mid, KF: kf, TS: uint32(now), Type: c.typ, Payload: c.payload,
				RecipientKey: mustHex(v.RecipientKey), SenderAK: e2e.AK(sa), RecipientAK: e2e.AK(sb).PublicKey().Bytes()})
			if err != nil {
				return nil, err
			}
			v.Enc, v.CT, v.MAC, v.Exporter, v.KAuth, v.Envelope, v.Size = hx(s.Enc), hx(s.CT), hx(s.MAC), hx(s.Exporter), hx(s.KAuth), hx(s.Envelope), len(s.Envelope)
		}
		d.Vectors = append(d.Vectors, v)
	}
	os := g.seed()
	online := ed25519.NewKeyFromSeed(os)
	hdr := mustHex(d.Vectors[0].Hdr)
	d.Rcpt = rcptVec{OnlineSeed: hx(os), OnlinePK: hx(pub(online)), Seq: 1099511627776 + 42, At: uint64(now + 2), Hdr: hx(hdr),
		Statement: hx(e2e.RcptBytes(hdr, 1099511627776+42, uint64(now+2))), Rcpt: hx(e2e.SignRcpt(online, hdr, 1099511627776+42, uint64(now+2)))}

	env := mustHex(d.Vectors[0].Envelope)
	flip := func(i int) string {
		b := append([]byte(nil), env...)
		b[i] ^= 1
		return hx(b)
	}
	moved := append([]byte(nil), env...)
	copy(moved[10:17], carol)
	epochUp := append([]byte(nil), env...)
	epochUp[20] ^= 1
	csByte := append([]byte(nil), env...)
	csByte[1] = 2
	d.Negative = []cxm1Neg{
		{What: "flipped C (header byte 39)", Vector: 0, Envelope: flip(39)},
		{What: "flipped mid", Vector: 0, Envelope: flip(23)},
		{What: "flipped enc", Vector: 0, Envelope: flip(71)},
		{What: "flipped ct", Vector: 0, Envelope: flip(120)},
		{What: "flipped mac", Vector: 0, Envelope: flip(len(env) - 1)},
		{What: "truncated by one byte", Vector: 0, Envelope: hx(env[:len(env)-1])},
		{What: "cs=2 header on a 32-byte enc (size bucket)", Vector: 0, Envelope: hx(csByte)},
		{What: "moved to another inbox (to = carol)", Vector: 0, Envelope: hx(moved)},
		{What: "epoch changed (info and AAD disagree)", Vector: 0, Envelope: hx(epochUp)},
		{What: "envelope of vector 1 opened with vector 0's epoch key", Vector: 4, Envelope: d.Vectors[1].Envelope},
	}
	// a franking mismatch: valid MAC and AEAD, C committing to another payload (a patched client)
	if hasPrior && len(prior.Negative) > len(d.Negative) && strings.HasPrefix(prior.Negative[len(d.Negative)].What, "franking") && openFails(d.Vectors[0], prior.Negative[len(d.Negative)].Envelope, e2e.ErrFrank) {
		d.Negative = append(d.Negative, prior.Negative[len(d.Negative)])
	} else {
		bad, err := frankMismatch(d.Vectors[0])
		if err != nil {
			return nil, err
		}
		d.Negative = append(d.Negative, cxm1Neg{What: "franking mismatch: C commits to another payload (dropped before the agent sees it)", Vector: 0, Envelope: hx(bad)})
	}
	return d, nil
}

// fillCxm1Det computes the deterministic fields of a vector from its inputs.
func fillCxm1Det(v *cxm1Vec) error {
	x := &dec{}
	sa, sb, mid, kf, payload := x.b(v.SenderSeed), x.b(v.RecipientSeed), x.b(v.Mid), x.b(v.KF), x.b(v.Payload)
	if x.err != nil {
		return x.err
	}
	inner, err := (&e2e.Inner{KF: kf, TS: v.TS, Type: v.Type, Payload: payload}).Marshal()
	if err != nil {
		return err
	}
	padded, err := e2e.Pad(inner, e2e.MailBuckets)
	if err != nil {
		return err
	}
	c := e2e.Frank(kf, v.From, v.To, mid, v.Type, payload)
	h := e2e.Hdr{CS: e2e.Suite(v.CS), Flags: v.Flags, From: v.From, To: v.To, Epoch: v.Epoch, Pol: v.Pol, Mid: mid, C: c}
	sk, err := recipientSK(sb, e2e.Suite(v.CS), v.Flags, v.Epoch)
	if err != nil {
		return err
	}
	rak, _ := ecdh.X25519().NewPublicKey(e2e.AK(sb).PublicKey().Bytes())
	ss, err := e2e.AK(sa).ECDH(rak)
	if err != nil {
		return err
	}
	v.Inner, v.Padded, v.C, v.Hdr = hx(inner), hx(padded), hx(c), hx(h.Marshal())
	v.Info, v.AuthInfo = hx(e2e.MailInfo(v.From, v.To, v.Epoch)), hx(e2e.Labeled(e2e.LabelAuth, []byte(v.From), []byte(v.To)))
	v.RecipientKey, v.SenderAK, v.RecipientAK, v.SS = hx(sk.PublicKey().Bytes()), hx(e2e.AK(sa).PublicKey().Bytes()), hx(e2e.AK(sb).PublicKey().Bytes()), hx(ss)
	return nil
}

// reopenCxm1 verifies the recorded fields of a vector by opening its envelope.
func reopenCxm1(v cxm1Vec) error {
	x := &dec{}
	sa, sb := x.b(v.SenderSeed), x.b(v.RecipientSeed)
	env, hdr, enc, ct, mac := x.b(v.Envelope), x.b(v.Hdr), x.b(v.Enc), x.b(v.CT), x.b(v.MAC)
	if x.err != nil {
		return x.err
	}
	if !bytes.Equal(env, append(append(append(append([]byte(nil), hdr...), enc...), ct...), mac...)) || len(env) != v.Size || len(env) != e2e.EnvelopeSize(e2e.Suite(v.CS), len(x.b(v.Padded))) {
		return errors.New("envelope assembly")
	}
	e, err := e2e.ParseEnvelope(env)
	if err != nil {
		return err
	}
	sk, err := recipientSK(sb, e2e.Suite(v.CS), v.Flags, v.Epoch)
	if err != nil {
		return err
	}
	in, err := e.Open(e2e.OpenParams{Me: v.To, RecipientKey: sk, RecipientAK: e2e.AK(sb), SenderAK: e2e.AK(sa).PublicKey().Bytes()})
	if err != nil {
		return err
	}
	if !bytes.Equal(in.KF, x.b(v.KF)) || in.TS != v.TS || in.Type != v.Type || !bytes.Equal(in.Payload, x.b(v.Payload)) {
		return errors.New("opened inner differs")
	}
	r, err := hpke.NewRecipient(enc, sk, e2e.KDF(), e2e.AEAD(), x.b(v.Info))
	if err != nil {
		return err
	}
	exporter, err := r.Export(e2e.LabelAuth, 32)
	if err != nil {
		return err
	}
	if err := want("exporter", exporter, x.b(v.Exporter)); err != nil {
		return err
	}
	kAuth := e2e.AuthKey(x.b(v.SS), exporter, v.From, v.To)
	if err := want("k_auth", kAuth, x.b(v.KAuth)); err != nil {
		return err
	}
	if err := want("mac", e2e.SenderMAC(kAuth, hdr, enc, ct), mac); err != nil {
		return err
	}
	if !e2e.VerifyFrank(&e.Hdr, in.KF, in.Type, in.Payload) {
		return errors.New("frank")
	}
	return x.err
}

func openFails(v cxm1Vec, envHex string, target error) bool {
	x := &dec{}
	sa, sb, env := x.b(v.SenderSeed), x.b(v.RecipientSeed), x.b(envHex)
	if x.err != nil {
		return false
	}
	e, err := e2e.ParseEnvelope(env)
	if err != nil {
		return target == nil
	}
	sk, err := recipientSK(sb, e2e.Suite(v.CS), v.Flags, v.Epoch)
	if err != nil {
		return false
	}
	_, err = e.Open(e2e.OpenParams{Me: v.To, RecipientKey: sk, RecipientAK: e2e.AK(sb), SenderAK: e2e.AK(sa).PublicKey().Bytes()})
	if target == nil {
		return err != nil
	}
	return errors.Is(err, target)
}

// frankMismatch builds an envelope whose MAC and AEAD verify but whose C commits to another payload.
func frankMismatch(v cxm1Vec) ([]byte, error) {
	x := &dec{}
	sa, sb, mid, kf, padded := x.b(v.SenderSeed), x.b(v.RecipientSeed), x.b(v.Mid), x.b(v.KF), x.b(v.Padded)
	if x.err != nil {
		return nil, x.err
	}
	h := e2e.Hdr{CS: e2e.Suite(v.CS), Flags: v.Flags, From: v.From, To: v.To, Epoch: v.Epoch, Pol: v.Pol, Mid: mid,
		C: e2e.Frank(kf, v.From, v.To, mid, v.Type, []byte("something innocent"))}
	hdr := h.Marshal()
	pk, err := e2e.Suite(v.CS).NewPublicKey(x.b(v.RecipientKey))
	if err != nil {
		return nil, err
	}
	enc, s, err := hpke.NewSender(pk, e2e.KDF(), e2e.AEAD(), e2e.MailInfo(v.From, v.To, v.Epoch))
	if err != nil {
		return nil, err
	}
	ct, err := s.Seal(hdr, padded)
	if err != nil {
		return nil, err
	}
	exp, err := s.Export(e2e.LabelAuth, 32)
	if err != nil {
		return nil, err
	}
	rak, _ := ecdh.X25519().NewPublicKey(e2e.AK(sb).PublicKey().Bytes())
	ss, _ := e2e.AK(sa).ECDH(rak)
	mac := e2e.SenderMAC(e2e.AuthKey(ss, exp, v.From, v.To), hdr, enc, ct)
	return append(append(append(hdr, enc...), ct...), mac...), nil
}

func checkCxm1(data []byte) error {
	var d cxm1Doc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	for i, v := range d.Vectors {
		det := v
		if err := fillCxm1Det(&det); err != nil {
			return fmt.Errorf("vector %d: %w", i, err)
		}
		for _, c := range []struct{ what, got, exp string }{{"inner", det.Inner, v.Inner}, {"padded", det.Padded, v.Padded}, {"C", det.C, v.C}, {"hdr", det.Hdr, v.Hdr},
			{"info", det.Info, v.Info}, {"auth_info", det.AuthInfo, v.AuthInfo}, {"recipient_key", det.RecipientKey, v.RecipientKey}, {"sender_ak", det.SenderAK, v.SenderAK},
			{"recipient_ak", det.RecipientAK, v.RecipientAK}, {"ss", det.SS, v.SS}} {
			if err := wantS(fmt.Sprintf("vector %d %s", i, c.what), c.got, c.exp); err != nil {
				return err
			}
		}
		if err := reopenCxm1(v); err != nil {
			return fmt.Errorf("vector %d: %w", i, err)
		}
	}
	x := &dec{}
	r := d.Rcpt
	online := ed25519.NewKeyFromSeed(x.b(r.OnlineSeed))
	if err := want("rcpt statement", e2e.RcptBytes(x.b(r.Hdr), r.Seq, r.At), x.b(r.Statement)); err != nil {
		return err
	}
	if err := want("rcpt", e2e.SignRcpt(online, x.b(r.Hdr), r.Seq, r.At), x.b(r.Rcpt)); err != nil {
		return err
	}
	if !e2e.VerifyRcpt(x.b(r.OnlinePK), x.b(r.Hdr), r.Seq, r.At, x.b(r.Rcpt)) || e2e.VerifyRcpt(x.b(r.OnlinePK), x.b(r.Hdr), r.Seq, r.At+1, x.b(r.Rcpt)) {
		return errors.New("rcpt verify")
	}
	for _, n := range d.Negative {
		if n.Vector >= len(d.Vectors) || !openFails(d.Vectors[n.Vector], n.Envelope, nil) {
			return fmt.Errorf("negative %q accepted", n.What)
		}
	}
	return x.err
}

// ---- dvr.json

type headVec struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
	At   uint64 `json:"at"`
	Sig  string `json:"sig"`
	W1   string `json:"w1,omitempty"`
}

type dvrCase struct {
	What        string   `json:"what"`
	Now         int64    `json:"now"`
	ID          string   `json:"id"`
	Bundle      string   `json:"bundle"` // key into dvrDoc.Bundles
	Leaf        uint64   `json:"leaf"`
	Pending     bool     `json:"pending,omitempty"`
	MinWitness  int      `json:"min_witness,omitempty"`
	Witnessed   *headVec `json:"witnessed,omitempty"`
	ServerSTH   *headVec `json:"server_sth,omitempty"`
	Inclusion   []string `json:"inclusion"`
	Consistency []string `json:"consistency,omitempty"`
	IndexSeq    uint32   `json:"index_seq,omitempty"`
	Pin         *e2e.Pin `json:"pin,omitempty"`
	PrevIK      string   `json:"prev_ik,omitempty"`
	ClientMaxCS uint8    `json:"client_max_cs,omitempty"`
	TOFU        bool     `json:"tofu,omitempty"`
	Expect      string   `json:"expect"` // "ok" or "err dvr <step>"
	CS          uint8    `json:"cs,omitempty"`
	Epoch       uint32   `json:"epoch,omitempty"`
	Key         string   `json:"key,omitempty"`
	LT          bool     `json:"lt,omitempty"`
	Provisional bool     `json:"provisional,omitempty"`
}

type dvrDoc struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	OnlineSeed  string            `json:"online_seed"`
	OnlinePK    string            `json:"online_pk"`
	W1Seed      string            `json:"w1_seed"`
	W1PK        string            `json:"w1_pk"`
	LogLeaves   []string          `json:"log_leaves"` // leaf hashes of the honest log
	Bundles     map[string]string `json:"bundles"`    // name -> canonical || sigs (hex)
	Cases       []dvrCase         `json:"cases"`
}

func headOf(tr *e2e.Tree, size uint64, at int64, online, w1 ed25519.PrivateKey) *headVec {
	root := tr.RootAt(size)
	h := &headVec{Size: size, Root: hx(root), At: uint64(at), Sig: hx(e2e.Sign(online, e2e.STHBytes(size, root, uint64(at))))}
	if w1 != nil {
		h.W1 = hx(e2e.Sign(w1, e2e.WitnessBytes(size, root, uint64(at))))
	}
	return h
}

func toHead(h *headVec, x *dec) *e2e.Head {
	if h == nil {
		return nil
	}
	out := &e2e.Head{Size: h.Size, Root: x.b(h.Root), At: h.At, Sig: x.b(h.Sig)}
	if h.W1 != "" {
		out.Witness = map[string][]byte{"w1": x.b(h.W1)}
	}
	return out
}

func (g *gen) dvr() (*dvrDoc, error) {
	d := &dvrDoc{Name: "dvr", Description: "Directory verification rule (E2EE 3.4) as a pure function: each case is a full input (bundle bytes, claimed leaf, witnessed head with STH and w1 signatures, server STH, audit and consistency paths, pin, clock) and the expected outcome: ok with the key to seal to, or err dvr <step>. Heads: sig = Ed25519(online, \"cx1/sth\" || 0x00 || u64(size) || root || u64(at)), w1 = Ed25519(w1, \"cx1/witness\" || ...)."}
	os, ws := g.seed(), g.seed()
	online, w1 := ed25519.NewKeyFromSeed(os), ed25519.NewKeyFromSeed(ws)
	d.OnlineSeed, d.OnlinePK, d.W1Seed, d.W1PK = hx(os), hx(pub(online)), hx(ws), hx(pub(w1))
	sb := g.seed()
	epoch := e2e.Epoch(now)
	x := &dec{}
	bb, raw, err := signBundle(sb, nil, e2e.BundleParams{ID: bob, Seq: 1, IAT: uint32(now - 3600), Exp: uint32(now + 30*86400), Flags: e2e.FlagCS2 | e2e.FlagLKOK, MailPolicy: e2e.PolicyBoth, MinCS: 1, E0: epoch - 1, NEK: 5, RevCommit: g.d.bytes(32)})
	if err != nil {
		return nil, err
	}
	ch, _ := bb.CanonicalHash()
	var tr e2e.Tree
	for i := 0; i < 5; i++ {
		tr.Append(e2e.LeafHash(g.d.bytes(8)))
	}
	tr.Append(e2e.KlogLeaf(1, bob, ch, 5))
	for i := 0; i < 3; i++ {
		tr.Append(e2e.LeafHash(g.d.bytes(8)))
	}
	for i := uint64(0); i < tr.Size(); i++ {
		d.LogLeaves = append(d.LogLeaves, hx(tr.Leaf(i)))
	}
	hw := headOf(&tr, 9, now-3600, online, w1)
	hw4 := headOf(&tr, 4, now-7200, online, w1)
	ek2, _ := bb.EK(e2e.CS2, epoch)
	ek1, _ := bb.EK(e2e.CS1, epoch)
	d.Bundles = map[string]string{"bob": hx(raw)}
	base := dvrCase{Now: now, ID: bob, Bundle: "bob", Leaf: 5, Witnessed: hw, Inclusion: hxs(tr.Inclusion(5, 9))}
	ok := func(what string, c dvrCase, cs e2e.Suite, key []byte, ep uint32, lt, prov bool) dvrCase {
		c.What, c.Expect, c.CS, c.Key, c.Epoch, c.LT, c.Provisional = what, "ok", uint8(cs), hx(key), ep, lt, prov
		return c
	}
	fail := func(what string, c dvrCase, step int) dvrCase {
		c.What, c.Expect = what, fmt.Sprintf("err dvr %d", step)
		return c
	}
	d.Cases = append(d.Cases, ok("leaf under the witnessed head, cs=2 client", base, e2e.CS2, ek2, epoch, false, false))
	c := base
	c.ClientMaxCS = 1
	d.Cases = append(d.Cases, ok("cs=1-only client picks ek1", c, e2e.CS1, ek1, epoch, false, false))
	c = base
	c.Witnessed, c.ServerSTH, c.Consistency = hw4, headOf(&tr, 9, now-600, online, nil), hxs(tr.Consistency(4, 9))
	d.Cases = append(d.Cases, ok("leaf newer than the witnessed head: fresh STH consistent with it -> provisional", c, e2e.CS2, ek2, epoch, false, true))
	c.ServerSTH = headOf(&tr, 9, now-86401, online, nil)
	d.Cases = append(d.Cases, fail("server STH older than 24 h", c, 2))
	c.ServerSTH = nil
	d.Cases = append(d.Cases, fail("leaf newer than the witnessed head and no STH", c, 2))
	// the host forks the log for the victim: leaf 5 substituted, attacker bundle appended at 9
	attacker := g.seed()
	ab, rawAtt, err := signBundle(attacker, nil, e2e.BundleParams{ID: bob, Seq: 2, IAT: uint32(now - 60), Exp: uint32(now + 86400), Flags: e2e.FlagCS2, MailPolicy: e2e.PolicyBoth, MinCS: 1, E0: epoch, NEK: 5, RevCommit: make([]byte, 32), PrevHash: ch})
	if err != nil {
		return nil, err
	}
	chA, _ := ab.CanonicalHash()
	var fork e2e.Tree
	for i := uint64(0); i < 9; i++ {
		if i == 5 {
			fork.Append(e2e.KlogLeaf(1, bob, chA, 5))
		} else {
			fork.Append(tr.Leaf(i))
		}
	}
	fork.Append(e2e.KlogLeaf(1, bob, chA, 9))
	fork.Append(e2e.LeafHash([]byte("filler")))
	c = base
	d.Bundles["attacker"] = hx(rawAtt)
	c.Bundle, c.Leaf, c.ServerSTH, c.Inclusion, c.Consistency = "attacker", 9, headOf(&fork, 11, now-60, online, nil), hxs(fork.Inclusion(9, 11)), hxs(fork.Consistency(9, 11))
	d.Cases = append(d.Cases, fail("fork: the server's STH is not consistent with the witnessed head", c, 2))
	c = base
	c.Bundle = "attacker"
	d.Cases = append(d.Cases, fail("unpublished substitute: not included under the witnessed head", c, 2))
	c = base
	c.Witnessed, c.ServerSTH, c.Consistency = hw4, &headVec{Size: 4, Root: hx(e2e.Sum([]byte("other"))), At: uint64(now - 60)}, hxs(fork.Consistency(4, 11))
	c.ServerSTH.Sig = hx(e2e.Sign(online, e2e.STHBytes(4, e2e.Sum([]byte("other")), uint64(now-60))))
	d.Cases = append(d.Cases, fail("split-view: same size as the witnessed head, different root", c, 2))
	c = base
	c.Witnessed = nil
	d.Cases = append(d.Cases, fail("mirror unreachable, no CX_TRUST=tofu", c, 2))
	c = base
	c.Witnessed = &headVec{Size: hw.Size, Root: hw.Root, At: hw.At, Sig: hw.Sig}
	d.Cases = append(d.Cases, fail("witnessed head without a witness signature", c, 2))
	c = base
	c.Witnessed, c.TOFU, c.ServerSTH = nil, true, headOf(&tr, 9, now-600, online, nil)
	d.Cases = append(d.Cases, ok("tier D (CX_TRUST=tofu): the server's fresh STH only", c, e2e.CS2, ek2, epoch, false, false))
	c = base
	c.Pending = true
	d.Cases = append(d.Cases, fail("pending bundle (legacy contested publish) never seals", c, 2))
	c = base
	c.IndexSeq = 2
	d.Cases = append(d.Cases, fail("daily index lists a higher seq: refetch", c, 2))
	fp := hx(bb.Fingerprint())
	c = base
	c.Pin = &e2e.Pin{FP: fp, Seq: 2, CS: 2, Leaf: 5, Pol: 1}
	d.Cases = append(d.Cases, fail("pin regression on seq", c, 3))
	c = base
	c.Pin = &e2e.Pin{FP: fp, Seq: 1, CS: 2, Leaf: 5, Pol: e2e.PolicyE2EE}
	d.Cases = append(d.Cases, fail("pin regression on mail_policy (e2ee -> both)", c, 3))
	c = base
	c.Pin = &e2e.Pin{FP: hx(e2e.Sum([]byte("someone else"))), Seq: 1, CS: 2, Leaf: 5, Pol: 1}
	d.Cases = append(d.Cases, fail("ik differs from the pinned ik", c, 3))
	c = base
	c.Pin = &e2e.Pin{FP: fp, Seq: 1, CS: 2, Leaf: 5, Pol: 1}
	d.Cases = append(d.Cases, ok("pinned peer, same ik", c, e2e.CS2, ek2, epoch, false, false))
	// stale bundle: epochs e-10..e-6, no lk_ok
	_, rawStale, err := signBundle(sb, nil, e2e.BundleParams{ID: bob, Seq: 1, IAT: uint32(now - 3600), Exp: uint32(now + 30*86400), Flags: e2e.FlagCS2, MailPolicy: e2e.PolicyBoth, MinCS: 1, E0: epoch - 10, NEK: 5, RevCommit: g.d.bytes(32)})
	if err != nil {
		return nil, err
	}
	sbun, _ := e2e.ParseBundle(rawStale)
	chS, _ := sbun.CanonicalHash()
	var st e2e.Tree
	st.Append(e2e.KlogLeaf(1, bob, chS, 0))
	c = base
	d.Bundles["stale"] = hx(rawStale)
	c.Bundle, c.Leaf, c.Witnessed, c.Inclusion = "stale", 0, headOf(&st, 1, now-60, online, w1), []string{}
	d.Cases = append(d.Cases, fail("no ek for the current epoch and no lk_ok: stale-bundle", c, 4))
	_, rawLK, err := signBundle(sb, nil, e2e.BundleParams{ID: bob, Seq: 1, IAT: uint32(now - 3600), Exp: uint32(now + 30*86400), Flags: e2e.FlagCS2 | e2e.FlagLKOK, MailPolicy: e2e.PolicyBoth, MinCS: 1, E0: epoch - 10, NEK: 5, RevCommit: g.d.bytes(32)})
	if err != nil {
		return nil, err
	}
	lbun, _ := e2e.ParseBundle(rawLK)
	chL, _ := lbun.CanonicalHash()
	var lt e2e.Tree
	lt.Append(e2e.KlogLeaf(1, bob, chL, 0))
	d.Bundles["lk_ok"] = hx(rawLK)
	c.Bundle, c.Witnessed = "lk_ok", headOf(&lt, 1, now-60, online, w1)
	d.Cases = append(d.Cases, ok("stale epochs but lk_ok and unpinned: last resort to lk2", c, e2e.CS2, lbun.LK2, 0, true, false))
	c.Pin = &e2e.Pin{FP: hx(lbun.Fingerprint()), Seq: 1, CS: 2, Leaf: 0, Pol: 1}
	d.Cases = append(d.Cases, fail("lk_ok but the peer is pinned: refuse", c, 4))
	c = base
	b := mustHex(d.Bundles["bob"])
	b[200] ^= 1
	d.Bundles["tampered"] = hx(b)
	c.Bundle = "tampered"
	d.Cases = append(d.Cases, fail("tampered bundle bytes", c, 1))
	c = base
	c.Now = int64(bb.Exp) + 1
	c.Witnessed = headOf(&tr, 9, int64(bb.Exp), online, w1)
	d.Cases = append(d.Cases, fail("expired bundle", c, 1))
	if x.err != nil {
		return nil, x.err
	}
	return d, nil
}

func checkDVR(data []byte) error {
	var d dvrDoc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	x := &dec{}
	online, w1 := ed25519.NewKeyFromSeed(x.b(d.OnlineSeed)), ed25519.NewKeyFromSeed(x.b(d.W1Seed))
	if err := want("online_pk", pub(online), x.b(d.OnlinePK)); err != nil {
		return err
	}
	if err := want("w1_pk", pub(w1), x.b(d.W1PK)); err != nil {
		return err
	}
	for _, c := range d.Cases {
		rawHex, ok := d.Bundles[c.Bundle]
		if !ok {
			return fmt.Errorf("case %q: unknown bundle %q", c.What, c.Bundle)
		}
		in := e2e.DVRInput{Now: c.Now, ID: c.ID, Raw: x.b(rawHex), Leaf: c.Leaf, Pending: c.Pending, OnlinePK: x.b(d.OnlinePK), WitnessPKs: map[string][]byte{"w1": x.b(d.W1PK)},
			MinWitness: c.MinWitness, Witnessed: toHead(c.Witnessed, x), ServerSTH: toHead(c.ServerSTH, x), Inclusion: x.bs(c.Inclusion), Consistency: x.bs(c.Consistency),
			IndexSeq: c.IndexSeq, Pin: c.Pin, ClientMaxCS: e2e.Suite(c.ClientMaxCS), TOFU: c.TOFU}
		if c.PrevIK != "" {
			in.PrevIK = x.b(c.PrevIK)
		}
		// heads are re-signed from the seeds to prove the recorded signatures are the statements of 3.3/3.4
		for _, h := range []*headVec{c.Witnessed, c.ServerSTH} {
			if h == nil {
				continue
			}
			if !e2e.Verify(pub(online), e2e.STHBytes(h.Size, x.b(h.Root), h.At), x.b(h.Sig)) {
				return fmt.Errorf("case %q: head signature is not the online key's statement", c.What)
			}
			if h.W1 != "" && !e2e.Verify(pub(w1), e2e.WitnessBytes(h.Size, x.b(h.Root), h.At), x.b(h.W1)) {
				return fmt.Errorf("case %q: witness signature", c.What)
			}
		}
		res, err := e2e.DVR(in)
		if c.Expect == "ok" {
			if err != nil {
				return fmt.Errorf("case %q: %v", c.What, err)
			}
			if uint8(res.CS) != c.CS || hx(res.Key) != c.Key || res.Epoch != c.Epoch || res.LT != c.LT || res.Provisional != c.Provisional || res.TOFU != c.TOFU {
				return fmt.Errorf("case %q: result differs", c.What)
			}
			continue
		}
		if err == nil || !strings.HasPrefix(err.Error(), c.Expect+" ") {
			return fmt.Errorf("case %q: want %q, got %v", c.What, c.Expect, err)
		}
	}
	return x.err
}
