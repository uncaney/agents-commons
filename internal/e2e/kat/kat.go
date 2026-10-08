// Package kat generates and checks the composition known-answer vectors of internal/e2e/vectors
// (SECURITY-E2EE-v2 9.6). Every vector records inputs, intermediates and outputs so that a
// reimplementation (/e2e.py, /e2e.mjs) can reproduce them byte for byte; negative vectors must fail.
//
// Generation is deterministic from a seed (one SHAKE256 stream) except for HPKE encapsulations, which
// draw an ephemeral key from crypto/rand inside the standard library: those recorded ciphertexts are
// reused from the existing files when they still open, so `go run ./internal/e2e/gen` regenerates the
// checked-in set byte-identically.
package kat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"ekaii.fr/commons/internal/e2e"
)

// Files lists the vector files in generation order.
var Files = []string{"labels.json", "derive.json", "pad.json", "merkle.json", "reqsig.json", "cxs1.json",
	"state.json", "att.json", "bundle.json", "cxm1.json", "cxg1.json", "dvr.json"}

const (
	alice = "aalice2"
	bob   = "abobbob"
	carol = "acarol7"
	dave  = "adave77"
	gid   = "gswarm2"
	now   = int64(1_790_000_000) // fixed clock of the vectors (2026-09-21)
)

type drbg struct{ h *sha3.SHAKE }

func newDRBG(seed uint64) *drbg {
	h := sha3.NewSHAKE256()
	h.Write([]byte("cx1-kat-gen"))
	h.Write(e2e.U64(seed))
	return &drbg{h}
}

func (d *drbg) bytes(n int) []byte {
	b := make([]byte, n)
	d.h.Read(b)
	return b
}

func (d *drbg) Read(p []byte) (int, error) { return d.h.Read(p) }

type gen struct {
	d     *drbg
	prior map[string][]byte
}

// Generate produces every file; prior holds the existing files (nil when generating from scratch).
func Generate(seed uint64, prior map[string][]byte) (map[string][]byte, error) {
	g := &gen{d: newDRBG(seed), prior: prior}
	out := map[string][]byte{}
	for _, name := range Files {
		var doc any
		var err error
		switch name {
		case "labels.json":
			doc = g.labels()
		case "derive.json":
			doc = g.derive()
		case "pad.json":
			doc = g.pad()
		case "merkle.json":
			doc = g.merkle()
		case "reqsig.json":
			doc = g.reqsig()
		case "cxs1.json":
			doc = g.cxs1()
		case "state.json":
			doc, err = g.state()
		case "att.json":
			doc, err = g.att()
		case "bundle.json":
			doc, err = g.bundle()
		case "cxm1.json":
			doc, err = g.cxm1()
		case "cxg1.json":
			doc, err = g.cxg1()
		case "dvr.json":
			doc, err = g.dvr()
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		b, err := json.MarshalIndent(doc, "", " ")
		if err != nil {
			return nil, err
		}
		b = append(b, '\n')
		if err := Check(name, b); err != nil {
			return nil, fmt.Errorf("%s: self-check: %w", name, err)
		}
		out[name] = b
	}
	return out, nil
}

// Check re-verifies one vector file against the e2e package.
func Check(name string, data []byte) error {
	switch name {
	case "labels.json":
		return checkLabels(data)
	case "derive.json":
		return checkDerive(data)
	case "pad.json":
		return checkPad(data)
	case "merkle.json":
		return checkMerkle(data)
	case "reqsig.json":
		return checkReqsig(data)
	case "cxs1.json":
		return checkCxs1(data)
	case "state.json":
		return checkState(data)
	case "att.json":
		return checkAtt(data)
	case "bundle.json":
		return checkBundle(data)
	case "cxm1.json":
		return checkCxm1(data)
	case "cxg1.json":
		return checkCxg1(data)
	case "dvr.json":
		return checkDVR(data)
	}
	return fmt.Errorf("unknown vector file %q", name)
}

// ---- helpers

func hx(b []byte) string { return hex.EncodeToString(b) }

func hxs(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = hx(b)
	}
	return out
}

// dec decodes hex fields, latching the first error.
type dec struct{ err error }

func (d *dec) b(s string) []byte {
	if d.err != nil {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		d.err = fmt.Errorf("bad hex %q", s)
	}
	return b
}

func (d *dec) bs(ss []string) [][]byte {
	out := make([][]byte, len(ss))
	for i, s := range ss {
		out[i] = d.b(s)
	}
	return out
}

func want(what string, got, exp []byte) error {
	if !bytes.Equal(got, exp) {
		return fmt.Errorf("%s: got %s want %s", what, short(hx(got)), short(hx(exp)))
	}
	return nil
}

func short(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

func wantS(what, got, exp string) error {
	if got != exp {
		return fmt.Errorf("%s: got %q want %q", what, short(got), short(exp))
	}
	return nil
}

func unmarshal(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

func pub(k ed25519.PrivateKey) []byte { return k.Public().(ed25519.PublicKey) }

func (g *gen) seed() []byte { return g.d.bytes(32) }

func (g *gen) priorDoc(name string, v any) bool {
	b, ok := g.prior[name]
	if !ok {
		return false
	}
	return unmarshal(b, v) == nil
}

// ---- labels.json

type labeledVec struct {
	Label string   `json:"label"`
	Parts []string `json:"parts"`
	Out   string   `json:"out"`
}

type hkdfVec struct {
	Secret string `json:"secret"`
	Salt   string `json:"salt"` // "" = DefaultSalt
	Info   string `json:"info"` // hex
	N      int    `json:"n"`
	Out    string `json:"out"`
}

type labelsDoc struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Labels      []string     `json:"labels"`
	DefaultSalt string       `json:"default_salt"`
	Separator   string       `json:"separator"`
	Labeled     []labeledVec `json:"labeled"`
	HKDF        []hkdfVec    `json:"hkdf"`
}

func (g *gen) labels() *labelsDoc {
	d := &labelsDoc{Name: "labels", Description: "Domain separation (E2EE 2.3): every signed, MACed or derived input is label || 0x00 || payload; a bare label when there is no payload. HKDF is hkdf.Key(sha256, secret, salt, info, n) with salt agents.ekaii.fr/cx1 unless a per-message salt is given.",
		Labels: e2e.Labels, DefaultSalt: e2e.DefaultSalt, Separator: "00"}
	parts := [][]byte{[]byte(alice), []byte(bob), e2e.U32(7)}
	d.Labeled = append(d.Labeled, labeledVec{Label: e2e.LabelMail, Parts: hxs(parts), Out: hx(e2e.Labeled(e2e.LabelMail, parts...))})
	d.Labeled = append(d.Labeled, labeledVec{Label: e2e.LabelIK, Parts: []string{}, Out: hx(e2e.Labeled(e2e.LabelIK))})
	d.Labeled = append(d.Labeled, labeledVec{Label: e2e.LabelCXS1, Parts: hxs([][]byte{{}, {0xff}}), Out: hx(e2e.Labeled(e2e.LabelCXS1, nil, []byte{0xff}))})
	s := g.seed()
	d.HKDF = append(d.HKDF, hkdfVec{Secret: hx(s), Salt: "", Info: hx([]byte(e2e.LabelIK)), N: 32, Out: hx(e2e.HKDF(s, nil, e2e.LabelIK, 32))})
	salt := g.d.bytes(32)
	info := e2e.Labeled(e2e.LabelAuth, []byte(alice), []byte(bob))
	d.HKDF = append(d.HKDF, hkdfVec{Secret: hx(s), Salt: hx(salt), Info: hx(info), N: 32, Out: hx(e2e.HKDF(s, salt, string(info), 32))})
	d.HKDF = append(d.HKDF, hkdfVec{Secret: hx(s), Salt: "", Info: hx([]byte(e2e.EKInfo(e2e.CS2, 2959))), N: 32, Out: hx(e2e.HKDF(s, nil, e2e.EKInfo(e2e.CS2, 2959), 32))})
	return d
}

func checkLabels(data []byte) error {
	var d labelsDoc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	if strings.Join(d.Labels, "\n") != strings.Join(e2e.Labels, "\n") || d.DefaultSalt != e2e.DefaultSalt {
		return errors.New("labels list differs")
	}
	for _, v := range d.Labeled {
		x := &dec{}
		parts := x.bs(v.Parts)
		if x.err != nil {
			return x.err
		}
		if err := want("labeled "+v.Label, e2e.Labeled(v.Label, parts...), x.b(v.Out)); err != nil {
			return err
		}
	}
	for _, v := range d.HKDF {
		x := &dec{}
		var salt []byte
		if v.Salt != "" {
			salt = x.b(v.Salt)
		}
		out := e2e.HKDF(x.b(v.Secret), salt, string(x.b(v.Info)), v.N)
		if x.err != nil {
			return x.err
		}
		if err := want("hkdf", out, x.b(v.Out)); err != nil {
			return err
		}
	}
	return nil
}

// ---- derive.json

type deriveVec struct {
	Seed         string   `json:"seed"`
	SeedText     string   `json:"seed_text"`
	IK           string   `json:"ik"`
	RK           string   `json:"rk"`
	AK           string   `json:"ak"`
	LK1          string   `json:"lk1"`
	LK2          string   `json:"lk2"`
	E0           uint32   `json:"e0"`
	EK1          []string `json:"ek1"`
	EK2          []string `json:"ek2"`
	Share        string   `json:"share"`
	EK1Share     string   `json:"ek1_share"` // ek1(e0) in mode D+ with Share as salt
	KState       string   `json:"k_state"`
	SubID        string   `json:"sub_id"`
	Sub          string   `json:"sub"`
	MK           string   `json:"mk"`
	KV           string   `json:"k_v"`
	Seal2MAC     string   `json:"seal2_mac"`
	RecoveryCode string   `json:"recovery_code"`
	WrapNonce    string   `json:"wrap_nonce"`
	MKWrapped    string   `json:"mk_wrapped"`
	PQID         string   `json:"pq_id"`
	FP           string   `json:"fp"`
	FPDigits     string   `json:"fp_digits"`
	FP16         string   `json:"fp16"`
	Unix         int64    `json:"unix"`
	Epoch        uint32   `json:"epoch"`
	EpochStart   int64    `json:"epoch_start"`
}

type deriveDoc struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Vectors     []deriveVec `json:"vectors"`
}

func (g *gen) derive() *deriveDoc {
	d := &deriveDoc{Name: "derive", Description: "Seed derivations (E2EE 2.4, SPEC-v2 26.4): public halves of ik/rk/ak/lk/ek, k_state, sub seed, mk, k_v, pq_id, fingerprint and epochs."}
	for i := 0; i < 2; i++ {
		s := g.seed()
		v := deriveVec{Seed: hx(s), SeedText: e2e.FormatSeed(s), IK: hx(pub(e2e.IK(s))), RK: hx(pub(e2e.RK(s))), AK: hx(e2e.AK(s).PublicKey().Bytes()),
			E0: 2959 + uint32(i), KState: hx(e2e.KState(s)), SubID: "worker-1", Sub: hx(e2e.Sub(s, "worker-1")), MK: hx(e2e.MK(s)),
			PQID: hx(e2e.PQID(s).PublicKey().Bytes()), Unix: now + int64(i)*604800, Epoch: e2e.Epoch(now + int64(i)*604800), EpochStart: e2e.EpochStart(e2e.Epoch(now + int64(i)*604800))}
		lk1, _ := e2e.LK(s, e2e.CS1)
		lk2, _ := e2e.LK(s, e2e.CS2)
		v.LK1, v.LK2 = hx(lk1.PublicKey().Bytes()), hx(lk2.PublicKey().Bytes())
		for e := v.E0; e < v.E0+2; e++ {
			k1, _ := e2e.EK(s, e2e.CS1, e, nil)
			k2, _ := e2e.EK(s, e2e.CS2, e, nil)
			v.EK1 = append(v.EK1, hx(k1.PublicKey().Bytes()))
			v.EK2 = append(v.EK2, hx(k2.PublicKey().Bytes()))
		}
		share := g.d.bytes(32)
		ks, _ := e2e.EK(s, e2e.CS1, v.E0, share)
		v.Share, v.EK1Share = hx(share), hx(ks.PublicKey().Bytes())
		kv := e2e.SealV1Key(e2e.MK(s))
		v.KV, v.Seal2MAC = hx(kv), hx(e2e.Seal2MACKey(kv, ""))
		code, nonce := g.d.bytes(16), g.d.bytes(12)
		w, _ := e2e.WrapMK(e2e.MK(s), code, bytes.NewReader(nonce))
		v.RecoveryCode, v.WrapNonce, v.MKWrapped = hx(code), hx(nonce), hx(w)
		fp := e2e.Fingerprint(pub(e2e.IK(s)))
		v.FP, v.FPDigits, v.FP16 = hx(fp), e2e.FPDigits(fp), e2e.FP16(fp)
		d.Vectors = append(d.Vectors, v)
	}
	return d
}

func checkDerive(data []byte) error {
	var d deriveDoc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	for _, v := range d.Vectors {
		x := &dec{}
		s := x.b(v.Seed)
		if x.err != nil || len(s) != 32 {
			return errors.New("bad seed")
		}
		if ps, err := e2e.ParseSeed(v.SeedText); err != nil || !bytes.Equal(ps, s) || e2e.FormatSeed(s) != v.SeedText {
			return errors.New("seed text")
		}
		lk1, _ := e2e.LK(s, e2e.CS1)
		lk2, _ := e2e.LK(s, e2e.CS2)
		checks := []struct {
			what string
			got  []byte
			exp  string
		}{{"ik", pub(e2e.IK(s)), v.IK}, {"rk", pub(e2e.RK(s)), v.RK}, {"ak", e2e.AK(s).PublicKey().Bytes(), v.AK},
			{"lk1", lk1.PublicKey().Bytes(), v.LK1}, {"lk2", lk2.PublicKey().Bytes(), v.LK2}, {"k_state", e2e.KState(s), v.KState},
			{"sub", e2e.Sub(s, v.SubID), v.Sub}, {"mk", e2e.MK(s), v.MK}, {"k_v", e2e.SealV1Key(e2e.MK(s)), v.KV},
			{"seal2_mac", e2e.Seal2MACKey(e2e.SealV1Key(e2e.MK(s)), ""), v.Seal2MAC}, {"pq_id", e2e.PQID(s).PublicKey().Bytes(), v.PQID},
			{"fp", e2e.Fingerprint(pub(e2e.IK(s))), v.FP}}
		for _, c := range checks {
			if err := want(c.what, c.got, x.b(c.exp)); err != nil {
				return err
			}
		}
		for i := range v.EK1 {
			k1, _ := e2e.EK(s, e2e.CS1, v.E0+uint32(i), nil)
			k2, _ := e2e.EK(s, e2e.CS2, v.E0+uint32(i), nil)
			if err := want("ek1", k1.PublicKey().Bytes(), x.b(v.EK1[i])); err != nil {
				return err
			}
			if err := want("ek2", k2.PublicKey().Bytes(), x.b(v.EK2[i])); err != nil {
				return err
			}
		}
		ks, _ := e2e.EK(s, e2e.CS1, v.E0, x.b(v.Share))
		if err := want("ek1_share", ks.PublicKey().Bytes(), x.b(v.EK1Share)); err != nil {
			return err
		}
		w, err := e2e.WrapMK(e2e.MK(s), x.b(v.RecoveryCode), bytes.NewReader(x.b(v.WrapNonce)))
		if err != nil {
			return err
		}
		if err := want("mk_wrapped", w, x.b(v.MKWrapped)); err != nil {
			return err
		}
		if mk, err := e2e.UnwrapMK(w, x.b(v.RecoveryCode)); err != nil || !bytes.Equal(mk, e2e.MK(s)) {
			return errors.New("unwrap mk")
		}
		fp := x.b(v.FP)
		if err := wantS("fp_digits", e2e.FPDigits(fp), v.FPDigits); err != nil {
			return err
		}
		if err := wantS("fp16", e2e.FP16(fp), v.FP16); err != nil {
			return err
		}
		if e2e.Epoch(v.Unix) != v.Epoch || e2e.EpochStart(v.Epoch) != v.EpochStart {
			return errors.New("epoch")
		}
		if x.err != nil {
			return x.err
		}
	}
	return nil
}

// ---- pad.json

type padVec struct {
	Lane    string `json:"lane"`
	Buckets []int  `json:"buckets"`
	In      string `json:"in"`
	Out     string `json:"out"`
}

type padNeg struct {
	Kind  string `json:"kind"` // unpad | pad
	What  string `json:"what"`
	Lane  string `json:"lane,omitempty"`
	Input string `json:"input"`
}

type padDoc struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Vectors     []padVec `json:"vectors"`
	Negative    []padNeg `json:"negative"`
}

func lane(name string) []int {
	switch name {
	case "mail":
		return e2e.MailBuckets
	case "group":
		return e2e.GroupBuckets
	case "object":
		return e2e.ObjectBuckets
	}
	return nil
}

func (g *gen) pad() *padDoc {
	d := &padDoc{Name: "pad", Description: "ISO/IEC 7816-4 padding (one 0x80 then zeros) to the lane buckets: mail 1k/2k/4k, group 1k/4k, object 4k/16k/64k (E2EE 2.5, SPEC-v2 26.4)."}
	for _, c := range []struct {
		lane string
		n    int
	}{{"mail", 0}, {"mail", 5}, {"mail", 1023}, {"mail", 1024}, {"mail", 2047}, {"group", 1023}, {"group", 1024}, {"object", 4095}} {
		in := g.d.bytes(c.n)
		out, _ := e2e.Pad(in, lane(c.lane))
		d.Vectors = append(d.Vectors, padVec{Lane: c.lane, Buckets: lane(c.lane), In: hx(in), Out: hx(out)})
	}
	d.Negative = []padNeg{
		{Kind: "unpad", What: "empty", Input: ""},
		{Kind: "unpad", What: "all zeros", Input: hx(make([]byte, 1024))},
		{Kind: "unpad", What: "no marker", Input: hx(bytes.Repeat([]byte{1}, 1024))},
		{Kind: "pad", What: "4096 bytes do not fit the 4k mail bucket", Lane: "mail", Input: hx(make([]byte, 4096))},
		{Kind: "pad", What: "4096 bytes do not fit the 4k group bucket", Lane: "group", Input: hx(make([]byte, 4096))},
	}
	return d
}

func checkPad(data []byte) error {
	var d padDoc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	for _, v := range d.Vectors {
		x := &dec{}
		in, out := x.b(v.In), x.b(v.Out)
		if x.err != nil {
			return x.err
		}
		got, err := e2e.Pad(in, v.Buckets)
		if err != nil {
			return err
		}
		if err := want("pad", got, out); err != nil {
			return err
		}
		if u, err := e2e.Unpad(out); err != nil || !bytes.Equal(u, in) {
			return errors.New("unpad")
		}
		if len(v.Buckets) != len(lane(v.Lane)) {
			return errors.New("bucket table")
		}
	}
	for _, n := range d.Negative {
		x := &dec{}
		in := x.b(n.Input)
		if x.err != nil {
			return x.err
		}
		switch n.Kind {
		case "unpad":
			if _, err := e2e.Unpad(in); err == nil {
				return fmt.Errorf("negative %q accepted", n.What)
			}
		case "pad":
			if _, err := e2e.Pad(in, lane(n.Lane)); err == nil {
				return fmt.Errorf("negative %q accepted", n.What)
			}
		default:
			return fmt.Errorf("unknown negative kind %q", n.Kind)
		}
	}
	return nil
}

// ---- merkle.json

type pathVec struct {
	Idx  uint64   `json:"idx"`
	Size uint64   `json:"size"`
	Path []string `json:"path"`
}

type consVec struct {
	From uint64   `json:"from"`
	To   uint64   `json:"to"`
	Path []string `json:"path"`
}

type klogVec struct {
	Kind     uint8  `json:"kind"`
	ID       string `json:"id"`
	ItemHash string `json:"item_hash"`
	Idx      uint64 `json:"idx"`
	Leaf     string `json:"leaf"`
}

type merkleNeg struct {
	Kind     string   `json:"kind"` // inclusion | consistency
	What     string   `json:"what"`
	LeafHash string   `json:"leaf_hash,omitempty"`
	Idx      uint64   `json:"idx,omitempty"`
	Size     uint64   `json:"size,omitempty"`
	From     uint64   `json:"from,omitempty"`
	To       uint64   `json:"to,omitempty"`
	Root1    string   `json:"root1,omitempty"`
	Root     string   `json:"root"`
	Path     []string `json:"path"`
}

type merkleDoc struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Leaves      []string    `json:"leaves"`
	LeafHashes  []string    `json:"leaf_hashes"`
	Roots       []string    `json:"roots"` // roots[n] = root of the first n leaves
	Inclusion   []pathVec   `json:"inclusion"`
	Consistency []consVec   `json:"consistency"`
	Klog        klogVec     `json:"klog"`
	Negative    []merkleNeg `json:"negative"`
}

var rfc6962Leaves = [][]byte{{}, {0x00}, {0x10}, {0x20, 0x21}, {0x30, 0x31}, {0x40, 0x41, 0x42, 0x43},
	{0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57}, {0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f}}

func (g *gen) merkle() *merkleDoc {
	d := &merkleDoc{Name: "merkle", Description: "RFC 6962 hashing (leaf sha256(0x00||data), node sha256(0x01||l||r)) over the certificate-transparency test leaves: roots for every prefix, every audit path of the 7- and 8-leaf trees, every consistency path up to 8, and the klog leaf of E2EE 3.3."}
	var tr e2e.Tree
	for _, l := range rfc6962Leaves {
		d.Leaves = append(d.Leaves, hx(l))
		d.LeafHashes = append(d.LeafHashes, hx(e2e.LeafHash(l)))
		tr.Append(e2e.LeafHash(l))
	}
	for n := uint64(0); n <= tr.Size(); n++ {
		d.Roots = append(d.Roots, hx(tr.RootAt(n)))
	}
	for _, size := range []uint64{7, 8} {
		for i := uint64(0); i < size; i++ {
			d.Inclusion = append(d.Inclusion, pathVec{Idx: i, Size: size, Path: hxs(tr.Inclusion(i, size))})
		}
	}
	for to := uint64(1); to <= 8; to++ {
		for from := uint64(1); from <= to; from++ {
			d.Consistency = append(d.Consistency, consVec{From: from, To: to, Path: hxs(tr.Consistency(from, to))})
		}
	}
	item := g.d.bytes(32)
	d.Klog = klogVec{Kind: 1, ID: alice, ItemHash: hx(item), Idx: 42, Leaf: hx(e2e.KlogLeaf(1, alice, item, 42))}
	wrong := hxs(tr.Inclusion(3, 8))
	d.Negative = []merkleNeg{
		{Kind: "inclusion", What: "path of leaf 3 presented for leaf 2", LeafHash: hx(tr.Leaf(2)), Idx: 2, Size: 8, Root: hx(tr.Root()), Path: wrong},
		{Kind: "inclusion", What: "truncated path", LeafHash: hx(tr.Leaf(3)), Idx: 3, Size: 8, Root: hx(tr.Root()), Path: wrong[:2]},
		{Kind: "inclusion", What: "index beyond the tree", LeafHash: hx(tr.Leaf(3)), Idx: 8, Size: 8, Root: hx(tr.Root()), Path: wrong},
		{Kind: "consistency", What: "proof between inconsistent trees (first root altered)", From: 4, To: 8, Root1: hx(e2e.Sum(tr.RootAt(4))), Root: hx(tr.Root()), Path: hxs(tr.Consistency(4, 8))},
		{Kind: "consistency", What: "empty proof for a real extension", From: 4, To: 8, Root1: hx(tr.RootAt(4)), Root: hx(tr.Root()), Path: []string{}},
	}
	return d
}

func checkMerkle(data []byte) error {
	var d merkleDoc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	x := &dec{}
	var tr e2e.Tree
	for i, l := range x.bs(d.Leaves) {
		h := e2e.LeafHash(l)
		if err := want("leaf hash", h, x.b(d.LeafHashes[i])); err != nil {
			return err
		}
		tr.Append(h)
	}
	for n := range d.Roots {
		if err := want(fmt.Sprintf("root %d", n), tr.RootAt(uint64(n)), x.b(d.Roots[n])); err != nil {
			return err
		}
	}
	for _, p := range d.Inclusion {
		path := x.bs(p.Path)
		if hx(bytes.Join(tr.Inclusion(p.Idx, p.Size), nil)) != hx(bytes.Join(path, nil)) {
			return fmt.Errorf("inclusion path %d/%d", p.Idx, p.Size)
		}
		if !e2e.VerifyInclusion(tr.Leaf(p.Idx), p.Idx, p.Size, path, tr.RootAt(p.Size)) {
			return fmt.Errorf("inclusion verify %d/%d", p.Idx, p.Size)
		}
	}
	for _, c := range d.Consistency {
		path := x.bs(c.Path)
		if hx(bytes.Join(tr.Consistency(c.From, c.To), nil)) != hx(bytes.Join(path, nil)) {
			return fmt.Errorf("consistency path %d->%d", c.From, c.To)
		}
		if !e2e.VerifyConsistency(c.From, c.To, tr.RootAt(c.From), tr.RootAt(c.To), path) {
			return fmt.Errorf("consistency verify %d->%d", c.From, c.To)
		}
	}
	if err := want("klog leaf", e2e.KlogLeaf(d.Klog.Kind, d.Klog.ID, x.b(d.Klog.ItemHash), d.Klog.Idx), x.b(d.Klog.Leaf)); err != nil {
		return err
	}
	for _, n := range d.Negative {
		switch n.Kind {
		case "inclusion":
			if e2e.VerifyInclusion(x.b(n.LeafHash), n.Idx, n.Size, x.bs(n.Path), x.b(n.Root)) {
				return fmt.Errorf("negative %q verified", n.What)
			}
		case "consistency":
			if e2e.VerifyConsistency(n.From, n.To, x.b(n.Root1), x.b(n.Root), x.bs(n.Path)) {
				return fmt.Errorf("negative %q verified", n.What)
			}
		default:
			return fmt.Errorf("unknown negative kind %q", n.Kind)
		}
	}
	return x.err
}

// ---- reqsig.json

type reqVec struct {
	What      string `json:"what"`
	RKSeed    string `json:"rk_seed"` // the agent seed; rk = RK(seed)
	RK        string `json:"rk"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	TS        uint64 `json:"ts"`
	Nonce     string `json:"nonce"`
	Body      string `json:"body"`
	BodyHash  string `json:"body_hash"`
	Canonical string `json:"canonical"`
	Sig       string `json:"sig"`
	Header    string `json:"header"`
	SendSig   string `json:"send_sig"`
}

type respVec struct {
	OnlineSeed string `json:"online_seed"`
	OnlinePK   string `json:"online_pk"`
	Path       string `json:"path"`
	T          uint64 `json:"t"`
	Body       string `json:"body"`
	Canonical  string `json:"canonical"`
	Header     string `json:"header"`
}

type stmtsVec struct {
	OnlineSeed string `json:"online_seed"`
	OnlinePK   string `json:"online_pk"`
	RootSeed   string `json:"root_seed"`
	RootPK     string `json:"root_pk"`
	W1Seed     string `json:"w1_seed"`
	W1PK       string `json:"w1_pk"`
	Size       uint64 `json:"size"`
	Root       string `json:"root"`
	At         uint64 `json:"at"`
	STH        string `json:"sth"`
	STHSig     string `json:"sth_sig"`
	Witness    string `json:"witness"`
	WitnessSig string `json:"witness_sig"`
	NBF        uint64 `json:"nbf"`
	Exp        uint64 `json:"exp"`
	CertSeq    uint32 `json:"cert_seq"`
	Cert       string `json:"cert"`
	CertSig    string `json:"cert_sig"`
	Old        string `json:"old"`
	New        string `json:"new"`
	IKNew      string `json:"ik_new"`
	Succ       string `json:"succ"`
	Hdr        string `json:"hdr"`
	Seq        uint64 `json:"seq"`
	RcptAt     uint64 `json:"rcpt_at"`
	Rcpt       string `json:"rcpt"`
	RcptSig    string `json:"rcpt_sig"`
	GRcpt      string `json:"grcpt"`
	GRcptSig   string `json:"grcpt_sig"`
	ID         string `json:"id"`
	RootID     string `json:"root_id"`
	Rep        int32  `json:"rep"`
	Day        uint32 `json:"day"`
	AttRep     string `json:"att_rep"`
	Stamp      string `json:"stamp"` // StampPrefix(bob, body, day)
}

type reqNeg struct {
	What   string `json:"what"`
	RK     string `json:"rk"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body"`
	Header string `json:"header"`
	Now    int64  `json:"now"`
}

type reqsigDoc struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Requests    []reqVec `json:"requests"`
	Reply       respVec  `json:"reply"`
	Statements  stmtsVec `json:"statements"`
	Negative    []reqNeg `json:"negative"`
}

func (g *gen) reqsig() *reqsigDoc {
	d := &reqsigDoc{Name: "reqsig", Description: "Request signing (E2EE 3.5): sig = Ed25519(rk, \"cx1/req\" || 0x00 || METHOD || 0x0a || path?query || 0x0a || u64(ts) || nonce || sha256(body)); header v1,<ts>,<nonce b64url>,<sig b64url>; send_sig dotted form. Signed replies (3.6), STH/witness/cert/succession/receipt/attestation statements."}
	s := g.seed()
	rk := e2e.RK(s)
	for _, c := range []struct {
		what, method, path string
		body               []byte
	}{{"send", "POST", "/v1/x/" + bob, g.d.bytes(1175)}, {"ack", "POST", "/v1/x/ack", []byte(`{"upto":12}`)}, {"keys", "PUT", "/v1/keys?f=json", g.d.bytes(514)}} {
		nonce := g.d.bytes(16)
		ts := uint64(now)
		bh := e2e.Sum(c.body)
		h, _ := e2e.SignReq(rk, c.method, c.path, ts, nonce, c.body)
		sig, _ := e2e.ParseReqSig(h)
		d.Requests = append(d.Requests, reqVec{What: c.what, RKSeed: hx(s), RK: hx(pub(rk)), Method: c.method, Path: c.path, TS: ts, Nonce: hx(nonce), Body: hx(c.body),
			BodyHash: hx(bh), Canonical: hx(e2e.ReqBytes(c.method, c.path, ts, nonce, bh)), Sig: hx(sig.Sig), Header: h, SendSig: sig.SendSig()})
	}
	os, rs, ws := g.seed(), g.seed(), g.seed()
	online, root, w1 := ed25519.NewKeyFromSeed(os), ed25519.NewKeyFromSeed(rs), ed25519.NewKeyFromSeed(ws)
	reply := []byte("id=" + alice + " token=cx_x credits=100 seq=1 leaf=3 bundle=ab head=cd\n")
	d.Reply = respVec{OnlineSeed: hx(os), OnlinePK: hx(pub(online)), Path: "/v1/register", T: uint64(now), Body: hx(reply),
		Canonical: hx(e2e.RespBytes("/v1/register", uint64(now), e2e.Sum(reply))), Header: e2e.SignResp(online, "/v1/register", uint64(now), reply)}
	rootHash := g.d.bytes(32)
	hdr := g.d.bytes(71)
	ikNew := g.d.bytes(32)
	st := stmtsVec{OnlineSeed: hx(os), OnlinePK: hx(pub(online)), RootSeed: hx(rs), RootPK: hx(pub(root)), W1Seed: hx(ws), W1PK: hx(pub(w1)),
		Size: 9, Root: hx(rootHash), At: uint64(now), NBF: uint64(now), Exp: uint64(now + 30*86400), CertSeq: 3, Old: alice, New: bob, IKNew: hx(ikNew),
		Hdr: hx(hdr), Seq: 77, RcptAt: uint64(now + 1), ID: alice, RootID: alice, Rep: -5, Day: 20699}
	st.STH = hx(e2e.STHBytes(9, rootHash, uint64(now)))
	st.STHSig = hx(e2e.Sign(online, e2e.STHBytes(9, rootHash, uint64(now))))
	st.Witness = hx(e2e.WitnessBytes(9, rootHash, uint64(now)))
	st.WitnessSig = hx(e2e.Sign(w1, e2e.WitnessBytes(9, rootHash, uint64(now))))
	st.Cert = hx(e2e.CertBytes(pub(online), st.NBF, st.Exp, 3))
	st.CertSig = hx(e2e.Sign(root, e2e.CertBytes(pub(online), st.NBF, st.Exp, 3)))
	st.Succ = hx(e2e.SuccBytes(alice, bob, ikNew))
	st.Rcpt = hx(e2e.RcptBytes(hdr, 77, st.RcptAt))
	st.RcptSig = hx(e2e.SignRcpt(online, hdr, 77, st.RcptAt))
	st.GRcpt = hx(e2e.GRcptBytes(hdr, 77, st.RcptAt))
	st.GRcptSig = hx(e2e.Sign(online, e2e.GRcptBytes(hdr, 77, st.RcptAt)))
	st.AttRep = hx(e2e.AttRepBytes(alice, alice, -5, 20699))
	st.Stamp = e2e.StampPrefix(bob, reply, "20260921")
	d.Statements = st
	r0 := d.Requests[0]
	flip := []byte(r0.Header)
	flip[len(flip)-1] ^= 1
	d.Negative = []reqNeg{
		{What: "tampered signature", RK: r0.RK, Method: r0.Method, Path: r0.Path, Body: r0.Body, Header: string(flip), Now: now},
		{What: "other path", RK: r0.RK, Method: r0.Method, Path: "/v1/x/" + carol, Body: r0.Body, Header: r0.Header, Now: now},
		{What: "other method", RK: r0.RK, Method: "PUT", Path: r0.Path, Body: r0.Body, Header: r0.Header, Now: now},
		{What: "other body", RK: r0.RK, Method: r0.Method, Path: r0.Path, Body: hx([]byte("x")), Header: r0.Header, Now: now},
		{What: "skew 301 s", RK: r0.RK, Method: r0.Method, Path: r0.Path, Body: r0.Body, Header: r0.Header, Now: now + 301},
		{What: "another rk", RK: hx(pub(e2e.RK(g.seed()))), Method: r0.Method, Path: r0.Path, Body: r0.Body, Header: r0.Header, Now: now},
		{What: "ack signature replayed as a send", RK: r0.RK, Method: r0.Method, Path: r0.Path, Body: r0.Body, Header: d.Requests[1].Header, Now: now},
	}
	return d
}

func checkReqsig(data []byte) error {
	var d reqsigDoc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	x := &dec{}
	for _, v := range d.Requests {
		rk := e2e.RK(x.b(v.RKSeed))
		if err := want("rk", pub(rk), x.b(v.RK)); err != nil {
			return err
		}
		body := x.b(v.Body)
		if err := want("body hash", e2e.Sum(body), x.b(v.BodyHash)); err != nil {
			return err
		}
		if err := want("canonical", e2e.ReqBytes(v.Method, v.Path, v.TS, x.b(v.Nonce), e2e.Sum(body)), x.b(v.Canonical)); err != nil {
			return err
		}
		h, err := e2e.SignReq(rk, v.Method, v.Path, v.TS, x.b(v.Nonce), body)
		if err != nil {
			return err
		}
		if err := wantS("header", h, v.Header); err != nil {
			return err
		}
		sig, err := e2e.VerifyReq(pub(rk), v.Method, v.Path, v.Header, body, int64(v.TS))
		if err != nil {
			return err
		}
		if err := want("sig", sig.Sig, x.b(v.Sig)); err != nil {
			return err
		}
		if err := wantS("send_sig", sig.SendSig(), v.SendSig); err != nil {
			return err
		}
		if ss, err := e2e.ParseSendSig(v.SendSig); err != nil || !ss.VerifyHash(pub(rk), v.Method, v.Path, x.b(v.BodyHash)) {
			return errors.New("send_sig verify")
		}
	}
	r := d.Reply
	online := ed25519.NewKeyFromSeed(x.b(r.OnlineSeed))
	body := x.b(r.Body)
	if err := want("resp canonical", e2e.RespBytes(r.Path, r.T, e2e.Sum(body)), x.b(r.Canonical)); err != nil {
		return err
	}
	if err := wantS("resp header", e2e.SignResp(online, r.Path, r.T, body), r.Header); err != nil {
		return err
	}
	if t, err := e2e.VerifyResp(x.b(r.OnlinePK), r.Path, r.Header, body); err != nil || t != r.T {
		return errors.New("resp verify")
	}
	s := d.Statements
	root, w1 := ed25519.NewKeyFromSeed(x.b(s.RootSeed)), ed25519.NewKeyFromSeed(x.b(s.W1Seed))
	online = ed25519.NewKeyFromSeed(x.b(s.OnlineSeed))
	rootHash, hdr := x.b(s.Root), x.b(s.Hdr)
	checks := []struct {
		what string
		got  []byte
		exp  string
	}{{"sth", e2e.STHBytes(s.Size, rootHash, s.At), s.STH}, {"sth sig", e2e.Sign(online, e2e.STHBytes(s.Size, rootHash, s.At)), s.STHSig},
		{"witness", e2e.WitnessBytes(s.Size, rootHash, s.At), s.Witness}, {"witness sig", e2e.Sign(w1, e2e.WitnessBytes(s.Size, rootHash, s.At)), s.WitnessSig},
		{"cert", e2e.CertBytes(pub(online), s.NBF, s.Exp, s.CertSeq), s.Cert}, {"cert sig", e2e.Sign(root, e2e.CertBytes(pub(online), s.NBF, s.Exp, s.CertSeq)), s.CertSig},
		{"succ", e2e.SuccBytes(s.Old, s.New, x.b(s.IKNew)), s.Succ}, {"rcpt", e2e.RcptBytes(hdr, s.Seq, s.RcptAt), s.Rcpt}, {"rcpt sig", e2e.SignRcpt(online, hdr, s.Seq, s.RcptAt), s.RcptSig},
		{"grcpt", e2e.GRcptBytes(hdr, s.Seq, s.RcptAt), s.GRcpt}, {"grcpt sig", e2e.Sign(online, e2e.GRcptBytes(hdr, s.Seq, s.RcptAt)), s.GRcptSig},
		{"att-rep", e2e.AttRepBytes(s.ID, s.RootID, s.Rep, s.Day), s.AttRep}}
	for _, c := range checks {
		if err := want(c.what, c.got, x.b(c.exp)); err != nil {
			return err
		}
	}
	if !e2e.VerifyRcpt(x.b(s.OnlinePK), hdr, s.Seq, s.RcptAt, x.b(s.RcptSig)) || e2e.VerifyHead(&e2e.Head{Size: s.Size, Root: rootHash, At: s.At, Sig: x.b(s.STHSig), Witness: map[string][]byte{"w1": x.b(s.WitnessSig)}}, x.b(s.OnlinePK), map[string][]byte{"w1": x.b(s.W1PK)}, 1) != nil {
		return errors.New("statement verification")
	}
	if err := wantS("stamp", e2e.StampPrefix(bob, body, "20260921"), s.Stamp); err != nil {
		return err
	}
	for _, n := range d.Negative {
		if _, err := e2e.VerifyReq(x.b(n.RK), n.Method, n.Path, n.Header, x.b(n.Body), n.Now); err == nil {
			return fmt.Errorf("negative %q verified", n.What)
		}
	}
	return x.err
}

// ---- cxs1.json

type cxs1Vec struct {
	Secret  string `json:"secret"`
	Locator string `json:"locator"`
	KEnc    string `json:"k_enc"`
	KMac    string `json:"k_mac"`
	WToken  string `json:"wtoken"`
	S       string `json:"s"`
	PT      string `json:"pt"`
	Record  string `json:"record"`
	Text    string `json:"text"`
}

type seal1Vec struct {
	MK    string `json:"mk"`
	KV    string `json:"k_v"`
	Nonce string `json:"nonce"`
	AAD   string `json:"aad"`
	PT    string `json:"pt"`
	Value string `json:"value"`
}

type seal2Vec struct {
	KV    string `json:"k_v"`
	KMac  string `json:"k_mac"`
	Nonce string `json:"nonce"`
	AAD   string `json:"aad"`
	PT    string `json:"pt"`
	Value string `json:"value"`
}

type cxs1Neg struct {
	Kind   string `json:"kind"` // cxs1 | seal1 | seal2 | nonce-reuse | not-sealed
	What   string `json:"what"`
	Secret string `json:"secret,omitempty"`
	KV     string `json:"k_v,omitempty"`
	AAD    string `json:"aad,omitempty"`
	Input  string `json:"input,omitempty"`
	A      string `json:"a,omitempty"`
	B      string `json:"b,omitempty"`
}

type cxs1Doc struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Vectors     []cxs1Vec  `json:"vectors"`
	Seal1       []seal1Vec `json:"seal1"`
	Seal2       []seal2Vec `json:"seal2"`
	Negative    []cxs1Neg  `json:"negative"`
}

func (g *gen) cxs1() *cxs1Doc {
	d := &cxs1Doc{Name: "cxs1", Description: "Symmetric lane (E2EE 7.4): locator = SHAKE256(\"cx1/loc\"||0x00||secret, 16); k_enc||k_mac = SHAKE256(\"cx1/key\"||0x00||secret, 64); wtoken = HMAC(k_mac, \"cx1/d-write\"); ct = pt xor SHAKE256(k_enc||s, len); tag = HMAC(k_mac, \"cxs1\"||0x00||s||locator||ct); record = \"cxs1\"||s||ct||tag; text form cxs1:<b64url>. Sealed memory values (SPEC-v2 26.4): k_v = HKDF(mk, \"cx-seal-v1\"); seal1:<b64url(nonce12||AES-256-GCM(k_v, pt, aad))>; seal2:<b64url(nonce16||ct||tag32)> with ct = pt xor HMAC(k_v, nonce||u32 counter) blocks and tag = HMAC(HKDF(k_v,\"mac\"||aad), nonce||ct), aad = ns|k binding the value to its key."}
	for _, n := range []int{0, 7, 100} {
		secret := g.d.bytes(24)
		s := g.d.bytes(32)
		pt := g.d.bytes(n)
		kEnc, kMac := e2e.Cxs1Keys(secret)
		rec, _ := e2e.Cxs1Seal(secret, pt, bytes.NewReader(s))
		d.Vectors = append(d.Vectors, cxs1Vec{Secret: hx(secret), Locator: e2e.LocatorHex(secret), KEnc: hx(kEnc), KMac: hx(kMac), WToken: hx(e2e.WriteToken(kMac)),
			S: hx(s), PT: hx(pt), Record: hx(rec), Text: e2e.EncodeCxs1(rec)})
	}
	mk := e2e.MK(g.seed())
	kv := e2e.SealV1Key(mk)
	for i, aad := range []string{"u:" + alice + "|k|todo", "cp|checkpoint-3", "note|plan"} {
		nonce := g.d.bytes(12)
		pt := g.d.bytes(10 * (i + 1))
		v, _ := e2e.Seal1(kv, aad, pt, bytes.NewReader(nonce))
		d.Seal1 = append(d.Seal1, seal1Vec{MK: hx(mk), KV: hx(kv), Nonce: hx(nonce), AAD: aad, PT: hx(pt), Value: v})
	}
	seal2AADs := []string{"u:" + alice + "|kv|count", "u:" + alice + "|kv|note", "cp|checkpoint-3", "note|plan"}
	for i, n := range []int{0, 31, 32, 100} {
		nonce := g.d.bytes(16)
		pt := g.d.bytes(n)
		aad := seal2AADs[i]
		v, _ := e2e.Seal2(kv, aad, pt, bytes.NewReader(nonce))
		d.Seal2 = append(d.Seal2, seal2Vec{KV: hx(kv), KMac: hx(e2e.Seal2MACKey(kv, aad)), Nonce: hx(nonce), AAD: aad, PT: hx(pt), Value: v})
	}
	v0 := d.Vectors[1]
	rec := mustHex(v0.Record)
	tagFlip := append([]byte(nil), rec...)
	tagFlip[len(tagFlip)-1] ^= 1
	ctFlip := append([]byte(nil), rec...)
	ctFlip[40] ^= 1
	s1 := d.Seal1[0]
	s1bad := flipLastB64(s1.Value)
	s2 := d.Seal2[1]
	same1, _ := e2e.Seal1(kv, "k", []byte("v2"), bytes.NewReader(mustHex(s1.Nonce)))
	same2, _ := e2e.Seal2(kv, s2.AAD, []byte("v2"), bytes.NewReader(mustHex(s2.Nonce)))
	d.Negative = []cxs1Neg{
		{Kind: "cxs1", What: "tag flipped", Secret: v0.Secret, Input: hx(tagFlip)},
		{Kind: "cxs1", What: "ciphertext flipped", Secret: v0.Secret, Input: hx(ctFlip)},
		{Kind: "cxs1", What: "wrong secret", Secret: hx(g.d.bytes(24)), Input: v0.Record},
		{Kind: "cxs1", What: "truncated", Secret: v0.Secret, Input: hx(rec[:67])},
		{Kind: "cxs1", What: "record of another locator (secret of vector 0)", Secret: d.Vectors[0].Secret, Input: v0.Record},
		{Kind: "seal1", What: "tampered seal1", KV: s1.KV, AAD: s1.AAD, Input: s1bad},
		{Kind: "seal1", What: "seal1 under another key name", KV: s1.KV, AAD: s1.AAD + "x", Input: s1.Value},
		{Kind: "seal1", What: "seal2 value opened as seal1", KV: s1.KV, AAD: s1.AAD, Input: s2.Value},
		{Kind: "seal2", What: "tampered seal2", KV: s2.KV, AAD: s2.AAD, Input: flipLastB64(s2.Value)},
		{Kind: "seal2", What: "seal2 under another k_v", KV: hx(e2e.SealV1Key(e2e.MK(g.seed()))), AAD: s2.AAD, Input: s2.Value},
		{Kind: "seal2", What: "seal2 under another key name (aad bound into the tag key, Security Review 2 #11)", KV: s2.KV, AAD: s2.AAD + "x", Input: s2.Value},
		{Kind: "nonce-reuse", What: "two seal1 values sharing a nonce are refused (err bad nonce reuse)", A: s1.Value, B: same1},
		{Kind: "nonce-reuse", What: "two seal2 values sharing a nonce", A: s2.Value, B: same2},
		{Kind: "not-sealed", What: "regex ^seal[12]:[A-Za-z0-9_-]+$ rejects a padded or spaced value", Input: s1.Value + "=="},
		{Kind: "not-sealed", What: "seal3 is not a format", Input: "seal3:AAAA"},
	}
	return d
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// flipLastB64 changes the last base64url character of a sealed value to another valid character.
func flipLastB64(v string) string {
	last := v[len(v)-1]
	if last == 'A' {
		return v[:len(v)-1] + "B"
	}
	return v[:len(v)-1] + "A"
}

func checkCxs1(data []byte) error {
	var d cxs1Doc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	x := &dec{}
	for _, v := range d.Vectors {
		secret := x.b(v.Secret)
		kEnc, kMac := e2e.Cxs1Keys(secret)
		if err := wantS("locator", e2e.LocatorHex(secret), v.Locator); err != nil {
			return err
		}
		for _, c := range []struct {
			what string
			got  []byte
			exp  string
		}{{"k_enc", kEnc, v.KEnc}, {"k_mac", kMac, v.KMac}, {"wtoken", e2e.WriteToken(kMac), v.WToken}} {
			if err := want(c.what, c.got, x.b(c.exp)); err != nil {
				return err
			}
		}
		rec, err := e2e.Cxs1Seal(secret, x.b(v.PT), bytes.NewReader(x.b(v.S)))
		if err != nil {
			return err
		}
		if err := want("record", rec, x.b(v.Record)); err != nil {
			return err
		}
		if pt, err := e2e.Cxs1Open(secret, rec); err != nil || !bytes.Equal(pt, x.b(v.PT)) {
			return errors.New("cxs1 open")
		}
		if err := wantS("text", e2e.EncodeCxs1(rec), v.Text); err != nil {
			return err
		}
		if dec, err := e2e.DecodeCxs1(v.Text); err != nil || !bytes.Equal(dec, rec) {
			return errors.New("text decode")
		}
	}
	for _, v := range d.Seal1 {
		kv := e2e.SealV1Key(x.b(v.MK))
		if err := want("k_v", kv, x.b(v.KV)); err != nil {
			return err
		}
		val, err := e2e.Seal1(kv, v.AAD, x.b(v.PT), bytes.NewReader(x.b(v.Nonce)))
		if err != nil {
			return err
		}
		if err := wantS("seal1", val, v.Value); err != nil {
			return err
		}
		if pt, err := e2e.Open1(kv, v.AAD, val); err != nil || !bytes.Equal(pt, x.b(v.PT)) {
			return errors.New("open1")
		}
		if n, err := e2e.SealedNonce(val); err != nil || !bytes.Equal(n, x.b(v.Nonce)) {
			return errors.New("seal1 nonce")
		}
	}
	for _, v := range d.Seal2 {
		kv := x.b(v.KV)
		if err := want("seal2 k_mac", e2e.Seal2MACKey(kv, v.AAD), x.b(v.KMac)); err != nil {
			return err
		}
		val, err := e2e.Seal2(kv, v.AAD, x.b(v.PT), bytes.NewReader(x.b(v.Nonce)))
		if err != nil {
			return err
		}
		if err := wantS("seal2", val, v.Value); err != nil {
			return err
		}
		if pt, err := e2e.Open2(kv, v.AAD, val); err != nil || !bytes.Equal(pt, x.b(v.PT)) {
			return errors.New("open2")
		}
		if _, err := e2e.Open2(kv, v.AAD+"x", val); err == nil {
			return errors.New("open2 accepted a value under another key name")
		}
		if n, err := e2e.SealedNonce(val); err != nil || !bytes.Equal(n, x.b(v.Nonce)) {
			return errors.New("seal2 nonce")
		}
	}
	for _, n := range d.Negative {
		var ok bool
		switch n.Kind {
		case "cxs1":
			_, err := e2e.Cxs1Open(x.b(n.Secret), x.b(n.Input))
			ok = err != nil
		case "seal1":
			_, err := e2e.Open1(x.b(n.KV), n.AAD, n.Input)
			ok = err != nil
		case "seal2":
			_, err := e2e.Open2(x.b(n.KV), n.AAD, n.Input)
			ok = err != nil
		case "nonce-reuse":
			ok = e2e.NonceReused(n.A, n.B)
		case "not-sealed":
			ok = !e2e.IsSealed(n.Input)
		default:
			return fmt.Errorf("unknown negative kind %q", n.Kind)
		}
		if !ok {
			return fmt.Errorf("negative %q accepted", n.What)
		}
	}
	return x.err
}

// ---- state.json

type stateVec struct {
	Seed    string `json:"seed"`
	KState  string `json:"k_state"`
	ID      string `json:"id"`
	Ver     uint64 `json:"ver"`
	S       string `json:"s"`
	Info    string `json:"info"` // "cx1/state" || 0x00 || id || u64(ver): HKDF info and AAD
	Key     string `json:"key"`
	PT      string `json:"pt"`
	Blob    string `json:"blob"`
	Receipt string `json:"receipt"`
}

type stateNeg struct {
	What   string `json:"what"`
	KState string `json:"k_state"`
	ID     string `json:"id"`
	Ver    uint64 `json:"ver"`
	Blob   string `json:"blob"`
}

type stateDoc struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Vectors     []stateVec `json:"vectors"`
	Negative    []stateNeg `json:"negative"`
}

func (g *gen) state() (*stateDoc, error) {
	d := &stateDoc{Name: "state", Description: "Sealed state blob (E2EE 7.2): 0x01 | s[32] | AES-256-GCM(k = HKDF(k_state, salt = s, info, 32), 0^12, aad = info, pt) with info = \"cx1/state\" || 0x00 || id || u64(ver); kind 6 receipt sha256(id || u64(ver) || sha256(blob))."}
	seed := g.seed()
	k := e2e.KState(seed)
	for i, pt := range [][]byte{[]byte(`{}`), []byte(`{"pins":{"` + bob + `":{"fp":"ab","seq":2,"cs":2,"leaf":7,"pol":1}},"cursor":99}`)} {
		s := g.d.bytes(32)
		ver := uint64(i + 1)
		blob, err := e2e.SealState(k, alice, ver, pt, bytes.NewReader(s))
		if err != nil {
			return nil, err
		}
		info := e2e.StateInfo(alice, ver)
		d.Vectors = append(d.Vectors, stateVec{Seed: hx(seed), KState: hx(k), ID: alice, Ver: ver, S: hx(s), Info: hx(info), Key: hx(e2e.HKDF(k, s, string(info), 32)),
			PT: hx(pt), Blob: hx(blob), Receipt: hx(e2e.StateReceipt(alice, ver, blob))})
	}
	v := d.Vectors[1]
	blob := mustHex(v.Blob)
	flip := append([]byte(nil), blob...)
	flip[40] ^= 1
	d.Negative = []stateNeg{
		{What: "blob of version 2 served as version 3 (rollback or replay across versions)", KState: v.KState, ID: v.ID, Ver: 3, Blob: v.Blob},
		{What: "blob served for another id", KState: v.KState, ID: bob, Ver: v.Ver, Blob: v.Blob},
		{What: "tampered ciphertext", KState: v.KState, ID: v.ID, Ver: v.Ver, Blob: hx(flip)},
		{What: "wrong version byte", KState: v.KState, ID: v.ID, Ver: v.Ver, Blob: "02" + v.Blob[2:]},
		{What: "another k_state", KState: hx(e2e.KState(g.seed())), ID: v.ID, Ver: v.Ver, Blob: v.Blob},
	}
	return d, nil
}

func checkState(data []byte) error {
	var d stateDoc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	x := &dec{}
	for _, v := range d.Vectors {
		k := e2e.KState(x.b(v.Seed))
		if err := want("k_state", k, x.b(v.KState)); err != nil {
			return err
		}
		info := e2e.StateInfo(v.ID, v.Ver)
		if err := want("info", info, x.b(v.Info)); err != nil {
			return err
		}
		if err := want("key", e2e.HKDF(k, x.b(v.S), string(info), 32), x.b(v.Key)); err != nil {
			return err
		}
		blob, err := e2e.SealState(k, v.ID, v.Ver, x.b(v.PT), bytes.NewReader(x.b(v.S)))
		if err != nil {
			return err
		}
		if err := want("blob", blob, x.b(v.Blob)); err != nil {
			return err
		}
		if pt, err := e2e.OpenState(k, v.ID, v.Ver, blob); err != nil || !bytes.Equal(pt, x.b(v.PT)) {
			return errors.New("open state")
		}
		if err := want("receipt", e2e.StateReceipt(v.ID, v.Ver, blob), x.b(v.Receipt)); err != nil {
			return err
		}
	}
	for _, n := range d.Negative {
		if _, err := e2e.OpenState(x.b(n.KState), n.ID, n.Ver, x.b(n.Blob)); err == nil {
			return fmt.Errorf("negative %q accepted", n.What)
		}
	}
	return x.err
}

// ---- att.json

type attVec struct {
	KAtt string `json:"k_att"`
	S    string `json:"s"`
	Key  string `json:"key"` // HKDF(k_att, salt = s, "cx1/att", 32)
	File string `json:"file"`
	Blob string `json:"blob"`
}

type snapVec struct {
	MsgRoot string `json:"msg_root"`
	S       string `json:"s"`
	KAtt    string `json:"k_att"` // HKDF(msg_root, salt = s, "cx1/snap", 32)
	File    string `json:"file"`
	Blob    string `json:"blob"`
}

type attDoc struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Vectors     []attVec  `json:"vectors"`
	Snapshots   []snapVec `json:"snapshots"`
}

func (g *gen) att() (*attDoc, error) {
	d := &attDoc{Name: "att", Description: "Sealed attachments and snapshot blobs (E2EE 7.3): s[32] | AES-256-GCM(HKDF(k_att, salt = s, \"cx1/att\", 32), 0^12, aad = \"cx1/att\", file); snapshot k_att = HKDF(msg_root, salt = s, \"cx1/snap\", 32)."}
	for _, n := range []int{0, 1000} {
		k, s, file := g.d.bytes(32), g.d.bytes(32), g.d.bytes(n)
		blob, err := e2e.SealAttachmentWithSalt(k, s, file)
		if err != nil {
			return nil, err
		}
		d.Vectors = append(d.Vectors, attVec{KAtt: hx(k), S: hx(s), Key: hx(e2e.HKDF(k, s, e2e.LabelAtt, 32)), File: hx(file), Blob: hx(blob)})
	}
	root, s, file := g.d.bytes(32), g.d.bytes(32), []byte(`{"ops":200,"state":{}}`)
	kAtt := e2e.SnapshotKey(root, s)
	blob, err := e2e.SealAttachmentWithSalt(kAtt, s, file)
	if err != nil {
		return nil, err
	}
	d.Snapshots = []snapVec{{MsgRoot: hx(root), S: hx(s), KAtt: hx(kAtt), File: hx(file), Blob: hx(blob)}}
	return d, nil
}

func checkAtt(data []byte) error {
	var d attDoc
	if err := unmarshal(data, &d); err != nil {
		return err
	}
	x := &dec{}
	for _, v := range d.Vectors {
		k, s := x.b(v.KAtt), x.b(v.S)
		if err := want("key", e2e.HKDF(k, s, e2e.LabelAtt, 32), x.b(v.Key)); err != nil {
			return err
		}
		blob, err := e2e.SealAttachmentWithSalt(k, s, x.b(v.File))
		if err != nil {
			return err
		}
		if err := want("blob", blob, x.b(v.Blob)); err != nil {
			return err
		}
		if f, err := e2e.OpenAttachment(k, blob); err != nil || !bytes.Equal(f, x.b(v.File)) {
			return errors.New("open attachment")
		}
		blob[len(blob)-1] ^= 1
		if _, err := e2e.OpenAttachment(k, blob); err == nil {
			return errors.New("tampered attachment accepted")
		}
	}
	for _, v := range d.Snapshots {
		root, s := x.b(v.MsgRoot), x.b(v.S)
		if err := want("snapshot k_att", e2e.SnapshotKey(root, s), x.b(v.KAtt)); err != nil {
			return err
		}
		if f, err := e2e.OpenSnapshot(root, x.b(v.Blob)); err != nil || !bytes.Equal(f, x.b(v.File)) {
			return errors.New("open snapshot")
		}
	}
	return x.err
}
