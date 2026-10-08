package e2e

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mldsa"
	"errors"
	"fmt"
)

// Key bundle (E2EE 3.1): canonical bytes signed by ik.
//
//	"cxkb2"(5) | id(7) | seq u32 | iat u32 | exp u32 | flags u8 | mail_policy u8 | min_cs u8 | min_pol u16
//	| ik 32 | rk 32 | ak 32 | lk1 32 | [lk2 1216 if flags.cs2]
//	| e0 u32 | n_ek u8 (1..5) | n_ek x ( ek1 32 | [ek2 1216] )
//	| rev_commit 32 | prev_hash 32 | [pq_id 1952 if flags.pq]
//	sig_ik 64 | sig_prev 64 (zero unless ik changed) | [sig_pq 3309 if flags.pq]

const (
	BundleMagic  = "cxkb2"
	IDLen        = 7
	BundleCap    = 16384
	BundleMaxTTL = 35 * 86400 // exp <= iat + 35 d
	IATSkew      = 300        // server rejects iat > now + 5 min

	FlagCS2    = 1 << 0 // lk2 and ek2 present
	FlagModeR  = 1 << 1 // random prekeys on disk
	FlagShares = 1 << 2 // epoch shares in use (mode D+)
	FlagPQ     = 1 << 3 // pq_id and sig_pq present
	FlagSub    = 1 << 4 // sub-identity
	FlagLKOK   = 1 << 5 // owner accepts last-resort sealing to lk

	PolicyPlain = 0
	PolicyBoth  = 1
	PolicyE2EE  = 2

	PQIDSize  = mldsa.MLDSA65PublicKeySize
	PQSigSize = mldsa.MLDSA65SignatureSize
)

var (
	ErrBundle    = errors.New("e2e: bad bundle")
	ErrBundleSig = errors.New("e2e: bundle signature invalid")
)

type Bundle struct {
	ID                        string
	Seq, IAT, Exp             uint32
	Flags, MailPolicy, MinCS  uint8
	MinPol                    uint16
	IK, RK, AK, LK1, LK2      []byte
	E0                        uint32
	EK1, EK2                  [][]byte // one entry per listed epoch (EK2 only with FlagCS2)
	RevCommit, PrevHash, PQID []byte
	SigIK, SigPrev, SigPQ     []byte
}

// ValidID reports whether id is a SPEC id: a lowercase prefix letter and six base32 chars.
func ValidID(id string) bool {
	if len(id) != IDLen || id[0] < 'a' || id[0] > 'z' {
		return false
	}
	for _, c := range id[1:] {
		if !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

func (b *Bundle) cs2() bool { return b.Flags&FlagCS2 != 0 }
func (b *Bundle) pq() bool  { return b.Flags&FlagPQ != 0 }

// HasCS2 reports whether the bundle advertises suite 2; MaxCS is the highest suite it lists.
func (b *Bundle) HasCS2() bool { return b.cs2() }

func (b *Bundle) MaxCS() Suite {
	if b.cs2() {
		return CS2
	}
	return CS1
}

// NEK is the number of listed epochs; HasEpoch and EK look a prekey up.
func (b *Bundle) NEK() int { return len(b.EK1) }

func (b *Bundle) HasEpoch(e uint32) bool {
	return e >= b.E0 && e < b.E0+uint32(len(b.EK1))
}

// EK returns the serialized prekey for (cs, epoch).
func (b *Bundle) EK(cs Suite, e uint32) ([]byte, bool) {
	if !b.HasEpoch(e) {
		return nil, false
	}
	i := int(e - b.E0)
	switch cs {
	case CS1:
		return b.EK1[i], true
	case CS2:
		if b.cs2() {
			return b.EK2[i], true
		}
	}
	return nil, false
}

// LK returns the long-term key for a suite.
func (b *Bundle) LK(cs Suite) ([]byte, bool) {
	switch cs {
	case CS1:
		return b.LK1, true
	case CS2:
		if b.cs2() {
			return b.LK2, true
		}
	}
	return nil, false
}

func (b *Bundle) Fingerprint() []byte { return Fingerprint(b.IK) }

// Rotated reports whether sig_prev is non-zero (the ik changed; verify it with VerifyRotation).
func (b *Bundle) Rotated() bool {
	var z [64]byte
	return len(b.SigPrev) == 64 && !hmac.Equal(b.SigPrev, z[:])
}

func (b *Bundle) check() error {
	n := len(b.EK1)
	switch {
	case !ValidID(b.ID):
		return fmt.Errorf("%w: id", ErrBundle)
	case b.Seq == 0:
		return fmt.Errorf("%w: seq 0", ErrBundle)
	case b.Exp <= b.IAT || uint64(b.Exp) > uint64(b.IAT)+BundleMaxTTL:
		return fmt.Errorf("%w: exp", ErrBundle)
	case b.Flags&^(FlagCS2|FlagModeR|FlagShares|FlagPQ|FlagSub|FlagLKOK) != 0:
		return fmt.Errorf("%w: flags", ErrBundle)
	case b.MailPolicy > PolicyE2EE:
		return fmt.Errorf("%w: mail_policy", ErrBundle)
	case !Suite(b.MinCS).Valid() || (b.MinCS == uint8(CS2) && !b.cs2()):
		return fmt.Errorf("%w: min_cs", ErrBundle)
	case len(b.IK) != 32 || len(b.RK) != 32 || len(b.AK) != 32 || len(b.LK1) != 32:
		return fmt.Errorf("%w: key lengths", ErrBundle)
	case b.cs2() != (len(b.LK2) == CS2.PKSize()):
		return fmt.Errorf("%w: lk2", ErrBundle)
	case n < 1 || n > EpochsAhead || uint64(b.E0)+uint64(n) > 1<<32:
		return fmt.Errorf("%w: n_ek", ErrBundle)
	case b.cs2() && len(b.EK2) != n, !b.cs2() && len(b.EK2) != 0:
		return fmt.Errorf("%w: ek2", ErrBundle)
	case len(b.RevCommit) != 32 || len(b.PrevHash) != 32:
		return fmt.Errorf("%w: commitments", ErrBundle)
	case b.pq() != (len(b.PQID) == PQIDSize):
		return fmt.Errorf("%w: pq_id", ErrBundle)
	}
	for i := 0; i < n; i++ {
		if len(b.EK1[i]) != 32 || (b.cs2() && len(b.EK2[i]) != CS2.PKSize()) {
			return fmt.Errorf("%w: ek %d", ErrBundle, i)
		}
	}
	return nil
}

// Canonical returns the canonical bytes (without signatures).
func (b *Bundle) Canonical() ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	out := make([]byte, 0, b.canonicalSize())
	out = append(out, BundleMagic...)
	out = append(out, b.ID...)
	out = append(out, U32(b.Seq)...)
	out = append(out, U32(b.IAT)...)
	out = append(out, U32(b.Exp)...)
	out = append(out, b.Flags, b.MailPolicy, b.MinCS)
	out = append(out, U16(b.MinPol)...)
	out = append(out, b.IK...)
	out = append(out, b.RK...)
	out = append(out, b.AK...)
	out = append(out, b.LK1...)
	if b.cs2() {
		out = append(out, b.LK2...)
	}
	out = append(out, U32(b.E0)...)
	out = append(out, byte(len(b.EK1)))
	for i := range b.EK1 {
		out = append(out, b.EK1[i]...)
		if b.cs2() {
			out = append(out, b.EK2[i]...)
		}
	}
	out = append(out, b.RevCommit...)
	out = append(out, b.PrevHash...)
	if b.pq() {
		out = append(out, b.PQID...)
	}
	return out, nil
}

func (b *Bundle) canonicalSize() int {
	n := 5 + IDLen + 4 + 4 + 4 + 3 + 2 + 4*32 + 4 + 1 + 32 + 32
	if b.cs2() {
		n += CS2.PKSize()
	}
	n += len(b.EK1) * 32
	if b.cs2() {
		n += len(b.EK1) * CS2.PKSize()
	}
	if b.pq() {
		n += PQIDSize
	}
	return n
}

// Sign produces canonical || sig_ik || sig_prev || [sig_pq] and records the signatures in b. ikPrev is the
// previous identity key when ik changed (nil otherwise); pq must be given when FlagPQ is set.
func (b *Bundle) Sign(ik, ikPrev ed25519.PrivateKey, pq *mldsa.PrivateKey) ([]byte, error) {
	can, err := b.Canonical()
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(ik.Public().(ed25519.PublicKey), b.IK) {
		return nil, fmt.Errorf("%w: ik does not match the signing key", ErrBundle)
	}
	b.SigIK = ed25519.Sign(ik, Labeled(LabelBundle, can))
	b.SigPrev = make([]byte, 64)
	if ikPrev != nil {
		b.SigPrev = ed25519.Sign(ikPrev, Labeled(LabelRotate, can))
	}
	b.SigPQ = nil
	if b.pq() {
		if pq == nil || !hmac.Equal(pq.PublicKey().Bytes(), b.PQID) {
			return nil, fmt.Errorf("%w: pq key does not match pq_id", ErrBundle)
		}
		if b.SigPQ, err = pq.SignDeterministic(Labeled(LabelBundle, can), &mldsa.Options{}); err != nil {
			return nil, err
		}
	}
	return cat(can, b.SigIK, b.SigPrev, b.SigPQ), nil
}

// ParseBundle decodes canonical || sigs strictly: every length must match the flags and nothing may
// trail. It does not verify signatures (Verify, VerifyRotation).
func ParseBundle(raw []byte) (*Bundle, error) {
	if len(raw) > BundleCap || len(raw) < 5+IDLen+17 {
		return nil, fmt.Errorf("%w: length", ErrBundle)
	}
	if string(raw[:5]) != BundleMagic {
		return nil, fmt.Errorf("%w: magic", ErrBundle)
	}
	b := &Bundle{}
	r := reader8{b: raw, i: 5}
	b.ID = string(r.take(IDLen))
	b.Seq, b.IAT, b.Exp = r.u32(), r.u32(), r.u32()
	b.Flags, b.MailPolicy, b.MinCS = r.u8(), r.u8(), r.u8()
	b.MinPol = r.u16()
	if b.Flags&^(FlagCS2|FlagModeR|FlagShares|FlagPQ|FlagSub|FlagLKOK) != 0 {
		return nil, fmt.Errorf("%w: flags", ErrBundle)
	}
	b.IK, b.RK, b.AK, b.LK1 = r.take(32), r.take(32), r.take(32), r.take(32)
	if b.cs2() {
		b.LK2 = r.take(CS2.PKSize())
	}
	b.E0 = r.u32()
	n := int(r.u8())
	if r.err || n < 1 || n > EpochsAhead {
		return nil, fmt.Errorf("%w: n_ek", ErrBundle)
	}
	for i := 0; i < n; i++ {
		b.EK1 = append(b.EK1, r.take(32))
		if b.cs2() {
			b.EK2 = append(b.EK2, r.take(CS2.PKSize()))
		}
	}
	b.RevCommit, b.PrevHash = r.take(32), r.take(32)
	if b.pq() {
		b.PQID = r.take(PQIDSize)
	}
	b.SigIK, b.SigPrev = r.take(64), r.take(64)
	if b.pq() {
		b.SigPQ = r.take(PQSigSize)
	}
	if r.err || r.i != len(raw) {
		return nil, fmt.Errorf("%w: length", ErrBundle)
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	return b, nil
}

// Verify checks sig_ik under the bundle's own ik and sig_pq when flags.pq (DVR step 1, shape part).
func (b *Bundle) Verify() error {
	can, err := b.Canonical()
	if err != nil {
		return err
	}
	if len(b.SigIK) != 64 || !ed25519.Verify(ed25519.PublicKey(b.IK), Labeled(LabelBundle, can), b.SigIK) {
		return ErrBundleSig
	}
	if b.Seq == 1 && b.Rotated() {
		return fmt.Errorf("%w: seq 1 carries sig_prev", ErrBundleSig)
	}
	if b.pq() {
		pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), b.PQID)
		if err != nil || len(b.SigPQ) != PQSigSize || mldsa.Verify(pk, Labeled(LabelBundle, can), b.SigPQ, nil) != nil {
			return fmt.Errorf("%w (pq)", ErrBundleSig)
		}
	}
	return nil
}

// VerifyRotation checks sig_prev under the previous identity key (pending ik rotation, E2EE 3.7).
func (b *Bundle) VerifyRotation(prevIK []byte) error {
	can, err := b.Canonical()
	if err != nil {
		return err
	}
	if len(prevIK) != 32 || len(b.SigPrev) != 64 || !ed25519.Verify(ed25519.PublicKey(prevIK), Labeled(LabelRotate, can), b.SigPrev) {
		return fmt.Errorf("%w (prev)", ErrBundleSig)
	}
	return nil
}

// CanonicalHash is sha256(canonical): the next bundle's prev_hash and the log item hash of a kind 1 leaf.
func (b *Bundle) CanonicalHash() ([]byte, error) {
	can, err := b.Canonical()
	if err != nil {
		return nil, err
	}
	return Sum(can), nil
}

// BundleHash is sha256 over the raw bytes as sent (the `bundle=` field of the signed register reply).
func BundleHash(raw []byte) []byte { return Sum(raw) }

// BundleParams drives NewBundle; keys are derived from the seed (mode D; Shares gives mode D+ salts).
type BundleParams struct {
	ID                       string
	Seq, IAT, Exp            uint32
	Flags, MailPolicy, MinCS uint8
	MinPol                   uint16
	E0                       uint32
	NEK                      int
	RevCommit, PrevHash      []byte
	Shares                   [][]byte // per listed epoch, nil for mode D
}

// NewBundle derives every public key from the seed and returns an unsigned bundle.
func NewBundle(seed []byte, p BundleParams) (*Bundle, error) {
	b := &Bundle{ID: p.ID, Seq: p.Seq, IAT: p.IAT, Exp: p.Exp, Flags: p.Flags, MailPolicy: p.MailPolicy,
		MinCS: p.MinCS, MinPol: p.MinPol, E0: p.E0, RevCommit: p.RevCommit, PrevHash: p.PrevHash}
	if b.MinCS == 0 {
		b.MinCS = uint8(CS1)
	}
	if p.NEK < 1 || p.NEK > EpochsAhead || (p.Shares != nil && len(p.Shares) != p.NEK) {
		return nil, fmt.Errorf("%w: n_ek", ErrBundle)
	}
	b.IK = IK(seed).Public().(ed25519.PublicKey)
	b.RK = RK(seed).Public().(ed25519.PublicKey)
	b.AK = AK(seed).PublicKey().Bytes()
	lk1, err := LK(seed, CS1)
	if err != nil {
		return nil, err
	}
	b.LK1 = lk1.PublicKey().Bytes()
	if b.cs2() {
		lk2, err := LK(seed, CS2)
		if err != nil {
			return nil, err
		}
		b.LK2 = lk2.PublicKey().Bytes()
	}
	for i := 0; i < p.NEK; i++ {
		var share []byte
		if p.Shares != nil {
			share = p.Shares[i]
		}
		e := p.E0 + uint32(i)
		k1, err := EK(seed, CS1, e, share)
		if err != nil {
			return nil, err
		}
		b.EK1 = append(b.EK1, k1.PublicKey().Bytes())
		if b.cs2() {
			k2, err := EK(seed, CS2, e, share)
			if err != nil {
				return nil, err
			}
			b.EK2 = append(b.EK2, k2.PublicKey().Bytes())
		}
	}
	if b.pq() {
		b.PQID = PQID(seed).PublicKey().Bytes()
	}
	if b.PrevHash == nil {
		b.PrevHash = make([]byte, 32)
	}
	if err := b.check(); err != nil {
		return nil, err
	}
	return b, nil
}

// reader8 is a bounds-checked cursor over a byte slice; err latches on the first short read.
type reader8 struct {
	b   []byte
	i   int
	err bool
}

func (r *reader8) take(n int) []byte {
	if r.err || n < 0 || r.i+n > len(r.b) {
		r.err = true
		return nil
	}
	out := r.b[r.i : r.i+n : r.i+n]
	r.i += n
	return out
}

func (r *reader8) u8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader8) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

func (r *reader8) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func (r *reader8) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return uint64(r.beU32(b[:4]))<<32 | uint64(r.beU32(b[4:]))
}

func (r *reader8) beU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
