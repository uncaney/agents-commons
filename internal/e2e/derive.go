package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
)

// Derivations from the 32-byte client seed (E2EE 2.4): nothing is stored client-side but the seed.

const (
	SeedSize     = 32
	SeedPrefix   = "cxs_"
	EpochSeconds = 604800 // one week; e = floor(unix / 604800)
	EpochsAhead  = 5      // a bundle lists ek for e0 .. e0+4
)

var ErrSeed = errors.New("e2e: bad seed")

// NewSeed draws a seed from crypto/rand.
func NewSeed() []byte {
	s := make([]byte, SeedSize)
	if _, err := rand.Read(s); err != nil {
		panic(err)
	}
	return s
}

// FormatSeed renders the seed as printed once by `cx join`: cxs_<43 base64url chars>.
func FormatSeed(seed []byte) string {
	return SeedPrefix + base64.RawURLEncoding.EncodeToString(seed)
}

// ParseSeed accepts the cxs_ form or the bare 43-char base64url form.
func ParseSeed(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), SeedPrefix)
	if len(s) != 43 {
		return nil, ErrSeed
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != SeedSize {
		return nil, ErrSeed
	}
	return b, nil
}

func checkSeed(seed []byte) {
	if len(seed) != SeedSize {
		panic("e2e: seed must be 32 bytes")
	}
}

// IK is the identity signing key (bundles, group messages).
func IK(seed []byte) ed25519.PrivateKey {
	checkSeed(seed)
	return ed25519.NewKeyFromSeed(HKDF(seed, nil, LabelIK, 32))
}

// RK is the request signing key (requests and sends; never signs content).
func RK(seed []byte) ed25519.PrivateKey {
	checkSeed(seed)
	return ed25519.NewKeyFromSeed(HKDF(seed, nil, LabelRK, 32))
}

// AK is the static X25519 auth key for the pairwise MAC.
func AK(seed []byte) *ecdh.PrivateKey {
	checkSeed(seed)
	k, err := ecdh.X25519().NewPrivateKey(HKDF(seed, nil, LabelAK, 32))
	if err != nil {
		panic(err)
	}
	return k
}

// LK is the long-term KEM key of a suite (last resort, only under lk_ok).
func LK(seed []byte, cs Suite) (hpke.PrivateKey, error) {
	checkSeed(seed)
	if !cs.Valid() {
		return nil, ErrSuite
	}
	return cs.DeriveKeyPair(HKDF(seed, nil, LabelLK+cs.String(), 32))
}

// EKInfo is the HKDF info of an epoch prekey: "cx1/ek/" + cs + "/" + u32(epoch) (raw big-endian bytes).
func EKInfo(cs Suite, epoch uint32) string {
	return LabelEK + cs.String() + "/" + string(U32(epoch))
}

// EK is the epoch prekey; share is the mode D+ epoch share used as salt (nil = default salt, mode D).
func EK(seed []byte, cs Suite, epoch uint32, share []byte) (hpke.PrivateKey, error) {
	checkSeed(seed)
	if !cs.Valid() {
		return nil, ErrSuite
	}
	if share != nil && len(share) != 32 {
		return nil, errors.New("e2e: epoch share must be 32 bytes")
	}
	return cs.DeriveKeyPair(HKDF(seed, share, EKInfo(cs, epoch), 32))
}

// KState is the sealed state blob key (7.2).
func KState(seed []byte) []byte {
	checkSeed(seed)
	return HKDF(seed, nil, LabelState, 32)
}

// Sub derives the child seed handed to a sub-agent with its token; a child cannot climb back.
func Sub(seed []byte, subid string) []byte {
	checkSeed(seed)
	return HKDF(seed, nil, LabelSub+subid, 32)
}

// PQID is the optional ML-DSA-65 identity attestation key.
func PQID(seed []byte) *mldsa.PrivateKey {
	checkSeed(seed)
	k, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), HKDF(seed, nil, LabelMLDSA, 32))
	if err != nil {
		panic(err)
	}
	return k
}

// MK is the sealed-memory key of SPEC-v2 26.4 (checkpoints, KV, notes).
func MK(seed []byte) []byte {
	checkSeed(seed)
	return HKDF(seed, nil, LabelMK, 32)
}

// WrapMK seals mk under HKDF(recovery_code, "cx-mk-recovery") as nonce12 || AES-256-GCM(mk); the result is
// what `PUT /v1/me/mk {"wrapped"}` stores. rnd nil means crypto/rand.
func WrapMK(mk, recoveryCode []byte, rnd io.Reader) ([]byte, error) {
	if len(mk) != 32 || len(recoveryCode) == 0 {
		return nil, errors.New("e2e: wrap mk: bad input")
	}
	g, err := gcm(HKDF(recoveryCode, nil, LabelMKRec, 32))
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(reader(rnd), nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, mk, nil), nil
}

// UnwrapMK reverses WrapMK.
func UnwrapMK(wrapped, recoveryCode []byte) ([]byte, error) {
	if len(wrapped) != 12+32+16 {
		return nil, errors.New("e2e: unwrap mk: bad length")
	}
	g, err := gcm(HKDF(recoveryCode, nil, LabelMKRec, 32))
	if err != nil {
		return nil, err
	}
	return g.Open(nil, wrapped[:12], wrapped[12:], nil)
}

// Epoch is the week number of a unix time; EpochStart its first second.
func Epoch(unix int64) uint32 {
	if unix < 0 {
		return 0
	}
	return uint32(unix / EpochSeconds)
}

func EpochStart(e uint32) int64 { return int64(e) * EpochSeconds }

// Fingerprint is sha256("cx1/fp" || 0x00 || ik) of an Ed25519 identity public key.
func Fingerprint(ik []byte) []byte { return Sum(Labeled(LabelFP, ik)) }

// FPDigits renders a fingerprint as 12 groups of 5 digits (Signal safety-number style): group i is the
// big-endian 40-bit integer at bytes 5i..5i+4 of fp || sha256(fp), modulo 100000, zero-padded.
func FPDigits(fp []byte) string {
	ext := cat(fp, Sum(fp))
	var b strings.Builder
	for i := 0; i < 12; i++ {
		var v uint64
		for _, c := range ext[5*i : 5*i+5] {
			v = v<<8 | uint64(c)
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		s := strconv.FormatUint(v%100000, 10)
		b.WriteString(strings.Repeat("0", 5-len(s)) + s)
	}
	return b.String()
}

// FP16 is the 16-hex-char short form shown in `e2ee ok from=<fp16>` lines.
func FP16(fp []byte) string { return hex.EncodeToString(fp)[:16] }

func gcm(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func reader(r io.Reader) io.Reader {
	if r == nil {
		return rand.Reader
	}
	return r
}

// zeroNonce is the fixed GCM nonce of the one-key-one-message rule (E2EE 2.5).
var zeroNonce = make([]byte, 12)
