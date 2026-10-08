package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// cxs1: the symmetric lane for agents that can only hash (E2EE 7.4), and the seal1:/seal2: sealed memory
// values of SPEC-v2 26.4.
//
//	locator        = SHAKE256("cx1/loc" || 0x00 || secret, 16)
//	k_enc || k_mac = SHAKE256("cx1/key" || 0x00 || secret, 64)
//	wtoken         = HMAC-SHA256(k_mac, "cx1/d-write")
//	s = 32 random; keystream = SHAKE256(k_enc || s, len(pt)); ct = pt xor keystream
//	tag            = HMAC-SHA256(k_mac, "cxs1" || 0x00 || s || locator || ct)
//	record         = "cxs1" || s || ct || tag            (encrypt-then-MAC; the tag is verified before any use of ct)
//
// Non-goals: no sender authentication beyond the shared secret, no forward secrecy, no agility beyond
// the cxs1 tag. SHAKE256 keyed with k_enc and a fresh per-record salt is the PRF stream; HMAC over
// (salt, locator, ciphertext) gives INT-CTXT, and binding the locator stops a record from being moved
// between drops.

const (
	Cxs1Magic    = LabelCXS1
	LocatorSize  = 16
	Cxs1Overhead = 4 + 32 + 32
	Cxs1Cap      = 1 << 20 // parser bound; drop caps are the server's
	SealedCap    = 1 << 16
	Seal1Nonce   = 12
	Seal2Nonce   = 16
)

var (
	ErrCxs1   = errors.New("e2e: bad cxs1 record")
	ErrSealed = errors.New("e2e: bad sealed value")
)

// Locator is what the CDN and the host see in the path; never the secret.
func Locator(secret []byte) []byte { return sha3.SumSHAKE256(Labeled(LabelLoc, secret), LocatorSize) }

func LocatorHex(secret []byte) string { return hex.EncodeToString(Locator(secret)) }

// Cxs1Keys splits SHAKE256("cx1/key" || secret, 64) into k_enc and k_mac.
func Cxs1Keys(secret []byte) (kEnc, kMac []byte) {
	k := sha3.SumSHAKE256(Labeled(LabelKey, secret), 64)
	return k[:32], k[32:]
}

// WriteToken is the append/delete capability sent only in X-Drop-Token; the server stores sha256 of it.
func WriteToken(kMac []byte) []byte {
	m := hmac.New(sha256.New, kMac)
	m.Write([]byte(LabelDWrite))
	return m.Sum(nil)
}

func cxs1Tag(kMac, s, locator, ct []byte) []byte {
	m := hmac.New(sha256.New, kMac)
	m.Write(Labeled(LabelCXS1, s, locator, ct))
	return m.Sum(nil)
}

func cxs1Stream(kEnc, s []byte, n int) []byte { return sha3.SumSHAKE256(cat(kEnc, s), n) }

// Cxs1Seal produces a record; rnd nil means crypto/rand.
func Cxs1Seal(secret, pt []byte, rnd io.Reader) ([]byte, error) {
	if len(secret) == 0 || len(pt)+Cxs1Overhead > Cxs1Cap {
		return nil, ErrCxs1
	}
	s := make([]byte, 32)
	if _, err := io.ReadFull(reader(rnd), s); err != nil {
		return nil, err
	}
	kEnc, kMac := Cxs1Keys(secret)
	ct := make([]byte, len(pt))
	ks := cxs1Stream(kEnc, s, len(pt))
	for i := range pt {
		ct[i] = pt[i] ^ ks[i]
	}
	return cat([]byte(Cxs1Magic), s, ct, cxs1Tag(kMac, s, Locator(secret), ct)), nil
}

// Cxs1Open verifies the tag in constant time, then decrypts.
func Cxs1Open(secret, record []byte) ([]byte, error) {
	if len(secret) == 0 || len(record) < Cxs1Overhead || len(record) > Cxs1Cap || string(record[:4]) != Cxs1Magic {
		return nil, ErrCxs1
	}
	s, ct, tag := record[4:36], record[36:len(record)-32], record[len(record)-32:]
	kEnc, kMac := Cxs1Keys(secret)
	if !hmac.Equal(cxs1Tag(kMac, s, Locator(secret), ct), tag) {
		return nil, fmt.Errorf("%w: tag", ErrCxs1)
	}
	pt := make([]byte, len(ct))
	ks := cxs1Stream(kEnc, s, len(ct))
	for i := range ct {
		pt[i] = ct[i] ^ ks[i]
	}
	return pt, nil
}

// Cxs1OpenAll opens appended records independently: bad ones are reported by index and skipped.
func Cxs1OpenAll(secret []byte, records [][]byte) (pts [][]byte, bad []int) {
	for i, r := range records {
		pt, err := Cxs1Open(secret, r)
		if err != nil {
			bad = append(bad, i)
			continue
		}
		pts = append(pts, pt)
	}
	return pts, bad
}

// EncodeCxs1 and DecodeCxs1 are the text form `cxs1:<base64url record>` accepted as a drop body.
func EncodeCxs1(record []byte) string { return Cxs1Prefix + b64(record) }

func DecodeCxs1(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, Cxs1Prefix) || len(s) > Cxs1Cap*4/3+8 {
		return nil, ErrCxs1
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s[len(Cxs1Prefix):])
	if err != nil || len(b) < Cxs1Overhead {
		return nil, ErrCxs1
	}
	return b, nil
}

// ---- sealed memory values (SPEC-v2 26.4)
//
//	k_v  = HKDF(mk, "cx-seal-v1")
//	seal1:<base64url(nonce12 || AES-256-GCM(k_v, plaintext, aad = ns||k | cp name | note name))>
//	seal2:<base64url(nonce16 || ct || tag32)>  ct = pt XOR blocks HMAC-SHA256(k_v, nonce || u32 counter from 0),
//	                                            tag = HMAC-SHA256(HKDF(k_v, "mac"||aad), nonce || ct)
//
// seal2 is the hashlib-only recipe of /seal.py. Its tag key is bound to the value's aad (ns|k, the same
// binding seal1 carries in its GCM aad) so the server cannot move a sealed value between keys (Security
// Review 2 #11). The server refuses a value whose nonce equals the previous version's nonce for the same
// key (NonceReused).

// SealV1Key derives k_v from the sealed-memory key mk.
func SealV1Key(mk []byte) []byte { return HKDF(mk, nil, LabelSealV1, 32) }

// Seal2MACKey derives the seal2 tag key from k_v, bound to the value's aad (ns|k) so a value sealed
// for one key cannot be reattributed to another (Security Review 2 #11). aad "" is the unbound base.
func Seal2MACKey(kv []byte, aad string) []byte { return HKDF(kv, nil, LabelSealMAC+aad, 32) }

func Seal1(kv []byte, aad string, pt []byte, rnd io.Reader) (string, error) {
	if len(kv) != 32 || len(pt)+Seal1Nonce+16 > SealedCap {
		return "", ErrSealed
	}
	g, err := gcm(kv)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, Seal1Nonce)
	if _, err := io.ReadFull(reader(rnd), nonce); err != nil {
		return "", err
	}
	return Seal1Prefix + b64(g.Seal(nonce, nonce, pt, []byte(aad))), nil
}

func Open1(kv []byte, aad string, value string) ([]byte, error) {
	kind, b, err := decodeSealed(value)
	if err != nil || kind != 1 || len(b) < Seal1Nonce+16 || len(kv) != 32 {
		return nil, ErrSealed
	}
	g, err := gcm(kv)
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, b[:Seal1Nonce], b[Seal1Nonce:], []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("%w: open", ErrSealed)
	}
	return pt, nil
}

func seal2Stream(kv, nonce []byte, n int) []byte {
	out := make([]byte, 0, n+32)
	for i := uint32(0); len(out) < n; i++ {
		m := hmac.New(sha256.New, kv)
		m.Write(nonce)
		m.Write(U32(i))
		out = m.Sum(out)
	}
	return out[:n]
}

func seal2Tag(kMac, nonce, ct []byte) []byte {
	m := hmac.New(sha256.New, kMac)
	m.Write(nonce)
	m.Write(ct)
	return m.Sum(nil)
}

func Seal2(kv []byte, aad string, pt []byte, rnd io.Reader) (string, error) {
	if len(kv) != 32 || len(pt)+Seal2Nonce+32 > SealedCap {
		return "", ErrSealed
	}
	nonce := make([]byte, Seal2Nonce)
	if _, err := io.ReadFull(reader(rnd), nonce); err != nil {
		return "", err
	}
	ks := seal2Stream(kv, nonce, len(pt))
	ct := make([]byte, len(pt))
	for i := range pt {
		ct[i] = pt[i] ^ ks[i]
	}
	return Seal2Prefix + b64(cat(nonce, ct, seal2Tag(Seal2MACKey(kv, aad), nonce, ct))), nil
}

func Open2(kv []byte, aad string, value string) ([]byte, error) {
	kind, b, err := decodeSealed(value)
	if err != nil || kind != 2 || len(b) < Seal2Nonce+32 || len(kv) != 32 {
		return nil, ErrSealed
	}
	nonce, ct, tag := b[:Seal2Nonce], b[Seal2Nonce:len(b)-32], b[len(b)-32:]
	if !hmac.Equal(seal2Tag(Seal2MACKey(kv, aad), nonce, ct), tag) {
		return nil, fmt.Errorf("%w: tag", ErrSealed)
	}
	ks := seal2Stream(kv, nonce, len(ct))
	pt := make([]byte, len(ct))
	for i := range ct {
		pt[i] = ct[i] ^ ks[i]
	}
	return pt, nil
}

// IsSealed matches ^seal[12]:[A-Za-z0-9_-]+$ within the cap.
func IsSealed(v string) bool {
	_, _, err := decodeSealed(v)
	return err == nil
}

func decodeSealed(v string) (kind int, b []byte, err error) {
	switch {
	case strings.HasPrefix(v, Seal1Prefix):
		kind = 1
	case strings.HasPrefix(v, Seal2Prefix):
		kind = 2
	default:
		return 0, nil, ErrSealed
	}
	body := v[len(Seal1Prefix):]
	if body == "" || len(body) > SealedCap*4/3+4 {
		return 0, nil, ErrSealed
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return 0, nil, ErrSealed
		}
	}
	b, err = base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil {
		return 0, nil, ErrSealed
	}
	return kind, b, nil
}

// SealedNonce extracts the nonce of a seal1:/seal2: value (12 or 16 bytes).
func SealedNonce(v string) ([]byte, error) {
	kind, b, err := decodeSealed(v)
	if err != nil {
		return nil, err
	}
	n := Seal1Nonce
	if kind == 2 {
		n = Seal2Nonce
	}
	if len(b) < n {
		return nil, ErrSealed
	}
	return b[:n], nil
}

// NonceReused reports whether two sealed values share a nonce (`err bad nonce reuse`).
func NonceReused(prev, cur string) bool {
	a, err1 := SealedNonce(prev)
	b, err2 := SealedNonce(cur)
	return err1 == nil && err2 == nil && hmac.Equal(a, b)
}
