// Package pow implements the stateless hashcash challenges used for registration
// and anonymous writes (SPEC-v2 3.1, 27.2).
//
// v2 challenge = base64url(rand16 || exp_u32be || bits_u8 || purpose_u8 || hmac_sha256(secret, first 22 bytes)[:8]).
// v1 challenge = base64url(rand16 || exp_u32be || hmac_sha256(secret, first 20 bytes)[:8]); still verifies until expiry.
// Solution = decimal nonce such that sha256(c + ":" + nonce) has >= bits leading zero bits.
package pow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/bits"
	"strconv"
	"time"
)

var enc = base64.RawURLEncoding

// Purpose is what a challenge may be spent on; it is covered by the challenge MAC.
type Purpose byte

const (
	PurposeReg   Purpose = 'r' // registration; Bits = the difficulty this root was asked for
	PurposeWrite Purpose = 'w' // anonymous per-request write (X-PoW); Bits = difficulty
	PurposeWait  Purpose = 3   // anonymous wait-mode write (27.2): Bits = wait_s/10, no hashing
)

// String renders the `for=` value: reg, w, w_wait.
func (p Purpose) String() string {
	switch p {
	case PurposeReg:
		return "reg"
	case PurposeWrite:
		return "w"
	case PurposeWait:
		return "w_wait"
	}
	return "?"
}

// Info is what a verified challenge authenticates. A v1 challenge reports Bits 0
// (the caller applies its configured difficulty) and PurposeReg.
type Info struct {
	Exp     time.Time
	Bits    int
	Purpose Purpose
}

var (
	ErrMalformed = errors.New("malformed challenge")
	ErrBad       = errors.New("bad challenge")
	ErrExpired   = errors.New("challenge expired")
)

const (
	v1Len  = 28
	v2Len  = 30
	macLen = 8
)

// New mints a v2 challenge valid until exp; bits must fit a byte (0..255).
func New(secret []byte, exp time.Time, bits int, purpose Purpose) string {
	if bits < 0 || bits > 255 {
		panic("pow: bits out of range")
	}
	var raw [v2Len]byte
	fill(raw[:], exp)
	raw[20], raw[21] = byte(bits), byte(purpose)
	copy(raw[22:], mac(secret, raw[:22]))
	return enc.EncodeToString(raw[:])
}

// Mint creates a v1 (28-byte) challenge valid until exp; kept for v1 callers.
func Mint(secret []byte, exp time.Time) string {
	var raw [v1Len]byte
	fill(raw[:], exp)
	copy(raw[20:], mac(secret, raw[:20]))
	return enc.EncodeToString(raw[:])
}

func fill(raw []byte, exp time.Time) {
	if _, err := rand.Read(raw[:16]); err != nil {
		panic(err)
	}
	binary.BigEndian.PutUint32(raw[16:20], uint32(exp.Unix()))
}

func mac(secret, msg []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(msg)
	return m.Sum(nil)[:macLen]
}

// VerifyV2 checks the MAC and expiry of a v2 or v1 challenge and returns what it
// authenticates. Callers compare Info.Purpose with the one their route expects.
// On ErrExpired, Info is still filled.
func VerifyV2(secret []byte, c string, now time.Time) (Info, error) {
	raw, err := enc.DecodeString(c)
	if err != nil || (len(raw) != v1Len && len(raw) != v2Len) {
		return Info{}, ErrMalformed
	}
	n := len(raw) - macLen
	if !hmac.Equal(mac(secret, raw[:n]), raw[n:]) {
		return Info{}, ErrBad
	}
	info := Info{Exp: time.Unix(int64(binary.BigEndian.Uint32(raw[16:20])), 0), Purpose: PurposeReg}
	if len(raw) == v2Len {
		info.Bits, info.Purpose = int(raw[20]), Purpose(raw[21])
	}
	if now.After(info.Exp) {
		return info, ErrExpired
	}
	return info, nil
}

// Verify is the v1 entry point: it accepts both layouts and returns only the expiry.
func Verify(secret []byte, c string, now time.Time) (time.Time, error) {
	info, err := VerifyV2(secret, c, now)
	return info.Exp, err
}

// LeadingZeros returns the number of leading zero bits of sha256(c + ":" + nonce).
func LeadingZeros(c, nonce string) int {
	h := sha256.Sum256([]byte(c + ":" + nonce))
	n := 0
	for _, b := range h {
		if b != 0 {
			return n + bits.LeadingZeros8(b)
		}
		n += 8
	}
	return n
}

// Check reports whether nonce solves c at the given difficulty.
func Check(c, nonce string, bits int) bool {
	return nonce != "" && LeadingZeros(c, nonce) >= bits
}

// Solve brute-forces a nonce for c at the given difficulty.
func Solve(c string, bits int) string {
	for i := uint64(0); ; i++ {
		n := strconv.FormatUint(i, 10)
		if Check(c, n, bits) {
			return n
		}
	}
}
