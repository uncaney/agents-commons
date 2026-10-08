package e2e

import (
	"crypto/ecdh"
	"crypto/hpke"
	"errors"
	"strconv"
)

// Suite is the cipher suite id (E2EE 2.1): 1 = DHKEM(X25519, HKDF-SHA256), 2 = MLKEM768X25519 (X-Wing);
// both with HKDF-SHA256 and AES-256-GCM, HPKE Base mode, one Seal per context.
type Suite uint8

const (
	CS1 Suite = 1
	CS2 Suite = 2
)

var ErrSuite = errors.New("e2e: unknown cipher suite")

func (cs Suite) Valid() bool { return cs == CS1 || cs == CS2 }

func (cs Suite) String() string { return strconv.Itoa(int(cs)) }

// KEM returns the HPKE KEM of the suite (nil for an unknown suite).
func (cs Suite) KEM() hpke.KEM {
	switch cs {
	case CS1:
		return hpke.DHKEM(ecdh.X25519())
	case CS2:
		return hpke.MLKEM768X25519()
	}
	return nil
}

// PKSize is the serialized public key length, EncSize the encapsulated key length.
func (cs Suite) PKSize() int {
	switch cs {
	case CS1:
		return 32
	case CS2:
		return 1216
	}
	return 0
}

func (cs Suite) EncSize() int {
	switch cs {
	case CS1:
		return 32
	case CS2:
		return 1120
	}
	return 0
}

// SuiteForEnc maps an encapsulated key length back to its suite.
func SuiteForEnc(n int) (Suite, bool) {
	switch n {
	case 32:
		return CS1, true
	case 1120:
		return CS2, true
	}
	return 0, false
}

// KDF and AEAD are fixed across suites.
func KDF() hpke.KDF   { return hpke.HKDFSHA256() }
func AEAD() hpke.AEAD { return hpke.AES256GCM() }

// NewPublicKey deserializes a KEM public key of the suite, checking the length first.
func (cs Suite) NewPublicKey(b []byte) (hpke.PublicKey, error) {
	if !cs.Valid() {
		return nil, ErrSuite
	}
	if len(b) != cs.PKSize() {
		return nil, errors.New("e2e: public key length does not match suite " + cs.String())
	}
	return cs.KEM().NewPublicKey(b)
}

// DeriveKeyPair derives the suite's KEM key pair from 32 bytes of ikm (RFC 9180 DeriveKeyPair).
func (cs Suite) DeriveKeyPair(ikm []byte) (hpke.PrivateKey, error) {
	if !cs.Valid() {
		return nil, ErrSuite
	}
	return cs.KEM().DeriveKeyPair(ikm)
}

// GenerateKey draws a fresh KEM key pair of the suite (mode R prekeys).
func (cs Suite) GenerateKey() (hpke.PrivateKey, error) {
	if !cs.Valid() {
		return nil, ErrSuite
	}
	return cs.KEM().GenerateKey()
}
