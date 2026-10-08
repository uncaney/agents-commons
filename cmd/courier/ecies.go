package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Stdlib ECIES for WAL shipment (SPEC-v2 27.9, kind wal_ship): each segment is sealed to the
// recipient's X25519 public key with an ephemeral X25519 key, an HKDF-SHA256 derived AES-256-GCM key
// and a fresh 96-bit nonce. The wire layout is
//
//	ephemeral_public(32) || nonce(12) || AES-256-GCM(key, nonce, plaintext, aad)
//
// where key = HKDF-SHA256(secret = ECDH(ephemeral, recipient), salt = ephemeral_pub||recipient_pub,
// info = "cx-wal-ecies-v1") and aad is the object key the blob is stored under (so a ciphertext can
// only be decrypted under the name it was uploaded as). Only the public key ever reaches the courier;
// the matching private key stays on the operator box and is used by deploy/wal/restore-pitr.sh.
const (
	eciesInfo    = "cx-wal-ecies-v1"
	eciesPubLen  = 32 // X25519 public key
	eciesNonce   = 12 // AES-GCM standard nonce
	eciesKeyLen  = 32 // AES-256
	eciesTagLen  = 16 // AES-GCM tag
	eciesHdrLen  = eciesPubLen + eciesNonce
	eciesMinSize = eciesHdrLen + eciesTagLen
)

// eciesEncrypt seals plaintext to pub with crypto/rand as the entropy source, binding aad.
func eciesEncrypt(pub *ecdh.PublicKey, plaintext, aad []byte) ([]byte, error) {
	return eciesSeal(rand.Reader, pub, plaintext, aad)
}

// eciesSeal is eciesEncrypt with an explicit entropy source so golden vectors are reproducible
// (the reader supplies the ephemeral key's 32 bytes, then the 12-byte nonce).
func eciesSeal(entropy io.Reader, pub *ecdh.PublicKey, plaintext, aad []byte) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("ecies: nil recipient key")
	}
	eph, err := ecdh.X25519().GenerateKey(entropy)
	if err != nil {
		return nil, fmt.Errorf("ecies: ephemeral key: %w", err)
	}
	shared, err := eph.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecies: ecdh: %w", err)
	}
	ephPub := eph.PublicKey().Bytes()
	key, err := eciesKDF(shared, ephPub, pub.Bytes())
	if err != nil {
		return nil, err
	}
	gcm, err := eciesGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, eciesNonce)
	if _, err := io.ReadFull(entropy, nonce); err != nil {
		return nil, fmt.Errorf("ecies: nonce: %w", err)
	}
	out := make([]byte, 0, eciesHdrLen+len(plaintext)+eciesTagLen)
	out = append(out, ephPub...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, aad), nil
}

// eciesDecrypt opens a blob produced by eciesEncrypt with the recipient private key, checking aad.
func eciesDecrypt(priv *ecdh.PrivateKey, blob, aad []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("ecies: nil private key")
	}
	if len(blob) < eciesMinSize {
		return nil, errors.New("ecies: ciphertext too short")
	}
	ephPub, err := ecdh.X25519().NewPublicKey(blob[:eciesPubLen])
	if err != nil {
		return nil, fmt.Errorf("ecies: ephemeral public: %w", err)
	}
	nonce := blob[eciesPubLen:eciesHdrLen]
	ct := blob[eciesHdrLen:]
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, fmt.Errorf("ecies: ecdh: %w", err)
	}
	key, err := eciesKDF(shared, ephPub.Bytes(), priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	gcm, err := eciesGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("ecies: open: %w", err)
	}
	return pt, nil
}

// eciesKDF derives the AES-256 key from the ECDH secret, salted with both public keys.
func eciesKDF(shared, ephPub, recipientPub []byte) ([]byte, error) {
	salt := make([]byte, 0, len(ephPub)+len(recipientPub))
	salt = append(salt, ephPub...)
	salt = append(salt, recipientPub...)
	return hkdf.Key(sha256.New, shared, salt, eciesInfo, eciesKeyLen)
}

func eciesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// parseWalPublicKey parses the wal_pub secret into an X25519 public key. A 32-byte key is accepted as
// hex (64 chars) or base64 (standard or URL, padded or not); surrounding whitespace is ignored.
func parseWalPublicKey(s string) (*ecdh.PublicKey, error) {
	raw, err := decodeKey32(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPublicKey(raw)
}

// parseWalPrivateKey parses an X25519 private key in the same encodings (used by tests and tooling).
func parseWalPrivateKey(s string) (*ecdh.PrivateKey, error) {
	raw, err := decodeKey32(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

// decodeKey32 decodes a 32-byte key from hex or base64, ignoring whitespace and an optional
// "x25519:" prefix.
func decodeKey32(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	if i := strings.IndexByte(s, ':'); i >= 0 && i < 16 {
		s = s[i+1:]
	}
	if s == "" {
		return nil, errors.New("ecies: empty key")
	}
	if len(s) == 2*eciesPubLen {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == eciesPubLen {
			return b, nil
		}
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == eciesPubLen {
		return b, nil
	}
	return nil, fmt.Errorf("ecies: key must be a %d-byte hex or base64 value", eciesPubLen)
}
