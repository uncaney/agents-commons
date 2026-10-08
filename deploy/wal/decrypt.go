//go:build ignore

// decrypt.go — operator-box WAL/basebackup decryptor for the P121 restore drill. It reverses the
// stdlib ECIES that cmd/courier/kind_wal.go applies before shipping to the backup bucket:
//
//	blob = ephemeral_public(32) || nonce(12) || AES-256-GCM(key, nonce, plaintext, aad)
//	key  = HKDF-SHA256(secret = ECDH(ephemeral, recipient), salt = eph_pub||recipient_pub, info)
//
// It never runs on the server: only the operator box holds the private key. Build tag `ignore` keeps
// it out of `go build ./...`; run it directly:
//
//	go run deploy/wal/decrypt.go -key wal_priv.hex -aad "wal/<f>" < blob.enc > <f>
//
// The private key is a 32-byte X25519 scalar as hex or base64 (file via -key, or env WAL_PRIV_KEY).
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	eciesInfo   = "cx-wal-ecies-v1"
	eciesPubLen = 32
	eciesNonce  = 12
	eciesKeyLen = 32
	eciesTagLen = 16
	eciesHdr    = eciesPubLen + eciesNonce
)

func main() {
	keyFile := flag.String("key", "", "file holding the X25519 private key (hex or base64); or env WAL_PRIV_KEY")
	aad := flag.String("aad", "", "object key the blob was stored under, e.g. wal/000000010000000000000001")
	in := flag.String("in", "", "input ciphertext file (default: stdin)")
	out := flag.String("out", "", "output plaintext file (default: stdout)")
	flag.Parse()

	if err := run(*keyFile, *aad, *in, *out); err != nil {
		fmt.Fprintln(os.Stderr, "decrypt:", err)
		os.Exit(1)
	}
}

func run(keyFile, aad, in, out string) error {
	keyStr := os.Getenv("WAL_PRIV_KEY")
	if keyFile != "" {
		b, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}
		keyStr = string(b)
	}
	priv, err := parsePrivate(keyStr)
	if err != nil {
		return err
	}
	blob, err := readInput(in)
	if err != nil {
		return err
	}
	pt, err := decrypt(priv, blob, []byte(aad))
	if err != nil {
		return err
	}
	if out == "" || out == "-" {
		_, err = os.Stdout.Write(pt)
		return err
	}
	return os.WriteFile(out, pt, 0o600)
}

func readInput(in string) ([]byte, error) {
	if in == "" || in == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(in)
}

func decrypt(priv *ecdh.PrivateKey, blob, aad []byte) ([]byte, error) {
	if len(blob) < eciesHdr+eciesTagLen {
		return nil, errors.New("ciphertext too short")
	}
	ephPub, err := ecdh.X25519().NewPublicKey(blob[:eciesPubLen])
	if err != nil {
		return nil, err
	}
	nonce := blob[eciesPubLen:eciesHdr]
	ct := blob[eciesHdr:]
	shared, err := priv.ECDH(ephPub)
	if err != nil {
		return nil, err
	}
	salt := append(append([]byte{}, ephPub.Bytes()...), priv.PublicKey().Bytes()...)
	key, err := hkdf.Key(sha256.New, shared, salt, eciesInfo, eciesKeyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, aad)
}

func parsePrivate(s string) (*ecdh.PrivateKey, error) {
	raw, err := decodeKey(s)
	if err != nil {
		return nil, err
	}
	return ecdh.X25519().NewPrivateKey(raw)
}

func decodeKey(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	if i := strings.IndexByte(s, ':'); i >= 0 && i < 16 {
		s = s[i+1:]
	}
	if s == "" {
		return nil, errors.New("empty key")
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
	return nil, fmt.Errorf("key must be a %d-byte hex or base64 value", eciesPubLen)
}
