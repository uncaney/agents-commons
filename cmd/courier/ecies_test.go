package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// Deterministic golden ECIES vector (see ecies.go): the ciphertext below was sealed to the recipient
// public key derived from walTestRecipientPriv with a fixed ephemeral key and nonce. It must decrypt
// with that private key and the aad walGoldenAAD to exactly walGoldenPlaintext. These constants are
// shared with the scanner tests in kind_wal_test.go.
const (
	walTestRecipientPriv = "1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"
	walTestRecipientPub  = "4d27bcee3135c4944b28d27dd809b07be10c35160d20131caa7e85575498d07c"
	walGoldenCiphertext  = "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a" +
		"909192939495969798999a9b" +
		"b2597c9e7beff289cdaa2d01b69bc847adee85351001039b52f80cbae99945f8889fff5849e613f60df" +
		"b7702d3249d444b5a877c32f790970a27c4c0c7ec84ab6d679fc78d"
	walGoldenPlaintext = "agents.ekaii.fr WAL segment 000000010000000000000003\n"
	walGoldenAAD       = "wal/000000010000000000000003"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestECIESRoundTripAndVectors(t *testing.T) {
	priv, err := parseWalPrivateKey(walTestRecipientPriv)
	if err != nil {
		t.Fatalf("parse private: %v", err)
	}
	pub, err := parseWalPublicKey(walTestRecipientPub)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	if !pub.Equal(priv.PublicKey()) {
		t.Fatal("public key does not match private key")
	}

	// Golden vector: the hardcoded ciphertext decrypts with the test private key.
	gold := mustHex(t, walGoldenCiphertext)
	got, err := eciesDecrypt(priv, gold, []byte(walGoldenAAD))
	if err != nil {
		t.Fatalf("decrypt golden: %v", err)
	}
	if string(got) != walGoldenPlaintext {
		t.Fatalf("golden plaintext = %q, want %q", got, walGoldenPlaintext)
	}
	// The golden ciphertext is the ephemeral public || 12-byte nonce || GCM(ct+tag).
	if len(gold) != eciesHdrLen+len(walGoldenPlaintext)+eciesTagLen {
		t.Fatalf("golden length = %d", len(gold))
	}

	// Round trip over a range of sizes; each encryption is randomized (fresh ephemeral + nonce).
	for _, n := range []int{0, 1, 16, 4096, 1 << 16} {
		pt := make([]byte, n)
		rand.Read(pt)
		aad := []byte("wal/seg")
		c1, err := eciesEncrypt(pub, pt, aad)
		if err != nil {
			t.Fatalf("encrypt n=%d: %v", n, err)
		}
		c2, err := eciesEncrypt(pub, pt, aad)
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 && string(c1) == string(c2) {
			t.Fatalf("n=%d: two encryptions are identical (nonce/ephemeral not fresh)", n)
		}
		if len(c1) != eciesHdrLen+n+eciesTagLen {
			t.Fatalf("n=%d: ciphertext length %d", n, len(c1))
		}
		out, err := eciesDecrypt(priv, c1, aad)
		if err != nil {
			t.Fatalf("decrypt n=%d: %v", n, err)
		}
		if string(out) != string(pt) {
			t.Fatalf("n=%d: round trip mismatch", n)
		}
	}

	// Negative cases: wrong aad, a tampered byte, a short blob, and the wrong recipient key all fail.
	pt := []byte("secret wal bytes")
	blob, _ := eciesEncrypt(pub, pt, []byte("wal/a"))
	if _, err := eciesDecrypt(priv, blob, []byte("wal/b")); err == nil {
		t.Fatal("wrong aad accepted")
	}
	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 0x01
	if _, err := eciesDecrypt(priv, bad, []byte("wal/a")); err == nil {
		t.Fatal("tampered tag accepted")
	}
	tampHdr := append([]byte(nil), blob...)
	tampHdr[0] ^= 0x01 // corrupt the ephemeral public key
	if _, err := eciesDecrypt(priv, tampHdr, []byte("wal/a")); err == nil {
		t.Fatal("tampered ephemeral public accepted")
	}
	if _, err := eciesDecrypt(priv, blob[:eciesMinSize-1], []byte("wal/a")); err == nil {
		t.Fatal("short blob accepted")
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if _, err := eciesDecrypt(other, blob, []byte("wal/a")); err == nil {
		t.Fatal("wrong recipient key accepted")
	}

	// Key parsing accepts hex and base64 (std/url, padded/raw) of the same 32 bytes.
	raw := mustHex(t, walTestRecipientPub)
	for _, enc := range []string{
		walTestRecipientPub,
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		base64.URLEncoding.EncodeToString(raw),
		"x25519:" + base64.StdEncoding.EncodeToString(raw),
		"  " + walTestRecipientPub + "\n",
	} {
		p, err := parseWalPublicKey(enc)
		if err != nil {
			t.Fatalf("parse %q: %v", enc, err)
		}
		if !p.Equal(pub) {
			t.Fatalf("parse %q: wrong key", enc)
		}
	}
	for _, bad := range []string{"", "zz", strings.Repeat("ab", 16), strings.Repeat("ab", 40)} {
		if _, err := parseWalPublicKey(bad); err == nil {
			t.Fatalf("parseWalPublicKey(%q) accepted", bad)
		}
	}
}
