package drop

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

// keys are the server-secret derivations of this package (SPEC-v2 23, distinct info strings):
// the HKDF salt of every body key and the HMAC key of the stored reader groups.
type keys struct {
	salt []byte
	grp  []byte
}

func newKeys(serverSecret []byte) keys {
	g, err := hkdf.Key(sha256.New, serverSecret, nil, "cx-drop-grp", 32)
	if err != nil {
		panic(err)
	}
	return keys{salt: serverSecret, grp: g}
}

// hashSecret is the row key: sha256 of the URL secret (or of a write key for wh).
func hashSecret(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// bodyKey derives the AES-256 key of one drop: HKDF-SHA256(ikm = URL secret, salt = server secret,
// info = "cx-drop"). Without the URL the stored body cannot be opened, even with a database dump.
func (k keys) bodyKey(secret string) []byte {
	key, err := hkdf.Key(sha256.New, []byte(secret), k.salt, "cx-drop", 32)
	if err != nil {
		panic(err)
	}
	return key
}

// group hashes a reader's IP group for the groups column (never the raw group).
func (k keys) group(g string) []byte {
	m := hmac.New(sha256.New, k.grp)
	m.Write([]byte(g))
	return m.Sum(nil)[:16]
}

const nonceLen = 12

// seal encrypts plain with AES-256-GCM; the row hash is the additional data so a body can never be
// moved to another row. Output = nonce || ciphertext.
func seal(key, h, plain []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	out := make([]byte, nonceLen, nonceLen+len(plain)+g.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return g.Seal(out, out[:nonceLen], plain, h), nil
}

// open decrypts a stored body; false on any mismatch.
func open(key, h, body []byte) ([]byte, bool) {
	if len(body) < nonceLen {
		return nil, false
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, false
	}
	plain, err := g.Open(nil, body[:nonceLen], body[nonceLen:], h)
	if err != nil {
		return nil, false
	}
	return plain, true
}
