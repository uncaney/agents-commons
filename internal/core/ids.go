package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
)

const b32 = "abcdefghijklmnopqrstuvwxyz234567"

// NewID returns a 7-char lowercase base32 id with the given type prefix ('a', 'k', 'j', …).
func NewID(prefix byte) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	out := make([]byte, 7)
	out[0] = prefix
	for i, c := range b {
		out[i+1] = b32[c&31]
	}
	return string(out)
}

// idRe is the v2 id grammar (SPEC-v2 0): any lowercase prefix letter, six base32 chars.
var idRe = regexp.MustCompile(`^[a-z][a-z2-7]{6}$`)

func ValidID(s string) bool { return idRe.MatchString(s) }

// ValidIDPrefix reports whether s is a valid id of the given type prefix.
func ValidIDPrefix(s string, prefix byte) bool { return ValidID(s) && s[0] == prefix }

// NewToken returns a bearer token "cx_<43 base64url chars>" and its sha256 as stored in the DB.
func NewToken() (string, []byte) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	tok := "cx_" + base64.RawURLEncoding.EncodeToString(b[:])
	return tok, HashToken(tok)
}

func HashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

// RecoveryLen is the length of a recovery code: 26 base32 chars = 130 bits (3.4).
const RecoveryLen = 26

var recoveryRe = regexp.MustCompile(`^[a-z2-7]{26}$`)

// ValidRecovery reports whether s has the shape of a recovery code.
func ValidRecovery(s string) bool { return recoveryRe.MatchString(s) }

// NewRecoveryCode returns a recovery code and its sha256 (the only form ever stored).
func NewRecoveryCode() (string, []byte) {
	var b [RecoveryLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	out := make([]byte, RecoveryLen)
	for i, c := range b {
		out[i] = b32[c&31]
	}
	code := string(out)
	return code, HashToken(code)
}

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,32}$`)

func ValidName(s string) bool { return nameRe.MatchString(s) }

// bearer extracts the Bearer token from an Authorization header value.
func bearer(h string) string {
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}
