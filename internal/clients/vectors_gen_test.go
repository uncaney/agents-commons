package clients

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/errsig"
)

// TestGenerateVectors regenerates the cross-implementation vector file /e2e-vectors.json and the
// errsig.tsv lookup table from the Go reference (internal/e2e and internal/kb via internal/errsig),
// so /e2e.py, /e2e.mjs and Go all reproduce the same bytes. It is the authority; it only rewrites
// the committed files when GEN_VECTORS=1 so the normal acceptance run stays read-only. The committed
// files are what the embedded server serves and what the self-tests check.
func TestGenerateVectors(t *testing.T) {
	if os.Getenv("GEN_VECTORS") == "" {
		t.Skip("set GEN_VECTORS=1 to rewrite assets/e2e-vectors.json and clients/errsig.tsv")
	}
	vj := buildVectors(t)
	writeBoth(t, "e2e-vectors.json", vj)
	writeBoth(t, "errsig.tsv", []byte(errsig.VectorsTSV()))
}

type sealVec struct {
	Name  string `json:"name"`
	Mk    string `json:"mk"`
	Nonce string `json:"nonce"`
	Pt    string `json:"pt"`
	Value string `json:"value"`
}
type cxs1Vec struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
	Salt   string `json:"salt"`
	Pt     string `json:"pt"`
	Record string `json:"record"`
}
type xVec struct {
	Name string `json:"name"`
	Sk   string `json:"sk"`
	U    string `json:"u"`
	Out  string `json:"out"`
	Base bool   `json:"base"`
}

// buildVectors produces deterministic seal2 / cxs1 / x25519 vectors from the Go primitives.
func buildVectors(t *testing.T) []byte {
	t.Helper()
	fix := func(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }
	type doc struct {
		Note   string    `json:"note"`
		Seal2  []sealVec `json:"seal2"`
		Cxs1   []cxs1Vec `json:"cxs1"`
		X25519 []xVec    `json:"x25519"`
	}
	d := doc{Note: "agents.ekaii.fr cross-impl vectors (SPEC-v2 26.4 seal2, 7.4 cxs1, RFC 7748). Generated from internal/e2e; reproduce byte for byte."}

	seals := []struct {
		name          string
		mk, nonce, pt []byte
	}{
		{"empty", fix(0x11, 32), fix(0x00, 16), nil},
		{"short", fix(0x22, 32), fix(0xab, 16), []byte("hello sealed world")},
		{"block-boundary", fix(0x33, 32), fix(0x5a, 16), bytes.Repeat([]byte("A"), 32)},
		{"multi-block", fix(0x44, 32), fix(0x7e, 16), bytes.Repeat([]byte("checkpoint body "), 6)},
	}
	for _, s := range seals {
		// cross-impl vectors mirror the aad-free /seal.py recipe; aad "" keeps the unbound MAC base.
		v, err := e2e.Seal2(e2e.SealV1Key(s.mk), "", s.pt, bytes.NewReader(s.nonce))
		if err != nil {
			t.Fatalf("seal2 %s: %v", s.name, err)
		}
		if _, err := e2e.Open2(e2e.SealV1Key(s.mk), "", v); err != nil {
			t.Fatalf("seal2 %s round-trip: %v", s.name, err)
		}
		d.Seal2 = append(d.Seal2, sealVec{s.name, hex.EncodeToString(s.mk), hex.EncodeToString(s.nonce), hex.EncodeToString(s.pt), v})
	}

	cxs := []struct {
		name             string
		secret, salt, pt []byte
	}{
		{"short", fix(0x07, 16), fix(0x01, 32), []byte("drop body hello")},
		{"empty", fix(0x08, 24), fix(0x02, 32), nil},
		{"multi-block", fix(0x09, 32), fix(0x03, 32), bytes.Repeat([]byte("Z"), 100)},
	}
	for _, c := range cxs {
		rec, err := e2e.Cxs1Seal(c.secret, c.pt, bytes.NewReader(c.salt))
		if err != nil {
			t.Fatalf("cxs1 %s: %v", c.name, err)
		}
		if _, err := e2e.Cxs1Open(c.secret, rec); err != nil {
			t.Fatalf("cxs1 %s round-trip: %v", c.name, err)
		}
		d.Cxs1 = append(d.Cxs1, cxs1Vec{c.name, hex.EncodeToString(c.secret), hex.EncodeToString(c.salt),
			hex.EncodeToString(c.pt), base64.RawURLEncoding.EncodeToString(rec)})
	}

	base := make([]byte, 32)
	base[0] = 9
	for _, sk := range [][]byte{fix(0x09, 32), fix(0x4a, 32)} {
		priv, err := ecdh.X25519().NewPrivateKey(clampX(sk))
		if err != nil {
			t.Fatalf("x25519 key: %v", err)
		}
		d.X25519 = append(d.X25519, xVec{"base-" + hex.EncodeToString(sk[:1]), hex.EncodeToString(sk),
			hex.EncodeToString(base), hex.EncodeToString(priv.PublicKey().Bytes()), true})
	}

	b, err := json.MarshalIndent(d, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func clampX(k []byte) []byte {
	c := append([]byte(nil), k...)
	c[0] &= 248
	c[31] &= 127
	c[31] |= 64
	return c
}

// writeBoth writes name into the embedded assets dir and the repo-root clients/ dir.
func writeBoth(t *testing.T, name string, b []byte) {
	t.Helper()
	for _, p := range []string{filepath.Join("assets", name), filepath.Join("..", "..", "clients", name)} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
		t.Logf("wrote %s (%d bytes)", p, len(b))
	}
}
