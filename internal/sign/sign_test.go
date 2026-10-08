package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
)

const testSecret = "test-secret-0123456789abcdef"

// Vectors computed independently with crypto/hkdf + crypto/ed25519 (stdlib only, no package code).
const (
	vecPub1 = "81acc79fb551db513b3b68395ad4b39029e2bca09b90097ad4cd071c0accee89"
	vecPub2 = "86456bb4e1583c85e3cbe997a53ffe6d30d76bcfaa6d8e3528c40af4d92a49f7"
	vecLine = "att1 j=j1 o=ab t=1 k=1"
	vecSig  = "sig=tP-l2lLo2QqRH0WWO8bjUSmM7Kf-PyOAlz-t9bHW7NVAKQZLZQvtp_v6yDQBsignLfvI99dJ-GjkjYHjw91VCA"
)

func cfg(kid int) core.Config {
	return core.Config{ServerSecret: []byte(testSecret), SignKID: kid}
}

func mustPanic(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: expected panic", what)
		}
	}()
	fn()
}

func TestDeterministicKey(t *testing.T) {
	a, b := MustNew(cfg(1)), MustNew(cfg(1))
	if !bytes.Equal(a.Public(), b.Public()) {
		t.Fatal("same secret, different keys")
	}
	if got := hex.EncodeToString(a.Public()); got != vecPub1 {
		t.Fatalf("kid 1 pub %s want %s", got, vecPub1)
	}
	// SPEC-v2 17.1 formula, spelled out: HKDF-SHA256(secret, salt "", info "cx-sign-v1") -> seed.
	seed, _ := hkdf.Key(sha256.New, []byte(testSecret), nil, "cx-sign-v1", ed25519.SeedSize)
	if want := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey); !bytes.Equal(a.Public(), want) {
		t.Fatal("key does not follow the SPEC derivation")
	}
	if got := a.Sign("att1", vecLine); got != vecSig {
		t.Fatalf("signature %s want %s", got, vecSig)
	}
	if got := hex.EncodeToString(MustNew(cfg(2)).Public()); got != vecPub2 {
		t.Fatalf("kid 2 pub %s want %s", got, vecPub2)
	}
	if bytes.Equal(MustNew(core.Config{ServerSecret: []byte("another-secret-0123456789")}).Public(), a.Public()) {
		t.Fatal("different secrets, same key")
	}
	if s := MustNew(core.Config{ServerSecret: []byte(testSecret)}); s.KID() != 1 || !bytes.Equal(s.Public(), a.Public()) {
		t.Fatal("unset SIGN_KID must mean kid 1")
	}
	if _, err := New(core.Config{}); err == nil {
		t.Fatal("empty secret accepted")
	}
	if _, err := New(cfg(MaxKID + 1)); err == nil {
		t.Fatal("kid above MaxKID accepted")
	}
	if _, err := New(cfg(-1)); err == nil {
		t.Fatal("negative kid accepted")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := MustNew(cfg(1))
	line := Canonical("att1", KV{"j", "j7f2"}, KV{"w", "3a1c"}, KV{"s", "exit"}, KV{"c", "0"}, KV{"n", "2/2"}, KV{"d", "1"}, KV{"t", "1760000000"}, KV{"k", "1"})
	if line != "att1 j=j7f2 w=3a1c s=exit c=0 n=2/2 d=1 t=1760000000 k=1" {
		t.Fatalf("canonical line %q", line)
	}
	sig := s.Sign("att1", line)
	if !strings.HasPrefix(sig, "sig=") || len(sig) != 4+86 {
		t.Fatalf("sig form %q", sig)
	}
	if kid, ok := s.Verify("att1", line, sig); !ok || kid != 1 {
		t.Fatalf("verify: kid=%d ok=%v", kid, ok)
	}
	bare := strings.TrimPrefix(sig, "sig=")
	for _, v := range []string{bare, bare + "==", " " + sig + "\n", "sig=" + bare + "=="} {
		if kid, ok := s.Verify("att1", line, v); !ok || kid != 1 {
			t.Fatalf("verify variant %q: kid=%d ok=%v", v, kid, ok)
		}
	}
	raw, err := DecodeSig(sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		t.Fatal("DecodeSig", err)
	}
	if kid, ok := s.VerifyBytes(Message("att1", line), raw); !ok || kid != 1 {
		t.Fatal("VerifyBytes")
	}
	if !ed25519.Verify(s.Public(), Message("att1", line), raw) {
		t.Fatal("plain ed25519 verification of Message failed")
	}
	// Package default.
	Use(nil)
	mustPanic(t, "Default before Init", func() { Default() })
	if _, err := Init(cfg(1)); err != nil {
		t.Fatal(err)
	}
	if Sign("att1", line) != sig || KID() != 1 || !bytes.Equal(Public(), s.Public()) {
		t.Fatal("package-level default differs from New")
	}
	if kid, ok := Verify("att1", line, sig); !ok || kid != 1 {
		t.Fatal("package-level Verify")
	}
}

func TestTamperFails(t *testing.T) {
	s := MustNew(cfg(1))
	line := Canonical("ts1", KV{"h", strings.Repeat("ab", 32)}, KV{"t", "1760000000"}, KV{"n", "42"}, KV{"k", "1"})
	sig := s.Sign("ts1", line)
	if _, ok := s.Verify("ts1", line, sig); !ok {
		t.Fatal("control")
	}
	bad := map[string][3]string{
		"line digit":   {"ts1", strings.Replace(line, "n=42", "n=43", 1), sig},
		"line trail":   {"ts1", line + " ", sig},
		"line case":    {"ts1", strings.ToUpper(line[:1]) + line[1:], sig},
		"line empty":   {"ts1", "", sig},
		"sig flipped":  {"ts1", line, flip(sig)},
		"sig trunc":    {"ts1", line, sig[:len(sig)-2]},
		"sig empty":    {"ts1", line, ""},
		"sig prefix":   {"ts1", line, "sig="},
		"sig garbage":  {"ts1", line, "sig=!!"},
		"sig short":    {"ts1", line, "sig=" + base64.RawURLEncoding.EncodeToString(make([]byte, 10))},
		"sig long":     {"ts1", line, "sig=" + base64.RawURLEncoding.EncodeToString(make([]byte, 65))},
		"sig toolong":  {"ts1", line, "sig=" + strings.Repeat("A", MaxSig+1)},
		"sig std b64":  {"ts1", line, strings.NewReplacer("-", "+", "_", "/").Replace(sig) + "!"},
		"type empty":   {"", line, sig},
		"type invalid": {"TS1", line, sig},
	}
	for name, c := range bad {
		if kid, ok := s.Verify(c[0], c[1], c[2]); ok || kid != 0 {
			t.Errorf("%s: accepted (kid=%d)", name, kid)
		}
	}
	other := MustNew(core.Config{ServerSecret: []byte("another-secret-0123456789")})
	if _, ok := other.Verify("ts1", line, sig); ok {
		t.Fatal("other secret's key accepted the signature")
	}
	if _, ok := s.VerifyBytes(Message("ts1", line), []byte("short")); ok {
		t.Fatal("short raw signature accepted")
	}
}

// flip changes one signature character to another valid base64url character.
func flip(sig string) string {
	b := []byte(sig)
	i := len(b) - 1
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

func TestTypeDomainSeparation(t *testing.T) {
	s := MustNew(cfg(1))
	line := "att1 j=j1 o=ab t=1 k=1"
	sig := s.Sign("att1", line)
	for _, typ := range []string{"ts1", "attest1", "rep", "cxc1", "skill1", "att", "att10"} {
		if _, ok := s.Verify(typ, line, sig); ok {
			t.Fatalf("att1 signature verified as %s", typ)
		}
	}
	if s.Sign("ts1", line) == sig {
		t.Fatal("same signature for two types")
	}
	want := append([]byte("cx-sig-v1\x00att1\x00"), line...)
	if got := Message("att1", line); !bytes.Equal(got, want) {
		t.Fatalf("message %q want %q", got, want)
	}
	if !ed25519.Verify(s.Public(), want, mustDecode(t, sig)) {
		t.Fatal("signature is not over the domain-separated message")
	}
	if ed25519.Verify(s.Public(), []byte(line), mustDecode(t, sig)) {
		t.Fatal("signature verifies over the bare line")
	}
	// Framing cannot be shifted: types never contain NUL or spaces, so (typ, line) splits are unique.
	for _, typ := range []string{"att1\x00x", "", "Att1", "x y", "1att", "toolongtypename01", "att-1"} {
		if ValidType(typ) {
			t.Fatalf("ValidType(%q)", typ)
		}
		mustPanic(t, "Sign bad type", func() { s.Sign(typ, line) })
		if _, ok := s.Verify(typ, line, sig); ok {
			t.Fatalf("Verify accepted type %q", typ)
		}
	}
	shifted := s.Sign("att1", "x\x00y")
	if _, ok := s.Verify("att1\x00x", "y", shifted); ok {
		t.Fatal("framing shift verified")
	}
	if TypeOf(line) != "att1" || TypeOf("rep a=1") != "rep" || TypeOf("Att1 x") != "" || TypeOf("") != "" || TypeOf(" att1") != "" {
		t.Fatal("TypeOf")
	}
}

func mustDecode(t *testing.T, sig string) []byte {
	t.Helper()
	raw, err := DecodeSig(sig)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestKidRotationKeepsPrev(t *testing.T) {
	k1 := MustNew(cfg(1))
	line := Canonical("rep", KV{"id", "r1"}, KV{"rep", "12"}, KV{"at", "1760000000"}, KV{"k", "1"})
	old := k1.Sign("rep", line)
	if len(k1.Prev()) != 0 || k1.WellKnown().Prev == nil || len(k1.WellKnown().Prev) != 0 {
		t.Fatal("kid 1 must publish an empty, non-nil prev")
	}

	k2 := MustNew(cfg(2)) // SIGN_KID bumped
	if k2.KID() != 2 || bytes.Equal(k2.Public(), k1.Public()) {
		t.Fatal("kid 2 must be a different key")
	}
	if kid, ok := k2.Verify("rep", line, old); !ok || kid != 1 {
		t.Fatalf("previous key signature: kid=%d ok=%v", kid, ok)
	}
	fresh := k2.Sign("rep", line)
	if kid, ok := k2.Verify("rep", line, fresh); !ok || kid != 2 {
		t.Fatalf("current key signature: kid=%d ok=%v", kid, ok)
	}
	if fresh == old {
		t.Fatal("rotation did not change signatures")
	}
	if _, ok := k1.Verify("rep", line, fresh); ok {
		t.Fatal("an older server verified a newer key's signature")
	}
	prev := k2.Prev()
	if len(prev) != 1 || prev[0].KID != 1 || prev[0].Pub != hex.EncodeToString(k1.Public()) {
		t.Fatalf("prev %+v", prev)
	}
	if pub, ok := k2.PublicOf(1); !ok || !bytes.Equal(pub, k1.Public()) {
		t.Fatal("PublicOf(1)")
	}
	if pub, ok := k2.PublicOf(2); !ok || !bytes.Equal(pub, k2.Public()) {
		t.Fatal("PublicOf(2)")
	}
	if _, ok := k2.PublicOf(3); ok {
		t.Fatal("PublicOf(3) must be unknown")
	}
	wk := k2.WellKnown()
	if wk.KID != 2 || wk.Alg != "Ed25519" || wk.Pub != hex.EncodeToString(k2.Public()) || wk.Domain != "cx-sig-v1\x00<type>\x00<line>" {
		t.Fatalf("well-known %+v", wk)
	}
	js, _ := json.Marshal(wk)
	if !strings.Contains(string(js), `"prev":[{"kid":1,"pub":"`+vecPub1+`"}]`) || strings.Count(string(js), `\u0000`) != 2 {
		t.Fatalf("well-known json %s", js)
	}
	k3 := MustNew(cfg(3))
	if p := k3.Prev(); len(p) != 2 || p[0].KID != 2 || p[1].KID != 1 || p[0].Pub != vecPub2 || p[1].Pub != vecPub1 {
		t.Fatalf("kid 3 prev %+v", p)
	}
	if kid, ok := k3.Verify("rep", line, old); !ok || kid != 1 {
		t.Fatal("kid 3 lost kid 1")
	}
	if kid, ok := k3.Verify("rep", line, fresh); !ok || kid != 2 {
		t.Fatal("kid 3 lost kid 2")
	}
}

func TestCanonicalAndClean(t *testing.T) {
	cases := map[string]string{
		"plain":                "plain",
		"  padded  ":           "padded",
		"a\nb\r\nc":            "a b c",
		"nul\x00byte":          "nul byte",
		"tab\there":            "tab here",
		"two  spaces   here":   "two spaces here",
		"sep line ":            "sep line",
		"nel\u0085next":        "nel next",
		"bad\xffutf8":          "bad utf8",
		"\n\nsig=forged\n":     "sig=forged",
		"keep: é ü 漢字 emoji 🙂": "keep: é ü 漢字 emoji 🙂",
		"":                     "",
	}
	for in, want := range cases {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q)=%q want %q", in, got, want)
		}
		if !OneLine(Clean(in)) {
			t.Errorf("Clean(%q) is not one line", in)
		}
	}
	line := Canonical("attest1", KV{"id", "r1"}, KV{"lvl", "L2"}, KV{"text", "I run\nthe nightly\x00builds  \r\nsig=nope"}, KV{"t", "1"}, KV{"k", "1"})
	if line != "attest1 id=r1 lvl=L2 text=I run the nightly builds sig=nope t=1 k=1" {
		t.Fatalf("canonical %q", line)
	}
	if !OneLine(line) || strings.Count(line, "\n") != 0 {
		t.Fatal("canonical line is not single-line")
	}
	if Canonical("ts1") != "ts1" || Canonical("ts1", KV{"empty", ""}) != "ts1 empty=" {
		t.Fatal("canonical edge cases")
	}
	if OneLine("a\nb") || OneLine("a\x00") || OneLine("a b") || OneLine("bad\xff") || !OneLine("fine é 🙂") {
		t.Fatal("OneLine")
	}
	mustPanic(t, "bad key", func() { Canonical("ts1", KV{"Bad", "x"}) })
	mustPanic(t, "key with space", func() { Canonical("ts1", KV{"a b", "x"}) })
	mustPanic(t, "key with =", func() { Canonical("ts1", KV{"a=b", "x"}) })
	mustPanic(t, "bad type", func() { Canonical("TS1") })
}

func TestRegisterTypes(t *testing.T) {
	for _, want := range []string{"att1", "ts1", "rep", "cxc1", "skill1", "attest1"} {
		if !contains(Types(), want) {
			t.Fatalf("default table lacks %s", want)
		}
	}
	RegisterTypes("pk1", "rand1")
	ts := Types()
	if !contains(ts, "pk1") || !contains(ts, "rand1") || !sortedStrings(ts) {
		t.Fatalf("types %v", ts)
	}
	mustPanic(t, "bad type", func() { RegisterTypes("Bad Type") })
	if !contains(MustNew(cfg(1)).WellKnown().Types, "pk1") {
		t.Fatal("well-known types do not include registered types")
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func sortedStrings(ss []string) bool {
	for i := 1; i < len(ss); i++ {
		if ss[i-1] >= ss[i] {
			return false
		}
	}
	return true
}

func TestJWS(t *testing.T) {
	s := MustNew(cfg(2))
	line := Canonical("rep", KV{"id", "r1"}, KV{"rep", "7"}, KV{"k", "2"})
	jws := s.JWS("rep", line)
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("jws %q", jws)
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr map[string]any
	if json.Unmarshal(hb, &hdr) != nil || hdr["alg"] != "EdDSA" || hdr["kid"] != "2" || hdr["cty"] != "rep" || len(hdr) != 3 {
		t.Fatalf("header %s", hb)
	}
	if pb, _ := base64.RawURLEncoding.DecodeString(parts[1]); string(pb) != line {
		t.Fatalf("payload %q", pb)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(s.Public(), []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("standard JWS verification failed")
	}
	if typ, kid, got, ok := s.VerifyJWS(jws); !ok || typ != "rep" || kid != 2 || got != line {
		t.Fatalf("VerifyJWS: %q %d %q %v", typ, kid, got, ok)
	}
	// A kid-1 JWS still verifies after rotation; a tampered payload or header does not.
	oldJWS := MustNew(cfg(1)).JWS("rep", line)
	if _, kid, _, ok := s.VerifyJWS(oldJWS); !ok || kid != 1 {
		t.Fatal("previous key JWS rejected")
	}
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(line+"0")) + "." + parts[2]
	if _, _, _, ok := s.VerifyJWS(tampered); ok {
		t.Fatal("tampered JWS accepted")
	}
	for _, bad := range []string{"", "a.b", jws + ".x", "!!." + parts[1] + "." + parts[2], strings.Repeat("a", 2*MaxLine+1)} {
		if _, _, _, ok := s.VerifyJWS(bad); ok {
			t.Fatalf("bad JWS %q accepted", bad)
		}
	}
	JWSHeaderExtraFn = func(kid int) map[string]any {
		return map[string]any{"jku": "https://agents.example/.well-known/jwks.json", "alg": "none", "kid": "evil"}
	}
	defer func() { JWSHeaderExtraFn = nil }()
	hb, _ = base64.RawURLEncoding.DecodeString(strings.Split(s.JWS("rep", line), ".")[0])
	hdr = nil
	json.Unmarshal(hb, &hdr)
	if hdr["jku"] != "https://agents.example/.well-known/jwks.json" || hdr["alg"] != "EdDSA" || hdr["kid"] != "2" {
		t.Fatalf("extra header %s", hb)
	}
	mustPanic(t, "bad type", func() { s.JWS("Rep", line) })
}

func TestSignBytesRefusesDomain(t *testing.T) {
	s := MustNew(cfg(1))
	msg := []byte(`"@authority": agents.example` + "\n" + `"@path": /kb/x.md`)
	sig := s.SignBytes(msg)
	if kid, ok := s.VerifyBytes(msg, sig); !ok || kid != 1 {
		t.Fatal("raw round trip")
	}
	if _, ok := s.VerifyBytes(append(msg, '!'), sig); ok {
		t.Fatal("raw tamper accepted")
	}
	mustPanic(t, "statement domain through SignBytes", func() { s.SignBytes(Message("att1", "att1 x=1")) })
	s.SignBytes([]byte(Domain)) // the bare domain without framing is not a statement
}

// opensslBin finds an OpenSSL with Ed25519 + -rawin (>= 1.1.1); LibreSSL (macOS /usr/bin) has neither.
func opensslBin(t *testing.T) string {
	t.Helper()
	cands := []string{os.Getenv("OPENSSL"), "/opt/homebrew/opt/openssl@3/bin/openssl", "/opt/homebrew/bin/openssl",
		"/usr/local/opt/openssl@3/bin/openssl", "/usr/local/bin/openssl"}
	if p, err := exec.LookPath("openssl"); err == nil {
		cands = append(cands, p)
	}
	for _, c := range cands {
		if c == "" {
			continue
		}
		out, err := exec.Command(c, "version").Output()
		if err != nil {
			continue
		}
		f := strings.Fields(string(out))
		if len(f) < 2 || f[0] != "OpenSSL" || strings.HasPrefix(f[1], "0.") || strings.HasPrefix(f[1], "1.0") || strings.HasPrefix(f[1], "1.1.0") {
			continue
		}
		return c
	}
	t.Skip("no OpenSSL >= 1.1.1 found (LibreSSL lacks Ed25519 -rawin); set OPENSSL=/path/to/openssl")
	return ""
}

// TestOpenSSLVerify is the acceptance one-liner of README.md: the published hex key (as an Ed25519
// SubjectPublicKeyInfo) verifies domain||0||type||0||line with openssl pkeyutl.
func TestOpenSSLVerify(t *testing.T) {
	bin := opensslBin(t)
	s := MustNew(cfg(1))
	line := Canonical("att1", KV{"j", "j7f2"}, KV{"w", "3a1c"}, KV{"i", "9e"}, KV{"o", "71"}, KV{"s", "exit"}, KV{"c", "0"}, KV{"n", "2/2"}, KV{"d", "1"}, KV{"t", "1760000000"}, KV{"k", "1"})
	sig := s.Sign("att1", line)
	pub, err := hex.DecodeString(s.WellKnown().Pub)
	if err != nil {
		t.Fatal(err)
	}
	spkiPrefix, _ := hex.DecodeString("302a300506032b6570032100")
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pubDer := write("pub.der", append(spkiPrefix, pub...))
	msg := write("msg.bin", append([]byte("cx-sig-v1\x00"+TypeOf(line)+"\x00"), line...))
	sigBin := write("sig.bin", mustDecode(t, sig))
	run := func(msgPath string) (string, error) {
		out, err := exec.Command(bin, "pkeyutl", "-verify", "-pubin", "-keyform", "DER", "-inkey", pubDer, "-rawin", "-in", msgPath, "-sigfile", sigBin).CombinedOutput()
		return string(out), err
	}
	out, err := run(msg)
	if err != nil || !strings.Contains(out, "Signature Verified Successfully") {
		t.Fatalf("%s pkeyutl -verify: %v\n%s", bin, err, out)
	}
	bare := write("bare.bin", []byte(line))
	if out, err := run(bare); err == nil && strings.Contains(out, "Verified Successfully") {
		t.Fatal("openssl verified the bare line without the domain prefix")
	}
	wrongType := write("ts1.bin", append([]byte("cx-sig-v1\x00ts1\x00"), line...))
	if out, err := run(wrongType); err == nil && strings.Contains(out, "Verified Successfully") {
		t.Fatal("openssl verified the line under another type")
	}
	if !reflect.DeepEqual(TypeOf(line), "att1") {
		t.Fatal("type inference")
	}
}
