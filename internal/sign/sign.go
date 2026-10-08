// Package sign derives the server's Ed25519 statement key from the server secret and signs
// canonical one-line statements under a per-type domain (SPEC-v2 17.1).
//
// Every signature covers Domain || 0x00 || <type> || 0x00 || <line>, never the bare line, so a
// signature of one statement type can never be replayed as another. Statement lines are built
// with Canonical and are always a single line without control characters; "sig=<base64url>" is
// the next line on the wire.
package sign

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
)

const (
	// Domain is the signature domain prefix; the wire form is Domain || 0x00 || type || 0x00 || line.
	Domain = "cx-sig-v1"
	// Info is the HKDF info of key id 1 (SPEC-v2 17.1); later key ids append "/<kid>".
	Info = "cx-sign-v1"
	// Alg is the published algorithm name.
	Alg = "Ed25519"
	// MaxKID bounds SIGN_KID (every previous key is derived and published for verification).
	MaxKID = 100
	// MaxLine is the longest statement line Verify/Canonical accept (bytes).
	MaxLine = 8 << 10
	// MaxSig is the longest signature token accepted (base64url of 64 bytes is 86 chars).
	MaxSig = 128
)

var (
	enc    = base64.RawURLEncoding
	typeRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)
	keyRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// Key is a published key: its id and the hex public half.
type Key struct {
	KID int    `json:"kid"`
	Pub string `json:"pub"`
}

// Signer holds the current key and the public halves of every previous key id.
type Signer struct {
	kid  int
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	prev []prevKey // kid-1 .. 1, newest first
}

type prevKey struct {
	kid int
	pub ed25519.PublicKey
}

// New derives the current key (id cfg.SignKID, 1 when unset) and every previous key from
// cfg.ServerSecret: seed = HKDF-SHA256(secret, salt "", info Info[/kid]), ed25519.NewKeyFromSeed.
func New(cfg core.Config) (*Signer, error) {
	if len(cfg.ServerSecret) == 0 {
		return nil, errors.New("sign: SERVER_SECRET required")
	}
	kid := cfg.SignKID
	if kid == 0 {
		kid = 1
	}
	if kid < 1 || kid > MaxKID {
		return nil, fmt.Errorf("sign: SIGN_KID must be 1..%d", MaxKID)
	}
	s := &Signer{kid: kid, priv: derive(cfg.ServerSecret, kid)}
	s.pub = s.priv.Public().(ed25519.PublicKey)
	for k := kid - 1; k >= 1; k-- {
		s.prev = append(s.prev, prevKey{k, derive(cfg.ServerSecret, k).Public().(ed25519.PublicKey)})
	}
	return s, nil
}

// MustNew is New that panics; configuration errors are fatal at boot.
func MustNew(cfg core.Config) *Signer {
	s, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return s
}

func derive(secret []byte, kid int) ed25519.PrivateKey {
	info := Info
	if kid > 1 {
		info += "/" + strconv.Itoa(kid)
	}
	seed, err := hkdf.Key(sha256.New, secret, nil, info, ed25519.SeedSize)
	if err != nil {
		panic(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// KID is the current key id.
func (s *Signer) KID() int { return s.kid }

// Public is the current public key.
func (s *Signer) Public() ed25519.PublicKey { return s.pub }

// PublicOf returns the public key of a current or previous key id.
func (s *Signer) PublicOf(kid int) (ed25519.PublicKey, bool) {
	if kid == s.kid {
		return s.pub, true
	}
	for _, p := range s.prev {
		if p.kid == kid {
			return p.pub, true
		}
	}
	return nil, false
}

// Prev lists the previous keys, newest first.
func (s *Signer) Prev() []Key {
	out := make([]Key, 0, len(s.prev))
	for _, p := range s.prev {
		out = append(out, Key{p.kid, hex.EncodeToString(p.pub)})
	}
	return out
}

// ValidType reports whether typ is a statement type: [a-z][a-z0-9]{0,15} (att1, ts1, rep, …).
// The grammar excludes NUL and spaces, so the domain framing and TypeOf are unambiguous.
func ValidType(typ string) bool { return typeRe.MatchString(typ) }

// Message is the signed bytes of a statement: Domain || 0x00 || typ || 0x00 || line.
func Message(typ, line string) []byte {
	b := make([]byte, 0, len(Domain)+len(typ)+len(line)+2)
	b = append(b, Domain...)
	b = append(b, 0)
	b = append(b, typ...)
	b = append(b, 0)
	return append(b, line...)
}

// Sign returns "sig=<base64url>" over Message(typ, line). typ must satisfy ValidType (a bad type
// is a programming error and panics); line should come from Canonical.
func (s *Signer) Sign(typ, line string) string {
	return "sig=" + enc.EncodeToString(s.sign(typ, line))
}

func (s *Signer) sign(typ, line string) []byte {
	if !ValidType(typ) {
		panic("sign: bad statement type " + strconv.Quote(typ))
	}
	return ed25519.Sign(s.priv, Message(typ, line))
}

// Verify checks sig ("sig=<base64url>" or the bare token, padded or not) over Message(typ, line)
// against the current key, then every previous one; it returns the key id that verified.
func (s *Signer) Verify(typ, line, sig string) (kid int, ok bool) {
	raw, err := DecodeSig(sig)
	if err != nil || !ValidType(typ) {
		return 0, false
	}
	return s.VerifyBytes(Message(typ, line), raw)
}

// SignBytes signs an arbitrary message with the current key (JWS inputs, RFC 9421 bases, …). Such
// messages must never start with the statement domain, which is reserved to Sign; that is enforced.
func (s *Signer) SignBytes(msg []byte) []byte {
	if len(msg) > len(Domain) && string(msg[:len(Domain)]) == Domain && msg[len(Domain)] == 0 {
		panic("sign: SignBytes refuses the statement domain, use Sign")
	}
	return ed25519.Sign(s.priv, msg)
}

// VerifyBytes checks a raw signature against the current key then the previous ones.
func (s *Signer) VerifyBytes(msg, sig []byte) (kid int, ok bool) {
	if len(sig) != ed25519.SignatureSize {
		return 0, false
	}
	if ed25519.Verify(s.pub, msg, sig) {
		return s.kid, true
	}
	for _, p := range s.prev {
		if ed25519.Verify(p.pub, msg, sig) {
			return p.kid, true
		}
	}
	return 0, false
}

// DecodeSig decodes a signature token: an optional "sig=" prefix, base64url with or without padding.
func DecodeSig(sig string) ([]byte, error) {
	sig = strings.TrimSpace(sig)
	if len(sig) > MaxSig {
		return nil, errors.New("signature too long")
	}
	sig = strings.TrimRight(strings.TrimPrefix(sig, "sig="), "=")
	raw, err := enc.DecodeString(sig)
	if err != nil {
		return nil, errors.New("bad base64url")
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, errors.New("bad signature length")
	}
	return raw, nil
}

// WellKnown is the body of GET /.well-known/cx-key.
type WellKnown struct {
	KID    int      `json:"kid"`
	Alg    string   `json:"alg"`
	Pub    string   `json:"pub"`
	Prev   []Key    `json:"prev"`
	Domain string   `json:"domain"`
	Types  []string `json:"types"`
}

// WellKnown describes the current key, the previous ones, the signing domain and the known types.
func (s *Signer) WellKnown() WellKnown {
	return WellKnown{KID: s.kid, Alg: Alg, Pub: hex.EncodeToString(s.pub), Prev: s.Prev(),
		Domain: Domain + "\x00<type>\x00<line>", Types: Types()}
}

// KV is one "key=value" field of a statement line.
type KV struct{ K, V string }

// Canonical renders "<typ> k=v k=v …" as one safe line. Keys must match [a-z][a-z0-9_]{0,31} and
// typ ValidType (programming errors panic); values lose control characters (CR, LF, TAB, NUL, …),
// line/paragraph separators and invalid UTF-8, runs of whitespace collapse to one space and the
// value is trimmed, so no value can start a line of its own or hide a second statement.
func Canonical(typ string, fields ...KV) string {
	if !ValidType(typ) {
		panic("sign: bad statement type " + strconv.Quote(typ))
	}
	var b strings.Builder
	b.WriteString(typ)
	for _, f := range fields {
		if !keyRe.MatchString(f.K) {
			panic("sign: bad statement key " + strconv.Quote(f.K))
		}
		b.WriteByte(' ')
		b.WriteString(f.K)
		b.WriteByte('=')
		b.WriteString(Clean(f.V))
	}
	return b.String()
}

// Clean makes v a single trimmed line: control characters, line separators and invalid UTF-8
// become spaces, consecutive spaces collapse.
func Clean(v string) string {
	if !utf8.ValidString(v) {
		v = strings.ToValidUTF8(v, " ")
	}
	var b strings.Builder
	b.Grow(len(v))
	space := false
	for _, r := range v {
		if r == ' ' || isCtl(r) {
			space = b.Len() > 0
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isCtl(r rune) bool {
	return unicode.IsControl(r) || r == utf8.RuneError || r == ' ' || r == ' '
}

// OneLine reports whether s is valid UTF-8 free of control characters and line separators.
func OneLine(s string) bool {
	return utf8.ValidString(s) && strings.IndexFunc(s, isCtl) < 0
}

// TypeOf infers a statement's type: its first space-delimited token when that is a ValidType, else "".
func TypeOf(statement string) string {
	typ, _, _ := strings.Cut(statement, " ")
	if !ValidType(typ) {
		return ""
	}
	return typ
}

// Statement types known to /verify's inference table (SPEC-v2 17.1); packages add theirs with
// RegisterTypes. Verification never depends on the table: it only documents the live prefixes.
var (
	typesMu sync.RWMutex
	types   = map[string]bool{"att1": true, "ts1": true, "rep": true, "cxc1": true, "skill1": true, "attest1": true}
)

// RegisterTypes adds statement prefixes to the published inference table.
func RegisterTypes(ts ...string) {
	typesMu.Lock()
	defer typesMu.Unlock()
	for _, t := range ts {
		if !ValidType(t) {
			panic("sign: bad statement type " + strconv.Quote(t))
		}
		types[t] = true
	}
}

// Types lists the known statement types, sorted.
func Types() []string {
	typesMu.RLock()
	out := make([]string, 0, len(types))
	for t := range types {
		out = append(out, t)
	}
	typesMu.RUnlock()
	sort.Strings(out)
	return out
}

// JWSHeaderExtraFn adds protected-header members (jku, …) to JWS statements; nil-safe, and it can
// never override alg, kid or cty. P113 installs did.JWSHeaders.
var JWSHeaderExtraFn func(kid int) map[string]any

// JWS renders a statement as a compact JWS (protected header {alg EdDSA, kid "<kid>", cty "<typ>"},
// payload = the line). The signature covers the standard JWS signing input, so any JOSE library
// verifies it with the published key; base64url text can never collide with the NUL-framed domain.
func (s *Signer) JWS(typ, line string) string {
	if !ValidType(typ) {
		panic("sign: bad statement type " + strconv.Quote(typ))
	}
	hdr := map[string]any{}
	if JWSHeaderExtraFn != nil {
		for k, v := range JWSHeaderExtraFn(s.kid) {
			hdr[k] = v
		}
	}
	hdr["alg"], hdr["kid"], hdr["cty"] = "EdDSA", strconv.Itoa(s.kid), typ
	hb, _ := json.Marshal(hdr)
	input := enc.EncodeToString(hb) + "." + enc.EncodeToString([]byte(line))
	return input + "." + enc.EncodeToString(ed25519.Sign(s.priv, []byte(input)))
}

// VerifyJWS checks a compact JWS produced by JWS and returns its type, key id and statement line.
func (s *Signer) VerifyJWS(jws string) (typ string, kid int, line string, ok bool) {
	if len(jws) > 2*MaxLine {
		return "", 0, "", false
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return "", 0, "", false
	}
	hb, err1 := enc.DecodeString(parts[0])
	pb, err2 := enc.DecodeString(parts[1])
	sig, err3 := enc.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return "", 0, "", false
	}
	var hdr struct{ Alg, Kid, Cty string }
	if json.Unmarshal(hb, &hdr) != nil || hdr.Alg != "EdDSA" || !ValidType(hdr.Cty) {
		return "", 0, "", false
	}
	want, err := strconv.Atoi(hdr.Kid)
	if err != nil {
		return "", 0, "", false
	}
	pub, found := s.PublicOf(want)
	if !found || !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return "", 0, "", false
	}
	return hdr.Cty, want, string(pb), true
}

// The package default: Register/Init install the server signer so packages call sign.Sign(typ,
// line) and sign.Verify(typ, line, sig) directly.
var def atomic.Pointer[Signer]

// Init derives the signer from cfg and installs it as the package default.
func Init(cfg core.Config) (*Signer, error) {
	s, err := New(cfg)
	if err != nil {
		return nil, err
	}
	def.Store(s)
	return s, nil
}

// Use installs s as the package default (tests); nil uninstalls it.
func Use(s *Signer) { def.Store(s) }

// Default returns the installed signer; calling it before Init/Register is a programming error.
func Default() *Signer {
	s := def.Load()
	if s == nil {
		panic("sign: not initialised (call sign.Init or sign.Register first)")
	}
	return s
}

// Sign signs with the default signer: "sig=<base64url>" over Domain||0||typ||0||line.
func Sign(typ, line string) string { return Default().Sign(typ, line) }

// Verify verifies with the default signer, returning the key id that matched.
func Verify(typ, line, sig string) (kid int, ok bool) { return Default().Verify(typ, line, sig) }

// KID is the default signer's current key id.
func KID() int { return Default().KID() }

// Public is the default signer's current public key.
func Public() ed25519.PublicKey { return Default().Public() }
