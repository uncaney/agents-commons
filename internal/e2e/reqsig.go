package e2e

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Request signing (E2EE 3.5), signed replies (3.6) and the other server-side signature statements
// (STH, witness, cert, succession, receipts). All are Ed25519 over Labeled(label, parts...).

const (
	SigVersion = "v1"
	ReqSkew    = 300 // seconds
	NonceSize  = 16
)

var (
	ErrSig     = errors.New("e2e: bad signature header")
	ErrSkew    = errors.New("e2e: request timestamp outside the skew window")
	ErrReqSig  = errors.New("e2e: request signature invalid")
	ErrRespSig = errors.New("e2e: reply signature invalid")
)

// ReqSig is a parsed X-Cx-Sig header (also the stored send_sig of a ledger row).
type ReqSig struct {
	TS    uint64
	Nonce []byte
	Sig   []byte
}

// ReqBytes is the canonical request statement:
// "cx1/req" || 0x00 || METHOD || 0x0a || path?query || 0x0a || u64(ts) || nonce || sha256(body).
func ReqBytes(method, pathQuery string, ts uint64, nonce, bodyHash []byte) []byte {
	nl := []byte{0x0a}
	return Labeled(LabelReq, []byte(method), nl, []byte(pathQuery), nl, U64(ts), nonce, bodyHash)
}

// SignReq signs a request with rk and returns the X-Cx-Sig header value v1,<ts>,<nonce>,<sig>.
func SignReq(rk ed25519.PrivateKey, method, pathQuery string, ts uint64, nonce, body []byte) (string, error) {
	if len(nonce) != NonceSize {
		return "", fmt.Errorf("%w: nonce", ErrSig)
	}
	sig := ed25519.Sign(rk, ReqBytes(method, pathQuery, ts, nonce, Sum(body)))
	return (&ReqSig{TS: ts, Nonce: nonce, Sig: sig}).Header(), nil
}

// Header renders the X-Cx-Sig value; SendSig renders the dotted <ts>.<nonce>.<sig> form used in reports.
func (s *ReqSig) Header() string {
	return SigVersion + "," + strconv.FormatUint(s.TS, 10) + "," + b64(s.Nonce) + "," + b64(s.Sig)
}

func (s *ReqSig) SendSig() string {
	return strconv.FormatUint(s.TS, 10) + "." + b64(s.Nonce) + "." + b64(s.Sig)
}

// ParseReqSig parses the header form; ParseSendSig the dotted form.
func ParseReqSig(h string) (*ReqSig, error) {
	p := strings.Split(strings.TrimSpace(h), ",")
	if len(p) != 4 || p[0] != SigVersion {
		return nil, ErrSig
	}
	return parseSigParts(p[1], p[2], p[3])
}

func ParseSendSig(s string) (*ReqSig, error) {
	p := strings.Split(strings.TrimSpace(s), ".")
	if len(p) != 3 {
		return nil, ErrSig
	}
	return parseSigParts(p[0], p[1], p[2])
}

func parseSigParts(ts, nonce, sig string) (*ReqSig, error) {
	if len(ts) == 0 || len(ts) > 20 || (ts[0] == '0' && len(ts) > 1) || len(nonce) != 22 || len(sig) != 86 {
		return nil, ErrSig
	}
	t, err := strconv.ParseUint(ts, 10, 64)
	if err != nil {
		return nil, ErrSig
	}
	n, err1 := base64.RawURLEncoding.Strict().DecodeString(nonce)
	g, err2 := base64.RawURLEncoding.Strict().DecodeString(sig)
	if err1 != nil || err2 != nil || len(n) != NonceSize || len(g) != 64 {
		return nil, ErrSig
	}
	return &ReqSig{TS: t, Nonce: n, Sig: g}, nil
}

// VerifyReq checks the header against the body bytes at time now (nonce single-use is the caller's).
func VerifyReq(rkPub []byte, method, pathQuery, header string, body []byte, now int64) (*ReqSig, error) {
	s, err := ParseReqSig(header)
	if err != nil {
		return nil, err
	}
	d := now - int64(s.TS)
	if d > ReqSkew || d < -ReqSkew {
		return nil, ErrSkew
	}
	if !s.VerifyHash(rkPub, method, pathQuery, Sum(body)) {
		return nil, ErrReqSig
	}
	return s, nil
}

// VerifyHash checks a parsed signature against a body hash (report verification after the row expired).
func (s *ReqSig) VerifyHash(rkPub []byte, method, pathQuery string, bodyHash []byte) bool {
	if len(rkPub) != 32 || len(s.Nonce) != NonceSize || len(s.Sig) != 64 || len(bodyHash) != 32 {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(rkPub), ReqBytes(method, pathQuery, s.TS, s.Nonce, bodyHash), s.Sig)
}

// Signed replies: X-Cx-Sig-Server: t=<unix>,s=<b64 Ed25519(online_sk, "cx1/resp" || path || u64(t) || sha256(body))>.
func RespBytes(path string, t uint64, bodyHash []byte) []byte {
	return Labeled(LabelResp, []byte(path), U64(t), bodyHash)
}

func SignResp(onlineSK ed25519.PrivateKey, path string, t uint64, body []byte) string {
	return "t=" + strconv.FormatUint(t, 10) + ",s=" + b64(ed25519.Sign(onlineSK, RespBytes(path, t, Sum(body))))
}

// VerifyResp checks a reply signature and returns its timestamp.
func VerifyResp(onlinePK []byte, path, header string, body []byte) (uint64, error) {
	p := strings.Split(strings.TrimSpace(header), ",")
	if len(p) != 2 || !strings.HasPrefix(p[0], "t=") || !strings.HasPrefix(p[1], "s=") {
		return 0, ErrSig
	}
	t, err := strconv.ParseUint(p[0][2:], 10, 64)
	if err != nil {
		return 0, ErrSig
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(p[1][2:])
	if err != nil || len(sig) != 64 || len(onlinePK) != 32 {
		return 0, ErrSig
	}
	if !ed25519.Verify(ed25519.PublicKey(onlinePK), RespBytes(path, t, Sum(body)), sig) {
		return 0, ErrRespSig
	}
	return t, nil
}

// STHBytes and WitnessBytes are the signed-head statements of E2EE 3.3 and 3.4.
func STHBytes(size uint64, root []byte, at uint64) []byte {
	return Labeled(LabelSTH, U64(size), root, U64(at))
}

func WitnessBytes(size uint64, root []byte, at uint64) []byte {
	return Labeled(LabelWitness, U64(size), root, U64(at))
}

// CertBytes is the online certificate statement signed by root_sk: online_pk | nbf u64 | exp u64 | seq u32.
func CertBytes(onlinePK []byte, nbf, exp uint64, seq uint32) []byte {
	return Labeled(LabelCert, onlinePK, U64(nbf), U64(exp), U32(seq))
}

// SuccBytes is the double-signed succession statement "cx1/succ" || old || new || ik_new.
func SuccBytes(oldID, newID string, ikNew []byte) []byte {
	return Labeled(LabelSucc, []byte(oldID), []byte(newID), ikNew)
}

// RcptBytes is the relay receipt statement of 4.4 (label cx1/rcpt) and GRcptBytes its group twin (5.3).
func RcptBytes(hdr []byte, seq, at uint64) []byte { return Labeled(LabelRcpt, hdr, U64(seq), U64(at)) }
func GRcptBytes(hdr []byte, seq, at uint64) []byte {
	return Labeled(LabelGRcpt, hdr, U64(seq), U64(at))
}

// AttRepBytes is the reputation attestation of 5.6: id | root | rep i32 | day.
func AttRepBytes(id, root string, rep int32, day uint32) []byte {
	return Labeled(LabelAttRep, []byte(id), []byte(root), U32(uint32(rep)), U32(day))
}

// Sign and Verify are the generic Ed25519 helpers over a prepared statement.
func Sign(sk ed25519.PrivateKey, statement []byte) []byte { return ed25519.Sign(sk, statement) }

func Verify(pk, statement, sig []byte) bool {
	return len(pk) == 32 && len(sig) == 64 && ed25519.Verify(ed25519.PublicKey(pk), statement, sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
