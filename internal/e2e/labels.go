// Package e2e is the pure cryptographic core of the sealed lane (docs/SECURITY-E2EE-v2.md, SPEC-v2 26):
// labels, suites, seed derivations, padding, the cxm1 pairwise envelope, the cxg1 group protocol, the sealed
// state blob, the cxs1 symmetric lane and the seal1:/seal2: value formats, bundle and request canonical
// bytes, RFC 6962 Merkle proofs and the directory verification rule as a pure function. Standard library
// only; no database, no HTTP. Every comparison of a tag, commitment or signature is constant time.
package e2e

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
)

// Domain-separation labels (E2EE 2.3). This file is the only place a label literal may appear
// (TestLabelsLint). Every signed, MACed or derived input is label || 0x00 || payload (Labeled); a
// derivation whose info is the bare label (no payload) uses the label alone.
const (
	LabelBundle    = "cx1/bundle"
	LabelRotate    = "cx1/rotate"
	LabelSucc      = "cx1/succ"
	LabelReq       = "cx1/req"
	LabelResp      = "cx1/resp"
	LabelRcpt      = "cx1/rcpt"
	LabelGRcpt     = "cx1/grcpt"
	LabelSTH       = "cx1/sth"
	LabelWitness   = "cx1/witness"
	LabelCert      = "cx1/cert"
	LabelLedger    = "cx1/ledger"
	LabelPolicy    = "cx1/policy"
	LabelAttRep    = "cx1/att-rep"
	LabelMail      = "cx1/mail"
	LabelAuth      = "cx1/auth"
	LabelAuthMAC   = "cx1/auth-mac"
	LabelFrank     = "cx1/frank"
	LabelGCtx      = "cx1/gctx"
	LabelEpoch     = "cx1/epoch"
	LabelInit      = "cx1/init"
	LabelConfirm   = "cx1/confirm"
	LabelMsg       = "cx1/msg"
	LabelGMsg      = "cx1/gmsg"
	LabelGObj      = "cx1/gobj"
	LabelGCommit   = "cx1/gcommit"
	LabelGWelcome  = "cx1/gwelcome"
	LabelGSig      = "cx1/gsig"
	LabelGFrank    = "cx1/gfrank"
	LabelState     = "cx1/state"
	LabelAtt       = "cx1/att"
	LabelSnap      = "cx1/snap"
	LabelShare     = "cx1/share"
	LabelLoc       = "cx1/loc"
	LabelKey       = "cx1/key"
	LabelDWrite    = "cx1/d-write"
	LabelFP        = "cx1/fp"
	LabelRegID     = "cx1/regid"
	LabelStamp     = "cx1/stamp"
	LabelOHTTP     = "cx1/ohttp"
	LabelOHTTPResp = "cx1/ohttp-resp"
	LabelCXS1      = "cxs1"

	// Seed derivations (E2EE 2.4) and the sealed-memory keys of SPEC-v2 26.4.
	LabelIK      = "cx1/ik"
	LabelRK      = "cx1/rk"
	LabelAK      = "cx1/ak"
	LabelLK      = "cx1/lk/"  // + decimal cs
	LabelEK      = "cx1/ek/"  // + decimal cs + "/" + u32 epoch
	LabelSub     = "cx1/sub/" // + subid
	LabelMLDSA   = "cx1/mldsa"
	LabelMK      = "cx-mk"
	LabelMKRec   = "cx-mk-recovery"
	LabelSealV1  = "cx-seal-v1"
	LabelSealMAC = "mac"

	// DefaultSalt is the HKDF salt everywhere a per-message salt is not specified (E2EE 2.3).
	DefaultSalt = "agents.ekaii.fr/cx1"

	// Seal1Prefix and Seal2Prefix mark sealed memory values (26.4); Cxs1Prefix marks drop bodies.
	Seal1Prefix = "seal1:"
	Seal2Prefix = "seal2:"
	Cxs1Prefix  = "cxs1:"
)

// Labels lists every label, for the lint test and the vector generator.
var Labels = []string{LabelBundle, LabelRotate, LabelSucc, LabelReq, LabelResp, LabelRcpt, LabelGRcpt, LabelSTH,
	LabelWitness, LabelCert, LabelLedger, LabelPolicy, LabelAttRep, LabelMail, LabelAuth, LabelAuthMAC, LabelFrank,
	LabelGCtx, LabelEpoch, LabelInit, LabelConfirm, LabelMsg, LabelGMsg, LabelGObj, LabelGCommit, LabelGWelcome,
	LabelGSig, LabelGFrank, LabelState, LabelAtt, LabelSnap, LabelShare, LabelLoc, LabelKey, LabelDWrite, LabelFP,
	LabelRegID, LabelStamp, LabelOHTTP, LabelOHTTPResp, LabelCXS1, LabelIK, LabelRK, LabelAK, LabelLK, LabelEK,
	LabelSub, LabelMLDSA, LabelMK, LabelMKRec, LabelSealV1, LabelSealMAC}

// Labeled returns label || 0x00 || parts... (the bare label when there are no parts).
func Labeled(label string, parts ...[]byte) []byte {
	n := len(label)
	if len(parts) > 0 {
		n++
	}
	for _, p := range parts {
		n += len(p)
	}
	b := make([]byte, 0, n)
	b = append(b, label...)
	if len(parts) > 0 {
		b = append(b, 0)
	}
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// HKDF is hkdf.Key(sha256.New, secret, salt, info, n); salt nil means DefaultSalt.
func HKDF(secret, salt []byte, info string, n int) []byte {
	if salt == nil {
		salt = []byte(DefaultSalt)
	}
	k, err := hkdf.Key(sha256.New, secret, salt, info, n)
	if err != nil {
		panic("e2e: hkdf: " + err.Error())
	}
	return k
}

// Extract and Expand expose HKDF-Extract and HKDF-Expand with SHA-256 (the cxg1 schedule, E2EE 5.2).
func Extract(salt, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha256.New, ikm, salt)
	if err != nil {
		panic("e2e: hkdf extract: " + err.Error())
	}
	return prk
}

func Expand(prk []byte, info string, n int) []byte {
	k, err := hkdf.Expand(sha256.New, prk, info, n)
	if err != nil {
		panic("e2e: hkdf expand: " + err.Error())
	}
	return k
}

// Fixed-width big-endian integers (E2EE 2.3).
func U16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func U32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func U64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// Sum is sha256 over the concatenation of parts.
func Sum(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// cat concatenates byte slices into a fresh slice.
func cat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	b := make([]byte, 0, n)
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}
