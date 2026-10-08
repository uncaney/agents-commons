package e2e

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// cxm1 pairwise envelope (E2EE 4.1-4.4): raw body, server cap 6144 bytes.
//
//	0   1  ver=0x01 | 1  1  cs | 2  1  flags | 3  7  from | 10  7  to | 17  4  epoch u32 | 21  2  pol u16
//	23  16 mid | 39  32 C (franking commitment) | 71 enc | ct = padded inner + 16 | mac 32
//
// Bytes 0..70 are hdr: the HPKE AAD, stored in clear by the server. Inner plaintext before padding is
// kf 32 | ts u32 | type u8 | len u16 | payload[len], padded to a MailBuckets size.

const (
	EnvVer      = 1
	HdrLen      = 71
	MailCap     = 6144
	MACLen      = 32
	MidLen      = 16
	InnerHdrLen = 32 + 4 + 1 + 2
	MaxPayload  = 4096 - InnerHdrLen - 1 // one byte of padding is always present

	FlagLT    = 1 << 0 // sealed to lk, epoch = 0
	FlagATT   = 1 << 1 // payload carries attachment refs
	FlagCTRL  = 1 << 2 // control message (4.7)
	FlagRESET = 1 << 3
	FlagTOFU  = 1 << 4 // sender verified the key at tier D

	TypeText    = 0
	TypeJSON    = 1
	TypeCtrl    = 2
	TypeReceipt = 3
)

var (
	ErrEnvelope = errors.New("e2e: bad envelope")
	ErrSizeBkt  = errors.New("e2e: size bucket")
	ErrMAC      = errors.New("e2e: sender mac invalid")
	ErrOpen     = errors.New("e2e: open failed")
	ErrInner    = errors.New("e2e: bad inner plaintext")
	ErrFrank    = errors.New("e2e: franking commitment mismatch")
	ErrNotMine  = errors.New("e2e: envelope addressed to another id")
)

type Hdr struct {
	CS       Suite
	Flags    uint8
	From, To string
	Epoch    uint32
	Pol      uint16
	Mid, C   []byte
}

const hdrFlagsMask = FlagLT | FlagATT | FlagCTRL | FlagRESET | FlagTOFU

// Marshal renders the 71-byte header.
func (h *Hdr) Marshal() []byte {
	out := make([]byte, 0, HdrLen)
	out = append(out, EnvVer, byte(h.CS), h.Flags)
	out = append(out, h.From...)
	out = append(out, h.To...)
	out = append(out, U32(h.Epoch)...)
	out = append(out, U16(h.Pol)...)
	out = append(out, h.Mid...)
	out = append(out, h.C...)
	return out
}

func (h *Hdr) check() error {
	switch {
	case !h.CS.Valid():
		return fmt.Errorf("%w: cs", ErrEnvelope)
	case h.Flags&^hdrFlagsMask != 0:
		return fmt.Errorf("%w: flags", ErrEnvelope)
	case !ValidID(h.From) || !ValidID(h.To):
		return fmt.Errorf("%w: ids", ErrEnvelope)
	case (h.Flags&FlagLT != 0) != (h.Epoch == 0):
		return fmt.Errorf("%w: epoch/LT", ErrEnvelope)
	case len(h.Mid) != MidLen || len(h.C) != 32:
		return fmt.Errorf("%w: mid/C", ErrEnvelope)
	}
	return nil
}

// ParseHdr decodes exactly 71 bytes.
func ParseHdr(b []byte) (*Hdr, error) {
	if len(b) != HdrLen {
		return nil, fmt.Errorf("%w: header length", ErrEnvelope)
	}
	if b[0] != EnvVer {
		return nil, fmt.Errorf("%w: version", ErrEnvelope)
	}
	r := reader8{b: b, i: 1}
	h := &Hdr{CS: Suite(r.u8()), Flags: r.u8()}
	h.From, h.To = string(r.take(IDLen)), string(r.take(IDLen))
	h.Epoch, h.Pol = r.u32(), r.u16()
	h.Mid, h.C = r.take(MidLen), r.take(32)
	if r.err {
		return nil, fmt.Errorf("%w: header", ErrEnvelope)
	}
	return h, h.check()
}

type Envelope struct {
	Hdr
	Enc, CT, MAC []byte
	hdr          []byte
}

// EnvelopeSize is the total size for a suite and a plaintext bucket.
func EnvelopeSize(cs Suite, bucket int) int { return HdrLen + cs.EncSize() + bucket + 16 + MACLen }

// ParseEnvelope decodes strictly: the length must equal EnvelopeSize for the header's suite and a mail
// bucket, which also forces enc to match cs.
func ParseEnvelope(b []byte) (*Envelope, error) {
	if len(b) > MailCap {
		return nil, fmt.Errorf("%w: cap", ErrSizeBkt)
	}
	if len(b) < HdrLen {
		return nil, fmt.Errorf("%w: short", ErrEnvelope)
	}
	h, err := ParseHdr(b[:HdrLen])
	if err != nil {
		return nil, err
	}
	bucket := len(b) - HdrLen - h.CS.EncSize() - 16 - MACLen
	if !IsBucket(bucket, MailBuckets) {
		return nil, ErrSizeBkt
	}
	e := &Envelope{Hdr: *h, hdr: b[:HdrLen:HdrLen]}
	i := HdrLen
	e.Enc = b[i : i+h.CS.EncSize() : i+h.CS.EncSize()]
	i += h.CS.EncSize()
	e.CT = b[i : i+bucket+16 : i+bucket+16]
	i += bucket + 16
	e.MAC = b[i : i+MACLen : i+MACLen]
	return e, nil
}

// Bytes re-serializes the envelope; HdrBytes is the 71-byte AAD.
func (e *Envelope) Bytes() []byte { return cat(e.HdrBytes(), e.Enc, e.CT, e.MAC) }

func (e *Envelope) HdrBytes() []byte {
	if e.hdr == nil {
		e.hdr = e.Hdr.Marshal()
	}
	return e.hdr
}

// Bucket is the padded plaintext size.
func (e *Envelope) Bucket() int { return len(e.CT) - 16 }

type Inner struct {
	KF      []byte
	TS      uint32
	Type    uint8
	Payload []byte
}

func (in *Inner) Marshal() ([]byte, error) {
	if len(in.KF) != 32 || len(in.Payload) > MaxPayload {
		return nil, ErrInner
	}
	out := make([]byte, 0, InnerHdrLen+len(in.Payload))
	out = append(out, in.KF...)
	out = append(out, U32(in.TS)...)
	out = append(out, in.Type)
	out = append(out, U16(uint16(len(in.Payload)))...)
	return append(out, in.Payload...), nil
}

// ParseInner decodes an unpadded inner plaintext; len must account for every byte.
func ParseInner(b []byte) (*Inner, error) {
	if len(b) < InnerHdrLen {
		return nil, ErrInner
	}
	r := reader8{b: b}
	in := &Inner{KF: r.take(32), TS: r.u32(), Type: r.u8()}
	n := int(r.u16())
	in.Payload = r.take(n)
	if r.err || r.i != len(b) || n > MaxPayload {
		return nil, ErrInner
	}
	return in, nil
}

// Frank is the franking commitment C = HMAC-SHA256(kf, "cx1/frank" || from || to || mid || type || u16(len) || payload).
func Frank(kf []byte, from, to string, mid []byte, typ uint8, payload []byte) []byte {
	m := hmac.New(sha256.New, kf)
	m.Write(Labeled(LabelFrank, []byte(from), []byte(to), mid, []byte{typ}, U16(uint16(len(payload))), payload))
	return m.Sum(nil)
}

// VerifyFrank recomputes C from a disclosed (kf, type, payload) and compares in constant time (reports, 8.3).
func VerifyFrank(h *Hdr, kf []byte, typ uint8, payload []byte) bool {
	if len(kf) != 32 || len(payload) > MaxPayload {
		return false
	}
	return hmac.Equal(Frank(kf, h.From, h.To, h.Mid, typ, payload), h.C)
}

// MailInfo is the HPKE info "cx1/mail" || from || to || u32(epoch).
func MailInfo(from, to string, epoch uint32) []byte {
	return Labeled(LabelMail, []byte(from), []byte(to), U32(epoch))
}

// AuthKey derives k_auth = HKDF(ss, salt = exporter, info = "cx1/auth" || from || to, 32) (E2EE 4.3).
func AuthKey(ss, exporter []byte, from, to string) []byte {
	return HKDF(ss, exporter, string(Labeled(LabelAuth, []byte(from), []byte(to))), 32)
}

// SenderMAC is HMAC-SHA256(k_auth, "cx1/auth-mac" || hdr || enc || ct).
func SenderMAC(kAuth, hdr, enc, ct []byte) []byte {
	m := hmac.New(sha256.New, kAuth)
	m.Write(Labeled(LabelAuthMAC, hdr, enc, ct))
	return m.Sum(nil)
}

type SealParams struct {
	CS       Suite
	Flags    uint8
	From, To string
	Epoch    uint32 // 0 with FlagLT
	Pol      uint16
	Mid, KF  []byte // 16 and 32 bytes; drawn from Rand when nil
	TS       uint32
	Type     uint8
	Payload  []byte

	RecipientKey []byte           // serialized ek(cs, epoch), or lk with FlagLT, from the DVR-verified bundle
	SenderAK     *ecdh.PrivateKey // ak of the sender
	RecipientAK  []byte           // ak of the recipient (32 bytes, from the bundle)
	MinBucket    int              // force at least this bucket (0 = smallest fitting)
	Rand         io.Reader        // nil = crypto/rand
}

// Sealed carries the envelope and the intermediates the vectors record.
type Sealed struct {
	Envelope []byte
	Hdr      []byte
	Enc, CT  []byte
	MAC      []byte
	Exporter []byte
	KAuth    []byte
	Padded   []byte
}

// Seal builds a cxm1 envelope. The recipient key must already have passed the DVR.
func Seal(p SealParams) (*Sealed, error) {
	rnd := reader(p.Rand)
	if p.Mid == nil {
		p.Mid = make([]byte, MidLen)
		if _, err := io.ReadFull(rnd, p.Mid); err != nil {
			return nil, err
		}
	}
	if p.KF == nil {
		p.KF = make([]byte, 32)
		if _, err := io.ReadFull(rnd, p.KF); err != nil {
			return nil, err
		}
	}
	if p.SenderAK == nil || len(p.RecipientAK) != 32 {
		return nil, fmt.Errorf("%w: auth keys", ErrEnvelope)
	}
	inner, err := (&Inner{KF: p.KF, TS: p.TS, Type: p.Type, Payload: p.Payload}).Marshal()
	if err != nil {
		return nil, err
	}
	buckets := MailBuckets
	if p.MinBucket > 0 {
		for i, b := range MailBuckets {
			if b >= p.MinBucket {
				buckets = MailBuckets[i:]
				break
			}
		}
	}
	padded, err := Pad(inner, buckets)
	if err != nil {
		return nil, err
	}
	h := Hdr{CS: p.CS, Flags: p.Flags, From: p.From, To: p.To, Epoch: p.Epoch, Pol: p.Pol, Mid: p.Mid,
		C: Frank(p.KF, p.From, p.To, p.Mid, p.Type, p.Payload)}
	if err := h.check(); err != nil {
		return nil, err
	}
	hdr := h.Marshal()
	pk, err := p.CS.NewPublicKey(p.RecipientKey)
	if err != nil {
		return nil, err
	}
	enc, s, err := hpke.NewSender(pk, KDF(), AEAD(), MailInfo(p.From, p.To, p.Epoch))
	if err != nil {
		return nil, err
	}
	ct, err := s.Seal(hdr, padded)
	if err != nil {
		return nil, err
	}
	exporter, err := s.Export(LabelAuth, 32)
	if err != nil {
		return nil, err
	}
	rpk, err := ecdh.X25519().NewPublicKey(p.RecipientAK)
	if err != nil {
		return nil, err
	}
	ss, err := p.SenderAK.ECDH(rpk)
	if err != nil {
		return nil, err
	}
	kAuth := AuthKey(ss, exporter, p.From, p.To)
	mac := SenderMAC(kAuth, hdr, enc, ct)
	return &Sealed{Envelope: cat(hdr, enc, ct, mac), Hdr: hdr, Enc: enc, CT: ct, MAC: mac, Exporter: exporter,
		KAuth: kAuth, Padded: padded}, nil
}

type OpenParams struct {
	Me           string          // expected hdr.To
	RecipientKey hpke.PrivateKey // sk for (hdr.CS, hdr.Epoch), or lk with FlagLT
	RecipientAK  *ecdh.PrivateKey
	SenderAK     []byte // from the directory entry current at `at`
}

// Open verifies the sender MAC, decrypts, unpads and checks the franking commitment, in that order.
// Any failure returns before the agent sees a byte.
func (e *Envelope) Open(p OpenParams) (*Inner, error) {
	if e.To != p.Me {
		return nil, ErrNotMine
	}
	if p.RecipientKey == nil || p.RecipientAK == nil || len(p.SenderAK) != 32 {
		return nil, fmt.Errorf("%w: keys", ErrOpen)
	}
	hdr := e.HdrBytes()
	r, err := hpke.NewRecipient(e.Enc, p.RecipientKey, KDF(), AEAD(), MailInfo(e.From, e.To, e.Epoch))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpen, err)
	}
	exporter, err := r.Export(LabelAuth, 32)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpen, err)
	}
	spk, err := ecdh.X25519().NewPublicKey(p.SenderAK)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMAC, err)
	}
	ss, err := p.RecipientAK.ECDH(spk)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMAC, err)
	}
	if !hmac.Equal(SenderMAC(AuthKey(ss, exporter, e.From, e.To), hdr, e.Enc, e.CT), e.MAC) {
		return nil, ErrMAC
	}
	padded, err := r.Open(hdr, e.CT)
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := Unpad(padded)
	if err != nil {
		return nil, ErrInner
	}
	in, err := ParseInner(pt)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(Frank(in.KF, e.From, e.To, e.Mid, in.Type, in.Payload), e.C) {
		return nil, ErrFrank
	}
	return in, nil
}

// SignRcpt and VerifyRcpt are the relay receipt of 4.4: Ed25519(online_sk, "cx1/rcpt" || hdr || u64(seq) || u64(at)).
func SignRcpt(onlineSK ed25519.PrivateKey, hdr []byte, seq, at uint64) []byte {
	return ed25519.Sign(onlineSK, RcptBytes(hdr, seq, at))
}

func VerifyRcpt(onlinePK, hdr []byte, seq, at uint64, sig []byte) bool {
	return len(hdr) == HdrLen && Verify(onlinePK, RcptBytes(hdr, seq, at), sig)
}

// StampPrefix is the PoW statement prefix of the first-contact stamp (8.1):
// "cx1/stamp:" + to + ":" + hex(sha256(body)) + ":" + YYYYMMDD.
func StampPrefix(to string, body []byte, day string) string {
	return LabelStamp + ":" + to + ":" + hex.EncodeToString(Sum(body)) + ":" + day
}
