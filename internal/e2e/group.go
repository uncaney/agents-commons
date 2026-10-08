package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// cxg1 group protocol (E2EE 5): MLS-shaped flat epochs, one HPKE seal per member per commit, the server
// as a content-blind Delivery Service. Row header (85 bytes, cleartext = AAD):
//
//	ver u8=1 | kind u8 | gid(7) | epoch u32 | idx u16 | gen u32 | pol u16 | s[32] | C[32]

const (
	GHdrLen       = 85
	GKindApp      = 1
	GKindCommit   = 2
	GKindProposal = 3
	GKindWelcome  = 4
	GKindObject   = 5

	CTypeText        = 1
	CTypeStateOp     = 2
	CTypeSnapshotRef = 3
	CTypeBallot      = 4

	CommitHdrCap  = 4096
	GroupRowCap   = 16384
	CommitCap     = 65536
	MaxMembersCS1 = 64
	MaxMembersCS2 = 48
	GCtxLen       = len(LabelGCtx) + 1 + IDLen + 4 + 32 + 32
	OIDLen        = 16
	BlindTagLen   = 16
	MaxBlindTags  = 32
	WelcomeExtCap = 4096
	ObjPayloadCap = 65536 - 32 - 2 - 1
)

var (
	ErrGroup    = errors.New("e2e: bad group row")
	ErrGSig     = errors.New("e2e: group signature invalid")
	ErrConfTag  = errors.New("e2e: confirmation tag mismatch")
	ErrOrder    = errors.New("e2e: commit built on another transcript (err order)")
	ErrNoEnv    = errors.New("e2e: commit carries no envelope for this member")
	InitSecret0 = make([]byte, 32)
)

type GHdr struct {
	Kind  uint8
	GID   string
	Epoch uint32
	Idx   uint16
	Gen   uint32
	Pol   uint16
	S, C  []byte
}

func (h *GHdr) Marshal() []byte {
	out := make([]byte, 0, GHdrLen)
	out = append(out, 1, h.Kind)
	out = append(out, h.GID...)
	out = append(out, U32(h.Epoch)...)
	out = append(out, U16(h.Idx)...)
	out = append(out, U32(h.Gen)...)
	out = append(out, U16(h.Pol)...)
	out = append(out, h.S...)
	out = append(out, h.C...)
	return out
}

func (h *GHdr) check() error {
	if h.Kind < GKindApp || h.Kind > GKindObject || !ValidID(h.GID) || len(h.S) != 32 || len(h.C) != 32 {
		return fmt.Errorf("%w: header", ErrGroup)
	}
	return nil
}

func ParseGHdr(b []byte) (*GHdr, error) {
	if len(b) != GHdrLen || b[0] != 1 {
		return nil, fmt.Errorf("%w: header", ErrGroup)
	}
	r := reader8{b: b, i: 1}
	h := &GHdr{Kind: r.u8(), GID: string(r.take(IDLen))}
	h.Epoch, h.Idx, h.Gen, h.Pol = r.u32(), r.u16(), r.u32(), r.u16()
	h.S, h.C = r.take(32), r.take(32)
	if r.err {
		return nil, fmt.Errorf("%w: header", ErrGroup)
	}
	return h, h.check()
}

// Member is a roster entry; RosterHash is sha256 over the entries sorted by idx, each as
// u16(idx) || id || ik || u64(leaf), so two members whose directories disagree about a key cannot
// compute the same GroupContext.
type Member struct {
	Idx  uint16
	ID   string
	IK   []byte
	Leaf uint64
}

func RosterHash(members []Member) []byte {
	ms := append([]Member(nil), members...)
	sort.Slice(ms, func(i, j int) bool { return ms[i].Idx < ms[j].Idx })
	h := sha256.New()
	for _, m := range ms {
		h.Write(U16(m.Idx))
		h.Write([]byte(m.ID))
		h.Write(m.IK)
		h.Write(U64(m.Leaf))
	}
	return h.Sum(nil)
}

// GroupContext is "cx1/gctx" || 0x00 || gid || u32(e) || roster_hash_e || confirmed_th_{e-1} (84 bytes).
func GroupContext(gid string, e uint32, rosterHash, thPrev []byte) []byte {
	return Labeled(LabelGCtx, []byte(gid), U32(e), rosterHash, thPrev)
}

// ParseGroupContext splits a GroupContext back into its fields.
func ParseGroupContext(g []byte) (gid string, e uint32, rosterHash, thPrev []byte, err error) {
	if len(g) != GCtxLen || string(g[:len(LabelGCtx)+1]) != LabelGCtx+"\x00" {
		return "", 0, nil, nil, fmt.Errorf("%w: group context", ErrGroup)
	}
	r := reader8{b: g, i: len(LabelGCtx) + 1}
	gid, e = string(r.take(IDLen)), r.u32()
	rosterHash, thPrev = r.take(32), r.take(32)
	if !ValidID(gid) {
		return "", 0, nil, nil, fmt.Errorf("%w: group context", ErrGroup)
	}
	return
}

// EpochSecrets is the cxg1 key schedule output (E2EE 5.2).
type EpochSecrets struct {
	Joiner, Epoch, Init, Confirm, MsgRoot []byte
}

// Schedule derives epoch e from init_secret_{e-1}, the committer's commit_secret and GroupContext_e.
func Schedule(initPrev, commitSecret, gctx []byte) EpochSecrets {
	return ScheduleFromJoiner(Extract(initPrev, commitSecret), gctx)
}

// ScheduleFromJoiner is what a Welcome recipient runs (it never learns init_secret_{e-1}).
func ScheduleFromJoiner(joiner, gctx []byte) EpochSecrets {
	s := EpochSecrets{Joiner: joiner}
	s.Epoch = Expand(joiner, string(Labeled(LabelEpoch, gctx)), 32)
	s.Init = Expand(s.Epoch, LabelInit, 32)
	s.Confirm = Expand(s.Epoch, LabelConfirm, 32)
	s.MsgRoot = Expand(s.Epoch, LabelMsg, 32)
	return s
}

// TranscriptHash is th_e = sha256(confirmed_th_{e-1} || clear_hdr_json || envs); ConfirmedTH is
// sha256(th_e || conf_tag_e); ConfTag is HMAC(confirmation_key_e, th_e).
func TranscriptHash(thPrev, clearHdrJSON, envs []byte) []byte { return Sum(thPrev, clearHdrJSON, envs) }

func ConfirmedTH(th, confTag []byte) []byte { return Sum(th, confTag) }

func ConfTag(confirmKey, th []byte) []byte {
	m := hmac.New(sha256.New, confirmKey)
	m.Write(th)
	return m.Sum(nil)
}

// MsgKey is k_m = HKDF(msg_root_e, salt = s, info = "cx1/gmsg" || gid || u32(e) || u16(idx), 32).
func MsgKey(msgRoot, s []byte, gid string, e uint32, idx uint16) []byte {
	return HKDF(msgRoot, s, string(Labeled(LabelGMsg, []byte(gid), U32(e), U16(idx))), 32)
}

// ObjKey is k_o = HKDF(msg_root_e, salt = s, "cx1/gobj" || gid || oid || u32(ver), 32).
func ObjKey(msgRoot, s []byte, gid string, oid []byte, ver uint32) []byte {
	return HKDF(msgRoot, s, string(Labeled(LabelGObj, []byte(gid), oid, U32(ver))), 32)
}

// GFrank is the group franking commitment over gid || u32(epoch) || u16(idx) || u32(gen) || ctype || u16(len) || payload.
func GFrank(kf []byte, gid string, e uint32, idx uint16, gen uint32, ctype uint8, payload []byte) []byte {
	m := hmac.New(sha256.New, kf)
	m.Write(Labeled(LabelGFrank, []byte(gid), U32(e), U16(idx), U32(gen), []byte{ctype}, U16(uint16(len(payload))), payload))
	return m.Sum(nil)
}

// GSig signs "cx1/gsig" || parts with the member's ik.
func GSig(ik ed25519.PrivateKey, parts ...[]byte) []byte {
	return ed25519.Sign(ik, Labeled(LabelGSig, parts...))
}

func verifyGSig(ikPub, sig []byte, parts ...[]byte) bool {
	return Verify(ikPub, Labeled(LabelGSig, parts...), sig)
}

// EKH is the 8-hex-char hint of the recipient key a commit sealed to.
func EKH(key []byte) string { return hex.EncodeToString(Sum(key))[:8] }

// ---- app messages (kind 1): hdr | ct | sig[64]

type AppParams struct {
	GID     string
	Epoch   uint32
	Idx     uint16
	Gen     uint32
	Pol     uint16
	KF      []byte // 32, drawn when nil
	S       []byte // 32 fresh salt, drawn when nil
	CType   uint8
	Payload []byte
	MsgRoot []byte
	IK      ed25519.PrivateKey
	Rand    io.Reader
}

type SealedApp struct {
	Row, Hdr, CT, Sig, Key, Padded []byte
}

// SealApp seals an app message: pt = kf | ctype | u16 len | payload, padded to GroupBuckets.
func SealApp(p AppParams) (*SealedApp, error) {
	rnd := reader(p.Rand)
	var err error
	if p.KF, err = fill(p.KF, 32, rnd); err != nil {
		return nil, err
	}
	if p.S, err = fill(p.S, 32, rnd); err != nil {
		return nil, err
	}
	if len(p.Payload) > 4096-35-1 || len(p.MsgRoot) != 32 || p.IK == nil {
		return nil, fmt.Errorf("%w: app params", ErrGroup)
	}
	pt := cat(p.KF, []byte{p.CType}, U16(uint16(len(p.Payload))), p.Payload)
	padded, err := Pad(pt, GroupBuckets)
	if err != nil {
		return nil, err
	}
	h := GHdr{Kind: GKindApp, GID: p.GID, Epoch: p.Epoch, Idx: p.Idx, Gen: p.Gen, Pol: p.Pol, S: p.S,
		C: GFrank(p.KF, p.GID, p.Epoch, p.Idx, p.Gen, p.CType, p.Payload)}
	if err := h.check(); err != nil {
		return nil, err
	}
	hdr := h.Marshal()
	key := MsgKey(p.MsgRoot, p.S, p.GID, p.Epoch, p.Idx)
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	ct := g.Seal(nil, zeroNonce, padded, hdr)
	sig := GSig(p.IK, hdr, ct)
	return &SealedApp{Row: cat(hdr, ct, sig), Hdr: hdr, CT: ct, Sig: sig, Key: key, Padded: padded}, nil
}

type AppMsg struct {
	Hdr     *GHdr
	CT, Sig []byte
	hdr     []byte
}

type AppInner struct {
	KF      []byte
	CType   uint8
	Payload []byte
}

func ParseApp(row []byte) (*AppMsg, error) {
	if len(row) > GroupRowCap || len(row) < GHdrLen+16+64 {
		return nil, fmt.Errorf("%w: app length", ErrGroup)
	}
	h, err := ParseGHdr(row[:GHdrLen])
	if err != nil {
		return nil, err
	}
	if h.Kind != GKindApp {
		return nil, fmt.Errorf("%w: kind", ErrGroup)
	}
	ctLen := len(row) - GHdrLen - 64
	if !IsBucket(ctLen-16, GroupBuckets) {
		return nil, ErrSizeBkt
	}
	return &AppMsg{Hdr: h, CT: row[GHdrLen : GHdrLen+ctLen : GHdrLen+ctLen], Sig: row[GHdrLen+ctLen:], hdr: row[:GHdrLen:GHdrLen]}, nil
}

func (m *AppMsg) VerifySig(ikPub []byte) bool { return verifyGSig(ikPub, m.Sig, m.hdr, m.CT) }

// Open decrypts under the epoch's msg_root and checks the franking commitment.
func (m *AppMsg) Open(msgRoot []byte) (*AppInner, error) {
	g, err := gcm(MsgKey(msgRoot, m.Hdr.S, m.Hdr.GID, m.Hdr.Epoch, m.Hdr.Idx))
	if err != nil {
		return nil, err
	}
	padded, err := g.Open(nil, zeroNonce, m.CT, m.hdr)
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := Unpad(padded)
	if err != nil || len(pt) < 35 {
		return nil, ErrInner
	}
	r := reader8{b: pt}
	in := &AppInner{KF: r.take(32), CType: r.u8()}
	n := int(r.u16())
	in.Payload = r.take(n)
	if r.err || r.i != len(pt) {
		return nil, ErrInner
	}
	if !hmac.Equal(GFrank(in.KF, m.Hdr.GID, m.Hdr.Epoch, m.Hdr.Idx, m.Hdr.Gen, in.CType, in.Payload), m.Hdr.C) {
		return nil, ErrFrank
	}
	return in, nil
}

// ---- commits (kind 2): hdr (s, C zero) | u16 jlen | clear_hdr_json | envs | conf_tag[32] | sig[64]
// envs = n u16 | n x (idx u16 | enc | ct(48)), each ct = hpke.Seal(member key, "cx1/gcommit" || gid || u32(e), commit_secret).

type Added struct {
	ID   string `json:"id"`
	Leaf uint64 `json:"leaf"`
	EKH  string `json:"ekh"`
}

// CommitHeader is the cleartext commit header the server validates. TH is the hex of the confirmed
// transcript hash the committer built on (confirmed_th_{e-1}); members refuse a commit whose TH is not
// their own view (ErrOrder).
type CommitHeader struct {
	E   uint32          `json:"e"`
	By  uint16          `json:"by"`
	Add []Added         `json:"add,omitempty"`
	Rm  []uint16        `json:"rm,omitempty"`
	Upd bool            `json:"upd,omitempty"`
	PP  []uint64        `json:"pp,omitempty"`
	TH  string          `json:"th"`
	Ext json.RawMessage `json:"ext,omitempty"`
}

// ParseCommitHeader decodes strictly (unknown fields refused, 4 KiB cap, shapes checked).
func ParseCommitHeader(b []byte) (*CommitHeader, error) {
	if len(b) > CommitHdrCap {
		return nil, fmt.Errorf("%w: commit header cap", ErrGroup)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var h CommitHeader
	if err := dec.Decode(&h); err != nil {
		return nil, fmt.Errorf("%w: commit header: %v", ErrGroup, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: commit header trailer", ErrGroup)
	}
	if th, err := hex.DecodeString(h.TH); err != nil || len(th) != 32 || h.E == 0 || len(h.Add) > MaxMembersCS1 || len(h.Rm) > MaxMembersCS1 || len(h.PP) > 256 {
		return nil, fmt.Errorf("%w: commit header fields", ErrGroup)
	}
	for _, a := range h.Add {
		if !ValidID(a.ID) || len(a.EKH) != 8 {
			return nil, fmt.Errorf("%w: commit header add", ErrGroup)
		}
		if _, err := hex.DecodeString(a.EKH); err != nil {
			return nil, fmt.Errorf("%w: commit header add", ErrGroup)
		}
	}
	if len(h.Ext) > 0 && !json.Valid(h.Ext) {
		return nil, fmt.Errorf("%w: commit header ext", ErrGroup)
	}
	return &h, nil
}

// Fanout names one member the commit seals to (all members of a group share one suite).
type Fanout struct {
	Idx uint16
	Key []byte // serialized ek or lk
}

type CommitParams struct {
	GID          string
	CS           Suite
	Epoch        uint32 // the new epoch e
	Idx          uint16 // committer
	Gen          uint32
	Pol          uint16
	Header       CommitHeader // TH is filled from THPrev
	Members      []Fanout
	CommitSecret []byte // 32, drawn when nil
	InitPrev     []byte // init_secret_{e-1} (InitSecret0 for a new group)
	THPrev       []byte // confirmed_th_{e-1} (32 zero bytes for a new group)
	RosterHash   []byte // roster_hash_e over the roster after this commit
	IK           ed25519.PrivateKey
	Rand         io.Reader
}

type BuiltCommit struct {
	Row, Hdr, JSON, Envs, TH, ConfTag, ConfirmedTH, Sig, GCtx []byte
	Secrets                                                   EpochSecrets
	CommitSecret                                              []byte
}

func BuildCommit(p CommitParams) (*BuiltCommit, error) {
	var err error
	if p.CommitSecret, err = fill(p.CommitSecret, 32, reader(p.Rand)); err != nil {
		return nil, err
	}
	if !p.CS.Valid() || len(p.InitPrev) != 32 || len(p.THPrev) != 32 || len(p.RosterHash) != 32 || p.IK == nil || len(p.Members) == 0 {
		return nil, fmt.Errorf("%w: commit params", ErrGroup)
	}
	if max := MaxMembersCS1; (p.CS == CS2 && len(p.Members) > MaxMembersCS2) || len(p.Members) > max {
		return nil, fmt.Errorf("%w: too many members", ErrGroup)
	}
	p.Header.E, p.Header.By, p.Header.TH = p.Epoch, p.Idx, hex.EncodeToString(p.THPrev)
	js, err := json.Marshal(&p.Header)
	if err != nil {
		return nil, err
	}
	if len(js) > CommitHdrCap {
		return nil, fmt.Errorf("%w: commit header cap", ErrGroup)
	}
	info := Labeled(LabelGCommit, []byte(p.GID), U32(p.Epoch))
	envs := U16(uint16(len(p.Members)))
	for _, m := range p.Members {
		pk, err := p.CS.NewPublicKey(m.Key)
		if err != nil {
			return nil, err
		}
		sealed, err := hpke.Seal(pk, KDF(), AEAD(), info, p.CommitSecret)
		if err != nil {
			return nil, err
		}
		envs = append(envs, U16(m.Idx)...)
		envs = append(envs, sealed...)
	}
	h := GHdr{Kind: GKindCommit, GID: p.GID, Epoch: p.Epoch, Idx: p.Idx, Gen: p.Gen, Pol: p.Pol, S: make([]byte, 32), C: make([]byte, 32)}
	if err := h.check(); err != nil {
		return nil, err
	}
	hdr := h.Marshal()
	th := TranscriptHash(p.THPrev, js, envs)
	gctx := GroupContext(p.GID, p.Epoch, p.RosterHash, p.THPrev)
	sec := Schedule(p.InitPrev, p.CommitSecret, gctx)
	tag := ConfTag(sec.Confirm, th)
	sig := GSig(p.IK, hdr, js, envs, tag)
	row := cat(hdr, U16(uint16(len(js))), js, envs, tag, sig)
	if len(row) > CommitCap {
		return nil, fmt.Errorf("%w: commit cap", ErrGroup)
	}
	return &BuiltCommit{Row: row, Hdr: hdr, JSON: js, Envs: envs, TH: th, ConfTag: tag, ConfirmedTH: ConfirmedTH(th, tag),
		Sig: sig, GCtx: gctx, Secrets: sec, CommitSecret: p.CommitSecret}, nil
}

type CommitEnv struct {
	Idx     uint16
	Enc, CT []byte
}

type Commit struct {
	Hdr          *GHdr
	Header       *CommitHeader
	JSON, Envs   []byte
	Env          []CommitEnv
	ConfTag, Sig []byte
	hdr          []byte
}

// ParseCommit decodes a commit row for a group of suite cs.
func ParseCommit(row []byte, cs Suite) (*Commit, error) {
	if len(row) > CommitCap || len(row) < GHdrLen+2+2+32+64 || !cs.Valid() {
		return nil, fmt.Errorf("%w: commit length", ErrGroup)
	}
	h, err := ParseGHdr(row[:GHdrLen])
	if err != nil {
		return nil, err
	}
	if h.Kind != GKindCommit || !hmac.Equal(h.S, make([]byte, 32)) || !hmac.Equal(h.C, make([]byte, 32)) {
		return nil, fmt.Errorf("%w: commit header", ErrGroup)
	}
	r := reader8{b: row, i: GHdrLen}
	jl := int(r.u16())
	js := r.take(jl)
	if r.err || jl > CommitHdrCap {
		return nil, fmt.Errorf("%w: commit json length", ErrGroup)
	}
	ch, err := ParseCommitHeader(js)
	if err != nil {
		return nil, err
	}
	if ch.E != h.Epoch || ch.By != h.Idx {
		return nil, fmt.Errorf("%w: commit header disagrees with row header", ErrGroup)
	}
	envStart := r.i
	n := int(r.u16())
	if n == 0 || n > MaxMembersCS1 {
		return nil, fmt.Errorf("%w: commit fan-out", ErrGroup)
	}
	envLen := cs.EncSize() + 48
	c := &Commit{Hdr: h, Header: ch, JSON: js, hdr: row[:GHdrLen:GHdrLen]}
	seen := map[uint16]bool{}
	for i := 0; i < n; i++ {
		idx := r.u16()
		e := r.take(envLen)
		if r.err || seen[idx] {
			return nil, fmt.Errorf("%w: commit envelopes", ErrGroup)
		}
		seen[idx] = true
		c.Env = append(c.Env, CommitEnv{Idx: idx, Enc: e[:cs.EncSize()], CT: e[cs.EncSize():]})
	}
	c.Envs = row[envStart:r.i:r.i]
	c.ConfTag, c.Sig = r.take(32), r.take(64)
	if r.err || r.i != len(row) {
		return nil, fmt.Errorf("%w: commit length", ErrGroup)
	}
	return c, nil
}

func (c *Commit) VerifySig(ikPub []byte) bool {
	return verifyGSig(ikPub, c.Sig, c.hdr, c.JSON, c.Envs, c.ConfTag)
}

// OpenSecret decapsulates commit_secret_e for member idx.
func (c *Commit) OpenSecret(idx uint16, sk hpke.PrivateKey) ([]byte, error) {
	for _, e := range c.Env {
		if e.Idx == idx {
			r, err := hpke.NewRecipient(e.Enc, sk, KDF(), AEAD(), Labeled(LabelGCommit, []byte(c.Hdr.GID), U32(c.Hdr.Epoch)))
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrOpen, err)
			}
			s, err := r.Open(nil, e.CT)
			if err != nil || len(s) != 32 {
				return nil, ErrOpen
			}
			return s, nil
		}
	}
	return nil, ErrNoEnv
}

// Process is a member's view: it checks the committer built on this member's confirmed transcript, opens
// its envelope, derives the schedule and verifies the confirmation tag. It returns the secrets and the
// new confirmed transcript hash.
func (c *Commit) Process(idx uint16, sk hpke.PrivateKey, initPrev, thPrev, rosterHash []byte) (EpochSecrets, []byte, error) {
	if len(initPrev) != 32 || len(thPrev) != 32 || len(rosterHash) != 32 {
		return EpochSecrets{}, nil, fmt.Errorf("%w: state", ErrGroup)
	}
	thBytes, _ := hex.DecodeString(c.Header.TH)
	if !hmac.Equal(thBytes, thPrev) {
		return EpochSecrets{}, nil, ErrOrder
	}
	secret, err := c.OpenSecret(idx, sk)
	if err != nil {
		return EpochSecrets{}, nil, err
	}
	th := TranscriptHash(thPrev, c.JSON, c.Envs)
	sec := Schedule(initPrev, secret, GroupContext(c.Hdr.GID, c.Hdr.Epoch, rosterHash, thPrev))
	if !hmac.Equal(ConfTag(sec.Confirm, th), c.ConfTag) {
		return EpochSecrets{}, nil, ErrConfTag
	}
	return sec, ConfirmedTH(th, c.ConfTag), nil
}

// ---- welcome (kind 4): hdr (epoch = e, idx = committer) | to(7) | enc | ct | sig[64]
// ct = hpke.Seal(newcomer key, info = "cx1/gwelcome" || gid || u32(e), aad = hdr || to,
//                pt = joiner_secret_e(32) || GroupContext_e(84) || u16 n || n x (u16 idx | id(7) | u64 leaf) || ix(32) || ext)

type RosterLeaf struct {
	Idx  uint16
	ID   string
	Leaf uint64
}

type WelcomeParams struct {
	GID         string
	CS          Suite
	Epoch       uint32
	Idx         uint16 // committer
	Gen         uint32
	Pol         uint16
	To          string
	NewcomerKey []byte
	Joiner      []byte
	GCtx        []byte
	Roster      []RosterLeaf
	IX          []byte // 32-byte blind-index key of the space (zero for plain groups)
	Ext         []byte
	IK          ed25519.PrivateKey
}

type WelcomeBody struct {
	Joiner, GCtx []byte
	Roster       []RosterLeaf
	IX, Ext      []byte
}

func (w *WelcomeBody) marshal() ([]byte, error) {
	if len(w.Joiner) != 32 || len(w.GCtx) != GCtxLen || len(w.IX) != 32 || len(w.Roster) == 0 || len(w.Roster) > MaxMembersCS1 || len(w.Ext) > WelcomeExtCap {
		return nil, fmt.Errorf("%w: welcome body", ErrGroup)
	}
	out := cat(w.Joiner, w.GCtx, U16(uint16(len(w.Roster))))
	for _, m := range w.Roster {
		if !ValidID(m.ID) {
			return nil, fmt.Errorf("%w: welcome roster id", ErrGroup)
		}
		out = append(out, U16(m.Idx)...)
		out = append(out, m.ID...)
		out = append(out, U64(m.Leaf)...)
	}
	out = append(out, w.IX...)
	return append(out, w.Ext...), nil
}

func parseWelcomeBody(b []byte) (*WelcomeBody, error) {
	r := reader8{b: b}
	w := &WelcomeBody{Joiner: r.take(32), GCtx: r.take(GCtxLen)}
	n := int(r.u16())
	if r.err || n == 0 || n > MaxMembersCS1 {
		return nil, fmt.Errorf("%w: welcome body", ErrGroup)
	}
	for i := 0; i < n; i++ {
		m := RosterLeaf{Idx: r.u16(), ID: string(r.take(IDLen)), Leaf: r.u64()}
		if r.err || !ValidID(m.ID) {
			return nil, fmt.Errorf("%w: welcome roster", ErrGroup)
		}
		w.Roster = append(w.Roster, m)
	}
	w.IX = r.take(32)
	if r.err {
		return nil, fmt.Errorf("%w: welcome body", ErrGroup)
	}
	w.Ext = b[r.i:]
	if len(w.Ext) > WelcomeExtCap {
		return nil, fmt.Errorf("%w: welcome ext", ErrGroup)
	}
	return w, nil
}

func BuildWelcome(p WelcomeParams) ([]byte, error) {
	if !p.CS.Valid() || !ValidID(p.To) || p.IK == nil {
		return nil, fmt.Errorf("%w: welcome params", ErrGroup)
	}
	body, err := (&WelcomeBody{Joiner: p.Joiner, GCtx: p.GCtx, Roster: p.Roster, IX: p.IX, Ext: p.Ext}).marshal()
	if err != nil {
		return nil, err
	}
	h := GHdr{Kind: GKindWelcome, GID: p.GID, Epoch: p.Epoch, Idx: p.Idx, Gen: p.Gen, Pol: p.Pol, S: make([]byte, 32), C: make([]byte, 32)}
	if err := h.check(); err != nil {
		return nil, err
	}
	hdr := h.Marshal()
	pk, err := p.CS.NewPublicKey(p.NewcomerKey)
	if err != nil {
		return nil, err
	}
	enc, s, err := hpke.NewSender(pk, KDF(), AEAD(), Labeled(LabelGWelcome, []byte(p.GID), U32(p.Epoch)))
	if err != nil {
		return nil, err
	}
	ct, err := s.Seal(cat(hdr, []byte(p.To)), body)
	if err != nil {
		return nil, err
	}
	sig := GSig(p.IK, hdr, []byte(p.To), enc, ct)
	row := cat(hdr, []byte(p.To), enc, ct, sig)
	if len(row) > GroupRowCap {
		return nil, fmt.Errorf("%w: welcome cap", ErrGroup)
	}
	return row, nil
}

type Welcome struct {
	Hdr          *GHdr
	To           string
	Enc, CT, Sig []byte
	hdr          []byte
}

func ParseWelcome(row []byte, cs Suite) (*Welcome, error) {
	if !cs.Valid() || len(row) > GroupRowCap || len(row) < GHdrLen+IDLen+cs.EncSize()+16+64 {
		return nil, fmt.Errorf("%w: welcome length", ErrGroup)
	}
	h, err := ParseGHdr(row[:GHdrLen])
	if err != nil {
		return nil, err
	}
	if h.Kind != GKindWelcome {
		return nil, fmt.Errorf("%w: kind", ErrGroup)
	}
	r := reader8{b: row, i: GHdrLen}
	w := &Welcome{Hdr: h, To: string(r.take(IDLen)), Enc: r.take(cs.EncSize()), hdr: row[:GHdrLen:GHdrLen]}
	ctLen := len(row) - r.i - 64
	w.CT, w.Sig = r.take(ctLen), r.take(64)
	if r.err || !ValidID(w.To) {
		return nil, fmt.Errorf("%w: welcome", ErrGroup)
	}
	return w, nil
}

func (w *Welcome) VerifySig(ikPub []byte) bool {
	return verifyGSig(ikPub, w.Sig, w.hdr, []byte(w.To), w.Enc, w.CT)
}

// Open decrypts the Welcome with the newcomer's key; the caller then runs the DVR on every roster leaf
// and recomputes the roster hash (RosterHash) against the GroupContext before deriving anything.
func (w *Welcome) Open(sk hpke.PrivateKey) (*WelcomeBody, error) {
	r, err := hpke.NewRecipient(w.Enc, sk, KDF(), AEAD(), Labeled(LabelGWelcome, []byte(w.Hdr.GID), U32(w.Hdr.Epoch)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOpen, err)
	}
	pt, err := r.Open(cat(w.hdr, []byte(w.To)), w.CT)
	if err != nil {
		return nil, ErrOpen
	}
	return parseWelcomeBody(pt)
}

// ---- proposals (kind 3): hdr | u16 jlen | clear_hdr_json | sig[64]; member-signed or server-signed.

func BuildProposal(gid string, epoch uint32, idx uint16, gen uint32, pol uint16, js []byte, sk ed25519.PrivateKey) ([]byte, error) {
	if len(js) > CommitHdrCap || !json.Valid(js) || sk == nil {
		return nil, fmt.Errorf("%w: proposal", ErrGroup)
	}
	h := GHdr{Kind: GKindProposal, GID: gid, Epoch: epoch, Idx: idx, Gen: gen, Pol: pol, S: make([]byte, 32), C: make([]byte, 32)}
	if err := h.check(); err != nil {
		return nil, err
	}
	hdr := h.Marshal()
	return cat(hdr, U16(uint16(len(js))), js, GSig(sk, hdr, js)), nil
}

type Proposal struct {
	Hdr       *GHdr
	JSON, Sig []byte
	hdr       []byte
}

func ParseProposal(row []byte) (*Proposal, error) {
	if len(row) > GroupRowCap || len(row) < GHdrLen+2+64 {
		return nil, fmt.Errorf("%w: proposal length", ErrGroup)
	}
	h, err := ParseGHdr(row[:GHdrLen])
	if err != nil {
		return nil, err
	}
	if h.Kind != GKindProposal {
		return nil, fmt.Errorf("%w: kind", ErrGroup)
	}
	r := reader8{b: row, i: GHdrLen}
	jl := int(r.u16())
	p := &Proposal{Hdr: h, JSON: r.take(jl), hdr: row[:GHdrLen:GHdrLen]}
	p.Sig = r.take(64)
	if r.err || r.i != len(row) || jl > CommitHdrCap || !json.Valid(p.JSON) {
		return nil, fmt.Errorf("%w: proposal", ErrGroup)
	}
	return p, nil
}

func (p *Proposal) VerifySig(pub []byte) bool { return verifyGSig(pub, p.Sig, p.hdr, p.JSON) }

// ---- objects (kind 5, E2EE 6.2): hdr | ver u32 | oid[16] | okind u8 | n_bt u8 | n_bt x bt[16] | ct | sig[64]
// ct = AES-256-GCM(k_o, 0^12, aad = hdr || ver || oid || okind || bts, pt), pt = kf | len u16 | payload | pad.

type ObjParams struct {
	GID     string
	Epoch   uint32
	Idx     uint16
	Gen     uint32
	Pol     uint16
	Ver     uint32
	OID     []byte
	OKind   byte
	Tags    [][]byte // blind tags (BlindTag), 16 bytes each
	KF, S   []byte
	Payload []byte
	MsgRoot []byte
	IK      ed25519.PrivateKey
	Rand    io.Reader
}

// ObjFrank is the per-object commitment over gid || oid || u32(ver) || okind || u16(len) || payload.
func ObjFrank(kf []byte, gid string, oid []byte, ver uint32, okind byte, payload []byte) []byte {
	m := hmac.New(sha256.New, kf)
	m.Write(Labeled(LabelGFrank, []byte(gid), oid, U32(ver), []byte{okind}, U16(uint16(len(payload))), payload))
	return m.Sum(nil)
}

func objMeta(ver uint32, oid []byte, okind byte, tags [][]byte) []byte {
	out := cat(U32(ver), oid, []byte{okind, byte(len(tags))})
	for _, t := range tags {
		out = append(out, t...)
	}
	return out
}

func SealObject(p ObjParams) ([]byte, error) {
	rnd := reader(p.Rand)
	var err error
	if p.KF, err = fill(p.KF, 32, rnd); err != nil {
		return nil, err
	}
	if p.S, err = fill(p.S, 32, rnd); err != nil {
		return nil, err
	}
	if len(p.OID) != OIDLen || len(p.Tags) > MaxBlindTags || len(p.Payload) > ObjPayloadCap || len(p.MsgRoot) != 32 || p.IK == nil {
		return nil, fmt.Errorf("%w: object params", ErrGroup)
	}
	for _, t := range p.Tags {
		if len(t) != BlindTagLen {
			return nil, fmt.Errorf("%w: blind tag", ErrGroup)
		}
	}
	padded, err := Pad(cat(p.KF, U16(uint16(len(p.Payload))), p.Payload), ObjectBuckets)
	if err != nil {
		return nil, err
	}
	h := GHdr{Kind: GKindObject, GID: p.GID, Epoch: p.Epoch, Idx: p.Idx, Gen: p.Gen, Pol: p.Pol, S: p.S,
		C: ObjFrank(p.KF, p.GID, p.OID, p.Ver, p.OKind, p.Payload)}
	if err := h.check(); err != nil {
		return nil, err
	}
	hdr := h.Marshal()
	meta := objMeta(p.Ver, p.OID, p.OKind, p.Tags)
	g, err := gcm(ObjKey(p.MsgRoot, p.S, p.GID, p.OID, p.Ver))
	if err != nil {
		return nil, err
	}
	ct := g.Seal(nil, zeroNonce, padded, cat(hdr, meta))
	return cat(hdr, meta, ct, GSig(p.IK, hdr, meta, ct)), nil
}

type Object struct {
	Hdr       *GHdr
	Ver       uint32
	OID       []byte
	OKind     byte
	Tags      [][]byte
	CT, Sig   []byte
	hdr, meta []byte
}

func ParseObject(row []byte) (*Object, error) {
	if len(row) > 65536+GHdrLen+4+OIDLen+2+MaxBlindTags*BlindTagLen+16+64 || len(row) < GHdrLen+4+OIDLen+2+16+64 {
		return nil, fmt.Errorf("%w: object length", ErrGroup)
	}
	h, err := ParseGHdr(row[:GHdrLen])
	if err != nil {
		return nil, err
	}
	if h.Kind != GKindObject {
		return nil, fmt.Errorf("%w: kind", ErrGroup)
	}
	r := reader8{b: row, i: GHdrLen}
	o := &Object{Hdr: h, Ver: r.u32(), OID: r.take(OIDLen), OKind: r.u8(), hdr: row[:GHdrLen:GHdrLen]}
	n := int(r.u8())
	if r.err || n > MaxBlindTags {
		return nil, fmt.Errorf("%w: object tags", ErrGroup)
	}
	for i := 0; i < n; i++ {
		o.Tags = append(o.Tags, r.take(BlindTagLen))
	}
	o.meta = row[GHdrLen:r.i:r.i]
	ctLen := len(row) - r.i - 64
	o.CT, o.Sig = r.take(ctLen), r.take(64)
	if r.err || !IsBucket(ctLen-16, ObjectBuckets) {
		return nil, fmt.Errorf("%w: object", ErrGroup)
	}
	return o, nil
}

func (o *Object) VerifySig(ikPub []byte) bool { return verifyGSig(ikPub, o.Sig, o.hdr, o.meta, o.CT) }

// Open decrypts an object under the epoch's msg_root and checks its commitment; it returns kf and payload.
func (o *Object) Open(msgRoot []byte) ([]byte, []byte, error) {
	g, err := gcm(ObjKey(msgRoot, o.Hdr.S, o.Hdr.GID, o.OID, o.Ver))
	if err != nil {
		return nil, nil, err
	}
	padded, err := g.Open(nil, zeroNonce, o.CT, cat(o.hdr, o.meta))
	if err != nil {
		return nil, nil, ErrOpen
	}
	pt, err := Unpad(padded)
	if err != nil || len(pt) < 34 {
		return nil, nil, ErrInner
	}
	r := reader8{b: pt}
	kf := r.take(32)
	n := int(r.u16())
	payload := r.take(n)
	if r.err || r.i != len(pt) {
		return nil, nil, ErrInner
	}
	if !hmac.Equal(ObjFrank(kf, o.Hdr.GID, o.OID, o.Ver, o.OKind, payload), o.Hdr.C) {
		return nil, nil, ErrFrank
	}
	return kf, payload, nil
}

// BlindTag is HMAC-SHA256(ix, lowercase(tag))[:16], the equality-search tag of 6.2.
func BlindTag(ix []byte, tag string) []byte {
	m := hmac.New(sha256.New, ix)
	m.Write([]byte(strings.ToLower(tag)))
	return m.Sum(nil)[:BlindTagLen]
}

// fill returns b when it has n bytes, draws n bytes from rnd when b is nil, and errors otherwise.
func fill(b []byte, n int, rnd io.Reader) ([]byte, error) {
	if b == nil {
		b = make([]byte, n)
		_, err := io.ReadFull(rnd, b)
		return b, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("e2e: expected %d bytes, got %d", n, len(b))
	}
	return b, nil
}
