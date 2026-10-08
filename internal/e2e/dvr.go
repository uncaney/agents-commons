package e2e

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The directory verification rule (E2EE 3.4) as a pure function over bytes the client fetched. A key is
// used for sealing only after every step passes, in order: 1 signature and shape, 2 inclusion under a
// witnessed head (or a fresh server STH consistent with it, then `provisional`), 3 pins and monotonicity,
// 4 freshness, 5 own entry (VerifyOwnEntry, at session start). Failures are machine-readable
// `err dvr <step> <detail>` and fail closed.

const (
	HeadMaxAge = 86400 // a server STH older than 24 h is stale
	FirstHour  = 3600  // ek of e-1 is accepted during the first hour of a week
)

// Head is a signed tree head with its witness cosignatures (witness id -> signature).
type Head struct {
	Size    uint64
	Root    []byte
	At      uint64
	Sig     []byte
	Witness map[string][]byte
}

type DVRError struct {
	Step   int
	Detail string
}

func (e *DVRError) Error() string { return fmt.Sprintf("err dvr %d %s", e.Step, e.Detail) }

func dvrErr(step int, detail string) error { return &DVRError{Step: step, Detail: detail} }

// ErrKeySubstituted is the step 5 alert: a foreign leaf exists for the owner's own id.
var ErrKeySubstituted = errors.New("alert key-substituted")

// VerifyHead checks the STH signature under online_pk and at least minWitness pinned witness signatures.
func VerifyHead(h *Head, onlinePK []byte, witnessPKs map[string][]byte, minWitness int) error {
	if h == nil || len(h.Root) != 32 {
		return errors.New("e2e: head shape")
	}
	if !Verify(onlinePK, STHBytes(h.Size, h.Root, h.At), h.Sig) {
		return errors.New("e2e: sth signature")
	}
	n := 0
	for id, sig := range h.Witness {
		if pk, ok := witnessPKs[id]; ok && Verify(pk, WitnessBytes(h.Size, h.Root, h.At), sig) {
			n++
		}
	}
	if n < minWitness {
		return fmt.Errorf("e2e: %d witness signature(s), need %d", n, minWitness)
	}
	return nil
}

type DVRInput struct {
	Now int64

	ID      string // the id looked up
	Raw     []byte // canonical || sigs as served (verified bytes, never a parse)
	Leaf    uint64 // leaf index the directory claims for this bundle
	Pending bool   // directory says pending=1: never used for sealing

	OnlinePK   []byte
	WitnessPKs map[string][]byte
	MinWitness int // pinned witness signatures required on the mirror head (default 1)

	Witnessed   *Head    // H_w from the mirror over the client's own egress
	ServerSTH   *Head    // the server's current STH (needed when the leaf is newer than H_w)
	Inclusion   [][]byte // audit path for Leaf under the head used
	Consistency [][]byte // consistency path Witnessed.Size -> ServerSTH.Size
	IndexSeq    uint32   // seq listed by the daily index for ID (0 = no entry)

	Pin    *Pin   // existing pin for ID (nil on first contact)
	PrevIK []byte // the pinned ik when the bundle carries a chained rotation (sig_prev)

	ClientMaxCS Suite // highest suite this client implements (0 = CS2)
	TOFU        bool  // CX_TRUST=tofu: no mirror, verify against the server STH only (tier D)
}

type DVRResult struct {
	Bundle      *Bundle
	CS          Suite
	Key         []byte // the ek (or lk) to seal to
	Epoch       uint32 // 0 when LT
	LT          bool
	Provisional bool
	TOFU        bool
	Pin         Pin
	Cache       DVRCache
}

// DVR runs steps 1 to 4. Step 5 is VerifyOwnEntry.
func DVR(in DVRInput) (*DVRResult, error) {
	// 1. signature and shape
	b, err := ParseBundle(in.Raw)
	if err != nil {
		return nil, dvrErr(1, "shape: "+err.Error())
	}
	switch {
	case b.ID != in.ID:
		return nil, dvrErr(1, "id mismatch")
	case int64(b.IAT) > in.Now+IATSkew:
		return nil, dvrErr(1, "iat in the future")
	case int64(b.Exp) <= in.Now:
		return nil, dvrErr(1, "expired")
	}
	if err := b.Verify(); err != nil {
		return nil, dvrErr(1, "signature")
	}
	if in.Pin != nil && in.Pin.PQ != "" {
		if !b.pq() || !hmac.Equal([]byte(hex.EncodeToString(Sum(b.PQID))), []byte(in.Pin.PQ)) {
			return nil, dvrErr(1, "pq_id missing or changed")
		}
	}
	if in.Pending {
		return nil, dvrErr(2, "pending bundle")
	}

	// 2. inclusion under a witnessed head
	ch, _ := b.CanonicalHash()
	leafHash := KlogLeaf(1, b.ID, ch, in.Leaf)
	res := &DVRResult{Bundle: b, TOFU: in.TOFU}
	minW := in.MinWitness
	if minW <= 0 {
		minW = 1
	}
	var headSize uint64
	switch {
	case in.TOFU:
		if in.ServerSTH == nil {
			return nil, dvrErr(2, "no sth")
		}
		if err := VerifyHead(in.ServerSTH, in.OnlinePK, nil, 0); err != nil {
			return nil, dvrErr(2, "sth: "+err.Error())
		}
		if err := headFresh(in.ServerSTH, in.Now); err != nil {
			return nil, dvrErr(2, err.Error())
		}
		if in.Leaf >= in.ServerSTH.Size || !VerifyInclusion(leafHash, in.Leaf, in.ServerSTH.Size, in.Inclusion, in.ServerSTH.Root) {
			return nil, dvrErr(2, "inclusion")
		}
		headSize = in.ServerSTH.Size
	case in.Witnessed == nil:
		return nil, dvrErr(2, "mirror unreachable (set CX_TRUST=tofu to proceed as tier D)")
	default:
		if err := VerifyHead(in.Witnessed, in.OnlinePK, in.WitnessPKs, minW); err != nil {
			return nil, dvrErr(2, "witnessed head: "+err.Error())
		}
		if in.Leaf < in.Witnessed.Size {
			if !VerifyInclusion(leafHash, in.Leaf, in.Witnessed.Size, in.Inclusion, in.Witnessed.Root) {
				return nil, dvrErr(2, "inclusion")
			}
			headSize = in.Witnessed.Size
			break
		}
		sth := in.ServerSTH
		if sth == nil {
			return nil, dvrErr(2, "leaf newer than the witnessed head and no sth")
		}
		if err := VerifyHead(sth, in.OnlinePK, nil, 0); err != nil {
			return nil, dvrErr(2, "sth: "+err.Error())
		}
		if err := headFresh(sth, in.Now); err != nil {
			return nil, dvrErr(2, err.Error())
		}
		if sth.Size == in.Witnessed.Size && !hmac.Equal(sth.Root, in.Witnessed.Root) {
			return nil, dvrErr(2, "split-view")
		}
		if sth.Size < in.Witnessed.Size {
			return nil, dvrErr(2, "sth older than the witnessed head")
		}
		if !VerifyConsistency(in.Witnessed.Size, sth.Size, in.Witnessed.Root, sth.Root, in.Consistency) {
			return nil, dvrErr(2, "fork: sth not consistent with the witnessed head")
		}
		if in.Leaf >= sth.Size || !VerifyInclusion(leafHash, in.Leaf, sth.Size, in.Inclusion, sth.Root) {
			return nil, dvrErr(2, "inclusion")
		}
		headSize = sth.Size
		res.Provisional = true
	}
	if in.IndexSeq > b.Seq {
		return nil, dvrErr(2, "index lists seq "+strconv.FormatUint(uint64(in.IndexSeq), 10)+": refetch")
	}

	// 3. pins and monotonicity
	fp := hex.EncodeToString(b.Fingerprint())
	pin := Pin{FP: fp, Seq: b.Seq, CS: uint8(b.MaxCS()), Leaf: in.Leaf, Pol: b.MailPolicy}
	if b.pq() {
		pin.PQ = hex.EncodeToString(Sum(b.PQID))
	}
	if in.Pin != nil {
		if !hmac.Equal([]byte(in.Pin.FP), []byte(fp)) {
			if !b.Rotated() || len(in.PrevIK) != 32 || !hmac.Equal([]byte(in.Pin.FP), []byte(hex.EncodeToString(Fingerprint(in.PrevIK)))) || b.VerifyRotation(in.PrevIK) != nil {
				return nil, dvrErr(3, "ik changed")
			}
		}
		switch {
		case b.Seq < in.Pin.Seq:
			return nil, dvrErr(3, "regress seq")
		case uint8(b.MaxCS()) < in.Pin.CS:
			return nil, dvrErr(3, "regress cs")
		case b.MailPolicy < in.Pin.Pol:
			return nil, dvrErr(3, "regress policy")
		case in.Leaf < in.Pin.Leaf:
			return nil, dvrErr(3, "regress leaf")
		}
		if in.Pin.PQ != "" {
			pin.PQ = in.Pin.PQ
		}
	}

	// 4. freshness
	cs := b.MaxCS()
	if in.ClientMaxCS.Valid() && in.ClientMaxCS < cs {
		cs = in.ClientMaxCS
	}
	if cs < Suite(b.MinCS) {
		return nil, dvrErr(4, "min_cs "+Suite(b.MinCS).String()+" above this client")
	}
	e := Epoch(in.Now)
	switch {
	case has(b, cs, e):
		res.Key, _ = b.EK(cs, e)
		res.Epoch = e
	case e > 0 && in.Now-EpochStart(e) < FirstHour && has(b, cs, e-1):
		res.Key, _ = b.EK(cs, e-1)
		res.Epoch = e - 1
	case b.Flags&FlagLKOK != 0 && in.Pin == nil:
		res.Key, _ = b.LK(cs)
		res.LT = true
	default:
		return nil, dvrErr(4, "stale-bundle from="+b.ID)
	}
	res.CS, res.Pin = cs, pin
	res.Cache = DVRCache{Seq: b.Seq, Leaf: in.Leaf, HeadSize: headSize, Provisional: res.Provisional}
	return res, nil
}

func has(b *Bundle, cs Suite, e uint32) bool {
	_, ok := b.EK(cs, e)
	return ok
}

func headFresh(h *Head, now int64) error {
	switch {
	case int64(h.At)+HeadMaxAge < now:
		return errors.New("stale head")
	case int64(h.At) > now+IATSkew:
		return errors.New("head from the future")
	}
	return nil
}

// VerifyOwnEntry is step 5: the leaves the log holds for the owner's id must be exactly the ones the
// client produced (sealed state keeps the list). A foreign leaf is `alert key-substituted`.
func VerifyOwnEntry(mine, logged []uint64) error {
	seen := make(map[uint64]bool, len(mine))
	for _, m := range mine {
		seen[m] = true
	}
	for _, l := range logged {
		if !seen[l] {
			return fmt.Errorf("%w: leaf %d", ErrKeySubstituted, l)
		}
		delete(seen, l)
	}
	if len(seen) != 0 {
		return errors.New("e2e: own leaf missing from the log (withheld or forked)")
	}
	return nil
}

// ---- wire parsers for the directory and log replies the DVR consumes

// GossipHeader renders CX-STH: <size>:<root hex16>; ParseGossip reads it; SplitView compares two.
func GossipHeader(size uint64, root []byte) string {
	return strconv.FormatUint(size, 10) + ":" + hex.EncodeToString(root)[:16]
}

func ParseGossip(h string) (uint64, string, error) {
	i := strings.IndexByte(h, ':')
	if i <= 0 || len(h)-i-1 != 16 {
		return 0, "", errors.New("e2e: bad CX-STH")
	}
	size, err := strconv.ParseUint(h[:i], 10, 64)
	if err != nil {
		return 0, "", errors.New("e2e: bad CX-STH")
	}
	if _, err := hex.DecodeString(h[i+1:]); err != nil {
		return 0, "", errors.New("e2e: bad CX-STH")
	}
	return size, h[i+1:], nil
}

// SplitView reports two different roots for one tree size (`warn log split-view`).
func SplitView(size1 uint64, root1 string, size2 uint64, root2 string) bool {
	return size1 == size2 && root1 != root2
}

// ParseSTHLine reads `size=<n> root=<hex> at=<unix> sig=<b64> cert=<b64>` (cert may be absent).
func ParseSTHLine(line string) (*Head, []byte, error) {
	kv := fields(line)
	size, err1 := strconv.ParseUint(kv["size"], 10, 64)
	root, err2 := hex.DecodeString(kv["root"])
	at, err3 := strconv.ParseUint(kv["at"], 10, 64)
	sig, err4 := base64.RawURLEncoding.DecodeString(kv["sig"])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(root) != 32 || len(sig) != 64 {
		return nil, nil, errors.New("e2e: bad sth line")
	}
	var cert []byte
	if c := kv["cert"]; c != "" {
		if cert, err1 = base64.RawURLEncoding.DecodeString(c); err1 != nil {
			return nil, nil, errors.New("e2e: bad sth cert")
		}
	}
	return &Head{Size: size, Root: root, At: at, Sig: sig}, cert, nil
}

// MirrorHead is one line of transparency/sth.jsonl: {size, root, at, sig, w:{<witness id>: <sig>}, seen}.
type MirrorHead struct {
	Size uint64            `json:"size"`
	Root string            `json:"root"`
	At   uint64            `json:"at"`
	Sig  string            `json:"sig"`
	W    map[string]string `json:"w"`
	Seen uint64            `json:"seen,omitempty"`
}

// ParseMirrorHead decodes a mirror line into a Head.
func ParseMirrorHead(line []byte) (*Head, error) {
	if len(line) > 8192 {
		return nil, errors.New("e2e: mirror line too long")
	}
	var m MirrorHead
	if err := json.Unmarshal(line, &m); err != nil {
		return nil, errors.New("e2e: bad mirror line")
	}
	root, err1 := hex.DecodeString(m.Root)
	sig, err2 := base64.RawURLEncoding.DecodeString(m.Sig)
	if err1 != nil || err2 != nil || len(root) != 32 || len(sig) != 64 || len(m.W) > 16 {
		return nil, errors.New("e2e: bad mirror line")
	}
	h := &Head{Size: m.Size, Root: root, At: m.At, Sig: sig, Witness: map[string][]byte{}}
	for id, s := range m.W {
		ws, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(ws) != 64 || len(id) > 32 {
			return nil, errors.New("e2e: bad mirror witness")
		}
		h.Witness[id] = ws
	}
	return h, nil
}

// FormatMirrorHead renders a Head as a mirror line.
func FormatMirrorHead(h *Head, seen uint64) ([]byte, error) {
	m := MirrorHead{Size: h.Size, Root: hex.EncodeToString(h.Root), At: h.At, Sig: b64(h.Sig), W: map[string]string{}, Seen: seen}
	for id, s := range h.Witness {
		m.W[id] = b64(s)
	}
	return json.Marshal(m)
}

// ParseInclLine reads `idx=<i> leaf=<hex> path=<hex,hex,...>`; ParseConsLine reads `path=<hex,...>`.
func ParseInclLine(line string) (uint64, []byte, [][]byte, error) {
	kv := fields(line)
	idx, err1 := strconv.ParseUint(kv["idx"], 10, 64)
	leaf, err2 := hex.DecodeString(kv["leaf"])
	path, err3 := DecodePath(kv["path"])
	if err1 != nil || err2 != nil || err3 != nil || len(leaf) != 32 {
		return 0, nil, nil, errors.New("e2e: bad inclusion line")
	}
	return idx, leaf, path, nil
}

func ParseConsLine(line string) ([][]byte, error) {
	path, err := DecodePath(fields(line)["path"])
	if err != nil {
		return nil, errors.New("e2e: bad consistency line")
	}
	return path, nil
}

// fields splits a `k=v k=v` line (first line only, at most 32 fields).
func fields(line string) map[string]string {
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	out := map[string]string{}
	for i, f := range strings.Fields(line) {
		if i >= 32 {
			break
		}
		if k, v, ok := strings.Cut(f, "="); ok {
			out[k] = v
		}
	}
	return out
}
