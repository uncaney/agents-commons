package e2e

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Sealed state blob (E2EE 7.2): the one place a stateless agent keeps what it cannot re-derive.
//
//	blob = 0x01 | s[32] | AES-256-GCM(k = HKDF(k_state, salt = s, "cx1/state" || id || u64(ver), 32), 0^12,
//	                                   aad = "cx1/state" || id || u64(ver), pt)
//
// ver in the key and the AAD stops the server from serving blob N under label M; the kind 6 log receipt
// sha256(id || u64(ver) || sha256(blob)) makes a rollback detectable against the witnessed head.

const (
	StateVer = 1
	StateCap = 65536
	SeenCap  = 512 // bounded seen-mid window
)

var ErrState = errors.New("e2e: bad sealed state")

// StateInfo is "cx1/state" || 0x00 || id || u64(ver).
func StateInfo(id string, ver uint64) []byte { return Labeled(LabelState, []byte(id), U64(ver)) }

// SealState seals pt for (id, ver); rnd nil means crypto/rand.
func SealState(kState []byte, id string, ver uint64, pt []byte, rnd io.Reader) ([]byte, error) {
	if len(kState) != 32 || !ValidID(id) || len(pt)+1+32+16 > StateCap {
		return nil, ErrState
	}
	s := make([]byte, 32)
	if _, err := io.ReadFull(reader(rnd), s); err != nil {
		return nil, err
	}
	info := StateInfo(id, ver)
	g, err := gcm(HKDF(kState, s, string(info), 32))
	if err != nil {
		return nil, err
	}
	return cat([]byte{StateVer}, s, g.Seal(nil, zeroNonce, pt, info)), nil
}

// OpenState opens a blob the server served for (id, ver).
func OpenState(kState []byte, id string, ver uint64, blob []byte) ([]byte, error) {
	if len(kState) != 32 || len(blob) > StateCap || len(blob) < 1+32+16 || blob[0] != StateVer {
		return nil, ErrState
	}
	info := StateInfo(id, ver)
	g, err := gcm(HKDF(kState, blob[1:33], string(info), 32))
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, zeroNonce, blob[33:], info)
	if err != nil {
		return nil, fmt.Errorf("%w: open", ErrState)
	}
	return pt, nil
}

// StateReceipt is the kind 6 log item hash sha256(id || u64(ver) || sha256(blob)).
func StateReceipt(id string, ver uint64, blob []byte) []byte {
	return Sum([]byte(id), U64(ver), Sum(blob))
}

// StateStale reports a rollback: the server served a version older than the latest receipted one
// (`warn state stale`).
func StateStale(servedVer, receiptedVer uint64) bool { return servedVer < receiptedVer }

// State is the JSON content of the blob (7.2). Pins and the DVR cache are what the DVR reads and writes.
type State struct {
	Pins      map[string]Pin        `json:"pins,omitempty"`
	DVR       map[string]DVRCache   `json:"dvr,omitempty"`
	Cursor    uint64                `json:"cursor,omitempty"`
	Groups    map[string]GroupState `json:"groups,omitempty"`
	Seen      []string              `json:"seen,omitempty"` // base64url mids, newest last
	Head      *HeadRef              `json:"head,omitempty"`
	OwnLeaves []uint64              `json:"own_leaves,omitempty"`
	Bans      []string              `json:"bans,omitempty"` // fingerprints (hex)
	Policy    *PolicyPin            `json:"policy,omitempty"`
}

// Pin records the highest (seq, cs, policy, leaf) seen for a peer (E2EE 3.8).
type Pin struct {
	FP   string `json:"fp"` // hex sha256("cx1/fp" || ik)
	Seq  uint32 `json:"seq"`
	CS   uint8  `json:"cs"`
	Leaf uint64 `json:"leaf"`
	Pol  uint8  `json:"pol"`
	PQ   string `json:"pq,omitempty"` // hex sha256 of a pinned pq_id
}

type DVRCache struct {
	Seq         uint32 `json:"seq"`
	Leaf        uint64 `json:"leaf"`
	HeadSize    uint64 `json:"head_size"`
	Provisional bool   `json:"provisional,omitempty"`
}

type GroupState struct {
	Epoch  uint32 `json:"epoch"`
	Secret string `json:"secret"` // base64url epoch_secret
	Init   string `json:"init"`   // base64url init_secret
	TH     string `json:"th"`     // hex confirmed transcript hash
	Cursor uint64 `json:"cursor"`
	Gen    uint32 `json:"gen"`
	Idx    uint16 `json:"idx"`
}

type HeadRef struct {
	Size uint64 `json:"size"`
	Root string `json:"root"`
	At   uint64 `json:"at"`
}

type PolicyPin struct {
	V    uint32 `json:"v"`
	Hash string `json:"hash"`
}

// Encode marshals the state (compact JSON) after bounding the seen window.
func (s *State) Encode() ([]byte, error) {
	if len(s.Seen) > SeenCap {
		s.Seen = s.Seen[len(s.Seen)-SeenCap:]
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(b)+1+32+16 > StateCap {
		return nil, fmt.Errorf("%w: too large", ErrState)
	}
	return b, nil
}

func DecodeState(b []byte) (*State, error) {
	if len(b) > StateCap {
		return nil, ErrState
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrState, err)
	}
	return &s, nil
}

// MarkSeen records a mid (base64url) and reports whether it was already in the window (replay).
func (s *State) MarkSeen(mid string) bool {
	for _, m := range s.Seen {
		if m == mid {
			return true
		}
	}
	s.Seen = append(s.Seen, mid)
	if len(s.Seen) > SeenCap {
		s.Seen = s.Seen[1:]
	}
	return false
}
