package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// RFC 6962 Merkle tree (E2EE 3.3): leaf sha256(0x00 || data), node sha256(0x01 || left || right),
// audit (inclusion) and consistency paths as in RFC 6962 2.1.1 and 2.1.2, verification as in RFC 9162
// 2.1.3.2 and 2.1.4.2. Pure functions over hashes so every client tier can verify in a few lines.

const MaxPathLen = 64

var ErrPath = errors.New("e2e: bad merkle path")

func LeafHash(data []byte) []byte { return Sum([]byte{0}, data) }

func NodeHash(left, right []byte) []byte { return Sum([]byte{1}, left, right) }

// EmptyRoot is the root of the empty tree, sha256 of nothing.
func EmptyRoot() []byte {
	h := sha256.Sum256(nil)
	return h[:]
}

// KlogLeaf is the key-log leaf: sha256(0x00 || u8(kind) || id || item_hash || u64(idx)).
func KlogLeaf(kind uint8, id string, itemHash []byte, idx uint64) []byte {
	return LeafHash(cat([]byte{kind}, []byte(id), itemHash, U64(idx)))
}

// largestPow2Below returns the largest power of two strictly less than n (n >= 2).
func largestPow2Below(n uint64) uint64 {
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// RootFromLeafHashes is MTH over already-hashed leaves.
func RootFromLeafHashes(hs [][]byte) []byte {
	switch len(hs) {
	case 0:
		return EmptyRoot()
	case 1:
		return hs[0]
	}
	k := largestPow2Below(uint64(len(hs)))
	return NodeHash(RootFromLeafHashes(hs[:k]), RootFromLeafHashes(hs[k:]))
}

// InclusionPath is PATH(m, D[n]) over leaf hashes.
func InclusionPath(hs [][]byte, m uint64) [][]byte {
	n := uint64(len(hs))
	if n <= 1 || m >= n {
		return nil
	}
	k := largestPow2Below(n)
	if m < k {
		return append(InclusionPath(hs[:k], m), RootFromLeafHashes(hs[k:]))
	}
	return append(InclusionPath(hs[k:], m-k), RootFromLeafHashes(hs[:k]))
}

// ConsistencyPath is PROOF(m, D[n]) over leaf hashes (0 < m <= n).
func ConsistencyPath(hs [][]byte, m uint64) [][]byte {
	n := uint64(len(hs))
	if m == 0 || m > n {
		return nil
	}
	return subproof(hs, m, true)
}

func subproof(hs [][]byte, m uint64, complete bool) [][]byte {
	n := uint64(len(hs))
	if m == n {
		if complete {
			return nil
		}
		return [][]byte{RootFromLeafHashes(hs)}
	}
	k := largestPow2Below(n)
	if m <= k {
		return append(subproof(hs[:k], m, complete), RootFromLeafHashes(hs[k:]))
	}
	return append(subproof(hs[k:], m-k, false), RootFromLeafHashes(hs[:k]))
}

// VerifyInclusion checks an audit path for leafHash at idx in a tree of size against root.
func VerifyInclusion(leafHash []byte, idx, size uint64, path [][]byte, root []byte) bool {
	if idx >= size || len(leafHash) != 32 || len(root) != 32 || len(path) > MaxPathLen {
		return false
	}
	fn, sn := idx, size-1
	r := leafHash
	for _, p := range path {
		if len(p) != 32 || sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && hmac.Equal(r, root)
}

// VerifyConsistency checks that the tree of size first with root1 is a prefix of the tree of size second
// with root2.
func VerifyConsistency(first, second uint64, root1, root2 []byte, path [][]byte) bool {
	if len(root1) != 32 || len(root2) != 32 || len(path) > MaxPathLen || first > second {
		return false
	}
	if first == second {
		return len(path) == 0 && hmac.Equal(root1, root2)
	}
	if first == 0 {
		return len(path) == 0
	}
	if len(path) == 0 {
		return false
	}
	if first&(first-1) == 0 {
		path = append([][]byte{root1}, path...)
	}
	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	if len(path[0]) != 32 {
		return false
	}
	fr, sr := path[0], path[0]
	for _, c := range path[1:] {
		if len(c) != 32 || sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(c, fr)
			sr = NodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && hmac.Equal(fr, root1) && hmac.Equal(sr, root2)
}

// Tree is an in-memory append-only tree over leaf hashes (witness, tests, the vector generator).
type Tree struct{ hs [][]byte }

func (t *Tree) Append(leafHash []byte) uint64 {
	t.hs = append(t.hs, leafHash)
	return uint64(len(t.hs) - 1)
}

func (t *Tree) Size() uint64         { return uint64(len(t.hs)) }
func (t *Tree) Root() []byte         { return RootFromLeafHashes(t.hs) }
func (t *Tree) Leaf(i uint64) []byte { return t.hs[i] }

// RootAt is the root of the first n leaves; Inclusion and Consistency the paths at a given tree size.
func (t *Tree) RootAt(n uint64) []byte { return RootFromLeafHashes(t.hs[:n]) }

func (t *Tree) Inclusion(idx, size uint64) [][]byte {
	if size > t.Size() {
		return nil
	}
	return InclusionPath(t.hs[:size], idx)
}

func (t *Tree) Consistency(from, to uint64) [][]byte {
	if to > t.Size() {
		return nil
	}
	return ConsistencyPath(t.hs[:to], from)
}

// EncodePath renders a path as comma-separated hex (the /v1/log/incl and /v1/log/cons wire form).
func EncodePath(path [][]byte) string {
	s := make([]string, len(path))
	for i, p := range path {
		s[i] = hex.EncodeToString(p)
	}
	return strings.Join(s, ",")
}

// DecodePath parses the wire form; at most MaxPathLen 32-byte elements.
func DecodePath(s string) ([][]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) > MaxPathLen {
		return nil, ErrPath
	}
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		b, err := hex.DecodeString(p)
		if err != nil || len(b) != 32 {
			return nil, ErrPath
		}
		out = append(out, b)
	}
	return out, nil
}
