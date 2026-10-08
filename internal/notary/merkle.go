package notary

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"
	"strings"
	"time"
)

// RFC 6962 Merkle tree over one UTC day of timestamps (SPEC-v2 17.2). Leaves are ordered by their
// sequence number n; leaf = SHA256(0x00 || h || t_be64 || n_be64) with t in unix seconds, node =
// SHA256(0x01 || L || R), the tree split at the largest power of two below its size. Proofs are the
// RFC 6962 audit paths and verify with the RFC 9162 algorithm in VerifyProof.

// HashSize is the size of every hash in the tree (SHA-256).
const HashSize = sha256.Size

// MaxProof bounds the hashes a proof may carry (2^40 leaves per day).
const MaxProof = 40

// Leaf is the leaf hash of one timestamp: SHA256(0x00 || h || t_be64 || n_be64).
func Leaf(h []byte, t time.Time, n int64) []byte {
	var buf [1 + HashSize + 16]byte
	buf[0] = 0
	copy(buf[1:1+HashSize], h)
	binary.BigEndian.PutUint64(buf[1+HashSize:], uint64(t.Unix()))
	binary.BigEndian.PutUint64(buf[1+HashSize+8:], uint64(n))
	s := sha256.Sum256(buf[:1+HashSize+16])
	return s[:]
}

// node is SHA256(0x01 || l || r).
func node(l, r []byte) []byte {
	var buf [1 + 2*HashSize]byte
	buf[0] = 1
	copy(buf[1:], l)
	copy(buf[1+HashSize:], r)
	s := sha256.Sum256(buf[:])
	return s[:]
}

// split returns the largest power of two strictly below n (n >= 2).
func split(n int) int { return 1 << (bits.Len(uint(n-1)) - 1) }

// Root is the RFC 6962 tree head of leaves in order: SHA256("") for none, the leaf itself for one.
func Root(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		s := sha256.Sum256(nil)
		return s[:]
	case 1:
		return leaves[0]
	}
	k := split(len(leaves))
	return node(Root(leaves[:k]), Root(leaves[k:]))
}

// Proof is the RFC 6962 audit path of leaves[idx]: the sibling hashes from the leaf up to the root.
// nil when idx is out of range (and for a one-leaf tree, whose root is the leaf).
func Proof(leaves [][]byte, idx int) [][]byte {
	if idx < 0 || idx >= len(leaves) {
		return nil
	}
	var path [][]byte
	for len(leaves) > 1 {
		k := split(len(leaves))
		if idx < k {
			path = append(path, Root(leaves[k:]))
			leaves = leaves[:k]
		} else {
			path = append(path, Root(leaves[:k]))
			leaves, idx = leaves[k:], idx-k
		}
	}
	// path is root-to-leaf; the wire order (and RFC 9162) is leaf-to-root.
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

// VerifyProof checks an inclusion proof (RFC 9162 2.1.3.2): leaf at index idx of a tree of size n
// hashes up through proof to root. Every hash must be HashSize bytes.
func VerifyProof(leaf []byte, idx, n int, proof [][]byte, root []byte) bool {
	if idx < 0 || n <= 0 || idx >= n || len(leaf) != HashSize || len(root) != HashSize || len(proof) > MaxProof {
		return false
	}
	fn, sn := uint64(idx), uint64(n-1)
	r := leaf
	for _, p := range proof {
		if len(p) != HashSize || sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = node(p, r)
			for fn&1 == 0 && fn != 0 {
				fn, sn = fn>>1, sn>>1
			}
		} else {
			r = node(r, p)
		}
		fn, sn = fn>>1, sn>>1
	}
	return sn == 0 && string(r) == string(root)
}

// FormatProof renders a proof as comma-separated lowercase hex ("-" for the empty path).
func FormatProof(proof [][]byte) string {
	if len(proof) == 0 {
		return "-"
	}
	parts := make([]string, len(proof))
	for i, p := range proof {
		parts[i] = hex.EncodeToString(p)
	}
	return strings.Join(parts, ",")
}

// ParseProof reverses FormatProof.
func ParseProof(s string) ([][]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	if len(parts) > MaxProof {
		return nil, errors.New("proof too long")
	}
	out := make([][]byte, 0, len(parts))
	for _, p := range parts {
		b, err := hex.DecodeString(strings.TrimSpace(p))
		if err != nil || len(b) != HashSize {
			return nil, errors.New("proof: bad hash")
		}
		out = append(out, b)
	}
	return out, nil
}
