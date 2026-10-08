package keys

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
)

// The key log (E2EE 3.3): klog holds the leaves, knodes every perfect-subtree node (level 0 = the
// leaf hashes), so the root of any tree size, an audit path and a consistency path are O(log n)
// point reads over immutable rows. Appends run under pg_advisory_xact_lock(hashtext('klog')) in
// the caller's transaction. Hashing follows RFC 6962: leaf sha256(0x00||data), node sha256(0x01||l||r).

const klogLock = "klog"

// LogSizeCap bounds proof parameters (levels fit a smallint, positions a bigint).
const LogSizeCap = 1 << 62

func lockLog(ctx context.Context, q core.Q) error {
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, klogLock)
	return err
}

// LogSize is the number of leaves (idx is contiguous from 0).
func LogSize(ctx context.Context, q core.Q) (uint64, error) {
	var n int64
	err := q.QueryRow(ctx, `SELECT coalesce(max(idx), -1) + 1 FROM klog`).Scan(&n)
	return uint64(n), err
}

// appendLeaf writes leaf idx = size with its item hash and updates the perfect-subtree nodes. The
// caller holds a transaction; the klog lock is taken here (re-entrant within the transaction).
func appendLeaf(ctx context.Context, q core.Q, kind uint8, id string, seq int, itemHash []byte) (idx uint64, leaf []byte, err error) {
	if len(itemHash) != 32 {
		return 0, nil, errors.New("keys: item hash must be 32 bytes")
	}
	if err := lockLog(ctx, q); err != nil {
		return 0, nil, err
	}
	n, err := LogSize(ctx, q)
	if err != nil {
		return 0, nil, err
	}
	if n >= LogSizeCap {
		return 0, nil, errors.New("keys: log full")
	}
	leaf = e2e.KlogLeaf(kind, id, itemHash, n)
	if _, err := q.Exec(ctx, `INSERT INTO klog (idx, kind, id, seq, item_hash, leaf) VALUES ($1, $2, $3, $4, $5, $6)`,
		int64(n), int16(kind), id, seq, itemHash, leaf); err != nil {
		return 0, nil, err
	}
	h, level, pos := leaf, 0, n
	for {
		if err := putNode(ctx, q, level, pos, h); err != nil {
			return 0, nil, err
		}
		if pos&1 == 0 {
			break
		}
		left, err := readNode(ctx, q, level, pos-1, false) // uncommitted siblings are never cached
		if err != nil {
			return 0, nil, err
		}
		h, level, pos = e2e.NodeHash(left, h), level+1, pos>>1
	}
	return n, leaf, nil
}

func nodeKey(level int, pos uint64) string {
	return strconv.Itoa(level) + ":" + strconv.FormatUint(pos, 10)
}

// putNode upserts a node: a rolled-back append may leave the same (level, pos) to a later append
// with another hash, which is why writers never populate the cache.
func putNode(ctx context.Context, q core.Q, level int, pos uint64, h []byte) error {
	_, err := q.Exec(ctx, `INSERT INTO knodes (level, pos, hash) VALUES ($1, $2, $3) ON CONFLICT (level, pos) DO UPDATE SET hash = EXCLUDED.hash`,
		int16(level), int64(pos), h)
	return err
}

// node reads a committed perfect-subtree node through the cache (committed nodes are immutable).
func node(ctx context.Context, q core.Q, level int, pos uint64) ([]byte, error) {
	return readNode(ctx, q, level, pos, true)
}

func readNode(ctx context.Context, q core.Q, level int, pos uint64, cache bool) ([]byte, error) {
	k := nodeKey(level, pos)
	if cache {
		if h, ok := nodeCache.Get(k); ok {
			return h, nil
		}
	}
	var h []byte
	if err := q.QueryRow(ctx, `SELECT hash FROM knodes WHERE level = $1 AND pos = $2`, int16(level), int64(pos)).Scan(&h); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("keys: node %s missing", k)
		}
		return nil, err
	}
	if cache {
		nodeCache.Put(k, h, 0)
	}
	return h, nil
}

// topLevel is the level whose single node covers a tree of size leaves (0 for sizes 0 and 1).
func topLevel(size uint64) int {
	if size <= 1 {
		return 0
	}
	return bits.Len64(size - 1)
}

// rangeHash is MTH over the leaves [pos<<level, min((pos+1)<<level, size)); nil when empty. A range
// that fits in the tree is a stored node; a partial (right-spine) range is hashed from its children.
func rangeHash(ctx context.Context, q core.Q, level int, pos, size uint64) ([]byte, error) {
	start := pos << level
	if start >= size {
		return nil, nil
	}
	if start+(1<<level) <= size {
		return node(ctx, q, level, pos)
	}
	left, err := rangeHash(ctx, q, level-1, 2*pos, size)
	if err != nil {
		return nil, err
	}
	right, err := rangeHash(ctx, q, level-1, 2*pos+1, size)
	if err != nil {
		return nil, err
	}
	if right == nil {
		return left, nil
	}
	return e2e.NodeHash(left, right), nil
}

// RootAt is the RFC 6962 root of the first size leaves.
func RootAt(ctx context.Context, q core.Q, size uint64) ([]byte, error) {
	if size == 0 {
		return e2e.EmptyRoot(), nil
	}
	return rangeHash(ctx, q, topLevel(size), 0, size)
}

// InclusionPath is PATH(m, D[size]) (RFC 6962 2.1.1) read from the stored nodes.
func InclusionPath(ctx context.Context, q core.Q, m, size uint64) ([][]byte, error) {
	if m >= size || size > LogSizeCap {
		return nil, core.Bad("leaf must be below size")
	}
	return inclPath(ctx, q, topLevel(size), 0, m, size)
}

func inclPath(ctx context.Context, q core.Q, level int, pos, m, size uint64) ([][]byte, error) {
	if level == 0 {
		return nil, nil
	}
	start, half := pos<<level, uint64(1)<<(level-1)
	end := min(start+(uint64(1)<<level), size)
	if end-start <= half { // the right child is empty: this range is its left child's tree
		return inclPath(ctx, q, level-1, 2*pos, m, size)
	}
	if m < start+half {
		path, err := inclPath(ctx, q, level-1, 2*pos, m, size)
		if err != nil {
			return nil, err
		}
		right, err := rangeHash(ctx, q, level-1, 2*pos+1, size)
		if err != nil {
			return nil, err
		}
		return append(path, right), nil
	}
	path, err := inclPath(ctx, q, level-1, 2*pos+1, m, size)
	if err != nil {
		return nil, err
	}
	left, err := node(ctx, q, level-1, 2*pos)
	if err != nil {
		return nil, err
	}
	return append(path, left), nil
}

// ConsistencyPath is PROOF(m, D[size]) (RFC 6962 2.1.2) between tree sizes m and size, 0 < m <= size.
func ConsistencyPath(ctx context.Context, q core.Q, m, size uint64) ([][]byte, error) {
	if m == 0 || m > size || size > LogSizeCap {
		return nil, core.Bad("from must be 1..to")
	}
	if m == size {
		return nil, nil
	}
	return subProof(ctx, q, topLevel(size), 0, m, size, true)
}

// subProof is SUBPROOF(m, D[range], complete) with the range's leaves counted from its start.
func subProof(ctx context.Context, q core.Q, level int, pos, m, size uint64, complete bool) ([][]byte, error) {
	start := pos << level
	end := min(start+(uint64(1)<<level), size)
	if m == end-start {
		if complete {
			return nil, nil
		}
		h, err := rangeHash(ctx, q, level, pos, size)
		return [][]byte{h}, err
	}
	half := uint64(1) << (level - 1)
	if end-start <= half {
		return subProof(ctx, q, level-1, 2*pos, m, size, complete)
	}
	if m <= half {
		path, err := subProof(ctx, q, level-1, 2*pos, m, size, complete)
		if err != nil {
			return nil, err
		}
		right, err := rangeHash(ctx, q, level-1, 2*pos+1, size)
		if err != nil {
			return nil, err
		}
		return append(path, right), nil
	}
	path, err := subProof(ctx, q, level-1, 2*pos+1, m-half, size, false)
	if err != nil {
		return nil, err
	}
	left, err := node(ctx, q, level-1, 2*pos)
	if err != nil {
		return nil, err
	}
	return append(path, left), nil
}

// --- signed heads --------------------------------------------------------------------------------

// Head is a signed tree head (ksth row).
type Head struct {
	Size uint64
	Root []byte
	At   time.Time
	Sig  []byte
}

// Line renders `size=<n> root=<hex> at=<unix> sig=<b64> cert=<b64>` (E2EE 3.3; e2e.ParseSTHLine reads it).
func (h *Head) Line(cert []byte) string {
	return fmt.Sprintf("size=%d root=%s at=%d sig=%s cert=%s", h.Size, hex.EncodeToString(h.Root), h.At.Unix(), b64(h.Sig), b64(cert))
}

// E2E converts to the pure-function head type.
func (h *Head) E2E() *e2e.Head {
	return &e2e.Head{Size: h.Size, Root: h.Root, At: uint64(h.At.Unix()), Sig: h.Sig}
}

func scanHead(row pgx.Row) (*Head, error) {
	h := &Head{}
	var size int64
	if err := row.Scan(&size, &h.Root, &h.At, &h.Sig); err != nil {
		return nil, err
	}
	h.Size = uint64(size)
	return h, nil
}

func (s *svc) latestHead(ctx context.Context, q core.Q) (*Head, error) {
	h, err := scanHead(q.QueryRow(ctx, `SELECT size, root, at, sig FROM ksth ORDER BY size DESC LIMIT 1`))
	if err == nil {
		s.head.Store(h)
	}
	return h, err
}

func (s *svc) headAt(ctx context.Context, q core.Q, size uint64) (*Head, error) {
	return scanHead(q.QueryRow(ctx, `SELECT size, root, at, sig FROM ksth WHERE size = $1`, int64(size)))
}

// signHead signs the current tree (size, root, now) under the online key and upserts ksth: a size
// already signed keeps its root (it cannot change) and gains the new at and signature.
func (s *svc) signHead(ctx context.Context) (*Head, error) {
	var h *Head
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := lockLog(ctx, tx); err != nil {
			return err
		}
		size, err := LogSize(ctx, tx)
		if err != nil {
			return err
		}
		root, err := RootAt(ctx, tx, size)
		if err != nil {
			return err
		}
		at := time.Now().Truncate(time.Second)
		h = &Head{Size: size, Root: root, At: at, Sig: e2e.Sign(s.sk.online, e2e.STHBytes(size, root, uint64(at.Unix())))}
		_, err = tx.Exec(ctx, `INSERT INTO ksth (size, root, at, sig) VALUES ($1, $2, $3, $4)
			ON CONFLICT (size) DO UPDATE SET at = EXCLUDED.at, sig = EXCLUDED.sig WHERE ksth.root = EXCLUDED.root`, int64(size), root, at, h.Sig)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.head.Store(h)
	return h, nil
}

// Cosign is a witness or root cosignature of a head (kcosign row).
type Cosign struct {
	Signer string
	HeadAt time.Time
	Sig    []byte
}

func (c Cosign) Line() string {
	return fmt.Sprintf("cosign id=%s at=%d sig=%s", c.Signer, c.HeadAt.Unix(), b64(c.Sig))
}

func (s *svc) cosigns(ctx context.Context, q core.Q, size uint64) ([]Cosign, error) {
	rows, err := q.Query(ctx, `SELECT signer, head_at, sig FROM kcosign WHERE size = $1 ORDER BY signer`, int64(size))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cosign
	for rows.Next() {
		var c Cosign
		if err := rows.Scan(&c.Signer, &c.HeadAt, &c.Sig); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// addCosign verifies sig over the head of size under pk and stores it for signer (once per signer and size).
func (s *svc) addCosign(ctx context.Context, q core.Q, size uint64, signer string, pk, sig []byte) (*Head, error) {
	h, err := s.headAt(ctx, q, size)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.E(404, "notfound", "no head at size "+strconv.FormatUint(size, 10))
	}
	if err != nil {
		return nil, err
	}
	if !e2e.Verify(pk, e2e.WitnessBytes(h.Size, h.Root, uint64(h.At.Unix())), sig) {
		return nil, core.E(400, "sig", "cosignature does not verify over this head")
	}
	tag, err := q.Exec(ctx, `INSERT INTO kcosign (size, signer, head_at, sig) VALUES ($1, $2, $3, $4) ON CONFLICT (size, signer) DO NOTHING`,
		int64(size), signer, h.At, sig)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, core.E(409, "dup", "already cosigned")
	}
	return h, nil
}

// LogEntry is one klog row.
type LogEntry struct {
	Idx      uint64
	Kind     int
	ID       string
	Seq      int
	ItemHash []byte
	Leaf     []byte
	At       time.Time
}

// Entries lists leaves from idx (delta sync, <= maxLogLines).
func Entries(ctx context.Context, q core.Q, from uint64, n int) ([]LogEntry, error) {
	if n <= 0 || n > maxLogLines {
		n = maxLogLines
	}
	rows, err := q.Query(ctx, `SELECT idx, kind, id, seq, item_hash, leaf, at FROM klog WHERE idx >= $1 ORDER BY idx LIMIT $2`, int64(from), n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEntries(rows)
}

// EntriesFor lists every leaf of an id.
func EntriesFor(ctx context.Context, q core.Q, id string) ([]LogEntry, error) {
	rows, err := q.Query(ctx, `SELECT idx, kind, id, seq, item_hash, leaf, at FROM klog WHERE id = $1 ORDER BY idx LIMIT $2`, id, maxLogLines)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEntries(rows)
}

func scanEntries(rows pgx.Rows) ([]LogEntry, error) {
	var out []LogEntry
	for rows.Next() {
		var e LogEntry
		var idx int64
		var kind int16
		if err := rows.Scan(&idx, &kind, &e.ID, &e.Seq, &e.ItemHash, &e.Leaf, &e.At); err != nil {
			return nil, err
		}
		e.Idx, e.Kind = uint64(idx), int(kind)
		out = append(out, e)
	}
	return out, rows.Err()
}

// deltaLines renders `<idx> <kind> <id> <item_hash> <leaf>`; idLines renders `<idx> <kind> <seq> <item_hash> <at>`.
func deltaLines(es []LogEntry) string {
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "%d %d %s %s %s\n", e.Idx, e.Kind, e.ID, hex.EncodeToString(e.ItemHash), hex.EncodeToString(e.Leaf))
	}
	return b.String()
}

func idLines(es []LogEntry) string {
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "%d %d %d %s %d\n", e.Idx, e.Kind, e.Seq, hex.EncodeToString(e.ItemHash), e.At.Unix())
	}
	return b.String()
}

func entriesJSON(es []LogEntry) []map[string]any {
	out := make([]map[string]any, 0, len(es))
	for _, e := range es {
		out = append(out, map[string]any{"idx": e.Idx, "kind": e.Kind, "id": e.ID, "seq": e.Seq,
			"item_hash": hex.EncodeToString(e.ItemHash), "leaf": hex.EncodeToString(e.Leaf), "at": e.At.Unix()})
	}
	return out
}
