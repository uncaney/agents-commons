package notary

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/trust"
)

// Caps (4.3) and bounds. Vars so tests can lower them.
var (
	AnonDaily   = 50 // anonymous timestamps per IP group per day; 4x per super-group (core.UseNetQuota)
	AttestDaily = 20 // attestations per root per day (x5 for established roots, core.UseQuota)
	// RowsKeep is the retention of ts rows (17.2: rows 1 y, roots forever).
	RowsKeep = 365 * 24 * time.Hour
)

const (
	MaxNote    = 64  // 17.2: note <= 64 bytes
	MaxText    = 200 // 17.3: attest text <= 200 bytes
	maxBody    = 4 << 10
	maxSkills  = 300
	maxExtra   = 8 // ReceiptExtraFn lines kept per receipt
	leafCache  = 8 << 20
	leafTTL    = time.Hour
	rootsTTL   = time.Minute
	dayFmt     = "2006-01-02"
	rootsPath  = "/ts/roots.txt"
	tsPath     = "/ts"
	tsCapKind  = "ts"
	attestKind = "attest"
)

// Statement types this package signs (17.1) and the rev 3 prefixes it registers in /verify's
// inference table (27.6, 26.6, 27.9) on behalf of the packages that produce them.
const (
	TypeTS     = "ts1"
	TypeRoot   = "root1"
	TypeRep    = "rep"
	TypeCard   = "cxc1"
	TypeAttest = "attest1"
)

func init() {
	sign.RegisterTypes(TypeTS, TypeRoot, TypeRep, TypeCard, TypeAttest,
		"rel1", "rand1", "ann1", "pk1", "svc1", "pin1", "row1", "export1", "manifest1", "frank1")
}

// Cross-package seams. Every var is nil-safe: unset means "nothing to add" (or 0).
var (
	// SkillsFn renders the owner's skill card summary (gym.SkillsLine): "kind:L3/0.87/31,…".
	SkillsFn func(ctx context.Context, q core.Q, root string) string
	// ReceiptExtraFn returns extra single-line fields for a sealed day (ctlog/wayback: "witness:
	// <url>", "chain=<hex>"); receipts print each on its own line, /ts/roots.txt appends them as
	// extra columns (whitespace collapsed to '_').
	ReceiptExtraFn func(ctx context.Context, q core.Q, day string) []string
	// RootExtraFn returns fields appended to the root1 statement before it is signed (chain=).
	RootExtraFn func(ctx context.Context, q core.Q, day string, n int, root []byte) []sign.KV
	// ReviewsFn counts a root's useful peer reviews (rev= on rep lines, rv= on cards).
	ReviewsFn func(ctx context.Context, q core.Q, root string) int
)

// signerP is the signer Register derives from the config; before Register the sign default is used.
var signerP atomic.Pointer[sign.Signer]

func signer() *sign.Signer {
	if s := signerP.Load(); s != nil {
		return s
	}
	return sign.Default()
}

// ErrDayOpen refuses sealing a UTC day that has not ended.
var ErrDayOpen = core.Bad("day not over")

// today is the current UTC date (midnight).
func today() time.Time {
	y, m, d := time.Now().UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// ParseDay parses a YYYY-MM-DD day.
func ParseDay(s string) (time.Time, error) {
	t, err := time.ParseInLocation(dayFmt, s, time.UTC)
	if err != nil {
		return time.Time{}, core.Bad("day must be YYYY-MM-DD")
	}
	return t, nil
}

// ParseHash decodes a 64-hex hash (case-insensitive).
func ParseHash(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if len(s) != 2*HashSize {
		return nil, core.Bad("h must be 64 hex chars (sha256)")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, core.Bad("h must be 64 hex chars (sha256)")
	}
	return b, nil
}

// --- stamps ------------------------------------------------------------------------------------

// Stamp notarises h (32 bytes) with a note (<= 64 bytes, server text) for root (” anonymous,
// core.SystemID for system stamps) and returns the sequence number and time of the receipt.
// First-seen semantics: a hash already in the log keeps its first n and t. System inserts bypass
// every cap (the callers are janitors); request paths charge their caps before calling it.
func Stamp(ctx context.Context, q core.Q, h []byte, note, root string) (n int64, t time.Time, err error) {
	n, t, _, err = stamp(ctx, q, h, note, root)
	return n, t, err
}

func stamp(ctx context.Context, q core.Q, h []byte, note, root string) (n int64, t time.Time, fresh bool, err error) {
	if len(h) != HashSize {
		return 0, time.Time{}, false, core.Bad("h must be 32 bytes")
	}
	if root != "" && !core.ValidID(root) {
		return 0, time.Time{}, false, core.Bad("root id")
	}
	note = sign.Clean(scrub.Normalize(note))
	if len(note) > MaxNote {
		return 0, time.Time{}, false, core.Bad(fmt.Sprintf("note must be <= %d bytes", MaxNote))
	}
	err = q.QueryRow(ctx, `INSERT INTO ts (h, note, owner, t, day) VALUES ($1, $2, $3, now(), (now() AT TIME ZONE 'UTC')::date)
		ON CONFLICT (h) DO NOTHING RETURNING n, t`, h, note, root).Scan(&n, &t)
	if errors.Is(err, pgx.ErrNoRows) {
		err = q.QueryRow(ctx, `SELECT n, t FROM ts WHERE h = $1`, h).Scan(&n, &t)
		return n, t.UTC(), false, err
	}
	return n, t.UTC(), err == nil, err
}

// Receipt is everything GET /ts/{h} shows about one hash.
type Receipt struct {
	H     []byte
	N     int64
	T     time.Time
	Day   string
	Note  string
	Owner string
	// Filled once the day is sealed.
	Root     []byte
	Idx      int
	Size     int
	Proof    [][]byte
	RootLine string
	RootSig  string
	Sealed   time.Time
	Extra    []string
}

// Line is the signed statement: ts1 h=<hex> t=<unix> n=<seq> k=<kid>.
func (rc *Receipt) Line() string {
	return sign.Canonical(TypeTS, sign.KV{K: "h", V: hex.EncodeToString(rc.H)}, sign.KV{K: "t", V: strconv.FormatInt(rc.T.Unix(), 10)},
		sign.KV{K: "n", V: strconv.FormatInt(rc.N, 10)}, sign.KV{K: "k", V: strconv.Itoa(signer().KID())})
}

// Sig signs Line.
func (rc *Receipt) Sig() string { return signer().Sign(TypeTS, rc.Line()) }

// IsSealed reports whether the receipt carries its day's root and proof.
func (rc *Receipt) IsSealed() bool { return len(rc.Root) == HashSize }

// Text is the wire receipt: statement, sig=, optional note:, then the root line (pending or
// root=<hex> idx=<i> proof=<hashes>), the signed root1 statement and any ReceiptExtraFn lines.
func (rc *Receipt) Text() string {
	var b strings.Builder
	b.WriteString(rc.Line() + "\n" + rc.Sig() + "\n")
	if rc.Note != "" {
		b.WriteString("note: " + doc.SafeLine(rc.Note) + "\n")
	}
	if !rc.IsSealed() {
		b.WriteString("root=pending day=" + rc.Day + "\n")
		return b.String()
	}
	fmt.Fprintf(&b, "root=%s idx=%d proof=%s\n%s\n%s\n", hex.EncodeToString(rc.Root), rc.Idx, FormatProof(rc.Proof), rc.RootLine, rc.RootSig)
	for _, l := range rc.Extra {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// JSON is the JSON twin of Text.
func (rc *Receipt) JSON() map[string]any {
	m := map[string]any{"statement": rc.Line(), "sig": rc.Sig(), "h": hex.EncodeToString(rc.H), "t": rc.T.Unix(),
		"n": rc.N, "k": signer().KID(), "day": rc.Day, "sealed": rc.IsSealed()}
	if rc.Note != "" {
		m["note"] = rc.Note
	}
	if rc.IsSealed() {
		proof := make([]string, len(rc.Proof))
		for i, p := range rc.Proof {
			proof[i] = hex.EncodeToString(p)
		}
		m["root"], m["idx"], m["size"], m["proof"] = hex.EncodeToString(rc.Root), rc.Idx, rc.Size, proof
		m["root_statement"], m["root_sig"] = rc.RootLine, rc.RootSig
		if len(rc.Extra) > 0 {
			m["extra"] = rc.Extra
		}
	}
	return m
}

// --- service -----------------------------------------------------------------------------------

type svc struct {
	d      *core.Deps
	leaves *core.ByteLRU // sealed days' leaf hashes (immutable) and the rendered roots.txt
}

func newSvc(d *core.Deps) *svc { return &svc{d: d, leaves: core.NewByteLRU(leafCache)} }

// dayLeaves returns the leaf hashes of a day in sequence order plus the sequence numbers. A
// sealed day is immutable, so its packed leaves (hash || n_be64 per row) are cached when cache is set.
func dayLeaves(ctx context.Context, q core.Q, day string, cache *core.ByteLRU) (leaves [][]byte, seqs []int64, err error) {
	const rec = HashSize + 8
	key := "d:" + day
	if cache != nil {
		if b, ok := cache.Get(key); ok && len(b)%rec == 0 {
			for i := 0; i+rec <= len(b); i += rec {
				leaves = append(leaves, b[i:i+HashSize])
				seqs = append(seqs, int64(binary.BigEndian.Uint64(b[i+HashSize:i+rec])))
			}
			return leaves, seqs, nil
		}
	}
	rows, err := q.Query(ctx, `SELECT n, h, t FROM ts WHERE day = $1 ORDER BY n`, day)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var packed []byte
	for rows.Next() {
		var n int64
		var h []byte
		var t time.Time
		if err := rows.Scan(&n, &h, &t); err != nil {
			return nil, nil, err
		}
		leaf := Leaf(h, t, n)
		leaves, seqs = append(leaves, leaf), append(seqs, n)
		if cache != nil {
			packed = append(packed, leaf...)
			packed = binary.BigEndian.AppendUint64(packed, uint64(n))
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if cache != nil && len(packed) > 0 {
		cache.Put(key, packed, leafTTL)
	}
	return leaves, seqs, nil
}

// receipt loads the first-seen receipt of h with its proof when the day is sealed; core.ErrNotFound
// for an unknown hash.
func (s *svc) receipt(ctx context.Context, q core.Q, h []byte) (*Receipt, error) {
	rc := &Receipt{H: h}
	var day time.Time
	var root []byte
	err := q.QueryRow(ctx, `SELECT n, t, day, note, owner, root FROM ts WHERE h = $1`, h).Scan(&rc.N, &rc.T, &day, &rc.Note, &rc.Owner, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rc.T, rc.Day = rc.T.UTC(), day.UTC().Format(dayFmt)
	if len(root) != HashSize {
		return rc, nil
	}
	var sealedAt time.Time
	err = q.QueryRow(ctx, `SELECT n, root, line, sig, sealed FROM ts_days WHERE day = $1`, rc.Day).Scan(&rc.Size, &rc.Root, &rc.RootLine, &rc.RootSig, &sealedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return rc, nil // sealed marker without a day row: served as pending, the janitor repairs it
	}
	if err != nil {
		return nil, err
	}
	rc.Sealed = sealedAt.UTC()
	leaves, seqs, err := dayLeaves(ctx, q, rc.Day, s.leaves)
	if err != nil {
		return nil, err
	}
	rc.Idx = -1
	for i, n := range seqs {
		if n == rc.N {
			rc.Idx = i
			break
		}
	}
	if rc.Idx < 0 || len(leaves) != rc.Size {
		rc.Root = nil // the day's rows no longer rebuild the sealed tree (retention): pending-shaped
		return rc, nil
	}
	rc.Proof = Proof(leaves, rc.Idx)
	rc.Extra = extraLines(ctx, q, rc.Day)
	return rc, nil
}

// extraLines runs ReceiptExtraFn and keeps at most maxExtra single safe lines.
func extraLines(ctx context.Context, q core.Q, day string) []string {
	if ReceiptExtraFn == nil {
		return nil
	}
	var out []string
	for _, l := range ReceiptExtraFn(ctx, q, day) {
		l = strings.TrimSpace(doc.SafeLine(l))
		if l == "" || strings.HasPrefix(l, "next:") || strings.HasPrefix(l, "> ") || strings.HasPrefix(l, "sig=") {
			continue
		}
		if len(l) > 512 {
			l = l[:512]
		}
		out = append(out, l)
		if len(out) == maxExtra {
			break
		}
	}
	return out
}

// --- sealing -----------------------------------------------------------------------------------

// Day is one sealed day.
type Day struct {
	Day    string
	N      int
	Root   []byte
	Line   string
	Sig    string
	Sealed time.Time
}

// SealDay seals one past UTC day inside the caller's tx: it builds the RFC 6962 tree over the
// day's rows in sequence order, signs `root1 day=<d> n=<n> root=<hex> k=<kid>` (plus RootExtraFn
// fields), stores ts_days, marks the rows and enqueues the courier job `anchor` {day, n, root, sig,
// line}. Idempotent: an already sealed day is returned with sealed=false; a day without rows is
// skipped (nil, false). ErrDayOpen for today or the future.
func SealDay(ctx context.Context, q core.Q, day time.Time) (d *Day, sealed bool, err error) {
	day = day.UTC().Truncate(24 * time.Hour)
	if !day.Before(today()) {
		return nil, false, ErrDayOpen
	}
	ds := day.Format(dayFmt)
	if d, err = loadDay(ctx, q, ds); err == nil {
		return d, false, nil
	} else if !errors.Is(err, core.ErrNotFound) {
		return nil, false, err
	}
	leaves, _, err := dayLeaves(ctx, q, ds, nil)
	if err != nil {
		return nil, false, err
	}
	if len(leaves) == 0 {
		return nil, false, nil
	}
	root := Root(leaves)
	kv := []sign.KV{{K: "day", V: ds}, {K: "n", V: strconv.Itoa(len(leaves))}, {K: "root", V: hex.EncodeToString(root)}}
	if RootExtraFn != nil {
		for _, f := range RootExtraFn(ctx, q, ds, len(leaves), root) {
			if f.K != "day" && f.K != "n" && f.K != "root" && f.K != "k" {
				kv = append(kv, f)
			}
		}
	}
	sg := signer()
	line := sign.Canonical(TypeRoot, append(kv, sign.KV{K: "k", V: strconv.Itoa(sg.KID())})...)
	sig := sg.Sign(TypeRoot, line)
	tag, err := q.Exec(ctx, `INSERT INTO ts_days (day, n, root, line, sig) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (day) DO NOTHING`, ds, len(leaves), root, line, sig)
	if err != nil {
		return nil, false, err
	}
	if tag.RowsAffected() == 0 {
		d, err = loadDay(ctx, q, ds)
		return d, false, err
	}
	if _, err := q.Exec(ctx, `UPDATE ts SET root = $1 WHERE day = $2`, root, ds); err != nil {
		return nil, false, err
	}
	payload := map[string]any{"day": ds, "n": len(leaves), "root": hex.EncodeToString(root), "sig": sig, "line": line}
	if err := core.Egress(ctx, q, "anchor", payload); err != nil && !errors.Is(err, core.ErrOutboxFull) {
		return nil, false, err
	}
	core.Event(ctx, q, "ts", ds, "", fmt.Sprintf("day %s sealed: %d timestamps, root %s", ds, len(leaves), hex.EncodeToString(root)[:16]))
	return &Day{Day: ds, N: len(leaves), Root: root, Line: line, Sig: sig, Sealed: time.Now().UTC()}, true, nil
}

func loadDay(ctx context.Context, q core.Q, day string) (*Day, error) {
	d := &Day{Day: day}
	err := q.QueryRow(ctx, `SELECT n, root, line, sig, sealed FROM ts_days WHERE day = $1`, day).Scan(&d.N, &d.Root, &d.Line, &d.Sig, &d.Sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return d, err
}

// SealPending seals every past day that still has unsealed rows, one transaction per day, oldest
// first; the janitor runs it under the task's advisory lock. It returns the days sealed now.
func SealPending(ctx context.Context, d *core.Deps) ([]string, error) {
	rows, err := d.DB.Query(ctx, `SELECT DISTINCT day FROM ts WHERE root IS NULL AND day < (now() AT TIME ZONE 'UTC')::date ORDER BY day LIMIT 64`)
	if err != nil {
		return nil, err
	}
	var days []time.Time
	for rows.Next() {
		var day time.Time
		if err := rows.Scan(&day); err != nil {
			rows.Close()
			return nil, err
		}
		days = append(days, day)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []string
	for _, day := range days {
		var sealed bool
		var dd *Day
		if err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
			var err error
			dd, sealed, err = SealDay(ctx, tx, day)
			if err == nil && dd != nil && !sealed {
				// A ts_days row exists but rows were left unmarked (a crash between the two writes).
				_, err = tx.Exec(ctx, `UPDATE ts SET root = $1 WHERE day = $2 AND root IS NULL`, dd.Root, dd.Day)
			}
			return err
		}); errors.Is(err, ErrDayOpen) {
			continue // the database clock is slightly ahead of ours around midnight: next tick
		} else if err != nil {
			return out, err
		}
		if sealed {
			out = append(out, dd.Day)
		}
	}
	return out, nil
}

// Days lists every sealed day, oldest first.
func Days(ctx context.Context, q core.Q) ([]Day, error) {
	rows, err := q.Query(ctx, `SELECT day, n, root, line, sig, sealed FROM ts_days ORDER BY day`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Day
	for rows.Next() {
		var d Day
		var day time.Time
		if err := rows.Scan(&day, &d.N, &d.Root, &d.Line, &d.Sig, &d.Sealed); err != nil {
			return nil, err
		}
		d.Day = day.UTC().Format(dayFmt)
		out = append(out, d)
	}
	return out, rows.Err()
}

// rootsText renders /ts/roots.txt: one line per sealed day, `<root1 statement> sig=<b64url>` plus
// the ReceiptExtraFn columns; modTime is the latest seal.
func (s *svc) rootsText(ctx context.Context, q core.Q) ([]byte, time.Time, error) {
	days, err := Days(ctx, q)
	if err != nil {
		return nil, time.Time{}, err
	}
	var b strings.Builder
	var mod time.Time
	for _, d := range days {
		b.WriteString(d.Line + " " + d.Sig)
		for _, x := range extraLines(ctx, q, d.Day) {
			b.WriteString(" " + strings.Join(strings.Fields(x), "_"))
		}
		b.WriteByte('\n')
		if d.Sealed.After(mod) {
			mod = d.Sealed
		}
	}
	return []byte(b.String()), mod.UTC(), nil
}

// --- reputation, cards, attestations -----------------------------------------------------------

// Rep is the portable reputation of a root (17.3).
type Rep struct {
	Root            string
	Rep, Lvl, AgeD  int
	Work, KBOK, Rev int
	Pub             string
	At              time.Time
}

// Line is `rep <root> rep=<n> lvl=L<l> age_d=<n> work=<n> kbok=<n> rev=<n> [pub=<hex>] at=<unix> k=<kid>`.
func (p *Rep) Line() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s rep=%d lvl=L%d age_d=%d work=%d kbok=%d rev=%d", TypeRep, p.Root, p.Rep, p.Lvl, p.AgeD, p.Work, p.KBOK, p.Rev)
	if p.Pub != "" {
		b.WriteString(" pub=" + p.Pub)
	}
	fmt.Fprintf(&b, " at=%d k=%d", p.At.Unix(), signer().KID())
	return b.String()
}

// Sig signs Line (type rep).
func (p *Rep) Sig() string { return signer().Sign(TypeRep, p.Line()) }

// JWS is the compact JWS form (?f=jws).
func (p *Rep) JWS() string { return signer().JWS(TypeRep, p.Line()) }

// JSON is the JSON twin.
func (p *Rep) JSON() map[string]any {
	return map[string]any{"statement": p.Line(), "sig": p.Sig(), "root": p.Root, "rep": p.Rep, "lvl": p.Lvl, "age_d": p.AgeD,
		"work": p.Work, "kbok": p.KBOK, "rev": p.Rev, "pub": p.Pub, "at": p.At.Unix(), "k": signer().KID()}
}

// loadRep builds the rep line of a root id; core.ErrNotFound for unknown ids and for subkeys.
func loadRep(ctx context.Context, q core.Q, root string) (*Rep, error) {
	if !core.ValidID(root) {
		return nil, core.ErrNotFound
	}
	st, err := trust.Load(ctx, q, root)
	if err != nil {
		return nil, err
	}
	if st.Root != root {
		return nil, core.ErrNotFound
	}
	p := &Rep{Root: root, Rep: st.Rep, Lvl: st.Level(), AgeD: int(st.Age / (24 * time.Hour)), At: time.Now().UTC()}
	err = q.QueryRow(ctx, `SELECT (SELECT count(*) FROM jobs WHERE root = $1 AND status = 'done'),
		(SELECT count(*) FROM kb WHERE author_root = $1 AND confirmed_at IS NOT NULL AND NOT hidden),
		(SELECT coalesce(encode(pub, 'hex'), '') FROM identities WHERE id = $1)`, root).Scan(&p.Work, &p.KBOK, &p.Pub)
	if err != nil {
		return nil, err
	}
	if ReviewsFn != nil {
		p.Rev = max(ReviewsFn(ctx, q, root), 0)
	}
	return p, nil
}

// Card is the owner card (17.3).
type Card struct {
	Root              string
	AgeD, Rep         int
	Posted, Confirmed int
	Jobs, RV          int
	Skills            string
	At                time.Time
}

// Line is `cxc1 id=<root> age=<d> rep=<n> kb=<posted>/<confirmed> jobs=<n> rv=<n> skills=<…> at=<unix> k=<kid>`.
func (c *Card) Line() string {
	skills := c.Skills
	if skills == "" {
		skills = "-"
	}
	return sign.Canonical(TypeCard, sign.KV{K: "id", V: c.Root}, sign.KV{K: "age", V: strconv.Itoa(c.AgeD)}, sign.KV{K: "rep", V: strconv.Itoa(c.Rep)},
		sign.KV{K: "kb", V: fmt.Sprintf("%d/%d", c.Posted, c.Confirmed)}, sign.KV{K: "jobs", V: strconv.Itoa(c.Jobs)}, sign.KV{K: "rv", V: strconv.Itoa(c.RV)},
		sign.KV{K: "skills", V: skills}, sign.KV{K: "at", V: strconv.FormatInt(c.At.Unix(), 10)}, sign.KV{K: "k", V: strconv.Itoa(signer().KID())})
}

// Sig signs Line (type cxc1).
func (c *Card) Sig() string { return signer().Sign(TypeCard, c.Line()) }

// JSON is the JSON twin.
func (c *Card) JSON() map[string]any {
	return map[string]any{"statement": c.Line(), "sig": c.Sig(), "id": c.Root, "age": c.AgeD, "rep": c.Rep, "kb_posted": c.Posted,
		"kb_confirmed": c.Confirmed, "jobs": c.Jobs, "rv": c.RV, "skills": c.Skills, "at": c.At.Unix(), "k": signer().KID()}
}

// loadCard builds the owner card of the caller's root.
func loadCard(ctx context.Context, q core.Q, id *core.Ident) (*Card, error) {
	st, err := trust.Load(ctx, q, id.Root)
	if err != nil {
		return nil, err
	}
	c := &Card{Root: st.Root, AgeD: int(st.Age / (24 * time.Hour)), Rep: st.Rep, At: time.Now().UTC()}
	err = q.QueryRow(ctx, `SELECT (SELECT count(*) FROM kb WHERE author_root = $1 AND NOT hidden),
		(SELECT count(*) FROM kb WHERE author_root = $1 AND confirmed_at IS NOT NULL AND NOT hidden),
		(SELECT count(*) FROM jobs WHERE root = $1 AND status = 'done')`, st.Root).Scan(&c.Posted, &c.Confirmed, &c.Jobs)
	if err != nil {
		return nil, err
	}
	if ReviewsFn != nil {
		c.RV = max(ReviewsFn(ctx, q, st.Root), 0)
	}
	if SkillsFn != nil {
		if sk := sign.Clean(SkillsFn(ctx, q, st.Root)); sk != "" {
			if len(sk) > maxSkills {
				sk = strings.TrimRight(sk[:maxSkills], ",")
			}
			c.Skills = strings.ReplaceAll(sk, " ", ",")
		}
	}
	return c, nil
}

// ErrL2 refuses attestations below L2 (17.3).
var ErrL2 = core.E(403, "auth", "L2 standing required (rep >= 5, 72 h, one confirmed entry)")

// Attestation is a signed self-statement of an L2 root (17.3).
type Attestation struct {
	Root string
	Lvl  int
	Text string
	T    time.Time
}

// Line is `attest1 id=<root> lvl=L<l> text=<text> t=<unix> k=<kid>`.
func (a *Attestation) Line() string {
	return sign.Canonical(TypeAttest, sign.KV{K: "id", V: a.Root}, sign.KV{K: "lvl", V: "L" + strconv.Itoa(a.Lvl)}, sign.KV{K: "text", V: a.Text},
		sign.KV{K: "t", V: strconv.FormatInt(a.T.Unix(), 10)}, sign.KV{K: "k", V: strconv.Itoa(signer().KID())})
}

// Sig signs Line (type attest1).
func (a *Attestation) Sig() string { return signer().Sign(TypeAttest, a.Line()) }

// JSON is the JSON twin.
func (a *Attestation) JSON() map[string]any {
	return map[string]any{"statement": a.Line(), "sig": a.Sig(), "id": a.Root, "lvl": a.Lvl, "text": a.Text, "t": a.T.Unix(), "k": signer().KID()}
}

// checkText validates an attestation text: normalised, one line, <= 200 bytes, no tier-1 secret
// (tier 2 masked in place), no lexicon hit at all (`err bad lexicon <flags>`, 17.3).
func checkText(text string) (string, error) {
	text = strings.TrimSpace(scrub.Normalize(text))
	if text == "" {
		return "", core.Bad("text required")
	}
	if !doc.OneLine(text) {
		return "", core.Bad("text must be a single line")
	}
	if len(text) > MaxText {
		return "", core.Bad(fmt.Sprintf("text must be <= %d bytes", MaxText))
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"text": &text}); aerr != nil {
		return "", aerr
	}
	// A server-signed statement must never lend credibility to an injection: every lexicon class
	// is refused here (authority claims first of all), not only the quarantine threshold.
	if score, flags, _ := scrub.Flags(text); score >= 1 || slices.Contains(flags, "authority") {
		return "", core.Bad("lexicon " + scrub.FlagsLine(flags))
	}
	return text, nil
}

// attest issues the statement for id after the L2 check and the daily quota (in the caller's tx).
func attest(ctx context.Context, q core.Q, id *core.Ident, text string) (*Attestation, error) {
	text, err := checkText(text)
	if err != nil {
		return nil, err
	}
	lvl := core.Level(ctx, q, id.Root)
	if lvl < 2 {
		return nil, ErrL2
	}
	if err := core.UseQuota(ctx, q, id, attestKind, AttestDaily); err != nil {
		return nil, err
	}
	if err := core.Audit(ctx, q, id.ID, "attest", "", len(text)); err != nil {
		return nil, err
	}
	return &Attestation{Root: id.Root, Lvl: lvl, Text: text, T: time.Now().UTC()}, nil
}

// --- write path shared by HTTP and MCP ---------------------------------------------------------

// write charges the cap of the caller (root cap 500/day flat through trust, or the anonymous
// group/super-group quota) and stamps h. id nil = anonymous with verified PoW keys grp/super.
func write(ctx context.Context, q core.Q, id *core.Ident, grp string, h []byte, note string) (*Receipt, bool, error) {
	owner := ""
	if id != nil {
		st, err := trust.Load(ctx, q, id.Root)
		if err != nil {
			return nil, false, err
		}
		if err := trust.UseCap(ctx, q, st, tsCapKind); err != nil {
			return nil, false, err
		}
		owner = id.Root
	} else if err := core.UseNetQuota(ctx, q, grp, tsCapKind, AnonDaily); err != nil {
		return nil, false, err
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"note": &note}); aerr != nil {
		return nil, false, aerr
	}
	n, t, fresh, err := stamp(ctx, q, h, note, owner)
	if err != nil {
		return nil, false, err
	}
	rc := &Receipt{H: h, N: n, T: t, Day: t.Format(dayFmt)}
	return rc, fresh, nil
}

// stampJSON is the JSON twin of a POST /v1/ts reply.
func stampJSON(rc *Receipt, fresh bool) map[string]any {
	return map[string]any{"statement": rc.Line(), "sig": rc.Sig(), "h": hex.EncodeToString(rc.H), "t": rc.T.Unix(), "n": rc.N,
		"k": signer().KID(), "day": rc.Day, "first_seen": fresh}
}

// export writes the caller root's timestamps as JSONL (OnExport).
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	rows, err := q.Query(ctx, `SELECT n, h, t, note, root FROM ts WHERE owner = $1 ORDER BY n`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	enc := json.NewEncoder(w)
	for rows.Next() {
		var n int64
		var h, root []byte
		var t time.Time
		var note string
		if err := rows.Scan(&n, &h, &t, &note, &root); err != nil {
			return err
		}
		rec := map[string]any{"kind": "ts", "n": n, "h": hex.EncodeToString(h), "t": t.UTC().Format(time.RFC3339), "note": note}
		if len(root) == HashSize {
			rec["root"] = hex.EncodeToString(root)
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}
