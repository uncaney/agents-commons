package export

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/sign"
)

const (
	dateFmt       = "2006-01-02"
	keepDailies   = 7 // retained besides the latest date
	tombstoneTTL  = 90 * 24 * time.Hour
	exportHour    = 3 // daily run at 03:00 UTC
	retryAfterErr = 10 * time.Minute
	pageSize      = 500
	maxLine       = 1 << 20 // longest JSONL line a filter pass accepts
	spaceJSONLMax = 2 << 20 // SpaceJSONL cap (27.5)
	usedSQL       = `SELECT coalesce(nullif((SELECT s FROM flags WHERE k = 'export:bytes'), ''), '0')::bigint`

	// Retention is the manifest's retention statement.
	Retention = "latest + the last 7 dailies, under 1 GiB; nothing is kept indefinitely"
)

// MaxBytes caps EXPORT_DIR (storage class exports, 21.2): the oldest dates are dropped first.
var MaxBytes int64 = 1 << 30

var (
	shardKinds = []string{"kb", "tasks", "claims", "digests"}
	// FileRe is the /export/{file} allowlist (9.5) plus the P111 delta shards (27.7).
	FileRe = regexp.MustCompile(`^(kb|tasks|claims|digests|delta)-(\d{4}-\d{2}-\d{2})\.jsonl\.gz$`)
	// summed are the non-shard files listed in SHA256SUMS and SIGNATURES, in order.
	summed = []string{"tombstones.jsonl", "croissant.json", "README.md", "manifest.json"}

	errUnchanged = errors.New("unchanged")
)

// ManifestFile is one entry of manifest.json files[] (and ExtraFileFn's return type).
type ManifestFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Rows   int64  `json:"rows"`
}

// Manifest is /export/manifest.json (9.5; sig per 27.1: type manifest1 over the compact JSON of
// the manifest without the sig member, keys in file order).
type Manifest struct {
	Date      string         `json:"date"`
	Generated string         `json:"generated"`
	Files     []ManifestFile `json:"files"`
	License   string         `json:"license"`
	Retention string         `json:"retention"`
	Latest    string         `json:"latest,omitempty"`
	KID       int            `json:"kid,omitempty"`
	Sig       string         `json:"sig,omitempty"`
}

// ExtraFileFn lists shards another package materialises in EXPORT_DIR (P111 delta-<date>);
// nil-safe. Files present on disk are measured there; the hint supplies row counts.
var ExtraFileFn func(ctx context.Context) ([]ManifestFile, error)

// Service owns EXPORT_DIR. Every write to the directory happens under mu.
type Service struct {
	d        *core.Deps
	dir, lic string
	now      func() time.Time
	mu       sync.Mutex
	lastFail time.Time
	man      atomic.Pointer[manCache]
}

type manCache struct {
	m    *Manifest
	size int64
	mod  time.Time
}

var cur atomic.Pointer[Service]

// New builds the service from the config (EXPORT_DIR, LICENSE_CONTENT) without installing it.
func New(d *core.Deps) *Service {
	dir := d.Cfg.ExportDir
	if dir == "" {
		dataDir := d.Cfg.DataDir
		if dataDir == "" {
			dataDir = "./data"
		}
		dir = filepath.Join(dataDir, "export")
	}
	lic := d.Cfg.LicenseContent
	if lic == "" {
		lic = "CC0-1.0"
	}
	return &Service{d: d, dir: dir, lic: lic, now: time.Now}
}

// Register mounts the routes, hooks and janitor task and installs the package default used by
// Remove, Regen, Row and Ops. core.ExportRemoveFn is set here too (idempotent with P60a).
func Register(mux *http.ServeMux, d *core.Deps) {
	s := New(d)
	cur.Store(s)
	core.ExportRemoveFn = Remove
	sign.RegisterTypes("export1", "manifest1")
	s.routes(mux)
	d.StorageClass("exports", MaxBytes, usedSQL)
	d.RegisterSitemap("export", s.sitemap)
	d.Janitor.Add("export", s.tick)
}

// Dir is the export directory.
func (s *Service) Dir() string { return s.dir }

// Regen writes today's dump through the installed service.
func Regen(ctx context.Context) error {
	s := cur.Load()
	if s == nil {
		return errors.New("export: not registered")
	}
	return s.Regen(ctx)
}

// tick is the janitor task: once per UTC day after 03:00 (immediately when nothing was ever
// exported), recorded in the flag export:<date>; a failed run is retried after 10 min.
func (s *Service) tick(ctx context.Context) error {
	now := s.now().UTC()
	today := now.Format(dateFmt)
	if s.d.Flag("export:"+today) || now.Sub(s.lastFail) < retryAfterErr {
		return nil
	}
	if now.Hour() < exportHour && s.manifest() != nil {
		return nil
	}
	if err := s.Regen(ctx); err != nil {
		s.lastFail = now
		return err
	}
	if err := s.d.SetFlag(ctx, "export:"+today, true, ""); err != nil {
		return err
	}
	_, err := s.d.DB.Exec(ctx, `DELETE FROM flags WHERE k LIKE 'export:____-__-__' AND k < $1`,
		"export:"+now.AddDate(0, 0, -10).Format(dateFmt))
	return err
}

// q is the pool janitor work runs on (the ops pool when present: longer statement timeout).
func (s *Service) q() core.Q {
	if s.d.Ops != nil {
		return s.d.Ops
	}
	return s.d.DB
}

// Regen regenerates every shard for today, the tombstones, the aux files and the signatures,
// applies retention and enqueues the hf mirror for each shard.
func (s *Service) Regen(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	date := s.now().UTC().Format(dateFmt)
	fresh := map[string]ManifestFile{}
	for _, kind := range shardKinds {
		name := kind + "-" + date + ".jsonl.gz"
		mf, err := s.writeShard(ctx, kind, name)
		if err != nil {
			return fmt.Errorf("export %s: %w", name, err)
		}
		fresh[name] = mf
	}
	if err := s.writeTombstones(ctx); err != nil {
		return fmt.Errorf("export tombstones: %w", err)
	}
	if err := s.retain(); err != nil {
		return err
	}
	if err := s.finish(ctx, date, fresh); err != nil {
		return err
	}
	for _, kind := range shardKinds {
		s.egress(ctx, "hf", map[string]any{"file": kind + "-" + date + ".jsonl.gz"})
	}
	s.recordUsage(ctx)
	return nil
}

// writeShard streams the visible rows of one kind into <name> (gzip JSONL, tmp+rename).
func (s *Service) writeShard(ctx context.Context, kind, name string) (ManifestFile, error) {
	var rows int64
	size, sum, err := s.writeAtomic(name, func(w io.Writer) error {
		gz := gzip.NewWriter(w)
		enc := json.NewEncoder(gz)
		enc.SetEscapeHTML(false)
		emit := func(row map[string]any) error {
			rows++
			return enc.Encode(row)
		}
		q := s.q()
		var err error
		switch kind {
		case "kb":
			err = kbRows(ctx, q, "", s.lic, emit)
		case "tasks":
			err = taskRows(ctx, q, 0, "", s.lic, emit)
		case "claims":
			err = claimRows(ctx, q, "", s.lic, emit)
		case "digests":
			err = digestRows(ctx, q, "", s.lic, emit)
		default:
			err = core.Bad("export kind")
		}
		if err != nil {
			return err
		}
		return gz.Close()
	})
	if err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{Name: name, Size: size, SHA256: sum, Rows: rows}, nil
}

type countHash struct {
	w io.Writer
	n int64
	h hash.Hash
}

func (c *countHash) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	c.h.Write(p[:n])
	return n, err
}

// writeAtomic writes name through fn into a temp file in the directory and renames it over the
// target; fn returning an error (errUnchanged included) leaves the target untouched.
func (s *Service) writeAtomic(name string, fn func(w io.Writer) error) (size int64, sum string, err error) {
	f, err := os.CreateTemp(s.dir, "."+name+".*.tmp")
	if err != nil {
		return 0, "", err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			os.Remove(tmp)
		}
	}()
	ch := &countHash{w: f, h: sha256.New()}
	if err = fn(ch); err != nil {
		f.Close()
		return 0, "", err
	}
	if err = f.Close(); err != nil {
		return 0, "", err
	}
	if err = os.Rename(tmp, filepath.Join(s.dir, name)); err != nil {
		return 0, "", err
	}
	return ch.n, hex.EncodeToString(ch.h.Sum(nil)), nil
}

// --- tombstones --------------------------------------------------------------------------------

type tombstone struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	RemovedAt time.Time `json:"removed_at"`
	Reason    string    `json:"reason"`
}

var reasonRe = regexp.MustCompile(`^[a-z][a-z-]{0,30}$`)

func (t tombstone) key() string { return t.Kind + "\x00" + t.ID }

// validTombstoneID accepts the ids a line may carry: a core id for kb/claim/digest, digits for tasks.
func validTombstoneID(kind, id string) bool {
	switch kind {
	case "kb":
		return core.ValidIDPrefix(id, 'k')
	case "claim":
		return core.ValidIDPrefix(id, 'v')
	case "digest":
		return core.ValidIDPrefix(id, 'd')
	case "task":
		n, err := strconv.ParseInt(id, 10, 64)
		return err == nil && n > 0 && len(id) <= 18
	}
	return false
}

// writeTombstones regenerates tombstones.jsonl: kb_tombstones (plus task/claim/digest tombstone
// tables when they exist) within 90 d, merged with the lines Remove appended that no table
// derives (table rows win), oldest first.
func (s *Service) writeTombstones(ctx context.Context) error {
	cut := s.now().Add(-tombstoneTTL)
	all, err := s.dbTombstones(ctx, cut)
	if err != nil {
		return err
	}
	return s.writeTombstoneFile(all, cut)
}

// writeTombstoneFile merges extra lines into the existing file (extra wins) and rewrites it.
func (s *Service) writeTombstoneFile(extra []tombstone, cut time.Time) error {
	seen := map[string]bool{}
	var all []tombstone
	for _, t := range extra {
		if !seen[t.key()] {
			seen[t.key()] = true
			all = append(all, t)
		}
	}
	for _, t := range readTombstones(filepath.Join(s.dir, "tombstones.jsonl")) {
		if t.RemovedAt.Before(cut) || seen[t.key()] {
			continue
		}
		seen[t.key()] = true
		all = append(all, t)
	}
	sort.Slice(all, func(i, j int) bool {
		if !all[i].RemovedAt.Equal(all[j].RemovedAt) {
			return all[i].RemovedAt.Before(all[j].RemovedAt)
		}
		return all[i].ID < all[j].ID
	})
	_, _, err := s.writeAtomic("tombstones.jsonl", func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		for _, t := range all {
			if err := enc.Encode(t); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// readTombstones parses an existing tombstones.jsonl, dropping malformed or unsafe lines.
func readTombstones(path string) []tombstone {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []tombstone
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), maxLine)
	for sc.Scan() {
		var t tombstone
		if json.Unmarshal(sc.Bytes(), &t) != nil || !validTombstoneID(t.Kind, t.ID) || t.RemovedAt.IsZero() {
			continue
		}
		if !reasonRe.MatchString(t.Reason) {
			t.Reason = "removed"
		}
		out = append(out, t)
	}
	return out
}

// dbTombstones reads kb_tombstones and, guarded by existence and shape, the task/claim/digest
// tombstone tables of later packages.
func (s *Service) dbTombstones(ctx context.Context, cut time.Time) ([]tombstone, error) {
	q := s.q()
	var out []tombstone
	read := func(sql, kind string) error {
		rows, err := q.Query(ctx, sql, cut)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t tombstone
			if err := rows.Scan(&t.ID, &t.Reason, &t.RemovedAt); err != nil {
				return err
			}
			t.Kind = kind
			if !validTombstoneID(kind, t.ID) {
				continue
			}
			if !reasonRe.MatchString(t.Reason) {
				t.Reason = "removed"
			}
			out = append(out, t)
		}
		return rows.Err()
	}
	if err := read(`SELECT id, reason, at FROM kb_tombstones WHERE at > $1 ORDER BY at`, "kb"); err != nil {
		return nil, err
	}
	for _, g := range []struct{ table, kind string }{{"task_tombstones", "task"}, {"claim_tombstones", "claim"}, {"digest_tombstones", "digest"}} {
		var ok bool
		err := q.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL AND (SELECT count(*) FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = $1 AND column_name IN ('id', 'reason', 'at')) = 3`, g.table).Scan(&ok)
		if err != nil || !ok {
			continue
		}
		if err := read(`SELECT id::text, coalesce(reason::text, 'removed'), at FROM `+g.table+` WHERE at > $1 ORDER BY at`, g.kind); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// --- retention ---------------------------------------------------------------------------------

// retain keeps the newest date plus keepDailies older dates (every kind of shard, delta included),
// then drops the oldest dates until the directory fits MaxBytes; stale temp files go too.
func (s *Service) retain() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	byDate := map[string][]string{}
	sizes := map[string]int64{}
	var total int64
	for _, e := range entries {
		name := e.Name()
		info, err := e.Info()
		if err != nil {
			continue
		}
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp") {
			if time.Since(info.ModTime()) > time.Hour {
				os.Remove(filepath.Join(s.dir, name))
			}
			continue
		}
		m := FileRe.FindStringSubmatch(name)
		if m == nil {
			total += info.Size()
			continue
		}
		byDate[m[2]] = append(byDate[m[2]], name)
		sizes[name] = info.Size()
	}
	dates := make([]string, 0, len(byDate))
	for d := range byDate {
		dates = append(dates, d)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dates)))
	keep := dates
	if len(keep) > keepDailies+1 {
		keep = keep[:keepDailies+1]
	}
	drop := dates[len(keep):]
	for _, d := range keep {
		for _, n := range byDate[d] {
			total += sizes[n]
		}
	}
	for len(keep) > 1 && total > MaxBytes {
		last := keep[len(keep)-1]
		for _, n := range byDate[last] {
			total -= sizes[n]
		}
		drop = append(drop, last)
		keep = keep[:len(keep)-1]
	}
	for _, d := range drop {
		for _, n := range byDate[d] {
			if err := os.Remove(filepath.Join(s.dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

// --- manifest, sums, signatures ----------------------------------------------------------------

// finish rebuilds croissant.json, README.md, manifest.json (+ .sig), SHA256SUMS (+ .sig) and
// SIGNATURES from the shards on disk; fresh carries the measurements of files written this run.
func (s *Service) finish(ctx context.Context, date string, fresh map[string]ManifestFile) error {
	files, err := s.listShards(ctx, fresh)
	if err != nil {
		return err
	}
	latest := ""
	for _, f := range files {
		if strings.HasPrefix(f.Name, "kb-") && f.Name > latest {
			latest = f.Name
		}
	}
	m := &Manifest{Date: date, Generated: s.now().UTC().Format(time.RFC3339), Files: files, License: s.lic, Retention: Retention, Latest: latest}
	if _, _, err := s.writeAtomic("croissant.json", func(w io.Writer) error { return writeJSON(w, croissant(m)) }); err != nil {
		return err
	}
	if _, _, err := s.writeAtomic("README.md", func(w io.Writer) error { _, err := io.WriteString(w, readme(m)); return err }); err != nil {
		return err
	}
	m.KID = signerKID()
	if sig, _ := signLine("manifest1", string(compactJSON(m))); sig != "" {
		m.Sig = sig
	}
	if _, _, err := s.writeAtomic("manifest.json", func(w io.Writer) error { return writeJSON(w, m) }); err != nil {
		return err
	}
	if m.Sig == "" { // no signer (tests without sign.Init): never leave stale signatures behind
		for _, n := range []string{"manifest.json.sig", "SHA256SUMS.sig", "SIGNATURES"} {
			os.Remove(filepath.Join(s.dir, n))
		}
	} else if _, _, err := s.writeAtomic("manifest.json.sig", func(w io.Writer) error { _, err := io.WriteString(w, "sig="+m.Sig+"\n"); return err }); err != nil {
		return err
	}
	sums := make([]ManifestFile, 0, len(files)+len(summed))
	sums = append(sums, files...)
	for _, name := range summed {
		mf, err := s.measure(name)
		if err != nil {
			return err
		}
		sums = append(sums, mf)
	}
	sort.Slice(sums, func(i, j int) bool { return sums[i].Name < sums[j].Name })
	var sumsText strings.Builder
	for _, f := range sums {
		sumsText.WriteString(f.SHA256 + "  " + f.Name + "\n")
	}
	if _, _, err := s.writeAtomic("SHA256SUMS", func(w io.Writer) error { _, err := io.WriteString(w, sumsText.String()); return err }); err != nil {
		return err
	}
	if sig, _ := signLine("manifest1", sumsText.String()); sig != "" {
		if _, _, err := s.writeAtomic("SHA256SUMS.sig", func(w io.Writer) error { _, err := io.WriteString(w, "sig="+sig+"\n"); return err }); err != nil {
			return err
		}
		var lines strings.Builder
		for _, f := range sums {
			line := f.Name + " sha256=" + f.SHA256
			if fs, _ := signLine("export1", line); fs != "" {
				lines.WriteString(line + " sig=" + fs + "\n")
			}
		}
		if _, _, err := s.writeAtomic("SIGNATURES", func(w io.Writer) error { _, err := io.WriteString(w, lines.String()); return err }); err != nil {
			return err
		}
	}
	s.man.Store(nil)
	return nil
}

// listShards measures every FileRe match on disk, reusing fresh measurements, the previous
// manifest (same name and size) or the ExtraFileFn hint before recounting rows.
func (s *Service) listShards(ctx context.Context, fresh map[string]ManifestFile) ([]ManifestFile, error) {
	known := map[string]ManifestFile{}
	if prev := s.manifest(); prev != nil {
		for _, f := range prev.Files {
			known[f.Name] = f
		}
	}
	if ExtraFileFn != nil {
		if extra, err := ExtraFileFn(ctx); err == nil {
			for _, f := range extra {
				if FileRe.MatchString(f.Name) {
					known[f.Name] = f
				}
			}
		}
	}
	for n, f := range fresh {
		known[n] = f
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []ManifestFile
	for _, e := range entries {
		name := e.Name()
		if !FileRe.MatchString(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if k, ok := known[name]; ok && k.Size == info.Size() && k.SHA256 != "" {
			out = append(out, k)
			continue
		}
		mf, err := s.measure(name)
		if err != nil {
			return nil, err
		}
		if k, ok := known[name]; ok && k.Size == info.Size() {
			mf.Rows = k.Rows
		} else if rows, err := countRows(filepath.Join(s.dir, name)); err == nil {
			mf.Rows = rows
		}
		out = append(out, mf)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// measure hashes one file in the directory.
func (s *Service) measure(name string) (ManifestFile, error) {
	f, err := os.Open(filepath.Join(s.dir, name))
	if err != nil {
		return ManifestFile{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return ManifestFile{}, err
	}
	return ManifestFile{Name: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// countRows counts the lines of a gzip JSONL shard.
func countRows(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, err
	}
	defer gz.Close()
	var n int64
	buf := make([]byte, 64<<10)
	for {
		k, err := gz.Read(buf)
		for _, b := range buf[:k] {
			if b == '\n' {
				n++
			}
		}
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// manifest returns the manifest on disk (cached by size and mtime), nil when none exists.
func (s *Service) manifest() *Manifest {
	p := filepath.Join(s.dir, "manifest.json")
	st, err := os.Stat(p)
	if err != nil {
		return nil
	}
	if c := s.man.Load(); c != nil && c.size == st.Size() && c.mod.Equal(st.ModTime()) {
		return c.m
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 4<<20 {
		return nil
	}
	var m Manifest
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	s.man.Store(&manCache{m: &m, size: st.Size(), mod: st.ModTime()})
	return &m
}

// compactJSON is the signed encoding: compact, no HTML escaping, no trailing newline.
func compactJSON(v any) []byte {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil
	}
	return []byte(strings.TrimRight(b.String(), "\n"))
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(v)
}

// signLine signs with the server key (17.1); "" before sign is initialised (no .sig files then).
func signLine(typ, line string) (sig string, kid int) {
	defer func() {
		if recover() != nil {
			sig, kid = "", 0
		}
	}()
	return strings.TrimPrefix(sign.Sign(typ, line), "sig="), sign.KID()
}

// signerKID is the current key id, 0 before sign is initialised.
func signerKID() (kid int) {
	defer func() {
		if recover() != nil {
			kid = 0
		}
	}()
	return sign.KID()
}

// --- hooks -------------------------------------------------------------------------------------

// egress enqueues a courier job; a full outbox is logged, never user-visible (20).
func (s *Service) egress(ctx context.Context, kind string, payload any) {
	if err := core.Egress(ctx, s.d.DB, kind, payload); err != nil {
		s.d.Log.Warn("export egress", "kind", kind, "err", err)
	}
}

// recordUsage stores the directory size in the flag export:bytes for the storage governor.
func (s *Service) recordUsage(ctx context.Context) {
	var total int64
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			total += info.Size()
		}
	}
	if err := s.d.SetFlag(ctx, "export:bytes", true, strconv.FormatInt(total, 10)); err != nil {
		s.d.Log.Warn("export usage flag", "err", err)
	}
}

func (s *Service) sitemap(context.Context) ([]core.SitemapURL, error) {
	u := core.SitemapURL{Loc: doc.Base() + "/export/"}
	if st, err := os.Stat(filepath.Join(s.dir, "manifest.json")); err == nil {
		u.LastMod = st.ModTime()
	}
	return []core.SitemapURL{u}, nil
}
