package compute

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/wasmscan"
	"ekaii.fr/commons/internal/zipscan"
)

func (s *svc) blobDir() string          { return filepath.Join(s.d.Cfg.DataDir, "blobs") }
func (s *svc) blobPath(h string) string { return filepath.Join(s.blobDir(), h[:2], h) }

// blobRow is the blobs row as the access, submit and info paths read it.
type blobRow struct {
	hash, owner, kind, pinnedBy string
	size                        int64
	public, private             bool
	usedAt                      *time.Time
	lastRef, created            time.Time
}

func loadBlob(ctx context.Context, q core.Q, hash string) (*blobRow, error) {
	b := &blobRow{hash: hash}
	err := q.QueryRow(ctx, `SELECT size, owner_root, kind, pinned_by, public, private, used_at, last_ref, created FROM blobs WHERE hash = $1`, hash).
		Scan(&b.size, &b.owner, &b.kind, &b.pinnedBy, &b.public, &b.private, &b.usedAt, &b.lastRef, &b.created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return b, err
}

// blobSize reports whether hash is stored (row), returning its size.
func blobSize(ctx context.Context, q core.Q, hash string) (int64, bool, error) {
	var n int64
	err := q.QueryRow(ctx, `SELECT size FROM blobs WHERE hash = $1`, hash).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	return n, err == nil, err
}

// exp is the date a blob leaves the store unless used again (27.6 tenure, v1 TTL).
func (b *blobRow) exp() string {
	switch {
	case b.pinnedBy != "":
		return "never"
	case b.private || (b.kind == "opaque" && b.usedAt == nil):
		return core.Date(b.created.Add(tenureHours * time.Hour))
	}
	return core.Date(b.lastRef.Add(blobTTLDays * 24 * time.Hour))
}

type putOpts struct {
	exempt   bool   // skip the per-root quota (donor outputs under a lease, pinned uploads)
	leaseOut bool   // X-Lease donor output attributed to the submitter: still bound by its 256 MiB cap
	private  bool   // owner-only, 24 h, own lane, no scan
	pinnedBy string // admin|seed: sets blobs.pinned_by
	max      int64  // body cap (0 = maxBlob)
}

// blobKind sniffs the stored kind (27.6): wasm, text (valid UTF-8 <= 1 MiB) or opaque.
func blobKind(b []byte) string {
	switch {
	case wasmscan.IsWasm(b):
		return "wasm"
	case len(b) <= maxText && utf8.Valid(b):
		return "text"
	}
	return "opaque"
}

// putBlob streams r to a temp file while hashing, scans it, then stores it under root's quota.
// Read errors (incl. *http.MaxBytesError) are returned as-is for core.Fail to map.
func (s *svc) putBlob(ctx context.Context, root string, r io.Reader, o putOpts) (*blobRow, []string, error) {
	tmpDir := filepath.Join(s.blobDir(), "tmp")
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		return nil, nil, err
	}
	f, err := os.CreateTemp(tmpDir, "up-*")
	if err != nil {
		return nil, nil, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, nil, err
	}
	if err := f.Close(); err != nil {
		return nil, nil, err
	}
	if max := o.max; max > 0 && n > max {
		return nil, nil, core.ErrSize
	}
	hash := hex.EncodeToString(h.Sum(nil))
	body, err := os.ReadFile(tmp)
	if err != nil {
		return nil, nil, err
	}
	kind := blobKind(body)
	meta := scanMeta(body, kind, o.private)
	row, err := s.store(ctx, root, hash, n, kind, tmp, o, meta)
	if core.IsUniqueViolation(err) { // lost a race with another uploader of the same hash
		row, err = s.store(ctx, root, hash, n, kind, tmp, o, meta)
	}
	if err != nil {
		return nil, nil, err
	}
	var warn []string
	if meta != nil {
		warn = meta.secretKinds
	}
	return row, warn, nil
}

// store records the blob (or counts a re-upload as a touch) and moves tmp into place.
func (s *svc) store(ctx context.Context, root, hash string, size int64, kind, tmp string, o putOpts, meta *blobMeta) (*blobRow, error) {
	dst := s.blobPath(hash)
	placed := false
	place := func() error {
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
		placed = true
		return syncDir(filepath.Dir(dst))
	}
	var row *blobRow
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "blob:"+root); err != nil {
			return err
		}
		if s.d.Frozen("blobs") {
			return core.Frozen("blobs")
		}
		if kind == "opaque" && s.d.Frozen("blobs_opaque") {
			return core.Frozen("blobs_opaque")
		}
		var touches int
		var prevKind string
		var prevRef time.Time
		err := tx.QueryRow(ctx, `SELECT touches, kind, last_ref FROM blobs WHERE hash = $1 FOR UPDATE`, hash).Scan(&touches, &prevKind, &prevRef)
		if err == nil {
			// Known hash: a touch. Opaque blobs may be re-uploaded at most maxTouches per week
			// (tenure, 27.6); the window restarts after a week without a touch.
			if time.Since(prevRef) > 7*24*time.Hour {
				touches = 0
			}
			touches++
			if prevKind == "opaque" && touches > maxTouches && o.pinnedBy == "" {
				return core.E(429, "quota", "blob tenure (re-uploaded over 3 times this week)")
			}
			if _, err := tx.Exec(ctx, `UPDATE blobs SET last_ref = now(), touches = $2 WHERE hash = $1`, hash, touches); err != nil {
				return err
			}
			if err := s.writeMeta(ctx, tx, hash, meta, true); err != nil {
				return err
			}
			if o.pinnedBy != "" {
				if _, err := tx.Exec(ctx, `UPDATE blobs SET pinned_by = $2, used_at = coalesce(used_at, now()) WHERE hash = $1 AND pinned_by = ''`, hash, o.pinnedBy); err != nil {
					return err
				}
			}
			if row, err = loadBlob(ctx, tx, hash); err != nil {
				return err
			}
			if _, serr := os.Stat(dst); serr == nil {
				return nil
			}
			return place() // row known but file missing: restore it
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var total int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(sum(size), 0) FROM blobs`).Scan(&total); err != nil {
			return err
		}
		if total+size > s.maxBytes {
			return core.E(507, "quota", "disk budget reached")
		}
		// Normal uploads and X-Lease donor outputs (leaseOut, attributed to the submitter root) are
		// bound by the submitter's per-root 256 MiB cap, so a leased donor cannot store unbounded blobs
		// past it. Fully-exempt system writes (admin/seed pins, joblog) keep their waiver. For lease
		// outputs only the per-root cap applies; the stricter L0/L1 opaque sub-cap stays waived.
		if !o.exempt || o.leaseOut {
			var used, opaque int64
			if err := tx.QueryRow(ctx, `SELECT coalesce(sum(size), 0), coalesce(sum(size) FILTER (WHERE kind = 'opaque'), 0) FROM blobs WHERE owner_root = $1`, root).Scan(&used, &opaque); err != nil {
				return err
			}
			if used+size > blobQuota {
				return core.E(429, "quota", "blob storage quota reached (256 MiB live per root)")
			}
			if !o.exempt && kind == "opaque" && opaque+size > opaqueQuota && core.Level(ctx, tx, root) < 2 {
				return core.E(429, "quota", "opaque blob quota reached (64 MiB live for L0/L1 roots)")
			}
		}
		var usedAt any
		if o.pinnedBy != "" {
			usedAt = time.Now()
		}
		if _, err := tx.Exec(ctx, `INSERT INTO blobs (hash, size, owner_root, kind, private, pinned_by, used_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			hash, size, root, kind, o.private, o.pinnedBy, usedAt); err != nil {
			return err
		}
		if err := s.writeMeta(ctx, tx, hash, meta, false); err != nil {
			return err
		}
		if row, err = loadBlob(ctx, tx, hash); err != nil {
			return err
		}
		return place()
	})
	if err != nil && placed {
		os.Remove(dst)
	}
	return row, err
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

// --- metadata (14.3, 27.6) ------------------------------------------------------------------

// blobMeta is the scan result stored in blob_meta: a parsed module, a zip directory or the
// tier-1 findings of a text input.
type blobMeta struct {
	kind        string
	size        int64
	info        wasmscan.Info
	parseErr    string
	zip         zipscan.Info
	secretKinds []string
}

// scanMeta inspects an upload: wasm -> wasmscan + tier-1 scan of its data-segment strings; zip
// -> zipscan; text -> tier-1 scan. Private blobs skip the secret scan (27.6). nil = nothing to
// record (clean text, opaque bytes).
func scanMeta(body []byte, kind string, private bool) *blobMeta {
	m := &blobMeta{size: int64(len(body))}
	switch {
	case kind == "wasm":
		m.kind = "wasm"
		info, err := wasmscan.Parse(body, 0)
		m.info = info
		if err != nil {
			m.parseErr = doc.SafeLine(err.Error())
			if len(m.parseErr) > 160 {
				m.parseErr = m.parseErr[:160]
			}
		}
		if !private && len(info.Strings) > 0 {
			m.secretKinds = tier1Kinds(strings.Join(info.Strings, "\n"))
		}
	case zipscan.IsZip(body):
		m.kind = "zip"
		m.zip, _ = zipscan.Parse(body)
	case kind == "text":
		if private {
			return nil
		}
		if m.secretKinds = tier1Kinds(string(body)); len(m.secretKinds) == 0 {
			return nil
		}
		m.kind = "text"
	default:
		return nil
	}
	return m
}

// tier1Kinds lists the distinct tier-1 secret kinds found in text, in rule order.
func tier1Kinds(text string) []string {
	var kinds []string
	seen := map[string]bool{}
	for _, f := range scrub.Scan("data", text) {
		if f.Tier == 1 && !seen[f.Kind] {
			seen[f.Kind] = true
			kinds = append(kinds, f.Kind)
		}
	}
	return kinds
}

// writeMeta upserts the scan facts; counters (runs_ok, compile_timeouts, banned) are kept.
func (s *svc) writeMeta(ctx context.Context, q core.Q, hash string, m *blobMeta, exists bool) error {
	if m == nil {
		return nil
	}
	imports := []byte("[]")
	if len(m.info.Imports) > 0 {
		imports, _ = json.Marshal(m.info.Imports)
	}
	fsUnusable := ""
	if m.kind == "zip" && !m.zip.OK {
		fsUnusable = m.zip.Reason
	}
	_, err := q.Exec(ctx, `INSERT INTO blob_meta (hash, kind, size, imports, import_count, bad_import, has_memory, min_pages, max_pages, has_max, memory64,
			funcs, has_start, producers, truncated, parse_err, entries, unpacked, fs_unusable, secret_kinds)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
		ON CONFLICT (hash) DO UPDATE SET kind = EXCLUDED.kind, size = EXCLUDED.size, imports = EXCLUDED.imports, import_count = EXCLUDED.import_count,
			bad_import = EXCLUDED.bad_import, has_memory = EXCLUDED.has_memory, min_pages = EXCLUDED.min_pages, max_pages = EXCLUDED.max_pages,
			has_max = EXCLUDED.has_max, memory64 = EXCLUDED.memory64, funcs = EXCLUDED.funcs, has_start = EXCLUDED.has_start, producers = EXCLUDED.producers,
			truncated = EXCLUDED.truncated, parse_err = EXCLUDED.parse_err, entries = EXCLUDED.entries, unpacked = EXCLUDED.unpacked,
			fs_unusable = EXCLUDED.fs_unusable, secret_kinds = EXCLUDED.secret_kinds`,
		hash, m.kind, m.size, imports, m.info.ImportCount, m.info.BadImport, m.info.HasMemory, int64(m.info.MinPages), int64(m.info.MaxPages),
		m.info.HasMax, m.info.Memory64, m.info.Funcs, m.info.HasStart, m.info.Producers, m.info.Truncated, m.parseErr,
		m.zip.Entries, int64(min(m.zip.Unpacked, 1<<62)), fsUnusable, strOrEmpty(m.secretKinds))
	return err
}

func strOrEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// metaRow is blob_meta as submit and info read it.
type metaRow struct {
	kind, badImport, producers, parseErr, fsUnusable, banned string
	size, minPages, maxPages, unpacked                       int64
	importCount, funcs, entries, runsOK, compileTimeouts     int
	hasMemory, hasMax, memory64, hasStart, truncated         bool
	imports                                                  []byte
	secretKinds                                              []string
	compileMs, memPages                                      []int32
}

func loadMeta(ctx context.Context, q core.Q, hash string) (*metaRow, error) {
	m := &metaRow{}
	err := q.QueryRow(ctx, `SELECT kind, size, imports, import_count, bad_import, has_memory, min_pages, max_pages, has_max, memory64, funcs, has_start,
			producers, truncated, parse_err, entries, unpacked, fs_unusable, runs_ok, compile_timeouts, banned, secret_kinds, compile_ms, mem_pages
		FROM blob_meta WHERE hash = $1`, hash).
		Scan(&m.kind, &m.size, &m.imports, &m.importCount, &m.badImport, &m.hasMemory, &m.minPages, &m.maxPages, &m.hasMax, &m.memory64, &m.funcs, &m.hasStart,
			&m.producers, &m.truncated, &m.parseErr, &m.entries, &m.unpacked, &m.fsUnusable, &m.runsOK, &m.compileTimeouts, &m.banned, &m.secretKinds, &m.compileMs, &m.memPages)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return m, err
}

// info rebuilds the wasmscan view of a module row (for Check and Line).
func (m *metaRow) info() wasmscan.Info {
	i := wasmscan.Info{Size: int(m.size), ImportCount: m.importCount, BadImport: m.badImport, HasMemory: m.hasMemory,
		MinPages: uint32(min(m.minPages, 1<<32-1)), MaxPages: uint32(min(m.maxPages, 1<<32-1)), HasMax: m.hasMax, Memory64: m.memory64,
		Funcs: m.funcs, HasStart: m.hasStart, Producers: m.producers, Truncated: m.truncated}
	json.Unmarshal(m.imports, &i.Imports)
	return i
}

// ensureMeta returns the metadata of a stored wasm/zip blob, scanning the file once for rows
// that predate 0070. nil when the blob is neither (text without findings, opaque).
func (s *svc) ensureMeta(ctx context.Context, q core.Q, b *blobRow) (*metaRow, error) {
	m, err := loadMeta(ctx, q, b.hash)
	if err != nil || m != nil {
		return m, err
	}
	body, err := os.ReadFile(s.blobPath(b.hash))
	if err != nil {
		return nil, nil
	}
	sm := scanMeta(body, blobKind(body), b.private)
	if sm == nil {
		return nil, nil
	}
	if err := s.writeMeta(ctx, q, b.hash, sm, true); err != nil {
		return nil, err
	}
	return loadMeta(ctx, q, b.hash)
}

// --- access -------------------------------------------------------------------------------------

// leaseSubmitter resolves a live lease held by worker identity wid to the submitter root of its job.
func (s *svc) leaseSubmitter(ctx context.Context, wid, lease string) (string, error) {
	var root string
	err := s.d.DB.QueryRow(ctx, `SELECT j.root FROM replicas r JOIN jobs j ON j.id = r.job
		WHERE r.lease = $1 AND r.worker = $2 AND r.state = 'leased' AND r.deadline > now()`, lease, wid).Scan(&root)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", core.E(404, "notfound", "lease")
	}
	return root, err
}

// canRead applies 27.6: the caller root owns the blob, the blob is public or pinned by the
// operator/seed, the request carries a live X-Lease whose job references it, or (v1 donors) the
// caller root holds a live lease on such a job. Private blobs are owner-only. Anonymous callers
// read public blobs only. Anything else is the same 404 as a missing hash.
func (s *svc) canRead(ctx context.Context, id *core.Ident, b *blobRow, lease string) (bool, error) {
	if b == nil {
		return false, nil
	}
	if id == nil {
		return b.public && !b.private, nil
	}
	if b.owner == id.Root {
		return true, nil
	}
	if b.private {
		return false, nil
	}
	if b.public || b.pinnedBy == "admin" || b.pinnedBy == "seed" {
		return true, nil
	}
	var ok bool
	err := s.d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM replicas r JOIN jobs j ON j.id = r.job
		WHERE r.state = 'leased' AND r.deadline > now() AND (j.wasm = $1 OR j.input = $1 OR j.fs = $1)
		  AND (r.worker_root = $2 OR ($3 <> '' AND r.lease = $3 AND r.worker = $4)))`, b.hash, id.Root, lease, id.ID).Scan(&ok)
	return ok, err
}

// --- handlers -----------------------------------------------------------------------------------

func (s *svc) hPutBlob(w http.ResponseWriter, r *http.Request) {
	id, err := s.authCompute(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if err := needScope(id, "j", "w"); err != nil {
		core.Fail(w, r, err)
		return
	}
	root, o := id.Root, putOpts{private: r.URL.Query().Get("private") == "1"}
	if lease := r.Header.Get("X-Lease"); lease != "" {
		if len(lease) > 64 {
			core.Fail(w, r, core.Bad("bad X-Lease"))
			return
		}
		if root, err = s.leaseSubmitter(r.Context(), id.ID, lease); err != nil {
			core.Fail(w, r, err)
			return
		}
		o.exempt, o.leaseOut, o.private = true, true, false
	}
	core.MaxBytes(w, r, maxBlob)
	b, warn, err := s.putBlob(r.Context(), root, r.Body, o)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	text := fmt.Sprintf("%s exp=%s kind=%s", b.hash, b.exp(), b.kind)
	j := map[string]any{"hash": b.hash, "size": b.size, "exp": b.exp(), "kind": b.kind}
	if len(warn) > 0 {
		text += " scrub=" + strings.Join(warn, ",")
		j["scrub"] = warn
	}
	core.OK(w, r, text, j)
}

func (s *svc) hGetBlob(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthOpt(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if err := needScope(id, "j", "w"); err != nil {
		core.Fail(w, r, err)
		return
	}
	hash := r.PathValue("hash")
	if !hashRe.MatchString(hash) {
		core.Fail(w, r, core.Bad("bad hash"))
		return
	}
	lease := r.Header.Get("X-Lease")
	if len(lease) > 64 {
		lease = ""
	}
	b, err := loadBlob(r.Context(), s.d.DB, hash)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	ok, err := s.canRead(r.Context(), id, b, lease)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if !ok {
		if id == nil {
			core.Fail(w, r, core.ErrAuth)
		} else {
			core.Fail(w, r, core.ErrNotFound)
		}
		return
	}
	f, err := os.Open(s.blobPath(hash))
	if err != nil {
		core.Fail(w, r, core.ErrNotFound)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Length", fmt.Sprint(st.Size()))
	h.Set("ETag", `"`+hash+`"`)
	if b.public {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "private, max-age=31536000, immutable")
	}
	http.ServeContent(w, r, "", time.Time{}, f)
}

// deleteBlob removes an own blob no active job references (14.3); pinned blobs stay.
func (s *svc) deleteBlob(ctx context.Context, id *core.Ident, hash string) error {
	if !hashRe.MatchString(hash) {
		return core.Bad("bad hash")
	}
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		b, err := loadBlob(ctx, tx, hash)
		if err != nil {
			return err
		}
		if b == nil || b.owner != id.Root {
			return core.ErrNotFound
		}
		if b.pinnedBy != "" {
			return core.E(409, "taken", "blob is pinned")
		}
		var active bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM jobs j WHERE j.status IN ('queued','running') AND (j.wasm = $1 OR j.input = $1 OR j.fs = $1))
			OR EXISTS (SELECT 1 FROM replicas r JOIN jobs j ON j.id = r.job WHERE r.out = $1 AND j.status IN ('queued','running'))`, hash).Scan(&active); err != nil {
			return err
		}
		if active {
			return core.E(409, "taken", "blob referenced by an active job")
		}
		if _, err := tx.Exec(ctx, `DELETE FROM blobs WHERE hash = $1`, hash); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM blob_meta WHERE hash = $1 AND banned = ''`, hash); err != nil {
			return err
		}
		return s.removeFile(hash)
	})
}

func (s *svc) hDeleteBlob(w http.ResponseWriter, r *http.Request) {
	id, err := s.authCompute(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	hash := r.PathValue("hash")
	if err := s.deleteBlob(r.Context(), id, hash); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, "ok deleted "+hash, map[string]any{"ok": true, "hash": hash})
}

// infoLines renders GET /v1/b/{hash}/info (14.3, 27.6): the kind line, scrub, probation facts,
// then InfoExtraFn lines.
func (s *svc) infoLines(ctx context.Context, b *blobRow) ([]string, map[string]any, error) {
	m, err := s.ensureMeta(ctx, s.d.DB, b)
	if err != nil {
		return nil, nil, err
	}
	j := map[string]any{"hash": b.hash, "size": b.size, "kind": b.kind, "exp": b.exp()}
	var head string
	scrubKinds := "clean"
	switch {
	case m != nil && m.kind == "wasm" && m.parseErr != "":
		head = fmt.Sprintf("wasm size=%d parse_err=%s", b.size, strings.ReplaceAll(strings.TrimPrefix(m.parseErr, "wasm: "), " ", "_"))
		j["parse_err"] = m.parseErr
	case m != nil && m.kind == "wasm":
		info := m.info()
		head = info.Line()
		j["imports"], j["min_pages"], j["max_pages"], j["funcs"], j["has_start"], j["producers"] = info.Imports, m.minPages, m.maxPages, m.funcs, m.hasStart, m.producers
	case m != nil && m.kind == "zip":
		zi := zipscan.Info{Entries: m.entries, Unpacked: uint64(m.unpacked), OK: m.fsUnusable == "", Reason: m.fsUnusable}
		head = zi.Line()
		j["entries"], j["unpacked"], j["fs_ok"] = m.entries, m.unpacked, m.fsUnusable == ""
	default:
		head = fmt.Sprintf("%s size=%d", b.kind, b.size)
	}
	if m != nil {
		if len(m.secretKinds) > 0 {
			scrubKinds = strings.Join(m.secretKinds, ",")
		}
		j["runs_ok"], j["compile_timeouts"] = m.runsOK, m.compileTimeouts
		if m.banned != "" {
			j["banned"] = m.banned
		}
	}
	line := head + " scrub=" + scrubKinds
	j["scrub"] = scrubKinds
	if b.pinnedBy != "" {
		line += " pinned_by=" + b.pinnedBy
		j["pinned_by"] = b.pinnedBy
	}
	if b.public {
		line += " public=1"
	}
	j["public"] = b.public
	line += " exp=" + b.exp()
	lines := []string{line}
	if m != nil && m.kind == "wasm" {
		l2 := fmt.Sprintf("runs_ok=%d compile_timeouts=%d", m.runsOK, m.compileTimeouts)
		if m.banned != "" {
			l2 += " banned=" + m.banned
		}
		if p50 := p50(m.compileMs); p50 > 0 {
			l2 += fmt.Sprintf(" compile_ms_p50=%d", p50)
			j["compile_ms_p50"] = p50
		}
		if p50 := p50(m.memPages); p50 > 0 {
			l2 += fmt.Sprintf(" mem_p50=%dMiB", (p50*wasmscan.PageSize+(1<<20-1))>>20)
			j["mem_pages_p50"] = p50
		}
		lines = append(lines, l2)
		if hint := compileHint(m.compileMs); hint != "" {
			lines = append(lines, hint)
			j["warn"] = hint
		}
	}
	if InfoExtraFn != nil {
		for _, l := range InfoExtraFn(ctx, s.d.DB, b.hash) {
			lines = append(lines, doc.SafeLine(l))
		}
	}
	return lines, j, nil
}

// compileHint is the 27.6 warning when the module's median compile time eats over 25 % of the
// 10 s donor compile budget.
func compileHint(samples []int32) string {
	p := p50(samples)
	if p <= 2500 {
		return ""
	}
	return fmt.Sprintf("warn compile uses %d %% of a 10 s budget; set ms>=20000", min(p*100/10000, 999))
}

func p50(v []int32) int {
	if len(v) == 0 {
		return 0
	}
	s := append([]int32(nil), v...)
	for i := 1; i < len(s); i++ { // insertion sort: <= 16 samples
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return int(s[(len(s)-1)/2])
}

// blobForInfo loads a blob the caller may inspect (owner, public, pinned, live lease); 404 otherwise.
func (s *svc) blobForInfo(ctx context.Context, id *core.Ident, hash, lease string) (*blobRow, error) {
	if !hashRe.MatchString(hash) {
		return nil, core.Bad("bad hash")
	}
	b, err := loadBlob(ctx, s.d.DB, hash)
	if err != nil {
		return nil, err
	}
	ok, err := s.canRead(ctx, id, b, lease)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, core.ErrNotFound
	}
	return b, nil
}

func (s *svc) hBlobInfo(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	b, err := s.blobForInfo(r.Context(), id, r.PathValue("hash"), r.Header.Get("X-Lease"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	lines, j, err := s.infoLines(r.Context(), b)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, strings.Join(lines, "\n"), j)
}

// magicDeny are the media/archive signatures publish refuses (27.6).
var magicDeny = []struct {
	off int
	sig string
}{{0, "PK\x03\x04"}, {0, "\x1f\x8b"}, {257, "ustar"}, {0, "\x89PNG"}, {0, "\xff\xd8"}, {0, "GIF8"}, {0, "%PDF"}, {0, "\x7fELF"}, {0, "MZ"}, {0, "RIFF"}, {4, "ftyp"}}

func denied(b []byte) bool {
	for _, m := range magicDeny {
		if len(b) >= m.off+len(m.sig) && string(b[m.off:m.off+len(m.sig)]) == m.sig {
			return true
		}
	}
	return false
}

// PublishBlob makes an own blob world-readable (14.2, 27.6): a scanned wasm module, or valid UTF-8
// <= 1 MiB with no tier-1 or tier-2 finding (public text cannot be masked); media and archives
// are refused.
func PublishBlob(ctx context.Context, d *core.Deps, id *core.Ident, hash string) error {
	return svcFor(d).publish(ctx, id, hash)
}

func (s *svc) publish(ctx context.Context, id *core.Ident, hash string) error {
	if !hashRe.MatchString(hash) {
		return core.Bad("bad hash")
	}
	b, err := loadBlob(ctx, s.d.DB, hash)
	if err != nil {
		return err
	}
	if b == nil || b.owner != id.Root {
		return core.ErrNotFound
	}
	if b.private {
		return core.Bad("private blob cannot be published")
	}
	if b.public {
		return nil
	}
	if b.size > maxBlob {
		return core.E(413, "size", "blob over 16 MiB")
	}
	body, err := os.ReadFile(s.blobPath(hash))
	if err != nil {
		return core.ErrNotFound
	}
	switch {
	case denied(body):
		return core.Bad("no media or archive hosting")
	case wasmscan.IsWasm(body):
		m, err := s.ensureMeta(ctx, s.d.DB, b)
		if err != nil {
			return err
		}
		if m == nil || m.parseErr != "" {
			return core.Bad("module does not scan (" + strings.TrimPrefix(func() string {
				if m != nil {
					return m.parseErr
				}
				return "wasm: unreadable"
			}(), "wasm: ") + ")")
		}
		if m.banned != "" {
			return core.Bad("module " + m.banned)
		}
	case len(body) <= maxText && utf8.Valid(body):
		var kinds []string
		seen := map[string]bool{}
		for _, f := range scrub.Scan("blob", string(body)) {
			if !seen[f.Kind] {
				seen[f.Kind] = true
				kinds = append(kinds, f.Kind)
			}
		}
		if len(kinds) > 0 {
			return core.E(400, "scrub", strings.Join(kinds, ","))
		}
	default:
		return core.Bad("no media or archive hosting")
	}
	_, err = s.d.DB.Exec(ctx, `UPDATE blobs SET public = true, last_ref = now(), used_at = coalesce(used_at, now()) WHERE hash = $1`, hash)
	return err
}

func (s *svc) hPublishBlob(w http.ResponseWriter, r *http.Request) {
	id, err := s.authCompute(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	hash := r.PathValue("hash")
	if err := s.publish(r.Context(), id, hash); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, "ok public "+hash+" /v1/b/"+hash, map[string]any{"ok": true, "hash": hash, "url": "/v1/b/" + hash})
}

// PutBlobBytes stores b under owner (catalog seeds, system inputs). pinnedBy (admin|seed) marks
// the blob pinned, lifts the per-root quota and the 16 MiB cap to cfg.AdminBlobMax.
func PutBlobBytes(ctx context.Context, d *core.Deps, owner string, b []byte, pinnedBy string) (string, error) {
	s := svcFor(d)
	o := putOpts{max: maxBlob}
	if pinnedBy != "" {
		if pinnedBy != "admin" && pinnedBy != "seed" {
			return "", core.Bad("pinned_by must be admin or seed")
		}
		o.pinnedBy, o.exempt = pinnedBy, true
		if o.max = d.Cfg.AdminBlobMax; o.max <= 0 {
			o.max = 64 << 20
		}
	}
	if int64(len(b)) > o.max {
		return "", core.ErrSize
	}
	row, _, err := s.putBlob(ctx, owner, bytes.NewReader(b), o)
	if err != nil {
		return "", err
	}
	return row.hash, nil
}

// readOutput loads a done job's output when it is small; tooBig when over 16 KiB or not UTF-8.
func (s *svc) readOutput(hash string) (body []byte, size int64, text bool, err error) {
	st, err := os.Stat(s.blobPath(hash))
	if err != nil {
		return nil, 0, false, core.E(404, "notfound", "output blob gone")
	}
	if st.Size() > 16<<10 {
		return nil, st.Size(), false, nil
	}
	b, err := os.ReadFile(s.blobPath(hash))
	if err != nil {
		return nil, 0, false, err
	}
	return b, st.Size(), utf8.Valid(b), nil
}

func (s *svc) removeFile(hash string) error {
	if err := os.Remove(s.blobPath(hash)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
