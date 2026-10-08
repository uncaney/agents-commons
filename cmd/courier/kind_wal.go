package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// wal_ship (SPEC-v2 27.9, P121): a scanner (no outbox rows) that continuously archives Postgres WAL.
// Postgres is configured with archive_mode=on and archive_command='test ! -f /wal/%f && cp %p /wal/%f'
// onto the shared walspool volume (deploy/wal/). Every tick the scanner lists the spool, seals each
// segment with stdlib ECIES to the operator's X25519 public key (secret wal_pub) and PUTs it to the
// backup bucket under wal/<f> with the P41 SigV4 signer (write-only policy), deleting the local copy
// after a 200; basebackup files are shipped the same way under basebackup/<f>.
//
// Watermarks: the spool is sized WAL_SPOOL_BYTES (2 GiB). At >= 50 % the scanner flags the status item
// for an operator inbox event (wal-spool); at >= 90 % it asks the gateway to raise freeze:write
// ("err frozen wal") until the spool drains below the low-water mark. The age of the newest archive
// (wal_last_archived_age_s) rides the same status item to the ops /metrics gauge. The gateway turns the
// status item into those effects through egress.ResultFn["wal_ship"] (wired by the integration
// package); the scanner itself never touches the database.
const (
	walEvery      = 60 * time.Second
	walDefaultDir = "/wal"
	walDefaultCap = int64(2) << 30 // 2 GiB spool
	walMaxFileCap = int64(1) << 30 // refuse to buffer a single file larger than this (OOM guard)
	walMaxShip    = 256            // segments shipped per tick
	walPutTimeout = 10 * time.Minute
	walWarnPct    = 50.0 // inbox event at/above this fill
	walFreezePct  = 90.0 // raise freeze:write at/above this fill
	walThawPct    = 80.0 // clear freeze once drained below this (hysteresis)
	walStatusPath = "/internal/wal/status"
	walBasebackup = "basebackup"
	walObjectWAL  = "wal"
)

var (
	// Postgres WAL file names: 24-hex segment, optional .partial; 8-hex timeline history; and
	// <24-hex>.<8-hex>.backup label files written by pg_basebackup.
	walSegRe      = regexp.MustCompile(`^[0-9A-Fa-f]{24}(\.partial)?$`)
	walHistoryRe  = regexp.MustCompile(`^[0-9A-Fa-f]{8}\.history$`)
	walBackupRe   = regexp.MustCompile(`^[0-9A-Fa-f]{24}\.[0-9A-Fa-f]{8}\.backup$`)
	walBaseFileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	errNoWalKey   = errors.New("wal_ship: secret wal_pub (X25519 public key) required")
	errNoWalS3    = errors.New("wal_ship: S3_ENDPOINT, S3_BUCKET and secret s3_key required")
)

func init() {
	Register(&Kind{Name: "wal_ship", Every: walEvery, Scan: walScan})
}

// walState carries the small amount of state a stateless scanner cannot recompute: when the archive
// was last caught up (for the age gauge), the current freeze decision (hysteresis) and the last
// watermark reported (so an inbox event fires only on an upward transition).
type walState struct {
	mu           sync.Mutex
	lastArchived time.Time
	frozen       bool
	lastMark     string // "", "warn", "freeze"
	started      bool
}

var wal walState

// walStatus is the status item the scanner POSTs to the gateway each tick; the gateway's
// egress.ResultFn["wal_ship"] reads it to set the gauge, emit the inbox event and toggle freeze:write.
type walStatus struct {
	Used             int64   `json:"used"`
	Cap              int64   `json:"cap"`
	Pct              float64 `json:"pct"`
	Pending          int     `json:"pending"` // WAL/basebackup files still in the spool after this tick
	Shipped          int     `json:"shipped"`
	Failed           int     `json:"failed"`
	LastArchivedAgeS float64 `json:"last_archived_age_s"`
	Watermark        string  `json:"watermark"` // ok | warn | freeze
	Freeze           bool    `json:"freeze"`    // raise/keep freeze:write
	Notify           bool    `json:"notify"`    // emit the wal-spool inbox event this tick
}

func walScan(ctx context.Context, e *Env) error {
	dir := strings.TrimSpace(e.Getenv("WAL_DIR"))
	if dir == "" {
		dir = walDefaultDir
	}
	pub, err := parseWalPublicKey(e.Secret("wal_pub"))
	if err != nil {
		return errNoWalKey
	}
	sh, err := newWalShipper(e, pub)
	if err != nil {
		return err
	}

	wal.mu.Lock()
	if !wal.started {
		wal.lastArchived, wal.started = e.Now(), true
	}
	wal.mu.Unlock()

	// Ship WAL segments first, then basebackup files; draining the spool before we measure it.
	shipped, failed, firstErr := sh.drain(ctx, e, dir)

	used, pending := spoolUsage(dir)
	st := walReport(e, used, pending, shipped, failed)
	if err := postWalStatus(ctx, e, st); err != nil {
		e.Log.Warn("wal_ship status", "err", oneLine(err.Error(), 200))
	}
	e.Log.Info("wal_ship", "shipped", shipped, "failed", failed, "pending", pending,
		"used", used, "pct", fmt.Sprintf("%.1f", st.Pct), "age_s", fmt.Sprintf("%.0f", st.LastArchivedAgeS), "freeze", st.Freeze)
	return firstErr
}

// walReport folds this tick's result into walState and builds the status item.
func walReport(e *Env, used int64, pending, shipped, failed int) walStatus {
	now := e.Now()
	capacity := walSpoolCap(e)
	pct := 0.0
	if capacity > 0 {
		pct = float64(used) / float64(capacity) * 100
	}
	wal.mu.Lock()
	defer wal.mu.Unlock()
	// The archive is "caught up" when nothing remains to ship; advance the age clock then.
	if pending == 0 {
		wal.lastArchived = now
	} else if shipped > 0 {
		wal.lastArchived = now
	}
	age := now.Sub(wal.lastArchived).Seconds()
	if age < 0 {
		age = 0
	}
	switch {
	case pct >= walFreezePct:
		wal.frozen = true
	case pct < walThawPct:
		wal.frozen = false
	}
	mark := "ok"
	if wal.frozen || pct >= walFreezePct {
		mark = "freeze"
	} else if pct >= walWarnPct {
		mark = "warn"
	}
	notify := markRank(mark) > markRank(wal.lastMark)
	wal.lastMark = mark
	return walStatus{Used: used, Cap: capacity, Pct: pct, Pending: pending, Shipped: shipped, Failed: failed,
		LastArchivedAgeS: age, Watermark: mark, Freeze: wal.frozen, Notify: notify}
}

func markRank(m string) int {
	switch m {
	case "warn":
		return 1
	case "freeze":
		return 2
	default:
		return 0
	}
}

func walSpoolCap(e *Env) int64 {
	if v := strings.TrimSpace(e.Getenv("WAL_SPOOL_BYTES")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return walDefaultCap
}

// postWalStatus sends the status item to the gateway's internal listener. The integration package
// registers walStatusPath (egress.RegisterInternal) and dispatches the body to
// egress.ResultFn["wal_ship"]; a non-200 is logged but never fails the scan.
func postWalStatus(ctx context.Context, e *Env, st walStatus) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	code, body, err := e.Internal(ctx, http.MethodPost, walStatusPath, bytes.NewReader(b), 8<<10)
	if err != nil {
		return err
	}
	if code != 200 && code != 204 {
		return statusErr("wal_ship status", code, body)
	}
	return nil
}

// walShipper seals and uploads one file at a time.
type walShipper struct {
	pub    *ecdh.PublicKey
	signer sigV4Signer
	base   string // https://<host>/<bucket>
}

func newWalShipper(e *Env, pub *ecdh.PublicKey) (*walShipper, error) {
	host := s3Host(e.Getenv("S3_ENDPOINT"))
	bucket := strings.Trim(strings.TrimSpace(e.Getenv("S3_BUCKET")), "/")
	key, secret, err := parseS3Key(e.Secret("s3_key"))
	if host == "" || bucket == "" || err != nil {
		return nil, errNoWalS3
	}
	if !validHost(host) {
		return nil, fmt.Errorf("wal_ship: S3_ENDPOINT host %q invalid", host)
	}
	return &walShipper{pub: pub, signer: newS3Signer(key, secret, e.Getenv("S3_REGION")),
		base: "https://" + host + "/" + bucket}, nil
}

// spoolFile is one shippable file: its absolute path and the object key it goes to.
type spoolFile struct {
	path string
	key  string // wal/<f> or basebackup/<f>
}

// drain ships every shippable file in the spool (WAL segments, history/backup labels, then
// basebackup files), returning how many were shipped, how many failed and the first error seen.
func (s *walShipper) drain(ctx context.Context, e *Env, dir string) (shipped, failed int, firstErr error) {
	files := listSpool(dir)
	for _, f := range files {
		if shipped+failed >= walMaxShip {
			break
		}
		if err := s.shipOne(ctx, e, f); err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			e.Log.Warn("wal_ship upload", "key", f.key, "err", oneLine(err.Error(), 200))
			continue
		}
		shipped++
	}
	return shipped, failed, firstErr
}

// shipOne seals one file to the recipient key and PUTs it; the local copy is removed only after a 2xx.
func (s *walShipper) shipOne(ctx context.Context, e *Env, f spoolFile) error {
	fi, err := os.Stat(f.path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return nil
	}
	if fi.Size() > walMaxFileCap {
		return fmt.Errorf("file %s too large to buffer (%d bytes)", f.key, fi.Size())
	}
	plain, err := os.ReadFile(f.path)
	if err != nil {
		return err
	}
	blob, err := eciesEncrypt(s.pub, plain, []byte(f.key))
	if err != nil {
		return err
	}
	if err := s.put(ctx, e, f.key, blob); err != nil {
		return err
	}
	return os.Remove(f.path)
}

// put uploads one sealed blob with SigV4 (content hash over the ciphertext).
func (s *walShipper) put(ctx context.Context, e *Env, key string, blob []byte) error {
	sum := sha256.Sum256(blob)
	req, err := http.NewRequest(http.MethodPut, s.base+"/"+awsURIEncode(key, true), bytes.NewReader(blob))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(blob))
	s.signer.sign(req, hex.EncodeToString(sum[:]), e.Now())
	code, body, _, err := e.Do(ctx, req, readCap, walPutTimeout)
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	if code/100 != 2 {
		return statusErr("put "+key, code, body)
	}
	return nil
}

// listSpool enumerates the files to ship, WAL segments first (oldest name first, which is oldest WAL
// first), then basebackup files. Non-WAL junk and the archive_status subdirectory are ignored.
func listSpool(dir string) []spoolFile {
	var out []spoolFile
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, en := range ents {
		if en.IsDir() || !shippableWAL(en.Name()) {
			continue
		}
		names = append(names, en.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, spoolFile{path: filepath.Join(dir, n), key: walObjectWAL + "/" + n})
	}
	// basebackup/<f>
	bdir := filepath.Join(dir, walBasebackup)
	bents, err := os.ReadDir(bdir)
	if err != nil {
		return out
	}
	var bnames []string
	for _, en := range bents {
		if en.IsDir() || !walBaseFileRe.MatchString(en.Name()) {
			continue
		}
		bnames = append(bnames, en.Name())
	}
	sort.Strings(bnames)
	for _, n := range bnames {
		out = append(out, spoolFile{path: filepath.Join(bdir, n), key: walBasebackup + "/" + n})
	}
	return out
}

func shippableWAL(name string) bool {
	return walSegRe.MatchString(name) || walHistoryRe.MatchString(name) || walBackupRe.MatchString(name)
}

// spoolUsage sums the bytes held in the spool (segments + basebackup) and counts the files that still
// remain to be shipped.
func spoolUsage(dir string) (used int64, pending int) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0
	}
	for _, en := range ents {
		if en.IsDir() {
			continue
		}
		fi, err := en.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		used += fi.Size()
		if shippableWAL(en.Name()) {
			pending++
		}
	}
	bdir := filepath.Join(dir, walBasebackup)
	if bents, err := os.ReadDir(bdir); err == nil {
		for _, en := range bents {
			if en.IsDir() {
				continue
			}
			fi, err := en.Info()
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			used += fi.Size()
			if walBaseFileRe.MatchString(en.Name()) {
				pending++
			}
		}
	}
	return used, pending
}
