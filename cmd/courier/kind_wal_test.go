package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---- scanner tests ----

// walFakeStore is a combined fake: the S3 bucket (egress, keyed by X-Egress-Host) and the gateway's
// internal /internal/wal/status endpoint (plain internal client).
type walFakeStore struct {
	t        *testing.T
	srv      *httptest.Server
	bucket   string
	s3Host   string
	putFail  bool
	mu       sync.Mutex
	puts     []s3Put
	methods  []string // every non-status S3 method seen
	statuses []walStatus
}

func newWalFakeStore(t *testing.T, bucket, s3host string) *walFakeStore {
	f := &walFakeStore{t: t, bucket: bucket, s3Host: s3host}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *walFakeStore) handle(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/internal/") {
		if r.URL.Path != walStatusPath || r.Method != http.MethodPost {
			w.WriteHeader(404)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var st walStatus
		if err := json.Unmarshal(body, &st); err != nil {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		f.statuses = append(f.statuses, st)
		f.mu.Unlock()
		w.WriteHeader(200)
		io.WriteString(w, `{"ok":true}`)
		return
	}
	if r.Header.Get("X-Egress-Host") != f.s3Host {
		w.WriteHeader(421)
		return
	}
	f.mu.Lock()
	f.methods = append(f.methods, r.Method)
	f.mu.Unlock()
	if r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/"+f.bucket+"/") {
		body, _ := io.ReadAll(r.Body)
		if f.putFail {
			w.WriteHeader(500)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/"+f.bucket+"/")
		f.mu.Lock()
		f.puts = append(f.puts, s3Put{key: key, auth: r.Header.Get("Authorization"), contentSHA: r.Header.Get("x-amz-content-sha256"), body: body})
		f.mu.Unlock()
		w.Header().Set("ETag", `"`+hexOf(body)+`"`)
		w.WriteHeader(200)
		return
	}
	w.WriteHeader(404)
}

func (f *walFakeStore) snapshotPuts() []s3Put {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]s3Put(nil), f.puts...)
}

func (f *walFakeStore) lastStatus() (walStatus, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.statuses) == 0 {
		return walStatus{}, false
	}
	return f.statuses[len(f.statuses)-1], true
}

// resetWal clears the scanner's package-global state so each test starts fresh.
func resetWal() { wal = walState{} }

func walTestEnv(t *testing.T, f *walFakeStore, waldir string) *tenv {
	te := testEnv(t, f.srv)
	te.envs["S3_ENDPOINT"] = f.s3Host
	te.envs["S3_BUCKET"] = f.bucket
	te.envs["S3_REGION"] = "us-east-1"
	te.envs["WAL_DIR"] = waldir
	te.secret(t, "s3_key", "AKIAWALEXAMPLE:secretwalvalue")
	te.secret(t, "wal_pub", walTestRecipientPub)
	return te
}

func writeFile(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWalScannerUploadsAndDeletes(t *testing.T) {
	resetWal()
	waldir := t.TempDir()
	f := newWalFakeStore(t, "walbucket", "s3.example.net")

	segs := map[string]string{
		"000000010000000000000001": "wal-segment-one-contents",
		"000000010000000000000002": "wal-segment-two-contents-xyz",
		"000000010000000000000003": "wal-segment-three-contents-abcdef",
	}
	for name, c := range segs {
		writeFile(t, waldir, name, []byte(c))
	}
	// A basebackup file in the subdirectory must ship under basebackup/<f>.
	bdir := filepath.Join(waldir, walBasebackup)
	if err := os.Mkdir(bdir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, bdir, "base-2026-10-07.tar.gz", []byte("fake-basebackup-tarball-bytes"))
	// Junk the scanner must ignore (wrong name + the archive_status subdir).
	writeFile(t, waldir, "README", []byte("ignore me"))
	os.Mkdir(filepath.Join(waldir, "archive_status"), 0o755)

	te := walTestEnv(t, f, waldir)
	if err := walScan(context.Background(), te.e); err != nil {
		t.Fatalf("walScan: %v", err)
	}

	priv, _ := parseWalPrivateKey(walTestRecipientPriv)
	puts := f.snapshotPuts()
	if len(puts) != 4 {
		t.Fatalf("PUT count = %d, want 4 (3 WAL + 1 basebackup)", len(puts))
	}
	got := map[string]string{}
	for _, p := range puts {
		if !strings.HasPrefix(p.auth, "AWS4-HMAC-SHA256 Credential=AKIAWALEXAMPLE/") {
			t.Fatalf("PUT %s not SigV4-signed: %q", p.key, p.auth)
		}
		if p.contentSHA != hexOf(p.body) {
			t.Fatalf("PUT %s content-sha mismatch", p.key)
		}
		// The body is an ECIES blob bound to the object key; decrypt it.
		plain, err := eciesDecrypt(priv, p.body, []byte(p.key))
		if err != nil {
			t.Fatalf("decrypt %s: %v", p.key, err)
		}
		got[p.key] = string(plain)
	}
	for name, c := range segs {
		if got["wal/"+name] != c {
			t.Fatalf("wal/%s decrypted to %q, want %q", name, got["wal/"+name], c)
		}
	}
	if got["basebackup/base-2026-10-07.tar.gz"] != "fake-basebackup-tarball-bytes" {
		t.Fatalf("basebackup decrypted to %q", got["basebackup/base-2026-10-07.tar.gz"])
	}

	// Every shipped file is gone locally; the ignored junk and subdir remain.
	for name := range segs {
		if _, err := os.Stat(filepath.Join(waldir, name)); !os.IsNotExist(err) {
			t.Fatalf("segment %s not deleted after ship", name)
		}
	}
	if _, err := os.Stat(filepath.Join(bdir, "base-2026-10-07.tar.gz")); !os.IsNotExist(err) {
		t.Fatal("basebackup not deleted after ship")
	}
	if _, err := os.Stat(filepath.Join(waldir, "README")); err != nil {
		t.Fatal("non-WAL file was removed")
	}

	// A status item was posted; with the spool drained it is caught up (age ~0, not frozen).
	st, ok := f.lastStatus()
	if !ok {
		t.Fatal("no status item posted")
	}
	if st.Shipped != 4 || st.Pending != 0 || st.Freeze || st.Watermark != "ok" {
		t.Fatalf("status = %+v", st)
	}
}

func TestWalSpoolWatermarks(t *testing.T) {
	resetWal()
	waldir := t.TempDir()
	f := newWalFakeStore(t, "walbucket", "s3.example.net")
	f.putFail = true // uploads fail, so the spool never drains and we can measure watermarks
	te := walTestEnv(t, f, waldir)
	te.envs["WAL_SPOOL_BYTES"] = "1000"

	// Each WAL segment file is 100 bytes; names are sequential 24-hex.
	add := func(i int) { writeFile(t, waldir, padHex(i), make([]byte, 100)) }

	// 6 files -> 600 bytes = 60% -> warn, first upward crossing notifies, not frozen.
	for i := 1; i <= 6; i++ {
		add(i)
	}
	_ = walScan(context.Background(), te.e)
	st, _ := f.lastStatus()
	if st.Watermark != "warn" || !st.Notify || st.Freeze {
		t.Fatalf("at 60%%: %+v", st)
	}

	// Up to 10 files -> 1000 bytes = 100% -> freeze (>=90%), notifies on warn->freeze.
	for i := 7; i <= 10; i++ {
		add(i)
	}
	_ = walScan(context.Background(), te.e)
	st, _ = f.lastStatus()
	if st.Watermark != "freeze" || !st.Freeze || !st.Notify {
		t.Fatalf("at 100%%: %+v", st)
	}

	// Drop to 7 files -> 700 bytes = 70% (< 80% thaw) -> freeze cleared; still warn, no re-notify.
	for i := 8; i <= 10; i++ {
		os.Remove(filepath.Join(waldir, padHex(i)))
	}
	_ = walScan(context.Background(), te.e)
	st, _ = f.lastStatus()
	if st.Freeze || st.Watermark != "warn" || st.Notify {
		t.Fatalf("after drain to 70%%: %+v", st)
	}

	// Drop to 3 files -> 300 bytes = 30% -> ok.
	for i := 4; i <= 7; i++ {
		os.Remove(filepath.Join(waldir, padHex(i)))
	}
	_ = walScan(context.Background(), te.e)
	st, _ = f.lastStatus()
	if st.Watermark != "ok" || st.Freeze {
		t.Fatalf("at 30%%: %+v", st)
	}
}

// padHex renders i as a 24-hex-character WAL segment file name.
func padHex(i int) string {
	s := hex.EncodeToString([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i)})
	return s // 24 hex chars
}

func TestWalUsesSigV4WriteOnly(t *testing.T) {
	resetWal()
	waldir := t.TempDir()
	f := newWalFakeStore(t, "walbucket", "s3.example.net")
	writeFile(t, waldir, "000000010000000000000001", []byte("segment-bytes"))
	te := walTestEnv(t, f, waldir)

	if err := walScan(context.Background(), te.e); err != nil {
		t.Fatalf("walScan: %v", err)
	}

	f.mu.Lock()
	methods := append([]string(nil), f.methods...)
	f.mu.Unlock()
	if len(methods) != 1 || methods[0] != http.MethodPut {
		t.Fatalf("S3 methods = %v, want exactly one PUT (write-only: no list, no GET, no DELETE)", methods)
	}
	puts := f.snapshotPuts()
	if len(puts) != 1 {
		t.Fatalf("PUT count = %d", len(puts))
	}
	p := puts[0]
	if p.key != "wal/000000010000000000000001" {
		t.Fatalf("PUT key = %q", p.key)
	}
	if !strings.HasPrefix(p.auth, "AWS4-HMAC-SHA256 Credential=AKIAWALEXAMPLE/") || !strings.Contains(p.auth, "SignedHeaders=") || !strings.Contains(p.auth, "Signature=") {
		t.Fatalf("PUT not SigV4-signed: %q", p.auth)
	}
	if !strings.Contains(p.auth, "/s3/aws4_request") {
		t.Fatalf("PUT not scoped to s3 service: %q", p.auth)
	}
	sum := sha256.Sum256(p.body)
	if p.contentSHA != hex.EncodeToString(sum[:]) {
		t.Fatalf("x-amz-content-sha256 %q does not match ciphertext", p.contentSHA)
	}
	// It must not be UNSIGNED-PAYLOAD; the content hash is signed.
	if p.contentSHA == unsignedPayload {
		t.Fatal("payload signed as UNSIGNED-PAYLOAD")
	}
}
