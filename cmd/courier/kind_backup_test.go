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
	"sort"
	"strings"
	"sync"
	"testing"
)

type s3Put struct {
	key, auth, contentSHA string
	body                  []byte
}

type fakeS3 struct {
	t      *testing.T
	srv    *httptest.Server
	bucket string
	mu     sync.Mutex
	keys   map[string]bool // objects present in the bucket
	puts   []s3Put
	lists  int
}

func newFakeS3(t *testing.T, bucket string, seed ...string) *fakeS3 {
	f := &fakeS3{t: t, bucket: bucket, keys: map[string]bool{}}
	for _, k := range seed {
		f.keys[k] = true
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeS3) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Egress-Host") != "s3.example.net" {
		w.WriteHeader(421)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/"+f.bucket && r.URL.Query().Get("list-type") == "2":
		f.mu.Lock()
		f.lists++
		keys := make([]string, 0, len(f.keys))
		for k := range f.keys {
			keys = append(keys, k)
		}
		f.mu.Unlock()
		sort.Strings(keys)
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
		b.WriteString(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
		b.WriteString(`<Name>` + f.bucket + `</Name><IsTruncated>false</IsTruncated>`)
		for _, k := range keys {
			b.WriteString("<Contents><Key>" + k + "</Key><Size>10</Size></Contents>")
		}
		b.WriteString(`</ListBucketResult>`)
		w.Header().Set("Content-Type", "application/xml")
		io.WriteString(w, b.String())
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/"+f.bucket+"/"):
		body, _ := io.ReadAll(r.Body)
		key := strings.TrimPrefix(r.URL.Path, "/"+f.bucket+"/")
		f.mu.Lock()
		f.keys[key] = true
		f.puts = append(f.puts, s3Put{key: key, auth: r.Header.Get("Authorization"), contentSHA: r.Header.Get("x-amz-content-sha256"), body: body})
		f.mu.Unlock()
		w.Header().Set("ETag", `"`+hexOf(body)+`"`)
		w.WriteHeader(200)
	default:
		w.WriteHeader(404)
	}
}

func hexOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestBackupShipUploadsOnlyNew(t *testing.T) {
	bucket := "backups"
	// The bucket already holds the 10-06 backup; only the 10-07 one is new.
	f := newFakeS3(t, bucket, "commons-2026-10-06.tar.age")

	dir := t.TempDir()
	contents := map[string]string{
		"commons-2026-10-06.tar.age": "old-backup-bytes",
		"commons-2026-10-07.tar.age": "new-backup-bytes-xyz",
	}
	for name, c := range contents {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Decoys that must be ignored: wrong extension and a subdirectory.
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o600)
	os.Mkdir(filepath.Join(dir, "images"), 0o755)

	te := testEnv(t, f.srv)
	te.envs["S3_ENDPOINT"] = "s3.example.net"
	te.envs["S3_BUCKET"] = bucket
	te.envs["S3_REGION"] = "us-east-1"
	te.envs["BACKUPS_DIR"] = dir
	te.secret(t, "s3_key", "AKIAEXAMPLE:secretkeyvalue")

	raw, err := runBackupShip(context.Background(), te.e, &Job{ID: 1, Kind: "backup_ship", Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("runBackupShip: %v", err)
	}
	var res backupResult
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Uploaded) != 1 || res.Uploaded[0] != "commons-2026-10-07.tar.age" {
		t.Fatalf("uploaded = %v, want only the new file", res.Uploaded)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "commons-2026-10-06.tar.age" {
		t.Fatalf("skipped = %v, want the already-present file", res.Skipped)
	}
	if res.Bytes != int64(len(contents["commons-2026-10-07.tar.age"])) {
		t.Fatalf("bytes = %d", res.Bytes)
	}

	f.mu.Lock()
	puts := append([]s3Put(nil), f.puts...)
	f.mu.Unlock()
	if len(puts) != 1 {
		t.Fatalf("PUT count = %d, want exactly 1", len(puts))
	}
	p := puts[0]
	if p.key != "commons-2026-10-07.tar.age" {
		t.Fatalf("PUT key %q", p.key)
	}
	if !strings.HasPrefix(p.auth, "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/") {
		t.Fatalf("PUT not SigV4-signed: %q", p.auth)
	}
	if p.contentSHA != hexOf([]byte(contents["commons-2026-10-07.tar.age"])) {
		t.Fatalf("x-amz-content-sha256 %q does not match the file", p.contentSHA)
	}
	if string(p.body) != contents["commons-2026-10-07.tar.age"] {
		t.Fatalf("PUT body %q", p.body)
	}

	// A second run now finds both objects present and uploads nothing.
	raw, err = runBackupShip(context.Background(), te.e, &Job{ID: 2, Kind: "backup_ship"})
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	var res2 backupResult
	json.Unmarshal(raw, &res2)
	if len(res2.Uploaded) != 0 || len(res2.Skipped) != 2 {
		t.Fatalf("second run: uploaded=%v skipped=%v", res2.Uploaded, res2.Skipped)
	}
	f.mu.Lock()
	total := len(f.puts)
	f.mu.Unlock()
	if total != 1 {
		t.Fatalf("total PUTs after two runs = %d, want 1", total)
	}

	// Missing configuration fails cleanly.
	te.envs["S3_BUCKET"] = ""
	if _, err := runBackupShip(context.Background(), te.e, &Job{ID: 3, Kind: "backup_ship"}); err == nil {
		t.Fatal("missing bucket accepted")
	}
}

func TestParseS3Key(t *testing.T) {
	cases := []struct {
		in, a, b string
		ok       bool
	}{
		{"AKID:secret", "AKID", "secret", true},
		{"AKID\nsecret\n", "AKID", "secret", true},
		{"  AKID  :  secret  ", "AKID", "secret", true},
		{"", "", "", false},
		{"onlyone", "", "", false},
	}
	for _, c := range cases {
		a, b, err := parseS3Key(c.in)
		if (err == nil) != c.ok {
			t.Fatalf("parseS3Key(%q) err=%v want ok=%v", c.in, err, c.ok)
		}
		if c.ok && (a != c.a || b != c.b) {
			t.Fatalf("parseS3Key(%q) = %q,%q want %q,%q", c.in, a, b, c.a, c.b)
		}
	}
}
