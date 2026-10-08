package sandbox

// v2 (SPEC-v2 14.4, 27.6): pinned size cap, byte-budget LRU, read-only zip filesystem with a
// read cap, failure diagnostics and the child-process precompile path.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/zipscan"
)

// testZip builds a zip holding etc/passwd (100 bytes), lib/big (1 MiB, stored) and lib/a.txt.
func testZip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, b []byte, method uint16) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: method, Modified: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(b)
	}
	add("etc/passwd", bytes.Repeat([]byte("r"), 100), zip.Deflate)
	add("lib/zeta.txt", []byte("zeta"), zip.Deflate)
	add("lib/a.txt", []byte("alpha"), zip.Deflate)
	big := make([]byte, 1<<20)
	for i := range big {
		big[i] = byte(i)
	}
	add("lib/big", big, zip.Store)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func probe(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name+".wasm"))
	if err != nil {
		t.Skipf("missing test module (run internal/sandbox/testdata/build.sh): %v", err)
	}
	return b
}

func TestFsMountDeterministicAndReadCap(t *testing.T) {
	z := testZip(t)
	fsprobe := probe(t, "fsprobe")
	ctx := context.Background()

	// Listing: sorted names, fake-epoch mtimes, implied directories; the file reads; writes refused.
	a := runner.RunOpts(ctx, fsprobe, []byte("/lib/a.txt"), 10000, 64, Options{FS: z})
	if a.Status != StatusOK {
		t.Fatalf("got %+v stderr=%s", a, a.Stderr)
	}
	out := string(a.Out)
	epoch := fmt.Sprint(zipscan.Epoch.Unix())
	for _, want := range []string{
		"/ etc 0 d " + epoch + "\n/ lib 0 d " + epoch + "\n",
		"/lib a.txt 5 f " + epoch + "\n/lib big 1048576 f " + epoch + "\n/lib zeta.txt 4 f " + epoch + "\n",
		`read /lib/a.txt x1 total=5 head="alpha"`,
		"write error:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "wrote") {
		t.Fatalf("filesystem must be read-only:\n%s", out)
	}
	b := runner.RunOpts(ctx, fsprobe, []byte("/lib/a.txt"), 10000, 64, Options{FS: z})
	if b.Status != StatusOK || !bytes.Equal(a.Out, b.Out) {
		t.Fatalf("not deterministic:\n%s\n---\n%s", a.Out, b.Out)
	}
	// A pre-parsed archive gives the same result; the v1 fs module now reads /etc/passwd.
	arc, err := zipscan.Open(z)
	if err != nil {
		t.Fatal(err)
	}
	c := runner.RunOpts(ctx, fsprobe, []byte("/lib/a.txt"), 10000, 64, Options{Archive: arc})
	if c.Status != StatusOK || !bytes.Equal(a.Out, c.Out) {
		t.Fatalf("archive run differs: %+v", c)
	}
	if res := runner.RunOpts(ctx, mod(t, "fs"), nil, 10000, 64, Options{FS: z}); res.Status != StatusExit || res.Code != 1 ||
		!bytes.Contains(res.Out, []byte("read 100 bytes")) || !bytes.Contains(res.Out, []byte("write error")) {
		t.Fatalf("fs module with a mount: %+v out=%s", res, res.Out)
	}
	// Without a mount nothing is visible (v1 behaviour).
	if res := runner.Run(ctx, mod(t, "fs"), nil, 10000, 64); res.Status != StatusOK || !bytes.Contains(res.Out, []byte("read error")) {
		t.Fatalf("fs module without a mount: %+v out=%s", res, res.Out)
	}
	// Missing path inside the mount: the guest sees ENOENT and exits 2.
	if res := runner.RunOpts(ctx, fsprobe, []byte("/lib/none"), 10000, 64, Options{FS: z}); res.Status != StatusExit || res.Code != 2 {
		t.Fatalf("missing file: %+v", res)
	}
	// Unusable zip -> error before anything runs.
	if res := runner.RunOpts(ctx, fsprobe, nil, 10000, 64, Options{FS: []byte("PK\x03\x04 not really")}); res.Status != StatusError || !strings.HasPrefix(res.Detail, "fs:") {
		t.Fatalf("bad zip: %+v", res)
	}

	// Read cap: 3 MiB of reads under a 2 MiB cap ends the run with error "fs read cap".
	old := fsReadCap
	fsReadCap = 2 << 20
	defer func() { fsReadCap = old }()
	start := time.Now()
	res := runner.RunOpts(ctx, fsprobe, []byte("/lib/big 3"), 10000, 64, Options{FS: z})
	if res.Status != StatusError || !strings.Contains(res.Detail, "fs read cap") || res.Out != nil || time.Since(start) > 5*time.Second {
		t.Fatalf("got %+v after %v", res, time.Since(start))
	}
	// Under the cap the same read loop succeeds.
	if res := runner.RunOpts(ctx, fsprobe, []byte("/lib/big 1"), 10000, 64, Options{FS: z}); res.Status != StatusOK || !bytes.Contains(res.Out, []byte("total=1048576")) {
		t.Fatalf("one read: %+v", res)
	}
}

func TestPinnedModuleSizeCap(t *testing.T) {
	big := make([]byte, MaxWasm+1)
	copy(big, "\x00asm\x01\x00\x00\x00")
	if res := runner.RunOpts(context.Background(), big, nil, 1000, 64, Options{}); res.Status != StatusError || !strings.Contains(res.Detail, "over") {
		t.Fatalf("default cap: %+v", res)
	}
	// A pin raises the cap to its size: the module is no longer refused for its size (it then
	// fails to compile, being zero padding).
	res := runner.RunOpts(context.Background(), big, nil, 1000, 64, Options{MaxWasm: 8 << 20})
	if res.Status != StatusError || strings.Contains(res.Detail, "over") || !strings.HasPrefix(res.Detail, "compile:") {
		t.Fatalf("pinned cap: %+v", res)
	}
	if res := runner.RunOpts(context.Background(), big, nil, 1000, 64, Options{MaxWasm: MaxWasm}); !strings.Contains(res.Detail, "over") {
		t.Fatalf("explicit default cap: %+v", res)
	}
}

// memModule is a minimal valid module (memory min = n pages) whose bytes differ per n.
func memModule(n byte) []byte {
	return []byte{0, 'a', 's', 'm', 1, 0, 0, 0, 5, 3, 1, 0, n}
}

func TestByteBudgetLRU(t *testing.T) {
	// Budget for two 13-byte modules; count limit 8.
	r, err := NewWithBudget("", 8, 2*13)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	ctx := context.Background()
	for _, n := range []byte{1, 2} {
		if res := r.Run(ctx, memModule(n), nil, 1000, 64); res.Status != StatusOK {
			t.Fatalf("mem %d: %+v", n, res)
		}
	}
	if n, b := r.Cached(); n != 2 || b != 26 {
		t.Fatalf("cached %d/%d", n, b)
	}
	r.Run(ctx, memModule(1), nil, 1000, 64) // touch 1: 2 becomes the oldest
	r.Run(ctx, memModule(3), nil, 1000, 64)
	if n, b := r.Cached(); n != 2 || b != 26 {
		t.Fatalf("after eviction cached %d/%d", n, b)
	}
	r.mu.Lock()
	_, has1 := r.index[keyOf(memModule(1), 1024)]
	_, has2 := r.index[keyOf(memModule(2), 1024)]
	_, has3 := r.index[keyOf(memModule(3), 1024)]
	r.mu.Unlock()
	if !has1 || has2 || !has3 {
		t.Fatalf("lru holds 1=%v 2=%v 3=%v", has1, has2, has3)
	}
	// An entry over the whole budget is kept alone (never thrash on a single large module).
	r2, _ := NewWithBudget("", 8, 10)
	defer r2.Close(ctx)
	r2.Run(ctx, memModule(1), nil, 1000, 64)
	r2.Run(ctx, memModule(2), nil, 1000, 64)
	if n, b := r2.Cached(); n != 1 || b != 13 {
		t.Fatalf("over-budget entry: cached %d/%d", n, b)
	}
	// The count limit still applies under a large budget (v1 behaviour).
	r3, _ := NewWithBudget("", 2, DefaultBudget)
	defer r3.Close(ctx)
	for _, n := range []byte{1, 2, 3} {
		r3.Run(ctx, memModule(n), nil, 1000, 64)
	}
	if n, _ := r3.Cached(); n != 2 {
		t.Fatalf("count limit: %d", n)
	}
}

// keyOf mirrors compile()'s LRU key.
func keyOf(wasm []byte, pages uint32) string {
	sum := sha256.Sum256(wasm)
	return hex.EncodeToString(sum[:]) + ":" + fmt.Sprint(pages)
}

func TestDiagFields(t *testing.T) {
	ctx := context.Background()
	// Trap: stack trace captured, error status.
	trap := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0, // type () -> ()
		3, 2, 1, 0, // func 0: type 0
		7, 10, 1, 6, '_', 's', 't', 'a', 'r', 't', 0, 0, // export _start
		10, 5, 1, 3, 0, 0x00, 0x0b, // body: unreachable; end
	}
	res := runner.Run(ctx, trap, nil, 1000, 64)
	if res.Status != StatusError || res.Trace == "" || !strings.Contains(res.Detail, "unreachable") {
		t.Fatalf("trap: %+v", res)
	}
	if res.CompileMs < 0 || len(res.Trace) > MaxTrace {
		t.Fatalf("trap diag: %+v", res)
	}
	// OOM: memory pages reported, stderr tail carries the runtime's message.
	res = run(t, "membomb", "", 10000, 32)
	if res.Status != StatusOOM || res.MemPages == 0 || len(res.Stderr) > MaxStderr {
		t.Fatalf("oom: status=%s mem=%d stderr=%d", res.Status, res.MemPages, len(res.Stderr))
	}
	t.Logf("membomb: mem_pages=%d stderr tail=%q", res.MemPages, trunc(res.Stderr, 80))
	// First compile of a module reports its compile time; a cache hit reports 0.
	fresh := memModule(7)
	if r := runner.Run(ctx, fresh, nil, 1000, 64); r.Status != StatusOK || r.CompileMs < 0 {
		t.Fatalf("fresh: %+v", r)
	}
	if r := runner.Run(ctx, fresh, nil, 1000, 64); r.Status != StatusOK || r.CompileMs > 50 {
		t.Fatalf("cached: %+v", r)
	}
	// Stderr is a tail: a guest writing more than MaxStderr keeps the end.
	var ht headTail
	ht.max = 8
	ht.Write([]byte("0123456789"))
	ht.Write([]byte("abc"))
	if string(ht.tail()) != "56789abc" || !bytes.HasPrefix(ht.all(), []byte("01234567")) {
		t.Fatalf("headTail tail=%q all=%q", ht.tail(), ht.all())
	}
	ht2 := headTail{max: 4}
	ht2.Write([]byte("xx"))
	ht2.Write(bytes.Repeat([]byte("y"), 100))
	if string(ht2.tail()) != "yyyy" || string(ht2.head) != "xxyy" {
		t.Fatalf("headTail big write tail=%q head=%q", ht2.tail(), ht2.head)
	}
}

func trunc(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}

func TestPrecompileFileCache(t *testing.T) {
	dir := t.TempDir()
	wasm := mod(t, "echo")
	ctx := context.Background()
	d, err := Precompile(ctx, dir, wasm)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := filepath.Glob(filepath.Join(dir, "wazero-*", "*"))
	if len(entries) == 0 {
		t.Fatalf("no file cache entries written under %s", dir)
	}
	t.Logf("precompiled echo in %v: %d cache files", d, len(entries))
	if _, err := Precompile(ctx, dir, []byte("not wasm")); err == nil {
		t.Fatal("bad module must fail")
	}
	if _, err := Precompile(ctx, "", wasm); err == nil {
		t.Fatal("cache dir required")
	}
	// A Runner on the same dir loads the machine code: compile is a cache hit and fast.
	r, err := New(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(ctx)
	res := r.Run(ctx, wasm, []byte("hi"), 5000, 64)
	if res.Status != StatusOK || string(res.Out) != "HI" {
		t.Fatalf("run from file cache: %+v", res)
	}
	if res.CompileMs > int(d/time.Millisecond)/2+50 {
		t.Fatalf("compile from file cache took %d ms (fresh compile %v)", res.CompileMs, d)
	}
	t.Logf("file cache load: %d ms", res.CompileMs)
}
