package wasmscan

import (
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// corpus is every synthetic module, a few hostile heads and the fixtures when they are built.
func corpus(t testing.TB) [][]byte {
	t.Helper()
	out := [][]byte{goodModule(), emscriptenModule(), bigMemModule(), noStartModule(), module(),
		module(typeSec(), funcSec(2), memSec(1, 1, true), exportSec(export("_start", 0, 0)), codeSec(2),
			dataSec(passiveData(bytes16(20)), activeData(0, []byte("abcdefghijklmnopqrstuvwxyz")))),
		[]byte("\x00asm\x0d\x00\x01\x00"), []byte("not wasm at all"), []byte("\x00asm\x01\x00\x00\x00\x0a\xff\xff\xff\xff\x0f")}
	paths, _ := filepath.Glob("../../testdata/wasm/out/*.wasm")
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			out = append(out, b)
		}
	}
	return out
}

var sink Info

// invariants is what must hold for any input: bounded output, printable strings, one safe line,
// a well-formed refusal, determinism. Not panicking is checked by getting here at all.
func invariants(t *testing.T, b []byte, info Info, err error) {
	t.Helper()
	if info.Size != len(b) {
		t.Fatalf("size %d for %d bytes", info.Size, len(b))
	}
	if err != nil {
		if s := err.Error(); !strings.HasPrefix(s, "wasm: ") || strings.ContainsAny(s, "\r\n") || len(s) > 300 {
			t.Fatalf("error text %q", s)
		}
		return
	}
	if len(info.Imports) > KeepImports || len(info.Imports) > info.ImportCount || info.ImportCount > len(b)/4 {
		t.Fatalf("imports kept=%d count=%d for %d bytes", len(info.Imports), info.ImportCount, len(b))
	}
	for _, im := range info.Imports {
		if !utf8.ValidString(im.Module) || !utf8.ValidString(im.Name) || im.Kind == "" {
			t.Fatalf("import %+v", im)
		}
	}
	if info.Funcs > len(b) || info.CodeBytes > len(b) || (info.Funcs > MaxFuncs && !info.Truncated) {
		t.Fatalf("funcs=%d code=%d truncated=%v for %d bytes", info.Funcs, info.CodeBytes, info.Truncated, len(b))
	}
	if len(info.Strings) > MaxStrings {
		t.Fatalf("%d strings", len(info.Strings))
	}
	total := 0
	for _, s := range info.Strings {
		total += len(s)
		if len(s) < MinString || strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
			t.Fatalf("string %q", s)
		}
	}
	if total > StringsBudget {
		t.Fatalf("%d string bytes", total)
	}
	l := info.Line()
	if !strings.HasPrefix(l, "wasm size=") || strings.ContainsAny(l, "\r\n\t\x00") || !utf8.ValidString(l) || len(l) > 2048 || info.Line() != l {
		t.Fatalf("line %q", l)
	}
	if cerr := info.Check(32); cerr != nil {
		var e *Error
		if !errors.As(cerr, &e) || e.Status != 400 || (e.Code != "bad" && e.Code != "oom") || strings.ContainsAny(e.Msg, "\r\n") || len(e.Msg) > 400 {
			t.Fatalf("refusal %#v", cerr)
		}
	} else if info.BadImport != "" || !info.HasStart || info.Memory64 || info.MinPages > 32*16 {
		t.Fatalf("Check passed a module it must refuse: %+v", info)
	}
}

// FuzzParse is the testing.F target (go test -fuzz=FuzzParse ./internal/wasmscan); its seeds are
// the corpus. TestParseMutations is the time-boxed driver that runs on every go test.
func FuzzParse(f *testing.F) {
	for _, b := range corpus(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := Parse(b, 0)
		invariants(t, b, info, err)
	})
}

// allocated returns the heap bytes Parse allocates for b. TotalAlloc is cumulative, so garbage
// collection between the two reads does not matter; nothing else runs in between.
func allocated(b []byte) (uint64, Info, error) {
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)
	info, err := Parse(b, 0)
	runtime.ReadMemStats(&m2)
	return m2.TotalAlloc - m1.TotalAlloc, info, err
}

// allocMax is the linear bound that holds for any input: one copy per kept string plus its
// header, at most 64 import headers, the carry buffer of a run spanning segments, the producers
// token. Real modules allocate far less than their size (TestAllocBound checks that too).
func allocMax(b []byte) uint64 { return uint64(4*len(b) + 16<<10) }

func TestAllocBound(t *testing.T) {
	for _, b := range corpus(t) {
		n, info, _ := allocated(b)
		if n > allocMax(b) {
			t.Fatalf("%d-byte input: %d bytes allocated > %d", len(b), n, allocMax(b))
		}
		sink = info
	}
	for name, b := range fixtures(t) {
		n, info, err := allocated(b)
		if err != nil {
			t.Fatal(err)
		}
		if n > uint64(len(b)) {
			t.Fatalf("%s: %d bytes allocated for a %d-byte module", name, n, len(b))
		}
		sink = info
		t.Logf("%s: %d bytes allocated for %d (%.1f%%), %d strings", name, n, len(b), 100*float64(n)/float64(len(b)), len(info.Strings))
	}
}

// TestParseMutations drives Parse over random mutations of the corpus for 10 s (also under
// -short): bit flips, byte swaps, LEB inflation, truncation, insertion and deletion, biased
// toward the head and the tail of big modules where the parsed sections live. Every result must
// honour the invariants and the allocation bound.
func TestParseMutations(t *testing.T) {
	bases := corpus(t)
	rng := rand.New(rand.NewPCG(7, 11))
	deadline := time.Now().Add(10 * time.Second)
	n := 0
	for time.Now().Before(deadline) {
		b := mutate(rng, bases[rng.IntN(len(bases))])
		alloc, info, err := allocated(b)
		if alloc > allocMax(b) {
			t.Fatalf("%d-byte input: %d bytes allocated > %d", len(b), alloc, allocMax(b))
		}
		invariants(t, b, info, err)
		n++
	}
	t.Logf("%d mutations", n)
}

func mutate(rng *rand.Rand, base []byte) []byte {
	b := append(make([]byte, 0, len(base)+16), base...)
	pick := func() int { // the head (headers, imports, memory, exports) and the tail (data, producers)
		switch n := len(b); {
		case n <= 65536 || rng.IntN(5) == 0:
			return rng.IntN(n)
		case rng.IntN(2) == 0:
			return rng.IntN(65536)
		default:
			return n - 1 - rng.IntN(n/5)
		}
	}
	for k := 1 + rng.IntN(4); k > 0 && len(b) > 0; k-- {
		i := pick()
		switch rng.IntN(8) {
		case 0:
			b[i] ^= 1 << rng.IntN(8)
		case 1:
			b[i] = byte(rng.IntN(256))
		case 2:
			b[i] |= 0x80
		case 3:
			b[i] = 0xff
		case 4:
			b = b[:i]
		case 5:
			b = append(b[:i], append([]byte{byte(rng.IntN(256))}, b[i:]...)...)
		case 6:
			j := i + rng.IntN(min(64, len(b)-i)+1)
			b = append(b[:i], b[j:]...)
		case 7:
			j := pick()
			b[i], b[j] = b[j], b[i]
		}
	}
	return b
}
