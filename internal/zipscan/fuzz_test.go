package zipscan

import (
	"archive/zip"
	"bytes"
	"errors"
	"io/fs"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// corpus is every fixture small enough to mutate thousands of times, plus hostile heads.
func corpus(t testing.TB) [][]byte {
	t.Helper()
	e := plain("secret", "x")
	e.flags = 1
	return [][]byte{normal(), libZip(t), zip64Arc(), bomb100G(), bomb32(), named("../etc/passwd", "ok"), named("a", "a"),
		named("lib", "lib/x.py"), build(arc{}), many(100), build(arc{ents: []ent{e}}),
		build(arc{ents: []ent{{name: "link", data: []byte("t"), creator: unix, attrs: 0o120777 << 16}}}),
		build(arc{ents: []ent{plain("c", "c")}, comment: "comment", trailing: []byte("junk")}),
		[]byte("PK\x03\x04"), make([]byte, 22), append([]byte("PK\x05\x06"), make([]byte, 18)...), []byte("not a zip at all, just text")}
}

// invariants is what must hold for any input: bounded output, one safe line, a well-formed
// refusal, determinism, and agreement with archive/zip on everything Parse accepts.
func invariants(t *testing.T, b []byte, info Info, err error) {
	t.Helper()
	if info.Size != len(b) {
		t.Fatalf("size %d for %d bytes", info.Size, len(b))
	}
	l := info.Line()
	if !strings.HasPrefix(l, "zip entries=") || strings.ContainsAny(l, "\r\n\t\x00") || !utf8.ValidString(l) || len(l) > 200 || strings.Count(l, " ") != 3 {
		t.Fatalf("line %q", l)
	}
	again, err2 := Parse(b)
	if !reflect.DeepEqual(info, again) || (err == nil) != (err2 == nil) {
		t.Fatalf("not deterministic: %+v %v / %+v %v", info, err, again, err2)
	}
	if err != nil {
		if info.OK || info.Reason == "" || !(errors.Is(err, ErrNotZip) || errors.Is(err, ErrFormat) || strings.Contains(err.Error(), "too large")) {
			t.Fatalf("error %v with info %+v", err, info)
		}
		if s := err.Error(); !strings.HasPrefix(s, "zip: ") || strings.ContainsAny(s, "\r\n") || len(s) > 300 {
			t.Fatalf("error text %q", s)
		}
		return
	}
	if info.Entries > len(b)/headerLen || info.Dirs > info.Entries || len(info.Names) > min(KeepNames, info.Entries) ||
		len(info.Unsafe) > min(KeepUnsafe, info.UnsafeCount) || info.UnsafeCount > info.Entries {
		t.Fatalf("counts %+v for %d bytes", info, len(b))
	}
	if info.OK != (info.Reason == "") {
		t.Fatalf("verdict %+v", info)
	}
	if !info.OK {
		switch info.Reason {
		case ReasonEntries, ReasonUnpacked, ReasonUnsafe, ReasonDuplicate, ReasonEncrypted, ReasonSymlinks, ReasonSpecial:
		default:
			if !strings.HasPrefix(info.Reason, "unsupported-method-") {
				t.Fatalf("reason %q", info.Reason)
			}
		}
		return
	}
	if info.Entries > MaxEntries || info.Unpacked > MaxUnpacked || info.UnsafeCount != 0 {
		t.Fatalf("accepted %+v", info)
	}
	r, zerr := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if zerr != nil || len(r.File) != info.Entries {
		t.Fatalf("archive/zip disagrees: %v, %d files vs %+v", zerr, len(r.File), info)
	}
	for i, f := range r.File {
		if i < len(info.Names) && f.Name != info.Names[i] {
			t.Fatalf("name %d: %q vs %q", i, f.Name, info.Names[i])
		}
		if n := strings.TrimSuffix(f.Name, "/"); n == "" || !fs.ValidPath(n) || n == "." || strings.ContainsAny(n, "\\\x00") {
			t.Fatalf("accepted name %q", f.Name)
		}
	}
	a, oerr := Open(b)
	if oerr != nil {
		t.Fatalf("Open: %v for %+v", oerr, info)
	}
	if es, derr := fs.ReadDir(a.FS(nil), "."); derr != nil || (info.Entries > 0) != (len(es) > 0) {
		t.Fatalf("root listing %v %v for %+v", es, derr, info)
	}
}

// FuzzParse is the testing.F target (go test -fuzz=FuzzParse ./internal/zipscan); its seeds are
// the corpus. TestParseMutations is the time-boxed driver that runs on every go test.
func FuzzParse(f *testing.F) {
	for _, b := range corpus(f) {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := Parse(b)
		invariants(t, b, info, err)
	})
}

// allocMax is the bound that holds for any input: the directory (names are copied from it, the
// dedupe table is smaller than it) plus the Names pre-allocation and, on error paths, fmt's
// sync.Pool refill right after a GC (per-P locals). Clean archives stay under the directory
// size alone (TestAllocBound).
func allocMax(b []byte) uint64 {
	if e, err := findEnd(b); err == nil {
		return e.dirSize + 16<<10
	}
	return 16 << 10
}

// TestParseMutations drives Parse over random mutations of the corpus for 10 s (also under
// -short): bit flips, byte swaps, truncation, insertion, deletion and little-endian field
// edits, biased toward the tail where the directory and end records live. Every result must
// honour the invariants and the allocation bound.
func TestParseMutations(t *testing.T) {
	bases := corpus(t)
	rng := rand.New(rand.NewPCG(7, 11))
	deadline := time.Now().Add(10 * time.Second)
	n, accepted := 0, 0
	for time.Now().Before(deadline) {
		b := mutate(rng, bases[rng.IntN(len(bases))])
		alloc, info, err := allocated(b)
		if alloc > allocMax(b) {
			t.Fatalf("%d-byte input: %d bytes allocated > %d", len(b), alloc, allocMax(b))
		}
		invariants(t, b, info, err)
		if err == nil && info.OK {
			accepted++
		}
		n++
	}
	t.Logf("%d mutations, %d accepted", n, accepted)
}

func mutate(rng *rand.Rand, base []byte) []byte {
	b := append(make([]byte, 0, len(base)+16), base...)
	pick := func() int { // the tail holds the directory and the end records
		switch n := len(b); {
		case n <= 256 || rng.IntN(4) == 0:
			return rng.IntN(n)
		default:
			return n - 1 - rng.IntN(min(n, 400))
		}
	}
	for k := 1 + rng.IntN(3); k > 0 && len(b) > 0; k-- {
		i := pick()
		switch rng.IntN(9) {
		case 0:
			b[i] ^= 1 << rng.IntN(8)
		case 1:
			b[i] = byte(rng.IntN(256))
		case 2:
			b[i] = 0xff
		case 3:
			b[i] = 0
		case 4:
			b = b[:i]
		case 5:
			b = append(b[:i], append([]byte{byte(rng.IntN(256))}, b[i:]...)...)
		case 6:
			j := i + rng.IntN(min(32, len(b)-i)+1)
			b = append(b[:i], b[j:]...)
		case 7:
			j := pick()
			b[i], b[j] = b[j], b[i]
		case 8: // a little-endian field: small value, maxed, or off by one
			if i+4 <= len(b) {
				switch v := b[i : i+4]; rng.IntN(3) {
				case 0:
					v[0], v[1], v[2], v[3] = byte(rng.IntN(64)), 0, 0, 0
				case 1:
					v[0], v[1], v[2], v[3] = 0xff, 0xff, 0xff, 0xff
				default:
					v[0]++
				}
			}
		}
	}
	return b
}
