package zipscan

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// --- a zip builder that writes whatever it is told ------------------------------------------

type ent struct {
	name    string
	data    []byte
	method  uint16 // 0 store, 8 deflate
	raw     bool   // data is already the payload: never compressed here, never inflated by Parse
	flags   uint16
	decl    uint64 // declared uncompressed size, 0 = len(data)
	zip64   bool   // sizes and offset through the zip64 extra
	creator uint16 // high byte of "version made by": 3 = Unix
	attrs   uint32 // external attributes
	comment string
}

type arc struct {
	ents       []ent
	zip64End   bool
	comment    string
	trailing   []byte
	badRecords int // added to the end record's count
}

func build(a arc) []byte {
	var out []byte
	p16 := func(v uint16) { out = binary.LittleEndian.AppendUint16(out, v) }
	p32 := func(v uint32) { out = binary.LittleEndian.AppendUint32(out, v) }
	p64 := func(v uint64) { out = binary.LittleEndian.AppendUint64(out, v) }
	type rec struct {
		e                 ent
		crc               uint32
		csize, usize, off uint64
	}
	var recs []rec
	for _, e := range a.ents {
		payload := e.data
		if e.method == 8 && !e.raw {
			var cb bytes.Buffer
			w, _ := flate.NewWriter(&cb, flate.BestSpeed)
			w.Write(e.data)
			w.Close()
			payload = cb.Bytes()
		}
		r := rec{e: e, crc: crc32.ChecksumIEEE(e.data), csize: uint64(len(payload)), usize: uint64(len(e.data)), off: uint64(len(out))}
		if e.decl != 0 {
			r.usize = e.decl
		}
		ver := uint16(20)
		if e.zip64 {
			ver = 45
		}
		p32(0x04034b50)
		p16(ver)
		p16(e.flags)
		p16(e.method)
		p16(0x4a2c) // a real-looking DOS time and date, to prove ModTime normalisation
		p16(0x5b47)
		p32(r.crc)
		if e.zip64 {
			p32(max32)
			p32(max32)
		} else {
			p32(uint32(r.csize))
			p32(uint32(r.usize))
		}
		p16(uint16(len(e.name)))
		if e.zip64 {
			p16(20)
		} else {
			p16(0)
		}
		out = append(out, e.name...)
		if e.zip64 {
			p16(1)
			p16(16)
			p64(r.usize)
			p64(r.csize)
		}
		out = append(out, payload...)
		recs = append(recs, r)
	}
	dirStart := len(out)
	for _, r := range recs {
		ver := uint16(20)
		if r.e.zip64 {
			ver = 45
		}
		p32(sigHeader)
		p16(r.e.creator<<8 | ver)
		p16(ver)
		p16(r.e.flags)
		p16(r.e.method)
		p16(0x4a2c)
		p16(0x5b47)
		p32(r.crc)
		if r.e.zip64 {
			p32(max32)
			p32(max32)
		} else {
			p32(uint32(r.csize))
			p32(uint32(r.usize))
		}
		p16(uint16(len(r.e.name)))
		if r.e.zip64 {
			p16(28)
		} else {
			p16(0)
		}
		p16(uint16(len(r.e.comment)))
		p16(0)
		p16(0)
		p32(r.e.attrs)
		if r.e.zip64 {
			p32(max32)
		} else {
			p32(uint32(r.off))
		}
		out = append(out, r.e.name...)
		if r.e.zip64 {
			p16(1)
			p16(24)
			p64(r.usize)
			p64(r.csize)
			p64(r.off)
		}
		out = append(out, r.e.comment...)
	}
	dirSize := len(out) - dirStart
	n := len(recs) + a.badRecords
	if a.zip64End {
		z := len(out)
		p32(sigEnd64)
		p64(44)
		p16(45)
		p16(45)
		p32(0)
		p32(0)
		p64(uint64(n))
		p64(uint64(n))
		p64(uint64(dirSize))
		p64(uint64(dirStart))
		p32(sigLoc64)
		p32(0)
		p64(uint64(z))
		p32(1)
		p32(sigEnd)
		p16(0)
		p16(0)
		p16(max16)
		p16(max16)
		p32(max32)
		p32(max32)
	} else {
		p32(sigEnd)
		p16(0)
		p16(0)
		p16(uint16(n))
		p16(uint16(n))
		p32(uint32(dirSize))
		p32(uint32(dirStart))
	}
	p16(uint16(len(a.comment)))
	out = append(out, a.comment...)
	return append(out, a.trailing...)
}

const unix = 3

func file(name, data string) ent {
	return ent{name: name, data: []byte(data), method: 8, creator: unix, attrs: 0o100644 << 16}
}

func plain(name, data string) ent {
	return ent{name: name, data: []byte(data), creator: unix, attrs: 0o100644 << 16}
}

func dirEnt(name string) ent { return ent{name: name, creator: unix, attrs: 0o040755<<16 | 0x10} }

// normal is a small python package with a scrambled entry order, one explicit directory and
// one implied directory (lib/data).
func normal() []byte {
	return build(arc{ents: []ent{
		plain("README.md", "# lib\n"),
		file("lib/util.py", "def add(a, b):\n    return a + b\n"),
		dirEnt("lib/"),
		plain("lib/data/table.json", "{\"table\": [1, 2, 3]}\n"),
		file("lib/__init__.py", "__all__ = [\"util\"]\n"),
	}})
}

func libZip(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "lib.zip"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func zip64Arc() []byte {
	e := plain("big.txt", "hello zip64\n")
	e.zip64 = true
	return build(arc{ents: []ent{e, plain("small.txt", "small\n")}, zip64End: true})
}

func bomb100G() []byte {
	e := plain("bomb.bin", "x")
	e.zip64, e.decl = true, 100<<30
	return build(arc{ents: []ent{e}})
}

func bomb32() []byte {
	var es []ent
	for i := 0; i < 25; i++ {
		e := plain(fmt.Sprintf("part%02d.bin", i), "x")
		e.decl = 0xfffffffe
		es = append(es, e)
	}
	return build(arc{ents: es})
}

// declared60M is a 1 MiB archive whose single deflate entry claims 60 MiB: the payload is
// random, so any attempt to inflate it would fail.
func declared60M() []byte {
	rng := rand.New(rand.NewPCG(1, 2))
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(rng.Uint32())
	}
	return build(arc{ents: []ent{{name: "blob.bin", data: data, method: 8, raw: true, decl: 60 << 20}}})
}

func named(names ...string) []byte {
	var es []ent
	for _, n := range names {
		if strings.HasSuffix(n, "/") {
			es = append(es, dirEnt(n))
		} else {
			es = append(es, plain(n, "x"))
		}
	}
	return build(arc{ents: es})
}

func many(n int) []byte {
	es := make([]ent, n)
	for i := range es {
		es[i] = ent{name: fmt.Sprintf("f%05d", i), data: []byte{'x'}}
	}
	return build(arc{ents: es})
}

func dirSizeOf(t testing.TB, b []byte) int {
	t.Helper()
	e, err := findEnd(b)
	if err != nil {
		t.Fatal(err)
	}
	return int(e.dirSize)
}

func parseOK(t *testing.T, b []byte) Info {
	t.Helper()
	info, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !info.OK || info.Reason != "" {
		t.Fatalf("not usable: %+v", info)
	}
	return info
}

func refused(t *testing.T, b []byte, reason string) Info {
	t.Helper()
	info, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if info.OK || info.Reason != reason {
		t.Fatalf("want fs_unusable=%s, got ok=%v reason=%q", reason, info.OK, info.Reason)
	}
	if l := info.Line(); !strings.HasSuffix(l, " fs_unusable="+reason) {
		t.Fatalf("line %q", l)
	}
	return info
}

// --- Parse -----------------------------------------------------------------------------------

func TestParseNormal(t *testing.T) {
	info := parseOK(t, normal())
	want := []string{"README.md", "lib/util.py", "lib/", "lib/data/table.json", "lib/__init__.py"}
	if info.Entries != 5 || info.Dirs != 1 || !reflect.DeepEqual(info.Names, want) || info.Zip64 || info.UnsafeCount != 0 {
		t.Fatalf("%+v", info)
	}
	if info.Unpacked != 6+32+0+21+19 {
		t.Fatalf("unpacked %d", info.Unpacked)
	}
	if l := info.Line(); l != "zip entries=5 unpacked=78B fs_ok=1" {
		t.Fatalf("line %q", l)
	}

	// The Info-ZIP fixture: zip -X -D lib.zip -r lib/ (no directory entries, no extras).
	info = parseOK(t, libZip(t))
	want = []string{"lib/util.py", "lib/__init__.py", "lib/sub/big.txt", "lib/sub/empty.py", "lib/data/table.json", "lib/data/words.txt"}
	if info.Entries != 6 || info.Dirs != 0 || info.Unpacked != 49444 || !reflect.DeepEqual(info.Names, want) {
		t.Fatalf("%+v", info)
	}
	if l := info.Line(); l != "zip entries=6 unpacked=48.3KiB fs_ok=1" {
		t.Fatalf("line %q", l)
	}
	if !IsZip(normal()) || !IsZip(build(arc{})) || IsZip([]byte("PK\x01\x02")) || IsZip(nil) {
		t.Fatal("IsZip")
	}
}

func TestParseEmptyAndComments(t *testing.T) {
	info := parseOK(t, build(arc{}))
	if info.Entries != 0 || info.Unpacked != 0 || info.Names != nil || info.Line() != "zip entries=0 unpacked=0B fs_ok=1" {
		t.Fatalf("%+v", info)
	}
	e := plain("a.txt", "aaa")
	e.comment = "entry comment, ignored"
	b := build(arc{ents: []ent{e}, comment: "archive comment, ignored", trailing: []byte("trailing bytes archive/zip tolerates")})
	if info := parseOK(t, b); info.Entries != 1 || info.Unpacked != 3 {
		t.Fatalf("%+v", info)
	}
	if _, err := zip.NewReader(bytes.NewReader(b), int64(len(b))); err != nil {
		t.Fatal(err)
	}
}

func TestZip64(t *testing.T) {
	b := zip64Arc()
	info := parseOK(t, b)
	if !info.Zip64 || info.Entries != 2 || info.Unpacked != 12+6 || info.Names[0] != "big.txt" {
		t.Fatalf("%+v", info)
	}
	fsys, err := FS(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile(fsys, "big.txt")
	if err != nil || string(got) != "hello zip64\n" {
		t.Fatalf("%q %v", got, err)
	}
	// zip64 end record alone, and zip64 extras alone, both count as zip64.
	if info := parseOK(t, build(arc{ents: []ent{plain("a", "a")}, zip64End: true})); !info.Zip64 || info.Entries != 1 {
		t.Fatalf("%+v", info)
	}
	e := plain("a", "a")
	e.zip64 = true
	if info := parseOK(t, build(arc{ents: []ent{e}})); !info.Zip64 || info.Unpacked != 1 {
		t.Fatalf("%+v", info)
	}
	// Maxed end-record fields without a locator are not a zip64 archive we accept.
	bad := build(arc{ents: []ent{plain("a", "a")}})
	binary.LittleEndian.PutUint32(bad[len(bad)-10:], max32) // directory size
	if _, err := Parse(bad); !errors.Is(err, ErrFormat) {
		t.Fatalf("err %v", err)
	}
}

func TestBombRefusedByDeclaredSize(t *testing.T) {
	info := refused(t, bomb100G(), ReasonUnpacked)
	if info.Unpacked != 100<<30 || info.Entries != 1 || !info.Zip64 {
		t.Fatalf("%+v", info)
	}
	if l := info.Line(); l != "zip entries=1 unpacked=100.0GiB fs_unusable=unpacked>64MiB" {
		t.Fatalf("line %q", l)
	}
	if info := refused(t, bomb32(), ReasonUnpacked); info.Unpacked != 25*0xfffffffe {
		t.Fatalf("%+v", info)
	}
	if _, err := FS(bomb100G(), nil); err == nil || !strings.Contains(err.Error(), "fs_unusable=unpacked>64MiB") {
		t.Fatalf("FS err %v", err)
	}
	// The cap is inclusive: 64 MiB declared is fine, one byte more is not.
	at := plain("a", "x")
	at.decl = MaxUnpacked - 1
	parseOK(t, build(arc{ents: []ent{at, plain("b", "x")}}))
	refused(t, build(arc{ents: []ent{at, plain("b", "xy")}}), ReasonUnpacked)
	// Many entries overflowing uint64 saturate instead of wrapping.
	var es []ent
	for i := 0; i < 3; i++ {
		e := plain(fmt.Sprintf("w%d", i), "x")
		e.zip64, e.decl = true, 1<<63
		es = append(es, e)
	}
	if info := refused(t, build(arc{ents: es}), ReasonUnpacked); info.Unpacked != ^uint64(0) || info.Line() != "zip entries=3 unpacked=16.0EiB fs_unusable=unpacked>64MiB" {
		t.Fatalf("%+v %s", info, info.Line())
	}
}

// TestParseNeverInflates: a 1 MiB archive declaring 60 MiB of random "deflate" data parses in
// well under 5 ms, which only holds if the payload is never touched.
func TestParseNeverInflates(t *testing.T) {
	b := declared60M()
	if len(b) < 1<<20 {
		t.Fatalf("%d bytes", len(b))
	}
	best := time.Hour
	for i := 0; i < 5; i++ {
		start := time.Now()
		info, err := Parse(b)
		if d := time.Since(start); d < best {
			best = d
		}
		if err != nil || !info.OK || info.Unpacked != 60<<20 {
			t.Fatalf("%+v %v", info, err)
		}
	}
	t.Logf("best of 5: %v", best)
	if best > 5*time.Millisecond {
		t.Fatalf("Parse took %v", best)
	}
}

func TestTraversalNamesUnsafe(t *testing.T) {
	bad := []string{"../etc/passwd", "/etc/passwd", "a/../b", "a/./b", "./a", "a//b", "nul\x00.txt",
		"win\\path.txt", "", "/", "..", ".", "x/..", "a/\\b", "../", "//", "a/..\\b", "bad\xf6utf8.txt", "\xff"}
	for _, n := range bad {
		info := refused(t, named(n), ReasonUnsafe)
		if info.UnsafeCount != 1 || len(info.Unsafe) != 1 || info.Unsafe[0] != n || info.Entries != 1 {
			t.Fatalf("%q: %+v", n, info)
		}
		if _, err := FS(named(n), nil); err == nil {
			t.Fatalf("%q mounted", n)
		}
	}
	good := []string{"a", "a/", "a/b", "a/b/", "lib/__init__.py", ".hidden", "..hidden", "a..b/c.", "sp ace/é.txt", "a.b/c-d_e~f"}
	for _, n := range good {
		if info := parseOK(t, named(n)); info.UnsafeCount != 0 {
			t.Fatalf("%q: %+v", n, info)
		}
	}
	// Mixed archives keep the first KeepUnsafe offenders and count them all.
	var names []string
	for i := 0; i < 20; i++ {
		names = append(names, fmt.Sprintf("../up%d", i))
	}
	names = append(names, "ok.txt")
	info := refused(t, named(names...), ReasonUnsafe)
	if info.UnsafeCount != 20 || len(info.Unsafe) != KeepUnsafe || info.Unsafe[15] != "../up15" || info.Entries != 21 {
		t.Fatalf("%+v", info)
	}
	for _, n := range bad {
		if safeName([]byte(n)) {
			t.Fatalf("safeName(%q)", n)
		}
	}
}

func TestEntryCap(t *testing.T) {
	info := refused(t, many(MaxEntries+1), ReasonEntries)
	if info.Entries != MaxEntries+1 || len(info.Names) != KeepNames || info.Names[63] != "f00063" || info.Unpacked != MaxEntries+1 {
		t.Fatalf("%+v", info)
	}
	if l := info.Line(); l != "zip entries=20001 unpacked=19.5KiB fs_unusable=entries>20000" {
		t.Fatalf("line %q", l)
	}
	if info := parseOK(t, many(MaxEntries)); info.Entries != MaxEntries {
		t.Fatalf("%+v", info)
	}
	// The end record's count must match (modulo 65536 without zip64, exactly with it).
	if _, err := Parse(build(arc{ents: []ent{plain("a", "a")}, badRecords: 1})); !errors.Is(err, ErrFormat) {
		t.Fatalf("err %v", err)
	}
	if _, err := Parse(build(arc{ents: []ent{plain("a", "a")}, badRecords: 1, zip64End: true})); !errors.Is(err, ErrFormat) {
		t.Fatalf("err %v", err)
	}
	parseOK(t, build(arc{ents: []ent{plain("a", "a")}, badRecords: 65536}))
}

func TestDuplicateNames(t *testing.T) {
	for _, names := range [][]string{
		{"a.txt", "a.txt"},
		{"lib", "lib/x.py"},
		{"lib/x.py", "lib"},
		{"a/", "a"},
		{"a", "a/"},
		{"a/b/", "a"},
		{"a", "a/b/c/d"},
		{"x", "y", "z", "a/b", "a/b/c"},
	} {
		if info := refused(t, named(names...), ReasonDuplicate); info.Entries != len(names) {
			t.Fatalf("%v: %+v", names, info)
		}
	}
	for _, names := range [][]string{
		{"lib/", "lib/x.py"},
		{"a", "ab", "a.txt", "a-b/c"},
		{"a/b", "a/c", "a/"},
		{"a/", "ab"},
		{"d/e/f", "d/e/", "d/"},
	} {
		parseOK(t, named(names...))
	}
	var names []string
	for i := 0; i < 300; i++ {
		names = append(names, fmt.Sprintf("dir%d/file%d.txt", i%7, i))
	}
	parseOK(t, named(names...))
	refused(t, named(append(names, "dir3/file10.txt")...), ReasonDuplicate)
}

func TestRefusedKinds(t *testing.T) {
	e := plain("secret.txt", "x")
	e.flags = 1
	refused(t, build(arc{ents: []ent{e}}), ReasonEncrypted)
	e = ent{name: "a.bz2", data: []byte("x"), method: 12, raw: true}
	refused(t, build(arc{ents: []ent{e}}), "unsupported-method-12")
	e = ent{name: "link", data: []byte("target"), creator: unix, attrs: 0o120777 << 16}
	refused(t, build(arc{ents: []ent{e}}), ReasonSymlinks)
	e = ent{name: "fifo", creator: unix, attrs: 0o010644 << 16}
	refused(t, build(arc{ents: []ent{e}}), ReasonSpecial)
	e = ent{name: "notadir", creator: unix, attrs: 0o040755 << 16} // S_IFDIR on a file entry
	refused(t, build(arc{ents: []ent{e}}), ReasonSpecial)
	// Non-Unix creators carry no mode: attributes are not interpreted.
	e = ent{name: "dos.txt", data: []byte("x"), attrs: 0o120777 << 16}
	parseOK(t, build(arc{ents: []ent{e}}))
	// Precedence: caps first, then names, then kinds.
	e = plain("../x", "x")
	e.flags = 1
	refused(t, build(arc{ents: []ent{e}}), ReasonUnsafe)
}

func TestParseErrors(t *testing.T) {
	check := func(b []byte, target error, reason string) {
		t.Helper()
		info, err := Parse(b)
		if !errors.Is(err, target) || info.OK || info.Reason != reason {
			t.Fatalf("err=%v info=%+v", err, info)
		}
		if s := err.Error(); !strings.HasPrefix(s, "zip: ") || strings.ContainsAny(s, "\r\n") {
			t.Fatalf("error text %q", s)
		}
		if l := info.Line(); !strings.HasSuffix(l, " fs_unusable="+reason) {
			t.Fatalf("line %q", l)
		}
	}
	n := normal()
	check(nil, ErrNotZip, reasonNotZip)
	check([]byte("PK\x03\x04 not really"), ErrNotZip, reasonNotZip)
	check(n[:len(n)-5], ErrNotZip, reasonNotZip)
	check(append([]byte("stub"), n...), ErrFormat, reasonMalformed) // prefix: directory does not end at the end record
	bad := normal()
	binary.LittleEndian.PutUint32(bad[len(bad)-6:], 7) // directory offset
	check(bad, ErrFormat, reasonMalformed)
	bad = normal()
	bad[dirStartOf(t, bad)] = 'Q' // first header signature
	check(bad, ErrFormat, reasonMalformed)
	bad = normal()
	binary.LittleEndian.PutUint16(bad[dirStartOf(t, bad)+28:], 60000) // name length past the directory
	check(bad, ErrFormat, reasonMalformed)
	bad = build(arc{ents: []ent{plain("a", "abc")}})
	binary.LittleEndian.PutUint32(bad[dirStartOf(t, bad)+42:], 0xfffffff0) // local header offset
	check(bad, ErrFormat, reasonMalformed)
	bad = build(arc{ents: []ent{plain("a", "abc")}})
	binary.LittleEndian.PutUint32(bad[dirStartOf(t, bad)+20:], 1000) // compressed size past the directory
	check(bad, ErrFormat, reasonMalformed)
	bad = normal()
	binary.LittleEndian.PutUint16(bad[len(bad)-2:], 9) // comment length past the end
	check(bad, ErrNotZip, reasonNotZip)
	bad = normal()
	bad[len(bad)-18] = 1 // disk number
	check(bad, ErrFormat, reasonMalformed)
	e := plain("a", "a")
	e.zip64 = true
	bad = build(arc{ents: []ent{e}})
	binary.LittleEndian.PutUint16(bad[dirStartOf(t, bad)+46+1+2:], 8) // zip64 extra too short for three fields
	check(bad, ErrFormat, reasonMalformed)
}

func dirStartOf(t testing.TB, b []byte) int {
	t.Helper()
	e, err := findEnd(b)
	if err != nil {
		t.Fatal(err)
	}
	return int(e.dirOffset)
}

func TestHuman(t *testing.T) {
	for n, want := range map[uint64]string{0: "0B", 812: "812B", 1023: "1023B", 1024: "1.0KiB", 1536: "1.5KiB", 5347737: "5.1MiB",
		64 << 20: "64.0MiB", 100 << 30: "100.0GiB", 1 << 40: "1.0TiB", 1 << 50: "1.0PiB", 1 << 60: "1.0EiB", ^uint64(0): "16.0EiB"} {
		if got := human(n); got != want {
			t.Fatalf("human(%d) = %q, want %q", n, got, want)
		}
	}
	if (Info{}).Line() != "zip entries=0 unpacked=0B fs_unusable=unknown" {
		t.Fatal((Info{}).Line())
	}
}

// allocated returns the heap bytes one Parse of b allocates (TotalAlloc is cumulative).
func allocated(b []byte) (uint64, Info, error) {
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)
	info, err := Parse(b)
	runtime.ReadMemStats(&m2)
	return m2.TotalAlloc - m1.TotalAlloc, info, err
}

var sink Info

// TestAllocBound: Parse never allocates more than the central directory it reads (the kept
// names, their slice and the dedupe table), whatever the archive.
func TestAllocBound(t *testing.T) {
	for name, b := range map[string][]byte{"normal": normal(), "lib.zip": libZip(t), "zip64": zip64Arc(), "many20000": many(MaxEntries),
		"many20001": many(MaxEntries + 1), "bomb": bomb100G(), "bomb32": bomb32(), "60M": declared60M(), "dups": named("a", "a"), "deep": named("a/b/c/d/e/f/g", "a/b/c/x")} {
		dir := dirSizeOf(t, b)
		n, info, err := allocated(b)
		if err != nil {
			t.Fatal(err)
		}
		sink = info
		t.Logf("%s: %d bytes allocated for a %d-byte directory (%d-byte archive)", name, n, dir, len(b))
		if n > uint64(dir) {
			t.Fatalf("%s: %d bytes allocated > %d-byte directory", name, n, dir)
		}
	}
}

// --- FS --------------------------------------------------------------------------------------

func TestFSDeterministicModTimeAndSortedReadDir(t *testing.T) {
	b := normal()
	a, err := Open(b)
	if err != nil {
		t.Fatal(err)
	}
	fsys := a.FS(nil)
	if err := fstest.TestFS(fsys, "README.md", "lib/__init__.py", "lib/util.py", "lib/data/table.json"); err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]bool{".": true, "lib": true, "lib/data": true, "README.md": false, "lib/util.py": false, "lib/data/table.json": false} {
		fi, err := fs.Stat(fsys, name)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.ModTime().Equal(Epoch) || fi.Sys() != nil || fi.IsDir() != dir {
			t.Fatalf("%s: %v %v %v", name, fi.ModTime(), fi.Sys(), fi.IsDir())
		}
		if want := fs.FileMode(0o444); dir {
			if fi.Mode() != fs.ModeDir|0o555 {
				t.Fatalf("%s: mode %v", name, fi.Mode())
			}
		} else if fi.Mode() != want {
			t.Fatalf("%s: mode %v", name, fi.Mode())
		}
		f, err := fsys.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		fi2, err := f.Stat()
		f.Close()
		if err != nil || !reflect.DeepEqual(fi, fi2) {
			t.Fatalf("%s: Stat differs through Open: %v %v %v", name, fi, fi2, err)
		}
	}
	if fi, _ := fs.Stat(fsys, "lib/data/table.json"); fi.Size() != 21 || fi.Name() != "table.json" {
		t.Fatalf("%v", fi)
	}
	if fi, _ := fs.Stat(fsys, "."); fi.Name() != "." {
		t.Fatalf("%v", fi)
	}
	// Archive order is scrambled; listings are sorted, explicit and implied directories alike.
	names := func(es []fs.DirEntry) (out []string) {
		for _, e := range es {
			out = append(out, e.Name())
		}
		return out
	}
	for dir, want := range map[string][]string{".": {"README.md", "lib"}, "lib": {"__init__.py", "data", "util.py"}, "lib/data": {"table.json"}} {
		es, err := fs.ReadDir(fsys, dir)
		if err != nil || !reflect.DeepEqual(names(es), want) {
			t.Fatalf("%s: %v %v", dir, names(es), err)
		}
		for _, e := range es {
			fi, err := e.Info()
			if err != nil || !fi.ModTime().Equal(Epoch) || fi.Sys() != nil || e.Type() != fi.Mode().Type() || e.IsDir() != fi.IsDir() {
				t.Fatalf("%s/%s: %v %v", dir, e.Name(), fi, err)
			}
		}
	}
	// Paged reads follow the same order and end with io.EOF.
	f, err := fsys.Open("lib")
	if err != nil {
		t.Fatal(err)
	}
	d := f.(fs.ReadDirFile)
	var paged []string
	for {
		es, err := d.ReadDir(1)
		if err == io.EOF {
			break
		}
		if err != nil || len(es) != 1 {
			t.Fatal(es, err)
		}
		paged = append(paged, es[0].Name())
	}
	if !reflect.DeepEqual(paged, []string{"__init__.py", "data", "util.py"}) {
		t.Fatal(paged)
	}
	if _, err := d.Read(make([]byte, 4)); err == nil {
		t.Fatal("Read on a directory")
	}
	for _, bad := range []string{"/lib", "lib/", "../x", "lib/../README.md", ""} {
		if _, err := fsys.Open(bad); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if _, err := fsys.Open("missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := fs.ReadDir(fsys, "README.md"); err == nil {
		t.Fatal("ReadDir on a file")
	}
	// Two mounts of one Archive, and a mount of the Info-ZIP fixture, pass the same checks.
	if err := fstest.TestFS(a.FS(func(int) {}), "lib/util.py"); err != nil {
		t.Fatal(err)
	}
	lib, err := FS(libZip(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := fstest.TestFS(lib, "lib/__init__.py", "lib/util.py", "lib/sub/big.txt", "lib/sub/empty.py", "lib/data/table.json", "lib/data/words.txt"); err != nil {
		t.Fatal(err)
	}
	got, err := fs.ReadFile(lib, "lib/sub/big.txt")
	if err != nil || len(got) != 49200 || !bytes.HasPrefix(got, []byte("0123456789abcdef")) {
		t.Fatalf("%d %v", len(got), err)
	}
}

func TestReadAccounting(t *testing.T) {
	big := strings.Repeat("0123456789", 1000) // 10000 bytes, deflated
	b := build(arc{ents: []ent{file("big.txt", big), plain("small.bin", strings.Repeat("s", 500))}})
	a, err := Open(b)
	if err != nil {
		t.Fatal(err)
	}
	var total int
	fsys := a.FS(func(n int) { total += n })
	if data, err := fs.ReadFile(fsys, "big.txt"); err != nil || string(data) != big || total != 10000 {
		t.Fatalf("len=%d total=%d err=%v", len(data), total, err)
	}
	total = 0
	if _, err := fs.Stat(fsys, "big.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.ReadDir(fsys, "."); err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Fatalf("metadata counted %d", total)
	}
	// Seeks on a compressed entry: forward discards are counted, backward seeks reopen.
	f, err := fsys.Open("big.txt")
	if err != nil {
		t.Fatal(err)
	}
	s := f.(io.ReadSeeker)
	if pos, err := s.Seek(6000, io.SeekStart); err != nil || pos != 6000 || total != 6000 {
		t.Fatalf("pos=%d total=%d err=%v", pos, total, err)
	}
	buf := make([]byte, 100)
	if n, err := io.ReadFull(s, buf); err != nil || n != 100 || string(buf) != big[6000:6100] || total != 6100 {
		t.Fatalf("n=%d total=%d err=%v", n, total, err)
	}
	if pos, err := s.Seek(1000, io.SeekStart); err != nil || pos != 1000 || total != 7100 {
		t.Fatalf("pos=%d total=%d err=%v", pos, total, err)
	}
	if n, _ := io.ReadFull(s, buf[:10]); n != 10 || string(buf[:10]) != big[1000:1010] {
		t.Fatal(string(buf[:10]))
	}
	if pos, err := s.Seek(0, io.SeekEnd); err != nil || pos != 10000 || total != 7110+8990 {
		t.Fatalf("pos=%d total=%d err=%v", pos, total, err)
	}
	if n, err := s.Read(buf); n != 0 || err != io.EOF {
		t.Fatal(n, err)
	}
	if pos, err := s.Seek(20000, io.SeekStart); err != nil || pos != 20000 {
		t.Fatal(pos, err)
	}
	if _, err := s.Seek(-1, io.SeekStart); err == nil {
		t.Fatal("negative seek")
	}
	if pos, err := s.Seek(-10000, io.SeekCurrent); err != nil || pos != 10000 || total != 16100+10000 {
		t.Fatalf("pos=%d total=%d err=%v", pos, total, err)
	}
	f.Close()
	if _, err := s.Read(buf); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
	// Stored entries are served from the blob with ReadAt and Seek, counted too.
	total = 0
	f, err = fsys.Open("small.bin")
	if err != nil {
		t.Fatal(err)
	}
	ra := f.(io.ReaderAt)
	if n, err := ra.ReadAt(buf, 450); n != 50 || err != io.EOF || total != 50 {
		t.Fatalf("n=%d total=%d err=%v", n, total, err)
	}
	if pos, err := f.(io.Seeker).Seek(-20, io.SeekEnd); err != nil || pos != 480 {
		t.Fatal(pos, err)
	}
	if n, err := f.Read(buf); n != 20 || err != nil || total != 70 {
		t.Fatalf("n=%d total=%d err=%v", n, total, err)
	}
	f.Close()
	// Each mount accounts separately, and a nil hook is fine.
	var other int
	if _, err := fs.ReadFile(a.FS(func(n int) { other += n }), "small.bin"); err != nil || other != 500 || total != 70 {
		t.Fatalf("other=%d total=%d err=%v", other, total, err)
	}
	if _, err := fs.ReadFile(a.FS(nil), "big.txt"); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRefusesUnusable(t *testing.T) {
	for reason, b := range map[string][]byte{ReasonUnpacked: bomb100G(), ReasonUnsafe: named("../x"), ReasonDuplicate: named("a", "a"),
		ReasonEntries: many(MaxEntries + 1), ReasonEncrypted: build(arc{ents: []ent{{name: "a", data: []byte("x"), flags: 1}}})} {
		if _, err := Open(b); err == nil || !strings.Contains(err.Error(), "fs_unusable="+reason) {
			t.Fatalf("%s: %v", reason, err)
		}
	}
	if _, err := Open([]byte("nope")); !errors.Is(err, ErrNotZip) {
		t.Fatal(err)
	}
	if a, err := Open(build(arc{})); err != nil {
		t.Fatal(err)
	} else if es, err := fs.ReadDir(a.FS(nil), "."); err != nil || len(es) != 0 {
		t.Fatal(es, err)
	}
}

// TestWazeroMount runs the fs test module (reads /etc/passwd, tries to write /tmp/x) against a
// mounted archive: the read succeeds and is accounted, the write fails on the read-only fs.
func TestWazeroMount(t *testing.T) {
	wasm, err := os.ReadFile(filepath.Join("..", "..", "testdata", "wasm", "out", "fs.wasm"))
	if err != nil {
		t.Skipf("missing test module (run testdata/wasm/build.sh): %v", err)
	}
	a, err := Open(build(arc{ents: []ent{file("etc/passwd", "root:x:0:0\n"), plain("etc/hosts", "::1 localhost\n")}}))
	if err != nil {
		t.Fatal(err)
	}
	var total int
	fsys := a.FS(func(n int) { total += n })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
	defer rt.Close(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	var out bytes.Buffer
	cfg := wazero.NewModuleConfig().WithStdout(&out).WithStderr(io.Discard).WithFSConfig(wazero.NewFSConfig().WithFSMount(fsys, "/"))
	_, err = rt.InstantiateWithConfig(ctx, wasm, cfg)
	var exit *sys.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("err=%v out=%q", err, out.String())
	}
	if s := out.String(); !strings.Contains(s, "read 11 bytes") || !strings.Contains(s, "write error") {
		t.Fatalf("out %q", s)
	}
	if total != 11 {
		t.Fatalf("accounted %d bytes", total)
	}
}
