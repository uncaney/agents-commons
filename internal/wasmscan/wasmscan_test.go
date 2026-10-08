package wasmscan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/tetratelabs/wazero"
)

// --- a tiny module builder ------------------------------------------------------------------

func uleb(v uint64) (out []byte) {
	for {
		c := byte(v & 0x7f)
		if v >>= 7; v != 0 {
			c |= 0x80
		}
		out = append(out, c)
		if v == 0 {
			return out
		}
	}
}

func sleb(v int64) (out []byte) {
	for {
		c := byte(v & 0x7f)
		v >>= 7
		done := (v == 0 && c&0x40 == 0) || (v == -1 && c&0x40 != 0)
		if !done {
			c |= 0x80
		}
		out = append(out, c)
		if done {
			return out
		}
	}
}

func str(s string) []byte { return append(uleb(uint64(len(s))), s...) }

func vec(items ...[]byte) []byte {
	out := uleb(uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

func section(id byte, body []byte) []byte {
	return append(append([]byte{id}, uleb(uint64(len(body)))...), body...)
}

const header = "\x00asm\x01\x00\x00\x00"

func module(secs ...[]byte) []byte {
	out := []byte(header)
	for _, s := range secs {
		out = append(out, s...)
	}
	return out
}

func typeSec() []byte                    { return section(1, vec([]byte{0x60, 0, 0})) } // one () -> ()
func importFunc(mod, name string) []byte { return append(append(str(mod), str(name)...), 0x00, 0x00) }
func importMem(mod, name string, min uint32) []byte {
	return append(append(append(str(mod), str(name)...), 0x02, 0x00), uleb(uint64(min))...)
}
func importSec(items ...[]byte) []byte { return section(2, vec(items...)) }

func funcSec(n int) []byte {
	body := uleb(uint64(n))
	for i := 0; i < n; i++ {
		body = append(body, 0)
	}
	return section(3, body)
}

func limits(flag byte, min, max uint64) []byte {
	b := append([]byte{flag}, uleb(min)...)
	if flag&1 != 0 {
		b = append(b, uleb(max)...)
	}
	return b
}
func memSec(min, max uint32, hasMax bool) []byte {
	var flag byte
	if hasMax {
		flag = 1
	}
	return section(5, vec(limits(flag, uint64(min), uint64(max))))
}

func export(name string, kind byte, idx uint32) []byte {
	return append(append(str(name), kind), uleb(uint64(idx))...)
}
func exportSec(items ...[]byte) []byte { return section(7, vec(items...)) }

func codeSec(n int) []byte {
	bodies := make([][]byte, n)
	for i := range bodies {
		bodies[i] = []byte{2, 0, 0x0b} // size 2: no locals, end
	}
	return section(10, vec(bodies...))
}

func activeData(offset int32, b []byte) []byte {
	seg := append([]byte{0, 0x41}, sleb(int64(offset))...)
	seg = append(seg, 0x0b)
	return append(append(seg, uleb(uint64(len(b)))...), b...)
}
func passiveData(b []byte) []byte            { return append(append([]byte{1}, uleb(uint64(len(b)))...), b...) }
func dataSec(segs ...[]byte) []byte          { return section(11, vec(segs...)) }
func custom(name string, body []byte) []byte { return section(0, append(str(name), body...)) }

func field(name string, vals ...[2]string) []byte {
	items := make([][]byte, len(vals))
	for i, v := range vals {
		items[i] = append(str(v[0]), str(v[1])...)
	}
	return append(str(name), vec(items...)...)
}
func producersSec(fields ...[]byte) []byte { return custom("producers", vec(fields...)) }

var goProducers = producersSec(field("language", [2]string{"Go", "go1.27.1"}), field("processed-by", [2]string{"Go cmd/compile", "go1.27.1"}))

// wasip1 builds a module shaped like a Go wasip1 binary: imports (functions unless the entry
// says otherwise), n defined functions, a memory section, exports and data.
func wasip1(imports [][]byte, n int, mem []byte, exports [][]byte, data []byte) []byte {
	secs := [][]byte{custom("go:buildid", []byte("abc")), typeSec()}
	if len(imports) > 0 {
		secs = append(secs, importSec(imports...))
	}
	secs = append(secs, funcSec(n))
	if mem != nil {
		secs = append(secs, mem)
	}
	secs = append(secs, exportSec(exports...), codeSec(n))
	if data != nil {
		secs = append(secs, data)
	}
	return module(append(secs, goProducers)...)
}

var (
	wasiImports = [][]byte{importFunc(WASI, "fd_write"), importFunc(WASI, "proc_exit")}
	goodData    = dataSec(activeData(1024, []byte("hello world, this is a sixteen+ byte string\x00\x01\x02short\x00")), passiveData([]byte("passive segment printable text here")))
)

func goodModule() []byte {
	return wasip1(wasiImports, 3, memSec(2, 65536, true), [][]byte{export("memory", 2, 0), export("_start", 0, 2)}, goodData)
}

// --- fixtures ---------------------------------------------------------------------------------

func fixtures(t testing.TB) map[string][]byte {
	t.Helper()
	paths, _ := filepath.Glob("../../testdata/wasm/out/*.wasm")
	if len(paths) == 0 {
		t.Skip("no fixtures in testdata/wasm/out (run testdata/wasm/build.sh)")
	}
	out := map[string][]byte{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out[strings.TrimSuffix(filepath.Base(p), ".wasm")] = b
	}
	return out
}

func mustParse(t *testing.T, b []byte) Info {
	t.Helper()
	info, err := Parse(b, 0)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return info
}

func wantErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || err.Error() != want {
		t.Fatalf("got %v\nwant %s", err, want)
	}
	var e *Error
	if !errors.As(err, &e) || e.Status != 400 || !strings.HasPrefix(want, "err "+e.Code+" ") || strings.ContainsAny(e.Msg, "\r\n") {
		t.Fatalf("not a 400 single-line *Error: %#v", err)
	}
}

// --- tests ------------------------------------------------------------------------------------

func TestSyntheticModulesAreValidWasm(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigInterpreter())
	defer rt.Close(ctx)
	for name, b := range map[string][]byte{
		"good":       goodModule(),
		"emscripten": emscriptenModule(),
		"bigmem":     bigMemModule(),
		"nostart":    noStartModule(),
	} {
		cm, err := rt.CompileModule(ctx, b)
		if err != nil {
			t.Fatalf("%s: wazero rejects the synthetic module: %v", name, err)
		}
		cm.Close(ctx)
	}
}

var lineRe = regexp.MustCompile(`^wasm size=\d+ imports=wasi_snapshot_preview1:\w+(,wasi_snapshot_preview1:\w+){7},… memory=min\d+( max\d+)? funcs=\d+ has_start=1 producers=Go1\.\d+(\.\d+)?$`)

func TestParseTestdataModules(t *testing.T) {
	for name, b := range fixtures(t) {
		info := mustParse(t, b)
		if info.Size != len(b) || info.Truncated {
			t.Fatalf("%s: size=%d truncated=%v", name, info.Size, info.Truncated)
		}
		if len(info.Imports) == 0 || len(info.Imports) != info.ImportCount || info.BadImport != "" {
			t.Fatalf("%s: imports %d/%d bad=%q", name, len(info.Imports), info.ImportCount, info.BadImport)
		}
		for _, im := range info.Imports {
			if im.Module != WASI || im.Kind != "func" || im.Name == "" {
				t.Fatalf("%s: unexpected import %+v", name, im)
			}
		}
		if !info.HasMemory || info.MinPages == 0 || info.Memory64 || !info.ExportsMemory || !info.HasStart {
			t.Fatalf("%s: memory/exports %+v", name, info)
		}
		if info.Funcs < 100 || info.CodeBytes < len(b)/2 || info.CodeBytes >= len(b) {
			t.Fatalf("%s: funcs=%d code=%d of %d", name, info.Funcs, info.CodeBytes, len(b))
		}
		if !strings.HasPrefix(info.Producers, "Go1.") {
			t.Fatalf("%s: producers %q", name, info.Producers)
		}
		if len(info.Strings) == 0 {
			t.Fatalf("%s: no data-segment strings", name)
		}
		if err := info.Check(32); err != nil {
			t.Fatalf("%s: Check(32): %v", name, err)
		}
		line := info.Line()
		if !lineRe.MatchString(line) {
			t.Fatalf("%s: line %q", name, line)
		}
		t.Logf("%s: %s strings=%d", name, line, len(info.Strings))
	}
}

func emscriptenModule() []byte {
	imports := [][]byte{importFunc("env", "emscripten_notify_memory_growth"), importFunc(WASI, "fd_write")}
	return wasip1(imports, 1, memSec(256, 256, true), [][]byte{export("memory", 2, 0), export("_start", 0, 2)}, nil)
}

func TestRejectsEmscriptenImports(t *testing.T) {
	info := mustParse(t, emscriptenModule())
	if info.BadImport != "env.emscripten_notify_memory_growth" || len(info.Imports) != 2 || info.Imports[0].Kind != "func" {
		t.Fatalf("%+v", info)
	}
	wantErr(t, info.Check(32), "err bad import env.emscripten_notify_memory_growth: only wasi_snapshot_preview1 is available")

	// an imported memory (emscripten -sIMPORTED_MEMORY) is refused as an import, even from env.
	m := wasip1([][]byte{importMem("env", "memory", 16), importFunc(WASI, "fd_write")}, 1, nil, [][]byte{export("_start", 0, 1)}, nil)
	info = mustParse(t, m)
	if !info.HasMemory || info.MinPages != 16 || info.Imports[0].Kind != "memory" {
		t.Fatalf("%+v", info)
	}
	wantErr(t, info.Check(32), "err bad import env.memory: only wasi_snapshot_preview1 is available")

	// a non-function import under the wasi module name is not a WASI function either.
	m = wasip1([][]byte{importMem(WASI, "memory", 1)}, 1, nil, [][]byte{export("_start", 0, 0)}, nil)
	wantErr(t, mustParse(t, m).Check(32), "err bad import wasi_snapshot_preview1.memory: only wasi_snapshot_preview1 is available")

	// hostile import names stay on one line in the message (invalid UTF-8 is a parse error).
	m = wasip1([][]byte{importFunc("env", "x\ny=1,\x7f​z")}, 1, nil, [][]byte{export("_start", 0, 1)}, nil)
	wantErr(t, mustParse(t, m).Check(32), "err bad import env.x?y?1???z: only wasi_snapshot_preview1 is available")
}

func bigMemModule() []byte {
	return wasip1(wasiImports, 1, memSec(1024, 0, false), [][]byte{export("memory", 2, 0), export("_start", 0, 2)}, nil)
}

func TestDeclaredMemoryOverLimit(t *testing.T) {
	info := mustParse(t, bigMemModule())
	if !info.HasMemory || info.MinPages != 1024 || info.HasMax || info.MaxPages != 0 {
		t.Fatalf("%+v", info)
	}
	wantErr(t, info.Check(32), "err oom declared min memory 1024 pages (64 MiB) > mb=32")
	wantErr(t, info.Check(63), "err oom declared min memory 1024 pages (64 MiB) > mb=63")
	for _, mb := range []int{64, 256, 0} {
		if err := info.Check(mb); err != nil {
			t.Fatalf("Check(%d): %v", mb, err)
		}
	}
	// 17 pages round up to 2 MiB in the message and fit mb=2.
	info = mustParse(t, wasip1(wasiImports, 1, memSec(17, 0, false), [][]byte{export("_start", 0, 2)}, nil))
	wantErr(t, info.Check(1), "err oom declared min memory 17 pages (2 MiB) > mb=1")
	if err := info.Check(2); err != nil {
		t.Fatal(err)
	}
	// memory64 limits parse (clamped) but are refused.
	m := module(typeSec(), funcSec(1), section(5, vec(limits(5, 1<<33, 1<<34))), exportSec(export("_start", 0, 0)), codeSec(1))
	info = mustParse(t, m)
	if !info.Memory64 || info.MinPages != 0xffffffff || !info.HasMax || info.MaxPages != 0xffffffff {
		t.Fatalf("%+v", info)
	}
	wantErr(t, info.Check(32), "err bad memory64 unsupported; build with wasi-sdk preview1, GOOS=wasip1 or --target wasm32-wasip1")
	if l := info.Line(); !strings.Contains(l, " memory=min4294967295 max4294967295 memory64=1 ") {
		t.Fatal(l)
	}
}

func noStartModule() []byte {
	return wasip1(wasiImports, 2, memSec(2, 0, false), [][]byte{export("memory", 2, 0), export("run", 0, 2), export("_initialize", 0, 3)}, nil)
}

const noStart = "err bad no _start export (component model/preview2 unsupported; build with wasi-sdk preview1, GOOS=wasip1 or --target wasm32-wasip1)"

func TestNoStartExport(t *testing.T) {
	info := mustParse(t, noStartModule())
	if info.HasStart || !info.ExportsMemory {
		t.Fatalf("%+v", info)
	}
	wantErr(t, info.Check(32), noStart)

	// _start must be a function export: a global or a table of that name does not count.
	m := wasip1(wasiImports, 1, memSec(1, 0, false), [][]byte{export("_start", 3, 0), export("_start", 1, 0)}, nil)
	wantErr(t, mustParse(t, m).Check(32), noStart)

	// a component (preview2) is told apart at the header.
	comp := []byte("\x00asm\x0d\x00\x01\x00")
	if _, err := Parse(comp, 0); !errors.Is(err, ErrComponent) {
		t.Fatalf("component: %v", err)
	}
	if _, err := Parse([]byte("\x00asm\x02\x00\x00\x00"), 0); !errors.Is(err, ErrVersion) {
		t.Fatalf("version: %v", err)
	}
	if _, err := Parse([]byte("\x7fELF\x01\x00\x00\x00"), 0); !errors.Is(err, ErrNotWasm) {
		t.Fatalf("elf: %v", err)
	}
	if IsWasm(comp) != true || IsWasm([]byte("\x00as")) {
		t.Fatal("IsWasm")
	}
	// the good module passes every rule.
	if err := mustParse(t, goodModule()).Check(32); err != nil {
		t.Fatal(err)
	}
}

// sectionEnds walks the section headers independently of the parser and returns every offset
// at which a prefix of b is a complete module (the header alone, then after each section).
func sectionEnds(t *testing.T, b []byte) map[int]bool {
	t.Helper()
	ends := map[int]bool{8: true}
	pos := 8
	for pos < len(b) {
		pos++ // id
		var size, shift uint64
		for {
			c := b[pos]
			pos++
			size |= uint64(c&0x7f) << shift
			shift += 7
			if c&0x80 == 0 {
				break
			}
		}
		pos += int(size)
		if pos > len(b) {
			t.Fatalf("fixture section runs past the end at %d", pos)
		}
		ends[pos] = true
	}
	return ends
}

func TestTruncatedSections(t *testing.T) {
	good := goodModule()
	ends := sectionEnds(t, good)
	for k := 0; k <= len(good); k++ {
		info, err := Parse(good[:k], 0)
		switch {
		case ends[k] && err != nil:
			t.Fatalf("cut at section boundary %d: %v", k, err)
		case !ends[k] && err == nil:
			t.Fatalf("cut at %d inside a section parsed: %s", k, info.Line())
		case info.Size != k:
			t.Fatalf("size %d at cut %d", info.Size, k)
		}
	}
	// a section whose size claims more than the remaining bytes, in every section position.
	for i := 0; i < len(good)-8; i++ {
		b := append([]byte{}, good...)
		b[8+i] = 0xff // inflates the id, a size byte or a body byte
		if _, err := Parse(b, 0); err == nil && i < 2 {
			t.Fatalf("inflated byte %d parsed", 8+i)
		}
	}
	// a LEB128 size running past the end and a 6-byte size.
	for _, tail := range [][]byte{{0x0a, 0x80}, {0x0a, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, {0x0a}} {
		if _, err := Parse(append([]byte(header), tail...), 0); err == nil {
			t.Fatalf("tail %x parsed", tail)
		}
	}
	// the max cap.
	if _, err := Parse(good, len(good)-1); err == nil || !strings.Contains(err.Error(), "over") {
		t.Fatalf("max: %v", err)
	}
	if _, err := Parse(good, len(good)); err != nil {
		t.Fatal(err)
	}
	// cuts inside each fixture: boundaries parse, everything else is an error, nothing panics.
	for name, b := range fixtures(t) {
		fe := sectionEnds(t, b)
		var offs []int
		for e := range fe {
			offs = append(offs, e-1, e, e+1)
		}
		for k := 0; k < len(b); k += len(b)/64 + 1 {
			offs = append(offs, k)
		}
		sort.Ints(offs)
		for _, k := range offs {
			if k < 0 || k > len(b) {
				continue
			}
			_, err := Parse(b[:k], 0)
			if fe[k] != (err == nil) {
				t.Fatalf("%s cut at %d (boundary=%v): %v", name, k, fe[k], err)
			}
		}
	}
}

func TestStructureErrors(t *testing.T) {
	cases := map[string][]byte{
		"unknown section id": module(section(14, nil)),
		"out of order":       module(typeSec(), exportSec(), importSec()),
		"duplicate":          module(typeSec(), typeSec()),
		"import kind":        module(typeSec(), importSec(append(append(str("a"), str("b")...), 0x07, 0x00))),
		"import count":       module(typeSec(), section(2, uleb(1000))),
		"import name utf8":   module(typeSec(), importSec(importFunc("\xff\xfe", "x"))),
		"import trailing":    module(typeSec(), section(2, append(vec(importFunc(WASI, "x")), 0x00))),
		"limits flag":        module(typeSec(), section(5, vec([]byte{0x08, 0x01}))),
		"export kind":        module(typeSec(), exportSec(export("x", 5, 0))),
		"data flag":          module(dataSec([]byte{3, 0})),
		"data expr opcode":   module(dataSec([]byte{0, 0x10, 0x0b, 0})),
		"data expr long":     module(dataSec(append([]byte{0}, append(bytesOf(0x6a, 64), 0x0b, 0)...))),
		"data past end":      module(dataSec([]byte{1, 0x05, 'a'})),
		"custom name":        module(section(0, str("\xff"))),
		"global mut":         module(typeSec(), importSec(append(append(str("a"), str("b")...), 0x03, 0x7f, 0x02))),
		"leb overflow":       module(typeSec(), section(3, []byte{0xff, 0xff, 0xff, 0xff, 0x7f})),
	}
	for name, b := range cases {
		if _, err := Parse(b, 0); err == nil {
			t.Errorf("%s: parsed", name)
		} else if !strings.HasPrefix(err.Error(), "wasm: ") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// accepted shapes: table/global/tag imports, every const-expr opcode, memidx 2 segments,
	// typed references, a padded LEB size like Go's go:buildid section, a start section.
	tableImp := append(append(str("e"), str("t")...), 0x01, 0x70, 0x01, 0x00, 0x10)
	globalImp := append(append(str("e"), str("g")...), 0x03, 0x63, 0x70, 0x01)
	tagImp := append(append(str("e"), str("x")...), 0x04, 0x00, 0x00)
	exprs := [][]byte{{0x42, 0x05, 0x0b}, {0x43, 1, 2, 3, 4, 0x0b}, {0x44, 1, 2, 3, 4, 5, 6, 7, 8, 0x0b},
		{0x23, 0x00, 0x0b}, {0xd0, 0x70, 0x0b}, {0xd2, 0x00, 0x0b}, {0x41, 0x01, 0x41, 0x02, 0x6a, 0x0b},
		append(append([]byte{0xfd, 12}, bytesOf(0, 16)...), 0x0b)}
	var segs [][]byte
	for _, e := range exprs {
		segs = append(segs, append(append(append([]byte{2, 0x00}, e...), 0x03), "abc"...))
	}
	ok := module(append([]byte{0x00, 0xf2, 0x80, 0x80, 0x80, 0x00}, append(str("go:buildid"), bytesOf('x', 103)...)...),
		typeSec(), importSec(tableImp, globalImp, tagImp), funcSec(1), memSec(1, 0, false), section(8, []byte{0x03}),
		section(12, uleb(uint64(len(segs)))), codeSec(1), dataSec(segs...))
	info := mustParse(t, ok)
	if info.ImportCount != 3 || info.BadImport != "e.t" || info.Imports[1].Kind != "global" || info.Imports[2].Kind != "tag" || info.Funcs != 1 {
		t.Fatalf("%+v", info)
	}
}

func bytesOf(c byte, n int) []byte { return []byte(strings.Repeat(string(c), n)) }

func TestAbortLimits(t *testing.T) {
	// 1500 imports: the walk stops at 1000, 64 are kept, nothing else is lost.
	imports := make([][]byte, 1500)
	for i := range imports {
		imports[i] = importFunc(WASI, fmt.Sprintf("f%d", i))
	}
	imports[1200] = importFunc("env", "late") // beyond the walk: never seen
	m := wasip1(imports, 1, memSec(2, 0, false), [][]byte{export("memory", 2, 0), export("_start", 0, 1500)}, goodData)
	info := mustParse(t, m)
	if !info.Truncated || len(info.Imports) != KeepImports || info.ImportCount != 1500 || info.BadImport != "" {
		t.Fatalf("truncated=%v kept=%d count=%d bad=%q", info.Truncated, len(info.Imports), info.ImportCount, info.BadImport)
	}
	if info.Imports[63].Name != "f63" || !info.HasStart || !info.ExportsMemory || len(info.Strings) != 2 || info.Producers != "Go1.27.1" {
		t.Fatalf("%+v", info)
	}
	wantErr(t, info.Check(32), "err bad 1500 imports: only wasi_snapshot_preview1 is available")
	if l := info.Line(); !strings.HasSuffix(l, " producers=Go1.27.1 truncated=1") || !strings.Contains(l, "imports=wasi_snapshot_preview1:f0,wasi_snapshot_preview1:f1,") || !strings.Contains(l, ":f7,… memory=") {
		t.Fatal(l)
	}
	// a bad import within the first 1000 is still found.
	imports[700] = importFunc("env", "early")
	info = mustParse(t, wasip1(imports, 1, nil, [][]byte{export("_start", 0, 1500)}, nil))
	if !info.Truncated || info.BadImport != "env.early" {
		t.Fatalf("%+v", info.BadImport)
	}
	wantErr(t, info.Check(32), "err bad import env.early: only wasi_snapshot_preview1 is available")

	// 100001 functions: counted, flagged, not refused.
	n := MaxFuncs + 1
	m = module(typeSec(), funcSec(n), memSec(1, 0, false), exportSec(export("_start", 0, 0)), section(10, append(uleb(uint64(n)), bytesOf(0, n)...)))
	info = mustParse(t, m)
	if !info.Truncated || info.Funcs != n || !info.HasStart {
		t.Fatalf("%+v", info)
	}
	if err := info.Check(32); err != nil {
		t.Fatal(err)
	}
	info = mustParse(t, module(typeSec(), funcSec(MaxFuncs)))
	if info.Truncated || info.Funcs != MaxFuncs {
		t.Fatalf("%+v", info)
	}

	// exports past the cap are not walked: a _start declared after it is unknown.
	exports := make([][]byte, MaxExports+1)
	for i := range exports {
		exports[i] = export(fmt.Sprintf("e%d", i), 0, 0)
	}
	exports[MaxExports] = export("_start", 0, 0)
	info = mustParse(t, module(typeSec(), funcSec(1), exportSec(exports...), codeSec(1)))
	if !info.Truncated || info.HasStart {
		t.Fatalf("%+v", info)
	}
	exports[MaxExports-1] = export("_start", 0, 0)
	if info = mustParse(t, module(typeSec(), funcSec(1), exportSec(exports...), codeSec(1))); !info.HasStart {
		t.Fatal("start within the cap not seen")
	}

	// more than MaxSections custom sections stop the walk without an error.
	secs := make([][]byte, MaxSections+10)
	for i := range secs {
		secs[i] = custom("c", nil)
	}
	info = mustParse(t, module(secs...))
	if !info.Truncated {
		t.Fatal("sections cap")
	}
}

func TestStrings(t *testing.T) {
	info := mustParse(t, goodModule())
	want := []string{"hello world, this is a sixteen+ byte string", "passive segment printable text here"}
	if strings.Join(info.Strings, "|") != strings.Join(want, "|") {
		t.Fatalf("%q", info.Strings)
	}
	// a run spanning two segments is one string; 15-byte runs and runs cut by \t or \n are dropped.
	m := module(dataSec(passiveData([]byte("0123456789")), passiveData([]byte("ABCDEFGHIJ\n123456789012345\tfifteen-bytes!!\x00")), passiveData([]byte("sixteen-bytes!!!"))))
	info = mustParse(t, m)
	if strings.Join(info.Strings, "|") != "0123456789ABCDEFGHIJ|sixteen-bytes!!!" {
		t.Fatalf("%q", info.Strings)
	}
	// a carried run that ends short is dropped without touching earlier strings.
	m = module(dataSec(passiveData([]byte("first string of sixteen+\x00abc")), passiveData([]byte("de\x00second string of sixteen+"))))
	info = mustParse(t, m)
	if strings.Join(info.Strings, "|") != "first string of sixteen+|second string of sixteen+" {
		t.Fatalf("%q", info.Strings)
	}
	// only the first StringsBudget data bytes are scanned.
	big := bytesOf('a', StringsBudget+5000)
	info = mustParse(t, module(dataSec(passiveData(big[:1000]), passiveData(big[1000:]))))
	if len(info.Strings) != 1 || len(info.Strings[0]) != StringsBudget {
		t.Fatalf("%d strings, first %d bytes", len(info.Strings), len(info.Strings[0]))
	}
	// at most MaxStrings runs.
	many := bytes16(MaxStrings + 100)
	info = mustParse(t, module(dataSec(passiveData(many))))
	if len(info.Strings) != MaxStrings || info.Strings[0] != "0000000000000000" {
		t.Fatalf("%d strings", len(info.Strings))
	}
	for _, s := range info.Strings {
		if len(s) < MinString {
			t.Fatal(s)
		}
	}
	// no data: nil
	if info = mustParse(t, module(typeSec())); info.Strings != nil {
		t.Fatal(info.Strings)
	}
	// fixtures: Go string tables are long printable runs; every string is printable ASCII.
	for name, b := range fixtures(t) {
		info := mustParse(t, b)
		total := 0
		for _, s := range info.Strings {
			total += len(s)
			if len(s) < MinString || strings.IndexFunc(s, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
				t.Fatalf("%s: bad string %q", name, s)
			}
		}
		if total > StringsBudget || total == 0 {
			t.Fatalf("%s: %d string bytes", name, total)
		}
	}
}

// bytes16 is n sixteen-byte runs "0000000000000000", "0000000000000001", … separated by NULs.
func bytes16(n int) []byte {
	var b []byte
	for i := 0; i < n; i++ {
		b = append(b, fmt.Sprintf("%016d\x00", i)...)
	}
	return b
}

func TestProducers(t *testing.T) {
	cases := []struct {
		sec  []byte
		want string
	}{
		{goProducers, "Go1.27.1"},
		{producersSec(field("language", [2]string{"Rust", ""}), field("processed-by", [2]string{"rustc", "1.75.0 (82e1608df 2023-12-21)"})), "Rust1.75.0"},
		{producersSec(field("language", [2]string{"C11", ""}), field("processed-by", [2]string{"clang", "16.0.0"}), field("sdk", [2]string{"Emscripten", "3.1.0"})), "C11+clang16.0.0+Emscripten3.1.0"},
		{producersSec(field("processed-by", [2]string{"wasm-opt", "116"})), "wasm-opt116"},
		{producersSec(field("language", [2]string{"a b", "1 2"}, [2]string{"x=y", "\n"}, [2]string{"", ""})), "a?b1+x?y?"},
		{producersSec(field("language", [2]string{strings.Repeat("L", 100), strings.Repeat("9", 100)})), strings.Repeat("L", 32)},
		{producersSec(), ""},
		{custom("producers", []byte{0x02, 0x08, 'l', 'a', 'n', 'g', 'u', 'a', 'g', 'e', 0x01, 0x05, 'x'}), ""}, // truncated inside
		{custom("producers", append(uleb(1), append(str("language"), uleb(1)...)...)), ""},                     // missing value
	}
	for i, c := range cases {
		info := mustParse(t, module(c.sec, typeSec()))
		if info.Producers != c.want {
			t.Errorf("case %d: %q want %q", i, info.Producers, c.want)
		}
		if l := info.Line(); strings.ContainsAny(l, "\r\n\t") || !utf8.ValidString(l) {
			t.Errorf("case %d: line %q", i, l)
		}
	}
	// the first producers section wins; a non-producers custom section is skipped.
	m := module(custom("name", []byte("\x00\x01x")), goProducers, producersSec(field("language", [2]string{"Zig", "0.13"})), typeSec())
	info := mustParse(t, m)
	if info.Producers != "Go1.27.1" {
		t.Fatal(info.Producers)
	}
	if l, want := info.Line(), fmt.Sprintf("wasm size=%d imports=- memory=- funcs=0 has_start=0 producers=Go1.27.1", len(m)); l != want {
		t.Fatalf("\n got %q\nwant %q", l, want)
	}
}

func TestLineIsOneSafeLine(t *testing.T) {
	imports := [][]byte{importFunc("en\nv", "a\rb"), importFunc("e=v", "x,y z"), importFunc("​ ", "\x00\x7f 　"), importFunc(strings.Repeat("m", 100), strings.Repeat("é", 100))}
	m := module(typeSec(), importSec(imports...), funcSec(1), memSec(3, 0, false), exportSec(export("_start", 0, 4)), codeSec(1), producersSec(field("language", [2]string{"L\n", "1\r2"})))
	info := mustParse(t, m)
	l := info.Line()
	want := fmt.Sprintf("wasm size=%d imports=en?v:a?b,e?v:x?y?z,??:????,%s:%s memory=min3 funcs=1 has_start=1 producers=L?1?2", len(m), strings.Repeat("m", 48), strings.Repeat("é", 48))
	if l != want {
		t.Fatalf("\n got %q\nwant %q", l, want)
	}
	if strings.ContainsAny(l, "\r\n\t\x00") || !utf8.ValidString(l) {
		t.Fatal(l)
	}
	wantErr(t, info.Check(32), "err bad import en?v.a?b: only wasi_snapshot_preview1 is available")
	// an empty module renders every field.
	if l := mustParse(t, module()).Line(); l != "wasm size=8 imports=- memory=- funcs=0 has_start=0 producers=-" {
		t.Fatal(l)
	}
}
