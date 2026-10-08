// Package wasmscan statically reads the head of a WebAssembly core module (SPEC-v2 14.3, 27.6):
// magic/version, section headers, imports, memory limits, exports, function count, code size,
// the "producers" custom section and the printable strings of its data segments. It never
// compiles or validates the module (wazero does that on the donor) and is bounded in time and
// memory: O(len(b)) with every length checked against the remaining bytes, no allocation beyond
// the kept imports, one copy of the scanned data-segment text and the producers string.
package wasmscan

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	MaxImports    = 1000      // the import walk stops here (Truncated, no error)
	MaxFuncs      = 100000    // a larger function count marks the module Truncated
	KeepImports   = 64        // imports retained in Info.Imports
	MaxExports    = 100000    // the export walk stops here (Truncated)
	MaxSections   = 256       // sections read before the parser stops (Truncated)
	StringsBudget = 256 << 10 // data-segment bytes scanned for Strings
	MinString     = 16        // shortest printable run kept
	MaxStrings    = 4096      // runs kept
	PageSize      = 65536
	WASI          = "wasi_snapshot_preview1"
)

var (
	ErrNotWasm   = errors.New("wasm: not a module (no \\0asm magic)")
	ErrComponent = errors.New("wasm: component model (preview2) unsupported; build with wasi-sdk preview1, GOOS=wasip1 or --target wasm32-wasip1")
	ErrVersion   = errors.New("wasm: unsupported binary version")
)

// Import is one entry of the import section; Kind is func, table, memory, global or tag.
type Import struct {
	Module string `json:"module"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
}

// Info is what Parse learns without decoding any function body.
type Info struct {
	Size          int
	Imports       []Import // the first KeepImports
	ImportCount   int      // declared count (the walk covers at most MaxImports)
	BadImport     string   // first import that is not a wasi_snapshot_preview1 function, as module.name
	HasMemory     bool
	MinPages      uint32
	MaxPages      uint32
	HasMax        bool
	Memory64      bool
	Funcs         int  // function section count (defined functions)
	CodeBytes     int  // code section size
	HasStart      bool // a `_start` function export
	ExportsMemory bool
	Producers     string   // compact toolchain string, e.g. Go1.27.1
	Strings       []string // printable runs >= MinString bytes from the first StringsBudget data bytes
	Truncated     bool     // a limit stopped a walk: counts and lists are incomplete
}

var kinds = [...]string{"func", "table", "memory", "global", "tag"}

// IsWasm reports whether b starts with the core module magic.
func IsWasm(b []byte) bool { return len(b) >= 4 && string(b[:4]) == "\x00asm" }

// Parse scans b. max > 0 refuses larger modules before reading them. Limit aborts set
// Truncated and are not errors; malformed structure (a length past the end, an unknown section
// id, sections out of order, a bad import kind, a bad data segment) is.
func Parse(b []byte, max int) (Info, error) {
	info := Info{Size: len(b)}
	if max > 0 && len(b) > max {
		return info, fmt.Errorf("wasm: module %d bytes over %d", len(b), max)
	}
	if !IsWasm(b) {
		return info, ErrNotWasm
	}
	if len(b) < 8 {
		return info, errorf("header truncated")
	}
	switch {
	case b[4] == 1 && b[5] == 0 && b[6] == 0 && b[7] == 0:
	case b[6] == 1 && b[7] == 0: // version N, layer 1 = component
		return info, ErrComponent
	default:
		return info, ErrVersion
	}
	r := reader{b: b, pos: 8}
	var strs stringScan
	last, n := -1, 0
	for r.rem() > 0 {
		if n++; n > MaxSections {
			info.Truncated = true
			break
		}
		id, err := r.byte()
		if err != nil {
			return info, errorf("section header truncated")
		}
		size, err := r.u32()
		if err != nil {
			return info, errorf("section %d size: %v", id, err)
		}
		body, err := r.take(size)
		if err != nil {
			return info, errorf("section %d truncated: size %d past end", id, size)
		}
		if id != 0 {
			if int(id) >= len(order) || order[id] == 0 {
				return info, errorf("unknown section id %d", id)
			}
			if order[id] <= last {
				return info, errorf("section %d out of order", id)
			}
			last = order[id]
		}
		s := reader{b: body}
		switch id {
		case 0:
			err = parseCustom(&s, &info)
		case 2:
			err = parseImports(&s, &info)
		case 3:
			err = parseFuncs(&s, &info)
		case 5:
			err = parseMemory(&s, &info)
		case 7:
			err = parseExports(&s, &info)
		case 10:
			info.CodeBytes = len(body)
		case 11:
			err = parseData(&s, &strs)
		}
		if err != nil {
			return info, errorf("section %d: %v", id, err)
		}
	}
	info.Strings = strs.strings()
	return info, nil
}

// order is each non-custom section's mandatory rank: type, import, function, table, memory, tag,
// global, export, start, element, data count, code, data (0 = unknown id).
var order = [...]int{1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 13: 6, 6: 7, 7: 8, 8: 9, 9: 10, 12: 11, 10: 12, 11: 13}

func errorf(format string, a ...any) error { return fmt.Errorf("wasm: "+format, a...) }

// --- byte reader -----------------------------------------------------------------------------

type reader struct {
	b   []byte
	pos int
}

func (r *reader) rem() int { return len(r.b) - r.pos }

func (r *reader) byte() (byte, error) {
	if r.pos >= len(r.b) {
		return 0, errors.New("unexpected end")
	}
	c := r.b[r.pos]
	r.pos++
	return c, nil
}

// u32 decodes an unsigned LEB128 of at most 5 bytes (non-minimal encodings allowed, as Go emits).
func (r *reader) u32() (uint32, error) {
	var v uint32
	for i := 0; i < 5; i++ {
		c, err := r.byte()
		if err != nil {
			return 0, err
		}
		if i == 4 && c&0x70 != 0 {
			return 0, errors.New("leb128 u32 overflow")
		}
		v |= uint32(c&0x7f) << (7 * i)
		if c&0x80 == 0 {
			return v, nil
		}
	}
	return 0, errors.New("leb128 u32 too long")
}

// u64 decodes an unsigned LEB128 of at most 10 bytes.
func (r *reader) u64() (uint64, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		c, err := r.byte()
		if err != nil {
			return 0, err
		}
		if i == 9 && c&0x7e != 0 {
			return 0, errors.New("leb128 u64 overflow")
		}
		v |= uint64(c&0x7f) << (7 * i)
		if c&0x80 == 0 {
			return v, nil
		}
	}
	return 0, errors.New("leb128 u64 too long")
}

// sleb skips a signed LEB128 of at most max bytes (const expression immediates).
func (r *reader) sleb(max int) error {
	for i := 0; i < max; i++ {
		c, err := r.byte()
		if err != nil {
			return err
		}
		if c&0x80 == 0 {
			return nil
		}
	}
	return errors.New("leb128 too long")
}

// take returns the next n bytes without copying.
func (r *reader) take(n uint32) ([]byte, error) {
	if uint64(n) > uint64(r.rem()) {
		return nil, errors.New("length past end")
	}
	s := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return s, nil
}

// name reads a length-prefixed UTF-8 name (no copy).
func (r *reader) name() ([]byte, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	s, err := r.take(n)
	if err != nil {
		return nil, fmt.Errorf("name of %d bytes past end", n)
	}
	if !utf8.Valid(s) {
		return nil, errors.New("name is not UTF-8")
	}
	return s, nil
}

// count reads a vector length and checks it against the smallest possible element size.
func (r *reader) count(minElem int) (int, error) {
	n, err := r.u32()
	if err != nil {
		return 0, err
	}
	if uint64(n)*uint64(minElem) > uint64(r.rem()) {
		return 0, fmt.Errorf("count %d past end", n)
	}
	return int(n), nil
}

// limits reads a memory or table limits record; min and max are clamped to uint32.
func (r *reader) limits() (min, max uint32, hasMax, is64 bool, err error) {
	flag, err := r.byte()
	if err != nil {
		return
	}
	if flag&^0x07 != 0 {
		err = fmt.Errorf("limits flag %#x", flag)
		return
	}
	hasMax, is64 = flag&1 != 0, flag&4 != 0
	read := func() (uint32, error) {
		if !is64 {
			return r.u32()
		}
		v, err := r.u64()
		if v > 0xffffffff {
			v = 0xffffffff
		}
		return uint32(v), err
	}
	if min, err = read(); err != nil {
		return
	}
	if hasMax {
		max, err = read()
	}
	return
}

// valtype skips a value type (number, vector or reference type, incl. typed references).
func (r *reader) valtype() error {
	c, err := r.byte()
	if err != nil {
		return err
	}
	switch c {
	case 0x7f, 0x7e, 0x7d, 0x7c, 0x7b, 0x70, 0x6f:
		return nil
	case 0x63, 0x64: // (ref null ht) / (ref ht): heap type as s33
		return r.sleb(5)
	}
	return fmt.Errorf("value type %#x", c)
}

// --- sections ------------------------------------------------------------------------------

func parseImports(r *reader, info *Info) error {
	n, err := r.count(4)
	if err != nil {
		return err
	}
	info.ImportCount = n
	if keep := min(n, KeepImports); keep > 0 {
		info.Imports = make([]Import, 0, keep)
	}
	for i := 0; i < n; i++ {
		if i >= MaxImports {
			info.Truncated = true
			return nil
		}
		mod, err := r.name()
		if err != nil {
			return fmt.Errorf("import %d module: %v", i, err)
		}
		name, err := r.name()
		if err != nil {
			return fmt.Errorf("import %d name: %v", i, err)
		}
		kind, err := r.byte()
		if err != nil {
			return err
		}
		switch kind {
		case 0:
			_, err = r.u32()
		case 1:
			if err = r.valtype(); err == nil {
				_, _, _, _, err = r.limits()
			}
		case 2:
			var min, max uint32
			var hasMax, is64 bool
			if min, max, hasMax, is64, err = r.limits(); err == nil && !info.HasMemory {
				info.HasMemory, info.MinPages, info.MaxPages, info.HasMax, info.Memory64 = true, min, max, hasMax, is64
			}
		case 3:
			if err = r.valtype(); err == nil {
				var m byte
				if m, err = r.byte(); err == nil && m > 1 {
					err = fmt.Errorf("global mutability %d", m)
				}
			}
		case 4:
			if _, err = r.byte(); err == nil {
				_, err = r.u32()
			}
		default:
			return fmt.Errorf("import %d kind %#x", i, kind)
		}
		if err != nil {
			return fmt.Errorf("import %d: %v", i, err)
		}
		if i < KeepImports {
			info.Imports = append(info.Imports, Import{string(mod), string(name), kinds[kind]})
		}
		if info.BadImport == "" && (kind != 0 || string(mod) != WASI) {
			info.BadImport = string(mod) + "." + string(name)
		}
	}
	if r.rem() != 0 {
		return errors.New("trailing bytes")
	}
	return nil
}

func parseFuncs(r *reader, info *Info) error {
	n, err := r.count(1)
	if err != nil {
		return err
	}
	info.Funcs = n
	if n > MaxFuncs {
		info.Truncated = true
	}
	return nil
}

func parseMemory(r *reader, info *Info) error {
	n, err := r.count(2)
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		min, max, hasMax, is64, err := r.limits()
		if err != nil {
			return fmt.Errorf("memory %d: %v", i, err)
		}
		if !info.HasMemory {
			info.HasMemory, info.MinPages, info.MaxPages, info.HasMax, info.Memory64 = true, min, max, hasMax, is64
		}
	}
	if r.rem() != 0 {
		return errors.New("trailing bytes")
	}
	return nil
}

func parseExports(r *reader, info *Info) error {
	n, err := r.count(3)
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		if i >= MaxExports {
			info.Truncated = true
			return nil
		}
		name, err := r.name()
		if err != nil {
			return fmt.Errorf("export %d: %v", i, err)
		}
		kind, err := r.byte()
		if err != nil {
			return err
		}
		if kind >= byte(len(kinds)) {
			return fmt.Errorf("export %d kind %#x", i, kind)
		}
		if _, err := r.u32(); err != nil {
			return fmt.Errorf("export %d: %v", i, err)
		}
		switch {
		case kind == 0 && string(name) == "_start":
			info.HasStart = true
		case kind == 2:
			info.ExportsMemory = true
		}
	}
	if r.rem() != 0 {
		return errors.New("trailing bytes")
	}
	return nil
}

// parseCustom reads the section name and, for "producers", its fields; other custom sections
// (name, go:buildid, target_features, …) are skipped. A malformed producers section is ignored.
func parseCustom(r *reader, info *Info) error {
	name, err := r.name()
	if err != nil {
		return fmt.Errorf("custom section name: %v", err)
	}
	if string(name) == "producers" && info.Producers == "" {
		info.Producers = producers(r)
	}
	return nil
}

// parseData walks the data segments (active or passive) and feeds their bytes to the string scan.
func parseData(r *reader, strs *stringScan) error {
	n, err := r.count(2)
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		flag, err := r.u32()
		if err != nil {
			return fmt.Errorf("data %d: %v", i, err)
		}
		switch flag {
		case 0:
			err = constExpr(r)
		case 1:
		case 2:
			if _, err = r.u32(); err == nil {
				err = constExpr(r)
			}
		default:
			return fmt.Errorf("data %d flag %d", i, flag)
		}
		if err != nil {
			return fmt.Errorf("data %d offset: %v", i, err)
		}
		size, err := r.u32()
		if err != nil {
			return fmt.Errorf("data %d: %v", i, err)
		}
		seg, err := r.take(size)
		if err != nil {
			return fmt.Errorf("data %d: %d bytes past end", i, size)
		}
		strs.feed(seg)
	}
	if r.rem() != 0 {
		return errors.New("trailing bytes")
	}
	return nil
}

// constExpr skips a constant expression (offset of an active segment) of at most 64 instructions.
func constExpr(r *reader) error {
	for i := 0; i < 64; i++ {
		op, err := r.byte()
		if err != nil {
			return err
		}
		switch op {
		case 0x0b:
			return nil
		case 0x41:
			err = r.sleb(5)
		case 0x42:
			err = r.sleb(10)
		case 0x43:
			_, err = r.take(4)
		case 0x44:
			_, err = r.take(8)
		case 0x23, 0xd2:
			_, err = r.u32()
		case 0xd0:
			_, err = r.byte()
		case 0x6a, 0x6b, 0x6c, 0x7c, 0x7d, 0x7e: // extended-const arithmetic
		case 0xfd:
			var sub uint32
			if sub, err = r.u32(); err == nil {
				if sub != 12 {
					return fmt.Errorf("vector opcode %d in const expr", sub)
				}
				_, err = r.take(16)
			}
		default:
			return fmt.Errorf("opcode %#x in const expr", op)
		}
		if err != nil {
			return err
		}
	}
	return errors.New("const expr too long")
}

// --- data-segment strings ------------------------------------------------------------------

// stringScan keeps the printable runs (>= MinString bytes of 0x20..0x7e) found in the first
// StringsBudget data-segment bytes: one copy per kept run, plus a carry buffer for the rare run
// that continues across segments. Segments are concatenated as the module lays them out.
type stringScan struct {
	out   []string
	carry []byte // bytes of the run in progress from earlier segments
	seen  int
}

func (s *stringScan) feed(seg []byte) {
	if s.seen >= StringsBudget || len(s.out) >= MaxStrings {
		return
	}
	if rest := StringsBudget - s.seen; len(seg) > rest {
		seg = seg[:rest]
	}
	s.seen += len(seg)
	start := 0
	for i, c := range seg {
		if c >= 0x20 && c <= 0x7e {
			continue
		}
		if i > start || len(s.carry) > 0 {
			s.end(seg[start:i])
		}
		start = i + 1
	}
	if start < len(seg) {
		s.carry = append(s.carry, seg[start:]...)
	}
}

// end closes the run whose last bytes are tail, preceded by whatever carry holds.
func (s *stringScan) end(tail []byte) {
	if len(s.carry)+len(tail) >= MinString && len(s.out) < MaxStrings {
		if len(s.carry) > 0 {
			tail = append(s.carry, tail...)
		}
		s.out = append(s.out, string(tail))
	}
	s.carry = s.carry[:0]
}

func (s *stringScan) strings() []string {
	s.end(nil)
	return s.out
}
