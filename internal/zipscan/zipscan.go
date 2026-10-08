// Package zipscan reads the end-of-central-directory record and the central directory of a zip
// blob (SPEC-v2 27.6) and decides whether it can serve as a job's read-only filesystem. Parse
// never inflates anything and is O(entries): every length is checked against the blob before it
// is used and the only allocations are the kept names and a dedupe table smaller than the
// directory. Open/FS (fs.go) mount a usable archive as the deterministic read-only fs.FS the
// sandbox exposes to a job.
//
// Parse is at least as strict as archive/zip: the directory must end exactly where the end
// record begins (no prefix, no slack), disk numbers must be zero and every entry's data must lie
// before the directory. An archive Parse accepts is therefore read by archive/zip with exactly
// the entries Parse counted, which Open checks.
package zipscan

import (
	"bytes"
	"errors"
	"fmt"
	"hash/maphash"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	MaxEntries  = 20000     // central directory records a usable filesystem may hold
	MaxUnpacked = 64 << 20  // cap on the sum of the declared uncompressed sizes
	KeepNames   = 64        // names kept in Info.Names
	KeepUnsafe  = 16        // names kept in Info.Unsafe
	endWindow   = 65 * 1024 // archive/zip looks for the end record in the last 65 KiB
)

// Reasons an archive is fs_unusable (Info.Reason). An unsupported compression method renders as
// "unsupported-method-<n>".
const (
	ReasonEntries   = "entries>20000"
	ReasonUnpacked  = "unpacked>64MiB"
	ReasonUnsafe    = "unsafe-names"
	ReasonDuplicate = "duplicate-names"
	ReasonEncrypted = "encrypted"
	ReasonSymlinks  = "symlinks"
	ReasonSpecial   = "special-files"
	reasonNotZip    = "not-a-zip"
	reasonMalformed = "malformed"
)

var (
	ErrNotZip = errors.New("zip: no end-of-central-directory record")
	ErrFormat = errors.New("zip: malformed central directory")
)

const (
	sigHeader = 0x02014b50 // central directory header
	sigEnd    = 0x06054b50 // end of central directory
	sigLoc64  = 0x07064b50 // zip64 end locator
	sigEnd64  = 0x06064b50 // zip64 end record
	headerLen = 46
	endLen    = 22
	loc64Len  = 20
	end64Len  = 56
	max16     = 0xffff
	max32     = 0xffffffff
)

// Info is what Parse learns from the central directory. Names are raw as declared (consumers
// sanitize at output); Line never prints them.
type Info struct {
	Size        int
	Entries     int      // central directory records, directories included
	Dirs        int      // records whose name ends in '/'
	Unpacked    uint64   // sum of the declared uncompressed sizes (saturating)
	Names       []string // the first KeepNames names
	Unsafe      []string // the first KeepUnsafe refused names
	UnsafeCount int
	Zip64       bool   // zip64 end record or extra fields were used
	OK          bool   // usable as a job filesystem
	Reason      string // why not: one token, also set when Parse fails so Line still renders
}

// IsZip reports whether b starts like a zip: a local file header or an empty archive's end record.
func IsZip(b []byte) bool {
	return len(b) >= 4 && b[0] == 'P' && b[1] == 'K' && (b[2] == 3 && b[3] == 4 || b[2] == 5 && b[3] == 6)
}

// Parse scans the end record and the central directory of b. Structural faults (no end record,
// a directory outside the blob, a bad header, entry data past the directory) are errors;
// policy refusals (caps, unsafe or duplicate names, encryption, unsupported methods, special
// files) leave err nil with OK false and Reason set.
func Parse(b []byte) (Info, error) {
	info := Info{Size: len(b), Reason: reasonNotZip}
	if uint64(len(b)) >= 1<<32 {
		return info, fmt.Errorf("zip: %d bytes: blob too large", len(b))
	}
	end, err := findEnd(b)
	if err != nil {
		if !errors.Is(err, ErrNotZip) {
			info.Reason = reasonMalformed
		}
		return info, err
	}
	info.Reason = reasonMalformed
	info.Zip64 = end.zip64
	if keep := min(end.records, KeepNames); keep > 0 {
		info.Names = make([]string, 0, keep)
	}
	dirStart, dirEnd := int(end.dirOffset), end.endOffset
	var unpacked uint64
	var encrypted, symlink, special bool
	var badMethod uint16
	for pos := dirStart; pos < dirEnd; {
		h, err := readHeader(b, pos, dirEnd)
		if err != nil {
			return info, fmt.Errorf("%w: entry %d at %d: %v", ErrFormat, info.Entries, pos, err)
		}
		if h.off > end.dirOffset || h.csize > end.dirOffset-h.off || end.dirOffset-h.off-h.csize < 30 {
			return info, fmt.Errorf("%w: entry %d: data at %d+%d past the directory", ErrFormat, info.Entries, h.off, h.csize)
		}
		info.Entries++
		info.Zip64 = info.Zip64 || h.zip64
		if unpacked+h.usize < unpacked {
			unpacked = math.MaxUint64
		} else {
			unpacked += h.usize
		}
		isDir := len(h.name) > 0 && h.name[len(h.name)-1] == '/'
		if isDir {
			info.Dirs++
		}
		if len(info.Names) < KeepNames {
			info.Names = append(info.Names, string(h.name))
		}
		if !safeName(h.name) {
			info.UnsafeCount++
			if len(info.Unsafe) < KeepUnsafe {
				info.Unsafe = append(info.Unsafe, string(h.name))
			}
		}
		if h.flags&1 != 0 {
			encrypted = true
		}
		if h.method != 0 && h.method != 8 && badMethod == 0 {
			badMethod = h.method
		}
		if c := h.creator >> 8; c == 3 || c == 19 { // Unix, macOS: the external attributes hold st_mode
			switch typ := h.attrs >> 16 & 0o170000; {
			case typ == 0 || typ == 0o100000 || typ == 0o040000 && isDir:
			case typ == 0o120000:
				symlink = true
			default:
				special = true
			}
		}
		pos += h.size
	}
	if end.zip64 && info.Entries != end.records || !end.zip64 && uint16(info.Entries) != uint16(end.records) {
		return info, fmt.Errorf("%w: %d entries, end record says %d", ErrFormat, info.Entries, end.records)
	}
	info.Unpacked = unpacked
	switch {
	case info.Entries > MaxEntries:
		info.Reason = ReasonEntries
	case unpacked > MaxUnpacked:
		info.Reason = ReasonUnpacked
	case info.UnsafeCount > 0:
		info.Reason = ReasonUnsafe
	case encrypted:
		info.Reason = ReasonEncrypted
	case badMethod != 0:
		info.Reason = "unsupported-method-" + strconv.Itoa(int(badMethod))
	case symlink:
		info.Reason = ReasonSymlinks
	case special:
		info.Reason = ReasonSpecial
	case duplicates(b, dirStart, dirEnd, info.Entries):
		info.Reason = ReasonDuplicate
	default:
		info.Reason, info.OK = "", true
	}
	return info, nil
}

// Line renders the binfo summary: "zip entries=812 unpacked=5.1MiB fs_ok=1" or
// "zip entries=25 unpacked=100.0GiB fs_unusable=unpacked>64MiB". Always one line of k=v tokens.
func (i Info) Line() string {
	var b strings.Builder
	b.WriteString("zip entries=")
	b.WriteString(strconv.Itoa(i.Entries))
	b.WriteString(" unpacked=")
	b.WriteString(human(i.Unpacked))
	if i.OK {
		b.WriteString(" fs_ok=1")
	} else {
		b.WriteString(" fs_unusable=")
		if i.Reason == "" {
			b.WriteString("unknown")
		} else {
			b.WriteString(i.Reason)
		}
	}
	return b.String()
}

// human renders n as 812B, 1.0KiB, 5.1MiB, 100.0GiB (binary units up to EiB).
func human(n uint64) string {
	if n < 1024 {
		return strconv.FormatUint(n, 10) + "B"
	}
	const units = "KMGTPE"
	d, i := uint64(1024), 0
	for n/1024 >= d && i < len(units)-1 {
		d *= 1024
		i++
	}
	return strconv.FormatFloat(float64(n)/float64(d), 'f', 1, 64) + string(units[i]) + "iB"
}

// --- end record ------------------------------------------------------------------------------

type endRec struct {
	records   int    // central directory records (uint16, or uint64 from the zip64 record)
	dirSize   uint64 // bytes of central directory
	dirOffset uint64 // where it starts
	endOffset int    // where it must end: the zip64 end record, else the end record
	zip64     bool
}

// findEnd locates the end record the way archive/zip does (last signature within 65 KiB whose
// comment fits), follows the zip64 locator when the 32-bit fields are maxed, and requires the
// directory to end exactly where the end record begins.
func findEnd(b []byte) (endRec, error) {
	var e endRec
	if len(b) < endLen {
		return e, ErrNotZip
	}
	p := -1
	for i, stop := len(b)-endLen, max(0, len(b)-endWindow); i >= stop; i-- {
		if b[i] == 'P' && b[i+1] == 'K' && b[i+2] == 5 && b[i+3] == 6 {
			if n := int(le16(b[i+20:])); i+endLen+n > len(b) {
				return e, ErrNotZip // truncated comment: archive/zip gives up too
			}
			p = i
			break
		}
	}
	if p < 0 {
		return e, ErrNotZip
	}
	r := b[p+4:]
	if le16(r) != 0 || le16(r[2:]) != 0 {
		return e, fmt.Errorf("%w: multi-disk archive", ErrFormat)
	}
	records := le16(r[6:]) // the this-disk count at r[4:] is ignored, as archive/zip does
	e.dirSize, e.dirOffset, e.endOffset = uint64(le32(r[8:])), uint64(le32(r[12:])), p
	e.records = int(records)
	if records == max16 || e.dirSize == max32 || e.dirOffset == max32 {
		loc := p - loc64Len
		if loc < 0 || le32(b[loc:]) != sigLoc64 || le32(b[loc+4:]) != 0 || le32(b[loc+16:]) != 1 {
			return e, fmt.Errorf("%w: zip64 end locator missing", ErrFormat)
		}
		z := le64(b[loc+8:])
		if z > uint64(loc) || uint64(loc)-z < end64Len {
			return e, fmt.Errorf("%w: zip64 end record at %d out of range", ErrFormat, z)
		}
		zr := b[z:loc]
		if le32(zr) != sigEnd64 {
			return e, fmt.Errorf("%w: zip64 end record signature", ErrFormat)
		}
		if le32(zr[16:]) != 0 || le32(zr[20:]) != 0 {
			return e, fmt.Errorf("%w: multi-disk zip64 archive", ErrFormat)
		}
		n := le64(zr[32:])
		if n > uint64(len(b))/headerLen {
			return e, fmt.Errorf("%w: zip64 end record says %d entries", ErrFormat, n)
		}
		e.records, e.dirSize, e.dirOffset = int(n), le64(zr[40:]), le64(zr[48:])
		e.endOffset, e.zip64 = int(z), true
	}
	if e.dirOffset > uint64(e.endOffset) || e.dirSize != uint64(e.endOffset)-e.dirOffset {
		return e, fmt.Errorf("%w: directory %d+%d does not end at the end record (%d)", ErrFormat, e.dirOffset, e.dirSize, e.endOffset)
	}
	return e, nil
}

// --- central directory header ----------------------------------------------------------------

type header struct {
	flags, method, creator uint16
	attrs                  uint32 // external attributes
	csize, usize, off      uint64
	name                   []byte // a view into the blob
	zip64                  bool
	size                   int // record length including name, extra and comment
}

// readHeader decodes the record at pos, which must end by end. The zip64 extra is applied with
// archive/zip's rules: only to fields holding 0xffffffff, each needing 8 bytes.
func readHeader(b []byte, pos, end int) (header, error) {
	var h header
	r := b[pos:end]
	if len(r) < headerLen {
		return h, errors.New("truncated header")
	}
	if le32(r) != sigHeader {
		return h, errors.New("bad header signature")
	}
	h.creator, h.flags, h.method = le16(r[4:]), le16(r[8:]), le16(r[10:])
	csize, usize := le32(r[20:]), le32(r[24:])
	nameLen, extraLen, commentLen := int(le16(r[28:])), int(le16(r[30:])), int(le16(r[32:]))
	h.attrs = le32(r[38:])
	off := le32(r[42:])
	h.size = headerLen + nameLen + extraLen + commentLen
	if h.size > len(r) {
		return h, errors.New("name, extra or comment past the directory end")
	}
	h.name = r[headerLen : headerLen+nameLen]
	h.csize, h.usize, h.off = uint64(csize), uint64(usize), uint64(off)
	for extra := r[headerLen+nameLen : headerLen+nameLen+extraLen]; len(extra) >= 4; {
		tag, n := le16(extra), int(le16(extra[2:]))
		extra = extra[4:]
		if len(extra) < n {
			break
		}
		field := extra[:n]
		extra = extra[n:]
		if tag != 1 {
			continue
		}
		h.zip64 = true
		for _, f := range [...]struct {
			maxed bool
			dst   *uint64
		}{{usize == max32, &h.usize}, {csize == max32, &h.csize}, {off == max32, &h.off}} {
			if !f.maxed {
				continue
			}
			if len(field) < 8 {
				return h, errors.New("short zip64 extra field")
			}
			*f.dst = le64(field)
			field = field[8:]
		}
	}
	return h, nil
}

// safeName accepts a non-empty UTF-8 slash-separated name with no NUL or backslash, not rooted,
// with no empty, "." or ".." element; a single trailing '/' marks a directory. Such a name is
// its own path.Clean and passes fs.ValidPath, so fs.FS lookups are exact and archive/zip never
// rewrites it.
func safeName(n []byte) bool {
	if len(n) == 0 || n[0] == '/' || !utf8.Valid(n) {
		return false
	}
	if n[len(n)-1] == '/' {
		n = n[:len(n)-1]
	}
	start := 0
	for i := 0; i <= len(n); i++ {
		if i < len(n) && n[i] != '/' {
			if n[i] == 0 || n[i] == '\\' {
				return false
			}
			continue
		}
		if seg := n[start:i]; len(seg) == 0 || string(seg) == "." || string(seg) == ".." {
			return false
		}
		start = i + 1
	}
	return true
}

// --- duplicates ------------------------------------------------------------------------------

var seed = maphash.MakeSeed()

// duplicates reports whether two records share a name (directory slash trimmed) or a file is
// named like a directory another entry lives in: archive/zip breaks ReadDir on both. It runs
// only on directories that passed every other check, over an open-addressing table of record
// offsets (4 bytes per slot, under two slots per record) keyed by a seeded hash.
func duplicates(b []byte, start, end, n int) bool {
	if n < 2 {
		return false
	}
	size := 1
	for size < 2*n {
		size <<= 1
	}
	tab, mask := make([]uint32, size), uint32(size-1)
	nameAt := func(rec int) []byte { // trimmed name of the record at rec
		nl := int(le16(b[rec+28:]))
		nm := b[rec+headerLen : rec+headerLen+nl]
		if nl > 0 && nm[nl-1] == '/' {
			nm = nm[:nl-1]
		}
		return nm
	}
	recLen := func(rec int) int {
		return headerLen + int(le16(b[rec+28:])) + int(le16(b[rec+30:])) + int(le16(b[rec+32:]))
	}
	lookup := func(name []byte) (slot uint32, rec int, found bool) {
		for i := uint32(maphash.Bytes(seed, name)) & mask; ; i = (i + 1) & mask {
			if tab[i] == 0 {
				return i, 0, false
			}
			if r := int(tab[i] - 1); bytes.Equal(nameAt(r), name) {
				return i, r, true
			}
		}
	}
	isDirRec := func(rec int) bool {
		nl := int(le16(b[rec+28:]))
		return nl > 0 && b[rec+headerLen+nl-1] == '/'
	}
	for rec := start; rec < end; rec += recLen(rec) {
		slot, _, found := lookup(nameAt(rec))
		if found {
			return true
		}
		tab[slot] = uint32(rec) + 1
	}
	for rec := start; rec < end; rec += recLen(rec) {
		name := nameAt(rec)
		for k := len(name) - 1; k > 0; k-- {
			if name[k] != '/' {
				continue
			}
			if _, r, found := lookup(name[:k]); found && !isDirRec(r) {
				return true
			}
		}
	}
	return false
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func le32(b []byte) uint32 { return uint32(le16(b)) | uint32(le16(b[2:]))<<16 }
func le64(b []byte) uint64 { return uint64(le32(b)) | uint64(le32(b[4:]))<<32 }
