package zipscan

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
	"time"
)

// Epoch is the ModTime every entry reports: the sandbox's fake wall-clock origin.
var Epoch = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// Archive is a parsed, fs-usable zip blob that can be mounted any number of times; cxw keeps
// one per fs hash in its byte-budget LRU. The blob is read lazily and must not change afterwards.
type Archive struct {
	Info  Info
	b     []byte
	files map[string]*zip.File // clean name -> file entry
	dirs  map[string][]child   // clean dir name ("." for the root) -> sorted children
}

type child struct {
	name string    // base name
	file *zip.File // nil for a directory
}

// Open parses b, refuses an archive that is not fs-usable (the error names the reason) and
// indexes the entries so Stat and ReadDir never touch file data. Implied parent directories
// exist whether or not the archive lists them.
func Open(b []byte) (*Archive, error) {
	info, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if !info.OK {
		return nil, fmt.Errorf("zip: fs_unusable=%s", info.Reason)
	}
	r, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		return nil, err
	}
	if len(r.File) != info.Entries {
		return nil, fmt.Errorf("%w: archive/zip reads %d entries, the directory scan %d", ErrFormat, len(r.File), info.Entries)
	}
	a := &Archive{Info: info, b: b, files: make(map[string]*zip.File, info.Entries-info.Dirs), dirs: make(map[string][]child)}
	kids := map[string]map[string]*zip.File{".": {}}
	var addDir func(d string)
	addDir = func(d string) {
		if _, ok := kids[d]; ok {
			return
		}
		kids[d] = map[string]*zip.File{}
		parent, base := split(d)
		addDir(parent)
		kids[parent][base] = nil
	}
	for _, f := range r.File {
		name, isDir := strings.CutSuffix(f.Name, "/")
		if isDir {
			addDir(name)
			continue
		}
		parent, base := split(name)
		addDir(parent)
		kids[parent][base] = f
		a.files[name] = f
	}
	for d, m := range kids {
		cs := make([]child, 0, len(m))
		for n, f := range m {
			cs = append(cs, child{n, f})
		}
		slices.SortFunc(cs, func(x, y child) int { return strings.Compare(x.name, y.name) })
		a.dirs[d] = cs
	}
	return a, nil
}

func split(name string) (dir, base string) {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[:i], name[i+1:]
	}
	return ".", name
}

func join(dir, base string) string {
	if dir == "." {
		return base
	}
	return dir + "/" + base
}

// FS returns a read-only deterministic view of the archive: every Stat reports ModTime Epoch,
// Sys() nil and mode 0444 (files) or ModeDir|0555 (directories); ReadDir is sorted by name;
// hook, when not nil, receives the length of every content read, bytes skipped by Seek
// included, so the sandbox can enforce its per-run read cap. Metadata calls are not counted.
func (a *Archive) FS(hook func(n int)) fs.FS { return &mount{a, hook} }

// FS is Open followed by Archive.FS for callers that mount once.
func FS(b []byte, hook func(n int)) (fs.FS, error) {
	a, err := Open(b)
	if err != nil {
		return nil, err
	}
	return a.FS(hook), nil
}

type mount struct {
	a    *Archive
	hook func(int)
}

func (m *mount) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if f, ok := m.a.files[name]; ok {
		return m.open(name, f)
	}
	if kids, ok := m.a.dirs[name]; ok {
		return &dir{info: dirInfo(name), kids: kids, path: name}, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// Stat answers from the index, without opening a decompressor.
func (m *mount) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	if f, ok := m.a.files[name]; ok {
		return fileInfo(name, f), nil
	}
	if _, ok := m.a.dirs[name]; ok {
		return dirInfo(name), nil
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}

func (m *mount) ReadDir(name string) ([]fs.DirEntry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	kids, ok := m.a.dirs[name]
	if !ok {
		err := fs.ErrNotExist
		if _, isFile := m.a.files[name]; isFile {
			err = errors.New("not a directory")
		}
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	return entries(name, kids), nil
}

func entries(dir string, kids []child) []fs.DirEntry {
	out := make([]fs.DirEntry, len(kids))
	for i, c := range kids {
		if c.file == nil {
			out[i] = dirInfo(join(dir, c.name))
		} else {
			out[i] = fileInfo(join(dir, c.name), c.file)
		}
	}
	return out
}

// open serves a stored entry straight from the blob (seekable, ReadAt) and streams anything
// else through archive/zip's checksumming reader.
func (m *mount) open(name string, f *zip.File) (fs.File, error) {
	fi := fileInfo(name, f)
	if f.Method == zip.Store && f.CompressedSize64 == f.UncompressedSize64 {
		off, err := f.DataOffset()
		if err != nil {
			return nil, &fs.PathError{Op: "open", Path: name, Err: err}
		}
		if off < 0 || uint64(off)+f.CompressedSize64 > uint64(len(m.a.b)) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: zip.ErrFormat}
		}
		return &stored{r: io.NewSectionReader(bytes.NewReader(m.a.b), off, int64(f.CompressedSize64)), info: fi, hook: m.hook}, nil
	}
	rc, err := f.Open()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &streamed{f: f, rc: rc, size: int64(f.UncompressedSize64), info: fi, hook: m.hook}, nil
}

// --- file infos ------------------------------------------------------------------------------

// info is both the fs.FileInfo and the fs.DirEntry of an entry: a name, a size and a kind.
type info struct {
	name string
	size int64
	dir  bool
}

func fileInfo(name string, f *zip.File) info {
	_, base := split(name)
	return info{name: base, size: int64(f.UncompressedSize64)}
}

func dirInfo(name string) info {
	if name == "." {
		return info{name: ".", dir: true}
	}
	_, base := split(name)
	return info{name: base, dir: true}
}

func (i info) Name() string { return i.name }
func (i info) Size() int64  { return i.size }
func (i info) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (i info) ModTime() time.Time         { return Epoch }
func (i info) IsDir() bool                { return i.dir }
func (i info) Sys() any                   { return nil }
func (i info) Type() fs.FileMode          { return i.Mode().Type() }
func (i info) Info() (fs.FileInfo, error) { return i, nil }
func (i info) String() string             { return fs.FormatFileInfo(i) }

// --- open files ------------------------------------------------------------------------------

func count(hook func(int), n int) {
	if hook != nil && n > 0 {
		hook(n)
	}
}

// stored is a method-0 entry: a section of the blob.
type stored struct {
	r    *io.SectionReader
	info info
	hook func(int)
}

func (s *stored) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	count(s.hook, n)
	return n, err
}

func (s *stored) ReadAt(p []byte, off int64) (int, error) {
	n, err := s.r.ReadAt(p, off)
	count(s.hook, n)
	return n, err
}

func (s *stored) Seek(off int64, whence int) (int64, error) { return s.r.Seek(off, whence) }
func (s *stored) Stat() (fs.FileInfo, error)                { return s.info, nil }
func (s *stored) Close() error                              { return nil }

// streamed is a compressed entry read through archive/zip. Seek is supported the only way a
// stream allows: forward by discarding (counted), backward by reopening and discarding.
type streamed struct {
	f         *zip.File
	rc        io.ReadCloser
	pos, size int64
	info      info
	hook      func(int)
}

func (s *streamed) Read(p []byte) (int, error) {
	if s.rc == nil {
		return 0, &fs.PathError{Op: "read", Path: s.f.Name, Err: fs.ErrClosed}
	}
	if s.pos >= s.size {
		return 0, io.EOF
	}
	n, err := s.rc.Read(p)
	s.pos += int64(n)
	count(s.hook, n)
	return n, err
}

func (s *streamed) Seek(off int64, whence int) (int64, error) {
	if s.rc == nil {
		return 0, &fs.PathError{Op: "seek", Path: s.f.Name, Err: fs.ErrClosed}
	}
	var target int64
	switch whence {
	case io.SeekStart:
		target = off
	case io.SeekCurrent:
		target = s.pos + off
	case io.SeekEnd:
		target = s.size + off
	default:
		return 0, &fs.PathError{Op: "seek", Path: s.f.Name, Err: fs.ErrInvalid}
	}
	if target < 0 {
		return 0, &fs.PathError{Op: "seek", Path: s.f.Name, Err: fs.ErrInvalid}
	}
	if target < s.pos {
		s.rc.Close()
		rc, err := s.f.Open()
		if err != nil {
			s.rc = nil
			return 0, &fs.PathError{Op: "seek", Path: s.f.Name, Err: err}
		}
		s.rc, s.pos = rc, 0
	}
	if skip := min(target, s.size) - s.pos; skip > 0 {
		n, err := io.CopyN(io.Discard, s.rc, skip)
		s.pos += n
		count(s.hook, int(n))
		if err != nil && err != io.EOF {
			return s.pos, &fs.PathError{Op: "seek", Path: s.f.Name, Err: err}
		}
	}
	s.pos = target
	return target, nil
}

func (s *streamed) Stat() (fs.FileInfo, error) { return s.info, nil }

func (s *streamed) Close() error {
	if s.rc == nil {
		return nil
	}
	err := s.rc.Close()
	s.rc = nil
	return err
}

// dir is an open directory: a cursor over its sorted children.
type dir struct {
	info info
	kids []child
	path string
	off  int
}

func (d *dir) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *dir) Close() error               { return nil }

func (d *dir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.path, Err: errors.New("is a directory")}
}

func (d *dir) ReadDir(n int) ([]fs.DirEntry, error) {
	rest := d.kids[d.off:]
	if n > 0 {
		if len(rest) == 0 {
			return nil, io.EOF
		}
		rest = rest[:min(n, len(rest))]
	}
	d.off += len(rest)
	return entries(d.path, rest), nil
}
