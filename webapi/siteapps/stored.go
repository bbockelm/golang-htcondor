package siteapps

import (
	"io"
	"io/fs"
	"path"
	"strings"
	"time"
)

// storedFS serves zip entries that are STORED (uncompressed) directly
// out of the backing file, through io.SectionReader.
//
// This is why a bundle is normalized to STORED at load time. A deflated
// entry is not seekable and each Open restarts a flate stream, so
// http.ServeFileFS cannot answer a Range request from one and every
// fetch pays the decompression again. A stored entry is a byte range at
// a known offset: seeking is a seek, Range works, and the only memory
// involved is the copy buffer.
//
// Nothing here holds file contents. The whole archive stays on disk,
// in a file that has already been unlinked.
type storedFS struct {
	ra    io.ReaderAt
	files map[string]*storedInfo
	dirs  map[string]*storedInfo
}

type storedInfo struct {
	name    string // base name, for FileInfo
	offset  int64
	size    int64
	modTime time.Time
	dir     bool
}

func (i *storedInfo) Name() string { return i.name }
func (i *storedInfo) Size() int64 {
	if i.dir {
		return 0
	}
	return i.size
}
func (i *storedInfo) Mode() fs.FileMode {
	if i.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (i *storedInfo) ModTime() time.Time { return i.modTime }
func (i *storedInfo) IsDir() bool        { return i.dir }
func (i *storedInfo) Sys() any           { return nil }

// storedFile is one open entry: a section of the backing file.
//
// It implements io.Seeker as well as fs.File, which is the whole
// point -- net/http checks for exactly that before it will serve a
// Range request.
type storedFile struct {
	*io.SectionReader
	info *storedInfo
}

func (f *storedFile) Stat() (fs.FileInfo, error) { return f.info, nil }
func (f *storedFile) Close() error               { return nil }

// storedDir is an open directory. It exists so the SPA handler's
// dirExists check can distinguish a directory from a missing path
// while resolving dynamic routes.
type storedDir struct {
	info *storedInfo
}

func (d *storedDir) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *storedDir) Close() error               { return nil }
func (d *storedDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.info.name, Err: fs.ErrInvalid}
}

// Open implements fs.FS.
func (s *storedFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if info, ok := s.files[name]; ok {
		return &storedFile{
			SectionReader: io.NewSectionReader(s.ra, info.offset, info.size),
			info:          info,
		}, nil
	}
	if info, ok := s.dirs[name]; ok {
		return &storedDir{info: info}, nil
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

var _ fs.FS = (*storedFS)(nil)

// newStoredFS builds the filesystem for the entries under root,
// with that prefix stripped.
//
// Rooting at construction rather than wrapping in fs.Sub keeps one
// layer out of every request, and means the entries outside root --
// app.yaml -- are not merely hidden but absent from the map.
func newStoredFS(ra io.ReaderAt, entries []storedEntry, root string) *storedFS {
	s := &storedFS{
		ra:    ra,
		files: make(map[string]*storedInfo),
		dirs:  map[string]*storedInfo{".": {name: ".", dir: true}},
	}
	prefix := root + "/"
	for _, e := range entries {
		if !strings.HasPrefix(e.name, prefix) {
			continue
		}
		rel := strings.TrimPrefix(e.name, prefix)
		if rel == "" {
			continue
		}
		if e.isDir {
			s.addDir(strings.TrimSuffix(rel, "/"), e.modTime)
			continue
		}
		s.files[rel] = &storedInfo{
			name:    path.Base(rel),
			offset:  e.offset,
			size:    e.size,
			modTime: e.modTime,
		}
		// Synthesize the parents. A zip need not carry directory
		// entries at all, and the SPA handler's dynamic-route
		// resolution walks directories to decide whether a segment is
		// a literal or a [param] placeholder.
		s.addDir(path.Dir(rel), e.modTime)
	}
	return s
}

func (s *storedFS) addDir(dir string, modTime time.Time) {
	for dir != "." && dir != "/" && dir != "" {
		if _, ok := s.dirs[dir]; ok {
			return
		}
		s.dirs[dir] = &storedInfo{name: path.Base(dir), dir: true, modTime: modTime}
		dir = path.Dir(dir)
	}
}

// storedEntry is one entry's location in the backing file.
type storedEntry struct {
	name    string
	offset  int64
	size    int64
	modTime time.Time
	isDir   bool
}
