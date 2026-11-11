package siteapps

import (
	"archive/zip"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// tempPrefix names the scratch file a bundle is decompressed into.
//
// The leading dot is defensive, not cosmetic. The file lives in the
// operator's bundle directory and is unlinked immediately, but there is
// a window between create and unlink; a scan that caught it in that
// window must not try to load it as a bundle. Three things rule that
// out independently: the scanner skips names beginning with a dot, the
// extension is not .zip, and ValidateID would reject the id anyway.
const tempPrefix = ".siteapp-"

// tempSuffix keeps the scratch file out of the .zip namespace.
const tempSuffix = ".tmp"

// normalizeToStored returns a backing file whose zip entries are all
// STORED, so every entry can be served as a seekable section of it.
//
// When the bundle is already stored -- which is what `zip -0` and a
// reproducible build produce -- the original file is returned untouched
// and nothing is written.
//
// Otherwise the archive is rewritten, decompressed, into a scratch file
// in the SAME directory as the bundle. Same directory because it is the
// one place the operator has already provisioned for bundles: /tmp may
// be a small tmpfs, and a 512 MiB bundle has to land somewhere real.
//
// The scratch file is unlinked the moment it is created, so it has no
// name for anything to find and the kernel frees its blocks when the
// last descriptor closes. That makes cleanup a property of the process
// rather than a code path that has to run: a crash, a SIGKILL or a
// forgotten Close all end the same way. There is no reaper, no stale
// file after a restart, and nothing to tidy on shutdown.
func normalizeToStored(original *os.File, zr *zip.Reader, bundlePath string) (*os.File, *zip.Reader, error) {
	if allStored(zr) {
		return original, zr, nil
	}

	dir := filepath.Dir(bundlePath)
	scratch, err := createUnlinked(dir)
	if err != nil {
		return nil, nil, err
	}

	written, err := rewriteStored(scratch, zr)
	if err != nil {
		_ = scratch.Close()
		return nil, nil, err
	}

	stored, err := zip.NewReader(scratch, written)
	if err != nil {
		_ = scratch.Close()
		return nil, nil, fmt.Errorf("reread the decompressed bundle: %w", err)
	}
	// The original is no longer needed: everything is served from the
	// scratch copy. Closing it here means a redeployed bundle's old
	// file is released even while the old copy is still serving.
	_ = original.Close()
	return scratch, stored, nil
}

// allStored reports whether every entry can already be read as a plain
// byte range.
func allStored(zr *zip.Reader) bool {
	for _, f := range zr.File {
		if f.Method != zip.Store {
			return false
		}
	}
	return true
}

// createUnlinked makes a file in dir and immediately removes its name,
// returning the still-open descriptor.
func createUnlinked(dir string) (*os.File, error) {
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("name a scratch file: %w", err)
	}
	path := filepath.Join(dir, tempPrefix+hex.EncodeToString(nonce[:])+tempSuffix)

	// O_EXCL so this cannot open something another process put there,
	// and 0600 because for the moment it has a name.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create a scratch file in %s: %w", dir, err)
	}
	if err := os.Remove(path); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("unlink the scratch file %s: %w", path, err)
	}
	return f, nil
}

// rewriteStored copies every entry into w with no compression, and
// returns the number of bytes written.
func rewriteStored(w io.Writer, zr *zip.Reader) (int64, error) {
	counter := &countingWriter{w: w}
	zw := zip.NewWriter(counter)

	for _, entry := range zr.File {
		header := &zip.FileHeader{
			Name:     entry.Name,
			Method:   zip.Store,
			Modified: entry.Modified,
		}
		header.SetMode(entry.Mode())

		dst, err := zw.CreateHeader(header)
		if err != nil {
			return 0, fmt.Errorf("write entry %q: %w", entry.Name, err)
		}
		if strings.HasSuffix(entry.Name, "/") {
			continue // a directory entry has no data
		}

		src, err := entry.Open()
		if err != nil {
			return 0, fmt.Errorf("read entry %q: %w", entry.Name, err)
		}
		// Bounded by the entry's declared size plus one byte, so a
		// header that lies about how much it holds cannot make this
		// write until the disk fills.
		limit := int64(entry.UncompressedSize64) + 1
		n, err := io.Copy(dst, io.LimitReader(src, limit))
		_ = src.Close()
		if err != nil {
			return 0, fmt.Errorf("decompress entry %q: %w", entry.Name, err)
		}
		if n > int64(entry.UncompressedSize64) {
			return 0, fmt.Errorf("entry %q holds more data than its header declares", entry.Name)
		}
	}

	if err := zw.Close(); err != nil {
		return 0, fmt.Errorf("finish the decompressed bundle: %w", err)
	}
	return counter.n, nil
}

// countingWriter counts what passes through it, so the rewritten
// archive's size is known without a Stat on an unlinked file.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// collectEntries records where each entry's data lives in the backing
// file. Every entry must be STORED by this point.
func collectEntries(zr *zip.Reader) ([]storedEntry, error) {
	out := make([]storedEntry, 0, len(zr.File))
	for _, f := range zr.File {
		if f.Method != zip.Store {
			return nil, fmt.Errorf("entry %q is still compressed after normalization", f.Name)
		}
		isDir := strings.HasSuffix(f.Name, "/")
		var offset int64
		if !isDir {
			var err error
			offset, err = f.DataOffset()
			if err != nil {
				return nil, fmt.Errorf("locate entry %q: %w", f.Name, err)
			}
		}
		out = append(out, storedEntry{
			name:    f.Name,
			offset:  offset,
			size:    int64(f.UncompressedSize64),
			modTime: f.Modified,
			isDir:   isDir,
		})
	}
	return out, nil
}
