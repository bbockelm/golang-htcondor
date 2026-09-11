// Package spool fans one tar of input files out to the procs of an
// HTCondor cluster.
//
// HTCondor spools input per job, not per submission. A cluster submitted
// with `queue N` leaves N procs held on HoldReasonCode 16, and each needs
// its own spool before it will run. Both the MCP tool and the REST
// endpoints need to do that, with the same limits and the same accounting,
// which is why this is a package rather than a method.
//
// The tar has to be readable once per proc. That is the whole reason a
// Source exists: the single-proc paths hand the schedd a stream and never
// hold the bytes, but a fan-out cannot replay a stream, so the bytes have
// to live somewhere for the duration.
package spool

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

// Source yields the same tar as many times as asked.
//
// Implementations are not required to be cheap to open, only to give
// identical bytes each time: a proc that receives a short tar loses the
// files that were cut off, and the schedd accepts a short tar without
// complaint -- the proc leaves its hold and fails at run time on a
// missing file. Every Reader must therefore start at the beginning.
type Source interface {
	// Reader returns a fresh reader positioned at the start.
	Reader() (io.ReadCloser, error)
	// Size is the tar's length in bytes, for accounting and limits.
	Size() int64
	// Close releases whatever the source holds. Safe to call twice.
	Close() error
}

// --- in memory ---

// Bytes is a Source over a tar already in memory. Suitable where the
// payload is bounded by something upstream -- the MCP tool builds its tar
// from an already-parsed request body, so the tar cannot exceed the
// request that carried it.
type Bytes []byte

// Reader returns a reader over the bytes. Each call is independent.
func (b Bytes) Reader() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(b)), nil
}

// Size is the tar's length in bytes.
func (b Bytes) Size() int64 { return int64(len(b)) }

// Close is a no-op: nothing was allocated outside the slice.
func (b Bytes) Close() error { return nil }

// --- spilled to disk ---

// File is a Source backed by a file on disk, for a tar that arrived as a
// stream and is too large to hold in memory. The REST upload paths accept
// up to a gigabyte, which is not a []byte.
//
// The file is opened fresh per proc rather than shared and seeked: the
// readers are handed to concurrent uploads, and a shared *os.File has one
// offset between them, so two procs reading at once would each get part
// of the tar. That failure is silent for the same reason a short tar is.
type File struct {
	path string
	size int64
}

// Spill copies r into a new file under dir and returns a Source over it.
//
// dir empty means the system temp directory. A caller that knows better --
// a filesystem with room, or one that is not shared -- should say so;
// spilling a gigabyte into a small /tmp is a way to take the server down
// with it.
//
// limit caps what is copied. A stream longer than limit is an error rather
// than a truncation: a truncated tar spools cleanly and fails later on a
// missing file, which is the worst available outcome.
func Spill(r io.Reader, dir string, limit int64) (*File, error) {
	f, err := os.CreateTemp(dir, "htcondor-spool-*.tar")
	if err != nil {
		return nil, fmt.Errorf("creating a spool buffer: %w", err)
	}
	path := f.Name()

	// One past the limit, so hitting it is distinguishable from a stream
	// that happens to end exactly there.
	n, copyErr := io.Copy(f, io.LimitReader(r, limit+1))
	closeErr := f.Close()
	switch {
	case copyErr != nil:
		_ = os.Remove(path)
		return nil, fmt.Errorf("buffering the upload: %w", copyErr)
	case closeErr != nil:
		_ = os.Remove(path)
		return nil, fmt.Errorf("closing the spool buffer: %w", closeErr)
	case n > limit:
		_ = os.Remove(path)
		return nil, fmt.Errorf(
			"upload exceeds the %d byte limit for a cluster-wide spool; "+
				"use HTTP/HTTPS URLs in transfer_input_files instead", limit)
	}
	return &File{path: path, size: n}, nil
}

// Reader opens the buffer file afresh, so concurrent readers do not
// share a file offset. The caller closes it.
func (f *File) Reader() (io.ReadCloser, error) {
	fh, err := os.Open(f.path)
	if err != nil {
		return nil, fmt.Errorf("reopening the spool buffer: %w", err)
	}
	return fh, nil
}

// Size is the buffered tar's length in bytes.
func (f *File) Size() int64 { return f.size }

// Close removes the buffer file. It is safe to call twice, and a
// fan-out that returns early must still call it or the file leaks for
// as long as the process lives.
func (f *File) Close() error {
	if f.path == "" {
		return nil
	}
	path := f.path
	f.path = ""
	return os.Remove(path)
}
