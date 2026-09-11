//go:build unix

package spool

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var errShortWindow = errors.New("spool: no mappable window yet")

// mapping is one mmap'd region.
type mapping struct{ b []byte }

func (m mapping) valid() bool   { return m.b != nil }
func (m mapping) bytes() []byte { return m.b }
func (m mapping) unmap() error  { return unix.Munmap(m.b) }

// mmapRegion maps length bytes at offset, which must be page-aligned.
func mmapRegion(f *os.File, offset int64, length int) (mapping, error) {
	// G115: a file descriptor is a small non-negative integer on every
	// platform this builds for; unix.Mmap takes an int and os.File
	// hands out a uintptr.
	b, err := unix.Mmap(int(f.Fd()), offset, length, unix.PROT_READ, unix.MAP_SHARED) //nolint:gosec // G115: fds fit in an int
	if err != nil {
		return mapping{}, err
	}
	// The reader walks the window front to back exactly once.
	_ = unix.Madvise(b, unix.MADV_SEQUENTIAL)
	return mapping{b: b}, nil
}

func pageAlign(off int64) int64 {
	page := int64(os.Getpagesize())
	return off - off%page
}
