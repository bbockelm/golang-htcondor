//go:build !unix

package spool

import (
	"errors"
	"os"
)

// Platforms without mmap read the buffer through the file descriptor.
// growingReader falls back on the first mapping failure, so returning an
// error here is the whole implementation.

var errShortWindow = errors.New("spool: no mappable window yet")

type mapping struct{}

func (mapping) valid() bool   { return false }
func (mapping) bytes() []byte { return nil }
func (mapping) unmap() error  { return nil }

func mmapRegion(*os.File, int64, int) (mapping, error) {
	return mapping{}, errors.New("spool: mmap is not available on this platform")
}

func pageAlign(off int64) int64 { return off }
