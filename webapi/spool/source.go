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
	"io"
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
