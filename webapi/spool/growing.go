package spool

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// ErrClosed is what readers get when the buffer is closed or aborted
// before the upload finished. It is an error rather than io.EOF on
// purpose: the schedd accepts a short tar without complaint, so a reader
// that stopped early must never look like one that reached the end.
var ErrClosed = errors.New("spool: buffer closed before the upload finished")

// growChunk is how much of the incoming stream one write covers. Small
// enough that a reader starts working on the first chunk while the rest
// is still arriving, large enough that the per-write bookkeeping is
// noise.
const growChunk = 1 << 20 // 1 MiB

// maxIdleReads bounds consecutive zero-byte, no-error reads before Fill
// calls the upload stalled. io.ReadAll uses a similar guard.
const maxIdleReads = 100

// Growing is a Source whose bytes are still arriving.
//
// Spill buffers the whole tar before the first proc is spooled, which
// costs a full receive before any upload starts -- on a slow client the
// schedd sits idle for the entire upload and then does N of them. A
// Growing buffer inverts that: Fill appends to a file while readers
// consume what has landed and block for the rest, so receiving and
// spooling overlap and the wall clock is the slower of the two rather
// than their sum.
//
// Readers see a consistent prefix and never a short read at the end:
// Read blocks until more bytes arrive, Fill reports EOF, or Fill fails,
// and a failure is returned to every reader as an error. That last part
// is what keeps a half-spooled proc from looking like a finished one --
// the schedd accepts a truncated tar without complaint, so a reader that
// quietly stopped early would release a proc whose files are missing.
type Growing struct {
	path  string
	w     *os.File
	limit int64

	mu   sync.Mutex
	cond *sync.Cond
	n    int64 // bytes written and visible to readers
	done bool  // Fill finished, successfully or not
	err  error // Fill's failure, returned to every reader
}

// NewGrowing creates the buffer file in dir (empty selects the system
// temp directory) and refuses more than limit bytes.
func NewGrowing(dir string, limit int64) (*Growing, error) {
	f, err := os.CreateTemp(dir, "htcondor-spool-*.tar")
	if err != nil {
		return nil, fmt.Errorf("creating a spool buffer: %w", err)
	}
	g := &Growing{path: f.Name(), w: f, limit: limit}
	g.cond = sync.NewCond(&g.mu)
	return g, nil
}

// Fill copies r into the buffer, publishing each chunk as it lands. It
// returns when the stream ends, or with an error if the stream fails or
// exceeds the limit. Callers must call it exactly once.
//
// A refusal is deliberate rather than a truncation: a short tar spools
// cleanly and leaves the job missing files at run time.
func (g *Growing) Fill(r io.Reader) error {
	buf := make([]byte, growChunk)
	var total int64
	// io.Reader permits an occasional (0, nil). A reader that returns
	// it forever would otherwise spin here at full tilt with every
	// proc's reader blocked behind it.
	idle := 0

	for {
		nr, readErr := r.Read(buf)
		if nr == 0 && readErr == nil {
			idle++
			if idle > maxIdleReads {
				return g.fail(fmt.Errorf(
					"the upload stopped making progress after %d bytes", total))
			}
			continue
		}
		idle = 0
		if nr > 0 {
			if total+int64(nr) > g.limit {
				return g.fail(fmt.Errorf(
					"upload exceeds the %d byte limit for a cluster-wide spool; "+
						"use HTTP/HTTPS URLs in transfer_input_files instead", g.limit))
			}
			if _, werr := g.w.Write(buf[:nr]); werr != nil {
				return g.fail(fmt.Errorf("buffering the upload: %w", werr))
			}
			total += int64(nr)

			// Publish only what is durable enough for a reader to
			// read back: the write above went through the file
			// descriptor, so a reader with its own descriptor sees it.
			g.mu.Lock()
			g.n = total
			g.cond.Broadcast()
			g.mu.Unlock()
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return g.fail(fmt.Errorf("buffering the upload: %w", readErr))
		}
	}

	if err := g.w.Sync(); err != nil {
		return g.fail(fmt.Errorf("flushing the spool buffer: %w", err))
	}

	g.mu.Lock()
	g.done = true
	g.cond.Broadcast()
	g.mu.Unlock()
	return nil
}

// fail records err, wakes every blocked reader, and returns it.
func (g *Growing) fail(err error) error {
	g.mu.Lock()
	g.err = err
	g.done = true
	g.cond.Broadcast()
	g.mu.Unlock()
	return err
}

// Size is how many bytes have been published. It is the final size only
// once Fill has returned; the fan-out does not need it, and Plan is told
// the ceiling up front instead -- see PlanStreaming.
func (g *Growing) Size() int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n
}

// Close removes the buffer file and releases anyone still reading.
// Safe to call twice.
//
// Waking the readers is not optional: they park on a condition variable
// that only Fill signals, so a Close while one is blocked -- Fill
// abandoned, a caller unwinding early, a future caller that does not
// happen to close in the order this package's own does -- left that
// goroutine parked for the life of the process.
func (g *Growing) Close() error {
	g.mu.Lock()
	path := g.path
	g.path = ""
	if !g.done {
		g.done = true
		if g.err == nil {
			g.err = ErrClosed
		}
	}
	g.cond.Broadcast()
	g.mu.Unlock()
	if path == "" {
		return nil
	}
	_ = g.w.Close()
	return os.Remove(path)
}

// Abort fails the buffer early, waking every reader with err.
//
// The fan-out's readers block in Read with no context of their own, so
// this is how a cancelled request or a caller that has given up gets
// them to stop rather than waiting out the upload.
func (g *Growing) Abort(err error) {
	if err == nil {
		err = ErrClosed
	}
	g.mu.Lock()
	if g.err == nil {
		g.err = err
	}
	g.done = true
	g.cond.Broadcast()
	g.mu.Unlock()
}

// wait blocks until there are bytes past off, the stream ended, or it
// failed. It returns the visible watermark and whether the stream is
// complete.
func (g *Growing) wait(off int64) (int64, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for {
		if g.n > off {
			return g.n, g.done, g.err
		}
		if g.err != nil {
			return g.n, true, g.err
		}
		if g.done {
			return g.n, true, nil
		}
		g.cond.Wait()
	}
}

// Reader returns an independent reader over the buffer, usable before
// Fill has finished.
func (g *Growing) Reader() (io.ReadCloser, error) {
	g.mu.Lock()
	path := g.path
	g.mu.Unlock()
	if path == "" {
		return nil, errors.New("the spool buffer is closed")
	}
	// The path is one NewGrowing made with os.CreateTemp; it is never
	// caller-supplied.
	f, err := os.Open(path) //nolint:gosec // G304: our own temp file, not a caller-supplied path
	if err != nil {
		return nil, fmt.Errorf("opening the spool buffer: %w", err)
	}
	return newGrowingReader(g, f), nil
}
