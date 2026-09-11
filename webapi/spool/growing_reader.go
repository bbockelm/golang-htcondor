package spool

import (
	"io"
	"os"
	"sync"
)

// growingReader reads a Growing buffer, blocking where the data has not
// arrived yet.
//
// It reads with ReadAt, which is a pread: no shared offset, so every
// proc's reader is independent, and no mapping, so closing a reader
// while another goroutine is mid-Read cannot fault.
//
// An earlier version mapped the file in 8 MiB windows on the theory
// that N readers of one buffer should share pages rather than copy
// them. Measured against the read size the schedd upload actually uses
// -- filetransfer.defaultBufferSize, 256 KiB -- that was 2.8x SLOWER
// (28.5ms vs 10.1ms for 64 MiB across 10 readers). mmap only won at
// 8 KiB reads, which was an artifact of the benchmark: io.Copy to
// io.Discard reads in 8 KiB chunks, so it was measuring syscall count
// at a size nothing in the product uses. The pages are in the page
// cache either way; at 256 KiB a pread costs one syscall per 32 pages
// and beats the mapping's per-page minor faults.
type growingReader struct {
	g   *Growing
	off int64

	mu sync.Mutex
	f  *os.File // nil once closed
}

func newGrowingReader(g *Growing, f *os.File) *growingReader {
	return &growingReader{g: g, f: f}
}

func (r *growingReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	watermark, done, err := r.g.wait(r.off)
	if r.off >= watermark {
		// Nothing more is coming. An error wins over EOF: a short read
		// reported as a clean end is how a proc ends up spooled with
		// files missing.
		if err != nil {
			return 0, err
		}
		if done {
			return 0, io.EOF
		}
		// wait only returns with no bytes when the stream is done or
		// failed, so this is unreachable; report it rather than
		// spinning if that ever stops being true.
		return 0, io.ErrNoProgress
	}

	want := int64(len(p))
	if avail := watermark - r.off; want > avail {
		want = avail
	}

	r.mu.Lock()
	f := r.f
	r.mu.Unlock()
	if f == nil {
		return 0, os.ErrClosed
	}

	n, rerr := f.ReadAt(p[:want], r.off)
	r.off += int64(n)
	if rerr == io.EOF && n > 0 {
		// Short only because the writer is still catching up; the next
		// Read blocks for the rest.
		rerr = nil
	}
	return n, rerr
}

func (r *growingReader) Close() error {
	r.mu.Lock()
	f := r.f
	r.f = nil
	r.mu.Unlock()
	if f == nil {
		return nil
	}
	return f.Close()
}
