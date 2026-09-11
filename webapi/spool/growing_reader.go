package spool

import (
	"io"
	"os"
)

// mapWindow is how much of the buffer one mapping covers. The fan-out
// has Concurrency readers over the same file, so the windows overlap in
// the page cache and cost one copy of the pages between them regardless
// of how many readers there are.
const mapWindow = 8 << 20 // 8 MiB

// growingReader reads a Growing buffer, blocking where the data has not
// arrived yet.
//
// It reads through a mapping rather than copying into a buffer first:
// the pages are already in the page cache (the writer just wrote them),
// and every reader shares them. A mapping cannot extend past the file's
// current length -- touching a page beyond it is a SIGBUS, not a short
// read -- so the window is clamped to what Fill has published and
// remapped as more lands.
type growingReader struct {
	g   *Growing
	f   *os.File
	off int64

	m            mapping
	mStart, mEnd int64
	fallback     bool // mmap unavailable; read through the descriptor
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
		// Nothing more is coming.
		if err != nil {
			return 0, err
		}
		if done {
			return 0, io.EOF
		}
		return 0, io.ErrNoProgress
	}

	want := int64(len(p))
	if avail := watermark - r.off; want > avail {
		want = avail
	}

	if r.fallback {
		n, rerr := r.f.ReadAt(p[:want], r.off)
		r.off += int64(n)
		if rerr == io.EOF && n > 0 {
			rerr = nil
		}
		return n, rerr
	}

	if err := r.ensureMapped(watermark); err != nil {
		// A mapping failure is not fatal: the bytes are in a file, and
		// reading them through the descriptor is merely slower.
		r.fallback = true
		r.release()
		return r.Read(p)
	}

	if end := r.mEnd - r.off; want > end {
		want = end
	}
	n := copy(p[:want], r.m.bytes()[r.off-r.mStart:])
	r.off += int64(n)
	return n, nil
}

// ensureMapped makes the window cover r.off, clamped to the published
// watermark.
func (r *growingReader) ensureMapped(watermark int64) error {
	if r.m.valid() && r.off >= r.mStart && r.off < r.mEnd {
		return nil
	}
	r.release()

	start := pageAlign(r.off)
	end := start + mapWindow
	if end > watermark {
		end = watermark
	}
	if end <= start {
		// Nothing to map yet; the caller only gets here with bytes
		// available, so this means the window math and the watermark
		// disagree -- fall back rather than map zero bytes.
		return errShortWindow
	}

	m, err := mmapRegion(r.f, start, int(end-start))
	if err != nil {
		return err
	}
	r.m, r.mStart, r.mEnd = m, start, end
	return nil
}

func (r *growingReader) release() {
	if r.m.valid() {
		_ = r.m.unmap()
	}
	r.m, r.mStart, r.mEnd = mapping{}, 0, 0
}

func (r *growingReader) Close() error {
	r.release()
	return r.f.Close()
}
