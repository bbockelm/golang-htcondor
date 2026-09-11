package spool

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// trickle delivers content in chunks, pausing between them, and reports
// when the last chunk went out.
type trickle struct {
	chunks   [][]byte
	pause    time.Duration
	i        int
	finished atomic.Int64 // UnixNano of the final Read
}

func (t *trickle) Read(p []byte) (int, error) {
	if t.i >= len(t.chunks) {
		t.finished.CompareAndSwap(0, time.Now().UnixNano())
		return 0, io.EOF
	}
	if t.i > 0 {
		time.Sleep(t.pause)
	}
	n := copy(p, t.chunks[t.i])
	t.i++
	return n, nil
}

func chunksOf(total, size int) ([][]byte, []byte) {
	var chunks [][]byte
	var all []byte
	for i := 0; i < total; i += size {
		n := size
		if i+n > total {
			n = total - i
		}
		c := make([]byte, n)
		for j := range c {
			c[j] = byte((i + j) % 251)
		}
		chunks = append(chunks, c)
		all = append(all, c...)
	}
	return chunks, all
}

// The point of the exercise, as a dependency rather than a stopwatch:
// the source refuses to emit its second chunk until a reader has seen
// the first one. Under spill-then-read that is a deadlock -- the reader
// gets nothing until the stream ends, and the stream is waiting on the
// reader -- so this test can only pass if receiving and reading overlap.
//
// An earlier version of this test timed how long after the last chunk
// the reader finished, and a mutation that made readers wait for the
// whole stream still passed it: 400KB out of the page cache is far
// faster than the pauses being measured.
func TestGrowingReadsWhileTheUploadIsStillArriving(t *testing.T) {
	chunks, want := chunksOf(400*1024, 64*1024)

	firstByte := make(chan struct{})
	var once sync.Once
	src := &gated{chunks: chunks, gate: firstByte}

	g, err := NewGrowing(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()

	r, err := g.Reader()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	got := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		var acc []byte
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
				// Tell the source a reader has consumed from the
				// prefix it has published so far.
				once.Do(func() { close(firstByte) })
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					got <- acc
					return
				}
				readErr <- rerr
				return
			}
		}
	}()

	if err := g.Fill(src); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	select {
	case b := <-got:
		if !bytes.Equal(b, want) {
			t.Errorf("read %d bytes, want %d", len(b), len(want))
		}
	case err := <-readErr:
		t.Fatalf("reading: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the reader never finished")
	}
}

// gated emits its first chunk, then waits for a reader to have consumed
// something before emitting the rest.
type gated struct {
	chunks [][]byte
	gate   <-chan struct{}
	i      int
}

func (s *gated) Read(p []byte) (int, error) {
	if s.i >= len(s.chunks) {
		return 0, io.EOF
	}
	if s.i == 1 {
		select {
		case <-s.gate:
		case <-time.After(5 * time.Second):
			return 0, errors.New("no reader consumed the published prefix; " +
				"the buffer is not pipelining")
		}
	}
	n := copy(p, s.chunks[s.i])
	s.i++
	return n, nil
}

// Every proc must get the whole tar even though the readers start at
// different times and the bytes arrive in pieces.
func TestGrowingServesEveryReaderTheWholeTar(t *testing.T) {
	chunks, want := chunksOf(300*1024, 32*1024)
	g, err := NewGrowing(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()

	const readers = 12
	var wg sync.WaitGroup
	errs := make(chan error, readers)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Stagger the starts: some begin before any byte has
			// landed, some in the middle, some after the end.
			time.Sleep(time.Duration(i) * 15 * time.Millisecond)
			r, rerr := g.Reader()
			if rerr != nil {
				errs <- rerr
				return
			}
			defer func() { _ = r.Close() }()
			got, rerr := io.ReadAll(r)
			if rerr != nil {
				errs <- fmt.Errorf("reader %d: %w", i, rerr)
				return
			}
			if !bytes.Equal(got, want) {
				errs <- fmt.Errorf("reader %d got %d bytes, want %d", i, len(got), len(want))
			}
		}(i)
	}

	if err := g.Fill(&trickle{chunks: chunks, pause: 10 * time.Millisecond}); err != nil {
		t.Fatalf("Fill: %v", err)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// Past the limit the upload is refused, and -- the part that matters --
// every reader is told, rather than seeing a clean EOF on a short tar.
// The schedd accepts a truncated tar without complaint, so a silent
// early EOF would release procs whose files are missing.
func TestGrowingRefusalReachesEveryReader(t *testing.T) {
	chunks, _ := chunksOf(300*1024, 32*1024)
	g, err := NewGrowing(t.TempDir(), 100*1024) // smaller than the stream
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()

	readErr := make(chan error, 1)
	go func() {
		r, rerr := g.Reader()
		if rerr != nil {
			readErr <- rerr
			return
		}
		defer func() { _ = r.Close() }()
		_, rerr = io.ReadAll(r)
		readErr <- rerr
	}()

	fillErr := g.Fill(&trickle{chunks: chunks, pause: 5 * time.Millisecond})
	if fillErr == nil {
		t.Fatal("Fill accepted a stream past its limit")
	}
	if !strings.Contains(fillErr.Error(), "limit") {
		t.Errorf("Fill error does not mention the limit: %v", fillErr)
	}

	select {
	case err := <-readErr:
		if err == nil {
			t.Error("the reader saw a clean EOF on a refused upload; a short tar spools cleanly and leaves the job broken")
		}
	case <-time.After(5 * time.Second):
		t.Error("the reader was left blocked after the upload was refused")
	}
}

// A reader that starts after everything has landed is the ordinary
// second-wave case: with Concurrency 10 and more procs than that, the
// later procs begin once the stream is long finished.
func TestGrowingReaderAfterTheStreamEnded(t *testing.T) {
	chunks, want := chunksOf(64*1024, 16*1024)
	g, err := NewGrowing(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()

	if err := g.Fill(&trickle{chunks: chunks}); err != nil {
		t.Fatal(err)
	}
	r, err := g.Reader()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("got %d bytes, want %d", len(got), len(want))
	}
}

// A buffer far larger than one read, trickled in, so the reader
// repeatedly catches up to a moving watermark and has to block, resume,
// and resume again mid-file.
func TestGrowingReadsAcrossManyChunks(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~20MB")
	}
	total := 16<<20 + 123*1024
	chunks, want := chunksOf(total, 512*1024)
	g, err := NewGrowing(t.TempDir(), int64(total)+1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()

	done := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		r, rerr := g.Reader()
		if rerr != nil {
			errCh <- rerr
			return
		}
		defer func() { _ = r.Close() }()
		b, rerr := io.ReadAll(r)
		if rerr != nil {
			errCh <- rerr
			return
		}
		done <- b
	}()

	if err := g.Fill(&trickle{chunks: chunks, pause: time.Millisecond}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if !bytes.Equal(got, want) {
			t.Errorf("got %d bytes, want %d", len(got), len(want))
		}
	case err := <-errCh:
		t.Fatalf("reading a trickled buffer: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("timed out reading a trickled buffer")
	}
}

// End to end through the fan-out: a growing source, more procs than the
// concurrency bound, and every proc gets the whole tar.
func TestFanOutOverAGrowingSource(t *testing.T) {
	chunks, want := chunksOf(200*1024, 25*1024)
	g, err := NewGrowing(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()

	const procs = 25
	ads := make([]*classad.ClassAd, 0, procs)
	for i := 0; i < procs; i++ {
		ad := classad.New()
		_ = ad.Set("ClusterId", 7)
		_ = ad.Set("ProcId", i)
		ads = append(ads, ad)
	}

	var mu sync.Mutex
	short := []string{}
	go func() { _ = g.Fill(&trickle{chunks: chunks, pause: 5 * time.Millisecond}) }()

	res := FanOut(context.Background(), ads, g,
		Limits{Concurrency: 10, MaxProcs: procs, MaxVolume: 1 << 30},
		func(_ context.Context, ads []*classad.ClassAd, r io.Reader) error {
			b, err := io.ReadAll(r)
			if err != nil {
				return err
			}
			if !bytes.Equal(b, want) {
				mu.Lock()
				short = append(short, fmt.Sprintf("%s got %d of %d bytes", ProcID(ads[0]), len(b), len(want)))
				mu.Unlock()
				return errors.New("short tar")
			}
			return nil
		})

	if len(res.Spooled) != procs {
		t.Errorf("spooled %d of %d procs; failed: %v", len(res.Spooled), procs, res.Failed)
	}
	mu.Lock()
	for _, s := range short {
		t.Error(s)
	}
	mu.Unlock()
}

// A reader parked waiting for bytes must be released when the buffer is
// closed. It parks on a condition variable that only Fill signals, so
// without this it waits for the life of the process -- and the fan-out
// is not the only possible caller.
func TestGrowingCloseReleasesABlockedReader(t *testing.T) {
	g, err := NewGrowing(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	r, err := g.Reader()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	got := make(chan error, 1)
	go func() {
		_, rerr := io.ReadAll(r)
		got <- rerr
	}()

	// Let the reader reach the blocking wait, then close underneath it.
	time.Sleep(50 * time.Millisecond)
	if err := g.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-got:
		if err == nil {
			t.Error("the reader saw a clean end of stream after Close; " +
				"a partial tar must never look finished")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close left the reader blocked; it would never wake")
	}
}

// Abort is how a cancelled request releases readers that are waiting on
// an upload nobody wants any more.
func TestGrowingAbortReleasesReadersWithTheReason(t *testing.T) {
	g, err := NewGrowing(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()

	const readers = 5
	got := make(chan error, readers)
	for i := 0; i < readers; i++ {
		go func() {
			r, rerr := g.Reader()
			if rerr != nil {
				got <- rerr
				return
			}
			defer func() { _ = r.Close() }()
			_, rerr = io.ReadAll(r)
			got <- rerr
		}()
	}

	time.Sleep(50 * time.Millisecond)
	g.Abort(context.Canceled)

	for i := 0; i < readers; i++ {
		select {
		case err := <-got:
			if err == nil {
				t.Error("a reader saw a clean end of stream after Abort")
			} else if !errors.Is(err, context.Canceled) {
				t.Errorf("reader error = %v, want the abort reason", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Abort left a reader blocked")
		}
	}
}

// A reader that stops early must not wedge the upload: Fill keeps
// going, and the other procs still get the whole tar.
func TestGrowingReaderAbandoningEarlyDoesNotStallTheUpload(t *testing.T) {
	chunks, want := chunksOf(200*1024, 16*1024)
	g, err := NewGrowing(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()

	// Fill runs alongside the readers; reading before it starts would
	// simply block, which is the buffer working as intended.
	fillErr := make(chan error, 1)
	go func() { fillErr <- g.Fill(&trickle{chunks: chunks, pause: 2 * time.Millisecond}) }()

	quitter, err := g.Reader()
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	if _, err := quitter.Read(buf); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("first read: %v", err)
	}
	_ = quitter.Close() // walks away mid-stream

	done := make(chan []byte, 1)
	go func() {
		r, rerr := g.Reader()
		if rerr != nil {
			t.Error(rerr)
			done <- nil
			return
		}
		defer func() { _ = r.Close() }()
		b, rerr := io.ReadAll(r)
		if rerr != nil {
			t.Error(rerr)
		}
		done <- b
	}()

	if err := <-fillErr; err != nil {
		t.Fatalf("Fill: %v", err)
	}
	select {
	case got := <-done:
		if !bytes.Equal(got, want) {
			t.Errorf("the surviving reader got %d bytes, want %d", len(got), len(want))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("an abandoned reader stalled the upload")
	}
}

// Reading and closing from two goroutines must not fault. The reader
// used to hand out a pointer into an mmap'd region, so a Close during a
// Read unmapped memory another goroutine was copying from -- an
// unrecoverable SIGSEGV rather than an error.
func TestGrowingConcurrentReadAndClose(t *testing.T) {
	chunks, _ := chunksOf(4<<20, 64*1024)
	g, err := NewGrowing(t.TempDir(), 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = g.Close() }()
	if err := g.Fill(&trickle{chunks: chunks}); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 50; i++ {
		r, rerr := g.Reader()
		if rerr != nil {
			t.Fatal(rerr)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			buf := make([]byte, 64*1024)
			for {
				if _, err := r.Read(buf); err != nil {
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i%5) * time.Millisecond)
			_ = r.Close()
		}()
		wg.Wait()
	}
}
