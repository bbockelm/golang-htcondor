package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
)

// The output tools read the job sandbox as a stream. These run them
// against a fake schedd whose sandbox holds a file far larger than the
// tools return, and measure the heap while they do: a tool that buffers
// the sandbox first -- as these did -- holds the whole file.

// byteSource is an endless run of one byte, counting what is read.
type byteSource struct {
	b    byte
	read *atomic.Int64
}

func (s byteSource) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = s.b
	}
	s.read.Add(int64(len(p)))
	return len(p), nil
}

// sandboxFile is a SandboxFile of size bytes of b; read counts the bytes
// the fake schedd sent of it.
func sandboxFile(name string, size int64, b byte, read *atomic.Int64) fakeschedd.SandboxFile {
	return fakeschedd.SandboxFile{
		Name: name,
		Size: size,
		Open: func() io.ReadCloser {
			return io.NopCloser(io.LimitReader(byteSource{b: b, read: read}, size))
		},
	}
}

// heapPeak samples the heap until stop is called and returns the highest
// allocation seen above where it started.
//
// The collector runs eagerly meanwhile, so what is measured is what the
// tool holds rather than how much garbage the default pacing lets pile up
// between collections.
func heapPeak(t *testing.T) (stop func() uint64) {
	t.Helper()
	old := debug.SetGCPercent(10)
	t.Cleanup(func() { debug.SetGCPercent(old) })
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	base := ms.HeapAlloc
	var peak atomic.Uint64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > base && ms.HeapAlloc-base > peak.Load() {
				peak.Store(ms.HeapAlloc - base)
			}
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	}()
	return func() uint64 {
		close(done)
		wg.Wait()
		return peak.Load()
	}
}

const (
	// smallSandboxFile and the larger sizes below are the two points a
	// memory measurement compares. A single reading against a fixed
	// ceiling was noise: both ends of the transfer run in this process,
	// so the heap also carries cedar's in-flight buffers and whatever
	// garbage GC pacing leaves, which differ by machine and run (10-12
	// MiB on arm64 CI against a 10 MiB ceiling). That noise does not
	// depend on the file's size; holding the file does.
	smallSandboxFile = 16 << 20
	hugeSandboxFile  = 1 << 30
	bigSandboxFile   = 256 << 20
)

// sandboxRun is one call of an output tool over a sandbox holding a
// file of some size between two small ones.
type sandboxRun struct {
	text string
	// peak is the heap growth during the call; sent is how much of the
	// sandbox the fake schedd sent.
	peak uint64
	sent int64
}

func runSandboxTool(t *testing.T, tool string, size int64) sandboxRun {
	t.Helper()
	f := newActionScopeFixture(t)
	ad := fakeschedd.JobAd(3, 0, "alice", 4)
	ad.InsertAttrString("Out", "big.out")
	f.schedd.AddJobs(ad)
	var sent atomic.Int64
	f.schedd.AddSandbox(3, 0,
		sandboxFile("before.txt", 10, 'b', &sent),
		sandboxFile("big.out", size, 'x', &sent),
		sandboxFile("after.txt", 10, 'a', &sent))
	alice := f.as(t, "alice", "mcp:read")

	stop := heapPeak(t)
	text, isErr := f.call(alice, t, tool, map[string]interface{}{"job_id": "3.0"})
	run := sandboxRun{text: text, peak: stop(), sent: sent.Load()}
	t.Logf("%s over a %d MiB file: peak heap growth %d KiB, %d KiB sent", tool, size>>20, run.peak>>10, run.sent>>10)
	if isErr {
		t.Fatalf("%s failed: %.300s", tool, text)
	}
	return run
}

// assertDoesNotScale fails when the heap grew with the file. A tool
// that buffers the sandbox holds at least the whole file, so the larger
// run's peak exceeds the smaller's by at least the size difference; one
// that streams differs only by noise. Half the difference splits the
// two: single peaks were seen anywhere from 2 to 35 MiB at either size,
// so a tighter bound would be measuring the noise again.
func assertDoesNotScale(t *testing.T, small, large sandboxRun, smallSize, largeSize int64) {
	t.Helper()
	var growth uint64
	if large.peak > small.peak {
		growth = large.peak - small.peak
	}
	if limit := uint64(largeSize-smallSize) / 2; growth > limit {
		t.Errorf("heap grew %d MiB more for a %d MiB file than for a %d MiB one; want under %d MiB -- memory scales with the sandbox",
			growth>>20, largeSize>>20, smallSize>>20, limit>>20)
	}
}

// get_job_stdout returns the head of a 1 GiB stdout, marked truncated,
// using no more memory than for a 16 MiB one, and abandons the transfer
// once it has it.
func TestGetJobStdoutStreamsAHugeFile(t *testing.T) {
	small := runSandboxTool(t, "get_job_stdout", smallSandboxFile)
	large := runSandboxTool(t, "get_job_stdout", hugeSandboxFile)

	if !strings.Contains(large.text, strings.Repeat("x", maxFileSize)) || strings.Contains(large.text, strings.Repeat("x", maxFileSize+1)) {
		t.Errorf("the output is not the file's first %d bytes", maxFileSize)
	}
	if want := fmt.Sprintf("showing the first %d of %d bytes", maxFileSize, hugeSandboxFile); !strings.Contains(large.text, want) {
		t.Errorf("the output does not say it was truncated (%q)", want)
	}
	assertDoesNotScale(t, small, large, smallSandboxFile, hugeSandboxFile)
	if large.sent > 64<<20 {
		t.Errorf("the schedd sent %d MiB of the sandbox; the transfer should stop once stdout is read", large.sent>>20)
	}
}

// get_job_output lists every file, past the big one, with bounded
// content, using no more memory for a 256 MiB file than for a 16 MiB
// one. It has to read the whole sandbox to list it, so the file is
// smaller than the stdout case's.
func TestGetJobOutputStreamsABigFile(t *testing.T) {
	small := runSandboxTool(t, "get_job_output", smallSandboxFile)
	large := runSandboxTool(t, "get_job_output", bigSandboxFile)

	for _, want := range []string{"before.txt", "after.txt", fmt.Sprintf("big.out (%d bytes", bigSandboxFile), "truncated"} {
		if !strings.Contains(large.text, want) {
			t.Errorf("the summary is missing %q: %.500s", want, large.text)
		}
	}
	assertDoesNotScale(t, small, large, smallSandboxFile, bigSandboxFile)
}

// Many files that are each under the per-file cap still add up; the
// total returned is capped too, and every file is still listed.
func TestGetJobOutputCapsTheTotal(t *testing.T) {
	f := newActionScopeFixture(t)
	f.schedd.AddJobs(fakeschedd.JobAd(3, 0, "alice", 4))
	var sent atomic.Int64
	var files []fakeschedd.SandboxFile
	const n = 20
	for i := 0; i < n; i++ {
		files = append(files, sandboxFile(fmt.Sprintf("part%02d.dat", i), maxFileSize, 'p', &sent))
	}
	f.schedd.AddSandbox(3, 0, files...)
	alice := f.as(t, "alice", "mcp:read")

	params, err := json.Marshal(map[string]interface{}{"name": "get_job_output", "arguments": map[string]interface{}{"job_id": "3.0"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(alice, 30*time.Second)
	defer cancel()
	resp := f.server.HandleMessage(ctx, &MCPMessage{JSONRPC: "2.0", ID: 1, Method: "tools/call", Params: params})
	if resp.Error != nil {
		t.Fatalf("protocol error %v", resp.Error)
	}
	raw, err := json.Marshal(resp.Result)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Structured struct {
			Files []OutputFile `json:"files"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Structured.Files) != n {
		t.Fatalf("%d files listed, want all %d", len(got.Structured.Files), n)
	}
	total := 0
	for _, file := range got.Structured.Files {
		total += len(file.Data)
	}
	if total > maxOutputTotalSize {
		t.Errorf("returned %d bytes of content in all, over the %d cap", total, maxOutputTotalSize)
	}
	if first := got.Structured.Files[0]; first.IsTruncated || len(first.Data) != maxFileSize {
		t.Errorf("the first file was cut short (%d bytes, truncated=%v)", len(first.Data), first.IsTruncated)
	}
	if last := got.Structured.Files[n-1]; !last.IsTruncated || last.Data != "" {
		t.Errorf("a file past the total cap carried %d bytes, truncated=%v", len(last.Data), last.IsTruncated)
	}
}
