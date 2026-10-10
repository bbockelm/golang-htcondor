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
	hugeSandboxFile = 1 << 30
	bigSandboxFile  = 128 << 20
	heapCeiling     = 10 << 20
)

// get_job_stdout returns the head of a 1 GiB stdout, marked truncated,
// without holding the file, and abandons the transfer once it has it.
func TestGetJobStdoutStreamsAHugeFile(t *testing.T) {
	f := newActionScopeFixture(t)
	ad := fakeschedd.JobAd(3, 0, "alice", 4)
	ad.InsertAttrString("Out", "big.out")
	f.schedd.AddJobs(ad)
	var sent atomic.Int64
	f.schedd.AddSandbox(3, 0,
		sandboxFile("before.txt", 10, 'b', &sent),
		sandboxFile("big.out", hugeSandboxFile, 'x', &sent),
		sandboxFile("after.txt", 10, 'a', &sent))
	alice := f.as(t, "alice", "mcp:read")

	stop := heapPeak(t)
	text, isErr := f.call(alice, t, "get_job_stdout", map[string]interface{}{"job_id": "3.0"})
	peak := stop()
	t.Logf("peak heap growth %d KiB, %d KiB sent", peak>>10, sent.Load()>>10)

	if isErr {
		t.Fatalf("get_job_stdout failed: %.300s", text)
	}
	if !strings.Contains(text, strings.Repeat("x", maxFileSize)) || strings.Contains(text, strings.Repeat("x", maxFileSize+1)) {
		t.Errorf("the output is not the file's first %d bytes", maxFileSize)
	}
	if want := fmt.Sprintf("showing the first %d of %d bytes", maxFileSize, hugeSandboxFile); !strings.Contains(text, want) {
		t.Errorf("the output does not say it was truncated (%q)", want)
	}
	if peak > heapCeiling {
		t.Errorf("heap grew by %d MiB reading a 1 GiB stdout; want under %d MiB", peak>>20, heapCeiling>>20)
	}
	if n := sent.Load(); n > 64<<20 {
		t.Errorf("the schedd sent %d MiB of the sandbox; the transfer should stop once stdout is read", n>>20)
	}
}

// get_job_output lists every file, past the big one, with bounded
// content, and never holds the big one. It has to read the whole sandbox
// to list it, so the file is smaller than the stdout case's -- still many
// times the heap ceiling.
func TestGetJobOutputStreamsABigFile(t *testing.T) {
	f := newActionScopeFixture(t)
	f.schedd.AddJobs(fakeschedd.JobAd(3, 0, "alice", 4))
	var sent atomic.Int64
	f.schedd.AddSandbox(3, 0,
		sandboxFile("before.txt", 10, 'b', &sent),
		sandboxFile("big.out", bigSandboxFile, 'x', &sent),
		sandboxFile("after.txt", 10, 'a', &sent))
	alice := f.as(t, "alice", "mcp:read")

	stop := heapPeak(t)
	text, isErr := f.call(alice, t, "get_job_output", map[string]interface{}{"job_id": "3.0"})
	peak := stop()
	t.Logf("peak heap growth %d KiB", peak>>10)

	if isErr {
		t.Fatalf("get_job_output failed: %.300s", text)
	}
	for _, want := range []string{"before.txt", "after.txt", fmt.Sprintf("big.out (%d bytes", bigSandboxFile), "truncated"} {
		if !strings.Contains(text, want) {
			t.Errorf("the summary is missing %q: %.500s", want, text)
		}
	}
	if peak > heapCeiling {
		t.Errorf("heap grew by %d MiB reading a %d MiB sandbox; want under %d MiB", peak>>20, bigSandboxFile>>20, heapCeiling>>20)
	}
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
