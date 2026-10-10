package htcondor

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/cedar/stream"
)

type tarEntry struct {
	name string
	dir  bool
	data string
}

func buildTar(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: tar.TypeReg, Size: int64(len(e.data))}
		if e.dir {
			h = &tar.Header{Name: e.name, Mode: 0o755, Typeflag: tar.TypeDir}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("tar header %q: %v", e.name, err)
		}
		if !e.dir {
			if _, err := tw.Write([]byte(e.data)); err != nil {
				t.Fatalf("tar data %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

// sendTarToSink runs sendJobFilesFromTar for one job against a peer that
// only reads, and returns the call's error and every byte it sent. A tar
// that is refused never gets as far as a file's GoAhead handshake, so a
// read-only peer is enough to see what would have reached the schedd; a
// tar that is accepted stalls waiting for an acknowledgement until the
// deadline.
func sendTarToSink(t *testing.T, allowed []string, tarBytes []byte) ([]byte, error) {
	t.Helper()
	c1, c2 := net.Pipe()
	_ = c1.SetDeadline(time.Now().Add(300 * time.Millisecond))
	var sent bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(&sent, c2)
	}()

	id := procID{cluster: 1, proc: 0}
	set := make(map[string]bool)
	for _, n := range allowed {
		set[n] = true
	}
	info := map[procID]*jobInfo{id: {inputFiles: set, jobID: id}}
	err := (&Schedd{}).sendJobFilesFromTar(context.Background(), stream.NewStream(c1),
		bytes.NewReader(tarBytes), info, []procID{id}, true)
	_ = c1.Close()
	wg.Wait()
	_ = c2.Close()
	return sent.Bytes(), err
}

// A name that is not a canonical path inside the sandbox -- directory or
// file, in the allow-set or not -- refuses the upload before that name is
// sent, and before the final command that would release the job.
func TestSpoolTarRefusesNonCanonicalNames(t *testing.T) {
	for _, tc := range []struct {
		label   string
		entries []tarEntry
		bad     string
	}{
		{"traversal dir", []tarEntry{{name: "../x/", dir: true}}, "../x"},
		{"non-canonical file", []tarEntry{{name: "foo/../bar", data: "b"}}, "foo/../bar"},
		{"absolute file", []tarEntry{{name: "/etc/passwd", data: "p"}}, "/etc/passwd"},
	} {
		sent, err := sendTarToSink(t, []string{"bar", "x", "foo/bar"}, buildTar(t, tc.entries))
		if !errors.Is(err, ErrInvalidTarEntry) {
			t.Errorf("%s: err = %v, want ErrInvalidTarEntry", tc.label, err)
		}
		if bytes.Contains(sent, []byte(tc.bad)) {
			t.Errorf("%s: %q reached the peer", tc.label, tc.bad)
		}
	}
}

// A directory is created only when an allowed input needs it, as files
// outside the allow-set are skipped.
func TestSpoolTarDirectoriesFollowTheAllowSet(t *testing.T) {
	sent, err := sendTarToSink(t, []string{"in.txt"},
		buildTar(t, []tarEntry{{name: "stray/", dir: true}}))
	if errors.Is(err, ErrInvalidTarEntry) {
		t.Errorf("a well-formed directory name was refused: %v", err)
	}
	if bytes.Contains(sent, []byte("stray")) {
		t.Error("a directory outside the allow-set was sent")
	}

	sent, _ = sendTarToSink(t, []string{"data/in.txt"},
		buildTar(t, []tarEntry{{name: "data/", dir: true}}))
	if !bytes.Contains(sent, []byte("data")) {
		t.Error("a directory an allowed input needs was not sent")
	}
}
