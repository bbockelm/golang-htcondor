package httpserver

import (
	"archive/tar"
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
)

// writeTar builds a tar the way a caller's `tar cf -` would, through the
// standard library, so the recorder is tested against real output rather
// than against bytes this test made up to match it.
func writeTar(t *testing.T, files map[string]string, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range order {
		body := files[name]
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
			Format:   tar.FormatUSTAR,
		}); err != nil {
			t.Fatalf("WriteHeader(%s): %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("Write(%s): %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

func recordAll(t *testing.T, data []byte, chunk int) *tarNameRecorder {
	t.Helper()
	rec := newTarNameRecorder()
	// Feed it the way io.TeeReader would, in whatever sizes the transport
	// happens to deliver.
	for off := 0; off < len(data); off += chunk {
		end := off + chunk
		if end > len(data) {
			end = len(data)
		}
		if _, err := rec.Write(data[off:end]); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	return rec
}

func TestTarNameRecorderFindsUnexpectedNames(t *testing.T) {
	files := map[string]string{
		"run.sh":   "#!/bin/sh\necho hi\n",
		"data.csv": strings.Repeat("x,y,z\n", 500), // spans several blocks
		"stray.db": "not in the allow-set",
	}
	order := []string{"run.sh", "data.csv", "stray.db"}
	data := writeTar(t, files, order)

	// Chunk sizes chosen to split headers: 1 byte at a time, mid-block,
	// and larger than the whole archive.
	for _, chunk := range []int{1, 7, 512, 513, len(data)} {
		rec := recordAll(t, data, chunk)
		if !reflect.DeepEqual(rec.names, order) {
			t.Fatalf("chunk=%d: recorded %v, want %v", chunk, rec.names, order)
		}
		got := rec.Unexpected([]string{"run.sh", "data.csv"})
		if !reflect.DeepEqual(got, []string{"stray.db"}) {
			t.Fatalf("chunk=%d: Unexpected = %v, want [stray.db]", chunk, got)
		}
		// The complement: with everything allowed there is nothing to warn
		// about. Without this a recorder that always reported its input
		// would pass the assertion above.
		if got := rec.Unexpected(order); len(got) != 0 {
			t.Fatalf("chunk=%d: Unexpected = %v with a full allow-set, want none", chunk, got)
		}
	}
}

// The schedd matches a tar entry's name verbatim, so a file uploaded
// under a directory prefix really is dropped even when its basename is
// in the allow-set. Reporting it is the point.
func TestTarNameRecorderComparesNamesVerbatim(t *testing.T) {
	data := writeTar(t, map[string]string{"data/x.csv": "1,2\n"}, []string{"data/x.csv"})
	rec := recordAll(t, data, 512)
	got := rec.Unexpected([]string{"x.csv"})
	if !reflect.DeepEqual(got, []string{"data/x.csv"}) {
		t.Fatalf("Unexpected = %v, want [data/x.csv]", got)
	}
}

// A pax or GNU long-name extension renames the entry that follows it.
// Reading the placeholder header would report "././@PaxHeader" as an
// uploaded file, so the recorder has to give up instead.
func TestTarNameRecorderGivesUpOnExtendedHeaders(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// A single component too long for ustar's name+prefix split forces a
	// real pax extended header. (A merely deep path does not: ustar
	// carries up to 255 bytes across its prefix field, which the recorder
	// handles -- see TestTarNameRecorderReadsUstarPrefixNames.)
	long := strings.Repeat("n", 204) + ".txt"
	if err := tw.WriteHeader(&tar.Header{
		Name: long, Mode: 0o644, Size: 2, Typeflag: tar.TypeReg, Format: tar.FormatPAX,
	}); err != nil {
		t.Fatalf("WriteHeader: %v", err)
	}
	if _, err := tw.Write([]byte("hi")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rec := recordAll(t, buf.Bytes(), 512)
	if !rec.unreliable {
		t.Fatal("a pax-extended archive did not set unreliable")
	}
	if got := rec.Unexpected(nil); got != nil {
		t.Fatalf("an unreliable recorder reported %v; it must report nothing", got)
	}
}

// Garbage, or a stream the recorder loses sync with, must silence the
// warning rather than produce names that were never in the upload.
func TestTarNameRecorderGivesUpOnNonTarInput(t *testing.T) {
	rec := newTarNameRecorder()
	if _, err := rec.Write(bytes.Repeat([]byte("not a tar file at all! "), 64)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !rec.unreliable {
		t.Fatal("non-tar input did not set unreliable")
	}
	if got := rec.Unexpected([]string{"anything"}); got != nil {
		t.Fatalf("Unexpected = %v, want nothing", got)
	}
}

// Truncation mid-payload must not invent a name from the partial block.
func TestTarNameRecorderHandlesATruncatedStream(t *testing.T) {
	data := writeTar(t, map[string]string{"a.txt": strings.Repeat("z", 4096)}, []string{"a.txt"})
	rec := recordAll(t, data[:1000], 512)
	if got := rec.Unexpected([]string{"a.txt"}); len(got) != 0 {
		t.Fatalf("Unexpected = %v on a truncated stream, want none", got)
	}
}

// Directories and symlinks are not regular files; the schedd skips them
// and so must the warning, or every `tar cf -` of a directory tree would
// report noise.
func TestTarNameRecorderIgnoresNonRegularEntries(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range []*tar.Header{
		{Name: "sub/", Mode: 0o755, Typeflag: tar.TypeDir, Format: tar.FormatUSTAR},
		{Name: "link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "run.sh", Format: tar.FormatUSTAR},
		{Name: "run.sh", Mode: 0o755, Size: 3, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("WriteHeader(%s): %v", h.Name, err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte("hi\n")); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	rec := recordAll(t, buf.Bytes(), 512)
	if !reflect.DeepEqual(rec.names, []string{"run.sh"}) {
		t.Fatalf("recorded %v, want [run.sh]", rec.names)
	}
}

// The recorder sits in the upload's data path via io.TeeReader: it must
// pass every byte through unchanged and never fail the copy.
func TestTarNameRecorderIsTransparentInATee(t *testing.T) {
	data := writeTar(t, map[string]string{"a.txt": "hello"}, []string{"a.txt"})
	rec := newTarNameRecorder()
	var sink bytes.Buffer
	n, err := io.Copy(&sink, io.TeeReader(bytes.NewReader(data), rec))
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if n != int64(len(data)) || !bytes.Equal(sink.Bytes(), data) {
		t.Fatal("the recorder altered the stream it was observing")
	}
	if !reflect.DeepEqual(rec.names, []string{"a.txt"}) {
		t.Fatalf("recorded %v, want [a.txt]", rec.names)
	}
}

// ustar splits a long path across its prefix and name fields. The
// recorder has to rejoin them, or a deep path would be reported as a
// dropped file under its tail alone.
func TestTarNameRecorderReadsUstarPrefixNames(t *testing.T) {
	name := strings.Repeat("d/", 80) + "deep.txt"
	data := writeTar(t, map[string]string{name: "hi"}, []string{name})
	rec := recordAll(t, data, 512)
	if rec.unreliable {
		t.Fatal("a prefix-split ustar name should be readable, not a giving-up case")
	}
	if !reflect.DeepEqual(rec.names, []string{name}) {
		t.Fatalf("recorded %v, want [%s]", rec.names, name)
	}
	if got := rec.Unexpected([]string{name}); len(got) != 0 {
		t.Fatalf("Unexpected = %v, want none", got)
	}
}
