package mcpserver

import (
	"archive/tar"
	"bytes"
	"strings"
	"testing"
)

func tarOf(t *testing.T, files map[string]string) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("tar body %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return &buf
}

func TestExtractSandboxFileFindsByBaseName(t *testing.T) {
	arc := tarOf(t, map[string]string{"test.1.0.out": "hello\n"})

	got, found, _, err := extractSandboxFile(arc, "test.1.0.out")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if got != "hello\n" {
		t.Errorf("content = %q", got)
	}
}

// The job's Out attribute is not always a bare filename. A job submitted
// with an initial directory of "/" stores it path-qualified, and
// comparing that against a tar entry's base name never matches -- the
// retrieval then reported the output missing for a job whose files were
// sitting in the spool directory.
func TestExtractSandboxFileMatchesAPathQualifiedName(t *testing.T) {
	arc := tarOf(t, map[string]string{"test.14996085.0.out": "output\n"})

	got, found, _, err := extractSandboxFile(arc, "/test.14996085.0.out")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !found {
		t.Fatal("a path-qualified Out did not match the sandbox entry")
	}
	if got != "output\n" {
		t.Errorf("content = %q", got)
	}
}

// And the reverse: a tar that carries a path.
func TestExtractSandboxFileMatchesAPathQualifiedEntry(t *testing.T) {
	arc := tarOf(t, map[string]string{"./cluster1.proc0.subproc0/test.1.0.err": "boom\n"})

	got, found, _, err := extractSandboxFile(arc, "test.1.0.err")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if got != "boom\n" {
		t.Errorf("content = %q", got)
	}
}

// An empty stdout is a real answer, not a missing file. Conflating them
// sends the caller hunting a transfer problem that does not exist.
func TestExtractSandboxFileDistinguishesEmptyFromMissing(t *testing.T) {
	arc := tarOf(t, map[string]string{"test.1.0.out": ""})

	got, found, _, err := extractSandboxFile(arc, "test.1.0.out")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !found {
		t.Error("an empty output file must still be found")
	}
	if got != "" {
		t.Errorf("content = %q, want empty", got)
	}
}

// A miss reports what the sandbox did hold, which is the thing that
// makes it diagnosable at all.
func TestExtractSandboxFileListsWhatWasThere(t *testing.T) {
	arc := tarOf(t, map[string]string{
		"job.log": "...", "test.1.0.out": "x", "test.1.0.err": "y",
	})

	_, found, entries, err := extractSandboxFile(arc, "wanted.out")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if found {
		t.Fatal("matched something it should not have")
	}
	if len(entries) != 3 {
		t.Fatalf("entries = %v, want all three", entries)
	}
	desc := describeSandboxEntries(entries)
	for _, want := range []string{"job.log", "test.1.0.out", "test.1.0.err"} {
		if !strings.Contains(desc, want) {
			t.Errorf("the description omits %q: %s", want, desc)
		}
	}
}

// An empty archive is its own diagnosis: the transfer brought nothing
// back, which is a different problem from a name mismatch.
func TestDescribeSandboxEntriesOnEmptyArchive(t *testing.T) {
	arc := tarOf(t, map[string]string{})
	_, found, entries, err := extractSandboxFile(arc, "test.1.0.out")
	if err != nil || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	desc := describeSandboxEntries(entries)
	if !strings.Contains(desc, "empty sandbox") || !strings.Contains(desc, "never transferred") {
		t.Errorf("an empty sandbox is not explained: %s", desc)
	}
}

// A big sandbox must not produce an unbounded error message.
func TestDescribeSandboxEntriesTruncates(t *testing.T) {
	many := make([]string, 60)
	for i := range many {
		many[i] = "f"
	}
	desc := describeSandboxEntries(many)
	if !strings.Contains(desc, "and 35 more") {
		t.Errorf("listing is not bounded: %s", desc)
	}
}

// Directory entries are not files and must not be offered as candidates.
func TestExtractSandboxFileSkipsDirectories(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "subdir/", Mode: 0755, Typeflag: tar.TypeDir})
	_ = tw.WriteHeader(&tar.Header{Name: "a.out", Mode: 0600, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("z"))
	_ = tw.Close()

	_, _, entries, err := extractSandboxFile(&buf, "nope")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	for _, e := range entries {
		if e == "subdir" {
			t.Errorf("a directory was listed as a sandbox file: %v", entries)
		}
	}
}
