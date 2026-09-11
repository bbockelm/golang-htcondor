package httpserver

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// formWith builds a parsed multipart form with the given files, in
// order, so a rejected entry can be placed after a good one.
func formWith(t *testing.T, files [][2]string) *multipart.Form {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for _, f := range files {
		fw, err := w.CreateFormFile("input", f[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(f[1])); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if err := req.ParseMultipartForm(1 << 20); err != nil {
		t.Fatal(err)
	}
	return req.MultipartForm
}

// A conversion that fails partway must reach the reader as an ERROR.
//
// It used to reach it as a clean io.EOF over a well-formed shorter tar:
// tar.Writer.Close appends an end-of-archive marker to whatever was
// written, and a plain pipe close looks like a finished stream. The
// schedd accepts that and releases the jobs, so every proc of the
// cluster came out of its spooling hold with a partial sandbox, and the
// 500 the handler returns afterwards was too late to stop it.
func TestMultipartTarFailureIsAnErrorNotAShortTar(t *testing.T) {
	// The second entry is rejected by validateTarEntryName, so the tar
	// holds one complete file when the conversion gives up.
	//
	// A backslash rather than "../": Go's multipart parser bases the
	// filename it reports, so a traversal shape never arrives intact
	// and cannot be used to trigger the rejection here.
	form := formWith(t, [][2]string{
		{"good.txt", "kept"},
		{`bad\name.txt`, "rejected"},
	})

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- writeMultipartTar(pw, form) }()

	// Drain the way the spool path does, then see how the stream ends.
	_, readErr := io.Copy(io.Discard, pr)

	convErr := <-done
	if convErr == nil {
		t.Fatal("the conversion reported success on a rejected entry")
	}
	if readErr == nil {
		t.Fatal("the reader saw a clean end of stream; " +
			"a short tar spools cleanly and releases the job with files missing")
	}
	if !strings.Contains(readErr.Error(), "backslash") {
		t.Errorf("the reader's error does not name the cause: %v", readErr)
	}
}

// The same, checked from the consumer's side: a tar reader must not be
// able to parse the truncated stream as a complete archive.
func TestMultipartTarFailureDoesNotParseAsACompleteArchive(t *testing.T) {
	form := formWith(t, [][2]string{
		{"good.txt", "kept"},
		{`bad\name.txt`, "rejected"},
	})

	pr, pw := io.Pipe()
	go func() { _ = writeMultipartTar(pw, form) }()

	tr := tar.NewReader(pr)
	var names []string
	var err error
	for {
		var h *tar.Header
		h, err = tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
		//nolint:gosec // G110: a fixed-size fixture built by this test
		if _, cerr := io.Copy(io.Discard, tr); cerr != nil {
			err = cerr
			break
		}
	}
	if errors.Is(err, io.EOF) {
		t.Errorf("the truncated tar parsed as a complete archive holding %v", names)
	}
}

// The success path still produces a readable archive with everything in
// it -- the fix must not cost the ordinary case.
func TestMultipartTarSuccess(t *testing.T) {
	form := formWith(t, [][2]string{
		{"a.txt", "alpha"},
		{"b.txt", "beta"},
	})

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- writeMultipartTar(pw, form) }()

	got := map[string]string{}
	tr := tar.NewReader(pr)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading the tar: %v", err)
		}
		var buf bytes.Buffer
		//nolint:gosec // G110: a fixed-size fixture built by this test
		if _, err := io.Copy(&buf, tr); err != nil {
			t.Fatal(err)
		}
		got[h.Name] = buf.String()
	}
	if err := <-done; err != nil {
		t.Fatalf("conversion failed: %v", err)
	}
	if got["a.txt"] != "alpha" || got["b.txt"] != "beta" {
		t.Errorf("archive contents = %v", got)
	}
}
