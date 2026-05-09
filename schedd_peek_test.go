package htcondor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
)

// TestPeekJobOutputRejectsEmptyRequest pins the early-return on a
// request that asks for neither stdout nor stderr. Without this guard
// we'd reach GetJobConnectInfo and burn a schedd RPC for a request
// that has nothing useful to return.
func TestPeekJobOutputRejectsEmptyRequest(t *testing.T) {
	s := NewSchedd("test", "127.0.0.1:0")
	_, err := s.PeekJobOutput(context.Background(), 1, 0, PeekRequest{})
	if err == nil {
		t.Fatal("expected error for request with no streams selected")
	}
	if !strings.Contains(err.Error(), "Stdout") {
		t.Errorf("error should mention which fields are required, got: %v", err)
	}
}

// TestDecodePeekFileKind pins the classification of each TransferFiles
// list entry the starter can emit. The C++ side encodes stdout/stderr
// as bare integers 0/1 and named files as strings — silently
// misclassifying any of them would route bytes to the wrong field of
// PeekResult (or drop them).
func TestDecodePeekFileKind(t *testing.T) {
	tests := []struct {
		name string
		in   classad.Value
		want peekFileKind
	}{
		{"int 0 → stdout", classad.NewIntValue(0), peekKindStdout},
		{"int 1 → stderr", classad.NewIntValue(1), peekKindStderr},
		{"int 2 → other", classad.NewIntValue(2), peekKindOther},
		{"int -1 → other", classad.NewIntValue(-1), peekKindOther},
		{"string filename → other", classad.NewStringValue("output.log"), peekKindOther},
		{"empty string → other", classad.NewStringValue(""), peekKindOther},
		{"undefined → other", classad.NewUndefinedValue(), peekKindOther},
		{"bool → other", classad.NewBoolValue(true), peekKindOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodePeekFileKind(tt.in); got != tt.want {
				t.Errorf("decodePeekFileKind(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestLookupListValues exercises the ad-list extraction used by the
// peek response parser. The relevant attributes (TransferFiles,
// TransferOffsets) are always lists in a successful response — but
// the helper has to fail loudly when they're missing or shaped
// wrong, otherwise the per-file walk silently does nothing.
func TestLookupListValues(t *testing.T) {
	t.Run("MixedIntStringList", func(t *testing.T) {
		// Reproduces the shape of TransferFiles when the request asked
		// for stdout + a named output file: list of [0, "output.log"].
		// Build via ParseExpr so the underlying ExprList has the same
		// shape the wire decoder produces; `ad.Set("…", []Value{…})`
		// goes through the generic marshaler and produces undefined
		// elements.
		expr, err := classad.ParseExpr(`{0, "output.log"}`)
		if err != nil {
			t.Fatalf("ParseExpr: %v", err)
		}
		ad := classad.New()
		_ = ad.Set("TransferFiles", expr)
		got, err := lookupListValues(ad, "TransferFiles")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 elements, got %d", len(got))
		}
		if !got[0].IsInteger() {
			t.Errorf("element 0 should be int, got %v", got[0])
		}
		if !got[1].IsString() {
			t.Errorf("element 1 should be string, got %v", got[1])
		}
	})

	t.Run("MissingAttributeIsAnError", func(t *testing.T) {
		ad := classad.New()
		if _, err := lookupListValues(ad, "TransferFiles"); err == nil {
			t.Error("expected error for missing attribute")
		}
	})

	t.Run("NonListAttributeIsAnError", func(t *testing.T) {
		ad := classad.New()
		_ = ad.Set("TransferFiles", "not-a-list")
		if _, err := lookupListValues(ad, "TransferFiles"); err == nil {
			t.Error("expected error when attribute is not a list")
		}
	})

	t.Run("EmptyListIsOk", func(t *testing.T) {
		// Empty TransferFiles is a legitimate response — the starter
		// returned no files. The helper shouldn't conflate "empty
		// list" with "missing".
		expr, err := classad.ParseExpr(`{}`)
		if err != nil {
			t.Fatalf("ParseExpr: %v", err)
		}
		ad := classad.New()
		_ = ad.Set("TransferFiles", expr)
		got, err := lookupListValues(ad, "TransferFiles")
		if err != nil {
			t.Fatalf("empty list should not error: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected 0 elements, got %d", len(got))
		}
	})
}

// TestReadPeekFile exercises the CEDAR get_file frame parser end-to-
// end against a buffer-backed stream. We feed it the same frame
// shape a real starter would send and verify the readback. Any
// regression in frame counting (forgetting EOM, mis-sizing the
// header, dropping the buffer-size field) shows up as a hang or
// wrong-bytes here.
func TestReadPeekFile(t *testing.T) {
	t.Run("EmptyFile", func(t *testing.T) {
		// filesize=0, buf_sz=4096. The reader bails on a sentinel
		// error rather than trying to consume the trailing
		// PUT_FILE_EOM_NUM marker — cedar's Go bindings can't
		// drain that raw int between framed messages, so once we
		// see an empty header the connection is no longer usable.
		// Callers (peekOutput) treat errEmptyFileFrame as "valid
		// empty payload, but stop reading further files".
		s := newFakeStream(t)
		writeHdr(t, s, 0, 4096)

		_, err := readPeekFile(context.Background(), s)
		if !errors.Is(err, errEmptyFileFrame) {
			t.Fatalf("expected errEmptyFileFrame, got %v", err)
		}
	})

	t.Run("SingleChunkPayload", func(t *testing.T) {
		// A short file fits in one buffered chunk. Verifies the
		// fileSize / buf_sz header is parsed correctly and the body
		// message is read in full.
		payload := []byte("hello from the starter\n")
		s := newFakeStream(t)
		writeHdr(t, s, int64(len(payload)), 256*1024)
		writeBody(t, s, payload)

		got, err := readPeekFile(context.Background(), s)
		if err != nil {
			t.Fatalf("readPeekFile: %v", err)
		}
		if string(got) != string(payload) {
			t.Errorf("payload mismatch:\n got: %q\nwant: %q", got, payload)
		}
	})

	t.Run("MultiChunkPayload", func(t *testing.T) {
		// File larger than buf_sz forces multiple chunk messages.
		// Validates the chunk loop terminates exactly at fileSize
		// and concatenates in the right order.
		const bufSz = 16
		payload := []byte(strings.Repeat("abcdefghij", 5)) // 50 bytes
		s := newFakeStream(t)
		writeHdr(t, s, int64(len(payload)), bufSz)
		// Split into chunks of bufSz bytes each.
		for off := 0; off < len(payload); off += bufSz {
			end := off + bufSz
			if end > len(payload) {
				end = len(payload)
			}
			writeBody(t, s, payload[off:end])
		}

		got, err := readPeekFile(context.Background(), s)
		if err != nil {
			t.Fatalf("readPeekFile: %v", err)
		}
		if string(got) != string(payload) {
			t.Errorf("payload mismatch:\n got: %q\nwant: %q", got, payload)
		}
	})
}

// --- Test helpers --------------------------------------------------

// fakeStream is an in-memory CEDAR StreamInterface backed by a
// FIFO of frames. WriteFrame appends; ReadFrame pops from the head.
// IsEncrypted returns true so cedar's message layer takes the
// AES-buffered code path that real starters use.
type fakeStream struct {
	mu     sync.Mutex
	frames []fakeFrame
}

type fakeFrame struct {
	data []byte
	eom  bool
}

func newFakeStream(t *testing.T) *fakeStream {
	t.Helper()
	return &fakeStream{}
}

func (s *fakeStream) ReadFrame(_ context.Context) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.frames) == 0 {
		return nil, false, errors.New("fakeStream: no more frames")
	}
	f := s.frames[0]
	s.frames = s.frames[1:]
	return f.data, f.eom, nil
}

func (s *fakeStream) WriteFrame(_ context.Context, data []byte, isEOM bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Copy so the caller can reuse its buffer.
	cp := make([]byte, len(data))
	copy(cp, data)
	s.frames = append(s.frames, fakeFrame{data: cp, eom: isEOM})
	return nil
}

func (s *fakeStream) IsEncrypted() bool { return true }

// writeHdr emits the get_file header message: int64 fileSize +
// int32 bufSz, terminated by EOM. Mirrors what ReliSock::put_file
// puts on the wire when AES-buffered transfers are in play.
func writeHdr(t *testing.T, s *fakeStream, fileSize int64, bufSz int32) {
	t.Helper()
	msg := message.NewMessageForStream(s)
	if err := msg.PutInt64(context.Background(), fileSize); err != nil {
		t.Fatalf("PutInt64(fileSize): %v", err)
	}
	if err := msg.PutInt32(context.Background(), bufSz); err != nil {
		t.Fatalf("PutInt32(bufSz): %v", err)
	}
	if err := msg.FinishMessage(context.Background()); err != nil {
		t.Fatalf("FinishMessage(hdr): %v", err)
	}
}

// writeBody emits one chunk message: raw bytes + EOM.
func writeBody(t *testing.T, s *fakeStream, data []byte) {
	t.Helper()
	msg := message.NewMessageForStream(s)
	if err := msg.PutBytes(context.Background(), data); err != nil {
		t.Fatalf("PutBytes: %v", err)
	}
	if err := msg.FinishMessage(context.Background()); err != nil {
		t.Fatalf("FinishMessage(body): %v", err)
	}
}
