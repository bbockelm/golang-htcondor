package httpserver

import (
	"archive/tar"
	"bytes"
	"sort"
	"strings"
)

// tarNameRecorder watches a tar stream go past and records the names of
// the regular files in it, so an upload can report the ones the schedd
// dropped. It is an io.Writer fed by an io.TeeReader: the bytes are
// already being read by the spool path, and this sees a copy of them
// without buffering the payload or running a second goroutine.
//
// It is deliberately conservative. Anything it cannot fully account for
// -- a header it does not understand, an extension that renames the
// following entry, a truncated stream -- sets unreliable, and an
// unreliable recorder reports nothing. A missed warning is a return to
// the status quo; a warning naming the wrong file would send someone
// looking for a bug that is not there.
type tarNameRecorder struct {
	buf        bytes.Buffer // partial header block
	skip       int64        // payload bytes still to pass before the next header
	names      []string
	unreliable bool
	done       bool // saw the end-of-archive marker
}

const tarBlockSize = 512

func newTarNameRecorder() *tarNameRecorder { return &tarNameRecorder{} }

// Write consumes a copy of the tar stream. It never returns an error:
// failing the write would fail the upload it is only observing.
func (t *tarNameRecorder) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if t.done || t.unreliable {
			return n, nil
		}
		// Pass over a file's payload without looking at it.
		if t.skip > 0 {
			advance := int64(len(p))
			if advance > t.skip {
				advance = t.skip
			}
			t.skip -= advance
			p = p[advance:]
			continue
		}
		// Accumulate one 512-byte header block; a Write may split it.
		want := tarBlockSize - t.buf.Len()
		if want > len(p) {
			t.buf.Write(p)
			return n, nil
		}
		t.buf.Write(p[:want])
		p = p[want:]
		block := t.buf.Bytes()
		t.consumeHeader(block)
		t.buf.Reset()
	}
	return n, nil
}

// consumeHeader interprets one header block and sets up the skip for its
// payload.
func (t *tarNameRecorder) consumeHeader(block []byte) {
	if isZeroBlock(block) {
		// First of the two end-of-archive blocks. Everything after is
		// padding, so stop here rather than trying to parse it.
		t.done = true
		return
	}
	// A ustar magic is the cheap check that we are actually looking at a
	// header and not at payload we lost sync with.
	if !bytes.HasPrefix(block[257:263], []byte("ustar")) {
		t.unreliable = true
		return
	}
	typeflag := block[156]
	switch typeflag {
	case tar.TypeXHeader, tar.TypeXGlobalHeader, tar.TypeGNULongName, tar.TypeGNULongLink:
		// These rename or annotate the entry that follows. Reading the
		// name off the next header would report the placeholder
		// ("././@PaxHeader") instead of the real one.
		t.unreliable = true
		return
	}
	size, ok := parseOctal(block[124:136])
	if !ok {
		t.unreliable = true
		return
	}
	if typeflag == tar.TypeReg || typeflag == tar.TypeRegA {
		name := cString(block[0:100])
		if prefix := cString(block[345:500]); prefix != "" {
			name = prefix + "/" + name
		}
		if name != "" && !strings.HasSuffix(name, "/") {
			t.names = append(t.names, name)
		}
	}
	// Payload is padded out to a block boundary.
	t.skip = (size + tarBlockSize - 1) / tarBlockSize * tarBlockSize
}

// Unexpected returns the recorded names absent from expected, sorted and
// deduplicated. It returns nil when the recorder lost confidence in what
// it saw -- see the type comment.
//
// The comparison is exact because the schedd's is: sendJobFilesFromTar
// matches a tar entry's name against the allow-set verbatim, so a file
// uploaded as "data/x.csv" against an allow-set of "x.csv" really is
// dropped, and saying so is the point.
func (t *tarNameRecorder) Unexpected(expected []string) []string {
	if t.unreliable {
		return nil
	}
	allow := make(map[string]bool, len(expected))
	for _, e := range expected {
		allow[e] = true
	}
	seen := make(map[string]bool, len(t.names))
	var out []string
	for _, name := range t.names {
		if allow[name] || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func isZeroBlock(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// cString reads a NUL-terminated field.
func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// parseOctal reads tar's NUL/space-padded octal numeric fields. The GNU
// base-256 extension (high bit set, used for sizes over 8 GiB) is not
// handled: it reports failure, which makes the recorder unreliable and
// silences the warning rather than mis-parsing a size and losing sync.
func parseOctal(b []byte) (int64, bool) {
	s := strings.Trim(cString(b), " ")
	if s == "" {
		return 0, true
	}
	var v int64
	for _, c := range s {
		if c < '0' || c > '7' {
			return 0, false
		}
		v = v*8 + int64(c-'0')
		if v < 0 {
			return 0, false
		}
	}
	return v, true
}
