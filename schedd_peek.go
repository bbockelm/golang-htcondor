// Implementation of condor_tail's "peek" of a running job's stdout/stderr,
// exposed as a Go-native call. Mirrors the C++ tool flow:
//
//   1. GET_JOB_CONNECT_INFO to schedd: returns StarterIpAddr + ClaimId
//      for an on-demand session the schedd minted on the starter on the
//      user's behalf. Same call condor_ssh_to_job uses; we share the
//      JobConnectInfo / buildAESStarterSession scaffolding with it.
//
//   2. STARTER_PEEK command (CEDAR id 1503) over the resumed session,
//      with a request ClassAd describing which streams to fetch and the
//      offsets / max byte cap.
//
//   3. Read response ClassAd. On success it carries TransferFiles (a
//      mixed list of ints {0,1} for stdout/stderr) and TransferOffsets
//      (the absolute file offset *after* this read, for follow-mode).
//
//   4. For each file, read the CEDAR get_file frame: an int64 filesize +
//      int32 buffer-size header in one message, then chunked content (each
//      chunk is its own message terminated by EOM). With AES-GCM in play
//      (which is what cedar's stream layer ships) this is the buffered
//      variant — see ReliSock::get_file in
//      reference/htcondor/src/condor_io/reli_sock.cpp:1979.
//
//   5. Final int32 remote_file_count + EOM closes the protocol.
//
// We only support stdout/stderr here. Arbitrary transfer_output_files
// would be a one-line extension: add filenames to the request ad's
// TransferFiles list and read the matching entries out of the response.
// The condor_tail "follow" affordance is left to the caller — the
// returned offsets can be fed back in for an incremental next call.

package htcondor

import (
	"context"
	"errors"
	"fmt"
	"os"

	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
)

// peekDebug toggles wire-level diagnostic logging via PEEK_DEBUG=1.
// Off by default since the wire is otherwise quiet.
var peekDebug = os.Getenv("PEEK_DEBUG") != ""

// starterPeekCommand is the CEDAR command id for STARTER_PEEK
// (STARTER_COMMANDS_BASE = 1500, +3). See
// reference/htcondor/src/condor_includes/condor_commands.h:505.
const starterPeekCommand = 1503

// Protocol note: the C++ ReliSock::put_file appends a sentinel int
// (666 — see reli_sock.cpp:1886) after a zero-byte file's header.
// The matching get_file consumes it; we don't, because cedar's Go
// bindings don't support the prepare_for_nobuffering trick HTCondor
// uses to read raw ints between framed messages. Consequence: an
// empty file forces us to close the connection — see readPeekFile.

// errEmptyFileFrame is returned by readPeekFile when it receives an
// empty-file header. Callers treat this as "valid empty payload, but
// the stream can't be reused". Not exported; clients see PeekedStream
// with len(Bytes)==0 instead.
var errEmptyFileFrame = errors.New("peek: empty file frame; connection cannot be reused")

// DefaultPeekMaxBytes is the per-call cap when the caller doesn't
// supply one. The C++ tool defaults to 1024 to be friendly on
// terminals; for a UI poll we want enough for a useful snapshot
// while still keeping each round-trip cheap.
const DefaultPeekMaxBytes = 64 * 1024

// PeekRequest controls a single STARTER_PEEK call.
//
// An offset of -1 asks the starter to "tail" — return the last
// MaxBytes of the file. After a successful call the response
// carries the new absolute offset; pass that back in on the next
// call to stream incremental chunks (the same trick the
// condor_tail -follow loop uses).
type PeekRequest struct {
	Stdout       bool
	StdoutOffset int64
	Stderr       bool
	StderrOffset int64
	// MaxBytes is the total cap shared across the requested
	// streams. The starter splits it across files internally.
	// Zero or negative falls back to DefaultPeekMaxBytes.
	MaxBytes int64

	// CCBStreaming reaches a starter behind CCB by having the broker relay
	// the connection instead of having the execute node dial back to us.
	// Set it when this process cannot accept inbound connections -- see
	// JobShellOptions.CCBStreaming, which is the same choice for the same
	// reason on the shell path.
	CCBStreaming bool
}

// PeekedStream is what came back for one of the requested streams.
type PeekedStream struct {
	Bytes  []byte
	Offset int64 // absolute byte offset at the *end* of Bytes
}

// PeekResult carries whichever streams the caller asked for. Each
// pointer is non-nil iff the matching request flag was set AND the
// starter returned a payload for it.
type PeekResult struct {
	Stdout *PeekedStream
	Stderr *PeekedStream
}

// peekConnectInfoMaxWait bounds the wait for the starter's address to
// show up. Shorter than the shell path's 30s: a tail is a poll, and a
// caller polling every few seconds would rather be told "not yet" than
// have one call block for half a minute.
const peekConnectInfoMaxWait = 10 * time.Second

// PeekJobOutput is the public entry point. It looks up the running
// job's starter, resumes the schedd-minted session, runs one
// STARTER_PEEK round, and returns whichever streams were requested.
func (s *Schedd) PeekJobOutput(ctx context.Context, cluster, proc int, req PeekRequest) (*PeekResult, error) {
	if !req.Stdout && !req.Stderr {
		return nil, fmt.Errorf("PeekJobOutput: at least one of Stdout or Stderr must be set")
	}
	if req.MaxBytes <= 0 {
		req.MaxBytes = DefaultPeekMaxBytes
	}
	// Same backoff the shell path uses, for the same race: a job that has
	// just reached Running is not yet one the schedd can hand out a
	// starter address for, and it answers "Failed to read address of
	// starter for this job" until the startd has registered it. Calling
	// straight through meant a caller who polled for Running and then
	// tailed -- which is the obvious thing to do, and what both the SPA
	// and an agent do -- got that error instead of the first few lines
	// of output.
	info, err := getJobConnectInfoWithBackoff(ctx, s, cluster, proc, peekConnectInfoMaxWait)
	if err != nil {
		return nil, fmt.Errorf("get_job_connect_info: %w", err)
	}
	result, unread, err := info.peekOutput(ctx, req)
	if err != nil {
		return nil, err
	}

	// An empty file frame ends the connection mid-response (see
	// errEmptyFileFrame), so any stream the starter had not sent yet went
	// unread. That is not a rare case: in follow mode a stream that has
	// not grown since the last call sends exactly that frame, so a job
	// writing only to stderr -- or any job whose stdout has gone quiet --
	// would report "nothing new" on stderr forever, which is the one
	// answer worse than an error here.
	//
	// The connection is dead but the starter contact is still good, so
	// ask again for just the stream we missed. A single-stream retry has
	// nothing queued behind it, so this does not chain.
	for _, kind := range unread {
		sub := req
		sub.Stdout = kind == peekKindStdout
		sub.Stderr = kind == peekKindStderr
		more, _, err := info.peekOutput(ctx, sub)
		if err != nil {
			// Leave the stream absent rather than present-and-empty:
			// a nil stream says "not read", a zero-byte one claims
			// the file did not grow.
			if peekDebug {
				fmt.Fprintf(os.Stderr, "peek: retry for %v failed: %v\n", kind, err)
			}
			continue
		}
		if kind == peekKindStdout {
			result.Stdout = more.Stdout
		} else {
			result.Stderr = more.Stderr
		}
	}
	return result, nil
}

// peekOutput is the per-(starter,session) half of the call. Held as
// a JobConnectInfo method for symmetry with startSSHDOnStarter.
// peekOutput runs one STARTER_PEEK round trip. It also reports which
// requested streams it never got to read, because an empty file frame
// forces the connection closed before the later frames arrive.
func (info *JobConnectInfo) peekOutput(ctx context.Context, req PeekRequest) (*PeekResult, []peekFileKind, error) {
	htcondorClient, err := info.dialStarter(ctx, starterPeekCommand, req.CCBStreaming)
	if err != nil {
		return nil, nil, fmt.Errorf("resume starter session at %s: %w", info.StarterAddr, err)
	}
	defer func() { _ = htcondorClient.Close() }()

	stream := htcondorClient.GetStream()

	// --- Send the request ad ----------------------------------------
	// Attribute names mirror DCStarter::peek
	// (reference/htcondor/src/condor_daemon_client/dc_starter.cpp:464).
	// The trap: the C++ macros ATTR_JOB_OUTPUT and ATTR_JOB_ERROR
	// expand to "Out" and "Err" — NOT "JobOutput" / "JobError" as
	// their names would suggest. Sending the wrong names doesn't
	// fail the round-trip; the starter ignores unknown attrs, sees
	// no streams requested, and returns an empty TransferFiles list.
	// Caught the hard way the first time live-tail returned no bytes
	// from a job that SSH could see clearly.
	reqAd := classad.New()
	_ = reqAd.Set("Out", req.Stdout)
	_ = reqAd.Set("OutOffset", req.StdoutOffset)
	_ = reqAd.Set("Err", req.Stderr)
	_ = reqAd.Set("ErrOffset", req.StderrOffset)
	_ = reqAd.Set("MaxTransferBytes", req.MaxBytes)
	_ = reqAd.Set("CondorVersion", wireVersionString())

	reqMsg := message.NewMessageForStream(stream)
	if err := reqMsg.PutClassAd(ctx, reqAd); err != nil {
		return nil, nil, fmt.Errorf("send peek request ad: %w", err)
	}
	if err := reqMsg.FinishMessage(ctx); err != nil {
		return nil, nil, fmt.Errorf("finish peek request: %w", err)
	}

	// --- Read the response ad ---------------------------------------
	respMsg := message.NewMessageFromStream(stream)
	respAd, err := respMsg.GetClassAd(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("read peek response ad: %w", err)
	}
	success, _ := respAd.EvaluateAttrBool("Result")
	if !success {
		errStr, _ := respAd.EvaluateAttrString("ErrorString")
		if errStr == "" {
			errStr = "starter rejected peek request"
		}
		return nil, nil, fmt.Errorf("starter peek failed: %s", errStr)
	}

	// TransferFiles entries are *either* string filenames or
	// integers (0=stdout, 1=stderr). TransferOffsets is a parallel
	// list of integer absolute file offsets.
	files, err := lookupListValues(respAd, "TransferFiles")
	if err != nil {
		return nil, nil, err
	}
	offsets, err := lookupListValues(respAd, "TransferOffsets")
	if err != nil {
		return nil, nil, err
	}
	walk, err := walkPeekFiles(ctx, stream, files, offsets, req)
	if err != nil {
		return nil, nil, err
	}
	result, unread, streamUnusable := walk.result, walk.unread, walk.connectionDead

	// Final remote_file_count + EOM. We don't strictly need the
	// number — our walk above is authoritative — and we skip it
	// entirely if streamUnusable is set, because in that case we
	// stopped reading mid-response and can't resync. The connection
	// is closed via the deferred Close() below, which is the cleanup
	// the starter expects regardless.
	if !streamUnusable {
		tailMsg := message.NewMessageFromStream(stream)
		_, _ = tailMsg.GetInt32(ctx)
	}

	return result, unread, nil
}

// peekWalk separates "this stream reported no new bytes" from "we never
// got to ask", and both from "the connection is spent". An empty frame
// on the last file leaves nothing unread but still kills the socket.
type peekWalk struct {
	result *PeekResult
	// unread lists requested streams whose frames were still queued
	// when the connection died. Their PeekedStream is absent, not
	// empty, so a caller cannot mistake them for an idle file.
	unread []peekFileKind
	// connectionDead reports that an empty frame was seen, so the
	// trailing count must not be read.
	connectionDead bool
}

type peekFileKind int

const (
	peekKindOther peekFileKind = iota
	peekKindStdout
	peekKindStderr
)

// decodePeekFileKind classifies one entry of the response's
// TransferFiles list. The C++ code emits raw integers 0/1 for
// stdout/stderr and string filenames for everything else.
func decodePeekFileKind(v classad.Value) peekFileKind {
	if v.IsInteger() {
		n, err := v.IntValue()
		if err != nil {
			return peekKindOther
		}
		switch n {
		case 0:
			return peekKindStdout
		case 1:
			return peekKindStderr
		}
	}
	// String entries are user-named output files — not handled.
	return peekKindOther
}

// lookupListValues pulls a list-typed attribute out of an ad and
// returns its element values. Used for TransferFiles /
// TransferOffsets in the peek response.
func lookupListValues(ad *classad.ClassAd, name string) ([]classad.Value, error) {
	expr, ok := ad.Lookup(name)
	if !ok || expr == nil {
		return nil, fmt.Errorf("missing %s in peek response", name)
	}
	val := expr.Eval(nil)
	if !val.IsList() {
		return nil, fmt.Errorf("%s is not a list", name)
	}
	elems, err := val.ListValue()
	if err != nil {
		return nil, fmt.Errorf("%s list: %w", name, err)
	}
	return elems, nil
}

// readPeekFile consumes one CEDAR get_file frame off the stream:
//
//   - One message: int64 filesize + int32 buf_sz + EOM.
//     (The buf_sz field appears only when the stream is in AES-GCM
//     buffered mode, which it is for us — every modern HTCondor
//     speaks AES and cedar's stream layer mirrors that.)
//
//   - Per chunk while bytes remain: a separate message containing
//     up to buf_sz bytes terminated by EOM.
//
// Returns the full payload as a single []byte. The starter caps
// total bytes at MaxTransferBytes from the request, so the buffer
// won't grow unbounded.
func readPeekFile(ctx context.Context, stream cedarStream) ([]byte, error) {
	hdrMsg := message.NewMessageFromStream(stream)
	fileSize, err := hdrMsg.GetInt64(ctx)
	if err != nil {
		return nil, fmt.Errorf("read filesize header: %w", err)
	}
	bufSize, err := hdrMsg.GetInt32(ctx)
	if err != nil {
		return nil, fmt.Errorf("read buffer-size header: %w", err)
	}
	if peekDebug {
		fmt.Fprintf(os.Stderr, "peek: file frame header: size=%d bufSize=%d\n", fileSize, bufSize)
	}
	if fileSize <= 0 {
		// Empty file. The C++ ReliSock::put_file appends a 4-byte
		// PUT_FILE_EOM_NUM (666) marker after the header EOM in this
		// case (reli_sock.cpp:2430), with the matching get_file
		// consuming it via a special "no buffering" mode that
		// suspends CEDAR's message framing for one int. cedar's Go
		// bindings don't expose that mode, so we can't cleanly drain
		// the marker and pick up the next file's header.
		//
		// The signal back is errEmptyFileFrame: a sentinel error the
		// caller treats as "valid empty payload, but the stream
		// can't be reused". Connections are one-shot per peek call
		// in our flow (defer Close in peekOutput), so abandoning the
		// rest of the response is fine — multi-stream peeks where
		// at least one stream has new bytes still work because we
		// process files in order, and the SPA polls one stream at a
		// time anyway.
		return nil, errEmptyFileFrame
	}

	// Defensive cap on the per-chunk size we'll allocate. The
	// sender promises chunks no larger than bufSize; a hostile
	// peer that lies could force us to allocate gigabytes per
	// chunk otherwise.
	const maxChunkAlloc = 1 * 1024 * 1024
	chunkCap := int64(bufSize)
	if chunkCap <= 0 || chunkCap > maxChunkAlloc {
		chunkCap = 256 * 1024
	}

	out := make([]byte, 0, fileSize)
	read := int64(0)
	for read < fileSize {
		want := fileSize - read
		if want > chunkCap {
			want = chunkCap
		}
		chunkMsg := message.NewMessageFromStream(stream)
		chunk, err := chunkMsg.GetBytes(ctx, int(want))
		if err != nil {
			return nil, fmt.Errorf("read chunk at offset %d: %w", read, err)
		}
		out = append(out, chunk...)
		read += int64(len(chunk))
		if len(chunk) == 0 {
			return nil, fmt.Errorf("zero-byte chunk at offset %d (size mismatch)", read)
		}
	}
	return out, nil
}

// cedarStream is the minimal subset of cedar's *stream.Stream we
// touch. Pulled out as an interface so tests can fake the wire.
type cedarStream interface {
	message.StreamInterface
}

// walkPeekFiles reads the file frames of one peek response in the order
// the starter listed them, and reports the requested streams it could
// not reach.
//
// It is a separate function so the empty-frame case can be tested
// without a starter: an empty stdout frame kills the connection before
// stderr's frame arrives, and reporting that stream as zero bytes
// rather than unread is indistinguishable, to a caller, from a file
// that did not grow.
func walkPeekFiles(ctx context.Context, stream cedarStream, files, offsets []classad.Value, req PeekRequest) (peekWalk, error) {

	// Compute the *next* offset for each stream as
	// (where-this-read-started) + (bytes-we-received). Where the
	// read started depends on the request:
	//
	//   - If the caller passed a non-negative offset (follow
	//     mode), the read started exactly there. We trust our own
	//     value rather than the response's TransferOffsets[i],
	//     because the C++ starter has an asymmetric quirk: for
	//     stdout the response's offset is hardcoded to 0 in
	//     follow mode (starter.cpp pushes a literal 0 for
	//     stdout's slot but stderr_off for stderr), so trusting
	//     the response would silently rewind stdout to byte
	//     `bytes_received` on every follow call.
	//
	//   - If the caller passed -1 (tail), the starter chose the
	//     start offset for us; it overrides the response slot
	//     with the actual start position in that path, so we use
	//     the response value.
	result := &PeekResult{}
	streamUnusable := false
	var unread []peekFileKind
	for i, fileVal := range files {
		kind := decodePeekFileKind(fileVal)
		respOffset := int64(0)
		if i < len(offsets) && offsets[i].IsInteger() {
			if v, err := offsets[i].IntValue(); err == nil {
				respOffset = v
			}
		}
		var buf []byte
		var err error
		if streamUnusable {
			// The connection died on an earlier frame, so this stream's
			// bytes are still sitting at the starter. Say so instead of
			// reporting it empty.
			if (kind == peekKindStdout && req.Stdout) || (kind == peekKindStderr && req.Stderr) {
				unread = append(unread, kind)
			}
		} else {
			buf, err = readPeekFile(ctx, stream)
			if errors.Is(err, errEmptyFileFrame) {
				// Empty payload is a valid result; we just can't
				// keep reading further frames on this connection
				// (see errEmptyFileFrame for why). Treat as zero
				// bytes for THIS stream, then mark subsequent
				// streams as "couldn't fetch on this round".
				buf = nil
				err = nil
				streamUnusable = true
			}
			if err != nil {
				return peekWalk{}, fmt.Errorf("read peek file %d: %w", i, err)
			}
		}
		if len(unread) > 0 && unread[len(unread)-1] == kind {
			continue
		}
		nextOffset := func(reqOffset int64) int64 {
			if reqOffset < 0 {
				return respOffset + int64(len(buf))
			}
			return reqOffset + int64(len(buf))
		}
		switch kind {
		case peekKindStdout:
			result.Stdout = &PeekedStream{Bytes: buf, Offset: nextOffset(req.StdoutOffset)}
		case peekKindStderr:
			result.Stderr = &PeekedStream{Bytes: buf, Offset: nextOffset(req.StderrOffset)}
		default:
			// Named files: ignored for the stdout/stderr-only API
			// surface. Drop the bytes on the floor; the wire is
			// still positioned correctly for the next iteration.
		}
	}

	return peekWalk{result: result, unread: unread, connectionDead: streamUnusable}, nil
}
