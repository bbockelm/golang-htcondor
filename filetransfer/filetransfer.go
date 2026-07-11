// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package filetransfer implements the direction-neutral core of HTCondor's
// CEDAR file-transfer wire protocol (FileTransfer::DoUpload / DoDownload in
// src/condor_utils/file_transfer.cpp), factored out so that both the tool-side
// spool/receive paths (github.com/bbockelm/golang-htcondor Schedd methods) and
// the shadow-side transfer server (golang-ap internal/shadow) drive the exact
// same bytes.
//
// One CEDAR file-transfer stream has two roles:
//
//   - the SENDER (C++ DoUpload): sends the final-transfer flag + an xfer_info
//     ad, then a per-file loop of {TransferCommand int, filename, go-ahead
//     handshake, permissions, size, data}, terminated by CommandFinished and a
//     TransferAck exchange. Use SendStream / SendPreamble / SendFile /
//     SendMkdir / SendFinished.
//   - the RECEIVER (C++ DoDownload): the mirror image, driven reactively off
//     the commands the peer sends. Use ReceiveStream with a Sink.
//
// The command names FILETRANS_UPLOAD/FILETRANS_DOWNLOAD are named from the
// server's perspective: on FILETRANS_UPLOAD the server is the SENDER, on
// FILETRANS_DOWNLOAD the server is the RECEIVER. ServeUpload/ServeDownload are
// the server-role entry points a registered cedar command handler calls after
// it has read and matched the TransferKey.
package filetransfer

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// Command is a TransferCommand code, sent as a raw int before each file. The
// values match the C++ enum class TransferCommand (file_transfer.cpp:88).
type Command int32

const (
	// CmdFinished ends the per-file loop.
	CmdFinished Command = 0
	// CmdXferFile transfers one regular file (permissions + size + data).
	CmdXferFile Command = 1
	// CmdEnableEncryption asks the peer to encrypt subsequent files.
	CmdEnableEncryption Command = 2
	// CmdDisableEncryption asks the peer to stop encrypting subsequent files.
	CmdDisableEncryption Command = 3
	// CmdXferX509 transfers an X.509 delegation (unused here).
	CmdXferX509 Command = 4
	// CmdDownloadURL asks the peer to fetch a URL (unused here).
	CmdDownloadURL Command = 5
	// CmdMkdir creates a directory.
	CmdMkdir Command = 6
	// CmdOther carries a sub-command ClassAd (unused here).
	CmdOther Command = 999
)

// goAheadAlways is GO_AHEAD_ALWAYS from file_transfer.cpp: the peer will send
// (or accept) every remaining file without asking again.
const goAheadAlways = 2

// defaultAliveInterval is the keepalive interval advertised in the go-ahead
// handshake (seconds). The value is informational for an in-process gate.
const defaultAliveInterval = 300

// defaultBufferSize is the fallback chunk size (AES_FILE_BUF_SZ in C++) used
// when the peer does not advertise one.
const defaultBufferSize = 256 * 1024

// putFileEOMNum is PUT_FILE_EOM_NUM (reli_sock.cpp): a zero-length file is
// followed by this marker int so the trailing message is non-empty.
const putFileEOMNum = 666

// Options tunes the wire behavior of a stream. The zero value uses the modern
// defaults (go-ahead handshake on, xfer_info ad exchanged).
type Options struct {
	// Logf, if set, receives debug logging.
	Logf func(format string, args ...any)

	// NoGoAhead disables the per-file go-ahead handshake (peer predates 6.9.5).
	// Modern peers require it, so leave false.
	NoGoAhead bool

	// NoXferInfo disables the SandboxSize xfer_info ad in the preamble (peer
	// predates 8.1.0). Modern peers exchange it, so leave false.
	NoXferInfo bool

	// ReceiveAck makes ReceiveStream perform the final TransferAck exchange
	// (receive the sender's ack, then send ours) after CommandFinished. The
	// tool-side TRANSFER_DATA download path leaves this false to preserve its
	// long-standing behavior; the shadow's output-download path sets it true
	// because a modern starter (PeerDoesTransferAck) sends an ack.
	ReceiveAck bool
}

func (o Options) logf(format string, args ...any) {
	if o.Logf != nil {
		o.Logf(format, args...)
	}
}

// FileSpec is one entry to send. Either Dir (a CommandMkdir) or a regular file
// whose bytes come from Open.
type FileSpec struct {
	// WireName is the destination path sent on the wire (relative to the
	// receiver's sandbox).
	WireName string
	// Mode is the Unix permission bits.
	Mode int64
	// Size is the file size in bytes (ignored for Dir).
	Size int64
	// Dir requests a CommandMkdir instead of a file transfer.
	Dir bool
	// Open returns the file contents. Required unless Dir.
	Open func() (io.ReadCloser, error)
}

// SendPlan is an ordered list of files/dirs to upload plus the transfer flag.
type SendPlan struct {
	// Files are sent in order.
	Files []FileSpec
	// FinalTransfer sets the final-transfer flag (1 = files land in the
	// receiver's real sandbox; 0 = intermediate/spool). The shadow uses 1.
	FinalTransfer bool
	// SandboxSize is advertised in the xfer_info ad; if zero it is summed from
	// Files.
	SandboxSize int64
}

// Sink receives files for the RECEIVER role.
type Sink interface {
	// Mkdir handles a CommandMkdir for the given (relative) directory name.
	Mkdir(name string) error
	// File is called for each incoming regular file with its wire name,
	// permission bits and size. Return a WriteCloser to receive the bytes, or
	// (nil, nil) to skip the file (its data is drained off the wire).
	File(name string, mode int64, size int64) (io.WriteCloser, error)
}

// ReceiveResult reports what a receive stream accepted.
type ReceiveResult struct {
	// Files are the wire names of the regular files that were written (not
	// skipped).
	Files []string
	// Dirs are the directory names created.
	Dirs []string
}

// SendState tracks whether GO_AHEAD_ALWAYS has been reached so per-file
// handshakes can be skipped. Callers driving SendFile directly (e.g. the tool's
// tar spool path, which sends files as it streams a tar) keep one across a
// job's files and reset it per job.
type SendState struct {
	// PeerGoesAheadAlways is set once the peer grants GO_AHEAD_ALWAYS.
	PeerGoesAheadAlways bool
	// FileIndex is the count of files sent so far in this stream.
	FileIndex int
}

// ServeUpload is the server entry point for FILETRANS_UPLOAD: the server is the
// SENDER of the plan's files. Call it from a command handler after the
// TransferKey has been read and matched.
func ServeUpload(ctx context.Context, st *stream.Stream, plan SendPlan, opts Options) error {
	return SendStream(ctx, st, plan, opts)
}

// ServeDownload is the server entry point for FILETRANS_DOWNLOAD: the server is
// the RECEIVER of the peer's files, written to sink.
func ServeDownload(ctx context.Context, st *stream.Stream, sink Sink, opts Options) (*ReceiveResult, error) {
	return ReceiveStream(ctx, st, sink, opts)
}

// SendStream performs a whole sender-role stream: preamble, every file, then
// CommandFinished + ack.
func SendStream(ctx context.Context, st *stream.Stream, plan SendPlan, opts Options) error {
	size := plan.SandboxSize
	if size == 0 {
		for _, f := range plan.Files {
			if !f.Dir {
				size += f.Size
			}
		}
	}
	if err := SendPreamble(ctx, st, size, plan.FinalTransfer, opts); err != nil {
		return err
	}
	state := &SendState{}
	for _, f := range plan.Files {
		if f.Dir {
			if err := SendMkdir(ctx, st, f.WireName, opts); err != nil {
				return err
			}
			continue
		}
		if err := SendFile(ctx, st, f, state, opts); err != nil {
			return err
		}
	}
	return SendFinished(ctx, st, opts)
}

// SendPreamble sends the final-transfer flag and (unless NoXferInfo) the
// xfer_info ClassAd carrying SandboxSize, all in one message. Mirrors the head
// of FileTransfer::DoUpload (file_transfer.cpp:4584).
func SendPreamble(ctx context.Context, st *stream.Stream, sandboxSize int64, finalTransfer bool, opts Options) error {
	msg := message.NewMessageForStream(st)
	flag := int32(0)
	if finalTransfer {
		flag = 1
	}
	if err := msg.PutInt32(ctx, flag); err != nil {
		return fmt.Errorf("send final_transfer flag: %w", err)
	}
	if !opts.NoXferInfo {
		xferInfo := classad.New()
		_ = xferInfo.Set("SandboxSize", sandboxSize)
		if err := msg.PutClassAd(ctx, xferInfo); err != nil {
			return fmt.Errorf("send xfer_info: %w", err)
		}
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish preamble: %w", err)
	}
	return nil
}

// SendMkdir sends a CommandMkdir + directory name.
func SendMkdir(ctx context.Context, st *stream.Stream, name string, opts Options) error {
	opts.logf("filetransfer: sending mkdir %q", name)
	msg := message.NewMessageForStream(st)
	if err := msg.PutInt32(ctx, int32(CmdMkdir)); err != nil {
		return fmt.Errorf("send CmdMkdir: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish CmdMkdir: %w", err)
	}
	msg = message.NewMessageForStream(st)
	if err := msg.PutString(ctx, name); err != nil {
		return fmt.Errorf("send dir name: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish dir name: %w", err)
	}
	return nil
}

// SendFile sends one regular file: CommandXferFile, filename, the go-ahead
// handshake (uploader side), permissions, size + buffer size, then the data in
// buffer-sized chunks. Mirrors the per-file body of DoUpload. state carries the
// GO_AHEAD_ALWAYS latch across files.
func SendFile(ctx context.Context, st *stream.Stream, spec FileSpec, state *SendState, opts Options) (err error) {
	opts.logf("filetransfer: sending file %q (%d bytes, mode %o)", spec.WireName, spec.Size, spec.Mode)

	msg := message.NewMessageForStream(st)
	if err := msg.PutInt32(ctx, int32(CmdXferFile)); err != nil {
		return fmt.Errorf("send CmdXferFile: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish CmdXferFile: %w", err)
	}

	msg = message.NewMessageForStream(st)
	if err := msg.PutString(ctx, spec.WireName); err != nil {
		return fmt.Errorf("send filename: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish filename: %w", err)
	}

	if !opts.NoGoAhead && (state.FileIndex == 0 || !state.PeerGoesAheadAlways) {
		if err := uploaderGoAhead(ctx, st, state, opts); err != nil {
			return err
		}
	}
	state.FileIndex++

	// Permissions (get_file_with_permissions sends the mode first).
	msg = message.NewMessageForStream(st)
	if err := msg.PutInt32(ctx, int32(spec.Mode)); err != nil { //nolint:gosec // spec.Mode holds Unix permission bits (<= 0777), always within int32
		return fmt.Errorf("send permissions: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish permissions: %w", err)
	}

	// Size + advertised buffer size (put_file buffered/encrypted framing).
	msg = message.NewMessageForStream(st)
	if err := msg.PutInt64(ctx, spec.Size); err != nil {
		return fmt.Errorf("send file size: %w", err)
	}
	if err := msg.PutInt32(ctx, int32(defaultBufferSize)); err != nil {
		return fmt.Errorf("send buffer size: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish size message: %w", err)
	}

	rc, err := spec.Open()
	if err != nil {
		return fmt.Errorf("open %q: %w", spec.WireName, err)
	}
	defer func() {
		if cerr := rc.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	buf := make([]byte, defaultBufferSize)
	var total int64
	for {
		n, rerr := rc.Read(buf)
		if n > 0 {
			chunk := message.NewMessageForStream(st)
			if err := chunk.PutBytes(ctx, buf[:n]); err != nil {
				return fmt.Errorf("send data chunk for %q: %w", spec.WireName, err)
			}
			if err := chunk.FinishMessage(ctx); err != nil {
				return fmt.Errorf("finish data chunk for %q: %w", spec.WireName, err)
			}
			total += int64(n)
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return fmt.Errorf("read %q: %w", spec.WireName, rerr)
		}
	}
	if total != spec.Size {
		return fmt.Errorf("size mismatch for %q: declared %d, sent %d", spec.WireName, spec.Size, total)
	}
	// A zero-length file carries a trailing PUT_FILE_EOM_NUM (666) marker so the
	// receiver's message is not empty (ReliSock::put_file, reli_sock.cpp:
	// "if (bytes_to_send == 0) put(PUT_FILE_EOM_NUM)"). Non-empty files send no
	// such marker.
	if spec.Size == 0 {
		eom := message.NewMessageForStream(st)
		if err := eom.PutInt32(ctx, putFileEOMNum); err != nil {
			return fmt.Errorf("send zero-length EOM marker for %q: %w", spec.WireName, err)
		}
		if err := eom.FinishMessage(ctx); err != nil {
			return fmt.Errorf("finish zero-length EOM marker for %q: %w", spec.WireName, err)
		}
	}
	return nil
}

// uploaderGoAhead runs the go-ahead handshake from the SENDER's side: send our
// alive_interval, receive the peer's GoAhead, receive the peer's alive_interval,
// send our GoAhead. Matches sendSingleFile in schedd_transfer.go and the
// ReceiveTransferGoAhead/ObtainAndSendTransferGoAhead pairing in C++.
func uploaderGoAhead(ctx context.Context, st *stream.Stream, state *SendState, opts Options) error {
	msg := message.NewMessageForStream(st)
	if err := msg.PutInt32(ctx, int32(defaultAliveInterval)); err != nil {
		return fmt.Errorf("send alive_interval: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish alive_interval: %w", err)
	}

	in := message.NewMessageFromStream(st)
	goAheadAd, err := in.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("receive peer GoAhead: %w", err)
	}
	result, err := goAheadResult(goAheadAd)
	if err != nil {
		return err
	}
	if result == goAheadAlways {
		state.PeerGoesAheadAlways = true
	}

	aliveIn := message.NewMessageFromStream(st)
	if _, err := aliveIn.GetInt32(ctx); err != nil {
		return fmt.Errorf("receive peer alive_interval: %w", err)
	}

	ours := classad.New()
	_ = ours.Set("Result", int64(goAheadAlways))
	_ = ours.Set("Timeout", int64(defaultAliveInterval))
	out := message.NewMessageForStream(st)
	if err := out.PutClassAd(ctx, ours); err != nil {
		return fmt.Errorf("send our GoAhead: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish our GoAhead: %w", err)
	}
	opts.logf("filetransfer: uploader go-ahead complete (always=%v)", state.PeerGoesAheadAlways)
	return nil
}

// SendFinished sends CommandFinished and performs the sender-side TransferAck
// exchange: send our ack (Result=0), receive the peer's ack. Mirrors
// ExitDoUpload (file_transfer.cpp:6101) and sendCommandFinished.
func SendFinished(ctx context.Context, st *stream.Stream, opts Options) error {
	msg := message.NewMessageForStream(st)
	if err := msg.PutInt32(ctx, int32(CmdFinished)); err != nil {
		return fmt.Errorf("send CmdFinished: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish CmdFinished: %w", err)
	}

	if err := sendTransferAck(ctx, st); err != nil {
		return err
	}

	in := message.NewMessageFromStream(st)
	ackAd, err := in.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("receive TransferAck: %w", err)
	}
	if err := checkAck(ackAd); err != nil {
		return err
	}
	opts.logf("filetransfer: upload finished, ack ok")
	return nil
}

// ReceiveStream performs a whole receiver-role stream: read the preamble, then
// the per-file loop, writing files to sink, until CommandFinished. If
// opts.ReceiveAck it then does the receiver-side TransferAck exchange.
func ReceiveStream(ctx context.Context, st *stream.Stream, sink Sink, opts Options) (*ReceiveResult, error) {
	// Preamble: final-transfer flag + optional xfer_info ad, one message.
	head := message.NewMessageFromStream(st)
	if _, err := head.GetInt32(ctx); err != nil {
		return nil, fmt.Errorf("receive final_transfer flag: %w", err)
	}
	if !opts.NoXferInfo {
		if _, err := head.GetClassAd(ctx); err != nil {
			return nil, fmt.Errorf("receive xfer_info: %w", err)
		}
	}

	res := &ReceiveResult{}
	state := &recvState{}
	for {
		cmdMsg := message.NewMessageFromStream(st)
		cmdInt, err := cmdMsg.GetInt32(ctx)
		if err != nil {
			return nil, fmt.Errorf("receive transfer command: %w", err)
		}
		switch Command(cmdInt) {
		case CmdFinished:
			if opts.ReceiveAck {
				if err := receiverFinalAck(ctx, st, opts); err != nil {
					return nil, err
				}
			}
			return res, nil

		case CmdMkdir:
			nameMsg := message.NewMessageFromStream(st)
			name, err := nameMsg.GetString(ctx)
			if err != nil {
				return nil, fmt.Errorf("receive dir name: %w", err)
			}
			if err := sink.Mkdir(name); err != nil {
				return nil, fmt.Errorf("mkdir %q: %w", name, err)
			}
			res.Dirs = append(res.Dirs, name)

		case CmdXferFile:
			name, err := receiveOneFile(ctx, st, sink, state, opts)
			if err != nil {
				return nil, err
			}
			if name != "" {
				res.Files = append(res.Files, name)
			}

		case CmdEnableEncryption, CmdDisableEncryption:
			// The cedar session is already encrypted end-to-end; these are
			// no-ops for us. They are standalone commands (no filename follows)
			// in the flows we serve.
			opts.logf("filetransfer: ignoring encryption toggle command %d", cmdInt)

		default:
			return nil, fmt.Errorf("filetransfer: unsupported transfer command %d", cmdInt)
		}
	}
}

type recvState struct {
	goAheadAlways bool
	fileIndex     int
}

// receiveOneFile reads one CommandXferFile body: filename, go-ahead (downloader
// side), permissions, size + buffer size, then the data. Returns the wire name
// of the file written, or "" if the sink skipped it.
func receiveOneFile(ctx context.Context, st *stream.Stream, sink Sink, state *recvState, opts Options) (string, error) {
	nameMsg := message.NewMessageFromStream(st)
	name, err := nameMsg.GetString(ctx)
	if err != nil {
		return "", fmt.Errorf("receive filename: %w", err)
	}

	if !opts.NoGoAhead && (state.fileIndex == 0 || !state.goAheadAlways) {
		if err := downloaderGoAhead(ctx, st, state, opts); err != nil {
			return "", err
		}
	}
	state.fileIndex++

	permMsg := message.NewMessageFromStream(st)
	mode, err := permMsg.GetInt64(ctx)
	if err != nil {
		return "", fmt.Errorf("receive permissions for %q: %w", name, err)
	}

	sizeMsg := message.NewMessageFromStream(st)
	size, err := sizeMsg.GetInt64(ctx)
	if err != nil {
		return "", fmt.Errorf("receive size for %q: %w", name, err)
	}
	bufSize, err := sizeMsg.GetInt32(ctx)
	if err != nil {
		return "", fmt.Errorf("receive buffer size for %q: %w", name, err)
	}
	chunkSize := int64(bufSize)
	if chunkSize <= 0 {
		chunkSize = defaultBufferSize
	}

	w, err := sink.File(name, mode, size)
	if err != nil {
		return "", fmt.Errorf("sink open %q: %w", name, err)
	}

	var read int64
	for read < size {
		want := size - read
		if want > chunkSize {
			want = chunkSize
		}
		chunk := message.NewMessageFromStream(st)
		data, err := chunk.GetBytes(ctx, int(want))
		if err != nil {
			if w != nil {
				_ = w.Close()
			}
			return "", fmt.Errorf("receive data chunk for %q: %w", name, err)
		}
		if w != nil {
			if _, werr := w.Write(data); werr != nil {
				_ = w.Close()
				return "", fmt.Errorf("write %q: %w", name, werr)
			}
		}
		read += int64(len(data))
	}
	// A zero-length file is followed by the PUT_FILE_EOM_NUM (666) marker
	// (ReliSock::get_file "if (filesize == 0)"); consume it so it is not misread
	// as the next transfer command.
	if size == 0 {
		eom := message.NewMessageFromStream(st)
		marker, err := eom.GetInt32(ctx)
		if err != nil {
			if w != nil {
				_ = w.Close()
			}
			return "", fmt.Errorf("receive zero-length EOM marker for %q: %w", name, err)
		}
		if marker != putFileEOMNum {
			opts.logf("filetransfer: unexpected zero-length marker %d for %q (want %d)", marker, name, putFileEOMNum)
		}
	}
	if w == nil {
		opts.logf("filetransfer: skipped file %q (%d bytes drained)", name, size)
		return "", nil
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("close %q: %w", name, err)
	}
	opts.logf("filetransfer: received file %q (%d bytes, mode %o)", name, size, mode)
	return name, nil
}

// downloaderGoAhead runs the go-ahead handshake from the RECEIVER's side:
// receive the peer's alive_interval, send our GoAhead, send our alive_interval,
// receive the peer's GoAhead. Matches receiveJobFiles in schedd_transfer.go.
func downloaderGoAhead(ctx context.Context, st *stream.Stream, state *recvState, opts Options) error {
	aliveIn := message.NewMessageFromStream(st)
	if _, err := aliveIn.GetInt32(ctx); err != nil {
		return fmt.Errorf("receive peer alive_interval: %w", err)
	}

	ours := classad.New()
	_ = ours.Set("Result", int64(goAheadAlways))
	_ = ours.Set("Timeout", int64(defaultAliveInterval))
	out := message.NewMessageForStream(st)
	if err := out.PutClassAd(ctx, ours); err != nil {
		return fmt.Errorf("send our GoAhead: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish our GoAhead: %w", err)
	}

	aliveOut := message.NewMessageForStream(st)
	if err := aliveOut.PutInt32(ctx, int32(defaultAliveInterval)); err != nil {
		return fmt.Errorf("send alive_interval: %w", err)
	}
	if err := aliveOut.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish alive_interval: %w", err)
	}

	in := message.NewMessageFromStream(st)
	goAheadAd, err := in.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("receive peer GoAhead: %w", err)
	}
	result, err := goAheadResult(goAheadAd)
	if err != nil {
		return err
	}
	if result == goAheadAlways {
		state.goAheadAlways = true
	}
	opts.logf("filetransfer: downloader go-ahead complete (always=%v)", state.goAheadAlways)
	return nil
}

// receiverFinalAck performs the receiver-side TransferAck exchange after
// CommandFinished: receive the sender's ack, then send ours (Result=0). Mirrors
// GetTransferAck+SendTransferAck at the tail of DoDownload.
func receiverFinalAck(ctx context.Context, st *stream.Stream, opts Options) error {
	in := message.NewMessageFromStream(st)
	ackAd, err := in.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("receive sender TransferAck: %w", err)
	}
	if err := checkAck(ackAd); err != nil {
		return err
	}
	if err := sendTransferAck(ctx, st); err != nil {
		return err
	}
	opts.logf("filetransfer: download finished, ack exchanged")
	return nil
}

// sendTransferAck sends a success TransferAck (Result=0 + empty TransferStats).
func sendTransferAck(ctx context.Context, st *stream.Stream) error {
	ack := classad.New()
	_ = ack.Set("Result", int64(0))
	_ = ack.Set("TransferStats", classad.New())
	msg := message.NewMessageForStream(st)
	if err := msg.PutClassAd(ctx, ack); err != nil {
		return fmt.Errorf("send TransferAck: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("finish TransferAck: %w", err)
	}
	return nil
}

// goAheadResult extracts a positive go-ahead Result from a GoAhead ad, or errors.
func goAheadResult(ad *classad.ClassAd) (int64, error) {
	expr, ok := ad.Lookup("Result")
	if !ok {
		return 0, fmt.Errorf("GoAhead missing Result")
	}
	result, err := expr.Eval(nil).IntValue()
	if err != nil || result <= 0 {
		return 0, fmt.Errorf("GoAhead failed: Result=%v (err=%w)", result, err)
	}
	return result, nil
}

// checkAck verifies a TransferAck ad reports success (Result==0), extracting the
// hold reason on failure.
func checkAck(ad *classad.ClassAd) error {
	expr, ok := ad.Lookup("Result")
	if !ok {
		return fmt.Errorf("TransferAck missing Result")
	}
	result, err := expr.Eval(nil).IntValue()
	if err != nil {
		return fmt.Errorf("TransferAck Result not an int: %w", err)
	}
	if result != 0 {
		if hr, ok := ad.Lookup("HoldReason"); ok {
			if s, serr := hr.Eval(nil).StringValue(); serr == nil && s != "" {
				return fmt.Errorf("transfer failed (Result=%d): %s", result, s)
			}
		}
		return fmt.Errorf("transfer failed (Result=%d)", result)
	}
	return nil
}
