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

// Package syscalls implements the STARTER-side (client) senders for
// HTCondor's shadow<->starter remote-syscall protocol. It is the client
// mirror of the shadow-side server in github.com/bbockelm/golang-ap's
// shadow package (shadow/syscalls.go). Each method here is a byte-exact
// peer of the corresponding C++ sender in
// src/condor_starter.V6.1/NTsenders.cpp.
//
// Framing (NTsenders.cpp / NTreceivers.cpp): every request is a single
// CEDAR message [int syscall#, args..., EOM]; every reply is a single
// CEDAR message [int rval, (int terrno if rval<0), payload..., EOM]. The
// ulog op is the sole exception: it has no reply at all. The job_exit op is
// the final RPC of a run (the C++ shadow's RemoteSyscallResult::ExpectedClose).
package syscalls

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// Remote syscall numbers, verified against
// src/condor_includes/condor_sys.h in HTCondor. Shared names with the
// golang-ap shadow server where sensible.
const (
	OpJobTermination      = -82 // CONDOR_job_termination (condor_sys.h:23)
	OpRegisterJobInfo     = -81 // CONDOR_register_job_info (condor_sys.h:24)
	OpBeginExecution      = -78 // CONDOR_begin_execution (condor_sys.h:27)
	OpRegisterStarterInfo = -77 // CONDOR_register_starter_info (condor_sys.h:28)
	OpGetUserInfo         = -76 // CONDOR_get_user_info (condor_sys.h:29)
	OpJobExit             = -65 // CONDOR_job_exit (condor_sys.h:40)
	OpGetJobInfo          = -63 // CONDOR_get_job_info (condor_sys.h:42)
	OpUlog                = 284 // CONDOR_ulog (condor_sys.h:387)
	OpGetSecSessionInfo   = 288 // CONDOR_get_sec_session_info (condor_sys.h:391)
)

// Job-exit reason codes from src/condor_includes/exit.h. These are the
// JOB_* values the starter passes to JobExit's reason argument. Each is
// (offset + EXIT_CODE_OFFSET) where EXIT_CODE_OFFSET == 100.
const (
	JobExited                = 100 // JOB_EXITED (0 + EXIT_CODE_OFFSET)
	JobKilled                = 102 // JOB_KILLED (2 + EXIT_CODE_OFFSET)
	JobCoredumped            = 103 // JOB_COREDUMPED (3 + EXIT_CODE_OFFSET)
	JobShouldRequeue         = 107 // JOB_SHOULD_REQUEUE (7 + EXIT_CODE_OFFSET)
	JobNotStarted            = 108 // JOB_NOT_STARTED (8 + EXIT_CODE_OFFSET)
	JobExecFailed            = 110 // JOB_EXEC_FAILED (10 + EXIT_CODE_OFFSET)
	JobShouldHold            = 112 // JOB_SHOULD_HOLD (12 + EXIT_CODE_OFFSET)
	JobExitedAndClaimClosing = 115 // JOB_EXITED_AND_CLAIM_CLOSING (15 + EXIT_CODE_OFFSET)
	JobReconnectFailed       = 116 // JOB_RECONNECT_FAILED (16 + EXIT_CODE_OFFSET)
)

// SyscallError is returned when a remote syscall completes on the wire but
// the shadow reports failure: rval < 0 with an accompanying terrno. It is
// distinct from a network/protocol error (those are returned as the raw
// wrapped I/O error, never as a *SyscallError).
type SyscallError struct {
	Op    int // the syscall number that failed
	Rval  int // the negative return value from the shadow
	Errno int // the terrno the shadow sent after a negative rval
}

func (e *SyscallError) Error() string {
	return fmt.Sprintf("remote syscall %d failed: rval=%d errno=%d", e.Op, e.Rval, e.Errno)
}

// SecSessionInfo holds the six session strings the shadow returns from
// get_sec_session_info: a reconnect security session and a file-transfer
// security session, each expressed as {id, info, key}. See
// REMOTE_CONDOR_get_sec_session_info in NTsenders.cpp (lines 1064-1070).
type SecSessionInfo struct {
	ReconnectID   string
	ReconnectInfo string
	ReconnectKey  string
	FiletransID   string
	FiletransInfo string
	FiletransKey  string
}

// Client sends remote syscalls to the shadow over the activation/syscall
// socket. It wraps the CEDAR stream that carries the RPCs. A Client is not
// safe for concurrent use: the protocol is a strict request/reply sequence
// on a single socket.
type Client struct {
	st *stream.Stream
}

// NewClient returns a Client that drives remote syscalls over st.
func NewClient(st *stream.Stream) *Client {
	return &Client{st: st}
}

// begin starts a request message and writes the syscall number.
func (c *Client) begin(ctx context.Context, op int) (*message.Message, error) {
	out := message.NewMessageForStream(c.st)
	if err := out.PutInt(ctx, op); err != nil {
		return nil, fmt.Errorf("syscalls: writing op %d: %w", op, err)
	}
	return out, nil
}

// readStatus reads the reply's rval; on rval<0 it also reads terrno,
// drains the reply message, and returns a *SyscallError. On success it
// leaves the message positioned to read any payload.
func readStatus(ctx context.Context, op int, in *message.Message) error {
	rval, err := in.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("syscalls: op %d reading rval: %w", op, err)
	}
	if rval < 0 {
		terrno, err := in.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("syscalls: op %d reading terrno: %w", op, err)
		}
		if err := drain(ctx, in); err != nil {
			return fmt.Errorf("syscalls: op %d draining error reply: %w", op, err)
		}
		return &SyscallError{Op: op, Rval: rval, Errno: terrno}
	}
	return nil
}

// callInt performs a request whose reply is a bare status (rval, optional
// terrno) with no payload: register_starter_info, begin_execution,
// register_job_info, job_termination, job_exit. putArgs may be nil.
func (c *Client) callInt(ctx context.Context, op int, putArgs func(*message.Message) error) error {
	out, err := c.begin(ctx, op)
	if err != nil {
		return err
	}
	if putArgs != nil {
		if err := putArgs(out); err != nil {
			return fmt.Errorf("syscalls: op %d writing args: %w", op, err)
		}
	}
	if err := out.FinishMessage(ctx); err != nil {
		return fmt.Errorf("syscalls: op %d flushing request: %w", op, err)
	}
	in := message.NewMessageFromStream(c.st)
	if err := readStatus(ctx, op, in); err != nil {
		return err
	}
	return drain(ctx, in)
}

// GetJobInfo performs CONDOR_get_job_info (op -63): no args; reply is
// rval + the job ClassAd. The shadow sends the ad WITH private attributes
// (PutClassAdIncludePrivate) so the starter can read TransferKey and other
// private-V1 attributes; GetClassAd reads every serialized attribute, so
// those survive here.
func (c *Client) GetJobInfo(ctx context.Context) (*classad.ClassAd, error) {
	out, err := c.begin(ctx, OpGetJobInfo)
	if err != nil {
		return nil, err
	}
	if err := out.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("syscalls: get_job_info flushing request: %w", err)
	}
	in := message.NewMessageFromStream(c.st)
	if err := readStatus(ctx, OpGetJobInfo, in); err != nil {
		return nil, err
	}
	ad, err := in.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("syscalls: get_job_info reading ad: %w", err)
	}
	if err := drain(ctx, in); err != nil {
		return nil, err
	}
	return ad, nil
}

// GetUserInfo performs CONDOR_get_user_info (op -76): no args; reply is
// rval + a ClassAd carrying Uid/Gid. Same-user activations may skip this,
// but it is provided for completeness.
func (c *Client) GetUserInfo(ctx context.Context) (*classad.ClassAd, error) {
	out, err := c.begin(ctx, OpGetUserInfo)
	if err != nil {
		return nil, err
	}
	if err := out.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("syscalls: get_user_info flushing request: %w", err)
	}
	in := message.NewMessageFromStream(c.st)
	if err := readStatus(ctx, OpGetUserInfo, in); err != nil {
		return nil, err
	}
	ad, err := in.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("syscalls: get_user_info reading ad: %w", err)
	}
	if err := drain(ctx, in); err != nil {
		return nil, err
	}
	return ad, nil
}

// RegisterStarterInfo performs CONDOR_register_starter_info (op -77): args
// are the starter ClassAd; reply is a bare status.
func (c *Client) RegisterStarterInfo(ctx context.Context, starterAd *classad.ClassAd) error {
	return c.callInt(ctx, OpRegisterStarterInfo, func(m *message.Message) error {
		return m.PutClassAd(ctx, starterAd)
	})
}

// BeginExecution performs CONDOR_begin_execution (op -78): no args; bare
// status reply.
func (c *Client) BeginExecution(ctx context.Context) error {
	return c.callInt(ctx, OpBeginExecution, nil)
}

// RegisterJobInfo performs CONDOR_register_job_info (op -81): args are the
// periodic update ClassAd; reply is a bare status.
func (c *Client) RegisterJobInfo(ctx context.Context, updateAd *classad.ClassAd) error {
	return c.callInt(ctx, OpRegisterJobInfo, func(m *message.Message) error {
		return m.PutClassAd(ctx, updateAd)
	})
}

// JobTermination performs CONDOR_job_termination (op -82): args are the
// (mock) terminate ClassAd the starter sends on the output-transfer-failure
// path; reply is a bare status.
func (c *Client) JobTermination(ctx context.Context, ad *classad.ClassAd) error {
	return c.callInt(ctx, OpJobTermination, func(m *message.Message) error {
		return m.PutClassAd(ctx, ad)
	})
}

// JobExit performs CONDOR_job_exit (op -65), the final RPC of a run. The
// wire arg order is: int status (wait-status), int reason (a JOB_* code
// from exit.h), then the final ClassAd. Reply is a bare status. Mirrors
// REMOTE_CONDOR_job_exit in NTsenders.cpp (lines 253-258): op, status,
// reason, ad, EOM.
func (c *Client) JobExit(ctx context.Context, status int, reason int, finalAd *classad.ClassAd) error {
	return c.callInt(ctx, OpJobExit, func(m *message.Message) error {
		if err := m.PutInt(ctx, status); err != nil {
			return err
		}
		if err := m.PutInt(ctx, reason); err != nil {
			return err
		}
		return m.PutClassAd(ctx, finalAd)
	})
}

// Ulog performs CONDOR_ulog (op 284): args are the user-log event ClassAd.
// This op has NO reply ("we expect no response" per NTsenders.cpp line 905);
// it is fire-and-forget and does not read from the stream.
func (c *Client) Ulog(ctx context.Context, eventAd *classad.ClassAd) error {
	out, err := c.begin(ctx, OpUlog)
	if err != nil {
		return err
	}
	if err := out.PutClassAd(ctx, eventAd); err != nil {
		return fmt.Errorf("syscalls: ulog writing ad: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return fmt.Errorf("syscalls: ulog flushing request: %w", err)
	}
	return nil
}

// GetSecSessionInfo performs CONDOR_get_sec_session_info (op 288). The
// starter sends its own reconnect and file-transfer session-info strings
// (empty when it has none to propose, in the wire order reconnect then
// filetrans; see NTsenders.cpp lines 1052-1053) and receives back the
// shadow's six session strings on success. On rval<0 the shadow declined
// (e.g. it minted no sessions) and a *SyscallError is returned.
//
// NOTE: the C++ sender forces crypto on for this op because it exchanges
// session keys (NTsenders.cpp lines 1046-1050). The caller is responsible
// for ensuring the syscall stream is encrypted; this sender does not toggle
// per-message crypto, matching the golang-ap shadow server which likewise
// does not.
func (c *Client) GetSecSessionInfo(ctx context.Context) (*SecSessionInfo, error) {
	out, err := c.begin(ctx, OpGetSecSessionInfo)
	if err != nil {
		return nil, err
	}
	// Two empty session-info strings: reconnect, then filetrans.
	if err := out.PutString(ctx, ""); err != nil {
		return nil, fmt.Errorf("syscalls: get_sec_session_info writing reconnect info: %w", err)
	}
	if err := out.PutString(ctx, ""); err != nil {
		return nil, fmt.Errorf("syscalls: get_sec_session_info writing filetrans info: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("syscalls: get_sec_session_info flushing request: %w", err)
	}
	in := message.NewMessageFromStream(c.st)
	if err := readStatus(ctx, OpGetSecSessionInfo, in); err != nil {
		return nil, err
	}
	var info SecSessionInfo
	fields := []*string{
		&info.ReconnectID, &info.ReconnectInfo, &info.ReconnectKey,
		&info.FiletransID, &info.FiletransInfo, &info.FiletransKey,
	}
	for i, dst := range fields {
		s, err := in.GetString(ctx)
		if err != nil {
			return nil, fmt.Errorf("syscalls: get_sec_session_info reading string %d: %w", i, err)
		}
		*dst = s
	}
	if err := drain(ctx, in); err != nil {
		return nil, err
	}
	return &info, nil
}

// drain consumes the remainder of a reply message through its
// end-of-message marker, keeping the stream framed for the next RPC even if
// the reply carried trailing bytes we did not read. Mirrors drain() in the
// golang-ap shadow server (shadow/syscalls.go).
func drain(ctx context.Context, in *message.Message) error {
	for {
		if _, err := in.GetBytes(ctx, 1); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("syscalls: draining reply: %w", err)
		}
	}
}
