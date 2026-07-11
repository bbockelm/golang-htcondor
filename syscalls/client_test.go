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

package syscalls

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
)

// loopbackStreams returns a connected pair of CEDAR streams over a real
// TCP loopback socket (copied from golang-ap shadow/shadow_test.go). net.Pipe
// is synchronous and unbuffered, which can deadlock CEDAR's frame writes; a
// real socket buffers like production.
func loopbackStreams(t *testing.T) (*stream.Stream, *stream.Stream) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acc{c, err}
	}()
	cli, err := net.Dial("tcp", ln.Addr().String()) //nolint:noctx // test-only loopback dialer
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	srv := <-ch
	if srv.err != nil {
		t.Fatalf("accept: %v", srv.err)
	}
	t.Cleanup(func() { _ = cli.Close(); _ = srv.c.Close() })
	return stream.NewStream(cli), stream.NewStream(srv.c)
}

// fakeShadow is a minimal shadow-side server. Each handler faithfully mirrors
// the corresponding handler in golang-ap shadow/syscalls.go (serveOne); the
// citations below name the mirrored case. It exists only to exercise the
// Client; it is NOT imported from golang-ap (that would create a dependency
// cycle golang-ap -> golang-htcondor -> golang-ap).
type fakeShadow struct {
	st *stream.Stream

	jobAd  *classad.ClassAd // returned by get_job_info (may carry private attrs)
	userAd *classad.ClassAd // returned by get_user_info

	secDecline bool           // if true, get_sec_session_info replies rval<0
	secInfo    SecSessionInfo // returned on the success path

	// captured request state
	mu         sync.Mutex
	starterAd  *classad.ClassAd
	updateAd   *classad.ClassAd
	termAd     *classad.ClassAd
	ulogAds    []*classad.ClassAd
	exitStatus int
	exitReason int
	exitAd     *classad.ClassAd
	ops        []int
}

// serve runs the shadow serve loop until job_exit (or an error/EOF). It
// mirrors golang-ap shadow/syscalls.go serveOne's framing exactly.
func (f *fakeShadow) serve(ctx context.Context) error {
	for {
		done, err := f.serveOne(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
		if done {
			return nil
		}
	}
}

func (f *fakeShadow) serveOne(ctx context.Context) (bool, error) { //nolint:gocyclo // exhaustive syscall dispatch in a test fake
	in := message.NewMessageFromStream(f.st)
	op, err := in.GetInt(ctx)
	if err != nil {
		return false, err
	}
	f.mu.Lock()
	f.ops = append(f.ops, op)
	f.mu.Unlock()

	switch op {

	case OpGetJobInfo:
		// Mirrors serveOne case opGetJobInfo: reply rval + job ad sent WITH
		// private attributes (PutClassAdIncludePrivate) so TransferKey survives.
		if err := drainSrv(ctx, in); err != nil {
			return false, err
		}
		out := message.NewMessageForStream(f.st)
		if err := out.PutInt(ctx, 0); err != nil {
			return false, err
		}
		if err := out.PutClassAdWithOptions(ctx, f.jobAd, &message.PutClassAdConfig{
			Options: message.PutClassAdIncludePrivate,
		}); err != nil {
			return false, err
		}
		return false, out.FinishMessage(ctx)

	case OpGetUserInfo:
		// Mirrors serveOne case opGetUserInfo: reply rval + {Uid,Gid} ad.
		if err := drainSrv(ctx, in); err != nil {
			return false, err
		}
		out := message.NewMessageForStream(f.st)
		if err := out.PutInt(ctx, 0); err != nil {
			return false, err
		}
		if err := out.PutClassAd(ctx, f.userAd); err != nil {
			return false, err
		}
		return false, out.FinishMessage(ctx)

	case OpRegisterStarterInfo:
		// Mirrors serveOne case opRegisterStarterInfo: read ad, reply rval.
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, err
		}
		if err := drainSrv(ctx, in); err != nil {
			return false, err
		}
		f.mu.Lock()
		f.starterAd = ad
		f.mu.Unlock()
		return false, f.replyInt(ctx, 0, 0)

	case OpBeginExecution:
		// Mirrors serveOne case opBeginExecution: no args, reply rval.
		if err := drainSrv(ctx, in); err != nil {
			return false, err
		}
		return false, f.replyInt(ctx, 0, 0)

	case OpRegisterJobInfo:
		// Mirrors serveOne case opRegisterJobInfo: read update ad, reply rval.
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, err
		}
		if err := drainSrv(ctx, in); err != nil {
			return false, err
		}
		f.mu.Lock()
		f.updateAd = ad
		f.mu.Unlock()
		return false, f.replyInt(ctx, 0, 0)

	case OpJobTermination:
		// Mirrors serveOne case opJobTermination: read ad, reply rval.
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, err
		}
		if err := drainSrv(ctx, in); err != nil {
			return false, err
		}
		f.mu.Lock()
		f.termAd = ad
		f.mu.Unlock()
		return false, f.replyInt(ctx, 0, 0)

	case OpUlog:
		// Mirrors serveOne case opUlog: read ad, NO reply.
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, err
		}
		if err := drainSrv(ctx, in); err != nil {
			return false, err
		}
		f.mu.Lock()
		f.ulogAds = append(f.ulogAds, ad)
		f.mu.Unlock()
		return false, nil

	case OpJobExit:
		// Mirrors serveOne case opJobExit: read status,reason,ad; reply rval;
		// terminate the loop (RemoteSyscallResult::ExpectedClose).
		status, err := in.GetInt(ctx)
		if err != nil {
			return false, err
		}
		reason, err := in.GetInt(ctx)
		if err != nil {
			return false, err
		}
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return false, err
		}
		if err := drainSrv(ctx, in); err != nil {
			return false, err
		}
		f.mu.Lock()
		f.exitStatus, f.exitReason, f.exitAd = status, reason, ad
		f.mu.Unlock()
		if err := f.replyInt(ctx, 0, 0); err != nil {
			return true, err
		}
		return true, nil

	case OpGetSecSessionInfo:
		// Mirrors serveOne case opGetSecSessionInfo: read two strings; on
		// decline reply rval<0+terrno; else reply rval=0 + 6 strings.
		if _, err := in.GetString(ctx); err != nil {
			return false, err
		}
		if _, err := in.GetString(ctx); err != nil {
			return false, err
		}
		if err := drainSrv(ctx, in); err != nil {
			return false, err
		}
		if f.secDecline {
			return false, f.replyInt(ctx, -1, 38 /* ENOSYS */)
		}
		out := message.NewMessageForStream(f.st)
		if err := out.PutInt(ctx, 0); err != nil {
			return false, err
		}
		for _, s := range []string{
			f.secInfo.ReconnectID, f.secInfo.ReconnectInfo, f.secInfo.ReconnectKey,
			f.secInfo.FiletransID, f.secInfo.FiletransInfo, f.secInfo.FiletransKey,
		} {
			if err := out.PutString(ctx, s); err != nil {
				return false, err
			}
		}
		return false, out.FinishMessage(ctx)

	default:
		// Mirrors serveOne default: drain and reply ENOSYS.
		if err := drainSrv(ctx, in); err != nil {
			return false, err
		}
		return false, f.replyInt(ctx, -1, 38)
	}
}

// replyInt mirrors Shadow.replyInt in golang-ap shadow/syscalls.go.
func (f *fakeShadow) replyInt(ctx context.Context, rval, terrno int) error {
	out := message.NewMessageForStream(f.st)
	if err := out.PutInt(ctx, rval); err != nil {
		return err
	}
	if rval < 0 {
		if err := out.PutInt(ctx, terrno); err != nil {
			return err
		}
	}
	return out.FinishMessage(ctx)
}

// drainSrv mirrors drain() in golang-ap shadow/syscalls.go.
func drainSrv(ctx context.Context, in *message.Message) error {
	for {
		if _, err := in.GetBytes(ctx, 1); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// startShadow spins up the fake shadow's serve loop on a goroutine and
// returns a channel carrying its terminal error (nil on clean job_exit).
func startShadow(ctx context.Context, f *fakeShadow) <-chan error {
	errCh := make(chan error, 1)
	go func() { errCh <- f.serve(ctx) }()
	return errCh
}

// TestClientFullRun exercises the full vanilla+FT starter RPC sequence
// against the fake shadow, covering every replied method plus the ulog
// no-reply path and get_sec_session_info's success path.
func TestClientFullRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cliSt, shadowSt := loopbackStreams(t)

	jobAd := classad.New()
	_ = jobAd.Set("ClusterId", int64(7))
	_ = jobAd.Set("Cmd", "/bin/sh")
	_ = jobAd.Set("TransferKey", "secret-transfer-key-42") // private-V1 attr

	userAd := classad.New()
	_ = userAd.Set("Uid", int64(1000))
	_ = userAd.Set("Gid", int64(1000))

	f := &fakeShadow{
		st:     shadowSt,
		jobAd:  jobAd,
		userAd: userAd,
		secInfo: SecSessionInfo{
			ReconnectID: "rc-id", ReconnectInfo: "rc-info", ReconnectKey: "rc-key",
			FiletransID: "ft-id", FiletransInfo: "ft-info", FiletransKey: "ft-key",
		},
	}
	errCh := startShadow(ctx, f)

	c := NewClient(cliSt)

	// (1) get_job_info: private TransferKey must survive the round trip.
	gotJob, err := c.GetJobInfo(ctx)
	if err != nil {
		t.Fatalf("GetJobInfo: %v", err)
	}
	if v, _ := gotJob.EvaluateAttrString("Cmd"); v != "/bin/sh" {
		t.Errorf("GetJobInfo Cmd = %q, want /bin/sh", v)
	}
	if v, _ := gotJob.EvaluateAttrString("TransferKey"); v != "secret-transfer-key-42" {
		t.Errorf("GetJobInfo TransferKey = %q, want secret-transfer-key-42 (private attr lost)", v)
	}

	// (2) get_user_info.
	gotUser, err := c.GetUserInfo(ctx)
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	if v, ok := gotUser.EvaluateAttrInt("Uid"); !ok || v != 1000 {
		t.Errorf("GetUserInfo Uid = %d (ok %v), want 1000", v, ok)
	}

	// (3) register_starter_info.
	starterAd := classad.New()
	_ = starterAd.Set("CondorVersion", "$CondorVersion: 25.0.0 $")
	if err := c.RegisterStarterInfo(ctx, starterAd); err != nil {
		t.Fatalf("RegisterStarterInfo: %v", err)
	}

	// (4) get_sec_session_info success: all six strings returned.
	sec, err := c.GetSecSessionInfo(ctx)
	if err != nil {
		t.Fatalf("GetSecSessionInfo: %v", err)
	}
	if sec.ReconnectID != "rc-id" || sec.FiletransKey != "ft-key" {
		t.Errorf("GetSecSessionInfo = %+v, want the six seeded strings", sec)
	}

	// (5) begin_execution.
	if err := c.BeginExecution(ctx); err != nil {
		t.Fatalf("BeginExecution: %v", err)
	}

	// (6) register_job_info.
	update := classad.New()
	_ = update.Set("JobState", "Running")
	if err := c.RegisterJobInfo(ctx, update); err != nil {
		t.Fatalf("RegisterJobInfo: %v", err)
	}

	// (7) two ulogs (no reply) followed by a replied op, proving no desync.
	ev := classad.New()
	_ = ev.Set("MyType", "ExecuteEvent")
	if err := c.Ulog(ctx, ev); err != nil {
		t.Fatalf("Ulog #1: %v", err)
	}
	if err := c.Ulog(ctx, ev); err != nil {
		t.Fatalf("Ulog #2: %v", err)
	}

	// (8) job_termination (replied) proves the stream is still framed.
	termAd := classad.New()
	_ = termAd.Set("OnExitCode", int64(0))
	if err := c.JobTermination(ctx, termAd); err != nil {
		t.Fatalf("JobTermination after ulogs: %v", err)
	}

	// (9) job_exit: final RPC. arg order status, reason, ad.
	exitAd := classad.New()
	_ = exitAd.Set("JobState", "Exited")
	if err := c.JobExit(ctx, 0, JobExited, exitAd); err != nil {
		t.Fatalf("JobExit: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("shadow serve: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("shadow did not finish")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ulogAds) != 2 {
		t.Errorf("shadow saw %d ulog events, want 2 (desync?)", len(f.ulogAds))
	}
	if f.exitStatus != 0 || f.exitReason != JobExited {
		t.Errorf("job_exit captured status=%d reason=%d, want 0/%d", f.exitStatus, f.exitReason, JobExited)
	}
	if f.termAd == nil {
		t.Error("job_termination ad not captured")
	}
	if f.starterAd == nil {
		t.Error("starter ad not captured")
	}
	if f.updateAd == nil {
		t.Error("update ad not captured")
	}
}

// TestGetSecSessionInfoDecline covers the rval<0 + terrno path: the shadow
// declines and the client returns a typed *SyscallError.
func TestGetSecSessionInfoDecline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cliSt, shadowSt := loopbackStreams(t)
	f := &fakeShadow{st: shadowSt, secDecline: true}
	errCh := startShadow(ctx, f)

	c := NewClient(cliSt)
	sec, err := c.GetSecSessionInfo(ctx)
	if sec != nil {
		t.Errorf("GetSecSessionInfo returned %+v, want nil on decline", sec)
	}
	var se *SyscallError
	if !errors.As(err, &se) {
		t.Fatalf("GetSecSessionInfo err = %v (%T), want *SyscallError", err, err)
	}
	if se.Op != OpGetSecSessionInfo {
		t.Errorf("SyscallError.Op = %d, want %d", se.Op, OpGetSecSessionInfo)
	}
	if se.Rval >= 0 {
		t.Errorf("SyscallError.Rval = %d, want <0", se.Rval)
	}
	if se.Errno != 38 {
		t.Errorf("SyscallError.Errno = %d, want 38 (ENOSYS)", se.Errno)
	}

	// The client must stay framed after an error reply: prove the next RPC
	// still works by driving get_sec_session_info again (still declined).
	if _, err := c.GetSecSessionInfo(ctx); !errors.As(err, &se) {
		t.Fatalf("second GetSecSessionInfo err = %v, want *SyscallError (stream desynced?)", err)
	}

	cancel()
	<-errCh
}

// TestGetJobInfoError covers an rval<0 reply on a payload op: the shadow
// returns an unknown-op-style error for get_job_info and the client returns
// a *SyscallError without attempting to read the (absent) ad.
func TestGetJobInfoError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cliSt, shadowSt := loopbackStreams(t)

	// Custom server: reply rval<0+terrno to a get_job_info request, exactly
	// as serveOne's error branch (replyInt with rval<0) would.
	go func() {
		in := message.NewMessageFromStream(shadowSt)
		if _, err := in.GetInt(ctx); err != nil {
			return
		}
		_ = drainSrv(ctx, in)
		out := message.NewMessageForStream(shadowSt)
		_ = out.PutInt(ctx, -1)
		_ = out.PutInt(ctx, 2) // ENOENT
		_ = out.FinishMessage(ctx)
	}()

	c := NewClient(cliSt)
	ad, err := c.GetJobInfo(ctx)
	if ad != nil {
		t.Errorf("GetJobInfo returned ad %v, want nil on error", ad)
	}
	var se *SyscallError
	if !errors.As(err, &se) {
		t.Fatalf("GetJobInfo err = %v (%T), want *SyscallError", err, err)
	}
	if se.Rval != -1 || se.Errno != 2 {
		t.Errorf("SyscallError = %+v, want Rval=-1 Errno=2", se)
	}
}
