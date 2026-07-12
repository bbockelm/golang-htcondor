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

package startd

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
	"github.com/bbockelm/cedar/stream"
)

const (
	testSessionInfo = `[Encryption="YES";Integrity="YES";CryptoMethods="AES";]`
	testSecret      = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// fakeStartd is a fake C++ startd: a cedar server that resumes the claim session
// and serves whatever claim reply the test wires up. It is the server side of
// the wire-encode unit tests.
type fakeStartd struct {
	claimID   string
	sessionID string
	addr      string // HTCondor sinful "<host:port>"
	srv       *cedarserver.Server
	cache     *security.SessionCache
	ln        net.Listener
	cancel    context.CancelFunc
}

// newFakeStartd starts a listener, imports the claim session (startd/submit
// side), and serves. The returned claim id embeds the listener's address so a
// startd.Client built from it dials this fake.
func newFakeStartd(t *testing.T) *fakeStartd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := fmt.Sprintf("<%s>", ln.Addr().String())
	claimID := addr + "#1700000000#7#" + testSessionInfo + testSecret

	cache := security.NewSessionCache()
	sesid, err := security.ImportClaimSession(cache, claimID, security.ClaimSessionOptions{
		PeerAddr: addr,
		PeerFQU:  security.SubmitSideMatchSessionFQU,
	})
	if err != nil {
		t.Fatalf("server ImportClaimSession: %v", err)
	}

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   cache,
	})

	ctx, cancel := context.WithCancel(context.Background())
	f := &fakeStartd{claimID: claimID, sessionID: sesid, addr: addr, srv: srv, cache: cache, ln: ln, cancel: cancel}
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return f
}

func (f *fakeStartd) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(f.claimID, nil)
	if err != nil {
		t.Fatalf("startd.New: %v", err)
	}
	return c
}

// requestClaimFields holds what a REQUEST_CLAIM handler decoded off the wire.
type requestClaimFields struct {
	claimID       string
	requestAd     *classad.ClassAd
	schedulerAddr string
	aliveInterval int
	resumed       bool
	encrypted     bool
}

// handleRequestClaim registers a REQUEST_CLAIM handler that decodes the request,
// hands it to capture, then writes reply codes/payloads via reply.
func (f *fakeStartd) handleRequestClaim(capture func(requestClaimFields), reply func(ctx context.Context, w *message.Message) error) {
	f.srv.Handle(cmdRequestClaim, func(ctx context.Context, c *cedarserver.Conn) error {
		in := message.NewMessageFromStream(c.Stream)
		cid, err := in.GetString(ctx)
		if err != nil {
			return err
		}
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return err
		}
		sa, err := in.GetString(ctx)
		if err != nil {
			return err
		}
		ai, err := in.GetInt(ctx)
		if err != nil {
			return err
		}
		capture(requestClaimFields{
			claimID: cid, requestAd: ad, schedulerAddr: sa, aliveInterval: ai,
			resumed: c.Negotiation != nil && c.Negotiation.SessionResumed, encrypted: c.Stream.IsEncrypted(),
		})
		out := message.NewMessageForStream(c.Stream)
		return reply(ctx, out)
	}, "DAEMON")
}

func TestRequestClaimOK(t *testing.T) {
	f := newFakeStartd(t)
	var got requestClaimFields
	f.handleRequestClaim(
		func(fld requestClaimFields) { got = fld },
		func(ctx context.Context, w *message.Message) error {
			if err := w.PutInt(ctx, ReplyOK); err != nil {
				return err
			}
			return w.FinishMessage(ctx)
		},
	)

	reqAd := classad.New()
	_ = reqAd.Set("Owner", "alice")
	_ = reqAd.Set("RequestCpus", int64(1))
	_ = reqAd.Set("JobUniverse", int64(5))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := f.client(t)
	res, err := c.RequestClaim(ctx, &ClaimRequest{
		RequestAd:     reqAd,
		SchedulerAddr: "<10.0.0.1:4080>",
		AliveInterval: 300,
		ScheddName:    "test-schedd",
	})
	if err != nil {
		t.Fatalf("RequestClaim: %v", err)
	}
	if !res.OK || res.Code != ReplyOK {
		t.Fatalf("result = %+v, want OK", res)
	}

	// The startd side saw a resumed, encrypted session (no fresh handshake).
	if !got.resumed {
		t.Error("startd did not resume the claim session (full handshake occurred)")
	}
	if !got.encrypted {
		t.Error("startd stream not encrypted")
	}
	// The wire carried the claim id, scheduler addr, and alive interval verbatim.
	if got.claimID != f.claimID {
		t.Errorf("claim id on wire = %q, want %q", got.claimID, f.claimID)
	}
	if got.schedulerAddr != "<10.0.0.1:4080>" {
		t.Errorf("scheduler addr = %q", got.schedulerAddr)
	}
	if got.aliveInterval != 300 {
		t.Errorf("alive interval = %d, want 300", got.aliveInterval)
	}
	// The caller's attrs survived and the injected capability/alive attrs are present.
	if v, _ := got.requestAd.EvaluateAttrString("Owner"); v != "alice" {
		t.Errorf("Owner = %q, want alice", v)
	}
	for _, attr := range []string{"_condor_SECURE_CLAIM_ID", "_condor_SEND_CLAIMED_AD", "_condor_SEND_LEFTOVERS", "StartdSendsAlives", "_condor_StartdHandlesAlives"} {
		if b, ok := got.requestAd.EvaluateAttrBool(attr); !ok || !b {
			t.Errorf("injected attr %s = (%v,%v), want true", attr, b, ok)
		}
	}
	if v, _ := got.requestAd.EvaluateAttrString("ScheddName"); v != "test-schedd" {
		t.Errorf("ScheddName = %q, want test-schedd", v)
	}
}

func TestRequestClaimSlotAdLoopThenOK(t *testing.T) {
	f := newFakeStartd(t)
	f.handleRequestClaim(
		func(requestClaimFields) {},
		func(ctx context.Context, w *message.Message) error {
			// Two REQUEST_CLAIM_SLOT_AD entries, then OK.
			for i := 0; i < 2; i++ {
				if err := w.PutInt(ctx, ReplySlotAd); err != nil {
					return err
				}
				if err := w.PutString(ctx, fmt.Sprintf("slot%d-claimid", i)); err != nil {
					return err
				}
				slot := classad.New()
				_ = slot.Set("Name", fmt.Sprintf("slot1_%d@host", i))
				if err := w.PutClassAd(ctx, slot); err != nil {
					return err
				}
			}
			if err := w.PutInt(ctx, ReplyOK); err != nil {
				return err
			}
			return w.FinishMessage(ctx)
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := f.client(t).RequestClaim(ctx, &ClaimRequest{SchedulerAddr: "<10.0.0.1:4080>", AliveInterval: 60})
	if err != nil {
		t.Fatalf("RequestClaim: %v", err)
	}
	if !res.OK || res.Code != ReplyOK {
		t.Fatalf("result code = %d, want OK", res.Code)
	}
	if len(res.ClaimedSlots) != 2 {
		t.Fatalf("claimed slots = %d, want 2", len(res.ClaimedSlots))
	}
	if res.ClaimedSlots[0].ClaimID != "slot0-claimid" {
		t.Errorf("slot 0 claim id = %q", res.ClaimedSlots[0].ClaimID)
	}
	if v, _ := res.ClaimedSlots[1].SlotAd.EvaluateAttrString("Name"); v != "slot1_1@host" {
		t.Errorf("slot 1 name = %q", v)
	}
}

func TestRequestClaimLeftovers2(t *testing.T) {
	f := newFakeStartd(t)
	f.handleRequestClaim(
		func(requestClaimFields) {},
		func(ctx context.Context, w *message.Message) error {
			if err := w.PutInt(ctx, ReplyLeftovers2); err != nil {
				return err
			}
			if err := w.PutString(ctx, "leftover-claimid"); err != nil {
				return err
			}
			pslot := classad.New()
			_ = pslot.Set("Name", "slot1@host")
			_ = pslot.Set("Cpus", int64(7))
			if err := w.PutClassAd(ctx, pslot); err != nil {
				return err
			}
			return w.FinishMessage(ctx)
		},
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := f.client(t).RequestClaim(ctx, &ClaimRequest{SchedulerAddr: "<10.0.0.1:4080>", AliveInterval: 60, ClaimPSlot: true})
	if err != nil {
		t.Fatalf("RequestClaim: %v", err)
	}
	if !res.OK || !res.HasLeftovers {
		t.Fatalf("result = %+v, want OK with leftovers", res)
	}
	if res.LeftoverClaimID != "leftover-claimid" {
		t.Errorf("leftover claim id = %q", res.LeftoverClaimID)
	}
	if v, _ := res.LeftoverSlotAd.EvaluateAttrInt("Cpus"); v != 7 {
		t.Errorf("leftover Cpus = %d, want 7", v)
	}
}

func TestRequestClaimNotOK(t *testing.T) {
	f := newFakeStartd(t)
	f.handleRequestClaim(
		func(requestClaimFields) {},
		func(ctx context.Context, w *message.Message) error {
			if err := w.PutInt(ctx, ReplyNotOK); err != nil {
				return err
			}
			return w.FinishMessage(ctx)
		},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := f.client(t).RequestClaim(ctx, &ClaimRequest{SchedulerAddr: "<10.0.0.1:4080>", AliveInterval: 60})
	if err != nil {
		t.Fatalf("RequestClaim: %v", err)
	}
	if res.OK || res.Code != ReplyNotOK {
		t.Fatalf("result = %+v, want NOT_OK", res)
	}
}

func TestReleaseClaim(t *testing.T) {
	f := newFakeStartd(t)
	gotCID := make(chan string, 1)
	f.srv.Handle(cmdReleaseClaim, func(ctx context.Context, c *cedarserver.Conn) error {
		in := message.NewMessageFromStream(c.Stream)
		cid, err := in.GetString(ctx)
		if err != nil {
			return err
		}
		gotCID <- cid
		return nil // fire-and-forget: no reply, matching command_release_claim
	}, "READ")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := f.client(t).ReleaseClaim(ctx); err != nil {
		t.Fatalf("ReleaseClaim: %v", err)
	}
	select {
	case cid := <-gotCID:
		if cid != f.claimID {
			t.Errorf("release claim id = %q, want %q", cid, f.claimID)
		}
	case <-ctx.Done():
		t.Fatal("startd never received RELEASE_CLAIM")
	}
}

func TestDeactivateClaim(t *testing.T) {
	f := newFakeStartd(t)
	f.srv.Handle(cmdDeactivateClaim, func(ctx context.Context, c *cedarserver.Conn) error {
		in := message.NewMessageFromStream(c.Stream)
		if _, err := in.GetString(ctx); err != nil {
			return err
		}
		out := message.NewMessageForStream(c.Stream)
		resp := classad.New()
		_ = resp.Set("Start", false)
		_ = resp.Set("StillCleaning", true)
		if err := out.PutClassAd(ctx, resp); err != nil {
			return err
		}
		return out.FinishMessage(ctx)
	}, "READ")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ad, err := f.client(t).DeactivateClaim(ctx, DeactivateGraceful)
	if err != nil {
		t.Fatalf("DeactivateClaim: %v", err)
	}
	if b, ok := ad.EvaluateAttrBool("Start"); !ok || b {
		t.Errorf("Start = (%v,%v), want false", b, ok)
	}
	if b, ok := ad.EvaluateAttrBool("StillCleaning"); !ok || !b {
		t.Errorf("StillCleaning = (%v,%v), want true", b, ok)
	}
}

func TestNewRejectsClaimWithoutAddress(t *testing.T) {
	if _, err := New("no-hash-here", nil); err == nil {
		t.Fatal("expected error for claim id without a startd address")
	}
}

// TestPutSecretEqualsPutStringWhenEncrypted documents the wire assumption the
// claim client depends on: on an encrypted stream a put_secret is byte-identical
// to a put_string, so composing the claim message with the streaming message API
// (rather than the stream-level PutSecret, which frames its own EOM) is correct.
func TestPutSecretEqualsPutStringWhenEncrypted(t *testing.T) {
	// This is exercised end-to-end by TestRequestClaimOK (the startd decodes the
	// claim id the client wrote as a secret using a plain GetString). This test
	// just asserts requireEncrypted refuses a plaintext stream.
	st := stream.NewStream(newNopConn())
	if err := requireEncrypted(st); err == nil {
		t.Fatal("requireEncrypted should reject a non-encrypted stream")
	}
}

type nopConn struct{ net.Conn }

func newNopConn() net.Conn {
	c1, _ := net.Pipe()
	return &nopConn{c1}
}
