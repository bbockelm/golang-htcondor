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

	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// aliveFields holds what the fake schedd's ALIVE handler decoded off the wire.
type aliveFields struct {
	claimID   string
	resumed   bool
	encrypted bool
}

// fakeSchedd is a fake C++ schedd: a cedar server that pre-registers the claim
// session (submit-side identity, exactly as golang-ap's match.CreateFromClaim
// does) and answers ALIVE with whatever interval the test wires up. It is the
// authoritative server peer of the startd->schedd ALIVE wire.
type fakeSchedd struct {
	claimID string
	addr    string // schedd command sinful "<host:port>"
	srv     *cedarserver.Server
	cache   *security.SessionCache
}

// newFakeSchedd starts a listener and imports the claim session into the
// server's own cache (separate from the client's, mirroring reality: the schedd
// and startd each hold their own copy of the match session). replyInterval is
// the int the ALIVE handler returns; capture (if non-nil) receives the decoded
// request. The returned claim id embeds the listener's address only as its
// sinful head -- SendAlive dials the addr passed to it, not the claim id.
func newFakeSchedd(t *testing.T, replyInterval int, capture func(aliveFields)) *fakeSchedd {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := fmt.Sprintf("<%s>", ln.Addr().String())
	claimID := addr + "#1700000000#7#" + testSessionInfo + testSecret

	cache := security.NewSessionCache()
	// The schedd is the submit side of a claim; it attributes the startd's
	// keepalives to submit-side@matchsession, matching what the startd
	// registered (see golang-ap match.CreateFromClaim).
	if _, err := security.ImportClaimSession(cache, claimID, security.ClaimSessionOptions{
		PeerAddr:           addr,
		PeerFQU:            security.SubmitSideMatchSessionFQU,
		ExtraValidCommands: []int{cmdAlive},
	}); err != nil {
		t.Fatalf("schedd ImportClaimSession: %v", err)
	}

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityOptional,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		SessionCache:   cache,
	})

	f := &fakeSchedd{claimID: claimID, addr: addr, srv: srv, cache: cache}
	srv.Handle(cmdAlive, func(ctx context.Context, c *cedarserver.Conn) error {
		in := message.NewMessageFromStream(c.Stream)
		cid, err := in.GetString(ctx)
		if err != nil {
			return err
		}
		if capture != nil {
			capture(aliveFields{
				claimID:   cid,
				resumed:   c.Negotiation != nil && c.Negotiation.SessionResumed,
				encrypted: c.Stream.IsEncrypted(),
			})
		}
		out := message.NewMessageForStream(c.Stream)
		if err := out.PutInt(ctx, replyInterval); err != nil {
			return err
		}
		return out.FinishMessage(ctx)
	}, "READ")

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return f
}

func TestSendAliveRenewsLease(t *testing.T) {
	var got aliveFields
	f := newFakeSchedd(t, 300, func(fld aliveFields) { got = fld })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The client holds its own cache; the claim session is imported on demand.
	interval, err := SendAlive(ctx, f.addr, f.claimID, security.NewSessionCache())
	if err != nil {
		t.Fatalf("SendAlive: %v", err)
	}
	if interval != 300 {
		t.Errorf("interval = %d, want 300", interval)
	}

	// The schedd saw a resumed, encrypted session (no fresh handshake) and the
	// claim id verbatim.
	if !got.resumed {
		t.Error("schedd did not resume the claim session (full handshake occurred)")
	}
	if !got.encrypted {
		t.Error("schedd stream not encrypted")
	}
	if got.claimID != f.claimID {
		t.Errorf("claim id on wire = %q, want %q", got.claimID, f.claimID)
	}
}

func TestSendAliveResumesPreImportedSession(t *testing.T) {
	var got aliveFields
	f := newFakeSchedd(t, 120, func(fld aliveFields) { got = fld })

	// Pre-import the session into the client's cache (as the startd does when it
	// mints/accepts the claim) so SendAlive resumes it rather than re-importing.
	clientCache := security.NewSessionCache()
	if _, err := security.ImportClaimSession(clientCache, f.claimID, security.ClaimSessionOptions{
		PeerAddr:           f.addr,
		PeerFQU:            security.SubmitSideMatchSessionFQU,
		ExtraValidCommands: []int{cmdAlive},
	}); err != nil {
		t.Fatalf("client ImportClaimSession: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	interval, err := SendAlive(ctx, f.addr, f.claimID, clientCache)
	if err != nil {
		t.Fatalf("SendAlive: %v", err)
	}
	if interval != 120 {
		t.Errorf("interval = %d, want 120", interval)
	}
	if !got.resumed {
		t.Error("schedd did not resume the pre-imported claim session")
	}
}

func TestSendAliveScheddForgotClaim(t *testing.T) {
	f := newFakeSchedd(t, AliveScheddForgotClaim, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	interval, err := SendAlive(ctx, f.addr, f.claimID, security.NewSessionCache())
	// -1 is a value, not an error: the exchange succeeded, the schedd just does
	// not recognize the claim.
	if err != nil {
		t.Fatalf("SendAlive returned error for a -1 reply, want nil: %v", err)
	}
	if interval != AliveScheddForgotClaim {
		t.Errorf("interval = %d, want %d (schedd forgot claim)", interval, AliveScheddForgotClaim)
	}
}

func TestSendAliveNetworkErrorIsError(t *testing.T) {
	// Dial an address nobody is listening on: a network failure must surface as
	// an error, never as a -1/other value.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	claimID := "<127.0.0.1:1>#1700000000#7#" + testSessionInfo + testSecret
	_, err := SendAlive(ctx, "<127.0.0.1:1>", claimID, security.NewSessionCache())
	if err == nil {
		t.Fatal("expected a network error dialing a dead address")
	}
}

func TestSendAliveRequiresCache(t *testing.T) {
	ctx := context.Background()
	claimID := "<127.0.0.1:1>#1700000000#7#" + testSessionInfo + testSecret
	if _, err := SendAlive(ctx, "<127.0.0.1:1>", claimID, nil); err == nil {
		t.Fatal("expected an error for a nil cache")
	}
}
