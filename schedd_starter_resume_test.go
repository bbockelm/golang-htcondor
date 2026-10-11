package htcondor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// refusingStarter accepts CEDAR connections, answers every session
// resumption with SID_NOT_FOUND, and counts the handshakes that are not
// resumptions -- each of which would be this daemon authenticating afresh to
// whatever host the execute node advertised.
type refusingStarter struct {
	addr string

	mu          sync.Mutex
	resumptions int
	full        int
}

func newRefusingStarter(t *testing.T) *refusingStarter {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	fs := &refusingStarter{addr: fmt.Sprintf("<%s>", ln.Addr())}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go fs.serve(conn)
		}
	}()
	return fs
}

func (fs *refusingStarter) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s := stream.NewStream(conn)
	in := message.NewMessageFromStream(s)
	if _, err := in.GetInt(ctx); err != nil {
		return // connected, then gave up without sending anything
	}
	ad, err := in.GetClassAd(ctx)
	if err != nil {
		return
	}
	if _, ok := ad.EvaluateAttrString("Sid"); !ok {
		fs.mu.Lock()
		fs.full++
		fs.mu.Unlock()
		return
	}
	fs.mu.Lock()
	fs.resumptions++
	fs.mu.Unlock()
	reply := classad.New()
	_ = reply.Set("ReturnCode", "SID_NOT_FOUND")
	out := message.NewMessageForStream(s)
	if err := out.PutClassAd(ctx, reply); err != nil {
		return
	}
	_ = out.FinishMessage(ctx)
}

func (fs *refusingStarter) counts() (resumptions, full int) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.resumptions, fs.full
}

// A starter that refuses the schedd-minted session must end the dial. The
// address came from the execute node, so a fresh handshake there would be
// this daemon authenticating to a host it has no reason to trust.
func TestStarterDialDoesNotAuthenticateAfterARefusedResumption(t *testing.T) {
	starter := newRefusingStarter(t)
	info := &JobConnectInfo{StarterAddr: starter.addr, ClaimID: validTestClaimID(t)}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cl, err := info.dialStarter(ctx, startSSHDCommand, nil)
	if err == nil {
		_ = cl.Close()
		t.Fatal("the dial succeeded against a starter that refused the session")
	}
	if !security.IsSessionResumptionError(err) {
		t.Errorf("err = %v, want a session resumption error", err)
	}
	resumptions, full := starter.counts()
	if resumptions == 0 {
		t.Error("the starter was never offered the schedd-minted session")
	}
	if full != 0 {
		t.Errorf("%d full handshake(s) reached the starter after it refused the session", full)
	}
}

// The broker leg authenticates as this daemon, so only brokers the pool's
// own configuration names are dialed; one the execute node made up is not.
func TestStarterDialOnlyUsesConfiguredBrokers(t *testing.T) {
	var dialed []string
	restore := ccbDialSinful
	ccbDialSinful = func(_ context.Context, addr string, _ *security.SecurityConfig, _ *DialOptions) (*client.HTCondorClient, error) {
		dialed = append(dialed, addr)
		return nil, errTestDialIntercepted
	}
	t.Cleanup(func() { ccbDialSinful = restore })

	dial := func(cfgText, starter string) error {
		dialed = nil
		info := &JobConnectInfo{StarterAddr: starter, ClaimID: validTestClaimID(t), cfg: mustConfig(t, cfgText)}
		_, err := info.dialStarter(context.Background(), startSSHDCommand,
			NewCCBDialer(CCBDialerConfig{Streaming: true, Logger: quietTestLogger()}))
		return err
	}

	// A broker the configuration does not name is refused before any dial.
	err := dial("COLLECTOR_HOST = 192.0.2.1:9618\nCCB_ADDRESS = 192.0.2.2:9618\n",
		"<10.0.0.1:9618?CCBID=198.51.100.7:9618%2342>")
	if err == nil || errors.Is(err, errTestDialIntercepted) || len(dialed) != 0 {
		t.Errorf("an unlisted broker: err = %v, dialed %v; want a refusal and no dial", err, dialed)
	}
	// So is a starter with a listed broker beside an unlisted one.
	err = dial("CCB_ADDRESS = 192.0.2.1:9618\n",
		"<10.0.0.1:9618?CCBID=192.0.2.1:9618%2342%20198.51.100.7:9618%2343>")
	if err == nil || errors.Is(err, errTestDialIntercepted) || len(dialed) != 0 {
		t.Errorf("a listed and an unlisted broker: err = %v, dialed %v; want a refusal and no dial", err, dialed)
	}
	// And any CCB starter, when the configuration names no broker at all.
	err = dial("", "<10.0.0.1:9618?CCBID=192.0.2.1:9618%2342>")
	if err == nil || errors.Is(err, errTestDialIntercepted) || len(dialed) != 0 {
		t.Errorf("no configured brokers: err = %v, dialed %v; want a refusal and no dial", err, dialed)
	}

	for _, tc := range []struct{ name, cfg, starter string }{
		{"CCB_ADDRESS", "CCB_ADDRESS = 192.0.2.1:9618\n", "<10.0.0.1:9618?CCBID=192.0.2.1:9618%2342>"},
		{"COLLECTOR_HOST, another port and shared-port id", "COLLECTOR_HOST = 192.0.2.1\n",
			"<10.0.0.1:9618?CCBID=192.0.2.1:9620%3Fsock%3Dcollector2%2342>"},
		{"a host name resolving to the broker", "CCB_ADDRESS = localhost:9618\n",
			"<10.0.0.1:9618?CCBID=127.0.0.1:9618%2342>"},
		{"a direct starter", "", "<10.0.0.1:9618>"},
	} {
		if err := dial(tc.cfg, tc.starter); !errors.Is(err, errTestDialIntercepted) || len(dialed) != 1 {
			t.Errorf("%s: err = %v, dialed %v; want the dial reached", tc.name, err, dialed)
		}
	}
}
