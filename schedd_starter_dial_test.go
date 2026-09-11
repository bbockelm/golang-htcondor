package htcondor

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/bbockelm/cedar/client"

	"github.com/bbockelm/cedar/security"
)

// Both ways of reaching into a running job must build the same security
// config, because both talk to the same starter for the same reason.
//
// They were separate copies of the same code, and the copies drifted:
// opening a shell was fixed to authenticate as this daemon and to
// traverse CCB, and tailing output was not. Asserting they agree is what
// makes the next divergence a test failure rather than a bug report from
// someone behind a firewall.
func TestStarterConfigIsTheSameForEveryStarterCommand(t *testing.T) {
	callers := &security.SecurityConfig{
		Token:       "a.browser.session.jwt",
		AuthMethods: []security.AuthMethod{security.AuthToken},
	}
	ctx := WithSecurityConfig(context.Background(), callers)

	for _, command := range []int{startSSHDCommand, starterPeekCommand} {
		cache := security.NewSessionCache()
		sc, err := starterSecurityConfig(ctx, "<10.0.0.1:9618>", command, cache)
		if err != nil {
			t.Fatalf("command %d: %v", command, err)
		}
		if sc.Token == callers.Token {
			t.Errorf("command %d: the caller's token reached the starter config; "+
				"a CCB broker cannot verify a token this server signed", command)
		}
		if sc.SessionCache != cache {
			t.Errorf("command %d: the ClaimID session cache was not installed", command)
		}
	}
}

// The streaming choice has to reach the dial, for every starter command.
// Without it the broker tells the execute node to connect back to an
// address nothing routes to, and the attempt times out having explained
// nothing -- which is what tailing output did until this shared dialer.
func TestStarterDialRequestsStreamingForEveryCommand(t *testing.T) {
	info := &JobConnectInfo{
		StarterAddr: "<10.0.0.1:9618?CCBID=192.0.2.1:9618%2342>",
		ClaimID:     validTestClaimID(t),
	}

	for _, command := range []int{startSSHDCommand, starterPeekCommand} {
		var gotAddr string
		var gotOpts *DialOptions
		restore := dialStarterConn
		dialStarterConn = func(_ context.Context, addr string, _ *security.SecurityConfig, opts *DialOptions) (*client.HTCondorClient, error) {
			gotAddr, gotOpts = addr, opts
			return nil, errTestDialIntercepted
		}
		_, err := info.dialStarter(context.Background(), command, true)
		dialStarterConn = restore

		if !errors.Is(err, errTestDialIntercepted) {
			t.Fatalf("command %d: the dial was not reached: %v", command, err)
		}
		if gotAddr != info.StarterAddr {
			t.Errorf("command %d: dialed %q, want the starter address", command, gotAddr)
		}
		if gotOpts == nil || !gotOpts.CCBRequireStreaming {
			t.Errorf("command %d: streaming was not requested; a firewalled execute node is unreachable", command)
		}
	}
}

// And it must not be requested when the caller did not ask: on a host that
// can accept the reverse connection, that path is the cheaper one.
func TestStarterDialLeavesStreamingOffByDefault(t *testing.T) {
	info := &JobConnectInfo{StarterAddr: "<10.0.0.1:9618>", ClaimID: validTestClaimID(t)}

	var gotOpts *DialOptions
	restore := dialStarterConn
	dialStarterConn = func(_ context.Context, _ string, _ *security.SecurityConfig, opts *DialOptions) (*client.HTCondorClient, error) {
		gotOpts = opts
		return nil, errTestDialIntercepted
	}
	_, _ = info.dialStarter(context.Background(), startSSHDCommand, false)
	dialStarterConn = restore

	if gotOpts == nil || gotOpts.CCBRequireStreaming {
		t.Error("streaming was requested without being asked for")
	}
}

// validTestClaimID is a ClaimID shaped as a modern schedd exports one, so
// dialStarter gets past parsing and reaches the dial.
func validTestClaimID(t *testing.T) string {
	t.Helper()
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	info := `[Encryption="YES";Integrity="YES";CryptoMethods="BLOWFISH";CryptoMethodsList="AES.BLOWFISH.3DES"]`
	return fmt.Sprintf("<127.0.0.1:9999>#100#1#%s%s", info, key)
}

var errTestDialIntercepted = errors.New("dial intercepted by test")

// Tailing must pass its own streaming choice down to the dial. The shared
// dialer honours the flag it is given; this is the other half -- that the
// tail path gives it the one the caller asked for.
func TestPeekPassesStreamingToTheDial(t *testing.T) {
	info := &JobConnectInfo{
		StarterAddr: "<10.0.0.1:9618?CCBID=192.0.2.1:9618%2342>",
		ClaimID:     validTestClaimID(t),
	}

	var gotOpts *DialOptions
	restore := dialStarterConn
	dialStarterConn = func(_ context.Context, _ string, _ *security.SecurityConfig, opts *DialOptions) (*client.HTCondorClient, error) {
		gotOpts = opts
		return nil, errTestDialIntercepted
	}
	_, err := info.peekOutput(context.Background(), PeekRequest{Stdout: true, CCBStreaming: true})
	dialStarterConn = restore

	if !errors.Is(err, errTestDialIntercepted) {
		t.Fatalf("the dial was not reached: %v", err)
	}
	if gotOpts == nil || !gotOpts.CCBRequireStreaming {
		t.Error("tail did not ask for streaming, so a firewalled execute node stays unreachable")
	}
}
