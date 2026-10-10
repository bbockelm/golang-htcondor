package htcondor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// TestPingResult tests the PingResult structure
func TestPingResult(t *testing.T) {
	result := &PingResult{
		AuthMethod:     "IDTOKENS",
		User:           "testuser@example.com",
		SessionID:      "test-session-123",
		ValidCommands:  "ALL",
		Encryption:     true,
		Authentication: true,
	}

	if result.AuthMethod != "IDTOKENS" {
		t.Errorf("Expected AuthMethod 'IDTOKENS', got '%s'", result.AuthMethod)
	}

	if result.User != "testuser@example.com" {
		t.Errorf("Expected User 'testuser@example.com', got '%s'", result.User)
	}

	if !result.Authentication {
		t.Error("Expected Authentication to be true")
	}

	if !result.Encryption {
		t.Error("Expected Encryption to be true")
	}
}

// TestWrapScheddConnectErrorStaleSock pins the diagnostic added on top of a
// connection-reset against a shared-port address. Without this, the error
// message would be the raw "connection reset by peer" — true but unhelpful,
// since the operator can't tell whether the schedd is down or has just
// restarted with a new sock= ID.
func TestWrapScheddConnectErrorStaleSock(t *testing.T) {
	const sharedPortAddr = "<128.105.68.62:9618?sock=schedd_7942_2140>"
	original := fmt.Errorf("authentication handshake failed: failed to parse server response: read tcp 10.0.0.1:42402->128.105.68.62:9618: read: connection reset by peer")

	wrapped := wrapScheddConnectError(sharedPortAddr, original)
	if wrapped == nil {
		t.Fatal("wrapScheddConnectError returned nil")
	}

	msg := wrapped.Error()

	// The hint must mention the shared-port restart hypothesis and the
	// remediation ("re-query the collector"). These are the bits the
	// operator needs to act on; the test pins both so a future copy edit
	// doesn't accidentally drop them.
	if !strings.Contains(msg, "sock=schedd_7942_2140") {
		t.Errorf("wrapped error should mention the stale sock id, got: %s", msg)
	}
	if !strings.Contains(msg, "re-query the collector") {
		t.Errorf("wrapped error should suggest re-querying the collector, got: %s", msg)
	}
	if !strings.Contains(msg, "the daemon likely restarted") {
		t.Errorf("wrapped error should mention daemon restart, got: %s", msg)
	}

	// Critically: errors.Is on the original error must still work. Callers
	// (and especially session-resumption fallbacks) rely on the chain.
	if !errors.Is(wrapped, original) {
		t.Error("wrapped error must preserve original via %w")
	}
}

func TestWrapScheddConnectErrorPlainAddress(t *testing.T) {
	// Connection reset on a non-shared-port address gets the original
	// wording — the stale-sock hint would be misleading.
	const plainAddr = "<127.0.0.1:9618>"
	original := fmt.Errorf("read: connection reset by peer")

	wrapped := wrapScheddConnectError(plainAddr, original)
	if wrapped == nil {
		t.Fatal("wrapScheddConnectError returned nil")
	}
	msg := wrapped.Error()
	if strings.Contains(msg, "sock=") {
		t.Errorf("plain-address wrapping should not mention sock=, got: %s", msg)
	}
	if !strings.Contains(msg, "failed to connect and authenticate to schedd at") {
		t.Errorf("expected baseline wording preserved, got: %s", msg)
	}
}

func TestWrapScheddConnectErrorOtherFailure(t *testing.T) {
	// Connection refused on a shared-port address is *not* the stale-sock
	// case — that's "schedd is down" and the wrapper should not invent
	// reasons. We just want the original wording preserved.
	const sharedPortAddr = "<127.0.0.1:9618?sock=schedd_42_99>"
	original := fmt.Errorf("dial tcp 127.0.0.1:9618: connect: connection refused")

	wrapped := wrapScheddConnectError(sharedPortAddr, original)
	msg := wrapped.Error()
	if strings.Contains(msg, "the daemon likely restarted") {
		t.Errorf("connection-refused should not get the restart hint, got: %s", msg)
	}
}

func TestWrapScheddConnectErrorNil(t *testing.T) {
	if wrapScheddConnectError("anything", nil) != nil {
		t.Error("nil err must wrap to nil err")
	}
}

func TestLooksLikeConnReset(t *testing.T) {
	if looksLikeConnReset(nil) {
		t.Error("nil should not be a reset")
	}
	if !looksLikeConnReset(fmt.Errorf("read: connection reset by peer")) {
		t.Error("substring match should detect reset")
	}
	if !looksLikeConnReset(fmt.Errorf("wrapped: %w", syscall.ECONNRESET)) {
		t.Error("errors.Is should see through %%w to ECONNRESET")
	}
	if looksLikeConnReset(fmt.Errorf("connection refused")) {
		t.Error("refused must not be classified as reset")
	}
}

// TestDCNopConstantsMatchWireValues pins the DC_NOP_* permission constants to
// the values HTCondor actually assigns them (condor_commands.h: DC_BASE is
// 60000 and DC_NOP_READ is DC_BASE+20, with no gaps).
//
// These were hardcoded and shifted by one for as long as they existed, because
// DC_NOP_OWNER was omitted from the middle of the list. Nothing caught it:
// PingWithOptions asks the daemon a DC_SEC_QUERY question and then ignores the
// answer, so asking about the wrong permission level produced an identical
// result. Anything that starts trusting PingResult.Authorized depends on these
// being right.
func TestDCNopConstantsMatchWireValues(t *testing.T) {
	const dcBase = 60000
	for _, tc := range []struct {
		name string
		got  int
		want int
	}{
		{"READ", DCNopRead, dcBase + 20},
		{"WRITE", DCNopWrite, dcBase + 21},
		{"NEGOTIATOR", DCNopNegotiator, dcBase + 22},
		{"ADMINISTRATOR", DCNopAdministrator, dcBase + 23},
		{"OWNER", DCNopOwner, dcBase + 24},
		{"CONFIG", DCNopConfig, dcBase + 25},
		{"DAEMON", DCNopDaemon, dcBase + 26},
		{"ADVERTISE_STARTD", DCNopAdvertiseStartd, dcBase + 27},
		{"ADVERTISE_SCHEDD", DCNopAdvertiseSchedd, dcBase + 28},
		{"ADVERTISE_MASTER", DCNopAdvertiseMaster, dcBase + 29},
	} {
		if tc.got != tc.want {
			t.Errorf("DC_NOP_%s = %d, want %d", tc.name, tc.got, tc.want)
		}
		if got := permissionName(tc.got); got != tc.name {
			t.Errorf("permissionName(%d) = %q, want %q", tc.got, got, tc.name)
		}
	}
}

// TestPingCommandSelection pins which command each set of options puts
// on the wire. A level-specific NOP is how a caller makes the ping
// itself an operation at that level, so a regression that quietly fell
// back to DC_NOP (registered at ALLOW) would turn an authorization check
// back into an authentication one with nothing visibly different.
func TestPingCommandSelection(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opts    PingOptions
		want    int
		wantErr bool
	}{
		{"default", PingOptions{}, int(commands.DC_NOP), false},
		{"permission query", PingOptions{CheckPermission: DCNopRead}, int(commands.DC_SEC_QUERY), false},
		{"read-level nop", PingOptions{Command: DCNopRead}, int(commands.DC_NOP_READ), false},
		{"write-level nop", PingOptions{Command: DCNopWrite}, int(commands.DC_NOP_WRITE), false},
		{"both set", PingOptions{CheckPermission: DCNopRead, Command: DCNopRead}, 0, true},
		{"not a nop", PingOptions{Command: int(commands.QUERY_JOB_ADS)}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.opts.pingCommand()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("pingCommand() = %d, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("pingCommand(): %v", err)
			}
			if got != tc.want {
				t.Errorf("pingCommand() = %d, want %d", got, tc.want)
			}
		})
	}
}

// newRecordingDaemon starts a CEDAR server that accepts FS and answers
// DC_NOP and DC_NOP_READ, reporting each command it dispatches. Each call
// gets its own address, so no session cached against one is resumed by
// another.
func newRecordingDaemon(t *testing.T) (string, <-chan int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		SessionCache:   security.NewSessionCache(),
	})
	got := make(chan int, 4)
	record := func(_ context.Context, c *cedarserver.Conn) error {
		got <- c.Command
		return nil
	}
	srv.Handle(int(commands.DC_NOP), record, "ALLOW")
	srv.Handle(int(commands.DC_NOP_READ), record, "READ")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return fmt.Sprintf("<%s>", ln.Addr().String()), got
}

// TestPingSendsRequestedNop drives a real handshake against a fake
// daemon and checks the command it was asked to run, for both the
// schedd and the collector client.
func TestPingSendsRequestedNop(t *testing.T) {
	type pinger interface {
		PingWithOptions(context.Context, *PingOptions) (*PingResult, error)
	}
	clients := map[string]func(addr string) pinger{
		"Schedd": func(addr string) pinger {
			return NewSchedd("fake", addr).WithConfig(mustConfig(t, fsOnlyConfig))
		},
		"Collector": func(addr string) pinger {
			return NewCollector(addr).WithConfig(mustConfig(t, fsOnlyConfig))
		},
	}
	for name, newClient := range clients {
		for _, opts := range []PingOptions{{Command: DCNopRead}, {}} {
			want := int(commands.DC_NOP)
			if opts.Command != 0 {
				want = opts.Command
			}
			t.Run(fmt.Sprintf("%s/%d", name, want), func(t *testing.T) {
				addr, got := newRecordingDaemon(t)
				res, err := newClient(addr).PingWithOptions(daemonContext(t), &opts)
				if err != nil {
					t.Fatalf("PingWithOptions(%+v): %v", opts, err)
				}
				if res.User == "" {
					t.Errorf("PingWithOptions(%+v) reported no identity", opts)
				}
				select {
				case cmd := <-got:
					if cmd != want {
						t.Errorf("daemon ran command %d, want %d", cmd, want)
					}
				case <-time.After(10 * time.Second):
					t.Fatalf("daemon never dispatched command %d", want)
				}
			})
		}
	}
}
