package htcondor

import (
	"context"
	"time"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/security"
)

// DialOptions configures DialSinful, principally for reaching daemons behind a
// Condor Connection Broker (CCB).
type DialOptions struct {
	// Timeout bounds connection establishment (default 30s).
	Timeout time.Duration

	// CCBReturnAddr enables streaming/proxy mode when the address is a CCB
	// sinful: it is this client's own CCB sinful (carrying a ccbid), used when
	// the client itself is private and cannot accept a direct reverse
	// connection. Leave empty for the common case (a publicly reachable tool
	// dialing into a private daemon).
	CCBReturnAddr string

	// CCBRequireStreaming makes streaming mode mandatory: if the broker does
	// not support it, DialSinful fails fast rather than attempting a direct
	// reverse connection.
	CCBRequireStreaming bool
}

// DialSinful establishes an authenticated connection to an HTCondor daemon
// named by a sinful string, transparently following the appropriate transport:
// direct TCP, a shared-port daemon, or — when the sinful carries a ccbid — the
// Condor Connection Broker via connection reversal.
//
// secConfig should be built with the existing helpers (e.g. GetSecurityConfig)
// for the intended command. The returned client's stream is ready for the
// command payload.
func DialSinful(ctx context.Context, address string, secConfig *security.SecurityConfig, opts *DialOptions) (*client.HTCondorClient, error) {
	cfg := &client.ClientConfig{
		Address:  address,
		Security: secConfig,
	}
	if opts != nil {
		cfg.Timeout = opts.Timeout
		cfg.CCBReturnAddr = opts.CCBReturnAddr
		cfg.CCBRequireStreaming = opts.CCBRequireStreaming
	}
	return client.ConnectAndAuthenticateWithConfig(ctx, cfg)
}
