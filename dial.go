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
	//
	// Setting this alone is enough to select streaming; CCBReturnAddr is
	// filled in for you. See DialSinful.
	CCBRequireStreaming bool
}

// ccbProxyPlaceholderAddr stands in for a streaming client's reverse-connect
// address.
//
// Streaming mode does not use one -- the broker splices onto the request
// socket it already holds -- but the request ad's MyAddress must be non-empty,
// and a non-empty CCBReturnAddr is also what selects streaming in the first
// place. A client with no CCB registration of its own has nothing real to put
// there, which is exactly the case streaming exists to serve.
const ccbProxyPlaceholderAddr = "<0.0.0.0:0>"

// DialSinful establishes an authenticated connection to an HTCondor daemon
// named by a sinful string, transparently following the appropriate transport:
// direct TCP, a shared-port daemon, or — when the sinful carries a ccbid — the
// Condor Connection Broker.
//
// CCB has two modes, and the default is wrong for a caller that cannot accept
// inbound connections. Standard mode has the private daemon dial back to the
// caller, so the caller must be reachable from it; streaming mode has the
// broker relay both directions over the request socket, so it need not be. A
// caller in a container or behind NAT wants opts.CCBRequireStreaming.
//
// secConfig should be built with the existing helpers (e.g. GetSecurityConfig)
// for the intended command. The returned client's stream is ready for the
// command payload.
func DialSinful(ctx context.Context, address string, secConfig *security.SecurityConfig, opts *DialOptions) (*client.HTCondorClient, error) {
	return client.ConnectAndAuthenticateWithConfig(ctx, dialConfig(address, secConfig, opts))
}

// dialConfig builds the cedar client config for DialSinful. Separated so the
// option translation -- which decides whether a CCB dial reverses or streams,
// and is not otherwise observable without a broker to dial -- can be tested.
func dialConfig(address string, secConfig *security.SecurityConfig, opts *DialOptions) *client.ClientConfig {
	cfg := &client.ClientConfig{
		Address:  address,
		Security: secConfig,
	}
	if opts == nil {
		return cfg
	}
	cfg.Timeout = opts.Timeout
	cfg.CCBReturnAddr = opts.CCBReturnAddr
	cfg.CCBRequireStreaming = opts.CCBRequireStreaming
	// Mode selection keys on the return address alone, so asking for
	// streaming without supplying one would silently get the standard
	// reverse-connect dial -- the opposite of what was asked for, and
	// discoverable only by watching the connection fail.
	if cfg.CCBRequireStreaming && cfg.CCBReturnAddr == "" {
		cfg.CCBReturnAddr = ccbProxyPlaceholderAddr
	}
	return cfg
}
