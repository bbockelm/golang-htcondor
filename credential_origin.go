package htcondor

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/bbockelm/cedar/security"
)

// CredentialOrigin records who a context is acting for.
//
// It exists because a context carrying no *security.SecurityConfig was
// ambiguous in the one way that matters. "Nobody attached a credential
// because this is the daemon's own queue mirroring" and "nobody attached a
// credential because the code that should have done so returned early" look
// identical at the point where the connection is built, and
// GetSecurityConfigOrDefault resolved both of them the same way: fall through
// to this daemon's own configuration. On an access point the daemon is a
// queue superuser, so a missing credential did not fail closed -- it
// escalated. A request whose authentication went wrong ended up with MORE
// authority than one whose went right.
//
// The classification therefore has to come from somewhere that cannot be
// skipped by the failure it is meant to catch, which means the transport that
// accepted the request rather than the branch that authenticates it. See
// WithUserRequest.
type CredentialOrigin int

const (
	// OriginUnset is a context nobody has classified. What happens when one
	// reaches the daemon fallback is the process-wide policy's decision;
	// see SetUnmarkedOriginPolicy.
	OriginUnset CredentialOrigin = iota
	// OriginUser is a context acting for somebody who is not this daemon.
	// The daemon fallback is never right for one of these: the worst
	// acceptable outcome is an unauthenticated connection the peer refuses,
	// not an authenticated one the peer trusts completely.
	OriginUser
	// OriginDaemon is this daemon's own work -- queue mirroring, collector
	// advertising, a CCB relay, a health ping. Here the daemon credential is
	// the point rather than an accident.
	OriginDaemon
)

func (o CredentialOrigin) String() string {
	switch o {
	case OriginUser:
		return "user"
	case OriginDaemon:
		return "daemon"
	default:
		return "unset"
	}
}

type credentialOriginKey struct{}

type credentialOriginValue struct {
	origin CredentialOrigin
	reason string
}

// WithUserRequest marks ctx as acting for somebody other than this daemon,
// so that reaching the daemon fallback under it is an error rather than a
// silent promotion.
//
// Mark at the transport, not at the authentication branch. The branches are
// precisely the code that forgets: one returns the context unchanged when it
// has no signing key, another hands back a context whose credential could not
// be minted, a third is a route that nobody wrapped in the gate. Marking
// where the request enters the process means a route added tomorrow inherits
// it, and a branch that fails to attach a credential produces a context that
// is refused instead of one that authenticates as a superuser.
//
// reason names the surface, and is carried into the refusal message: an
// operator reading the log line needs to know which door the context came in
// through, because the fix is at that door.
func WithUserRequest(ctx context.Context, reason string) context.Context {
	return context.WithValue(ctx, credentialOriginKey{},
		credentialOriginValue{origin: OriginUser, reason: reason})
}

// WithDaemonCredential marks ctx as this daemon's own work, which is what
// makes authenticating as this daemon legitimate.
//
// It also detaches any caller credential, because the two always belong
// together: the reason a piece of plumbing is daemon work is that the peer is
// infrastructure with no reason to trust the caller's token, and offering it
// one anyway asks a third party to accept a credential meant for somebody
// else. Doing both here means a context derived from a request cannot be
// half-converted.
func WithDaemonCredential(ctx context.Context, reason string) context.Context {
	ctx = context.WithValue(ctx, securityConfigContextKey{}, (*security.SecurityConfig)(nil))
	return context.WithValue(ctx, credentialOriginKey{},
		credentialOriginValue{origin: OriginDaemon, reason: reason})
}

// CredentialOriginFromContext reports how ctx was classified, and why.
func CredentialOriginFromContext(ctx context.Context) (CredentialOrigin, string) {
	v, ok := ctx.Value(credentialOriginKey{}).(credentialOriginValue)
	if !ok {
		return OriginUnset, ""
	}
	return v.origin, v.reason
}

// UnmarkedOriginPolicy says what an unclassified context may do when it
// reaches the daemon fallback.
//
// It is the dial that stages the migration. Every context in a daemon this
// large cannot be classified in one change, and a gate that refused the
// unclassified ones on day one would refuse the daemon's own background work
// along with the requests it is aimed at. So: Allow is today's behaviour and
// the default, Warn is the same plus a report per unmarked fallback naming
// the call, and Deny is the fail-closed end state where forgetting to
// classify a context breaks loudly rather than quietly running as a queue
// superuser.
type UnmarkedOriginPolicy int32

const (
	// UnmarkedAllow lets an unclassified context fall back to the daemon's
	// own configuration, as it always has.
	UnmarkedAllow UnmarkedOriginPolicy = iota
	// UnmarkedWarn allows the fallback and reports it, so the remaining
	// unclassified call sites can be enumerated from a running system
	// rather than guessed at from the source.
	UnmarkedWarn
	// UnmarkedDeny refuses an unclassified context the same way a
	// user-marked one is refused.
	UnmarkedDeny
)

// unmarkedPolicy is process-wide because the thing it governs is: whether
// this process may authenticate as itself for work nobody has classified.
var unmarkedPolicy atomic.Int32

// SetUnmarkedOriginPolicy sets the process-wide policy for unclassified
// contexts. The zero value, in force until something calls this, is
// UnmarkedAllow.
func SetUnmarkedOriginPolicy(p UnmarkedOriginPolicy) { unmarkedPolicy.Store(int32(p)) }

// unmarkedOriginReporter holds the Warn-mode report hook.
var unmarkedOriginReporter atomic.Pointer[func(command int, secContext, peerName string)]

// SetUnmarkedOriginReporter installs the function UnmarkedWarn calls for each
// unclassified daemon fallback. Passing nil removes it.
//
// A hook rather than a log call: this package deliberately does not depend on
// the logging package (a daemon hands its own logger in), and the caller that
// turns Warn on is the same one that knows where its logs go.
func SetUnmarkedOriginReporter(fn func(command int, secContext, peerName string)) {
	if fn == nil {
		unmarkedOriginReporter.Store(nil)
		return
	}
	unmarkedOriginReporter.Store(&fn)
}

// ErrDaemonFallbackRefused is returned when a context that is not this
// daemon's own work reaches the point where the daemon's credential would
// have been used.
//
// It always means a bug in this server: some code path reached CEDAR without
// attaching the caller's credential (htcondor.WithSecurityConfig), or did the
// daemon's own work without saying so (htcondor.WithDaemonCredential). That
// advice is for whoever fixes the code, so it lives here rather than in the
// message, which reaches log readers and, through the HTTP handlers, users.
type ErrDaemonFallbackRefused struct {
	// Origin is how the context was classified: OriginUser for a refused
	// caller, OriginUnset when the policy refuses unclassified contexts.
	Origin CredentialOrigin
	// Reason is the surface the classification was made at.
	Reason string
	// Command, Context and PeerName describe the connection that was about
	// to be built, so a log line identifies which call was refused.
	Command  int
	Context  string
	PeerName string
}

func (e *ErrDaemonFallbackRefused) Error() string {
	peer := e.PeerName
	if peer == "" {
		peer = "an HTCondor daemon"
	}
	return fmt.Sprintf(
		"%s had no credential to present to %s, and the server will not use its own "+
			"in the caller's place; this is a bug in the server",
		e.Reason, peer)
}

// IsDaemonFallbackRefused reports whether err is a refusal of the daemon
// fallback.
//
// Exported so a transport can answer with the status the refusal actually
// means. It is an authentication failure -- the caller presented nothing this
// server could use -- so it maps to 401, not to the 500 that a
// security-config error otherwise reads as.
func IsDaemonFallbackRefused(err error) bool {
	var target *ErrDaemonFallbackRefused
	return errors.As(err, &target)
}

// checkDaemonFallbackAllowed is the gate GetSecurityConfigOrDefault consults
// before building a connection out of this daemon's own configuration.
func checkDaemonFallbackAllowed(ctx context.Context, command int, secContext, peerName string) error {
	origin, reason := CredentialOriginFromContext(ctx)
	switch origin {
	case OriginUser:
		return &ErrDaemonFallbackRefused{
			Origin:  origin,
			Reason:  reason,
			Command: command,
			Context: secContext, PeerName: peerName,
		}
	case OriginDaemon:
		return nil
	}
	switch UnmarkedOriginPolicy(unmarkedPolicy.Load()) {
	case UnmarkedDeny:
		return &ErrDaemonFallbackRefused{
			Origin:  origin,
			Reason:  "unclassified context",
			Command: command,
			Context: secContext, PeerName: peerName,
		}
	case UnmarkedWarn:
		if fn := unmarkedOriginReporter.Load(); fn != nil {
			(*fn)(command, secContext, peerName)
		}
	}
	return nil
}
