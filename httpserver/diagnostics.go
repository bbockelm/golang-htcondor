package httpserver

import (
	"errors"
	"strings"
	"syscall"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/security"
)

// connErrorClass categorizes a connection failure for diagnostic logging.
// The string values are short, dashed identifiers suitable for log fields.
type connErrorClass string

const (
	// connErrorStaleSock: TCP connection to the shared-port daemon was reset
	// after the SYN/ACK, before any meaningful response. The most common cause
	// is the daemon having restarted with a new sock= ID, so the sock in our
	// cached address no longer routes to a live process. The shared-port daemon
	// closes such connections without sending an error frame.
	connErrorStaleSock connErrorClass = "stale-sock"

	// connErrorNoCompatibleAuth: cedar negotiated security but the client and
	// server have no overlapping authentication methods (or the client's tokens
	// were all filtered out for trust-domain / IssuerKeys mismatch).
	connErrorNoCompatibleAuth connErrorClass = "no-compatible-auth"

	// connErrorTimeout: connection or handshake timed out.
	connErrorTimeout connErrorClass = "timeout"

	// connErrorRefused: TCP connection refused.
	connErrorRefused connErrorClass = "connection-refused"

	// connErrorOther: a generic failure with no specific diagnostic.
	connErrorOther connErrorClass = "other"
)

// diagnostic captures a single connection error in a structured form suitable
// for slog-style key/value logging. It does not change the underlying error.
type diagnostic struct {
	Class       connErrorClass
	Hint        string // human-readable single-sentence explanation, may be empty
	SharedPort  string // sock= ID extracted from the address, if any
	ServerAddr  string // host:port portion of the address, if parseable
	Authoritive bool   // true when Class is determined from explicit signals (not pattern matching)
}

// classifyConnectionError inspects an error returned from
// client.ConnectAndAuthenticate (or wrappers around it) and the address that
// was being dialed, and returns a diagnostic that callers can fold into log
// output. The error itself is never modified — this is purely for human-
// readable hints.
//
// The function is intentionally tolerant of error wrapping: cedar wraps its
// errors several times (handshake → phase → root cause), and matching on
// substrings is the only reliable way to recognise specific conditions
// without making golang-htcondor depend on internal cedar error types.
func classifyConnectionError(addr string, err error) diagnostic {
	if err == nil {
		return diagnostic{Class: connErrorOther}
	}

	d := diagnostic{Class: connErrorOther}
	info := addresses.ParseHTCondorAddress(addr)
	d.ServerAddr = info.ServerAddr
	if info.IsSharedPort {
		d.SharedPort = info.SharedPortID
	}

	msg := err.Error()

	// "no compatible authentication methods found" is cedar's exact phrasing
	// at security/auth.go:1640. We match on it because callers want this
	// distinguished from other auth failures.
	if strings.Contains(msg, "no compatible authentication methods found") {
		d.Class = connErrorNoCompatibleAuth
		d.Authoritive = true
		d.Hint = "client and server share no auth methods — check that AuthMethods, TrustDomain, and available tokens match what the server advertises (cedar logs '🔐 SERVER:'/'🔐 CLIENT:' lines with the negotiated lists)"
		return d
	}

	if isConnectionResetError(err) {
		// Connection reset on a shared-port address strongly suggests the
		// schedd / collector restarted and our cached sock= is now stale.
		// shared_port silently RSTs connections destined for a sock that no
		// longer exists in its routing table.
		if info.IsSharedPort {
			d.Class = connErrorStaleSock
			d.Authoritive = true
			d.Hint = "TCP RST after connect on a shared-port address — the daemon almost certainly restarted with a new sock= ID. Re-querying the collector for the daemon's current address should resolve this."
			return d
		}
		d.Class = connErrorOther
		d.Hint = "connection reset by peer — peer closed the TCP connection without responding"
		return d
	}

	if isConnectionRefusedError(err) {
		d.Class = connErrorRefused
		d.Hint = "TCP connection refused — daemon is not listening at this address (possibly down, or the address is wrong)"
		return d
	}

	if isTimeoutError(err) {
		d.Class = connErrorTimeout
		d.Hint = "connection or handshake timed out — daemon is unreachable or overloaded"
		return d
	}

	return d
}

// isConnectionResetError returns true if err is, or wraps, a TCP connection
// reset (ECONNRESET). Cedar wraps this several times and the underlying
// syscall error may not be reachable via errors.Is on all platforms, so we
// also fall back to substring matching on the wrapped message.
func isConnectionResetError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	// Substring fallback. Go's net package formats ECONNRESET as
	// "read: connection reset by peer" or "write: connection reset by peer".
	msg := err.Error()
	return strings.Contains(msg, "connection reset by peer")
}

// isConnectionRefusedError returns true if err is, or wraps, ECONNREFUSED.
func isConnectionRefusedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return strings.Contains(err.Error(), "connection refused")
}

// isTimeoutError returns true if err is, or wraps, a timeout. We can't use
// the net.Error interface alone because it isn't preserved across error
// wrapping; substring matching catches the common cases.
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	type timeoutErr interface{ Timeout() bool }
	var te timeoutErr
	if errors.As(err, &te) && te.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "deadline exceeded")
}

// scheddSharedPortInfo is a thin re-export of addresses.ParseHTCondorAddress
// for use within the httpserver package, so callers don't need to import the
// cedar addresses package just to look at sock= for logging purposes.
func scheddSharedPortInfo(addr string) addresses.SharedPortInfo {
	return addresses.ParseHTCondorAddress(addr)
}

// summarizeAuthMethods renders a short, log-friendly description of the
// auth-side configuration that cedar will use when handshaking. This is what
// we want surfaced when "no compatible authentication methods found" fires —
// without it, the operator can't tell what we *tried* to use, only that
// nothing matched.
func summarizeAuthMethods(cfg *security.SecurityConfig) []any {
	if cfg == nil {
		return []any{"security_config", "<nil>"}
	}
	methods := make([]string, 0, len(cfg.AuthMethods))
	for _, m := range cfg.AuthMethods {
		methods = append(methods, string(m))
	}
	fields := []any{
		"client_auth_methods", strings.Join(methods, ","),
	}
	if cfg.TrustDomain != "" {
		fields = append(fields, "trust_domain", cfg.TrustDomain)
	}
	// Surface where tokens were being looked for, but never the tokens
	// themselves. TokenFile / TokenDir are paths, not secrets.
	if cfg.TokenFile != "" {
		fields = append(fields, "token_file", cfg.TokenFile)
	}
	if cfg.TokenDir != "" {
		fields = append(fields, "token_dir", cfg.TokenDir)
	}
	if cfg.Token != "" {
		fields = append(fields, "inline_token_present", true)
	}
	return fields
}
