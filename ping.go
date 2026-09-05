package htcondor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"

	"github.com/bbockelm/cedar/addresses"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
)

// Permission levels for DC_SEC_QUERY authorization checking.
// These are sent as AuthCommand during the security handshake.
//
// The values come from cedar's commands package rather than being written
// out here. They were previously hardcoded and every one from READ through
// ADMINISTRATOR was off by one — DC_NOP_OWNER (DC_BASE+24) was missing from
// the list, so DCNopRead asked the daemon about WRITE, DCNopWrite about
// NEGOTIATOR, and DCNopAdministrator about OWNER. The mistake was invisible
// because PingWithOptions never read the daemon's answer (see PingResult.
// Authorized), so nothing depended on asking the right question.
const (
	DCNopRead            = commands.DC_NOP_READ
	DCNopWrite           = commands.DC_NOP_WRITE
	DCNopNegotiator      = commands.DC_NOP_NEGOTIATOR
	DCNopAdministrator   = commands.DC_NOP_ADMINISTRATOR
	DCNopOwner           = commands.DC_NOP_OWNER
	DCNopConfig          = commands.DC_NOP_CONFIG
	DCNopDaemon          = commands.DC_NOP_DAEMON
	DCNopAdvertiseStartd = commands.DC_NOP_ADVERTISE_STARTD
	DCNopAdvertiseSchedd = commands.DC_NOP_ADVERTISE_SCHEDD
	DCNopAdvertiseMaster = commands.DC_NOP_ADVERTISE_MASTER
)

// PingResult contains the result of a ping operation
type PingResult struct {
	// AuthMethod is the authentication method that was negotiated
	AuthMethod string
	// User is the authenticated username
	User string
	// SessionID is the session identifier
	SessionID string
	// ValidCommands is a string describing which commands are authorized
	ValidCommands string
	// Encryption indicates whether encryption was negotiated
	Encryption bool
	// Authentication indicates whether authentication was performed
	Authentication bool
	// Authorized reports the daemon's answer to the DC_SEC_QUERY probe:
	// whether the authenticated identity would be permitted to run a
	// command at the requested level. Only meaningful when
	// PingOptions.CheckPermission was set; false otherwise.
	//
	// Note this is an authorization answer, not an identity one. It says
	// the daemon's ACLs admit whatever identity the connection presented;
	// it says nothing about whether that identity still exists wherever it
	// originated.
	Authorized bool
	// Permission is the permission level that was checked (e.g., "READ", "WRITE")
	// Only set when CheckPermission is specified
	Permission string
}

// PingOptions configures the ping operation
type PingOptions struct {
	// CheckPermission specifies a permission level to check authorization for.
	// If 0, only authentication is performed (DC_NOP).
	// If set to one of DC_NOP_* constants, authorization is checked (DC_SEC_QUERY).
	CheckPermission int
}

// Ping performs a ping operation against the collector daemon
// This is similar to condor_ping and provides information about authentication
// and authorization. It's useful for health checks and debugging security settings.
func (c *Collector) Ping(ctx context.Context) (*PingResult, error) {
	return c.PingWithOptions(ctx, nil)
}

// PingWithOptions performs a ping operation with optional permission checking
func (c *Collector) PingWithOptions(ctx context.Context, opts *PingOptions) (*PingResult, error) {
	if opts == nil {
		opts = &PingOptions{}
	}

	// Determine command based on whether we're checking permissions
	// For basic ping, use DC_NOP (no operation) command
	// For permission checks, use DC_SEC_QUERY
	command := int(commands.DC_NOP)
	if opts.CheckPermission != 0 {
		command = int(commands.DC_SEC_QUERY)
	}

	// Get SecurityConfig
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, command, "CLIENT", c.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Require authentication for ping operations
	secConfig.Authentication = "REQUIRED"

	// Set AuthCommand to the permission level if checking permissions
	if opts.CheckPermission != 0 {
		secConfig.AuthCommand = opts.CheckPermission
	}

	// Establish connection and authenticate
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, c.address, secConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect and authenticate to collector: %w", err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get security negotiation result
	negotiation := htcondorClient.GetSecurityNegotiation()
	if negotiation == nil {
		return nil, fmt.Errorf("no security negotiation performed")
	}

	// Convert negotiation result to PingResult
	result := &PingResult{
		AuthMethod:     string(negotiation.NegotiatedAuth),
		User:           negotiation.User,
		SessionID:      negotiation.SessionId,
		ValidCommands:  negotiation.ValidCommands,
		Encryption:     negotiation.Encryption,
		Authentication: negotiation.Authentication,
	}

	// If checking permissions, read the daemon's DC_SEC_QUERY verdict.
	if opts.CheckPermission != 0 {
		result.Permission = permissionName(opts.CheckPermission)
		authorized, err := readSecQueryResult(ctx, htcondorClient)
		if err != nil {
			return nil, err
		}
		result.Authorized = authorized
	}

	return result, nil
}

// Ping performs a ping operation against the schedd daemon
// This is similar to condor_ping and provides information about authentication
// and authorization. It's useful for health checks and debugging security settings.
func (s *Schedd) Ping(ctx context.Context) (*PingResult, error) {
	return s.PingWithOptions(ctx, nil)
}

// PingWithOptions performs a ping operation with optional permission checking
func (s *Schedd) PingWithOptions(ctx context.Context, opts *PingOptions) (*PingResult, error) {
	if opts == nil {
		opts = &PingOptions{}
	}

	// Determine command based on whether we're checking permissions
	// For basic ping, use DC_NOP (no operation) command
	// For permission checks, use DC_SEC_QUERY
	command := int(commands.DC_NOP)
	if opts.CheckPermission != 0 {
		command = int(commands.DC_SEC_QUERY)
	}

	// Get SecurityConfig
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, command, "CLIENT", s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Require authentication for ping operations
	secConfig.Authentication = "REQUIRED"

	// Set AuthCommand to the permission level if checking permissions
	if opts.CheckPermission != 0 {
		secConfig.AuthCommand = opts.CheckPermission
	}

	// Establish connection and authenticate
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return nil, wrapScheddConnectError(s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get security negotiation result
	negotiation := htcondorClient.GetSecurityNegotiation()
	if negotiation == nil {
		return nil, fmt.Errorf("no security negotiation performed")
	}

	// Convert negotiation result to PingResult
	result := &PingResult{
		AuthMethod:     string(negotiation.NegotiatedAuth),
		User:           negotiation.User,
		SessionID:      negotiation.SessionId,
		ValidCommands:  negotiation.ValidCommands,
		Encryption:     negotiation.Encryption,
		Authentication: negotiation.Authentication,
	}

	// If checking permissions, read the daemon's DC_SEC_QUERY verdict.
	if opts.CheckPermission != 0 {
		result.Permission = permissionName(opts.CheckPermission)
		authorized, err := readSecQueryResult(ctx, htcondorClient)
		if err != nil {
			return nil, err
		}
		result.Authorized = authorized
	}

	return result, nil
}

// wrapScheddConnectError takes the raw error from client.ConnectAndAuthenticate
// against a schedd address and produces a wrapped error whose message helps an
// operator distinguish "schedd is down" from "schedd has restarted and our
// cached sock= is stale". Both manifest as connection failures, but the
// remedies are different:
//
//   - schedd down: there's nothing the client can do — wait for it to come back
//   - stale sock: the client should re-query the collector for a fresh address
//
// The shared-port daemon answers the TCP SYN (so the connect itself succeeds)
// but RSTs the connection when it can't route the sock= to a live process,
// so the surface error from cedar is "connection reset by peer" partway
// through the handshake. We detect that combination and prepend a hint.
//
// The original error is always preserved via %w so callers can errors.Is /
// errors.As against it.
func wrapScheddConnectError(addr string, err error) error {
	if err == nil {
		return nil
	}
	// Default: keep the existing wording so log scrapers don't break.
	wrapped := fmt.Errorf("failed to connect and authenticate to schedd at %s: %w", addr, err)

	info := addresses.ParseHTCondorAddress(addr)
	if !info.IsSharedPort {
		return wrapped
	}
	if !looksLikeConnReset(err) {
		return wrapped
	}
	return fmt.Errorf(
		"failed to connect and authenticate to schedd at %s: %w (TCP reset on shared-port address with sock=%s; the daemon likely restarted and the cached sock ID is stale — re-query the collector for the current schedd address)",
		addr, err, info.SharedPortID)
}

// looksLikeConnReset returns true if err is, or wraps, a connection reset
// (ECONNRESET). Cedar wraps multiple times, so we fall back to substring
// matching when errors.Is can't see through to the syscall error.
func looksLikeConnReset(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	return strings.Contains(err.Error(), "connection reset by peer")
}

// readSecQueryResult reads the DC_SEC_QUERY reply that daemon core sends
// after the security handshake, and reports whether the authenticated
// identity is authorized for the level named by AuthCommand.
//
// The reply is a single ClassAd carrying AuthorizationSucceeded (see
// daemon_command.cpp: the DC_SEC_QUERY branch of ExecCommand). It is what
// makes this a real authorization probe rather than an authentication one:
// the handshake itself succeeds either way, and only this ad distinguishes
// "authenticated but denied" from "authorized". condor_ping reads the same
// field.
//
// A read failure is reported as an error rather than a denial. Callers that
// gate access on the result must treat an unreadable answer as "unknown",
// not as "no" — an older daemon, a truncated reply, or a network blip must
// not read as a revocation.
func readSecQueryResult(ctx context.Context, htcondorClient *client.HTCondorClient) (bool, error) {
	msg := message.NewMessageFromStream(htcondorClient.GetStream())
	ad, err := msg.GetClassAd(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to read DC_SEC_QUERY reply: %w", err)
	}
	authorized, ok := ad.EvaluateAttrBool("AuthorizationSucceeded")
	if !ok {
		return false, fmt.Errorf("DC_SEC_QUERY reply has no AuthorizationSucceeded attribute")
	}
	return authorized, nil
}

// permissionName converts a permission level constant to a human-readable name
func permissionName(permission int) string {
	switch permission {
	case DCNopRead:
		return "READ"
	case DCNopWrite:
		return "WRITE"
	case DCNopNegotiator:
		return "NEGOTIATOR"
	case DCNopAdministrator:
		return "ADMINISTRATOR"
	case DCNopOwner:
		return "OWNER"
	case DCNopConfig:
		return "CONFIG"
	case DCNopDaemon:
		return "DAEMON"
	case DCNopAdvertiseStartd:
		return "ADVERTISE_STARTD"
	case DCNopAdvertiseSchedd:
		return "ADVERTISE_SCHEDD"
	case DCNopAdvertiseMaster:
		return "ADVERTISE_MASTER"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", permission)
	}
}
