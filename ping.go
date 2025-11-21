package htcondor

import (
	"context"
	"fmt"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/security"
)

// Permission levels for DC_SEC_QUERY authorization checking.
// These are sent as AuthCommand during the security handshake.
// The naming follows HTCondor's command code constants (DC_NOP_*).
const (
	DCNopRead            = 60021
	DCNopWrite           = 60022
	DCNopNegotiator      = 60023
	DCNopAdministrator   = 60024
	DCNopConfig          = 60025
	DCNopDaemon          = 60026
	DCNopAdvertiseStartd = 60027
	DCNopAdvertiseSchedd = 60028
	DCNopAdvertiseMaster = 60029
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
	// Authorized indicates whether the client is authorized for the requested permission level
	// Only set when CheckPermission is specified
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

	// Establish connection using cedar client
	htcondorClient, err := client.ConnectToAddress(ctx, c.address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to collector: %w", err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

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

	// Perform security handshake
	auth := security.NewAuthenticator(secConfig, cedarStream)
	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		return nil, fmt.Errorf("ping handshake failed: %w", err)
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

	// If checking permissions, extract authorization result
	if opts.CheckPermission != 0 {
		// The authorization status should be in ValidCommands or a separate field
		// For now, we'll consider the handshake success as authorization success
		// TODO: Update once cedar exposes authorization status explicitly via SecAuthorizationSucceeded
		result.Authorized = negotiation.Authentication // Temporary: if auth succeeded, consider authorized
		result.Permission = permissionName(opts.CheckPermission)
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

	// Establish connection using cedar client
	htcondorClient, err := client.ConnectToAddress(ctx, s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to schedd at %s: %w", s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

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

	// Perform security handshake
	auth := security.NewAuthenticator(secConfig, cedarStream)
	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		return nil, fmt.Errorf("ping handshake failed: %w", err)
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

	// If checking permissions, extract authorization result
	if opts.CheckPermission != 0 {
		// The authorization status should be in ValidCommands or a separate field
		// For now, we'll consider the handshake success as authorization success
		// TODO: Update once cedar exposes authorization status explicitly via SecAuthorizationSucceeded
		result.Authorized = negotiation.Authentication // Temporary: if auth succeeded, consider authorized
		result.Permission = permissionName(opts.CheckPermission)
	}

	return result, nil
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
