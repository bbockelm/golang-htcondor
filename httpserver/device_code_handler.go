package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
)

// Device flow error codes (RFC 8628)
var (
	ErrAuthorizationPending = &fosite.RFC6749Error{
		ErrorField:       "authorization_pending",
		DescriptionField: "The authorization request is still pending",
		CodeField:        http.StatusBadRequest,
	}
	ErrSlowDown = &fosite.RFC6749Error{
		ErrorField:       "slow_down",
		DescriptionField: "Client is polling too frequently",
		CodeField:        http.StatusBadRequest,
	}
	ErrExpiredToken = &fosite.RFC6749Error{
		ErrorField:       "expired_token",
		DescriptionField: "The device code has expired",
		CodeField:        http.StatusBadRequest,
	}
)

// DeviceCodeHandler implements the OAuth 2.0 Device Authorization Grant (RFC 8628)
type DeviceCodeHandler struct {
	storage        *OAuth2Storage
	config         *fosite.Config
	deviceCodeLen  int
	userCodeLen    int
	userCodeFormat string // "numeric" or "alphanumeric"
}

// NewDeviceCodeHandler creates a new device code handler
func NewDeviceCodeHandler(storage *OAuth2Storage, config *fosite.Config) *DeviceCodeHandler {
	return &DeviceCodeHandler{
		storage:        storage,
		config:         config,
		deviceCodeLen:  32, // Length for device code
		userCodeLen:    8,  // Length for user code
		userCodeFormat: "alphanumeric",
	}
}

// HandleDeviceAuthorizationRequest handles the device authorization endpoint
func (h *DeviceCodeHandler) HandleDeviceAuthorizationRequest(ctx context.Context, client fosite.Client, scopes []string) (*DeviceAuthorizationResponse, error) {
	// Validate client
	if client == nil {
		return nil, fosite.ErrInvalidClient
	}

	// Generate device code
	deviceCode, err := h.generateDeviceCode()
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err).WithDebug("Failed to generate device code")
	}

	// Generate user code
	userCode, err := h.generateUserCode()
	if err != nil {
		return nil, fosite.ErrServerError.WithWrap(err).WithDebug("Failed to generate user code")
	}

	// Create request
	request := fosite.NewRequest()
	request.RequestedAt = time.Now()
	request.Client = client
	request.RequestedScope = scopes
	request.GrantedScope = scopes // Initially grant requested scopes

	// Calculate expiration
	expiresIn := 10 * time.Minute // Default 10 minutes for device codes
	expiresAt := time.Now().Add(expiresIn)

	// Store device code session
	if err := h.storage.CreateDeviceCodeSession(ctx, deviceCode, userCode, request, expiresAt); err != nil {
		return nil, fosite.ErrServerError.WithWrap(err).WithDebug("Failed to store device code")
	}

	// Get verification URI from config (should be set by the caller)
	verificationURI := h.config.AccessTokenIssuer + "/mcp/oauth2/device/verify"

	return &DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: fmt.Sprintf("%s?user_code=%s", verificationURI, userCode),
		ExpiresIn:               int(expiresIn.Seconds()),
		Interval:                5, // Poll interval in seconds
	}, nil
}

// HandleDeviceAccessRequest handles token requests with device_code grant type
func (h *DeviceCodeHandler) HandleDeviceAccessRequest(ctx context.Context, deviceCode string, session fosite.Session) (fosite.Requester, error) {
	// Get device code session
	request, err := h.storage.GetDeviceCodeSession(ctx, deviceCode, session)
	if err != nil {
		// Map storage errors to appropriate OAuth errors
		if err == fosite.ErrNotFound {
			return nil, fosite.ErrInvalidGrant.WithDebug("Device code not found")
		}
		if err == ErrAuthorizationPending {
			return nil, err // Return as-is for proper error response
		}
		if err == fosite.ErrAccessDenied {
			return nil, err // Return as-is for proper error response
		}
		if err == ErrExpiredToken {
			return nil, fosite.ErrInvalidGrant.WithDebug("Device code expired")
		}
		return nil, err
	}

	// Update polling timestamp for rate limiting (optional)
	_ = h.storage.UpdateDeviceCodePolling(ctx, deviceCode)

	// Invalidate the device code after successful use
	if err := h.storage.InvalidateDeviceCodeSession(ctx, deviceCode); err != nil {
		// Log but don't fail the request
		// In production, you'd want proper logging here
	}

	return request, nil
}

// generateDeviceCode generates a cryptographically secure random device code
func (h *DeviceCodeHandler) generateDeviceCode() (string, error) {
	b := make([]byte, h.deviceCodeLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// generateUserCode generates a user-friendly code for device authorization
func (h *DeviceCodeHandler) generateUserCode() (string, error) {
	if h.userCodeFormat == "numeric" {
		return h.generateNumericCode()
	}
	return h.generateAlphanumericCode()
}

// generateNumericCode generates a numeric user code (e.g., "12345678")
func (h *DeviceCodeHandler) generateNumericCode() (string, error) {
	// Generate a random number
	max := new(big.Int)
	max.Exp(big.NewInt(10), big.NewInt(int64(h.userCodeLen)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	// Format with leading zeros
	format := fmt.Sprintf("%%0%dd", h.userCodeLen)
	return fmt.Sprintf(format, n), nil
}

// generateAlphanumericCode generates an alphanumeric user code (e.g., "ABCD-EFGH")
// Uses a character set that avoids ambiguous characters (0/O, 1/I/l)
func (h *DeviceCodeHandler) generateAlphanumericCode() (string, error) {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude ambiguous chars
	const groupSize = 4
	const separator = "-"

	var code strings.Builder
	for i := 0; i < h.userCodeLen; i++ {
		if i > 0 && i%groupSize == 0 {
			code.WriteString(separator)
		}
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		code.WriteByte(charset[n.Int64()])
	}
	return code.String(), nil
}

// DeviceAuthorizationResponse represents the response from device authorization endpoint
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}
