// Package httpserver provides HTTP API handlers for HTCondor operations.
package httpserver

import (
	"context"
	"fmt"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// authContextKey is the type for the authentication context key
type authContextKey struct{}

// WithToken creates a context that includes authentication token information
// This sets up the security configuration for cedar to use TOKEN authentication
func WithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, authContextKey{}, token)
}

// GetTokenFromContext retrieves the token from the context
func GetTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(authContextKey{}).(string)
	return token, ok
}

// ConfigureSecurityForToken configures security settings to use the provided token
// This is a helper function to set up cedar's security configuration for TOKEN authentication
func ConfigureSecurityForToken(token string) (*security.SecurityConfig, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token provided")
	}

	// Create a security configuration that uses TOKEN authentication
	// The token content is stored in TokenFile field (cedar supports both file paths and direct content)
	secConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		Token:          token,
	}

	return secConfig, nil
}

// GetSecurityConfigFromToken retrieves the token from context and creates a SecurityConfig
// This is a convenience function for HTTP handlers to convert context token to SecurityConfig
func GetSecurityConfigFromToken(ctx context.Context) (*security.SecurityConfig, error) {
	token, ok := GetTokenFromContext(ctx)
	if !ok || token == "" {
		return nil, fmt.Errorf("no token in context")
	}

	return ConfigureSecurityForToken(token)
}

// GetScheddWithToken creates a schedd connection configured with token authentication
// This wraps the schedd to use token authentication from context
//
//nolint:revive // ctx parameter reserved for future use
func GetScheddWithToken(ctx context.Context, schedd *htcondor.Schedd) (*htcondor.Schedd, error) {
	// For now, we return the schedd as-is since the authentication is handled
	// at the cedar level during connection establishment. In the future, we may
	// need to extend the htcondor.Schedd API to accept SecurityConfig directly.
	//
	// TODO: Extend htcondor.Schedd to accept SecurityConfig or token in Query/Submit methods
	return schedd, nil
}
