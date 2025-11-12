package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/golang-jwt/jwt/v5"
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
// This is a helper function to set up cedar's security configuration
func ConfigureSecurityForToken(token string) (*security.SecurityConfig, error) {
	if token == "" {
		return nil, fmt.Errorf("empty token provided")
	}

	// Create a security configuration that uses TOKEN authentication
	secConfig := &security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthToken},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityOptional,
		Integrity:      security.SecurityOptional,
		TokenFile:      token, // Direct token content
	}

	return secConfig, nil
}

// GetScheddWithToken creates a schedd connection configured with token authentication
// This wraps the schedd to use token authentication from context
func GetScheddWithToken(ctx context.Context, schedd *htcondor.Schedd) (*htcondor.Schedd, error) {
	// For now, we return the schedd as-is since the authentication is handled
	// at the cedar level during connection establishment. In the future, we may
	// need to extend the htcondor.Schedd API to accept SecurityConfig directly.
	//
	// TODO: Extend htcondor.Schedd to accept SecurityConfig or token in Query/Submit methods
	return schedd, nil
}

// GenerateToken generates a simple HTCondor-compatible JWT token for the given username
// This is a simplified implementation for demo mode. In production, use condor_token_create.
func GenerateToken(username, signingKeyPath string) (string, error) {
	// Read signing key
	keyData, err := os.ReadFile(signingKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read signing key: %w", err)
	}

	// For HTCondor tokens, we need to use HS256 with a symmetric key
	signingKey := keyData

	// Create token claims
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": username,                       // Subject (username)
		"iat": now.Unix(),                     // Issued at
		"exp": now.Add(24 * time.Hour).Unix(), // Expires in 24 hours
		"iss": "htcondor-api-demo",            // Issuer
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign token
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// GenerateSigningKey generates a random signing key for token generation
func GenerateSigningKey() ([]byte, error) {
	key := make([]byte, 32) // 256-bit key
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate signing key: %w", err)
	}
	return key, nil
}

// EncodeSigningKey encodes a signing key as base64
func EncodeSigningKey(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}
