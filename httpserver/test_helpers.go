// Package httpserver provides HTTP API handlers for HTCondor operations.
package httpserver

import (
	"crypto/rand"
	"fmt"

	"github.com/bbockelm/cedar/security"
)

// GenerateSigningKey generates a new signing key for token generation
// Returns the key content as bytes
func GenerateSigningKey() ([]byte, error) {
	key := make([]byte, security.TokenKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate signing key: %w", err)
	}
	return key, nil
}
