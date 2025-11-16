package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// OAuth2Provider manages OAuth2 operations
type OAuth2Provider struct {
	oauth2  fosite.OAuth2Provider
	storage *OAuth2Storage
	config  *fosite.Config
}

// NewOAuth2Provider creates a new OAuth2 provider with SQLite storage
func NewOAuth2Provider(dbPath string, issuer string) (*OAuth2Provider, error) {
	storage, err := NewOAuth2Storage(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Try to load existing RSA key from database
	ctx := context.Background()
	privateKeyPEM, err := storage.LoadRSAKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load RSA key: %w", err)
	}

	var privateKey *rsa.PrivateKey
	if privateKeyPEM == "" {
		// Generate new RSA key
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}

		// Persist the key in the database
		keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		})
		if err := storage.SaveRSAKey(ctx, string(keyPEM)); err != nil {
			return nil, fmt.Errorf("failed to save RSA key: %w", err)
		}
	} else {
		// Parse existing key from PEM
		block, _ := pem.Decode([]byte(privateKeyPEM))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block")
		}
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key: %w", err)
		}
	}

	config := &fosite.Config{
		AccessTokenLifespan:      time.Hour,
		RefreshTokenLifespan:     time.Hour * 24 * 7,
		AuthorizeCodeLifespan:    time.Minute * 10,
		IDTokenLifespan:          time.Hour,
		TokenURL:                 issuer + "/mcp/oauth2/token",
		AccessTokenIssuer:        issuer,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}

	// Create key getter function for OpenID strategy
	keyGetter := func(_ context.Context) (interface{}, error) {
		return privateKey, nil
	}

	// Create strategy with proper key
	strategy := &compose.CommonStrategy{
		CoreStrategy:               compose.NewOAuth2HMACStrategy(config),
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
	}

	// Create OAuth2 provider with proper strategy
	oauth2Provider := compose.Compose(
		config,
		storage,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
	)

	return &OAuth2Provider{
		oauth2:  oauth2Provider,
		storage: storage,
		config:  config,
	}, nil
}

// Close closes the OAuth2 provider and its storage
func (p *OAuth2Provider) Close() error {
	return p.storage.Close()
}

// GetProvider returns the underlying fosite OAuth2Provider
func (p *OAuth2Provider) GetProvider() fosite.OAuth2Provider {
	return p.oauth2
}

// GetStorage returns the OAuth2 storage
func (p *OAuth2Provider) GetStorage() *OAuth2Storage {
	return p.storage
}

// DefaultOpenIDConnectSession creates a default OpenID Connect session
func DefaultOpenIDConnectSession(username string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject:   username,
			Issuer:    "htcondor-mcp",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
		Headers: &jwt.Headers{},
		Subject: username,
	}
}
