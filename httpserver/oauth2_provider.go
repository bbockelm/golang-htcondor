package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

	// Generate RSA key for JWT signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	config := &fosite.Config{
		AccessTokenLifespan:   time.Hour,
		RefreshTokenLifespan:  time.Hour * 24 * 7,
		AuthorizeCodeLifespan: time.Minute * 10,
		IDTokenLifespan:       time.Hour,
		TokenURL:              issuer + "/mcp/token",
		AccessTokenIssuer:     issuer,
		ScopeStrategy:         fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}

	// Create JWK strategy for signing
	jwtStrategy := &jwt.DefaultSigner{
		GetPrivateKey: func(ctx context.Context) (interface{}, error) {
			return privateKey, nil
		},
	}

	// Create OAuth2 provider with all necessary handlers
	oauth2Provider := compose.Compose(
		config,
		storage,
		jwtStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
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
