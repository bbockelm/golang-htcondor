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

// IDPProvider manages OAuth2 operations for the built-in IDP
type IDPProvider struct {
	oauth2   fosite.OAuth2Provider
	storage  *IDPStorage
	config   *fosite.Config
	strategy *compose.CommonStrategy
}

// NewIDPProvider creates a new IDP provider with SQLite storage
func NewIDPProvider(dbPath string, issuer string) (*IDPProvider, error) {
	storage, err := NewIDPStorage(dbPath)
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
		TokenURL:                 issuer + "/idp/token",
		AccessTokenIssuer:        issuer,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}

	// Generate or load HMAC secret (32 bytes for HMAC-SHA512/256)
	hmacSecret, err := storage.LoadHMACSecret(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load HMAC secret: %w", err)
	}
	if len(hmacSecret) == 0 {
		// Generate new HMAC secret
		hmacSecret = make([]byte, 32)
		if _, err := rand.Read(hmacSecret); err != nil {
			return nil, fmt.Errorf("failed to generate HMAC secret: %w", err)
		}
		if err := storage.SaveHMACSecret(ctx, hmacSecret); err != nil {
			return nil, fmt.Errorf("failed to save HMAC secret: %w", err)
		}
	}
	config.GlobalSecret = hmacSecret

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

	return &IDPProvider{
		oauth2:   oauth2Provider,
		storage:  storage,
		config:   config,
		strategy: strategy,
	}, nil
}

// Close closes the IDP provider and its storage
func (p *IDPProvider) Close() error {
	return p.storage.Close()
}

// GetProvider returns the underlying fosite OAuth2Provider
func (p *IDPProvider) GetProvider() fosite.OAuth2Provider {
	return p.oauth2
}

// GetStorage returns the IDP storage
func (p *IDPProvider) GetStorage() *IDPStorage {
	return p.storage
}

// GetStrategy returns the OAuth2 strategy
func (p *IDPProvider) GetStrategy() *compose.CommonStrategy {
	return p.strategy
}

// UpdateIssuer updates the issuer URL in the OAuth2 config
func (p *IDPProvider) UpdateIssuer(issuer string) {
	p.config.AccessTokenIssuer = issuer
	p.config.TokenURL = issuer + "/idp/token"
}

// DefaultIDPSession creates a default OpenID Connect session for IDP
func DefaultIDPSession(username string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Subject:   username,
			Issuer:    "htcondor-idp",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
		Headers: &jwt.Headers{},
		Subject: username,
	}
}
