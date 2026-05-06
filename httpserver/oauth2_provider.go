package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
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
	oauth2   fosite.OAuth2Provider
	storage  *OAuth2Storage
	config   *fosite.Config
	strategy *compose.CommonStrategy
}

// OAuth2ProviderOptions configures lifespans and other tunables for
// the OAuth2 provider. Lifespans must be > 0; callers are expected to
// validate or default before constructing. DB is the unified
// application database (see appdb); the provider does not own its
// lifecycle.
type OAuth2ProviderOptions struct {
	DB                   *sql.DB
	Issuer               string
	AccessTokenLifespan  time.Duration
	RefreshTokenLifespan time.Duration
}

// NewOAuth2Provider creates a new OAuth2 provider with SQLite storage.
// Both AccessTokenLifespan and RefreshTokenLifespan in opts must be > 0; otherwise an
// error is returned. This is intentional: silent fallback to fosite's defaults (1h
// access, 30d refresh) has bitten downstream projects when callers forget to pass them
// through, so callers must opt in explicitly.
func NewOAuth2Provider(opts OAuth2ProviderOptions) (*OAuth2Provider, error) {
	if opts.AccessTokenLifespan <= 0 {
		return nil, fmt.Errorf("OAuth2 provider: AccessTokenLifespan must be > 0")
	}
	if opts.RefreshTokenLifespan <= 0 {
		return nil, fmt.Errorf("OAuth2 provider: RefreshTokenLifespan must be > 0")
	}
	if opts.RefreshTokenLifespan < opts.AccessTokenLifespan {
		return nil, fmt.Errorf("OAuth2 provider: RefreshTokenLifespan (%s) must be >= AccessTokenLifespan (%s); shorter refresh tokens make refresh grants fail before access tokens expire",
			opts.RefreshTokenLifespan, opts.AccessTokenLifespan)
	}

	if opts.DB == nil {
		return nil, fmt.Errorf("OAuth2 provider: DB is required")
	}
	storage := NewOAuth2Storage(opts.DB)

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
		AccessTokenLifespan:      opts.AccessTokenLifespan,
		RefreshTokenLifespan:     opts.RefreshTokenLifespan,
		AuthorizeCodeLifespan:    time.Minute * 10,
		IDTokenLifespan:          opts.AccessTokenLifespan,
		TokenURL:                 opts.Issuer + "/mcp/oauth2/token",
		AccessTokenIssuer:        opts.Issuer,
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
		compose.OAuth2PKCEFactory,
	)

	return &OAuth2Provider{
		oauth2:   oauth2Provider,
		storage:  storage,
		config:   config,
		strategy: strategy,
	}, nil
}

// Close is now a no-op: the OAuth2 provider does not own the
// underlying *sql.DB anymore. The Handler that opened the unified
// app DB is responsible for closing it on shutdown. Method retained
// so callers that defer p.Close() during refactors don't break.
func (p *OAuth2Provider) Close() error {
	return nil
}

// GetProvider returns the underlying fosite OAuth2Provider
func (p *OAuth2Provider) GetProvider() fosite.OAuth2Provider {
	return p.oauth2
}

// GetStorage returns the OAuth2 storage
func (p *OAuth2Provider) GetStorage() *OAuth2Storage {
	return p.storage
}

// GetStrategy returns the OAuth2 strategy
func (p *OAuth2Provider) GetStrategy() *compose.CommonStrategy {
	return p.strategy
}

// UpdateIssuer updates the issuer URL in the configuration
// This is useful when using port 0 and getting the actual port after server start
func (p *OAuth2Provider) UpdateIssuer(issuer string) {
	p.config.TokenURL = issuer + "/mcp/oauth2/token"
	p.config.AccessTokenIssuer = issuer
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

// setStandardTokenExpiries populates Session.ExpiresAt for AccessToken and RefreshToken
// using the configured lifespans, mirroring what fosite's standard authorize-code and
// refresh-grant pipelines do internally. Custom flows that build a fosite.AccessRequest
// and call GenerateAccessToken / GenerateRefreshToken directly (device code grant, RFC
// 8693 token exchange, etc.) bypass that pipeline and must call this before generating
// tokens — otherwise the session is persisted with zero-valued expiries, which makes
// the HMAC strategy treat refresh tokens as having unlimited lifetime and access tokens
// as expiring relative to the (potentially old) RequestedAt timestamp instead of now.
// See PelicanPlatform/pelican#3389.
func setStandardTokenExpiries(ctx context.Context, cfg *fosite.Config, session fosite.Session) {
	if session == nil {
		return
	}
	now := time.Now().UTC()
	session.SetExpiresAt(fosite.AccessToken, now.Add(cfg.GetAccessTokenLifespan(ctx)).Round(time.Second))
	session.SetExpiresAt(fosite.RefreshToken, now.Add(cfg.GetRefreshTokenLifespan(ctx)).Round(time.Second))
}

// IntrospectToken validates an access token and returns the session
func (p *OAuth2Provider) IntrospectToken(ctx context.Context, token string) (fosite.Session, error) {
	session := DefaultOpenIDConnectSession("")
	_, _, err := p.oauth2.IntrospectToken(ctx, token, fosite.AccessToken, session, []string{}...)
	if err != nil {
		return nil, err
	}
	return session, nil
}
