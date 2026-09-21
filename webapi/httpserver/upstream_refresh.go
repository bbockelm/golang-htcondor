package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb/seal"
)

// Holding a credential to the upstream identity provider, so this server can
// ask it about a user after they have gone home.
//
// Every other token here is one this server ISSUES. This is the one it HOLDS,
// and it exists for a gap the refresh path documents in its own comments: the
// groups in a session are frozen at consent, so re-running the policy catches
// an operator changing it but not a user being removed from a group upstream.
// Closing that needs either an account database -- which systemGroupOracle
// uses where there is one, and a container has none -- or a live credential to
// the provider. This is the second.

// UpstreamRefreshMode decides whether that credential is kept and used.
type UpstreamRefreshMode string

const (
	// UpstreamRefreshAuto keeps and uses the credential when the provider
	// hands one over, and does nothing when it does not.
	//
	// The default, because whether a provider releases offline_access is
	// the provider's decision and not every one will. What this server
	// ASKS for is already the operator's to set (HTTP_API_OAUTH2_SCOPES);
	// auto does not add to that request, so enabling this cannot break a
	// login against a provider that rejects a scope it does not know.
	UpstreamRefreshAuto UpstreamRefreshMode = "auto"

	// UpstreamRefreshOn is auto plus a complaint: a provider that returns
	// no refresh token is a misconfiguration the operator asked to hear
	// about, rather than a silent fallback to never checking.
	UpstreamRefreshOn UpstreamRefreshMode = "on"

	// UpstreamRefreshOff never stores the credential. For a deployment
	// that would rather not hold one at all, which is a defensible
	// position: it is a long-lived key to somebody else's identity
	// provider, and the account-database path covers the same ground
	// where an account database exists.
	UpstreamRefreshOff UpstreamRefreshMode = "off"
)

// ParseUpstreamRefreshMode reads HTTP_API_UPSTREAM_REFRESH.
func ParseUpstreamRefreshMode(raw string) (UpstreamRefreshMode, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "auto":
		return UpstreamRefreshAuto, nil
	case "on", "true", "yes":
		return UpstreamRefreshOn, nil
	case "off", "false", "no":
		return UpstreamRefreshOff, nil
	default:
		return "", fmt.Errorf("expected auto, on or off, got %q", raw)
	}
}

// upstreamGrant is one stored credential.
type upstreamGrant struct {
	// Subject is the SESSION subject -- what a grant carries, and so what
	// the refresh path looks this up by.
	Subject string
	// ProviderSubject is the identity provider's own name for the same
	// user. The two differ wherever identities are mapped to local
	// accounts. Kept so a userinfo answer can be checked against the user
	// it was supposed to be about: the call names nobody, the credential
	// decides whose claims come back.
	ProviderSubject string
	Issuer          string
	RefreshToken    string
	GrantedScopes   []string
	ObtainedAt      time.Time
	LastCheckedAt   time.Time
}

// HasOfflineAccess reports whether the provider granted the scope this
// whole mechanism depends on.
//
// Read from what the provider RETURNED, not from what was asked: a
// provider may quietly drop a scope it does not wish to grant, and the
// request is then a statement of intent rather than of fact.
func (g upstreamGrant) HasOfflineAccess() bool {
	for _, s := range g.GrantedScopes {
		if s == "offline_access" {
			return true
		}
	}
	return false
}

// upstreamRefreshStore persists the credential.
type upstreamRefreshStore struct {
	db     *sql.DB
	sealer *seal.Sealer
	logger *logging.Logger
}

// Save records the credential for one subject at one issuer, replacing any
// previous one.
//
// A token with no refresh token is a delete rather than a no-op: the
// provider declining to renew it is exactly the case where a stale one
// must not keep being used.
func (s *upstreamRefreshStore) Save(ctx context.Context, g upstreamGrant) error {
	if s == nil || s.db == nil {
		return nil
	}
	if strings.TrimSpace(g.Subject) == "" || strings.TrimSpace(g.Issuer) == "" {
		return fmt.Errorf("subject and issuer are required")
	}
	if strings.TrimSpace(g.RefreshToken) == "" {
		return s.Delete(ctx, g.Subject, g.Issuer)
	}

	var data, dek []byte
	if s.sealer != nil {
		var err error
		data, dek, err = s.sealer.Seal([]byte(g.RefreshToken))
		if err != nil {
			return fmt.Errorf("seal the upstream refresh token: %w", err)
		}
	} else {
		data = []byte(g.RefreshToken)
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO upstream_refresh_tokens
			(subject, provider_subject, issuer, refresh_token, refresh_token_dek,
			 granted_scopes, obtained_at, last_checked_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
		g.Subject, g.ProviderSubject, g.Issuer, data, dek,
		strings.Join(g.GrantedScopes, " "), g.ObtainedAt.UTC())
	if err != nil {
		return fmt.Errorf("storing the upstream refresh token for %q: %w", g.Subject, err)
	}
	return nil
}

// Load returns the stored credential, or sql.ErrNoRows when there is none.
func (s *upstreamRefreshStore) Load(ctx context.Context, subject, issuer string) (upstreamGrant, error) {
	if s == nil || s.db == nil {
		return upstreamGrant{}, sql.ErrNoRows
	}
	var (
		data, dek       []byte
		providerSubject string
		scopes          string
		obtained        time.Time
		lastChecked     sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT refresh_token, refresh_token_dek, provider_subject, granted_scopes, obtained_at, last_checked_at
		FROM upstream_refresh_tokens WHERE subject = ? AND issuer = ?`,
		subject, issuer).Scan(&data, &dek, &providerSubject, &scopes, &obtained, &lastChecked)
	if err != nil {
		return upstreamGrant{}, err
	}

	token := string(data)
	if len(dek) > 0 {
		if s.sealer == nil {
			// Refusing beats guessing: the row was written by a server with
			// a KEK and this one has none, so the value is unreadable and
			// treating it as plaintext would send ciphertext to a provider.
			return upstreamGrant{}, errors.New(
				"the stored upstream refresh token is sealed but no KEK is configured (HTTP_API_KEK_FILE)")
		}
		plain, err := s.sealer.Open(data, dek)
		if err != nil {
			return upstreamGrant{}, fmt.Errorf("unseal the upstream refresh token: %w", err)
		}
		token = string(plain)
	}

	g := upstreamGrant{
		Subject:         subject,
		ProviderSubject: providerSubject,
		Issuer:          issuer,
		RefreshToken:    token,
		GrantedScopes:   strings.Fields(scopes),
		ObtainedAt:      obtained,
	}
	if lastChecked.Valid {
		g.LastCheckedAt = lastChecked.Time
	}
	return g, nil
}

// Delete forgets the credential, which is what a provider refusing to renew
// it means.
func (s *upstreamRefreshStore) Delete(ctx context.Context, subject, issuer string) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM upstream_refresh_tokens WHERE subject = ? AND issuer = ?`, subject, issuer)
	return err
}

// MarkChecked records that the credential was exercised, so the checker can
// rate-limit itself against somebody else's identity provider.
func (s *upstreamRefreshStore) MarkChecked(ctx context.Context, subject, issuer string, at time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE upstream_refresh_tokens SET last_checked_at = ? WHERE subject = ? AND issuer = ?`,
		at.UTC(), subject, issuer)
	return err
}

// upstreamIssuer names the provider a stored credential belongs to.
//
// The token endpoint rather than a nominal issuer string, because that is
// the thing the credential is redeemable at and it is always known -- the
// issuer URL is only present when the deployment configured OIDC
// discovery, and is discarded once the endpoints are resolved.
func (h *Handler) upstreamIssuer() string {
	if h.oauth2Config == nil {
		return ""
	}
	return h.oauth2Config.Endpoint.TokenURL
}

// rememberUpstreamRefresh stores the provider's refresh token for a user who
// has just logged in.
//
// Keyed by the SESSION subject, which is what a later refresh grant carries
// and therefore the only thing it can look this up by. Where identities are
// mapped that is the local account; the provider's own name for the user is
// kept beside it, because the userinfo answer has to be checked against the
// user it was meant to be about -- that call names nobody, so the credential
// alone decides whose claims come back.
//
// Failures are logged and swallowed. A login that worked must not be undone
// because a credential for a later background check could not be filed --
// the worst case is the check not running, which is where every deployment
// without this feature already is.
func (h *Handler) rememberUpstreamRefresh(ctx context.Context, subject, providerSubject, refreshToken string, grantedScopes []string) {
	if h.upstreamRefresh == nil || h.upstreamRefreshMode == UpstreamRefreshOff {
		return
	}
	issuer := h.upstreamIssuer()
	if subject == "" || issuer == "" {
		return
	}

	if strings.TrimSpace(refreshToken) == "" {
		// Nothing came back. Under "on" the operator asked to be told,
		// because they configured this expecting it to work and it is not
		// working; under "auto" this is the ordinary case for a provider
		// that does not release offline_access, and saying so on every
		// login would be noise.
		if h.upstreamRefreshMode == UpstreamRefreshOn {
			h.logger.Warn(logging.DestinationHTTP,
				"HTTP_API_UPSTREAM_REFRESH is on but the identity provider returned no refresh token; "+
					"membership will not be re-checked for this user",
				"subject", subject, "issuer", issuer,
				"hint", "add offline_access to HTTP_API_OAUTH2_SCOPES, and check the provider releases it")
		}
		// Still a delete: see Save. A provider that stops renewing has
		// retired the old credential whatever the mode says.
		if err := h.upstreamRefresh.Delete(ctx, subject, issuer); err != nil {
			h.logger.Warn(logging.DestinationHTTP, "Could not forget a stale upstream refresh token",
				"subject", subject, "error", err)
		}
		return
	}

	if err := h.upstreamRefresh.Save(ctx, upstreamGrant{
		Subject:         subject,
		ProviderSubject: providerSubject,
		Issuer:          issuer,
		RefreshToken:    refreshToken,
		GrantedScopes:   grantedScopes,
		ObtainedAt:      time.Now().UTC(),
	}); err != nil {
		h.logger.Warn(logging.DestinationHTTP, "Could not store the upstream refresh token",
			"subject", subject, "issuer", issuer, "error", err)
		return
	}
	h.logger.Info(logging.DestinationHTTP, "Stored the identity provider's refresh token",
		"subject", subject, "issuer", issuer)
}

// scopesFromToken reads the scopes the provider actually granted.
//
// Providers report this in the token response's "scope" field, which
// oauth2.Token carries as an extra. An absent field is not "none granted":
// it means the provider did not say, and the request's own scopes are the
// best available answer.
func scopesFromToken(tok *oauth2.Token, requested []string) []string {
	if tok == nil {
		return nil
	}
	if raw, ok := tok.Extra("scope").(string); ok && strings.TrimSpace(raw) != "" {
		return strings.Fields(raw)
	}
	return requested
}
