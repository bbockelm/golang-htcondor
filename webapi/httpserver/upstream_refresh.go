package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

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
	Subject       string
	Issuer        string
	RefreshToken  string
	GrantedScopes []string
	ObtainedAt    time.Time
	LastCheckedAt time.Time
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
			(subject, issuer, refresh_token, refresh_token_dek, granted_scopes, obtained_at, last_checked_at)
		VALUES (?, ?, ?, ?, ?, ?, NULL)`,
		g.Subject, g.Issuer, data, dek, strings.Join(g.GrantedScopes, " "), g.ObtainedAt.UTC())
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
		data, dek   []byte
		scopes      string
		obtained    time.Time
		lastChecked sql.NullTime
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT refresh_token, refresh_token_dek, granted_scopes, obtained_at, last_checked_at
		FROM upstream_refresh_tokens WHERE subject = ? AND issuer = ?`,
		subject, issuer).Scan(&data, &dek, &scopes, &obtained, &lastChecked)
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
		Subject:       subject,
		Issuer:        issuer,
		RefreshToken:  token,
		GrantedScopes: strings.Fields(scopes),
		ObtainedAt:    obtained,
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
