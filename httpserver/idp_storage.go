package httpserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	_ "github.com/glebarez/sqlite" // SQLite driver (pure Go, no CGO)
	"github.com/ory/fosite"
	"golang.org/x/crypto/bcrypt"
)

// IDPStorage implements fosite storage interfaces using the unified
// application database. The IDP's tables (idp_*) live alongside the
// OAuth2/MCP tables in the same SQLite file managed by appdb.
type IDPStorage struct {
	db *sql.DB
}

// NewIDPStorage wraps an already-opened, already-migrated DB. Schema
// is owned by the appdb migrations; this struct only holds the query
// helpers. The caller retains DB ownership.
func NewIDPStorage(db *sql.DB) *IDPStorage {
	return &IDPStorage{db: db}
}

// User management methods

// CreateUser creates a new user with hashed password and specified state
func (s *IDPStorage) CreateUser(ctx context.Context, username, password, state string) error {
	// Validate state
	if state != "pending" && state != "active" && state != "admin" {
		return fmt.Errorf("invalid user state: must be 'pending', 'active', or 'admin'")
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO idp_users (username, password_hash, state)
		VALUES (?, ?, ?)
	`, username, string(passwordHash), state)

	return err
}

// AuthenticateUser verifies username and password
func (s *IDPStorage) AuthenticateUser(ctx context.Context, username, password string) error {
	var passwordHash string
	var state string
	err := s.db.QueryRowContext(ctx, `
		SELECT password_hash, state FROM idp_users WHERE username = ?
	`, username).Scan(&passwordHash, &state)

	if err == sql.ErrNoRows {
		return fosite.ErrNotFound
	}
	if err != nil {
		return err
	}

	// Check if user is active or admin (pending users cannot log in)
	if state == "pending" {
		return fmt.Errorf("user account is pending activation")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return fosite.ErrNotFound // Don't leak that user exists
	}

	return nil
}

// GetUserState retrieves the state of a user
func (s *IDPStorage) GetUserState(ctx context.Context, username string) (string, error) {
	var state string
	err := s.db.QueryRowContext(ctx, `
		SELECT state FROM idp_users WHERE username = ?
	`, username).Scan(&state)

	if err == sql.ErrNoRows {
		return "", fosite.ErrNotFound
	}
	if err != nil {
		return "", err
	}

	return state, nil
}

// UserExists checks if a user exists
func (s *IDPStorage) UserExists(ctx context.Context, username string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM idp_users WHERE username = ?
	`, username).Scan(&count)

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// validIDPTableNames is a whitelist of allowed table names for IDP
var validIDPTableNames = map[string]bool{
	"idp_access_tokens":       true,
	"idp_refresh_tokens":      true,
	"idp_authorization_codes": true,
	"idp_oidc_sessions":       true,
	"idp_pkce_requests":       true,
}

// buildIDPInsertQuery builds an INSERT query for a valid IDP table name
func buildIDPInsertQuery(table string) (string, error) {
	if !validIDPTableNames[table] {
		return "", fmt.Errorf("invalid table name: %s", table)
	}
	// Safe: table name is from whitelist
	return `INSERT INTO ` + table + ` (signature, request_id, requested_at, client_id, scopes, granted_scopes,
		form_data, session_data, subject, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, nil
}

// buildIDPSelectQuery builds a SELECT query for a valid IDP table name
func buildIDPSelectQuery(table string) (string, error) {
	if !validIDPTableNames[table] {
		return "", fmt.Errorf("invalid table name: %s", table)
	}
	// Safe: table name is from whitelist
	return `SELECT request_id, requested_at, client_id, scopes, granted_scopes,
		form_data, session_data, subject, active
		FROM ` + table + ` WHERE signature = ?`, nil
}

// buildIDPDeleteQuery builds a DELETE query for a valid IDP table name
func buildIDPDeleteQuery(table string) (string, error) {
	if !validIDPTableNames[table] {
		return "", fmt.Errorf("invalid table name: %s", table)
	}
	// Safe: table name is from whitelist
	return `DELETE FROM ` + table + ` WHERE signature = ?`, nil
}

// CreateClient creates a new OAuth2 client
func (s *IDPStorage) CreateClient(ctx context.Context, client *fosite.DefaultClient) error {
	redirectURIs, err := json.Marshal(client.RedirectURIs)
	if err != nil {
		return err
	}
	grantTypes, err := json.Marshal(client.GrantTypes)
	if err != nil {
		return err
	}
	responseTypes, err := json.Marshal(client.ResponseTypes)
	if err != nil {
		return err
	}
	scopes, err := json.Marshal(client.Scopes)
	if err != nil {
		return err
	}

	public := 0
	if client.Public {
		public = 1
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO idp_clients (id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, client.ID, string(client.Secret), string(redirectURIs), string(grantTypes),
		string(responseTypes), string(scopes), public)

	return err
}

// GetClient retrieves a client by ID
//
//nolint:dupl // This method is similar to OAuth2Storage.GetClient but uses a different table
func (s *IDPStorage) GetClient(ctx context.Context, clientID string) (fosite.Client, error) {
	var (
		secret        string
		redirectURIs  string
		grantTypes    string
		responseTypes string
		scopes        string
		public        int
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT client_secret, redirect_uris, grant_types, response_types, scopes, public
		FROM idp_clients WHERE id = ?
	`, clientID).Scan(&secret, &redirectURIs, &grantTypes, &responseTypes, &scopes, &public)

	if err == sql.ErrNoRows {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	client := &fosite.DefaultClient{
		ID:     clientID,
		Secret: []byte(secret),
		Public: public == 1,
	}

	if err := json.Unmarshal([]byte(redirectURIs), &client.RedirectURIs); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(grantTypes), &client.GrantTypes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(responseTypes), &client.ResponseTypes); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(scopes), &client.Scopes); err != nil {
		return nil, err
	}

	return client, nil
}

// CreateAccessTokenSession stores an access token session
func (s *IDPStorage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "idp_access_tokens", signature, request)
}

// GetAccessTokenSession retrieves an access token session
func (s *IDPStorage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "idp_access_tokens", signature, session)
}

// DeleteAccessTokenSession deletes an access token session
func (s *IDPStorage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "idp_access_tokens", signature)
}

// CreateRefreshTokenSession stores a refresh token session
func (s *IDPStorage) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "idp_refresh_tokens", signature, request)
}

// GetRefreshTokenSession retrieves a refresh token session
func (s *IDPStorage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "idp_refresh_tokens", signature, session)
}

// DeleteRefreshTokenSession deletes a refresh token session
func (s *IDPStorage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "idp_refresh_tokens", signature)
}

// CreateAuthorizeCodeSession stores an authorization code session
func (s *IDPStorage) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "idp_authorization_codes", signature, request)
}

// GetAuthorizeCodeSession retrieves an authorization code session
func (s *IDPStorage) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "idp_authorization_codes", signature, session)
}

// InvalidateAuthorizeCodeSession invalidates an authorization code
func (s *IDPStorage) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE idp_authorization_codes SET active = 0 WHERE signature = ?`, signature)
	return err
}

// CreateSession creates a new session for the given username
func (s *IDPStorage) CreateSession(ctx context.Context, username string) (string, error) {
	// Generate random session ID
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}
	sessionID := base64.RawURLEncoding.EncodeToString(b)

	now := time.Now()
	expiresAt := now.Add(24 * time.Hour) // 24 hour session

	_, err := s.db.ExecContext(ctx,
		"INSERT INTO idp_sessions (session_id, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
		sessionID, username, now, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to store session: %w", err)
	}

	return sessionID, nil
}

// GetSession retrieves the username for a given session ID
func (s *IDPStorage) GetSession(ctx context.Context, sessionID string) (string, error) {
	var username string
	var expiresAt time.Time

	err := s.db.QueryRowContext(ctx,
		"SELECT username, expires_at FROM idp_sessions WHERE session_id = ?",
		sessionID).Scan(&username, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil // Not found
		}
		return "", fmt.Errorf("failed to get session: %w", err)
	}

	if time.Now().After(expiresAt) {
		// Session expired, delete it
		_ = s.DeleteSession(ctx, sessionID)
		return "", nil
	}

	return username, nil
}

// DeleteSession deletes a session
func (s *IDPStorage) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM idp_sessions WHERE session_id = ?", sessionID)
	return err
}

// Helper methods

//nolint:dupl // Similar to OAuth2Storage but uses different query builders
func (s *IDPStorage) createTokenSession(ctx context.Context, table string, signature string, request fosite.Requester) error {
	scopes, err := json.Marshal(request.GetRequestedScopes())
	if err != nil {
		return err
	}
	grantedScopes, err := json.Marshal(request.GetGrantedScopes())
	if err != nil {
		return err
	}
	formData, err := json.Marshal(request.GetRequestForm())
	if err != nil {
		return err
	}
	sessionData, err := json.Marshal(request.GetSession())
	if err != nil {
		return err
	}

	expiresAt := tokenSessionExpiresAt(table, request.GetSession())

	query, err := buildIDPInsertQuery(table)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, query,
		signature,
		request.GetID(),
		request.GetRequestedAt(),
		request.GetClient().GetID(),
		string(scopes),
		string(grantedScopes),
		string(formData),
		string(sessionData),
		request.GetSession().GetSubject(),
		expiresAt,
	)

	return err
}

//nolint:dupl // Similar to OAuth2Storage but uses different query builders
func (s *IDPStorage) getTokenSession(ctx context.Context, table string, signature string, session fosite.Session) (fosite.Requester, error) {
	var (
		requestID     string
		requestedAt   time.Time
		clientID      string
		scopes        string
		grantedScopes string
		formData      string
		sessionData   string
		subject       string
		active        int
	)

	query, err := buildIDPSelectQuery(table)
	if err != nil {
		return nil, err
	}

	err = s.db.QueryRowContext(ctx, query, signature).Scan(
		&requestID, &requestedAt, &clientID, &scopes, &grantedScopes,
		&formData, &sessionData, &subject, &active,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if active == 0 {
		return nil, fosite.ErrInactiveToken
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	request := fosite.NewRequest()
	request.ID = requestID
	request.RequestedAt = requestedAt
	request.Client = client

	var scopesList []string
	if err := json.Unmarshal([]byte(scopes), &scopesList); err != nil {
		return nil, err
	}
	request.RequestedScope = scopesList

	var grantedScopesList []string
	if err := json.Unmarshal([]byte(grantedScopes), &grantedScopesList); err != nil {
		return nil, err
	}
	request.GrantedScope = grantedScopesList

	var form url.Values
	if err := json.Unmarshal([]byte(formData), &form); err != nil {
		return nil, err
	}
	request.Form = form

	if err := json.Unmarshal([]byte(sessionData), session); err != nil {
		return nil, err
	}
	request.Session = session

	return request, nil
}

func (s *IDPStorage) deleteTokenSession(ctx context.Context, table string, signature string) error {
	query, err := buildIDPDeleteQuery(table)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, query, signature)
	return err
}

// RevokeRefreshToken revokes a refresh token
func (s *IDPStorage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE idp_refresh_tokens SET active = 0 WHERE request_id = ?`, requestID)
	return err
}

// RevokeAccessToken revokes an access token
func (s *IDPStorage) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE idp_access_tokens SET active = 0 WHERE request_id = ?`, requestID)
	return err
}

// SaveRSAKey stores the RSA private key in PEM format
func (s *IDPStorage) SaveRSAKey(ctx context.Context, privateKeyPEM string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO idp_rsa_keys (id, private_key_pem) VALUES (1, ?)`, privateKeyPEM)
	return err
}

// LoadRSAKey loads the RSA private key in PEM format
func (s *IDPStorage) LoadRSAKey(ctx context.Context) (string, error) {
	var privateKeyPEM string
	err := s.db.QueryRowContext(ctx, `SELECT private_key_pem FROM idp_rsa_keys WHERE id = 1`).Scan(&privateKeyPEM)
	if err == sql.ErrNoRows {
		return "", nil // No key stored yet
	}
	if err != nil {
		return "", err
	}
	return privateKeyPEM, nil
}

// SaveHMACSecret stores the HMAC secret
func (s *IDPStorage) SaveHMACSecret(ctx context.Context, secret []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO idp_hmac_secrets (id, secret) VALUES (1, ?)`, secret)
	return err
}

// LoadHMACSecret loads the HMAC secret
func (s *IDPStorage) LoadHMACSecret(ctx context.Context) ([]byte, error) {
	var secret []byte
	err := s.db.QueryRowContext(ctx, `SELECT secret FROM idp_hmac_secrets WHERE id = 1`).Scan(&secret)
	if err == sql.ErrNoRows {
		return nil, nil // No secret stored yet
	}
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// ClientAssertionJWTValid implements fosite.ClientAssertionJWTValid interface
func (s *IDPStorage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM idp_jwt_assertions WHERE jti = ? AND expires_at > ?`, jti, time.Now()).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check JWT assertion: %w", err)
	}
	if count > 0 {
		return fosite.ErrJTIKnown
	}
	return nil
}

// SetClientAssertionJWT implements fosite.SetClientAssertionJWT interface
func (s *IDPStorage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO idp_jwt_assertions (jti, expires_at) VALUES (?, ?)`, jti, exp)
	if err != nil {
		return fmt.Errorf("failed to store JWT assertion: %w", err)
	}

	// Clean up expired JWT assertions to prevent database bloat
	_, _ = s.db.ExecContext(ctx, `DELETE FROM idp_jwt_assertions WHERE expires_at < ?`, time.Now())

	return nil
}

// RevokeRefreshTokenMaybeGracePeriod implements fosite.TokenRevocationStorage interface
func (s *IDPStorage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, _ string) error {
	return s.RevokeRefreshToken(ctx, requestID)
}

// CreateOpenIDConnectSession implements openid.OpenIDConnectRequestStorage interface
func (s *IDPStorage) CreateOpenIDConnectSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.createTokenSession(ctx, "idp_oidc_sessions", signature, requester)
}

// GetOpenIDConnectSession implements openid.OpenIDConnectRequestStorage interface
func (s *IDPStorage) GetOpenIDConnectSession(ctx context.Context, signature string, requester fosite.Requester) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "idp_oidc_sessions", signature, requester.GetSession())
}

// DeleteOpenIDConnectSession implements openid.OpenIDConnectRequestStorage interface
func (s *IDPStorage) DeleteOpenIDConnectSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "idp_oidc_sessions", signature)
}

// CreatePKCERequestSession stores a PKCE request session
func (s *IDPStorage) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "idp_pkce_requests", signature, request)
}

// GetPKCERequestSession retrieves a PKCE request session
func (s *IDPStorage) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "idp_pkce_requests", signature, session)
}

// DeletePKCERequestSession deletes a PKCE request session
func (s *IDPStorage) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "idp_pkce_requests", signature)
}
