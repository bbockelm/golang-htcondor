package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/glebarez/sqlite" // SQLite driver (pure Go, no CGO)
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// OAuth2Storage implements fosite storage interfaces using SQLite
type OAuth2Storage struct {
	db *sql.DB
}

// NewOAuth2Storage creates a new OAuth2 storage backed by SQLite
func NewOAuth2Storage(dbPath string) (*OAuth2Storage, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &OAuth2Storage{db: db}
	if err := storage.createTables(); err != nil {
		_ = db.Close() // Ignore error on cleanup
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return storage, nil
}

// createTables creates the necessary database tables
func (s *OAuth2Storage) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS oauth2_clients (
		id TEXT PRIMARY KEY,
		client_secret TEXT NOT NULL,
		redirect_uris TEXT NOT NULL,
		grant_types TEXT NOT NULL,
		response_types TEXT NOT NULL,
		scopes TEXT NOT NULL,
		public INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS oauth2_access_tokens (
		signature TEXT PRIMARY KEY,
		request_id TEXT NOT NULL,
		requested_at TIMESTAMP NOT NULL,
		client_id TEXT NOT NULL,
		scopes TEXT NOT NULL,
		granted_scopes TEXT NOT NULL,
		form_data TEXT NOT NULL,
		session_data TEXT NOT NULL,
		subject TEXT NOT NULL,
		active INTEGER NOT NULL DEFAULT 1,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS oauth2_refresh_tokens (
		signature TEXT PRIMARY KEY,
		request_id TEXT NOT NULL,
		requested_at TIMESTAMP NOT NULL,
		client_id TEXT NOT NULL,
		scopes TEXT NOT NULL,
		granted_scopes TEXT NOT NULL,
		form_data TEXT NOT NULL,
		session_data TEXT NOT NULL,
		subject TEXT NOT NULL,
		active INTEGER NOT NULL DEFAULT 1,
		expires_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS oauth2_authorization_codes (
		signature TEXT PRIMARY KEY,
		request_id TEXT NOT NULL,
		requested_at TIMESTAMP NOT NULL,
		client_id TEXT NOT NULL,
		scopes TEXT NOT NULL,
		granted_scopes TEXT NOT NULL,
		form_data TEXT NOT NULL,
		session_data TEXT NOT NULL,
		subject TEXT NOT NULL,
		active INTEGER NOT NULL DEFAULT 1,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS oauth2_rsa_keys (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		private_key_pem TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS oauth2_hmac_secrets (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		secret BLOB NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS oauth2_oidc_sessions (
		signature TEXT PRIMARY KEY,
		request_id TEXT NOT NULL,
		requested_at TIMESTAMP NOT NULL,
		client_id TEXT NOT NULL,
		scopes TEXT NOT NULL,
		granted_scopes TEXT NOT NULL,
		form_data TEXT NOT NULL,
		session_data TEXT NOT NULL,
		subject TEXT NOT NULL,
		active INTEGER NOT NULL DEFAULT 1,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS oauth2_jwt_assertions (
		jti TEXT PRIMARY KEY,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS oauth2_device_codes (
		device_code TEXT PRIMARY KEY,
		user_code TEXT NOT NULL UNIQUE,
		request_id TEXT NOT NULL,
		requested_at TIMESTAMP NOT NULL,
		client_id TEXT NOT NULL,
		scopes TEXT NOT NULL,
		granted_scopes TEXT NOT NULL,
		form_data TEXT NOT NULL,
		session_data TEXT,
		subject TEXT,
		status TEXT NOT NULL DEFAULT 'pending',
		expires_at TIMESTAMP NOT NULL,
		last_polled_at TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON oauth2_access_tokens(client_id);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON oauth2_refresh_tokens(client_id);
	CREATE INDEX IF NOT EXISTS idx_authorization_codes_client ON oauth2_authorization_codes(client_id);
	CREATE INDEX IF NOT EXISTS idx_oidc_sessions_client ON oauth2_oidc_sessions(client_id);
	CREATE INDEX IF NOT EXISTS idx_jwt_assertions_expires ON oauth2_jwt_assertions(expires_at);
	CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON oauth2_device_codes(user_code);
	CREATE INDEX IF NOT EXISTS idx_device_codes_expires ON oauth2_device_codes(expires_at);
	`

	_, err := s.db.ExecContext(context.Background(), schema)
	return err
}

// Close closes the database connection
func (s *OAuth2Storage) Close() error {
	return s.db.Close()
}

// validTableNames is a whitelist of allowed table names
var validTableNames = map[string]bool{
	"oauth2_access_tokens":       true,
	"oauth2_refresh_tokens":      true,
	"oauth2_authorization_codes": true,
	"oauth2_oidc_sessions":       true,
}

// buildInsertQuery builds an INSERT query for a valid table name
func buildInsertQuery(table string) (string, error) {
	if !validTableNames[table] {
		return "", fmt.Errorf("invalid table name: %s", table)
	}
	// Safe: table name is from whitelist
	return `INSERT INTO ` + table + ` (signature, request_id, requested_at, client_id, scopes, granted_scopes,
		form_data, session_data, subject, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, nil
}

// buildSelectQuery builds a SELECT query for a valid table name
func buildSelectQuery(table string) (string, error) {
	if !validTableNames[table] {
		return "", fmt.Errorf("invalid table name: %s", table)
	}
	// Safe: table name is from whitelist
	return `SELECT request_id, requested_at, client_id, scopes, granted_scopes,
		form_data, session_data, subject, active
		FROM ` + table + ` WHERE signature = ?`, nil
}

// buildDeleteQuery builds a DELETE query for a valid table name
func buildDeleteQuery(table string) (string, error) {
	if !validTableNames[table] {
		return "", fmt.Errorf("invalid table name: %s", table)
	}
	// Safe: table name is from whitelist
	return `DELETE FROM ` + table + ` WHERE signature = ?`, nil
}

// CreateClient creates a new OAuth2 client
func (s *OAuth2Storage) CreateClient(ctx context.Context, client *fosite.DefaultClient) error {
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
		INSERT INTO oauth2_clients (id, client_secret, redirect_uris, grant_types, response_types, scopes, public)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, client.ID, string(client.Secret), string(redirectURIs), string(grantTypes),
		string(responseTypes), string(scopes), public)

	return err
}

// GetClient retrieves a client by ID
func (s *OAuth2Storage) GetClient(ctx context.Context, clientID string) (fosite.Client, error) {
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
		FROM oauth2_clients WHERE id = ?
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
func (s *OAuth2Storage) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "oauth2_access_tokens", signature, request)
}

// GetAccessTokenSession retrieves an access token session
func (s *OAuth2Storage) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oauth2_access_tokens", signature, session)
}

// DeleteAccessTokenSession deletes an access token session
func (s *OAuth2Storage) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "oauth2_access_tokens", signature)
}

// CreateRefreshTokenSession stores a refresh token session
func (s *OAuth2Storage) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "oauth2_refresh_tokens", signature, request)
}

// GetRefreshTokenSession retrieves a refresh token session
func (s *OAuth2Storage) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oauth2_refresh_tokens", signature, session)
}

// DeleteRefreshTokenSession deletes a refresh token session
func (s *OAuth2Storage) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "oauth2_refresh_tokens", signature)
}

// CreateAuthorizeCodeSession stores an authorization code session
func (s *OAuth2Storage) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.createTokenSession(ctx, "oauth2_authorization_codes", signature, request)
}

// GetAuthorizeCodeSession retrieves an authorization code session
func (s *OAuth2Storage) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oauth2_authorization_codes", signature, session)
}

// InvalidateAuthorizeCodeSession invalidates an authorization code
func (s *OAuth2Storage) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE oauth2_authorization_codes SET active = 0 WHERE signature = ?`, signature)
	return err
}

// Helper methods

func (s *OAuth2Storage) createTokenSession(ctx context.Context, table string, signature string, request fosite.Requester) error {
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

	expiresAt := time.Now().Add(1 * time.Hour) // Default expiration

	query, err := buildInsertQuery(table)
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

func (s *OAuth2Storage) getTokenSession(ctx context.Context, table string, signature string, session fosite.Session) (fosite.Requester, error) {
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

	query, err := buildSelectQuery(table)
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

	// Only unmarshal session data if we have a valid session to unmarshal into
	if session != nil && sessionData != "" {
		if err := json.Unmarshal([]byte(sessionData), session); err != nil {
			return nil, err
		}
		request.Session = session
	} else {
		// Create a default session if none provided
		request.Session = &openid.DefaultSession{}
	}

	return request, nil
}

func (s *OAuth2Storage) deleteTokenSession(ctx context.Context, table string, signature string) error {
	query, err := buildDeleteQuery(table)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, query, signature)
	return err
}

// RevokeRefreshToken revokes a refresh token
func (s *OAuth2Storage) RevokeRefreshToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE oauth2_refresh_tokens SET active = 0 WHERE request_id = ?`, requestID)
	return err
}

// RevokeAccessToken revokes an access token
func (s *OAuth2Storage) RevokeAccessToken(ctx context.Context, requestID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE oauth2_access_tokens SET active = 0 WHERE request_id = ?`, requestID)
	return err
}

// SaveRSAKey stores the RSA private key in PEM format
func (s *OAuth2Storage) SaveRSAKey(ctx context.Context, privateKeyPEM string) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO oauth2_rsa_keys (id, private_key_pem) VALUES (1, ?)`, privateKeyPEM)
	return err
}

// LoadRSAKey loads the RSA private key in PEM format
func (s *OAuth2Storage) LoadRSAKey(ctx context.Context) (string, error) {
	var privateKeyPEM string
	err := s.db.QueryRowContext(ctx, `SELECT private_key_pem FROM oauth2_rsa_keys WHERE id = 1`).Scan(&privateKeyPEM)
	if err == sql.ErrNoRows {
		return "", nil // No key stored yet
	}
	if err != nil {
		return "", err
	}
	return privateKeyPEM, nil
}

// SaveHMACSecret stores the HMAC secret
func (s *OAuth2Storage) SaveHMACSecret(ctx context.Context, secret []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO oauth2_hmac_secrets (id, secret) VALUES (1, ?)`, secret)
	return err
}

// LoadHMACSecret loads the HMAC secret
func (s *OAuth2Storage) LoadHMACSecret(ctx context.Context) ([]byte, error) {
	var secret []byte
	err := s.db.QueryRowContext(ctx, `SELECT secret FROM oauth2_hmac_secrets WHERE id = 1`).Scan(&secret)
	if err == sql.ErrNoRows {
		return nil, nil // No secret stored yet
	}
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// ClientAssertionJWTValid implements fosite.ClientAssertionJWTValid interface
// This checks if a JWT ID (JTI) has already been used to prevent replay attacks
func (s *OAuth2Storage) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM oauth2_jwt_assertions WHERE jti = ? AND expires_at > ?`, jti, time.Now()).Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check JWT assertion: %w", err)
	}
	if count > 0 {
		return fosite.ErrJTIKnown
	}
	return nil
}

// SetClientAssertionJWT implements fosite.SetClientAssertionJWT interface
// This stores the JTI (JWT ID) with expiration to prevent replay attacks
func (s *OAuth2Storage) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO oauth2_jwt_assertions (jti, expires_at) VALUES (?, ?)`, jti, exp)
	if err != nil {
		return fmt.Errorf("failed to store JWT assertion: %w", err)
	}

	// Clean up expired JWT assertions to prevent database bloat
	// This is done opportunistically on each insert
	_, _ = s.db.ExecContext(ctx, `DELETE FROM oauth2_jwt_assertions WHERE expires_at < ?`, time.Now())

	return nil
}

// RevokeRefreshTokenMaybeGracePeriod implements fosite.TokenRevocationStorage interface
// This handles refresh token revocation. The signature parameter allows for grace period implementation
// but for simplicity we immediately revoke the token by request ID
func (s *OAuth2Storage) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, _ string) error {
	// Immediately revoke the refresh token
	// For grace period support, you could store the signature and delay actual revocation
	return s.RevokeRefreshToken(ctx, requestID)
}

// CreateOpenIDConnectSession implements openid.OpenIDConnectRequestStorage interface
func (s *OAuth2Storage) CreateOpenIDConnectSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.createTokenSession(ctx, "oauth2_oidc_sessions", signature, requester)
}

// GetOpenIDConnectSession implements openid.OpenIDConnectRequestStorage interface
func (s *OAuth2Storage) GetOpenIDConnectSession(ctx context.Context, signature string, requester fosite.Requester) (fosite.Requester, error) {
	return s.getTokenSession(ctx, "oauth2_oidc_sessions", signature, requester.GetSession())
}

// DeleteOpenIDConnectSession implements openid.OpenIDConnectRequestStorage interface
func (s *OAuth2Storage) DeleteOpenIDConnectSession(ctx context.Context, signature string) error {
	return s.deleteTokenSession(ctx, "oauth2_oidc_sessions", signature)
}

// Device Code Flow Storage Methods

// CreateDeviceCodeSession creates a new device code session
func (s *OAuth2Storage) CreateDeviceCodeSession(ctx context.Context, deviceCode string, userCode string, request fosite.Requester, expiresAt time.Time) error {
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

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO oauth2_device_codes (device_code, user_code, request_id, requested_at, client_id,
			scopes, granted_scopes, form_data, expires_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
	`, deviceCode, userCode, request.GetID(), request.GetRequestedAt(), request.GetClient().GetID(),
		string(scopes), string(grantedScopes), string(formData), expiresAt)

	return err
}

// GetDeviceCodeSession retrieves a device code session by device code
func (s *OAuth2Storage) GetDeviceCodeSession(ctx context.Context, deviceCode string, session fosite.Session) (fosite.Requester, error) {
	var (
		userCode      string
		requestID     string
		requestedAt   time.Time
		clientID      string
		scopes        string
		grantedScopes string
		formData      string
		sessionData   sql.NullString
		subject       sql.NullString
		status        string
		expiresAt     time.Time
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT user_code, request_id, requested_at, client_id, scopes, granted_scopes,
			form_data, session_data, subject, status, expires_at
		FROM oauth2_device_codes WHERE device_code = ?
	`, deviceCode).Scan(&userCode, &requestID, &requestedAt, &clientID, &scopes, &grantedScopes,
		&formData, &sessionData, &subject, &status, &expiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	// Check if expired
	if time.Now().After(expiresAt) {
		return nil, ErrExpiredToken
	}

	// Check status
	if status == "denied" {
		return nil, fosite.ErrAccessDenied
	}
	if status == "pending" {
		return nil, ErrAuthorizationPending
	}
	if status == "used" {
		return nil, fosite.ErrInvalidGrant.WithDebug("Device code already used")
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

	// Unmarshal session data if available
	if sessionData.Valid && sessionData.String != "" {
		if err := json.Unmarshal([]byte(sessionData.String), session); err != nil {
			return nil, err
		}
		request.Session = session
	}

	return request, nil
}

// GetDeviceCodeSessionByUserCode retrieves a device code session by user code
func (s *OAuth2Storage) GetDeviceCodeSessionByUserCode(ctx context.Context, userCode string) (string, fosite.Requester, error) {
	var (
		deviceCode    string
		requestID     string
		requestedAt   time.Time
		clientID      string
		scopes        string
		grantedScopes string
		formData      string
		status        string
		expiresAt     time.Time
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT device_code, request_id, requested_at, client_id, scopes, granted_scopes,
			form_data, status, expires_at
		FROM oauth2_device_codes WHERE user_code = ?
	`, userCode).Scan(&deviceCode, &requestID, &requestedAt, &clientID, &scopes, &grantedScopes,
		&formData, &status, &expiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, fosite.ErrNotFound
	}
	if err != nil {
		return "", nil, err
	}

	// Check if expired
	if time.Now().After(expiresAt) {
		return "", nil, ErrExpiredToken
	}

	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return "", nil, err
	}

	request := fosite.NewRequest()
	request.ID = requestID
	request.RequestedAt = requestedAt
	request.Client = client

	var scopesList []string
	if err := json.Unmarshal([]byte(scopes), &scopesList); err != nil {
		return "", nil, err
	}
	request.RequestedScope = scopesList

	var grantedScopesList []string
	if err := json.Unmarshal([]byte(grantedScopes), &grantedScopesList); err != nil {
		return "", nil, err
	}
	request.GrantedScope = grantedScopesList

	return deviceCode, request, nil
}

// ApproveDeviceCodeSession approves a device code (user authorized the device)
func (s *OAuth2Storage) ApproveDeviceCodeSession(ctx context.Context, userCode string, subject string, session fosite.Session) error {
	sessionData, err := json.Marshal(session)
	if err != nil {
		return err
	}

	result, err := s.db.ExecContext(ctx, `
		UPDATE oauth2_device_codes
		SET status = 'approved', subject = ?, session_data = ?
		WHERE user_code = ? AND status = 'pending'
	`, subject, string(sessionData), userCode)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fosite.ErrNotFound
	}

	return nil
}

// DenyDeviceCodeSession denies a device code (user rejected the device)
func (s *OAuth2Storage) DenyDeviceCodeSession(ctx context.Context, userCode string) error {
	result, err := s.db.ExecContext(ctx, `
		UPDATE oauth2_device_codes
		SET status = 'denied'
		WHERE user_code = ? AND status = 'pending'
	`, userCode)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fosite.ErrNotFound
	}

	return nil
}

// UpdateDeviceCodePolling updates the last polled timestamp for rate limiting
func (s *OAuth2Storage) UpdateDeviceCodePolling(ctx context.Context, deviceCode string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE oauth2_device_codes
		SET last_polled_at = ?
		WHERE device_code = ?
	`, time.Now(), deviceCode)
	return err
}

// InvalidateDeviceCodeSession invalidates a device code after it's been used
func (s *OAuth2Storage) InvalidateDeviceCodeSession(ctx context.Context, deviceCode string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE oauth2_device_codes
		SET status = 'used'
		WHERE device_code = ?
	`, deviceCode)
	return err
}
