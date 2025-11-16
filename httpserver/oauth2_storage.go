package httpserver

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ory/fosite"
	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// OAuth2Storage implements fosite storage interfaces using SQLite
type OAuth2Storage struct {
	db *sql.DB
}

// NewOAuth2Storage creates a new OAuth2 storage backed by SQLite
func NewOAuth2Storage(dbPath string) (*OAuth2Storage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	storage := &OAuth2Storage{db: db}
	if err := storage.createTables(); err != nil {
		db.Close()
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

	CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON oauth2_access_tokens(client_id);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON oauth2_refresh_tokens(client_id);
	CREATE INDEX IF NOT EXISTS idx_authorization_codes_client ON oauth2_authorization_codes(client_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Close closes the database connection
func (s *OAuth2Storage) Close() error {
	return s.db.Close()
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

	query := fmt.Sprintf(`
		INSERT INTO %s (signature, request_id, requested_at, client_id, scopes, granted_scopes, 
			form_data, session_data, subject, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, table)

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
		requestID      string
		requestedAt    time.Time
		clientID       string
		scopes         string
		grantedScopes  string
		formData       string
		sessionData    string
		subject        string
		active         int
	)

	query := fmt.Sprintf(`
		SELECT request_id, requested_at, client_id, scopes, granted_scopes, 
			form_data, session_data, subject, active
		FROM %s WHERE signature = ?
	`, table)

	err := s.db.QueryRowContext(ctx, query, signature).Scan(
		&requestID, &requestedAt, &clientID, &scopes, &grantedScopes,
		&formData, &sessionData, &subject, &active,
	)

	if err == sql.ErrNoRows {
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

	if err := json.Unmarshal([]byte(sessionData), session); err != nil {
		return nil, err
	}
	request.Session = session

	return request, nil
}

func (s *OAuth2Storage) deleteTokenSession(ctx context.Context, table string, signature string) error {
	query := fmt.Sprintf(`DELETE FROM %s WHERE signature = ?`, table)
	_, err := s.db.ExecContext(ctx, query, signature)
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
