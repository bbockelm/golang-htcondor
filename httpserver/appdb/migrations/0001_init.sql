-- +goose Up
-- +goose StatementBegin

-- Initial schema for the unified htcondor-api database. Folds together
-- what used to be three separate SQLite files: oauth2.db (OAuth2 + MCP +
-- browser sessions), idp.db (embedded IDP provider), and
-- user-templates.db (batch-submission template library). Splitting them
-- meant adding a new feature with its own DB silently broke any
-- container where one storage path was writable and another wasn't.

------------------------------------------------------------------
-- OAuth2 / MCP storage
------------------------------------------------------------------

CREATE TABLE oauth2_clients (
    id TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    response_types TEXT NOT NULL,
    scopes TEXT NOT NULL,
    public INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE oauth2_access_tokens (
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

CREATE TABLE oauth2_refresh_tokens (
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

CREATE TABLE oauth2_authorization_codes (
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

CREATE TABLE oauth2_pkce_requests (
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

CREATE TABLE oauth2_rsa_keys (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    private_key_pem TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE oauth2_hmac_secrets (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    secret BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE oauth2_oidc_sessions (
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

CREATE TABLE oauth2_jwt_assertions (
    jti TEXT PRIMARY KEY,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE oauth2_device_codes (
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

CREATE INDEX idx_access_tokens_client ON oauth2_access_tokens(client_id);
CREATE INDEX idx_refresh_tokens_client ON oauth2_refresh_tokens(client_id);
CREATE INDEX idx_authorization_codes_client ON oauth2_authorization_codes(client_id);
CREATE INDEX idx_oidc_sessions_client ON oauth2_oidc_sessions(client_id);
CREATE INDEX idx_jwt_assertions_expires ON oauth2_jwt_assertions(expires_at);
CREATE INDEX idx_device_codes_user_code ON oauth2_device_codes(user_code);
CREATE INDEX idx_device_codes_expires ON oauth2_device_codes(expires_at);

------------------------------------------------------------------
-- Browser session store (used by the SPA's cookie-auth path)
------------------------------------------------------------------

CREATE TABLE http_sessions (
    session_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    token TEXT,
    groups_json TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_expires ON http_sessions(expires_at);
CREATE INDEX idx_sessions_username ON http_sessions(username);

------------------------------------------------------------------
-- Embedded IDP provider
------------------------------------------------------------------

CREATE TABLE idp_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CHECK (state IN ('pending', 'active', 'admin'))
);

CREATE TABLE idp_clients (
    id TEXT PRIMARY KEY,
    client_secret TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    response_types TEXT NOT NULL,
    scopes TEXT NOT NULL,
    public INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE idp_access_tokens (
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

CREATE TABLE idp_refresh_tokens (
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

CREATE TABLE idp_authorization_codes (
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

CREATE TABLE idp_pkce_requests (
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

CREATE TABLE idp_rsa_keys (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    private_key_pem TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE idp_hmac_secrets (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    secret BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE idp_oidc_sessions (
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

CREATE TABLE idp_jwt_assertions (
    jti TEXT PRIMARY KEY,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE idp_sessions (
    session_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_idp_access_tokens_client ON idp_access_tokens(client_id);
CREATE INDEX idx_idp_refresh_tokens_client ON idp_refresh_tokens(client_id);
CREATE INDEX idx_idp_authorization_codes_client ON idp_authorization_codes(client_id);
CREATE INDEX idx_idp_oidc_sessions_client ON idp_oidc_sessions(client_id);
CREATE INDEX idx_idp_jwt_assertions_expires ON idp_jwt_assertions(expires_at);
CREATE INDEX idx_idp_sessions_expires ON idp_sessions(expires_at);

------------------------------------------------------------------
-- User-saved batch-submission templates
------------------------------------------------------------------

CREATE TABLE templates_user (
    owner        TEXT      NOT NULL,
    id           TEXT      NOT NULL,
    name         TEXT      NOT NULL,
    description  TEXT      NOT NULL DEFAULT '',
    columns_csv  TEXT      NOT NULL DEFAULT '',
    columns_json TEXT      NOT NULL DEFAULT '',
    contents     TEXT      NOT NULL,
    input_files  BLOB      NOT NULL DEFAULT X'',
    created_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (owner, id)
);

CREATE INDEX templates_user_owner ON templates_user(owner);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- We don't ship a down migration for the initial schema — the user is
-- on their own to drop the file if they want to start over.
SELECT 1;
-- +goose StatementEnd
