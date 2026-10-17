-- +goose Up
-- +goose StatementBegin

-- Pending placement-token device grants (RFC 8628), for placement-client.
-- Separate from oauth2_device_codes, which issues this server's own OAuth2
-- tokens: these carry a condor_placementd IDTOKEN.
--
-- device_code_hash is the SHA-256 of the device code, like every other
-- bearer value this database keys on. token_sealed holds the placement
-- token once the user approves, sealed under the database KEK when one is
-- configured (token_dek is then its wrapped key). A row is deleted when the
-- client collects the token, and swept once expires_at passes.
CREATE TABLE IF NOT EXISTS placement_device_grants (
    device_code_hash TEXT PRIMARY KEY,
    user_code        TEXT NOT NULL UNIQUE,
    client_id        TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    interval         INTEGER NOT NULL,
    last_poll        INTEGER NOT NULL DEFAULT 0,
    state            TEXT NOT NULL DEFAULT 'pending',
    foreign_id       TEXT NOT NULL DEFAULT '',
    token_sealed     BLOB,
    token_dek        BLOB,
    token_expires_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_placement_device_grants_expires ON placement_device_grants(expires_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS placement_device_grants;
-- +goose StatementEnd
