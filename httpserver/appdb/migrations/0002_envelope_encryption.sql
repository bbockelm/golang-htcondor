-- +goose Up
-- +goose StatementBegin

-- Adds envelope-encryption columns and the KEK metadata table.
--
-- The application code wraps long-lived secrets (the OAuth2 / IDP
-- issuer's RSA private key, fosite's HMAC GlobalSecret) under a
-- per-row Data Encryption Key, which is itself sealed under a
-- DB-instance Key Encryption Key derived from a master KEK held in
-- a file outside the DB. See httpserver/appdb/seal for the design.
--
-- This migration does NOT encrypt any rows on its own — the schema
-- changes are zero-risk additive. When the app starts with a KEK
-- configured and notices a row whose `_dek` column is null, it
-- re-writes the row in encrypted form. When no KEK is configured the
-- new columns stay null and existing plaintext continues to be read
-- as-is (back-compat with the pre-encryption deployment).

------------------------------------------------------------------
-- KEK metadata: per-DB salt for HKDF.
------------------------------------------------------------------

CREATE TABLE kek_metadata (
    id         INTEGER   PRIMARY KEY CHECK (id = 1),
    salt       BLOB      NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

------------------------------------------------------------------
-- Wrapped DEKs alongside each long-lived secret column. Null DEK
-- means the column is plaintext (older row, or no KEK configured).
------------------------------------------------------------------

ALTER TABLE oauth2_rsa_keys     ADD COLUMN private_key_pem_dek BLOB;
ALTER TABLE oauth2_hmac_secrets ADD COLUMN secret_dek          BLOB;
ALTER TABLE idp_rsa_keys        ADD COLUMN private_key_pem_dek BLOB;
ALTER TABLE idp_hmac_secrets    ADD COLUMN secret_dek          BLOB;

------------------------------------------------------------------
-- Drop the unused http_sessions.token column. It was declared on
-- day one but never written to (session.Token is always empty in
-- session.go's Create path); leaving an unused secret-shaped column
-- on disk is one merge away from an accidental leak. SQLite has
-- supported ALTER TABLE DROP COLUMN since 3.35 (March 2021); the
-- driver we use (modernc.org/sqlite via glebarez/sqlite) tracks a
-- recent SQLite, so this works without rebuild gymnastics.
------------------------------------------------------------------

ALTER TABLE http_sessions DROP COLUMN token;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- We don't ship a working down migration. Reversing the encryption
-- additions would require decrypting every wrapped secret back to
-- plaintext, which the operator should drive explicitly (and which
-- requires the KEK they've presumably just removed). Restoring
-- http_sessions.token would silently re-create a hazard for no
-- benefit. If you want to roll back, drop the file.

SELECT 1;

-- +goose StatementEnd
