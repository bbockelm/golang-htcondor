-- +goose Up
-- +goose StatementBegin

-- The application master key, wrapped once per HTCondor signing key.
--
-- The same shape as the persisted CCB session cache uses
-- (sessioncache/sqlite/envelope.go) and as classad's DB encryption at rest
-- uses: a random master key is never stored in the clear, only wrapped
-- under each available signing key from SEC_PASSWORD_DIRECTORY. Any one of
-- those keys recovers it, so a rotated-in key can be added without
-- re-encrypting anything, and losing one key does not lose the master.
--
-- Purposes hang off the master by HKDF label rather than using it
-- directly, so one master can protect several unrelated things without key
-- reuse. The first consumer is the identity cookie's signing key.
--
-- A stolen database is useless without one of the signing keys.
CREATE TABLE master_keys (
    -- Signing key name, e.g. "POOL".
    key_id     TEXT      PRIMARY KEY,
    -- Per-row HKDF salt used to derive the wrapping key from the signing key.
    salt       BLOB      NOT NULL,
    nonce      BLOB      NOT NULL,
    -- AES-GCM(derived-from-signing-key, master)
    wrapped    BLOB      NOT NULL,
    created_at TIMESTAMP NOT NULL
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE master_keys;
-- +goose StatementEnd
