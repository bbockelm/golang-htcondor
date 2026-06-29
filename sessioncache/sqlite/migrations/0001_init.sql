-- +goose Up
-- +goose StatementBegin
-- master_key holds the data-encryption key (DEK) wrapped once per available
-- HTCondor signing key. Any one signing key recovers the DEK.
CREATE TABLE master_key (
    key_id  TEXT PRIMARY KEY,
    salt    BLOB NOT NULL,
    nonce   BLOB NOT NULL,
    wrapped BLOB NOT NULL
);
-- +goose StatementEnd
-- +goose StatementBegin
-- session holds the persisted CEDAR sessions, each encrypted under the DEK.
-- expiration is stored in the clear so expired rows can be swept without
-- decrypting.
CREATE TABLE session (
    id         TEXT PRIMARY KEY,
    expiration INTEGER NOT NULL,
    nonce      BLOB NOT NULL,
    ciphertext BLOB NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE session;
DROP TABLE master_key;
-- +goose StatementEnd
