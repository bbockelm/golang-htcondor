-- +goose Up
-- +goose StatementBegin

-- The SSH gateway's long-lived keys: the host key it presents to every
-- `ssh` client, and the CA key it signs user certificates with.
--
-- Both are stored ONLY in sealed form. That is the one way this table
-- differs from the other secrets in this database (oauth2_rsa_keys,
-- idp_rsa_keys, …), which carry a nullable `_dek` sibling so a
-- deployment with no HTTP_API_KEK_FILE keeps working against plaintext
-- rows. There is no plaintext era to stay compatible with here, so
-- private_key_dek is NOT NULL and a deployment without a KEK simply
-- has nowhere to keep these keys -- it must supply
-- HTTP_API_SSH_HOST_KEY_FILE instead, or run without the gateway.
--
-- For the same reason this table must NOT be added to sealableRows in
-- seal_setup.go: the backfill walker looks for rows that are plaintext
-- and need sealing, and by construction there are none.
--
-- public_key and fingerprint are deliberately in the clear. An operator
-- needs the CA's public key to write an @cert-authority line and the
-- host key's fingerprint to answer "is this the host I think it is",
-- and having to start the server to read them is the wrong failure mode
-- during an incident. Neither is secret.
CREATE TABLE ssh_gateway_keys (
    -- 'host' or 'ca'. One row each, at most.
    purpose         TEXT      PRIMARY KEY,
    -- AES-GCM(per-row DEK, OpenSSH-format PEM private key)
    private_key     BLOB      NOT NULL,
    -- AES-GCM(DB KEK, per-row DEK). Never null: see above.
    private_key_dek BLOB      NOT NULL,
    -- authorized_keys form, e.g. "ssh-ed25519 AAAA... comment".
    public_key      TEXT      NOT NULL,
    -- SHA256:... as ssh-keygen -l prints it.
    fingerprint     TEXT      NOT NULL,
    created_at      TIMESTAMP NOT NULL
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Dropping this table discards the host key, which every client that
-- has connected once has pinned in known_hosts, and the CA key, which
-- every outstanding certificate chains to. Rolling back therefore
-- presents as MITM to every existing user. Do it deliberately or not
-- at all.
DROP TABLE ssh_gateway_keys;

-- +goose StatementEnd
