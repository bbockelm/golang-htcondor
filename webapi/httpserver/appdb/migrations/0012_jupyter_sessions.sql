-- +goose Up
-- +goose StatementBegin

-- What a JupyterLab session needs to survive this process.
--
-- A session's job keeps running when the API server restarts, and so does
-- JupyterLab inside it -- but the tunnel does not. The helper dialed back to
-- a process that no longer exists, and everything needed to accept it again
-- lived in that process's memory: a random signing secret, and the registry
-- of which instance belonged to whom. So the sessions were unreachable, and
-- the jobs lingered with nothing left to reap them.
--
-- The job ad carries the session's identity (its batch name) because that is
-- not secret and any pool user can read an ad. The credential cannot go
-- there, so it goes here, sealed under the same KEK as every other
-- long-lived secret.
CREATE TABLE jupyter_sessions (
    -- hex of the 16-byte instance id. The same id the job ad names, which is
    -- what lets a restarted server match a queued job to its row.
    instance_id     TEXT PRIMARY KEY,
    owner           TEXT NOT NULL,
    cluster_id      INTEGER NOT NULL DEFAULT 0,
    proc_id         INTEGER NOT NULL DEFAULT 0,

    -- The nonce of the one token that may be presented next.
    --
    -- The nonce rather than the token: a nonce is useless without the
    -- signing secret, so a row that leaks is not a credential. Rolling it on
    -- every accepted connection is what keeps tokens single-use across a
    -- restart, which the in-memory burned set could not do -- it came back
    -- empty and every spent token was live again.
    next_nonce      BLOB NOT NULL,

    created_at      TIMESTAMP NOT NULL,
    -- When this session stops being valid, whatever the job does. The
    -- sweeper deletes past this, so a row cannot outlive its session and
    -- accumulate.
    expires_at      TIMESTAMP NOT NULL
);

CREATE INDEX idx_jupyter_sessions_expires ON jupyter_sessions(expires_at);

-- The registry's token-signing secret.
--
-- One row, and the reason the sessions table is worth having: regenerated
-- per process, every token minted before a restart stops verifying after it.
-- Sealed like idp_rsa_keys and upstream_refresh_tokens, so one KEK covers
-- every long-lived secret rather than each growing its own scheme.
-- secret_dek is the wrapped data key when sealed, NULL when stored in the
-- clear (no HTTP_API_KEK_FILE).
CREATE TABLE jupyter_signing_secret (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    secret      BLOB NOT NULL,
    secret_dek  BLOB,
    created_at  TIMESTAMP NOT NULL
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE jupyter_signing_secret;
DROP TABLE jupyter_sessions;
-- +goose StatementEnd
