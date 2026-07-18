-- +goose Up
-- +goose StatementBegin

-- API keys are an authentication channel for non-interactive callers
-- (Prometheus scrapes, scripts, CI). They live alongside browser
-- sessions and OAuth2 tokens but are intentionally distinct: they
-- carry no group identity from an IDP, and they're admin-mintable
-- only because we can't yet revoke a user's keys when their account
-- is suspended elsewhere.
--
-- Wire format of a key: "htca-v1-<key_id>-<secret>" where:
--   key_id  is 12 hex chars (6 bytes of CSPRNG; this column's PK)
--   secret  is 32 hex chars (16 bytes of CSPRNG; only its hash is
--           stored — see secret_hash)
-- The "htca-v1-" prefix is the leak-scan signature so a key
-- accidentally pasted in a public repo or log can be picked up by
-- secret-scanners that match a literal substring.
--
-- We don't bcrypt the secret. The secret already has 128 bits of
-- uniform entropy from /dev/urandom — bcrypt's slow KDF is for
-- low-entropy passwords. SHA-256 with a constant-time compare is
-- correct here and runs in microseconds, which matters because we
-- validate on every authenticated request.

CREATE TABLE api_keys (
    -- 12 hex chars (6 bytes). Indexed via PRIMARY KEY so request-
    -- path lookups are O(log n).
    key_id TEXT PRIMARY KEY,
    -- Hex SHA-256 of the secret half. NEVER NULL: a row without a
    -- hash would silently authenticate anyone who knew the key_id.
    secret_hash TEXT NOT NULL,
    -- User-supplied label (e.g. "prom-scrape", "alice-laptop"). Not
    -- unique — two keys can share a name.
    name TEXT NOT NULL,
    -- JSON array of scope strings: e.g. '["metrics"]'. We store as
    -- text rather than a normalized table because (a) the scope
    -- vocabulary is small and stable, (b) reading scopes happens
    -- once per request and a join would be more code for less
    -- speed.
    scopes_json TEXT NOT NULL,
    -- Username of the admin who minted this key. The key's effective
    -- auth identity (the user the key authenticates AS) is THIS
    -- field, not whoever holds the secret. Soft-deleting an account
    -- in a future user table will require also soft-deleting all
    -- keys with this creator value.
    creator TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Unix-epoch expiration. NULL means "never expires"; that's
    -- intentional and not a bug for service-account-style keys
    -- where rotation is automated externally.
    expires_at TIMESTAMP,
    -- Soft-delete tombstone for audit. The key stops authenticating
    -- the instant this is set; the row stays for forensics. A future
    -- migration can prune rows older than some window.
    deleted_at TIMESTAMP,
    -- Best-effort "last seen" — we update it on successful auth, but
    -- not synchronously (a future patch can defer to a background
    -- writer). NULL means never used.
    last_used_at TIMESTAMP
);

-- Lookup by creator drives the admin's "my keys" list. The active-
-- only partial index also accelerates the auth path's "is this id
-- valid right now?" check (we hit the row by PK, then check
-- deleted_at IS NULL and expires_at — having the active subset
-- compactly indexed keeps lookups working when the table grows large
-- with soft-deleted rows).
CREATE INDEX api_keys_creator ON api_keys(creator);
CREATE INDEX api_keys_active ON api_keys(deleted_at) WHERE deleted_at IS NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS api_keys_active;
DROP INDEX IF EXISTS api_keys_creator;
DROP TABLE IF EXISTS api_keys;

-- +goose StatementEnd
