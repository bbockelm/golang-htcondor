-- +goose Up
-- +goose StatementBegin

-- Service keys, and the staleness bound on everything that is not one.
--
-- An API key acts as the admin who minted it. Until now that was the
-- whole model: the key carried an identity and a scope set, and any
-- entitlement beyond "your own jobs" was re-derived on each request
-- from the creator's group membership. Where membership comes from the
-- token rather than the system (HTTP_API_GROUP_SOURCE=token, the
-- default and the only option in a container) there is nothing to
-- re-derive from, so a key minted by an administrator silently acted as
-- an ordinary user.
--
-- The entitlement is provable exactly once: at mint, where the minting
-- admin has a session whose groups came from their token. Recording it
-- there is what these columns are for. That is the same move the OAuth2
-- path already makes -- granted_scopes is decided at consent and stored
-- -- so a key stops being the odd credential out.
--
-- Recording a grant also inherits the hazard that comes with one: a
-- frozen entitlement outlives the membership that justified it. The two
-- columns below are the two different answers to that, and which one
-- applies is the whole distinction between a service key and an
-- ordinary one.

-- A service key is a credential belonging to an automation, not to a
-- person who happens to own it. Its entitlement is granted at mint and
-- held for the life of the key; bounded by a mandatory expires_at
-- rather than by its creator's membership, because there is no
-- interactive login in its future to re-prove anything. Re-minting it
-- is the re-attestation.
ALTER TABLE api_keys ADD COLUMN service BOOLEAN NOT NULL DEFAULT 0;

-- An ordinary key is its creator's, and tracks its creator. Its
-- entitlements are re-verified on use against whatever live source the
-- deployment has -- the account database, or the identity provider via
-- a stored upstream refresh token. This column is when that last
-- succeeded.
--
-- It exists because neither live source is always available: a
-- token-sourced deployment with no upstream credential has no way to
-- ask, and the upstream oracle deliberately rate-limits itself so most
-- requests get no answer. Rather than treat silence as consent
-- forever, an unverified entitlement is honored only while this
-- timestamp is recent and is dropped after that. Silence is not a
-- denial, but it does expire.
--
-- Seeded at mint, which is a verification: the minting admin proved the
-- entitlement with a live session to get the key at all.
ALTER TABLE api_keys ADD COLUMN entitlements_checked_at TIMESTAMP;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- SQLite before 3.35 cannot DROP COLUMN, and the table is small, so the
-- down migration rebuilds it. Column order matches the 0004 definition
-- so a re-run of the up migration lands where it started.
CREATE TABLE api_keys_pre_0030 (
    key_id TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    creator TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    deleted_at TIMESTAMP,
    last_used_at TIMESTAMP
);

INSERT INTO api_keys_pre_0030
    (key_id, secret_hash, name, scopes_json, creator, created_at,
     expires_at, deleted_at, last_used_at)
SELECT key_id, secret_hash, name, scopes_json, creator, created_at,
       expires_at, deleted_at, last_used_at
  FROM api_keys;

DROP INDEX IF EXISTS api_keys_active;
DROP INDEX IF EXISTS api_keys_creator;
DROP TABLE api_keys;
ALTER TABLE api_keys_pre_0030 RENAME TO api_keys;

CREATE INDEX api_keys_creator ON api_keys(creator);
CREATE INDEX api_keys_active ON api_keys(deleted_at) WHERE deleted_at IS NULL;

-- +goose StatementEnd
