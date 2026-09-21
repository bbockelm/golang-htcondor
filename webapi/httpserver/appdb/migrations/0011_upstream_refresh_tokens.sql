-- +goose Up
-- +goose StatementBegin

-- The refresh token this server holds AS A CLIENT of the upstream identity
-- provider, so it can ask that provider about a user after they have gone
-- home.
--
-- Everything else here is about tokens this server ISSUES. This is the one
-- credential it HOLDS, and it is what closes the membership-drift gap the
-- refresh path documents: group membership in a token is frozen at consent,
-- and re-reading it live needs either an account database (which a container
-- does not have) or a live credential to the provider. This is that
-- credential.
--
-- Keyed by subject and issuer together. A deployment can be moved between
-- providers, and a subject from the old one must not be answered by a token
-- minted for the new -- the string may even collide, since both are the
-- provider's own opaque identifier.
--
-- refresh_token_dek is the wrapped data key when the value is sealed
-- (HTTP_API_KEK_FILE), NULL when it is stored in the clear. Same shape as
-- idp_rsa_keys, so one KEK covers every long-lived secret rather than each
-- growing its own scheme.
CREATE TABLE upstream_refresh_tokens (
    subject             TEXT NOT NULL,
    issuer              TEXT NOT NULL,
    refresh_token       BLOB NOT NULL,
    refresh_token_dek   BLOB,
    -- The scopes the provider actually granted, which is not always what was
    -- asked for. Recorded so "auto" can tell a provider that withheld
    -- offline_access from one that was never asked.
    granted_scopes      TEXT NOT NULL DEFAULT '',
    obtained_at         TIMESTAMP NOT NULL,
    -- When this token was last exchanged successfully. The checker reads it
    -- to rate-limit itself: a client refreshing on a timer must not turn one
    -- user's session into a steady load on somebody else's identity provider.
    last_checked_at     TIMESTAMP,
    PRIMARY KEY (subject, issuer)
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE upstream_refresh_tokens;
-- +goose StatementEnd
