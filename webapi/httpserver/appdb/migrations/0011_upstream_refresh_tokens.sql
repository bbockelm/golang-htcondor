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
-- Keyed by the SESSION subject and the issuer together.
--
-- The session subject is what a grant carries and therefore what the refresh
-- path can look this up by. Where the deployment maps identities it is the
-- local account, not the provider's name for the user, so keying on the
-- provider's name would file the credential under something no later lookup
-- holds.
--
-- provider_subject records the provider's own name alongside it, because the
-- userinfo answer has to be checked against something: the call names no user
-- -- the credential decides whose claims come back -- so a credential filed
-- against the wrong row would quietly apply one person's groups to another.
--
-- The issuer is in the key because a deployment can be moved between
-- providers and both identifiers are the provider's own opaque strings, so
-- they can collide.
--
-- refresh_token_dek is the wrapped data key when the value is sealed
-- (HTTP_API_KEK_FILE), NULL when it is stored in the clear. Same shape as
-- idp_rsa_keys, so one KEK covers every long-lived secret rather than each
-- growing its own scheme.
CREATE TABLE upstream_refresh_tokens (
    subject             TEXT NOT NULL,
    issuer              TEXT NOT NULL,
    provider_subject    TEXT NOT NULL DEFAULT '',
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
