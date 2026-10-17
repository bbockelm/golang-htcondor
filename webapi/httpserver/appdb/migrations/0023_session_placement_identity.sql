-- +goose Up
-- +goose StatementBegin

-- The sign-in identity a browser session presents to condor_placementd,
-- derived from the provider's claims (HTTP_API_PLACEMENT_IDENTITY_CLAIMS),
-- and the name to greet the person with. '' for sessions created before
-- this column existed, which simply have no placement identity.
ALTER TABLE http_sessions ADD COLUMN placement_identity TEXT NOT NULL DEFAULT '';
ALTER TABLE http_sessions ADD COLUMN display_name TEXT NOT NULL DEFAULT '';

-- What the session may reach. '' is an ordinary session; 'placement' is
-- one for a person who maps to no local account, which reaches only the
-- placement onboarding pages and their API.
ALTER TABLE http_sessions ADD COLUMN scope TEXT NOT NULL DEFAULT '';

-- Where the session's HTCondor identity came from: '' for a local account
-- (or no mapping), 'placementd' for an account condor_placementd assigned
-- to the sign-in identity. placement_json then holds that account, its
-- grants and projects, the selected project, the mapping's expiry and
-- when it was last re-read.
ALTER TABLE http_sessions ADD COLUMN identity_source TEXT NOT NULL DEFAULT '';
ALTER TABLE http_sessions ADD COLUMN placement_json TEXT NOT NULL DEFAULT '';

-- The HTCondor account, grants and selected project of every OAuth2
-- subject a placementd-mapped session authorized, so a token minted for
-- such a grant stays within what the account holds.
CREATE TABLE IF NOT EXISTS placement_oauth_subjects (
    subject            TEXT PRIMARY KEY,
    identity           TEXT NOT NULL,
    authorizations     TEXT NOT NULL DEFAULT '',
    project            TEXT NOT NULL DEFAULT '',
    mapping_expires_at INTEGER NOT NULL DEFAULT 0,
    updated_at         INTEGER NOT NULL
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS placement_oauth_subjects;
ALTER TABLE http_sessions DROP COLUMN placement_json;
ALTER TABLE http_sessions DROP COLUMN identity_source;
ALTER TABLE http_sessions DROP COLUMN scope;
ALTER TABLE http_sessions DROP COLUMN display_name;
ALTER TABLE http_sessions DROP COLUMN placement_identity;
-- +goose StatementEnd
