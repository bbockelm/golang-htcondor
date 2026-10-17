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

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE http_sessions DROP COLUMN scope;
ALTER TABLE http_sessions DROP COLUMN display_name;
ALTER TABLE http_sessions DROP COLUMN placement_identity;
-- +goose StatementEnd
