-- +goose Up
-- +goose StatementBegin

-- Where an uploaded bundle came from, when it came from somewhere
-- nameable.
--
-- A bundle that arrived as bytes through the form has no source and
-- leaves these empty: nothing about a file picked from a laptop says
-- where it was built. A bundle the server fetched from a GitHub
-- release does, and recording it buys two things that are otherwise
-- impossible:
--
--   * "is there a newer one?" can be asked at all. Without the repo
--     there is nothing to ask it of, and an administrator's only way
--     to know an app is stale is to remember where they got it.
--   * the next update does not have to be retyped. Replacing the
--     bundle is then a choice of tag rather than a choice of repo,
--     asset and tag.
--
-- source_ref is the tag that was RESOLVED, never the word "latest":
-- "latest" is a question, and the answer is what was installed. A row
-- saying "latest" would compare equal to every future release and the
-- update check would never fire.
ALTER TABLE site_app_uploads ADD COLUMN source_repo  TEXT NOT NULL DEFAULT '';
ALTER TABLE site_app_uploads ADD COLUMN source_ref   TEXT NOT NULL DEFAULT '';
ALTER TABLE site_app_uploads ADD COLUMN source_asset TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE site_app_uploads DROP COLUMN source_asset;
ALTER TABLE site_app_uploads DROP COLUMN source_ref;
ALTER TABLE site_app_uploads DROP COLUMN source_repo;

-- +goose StatementEnd
