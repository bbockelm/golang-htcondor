-- +goose Up
-- +goose StatementBegin

-- Site apps an administrator published through the web interface,
-- rather than an operator through the configuration.
--
-- The configuration is the right home for an access point provisioned
-- by configuration management, and it stays the authority: an id named
-- in both places is the configuration's, and an upload for such an id
-- is refused rather than merged. Otherwise uploading would be a way to
-- restate a decision the configuration had already made, which is the
-- one thing moving policy into the configuration was meant to prevent.
--
-- Only the policy lives here. The bundle itself is written into the
-- site apps directory as <id>.zip, beside the ones that arrived by
-- scp, because that is where the loader looks and the daemon already
-- creates files there (see siteapps.createUnlinked). Keeping the bytes
-- in a row would mean materializing them again on every open for no
-- benefit.
CREATE TABLE IF NOT EXISTS site_app_uploads (
    app_id      TEXT    PRIMARY KEY,

    -- The policy, same shape as its configured counterpart.
    app_groups  TEXT    NOT NULL,
    home        INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    name        TEXT    NOT NULL DEFAULT '',
    description TEXT    NOT NULL DEFAULT '',
    icon        TEXT    NOT NULL DEFAULT '',

    -- Who to ask about it. An uploaded app runs with the full rights
    -- of whoever is looking at it, in code this release did not
    -- review, so "who put this here, and when?" is not bookkeeping --
    -- it is the first question after anything goes wrong.
    uploaded_by TEXT    NOT NULL DEFAULT '',
    uploaded_at INTEGER NOT NULL DEFAULT 0,
    -- The digest of the bytes that were accepted. The scan records
    -- what it later served (site_app_incarnations); this records what
    -- was handed over, and the two disagreeing means the file changed
    -- underneath after it was accepted.
    digest      TEXT    NOT NULL DEFAULT '',
    size_bytes  INTEGER NOT NULL DEFAULT 0
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP TABLE IF EXISTS site_app_uploads;

-- +goose StatementEnd
