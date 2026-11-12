-- +goose Up
-- +goose StatementBegin

-- What this access point has actually served under /site/, and when.
--
-- The configuration says what an operator intends; this says what the
-- server did. The two can disagree in ways only a record catches: a
-- bundle replaced in place, a checksum that stopped matching, an app
-- that was visible to a group for three weeks before anybody noticed.
-- "What was running on the third?" is not answerable from a
-- configuration file, which only ever describes now.
--
-- A row is an INCARNATION: a period during which one app was served
-- from one artifact under one policy. Each scan either bumps last_seen
-- on the open row or, when something in that sentence changed, closes
-- it and opens another. That is a handful of rows per app per year
-- rather than a row per scan, and it answers the question by date
-- range directly.
--
-- Reverting to a previous bundle opens a new row rather than reopening
-- the old one. The old row is a statement about a period of time, and
-- rewriting it to cover a second period would make it false about the
-- gap between them.
CREATE TABLE IF NOT EXISTS site_app_incarnations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    app_id          TEXT    NOT NULL,

    -- The artifact. digest is the SHA-256 of the bundle file, which is
    -- what identifies it; '' for a directory bundle, which has no
    -- single set of bytes to hash and is a development convenience
    -- rather than something anybody audits.
    digest          TEXT    NOT NULL,
    bundle_kind     TEXT    NOT NULL,          -- 'zip' | 'directory'
    size_bytes      INTEGER NOT NULL DEFAULT 0,
    -- Whether a .sha256 sidecar was present and matched. A bundle
    -- loaded without one is not suspect, but it is less attested, and
    -- the difference is worth keeping: it separates "these bytes are
    -- what the author sent" from "these are the bytes we found".
    digest_declared INTEGER NOT NULL DEFAULT 0,

    -- What the bundle said about itself (app.yaml). version and
    -- revision are the author's, free-form and absent in older
    -- bundles: they make "which build was this?" answerable without
    -- keeping every artifact.
    version         TEXT    NOT NULL DEFAULT '',
    revision        TEXT    NOT NULL DEFAULT '',
    name            TEXT    NOT NULL DEFAULT '',
    description     TEXT    NOT NULL DEFAULT '',
    icon            TEXT    NOT NULL DEFAULT '',

    -- The policy in force for this period, recorded rather than
    -- referenced. Configuration is not versioned and the file can be
    -- edited between one scan and the next, so a row that pointed at
    -- "the configuration" would describe today's answer, not the one
    -- that applied. groups is the comma-joined list as it was applied.
    app_groups      TEXT    NOT NULL DEFAULT '',
    home            INTEGER NOT NULL DEFAULT 0,
    -- Where the policy came from, e.g. the configuration parameter
    -- name. An upload path would write its own origin here, which is
    -- how "who decided this?" stays answerable once there is more than
    -- one way to decide it.
    policy_origin   TEXT    NOT NULL DEFAULT '',

    first_seen      INTEGER NOT NULL,          -- unix seconds
    last_seen       INTEGER NOT NULL
);

-- The common reads are "this app's history, newest first" and "what
-- was being served at time T", both of which want app_id with a time.
CREATE INDEX IF NOT EXISTS site_app_incarnations_app_time
    ON site_app_incarnations (app_id, last_seen DESC);

-- "Where else has this artifact been served?" -- the question a digest
-- is for, once the same bundle is deployed under two ids or at two
-- access points sharing a database.
CREATE INDEX IF NOT EXISTS site_app_incarnations_digest
    ON site_app_incarnations (digest);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS site_app_incarnations_digest;
DROP INDEX IF EXISTS site_app_incarnations_app_time;
DROP TABLE IF EXISTS site_app_incarnations;

-- +goose StatementEnd
