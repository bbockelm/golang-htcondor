-- +goose Up
-- +goose StatementBegin

-- One bound per (subject, identity) instead of per subject. Several sign-in
-- identities can map to one account, each with its own grants and project;
-- keyed by account alone, whichever signed in last rewrote the bound every
-- other identity's grants of that account are minted within.
CREATE TABLE placement_oauth_subjects_new (
    subject            TEXT NOT NULL,
    identity           TEXT NOT NULL,
    authorizations     TEXT NOT NULL DEFAULT '',
    project            TEXT NOT NULL DEFAULT '',
    mapping_expires_at INTEGER NOT NULL DEFAULT 0,
    updated_at         INTEGER NOT NULL,
    PRIMARY KEY (subject, identity)
);
INSERT INTO placement_oauth_subjects_new
    (subject, identity, authorizations, project, mapping_expires_at, updated_at)
    SELECT subject, identity, authorizations, project, mapping_expires_at, updated_at
    FROM placement_oauth_subjects;
DROP TABLE placement_oauth_subjects;
ALTER TABLE placement_oauth_subjects_new RENAME TO placement_oauth_subjects;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TABLE placement_oauth_subjects_old (
    subject            TEXT PRIMARY KEY,
    identity           TEXT NOT NULL,
    authorizations     TEXT NOT NULL DEFAULT '',
    project            TEXT NOT NULL DEFAULT '',
    mapping_expires_at INTEGER NOT NULL DEFAULT 0,
    updated_at         INTEGER NOT NULL
);
-- Keeps the most recently updated identity's row for each subject.
INSERT OR REPLACE INTO placement_oauth_subjects_old
    (subject, identity, authorizations, project, mapping_expires_at, updated_at)
    SELECT subject, identity, authorizations, project, mapping_expires_at, updated_at
    FROM placement_oauth_subjects ORDER BY updated_at;
DROP TABLE placement_oauth_subjects;
ALTER TABLE placement_oauth_subjects_old RENAME TO placement_oauth_subjects;
-- +goose StatementEnd
