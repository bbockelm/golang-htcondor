-- +goose Up
-- +goose StatementBegin

-- The email address the provider gave at sign-in, for a session that has a
-- placement identity: shown to administrators with an access request.
-- '' when the provider gave none, and on sessions created before this
-- column existed.
ALTER TABLE http_sessions ADD COLUMN email TEXT NOT NULL DEFAULT '';

-- Requests for access from people who signed in with a placement identity
-- condor_placementd does not map. The placementd records who has access;
-- this table records who asked for it and what an administrator decided.
--
-- identity is the session's placement identity, never anything the
-- requester typed. idp_subject, display_name and email are copied from the
-- session when the request is made. requested_projects is a JSON list of
-- strings. decided_by, decided_at and decision_note are set when an
-- administrator approves or denies; account and changeset_id when an
-- approval's directory change committed (changeset_id 0 when the
-- placementd did not say which change set it was).
CREATE TABLE IF NOT EXISTS placement_access_requests (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    identity           TEXT NOT NULL,
    idp_subject        TEXT NOT NULL DEFAULT '',
    display_name       TEXT NOT NULL DEFAULT '',
    email              TEXT NOT NULL DEFAULT '',
    requested_projects TEXT NOT NULL DEFAULT '[]',
    note               TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'approved', 'denied', 'withdrawn')),
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    decided_by         TEXT NOT NULL DEFAULT '',
    decided_at         INTEGER NOT NULL DEFAULT 0,
    decision_note      TEXT NOT NULL DEFAULT '',
    account            TEXT NOT NULL DEFAULT '',
    changeset_id       INTEGER NOT NULL DEFAULT 0
);
-- At most one pending request per identity.
CREATE UNIQUE INDEX IF NOT EXISTS idx_placement_access_requests_pending
    ON placement_access_requests(identity) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_placement_access_requests_identity
    ON placement_access_requests(identity, id);
CREATE INDEX IF NOT EXISTS idx_placement_access_requests_status
    ON placement_access_requests(status, id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS placement_access_requests;
ALTER TABLE http_sessions DROP COLUMN email;
-- +goose StatementEnd
