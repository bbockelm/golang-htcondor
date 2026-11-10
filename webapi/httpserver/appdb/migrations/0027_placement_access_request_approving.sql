-- +goose Up
-- +goose StatementBegin

-- An approval now holds its request while it edits the placementd's
-- directory: status 'approving', with decided_by naming the admin, so the
-- requester cannot withdraw it and another admin cannot deny it meanwhile.
-- SQLite cannot change a CHECK constraint in place, so the table is
-- rebuilt. A pending or approving request both count as the identity's
-- one open request.
CREATE TABLE placement_access_requests_new (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    identity           TEXT NOT NULL,
    idp_subject        TEXT NOT NULL DEFAULT '',
    display_name       TEXT NOT NULL DEFAULT '',
    email              TEXT NOT NULL DEFAULT '',
    requested_projects TEXT NOT NULL DEFAULT '[]',
    note               TEXT NOT NULL DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending', 'approving', 'approved', 'denied', 'withdrawn')),
    created_at         INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL,
    decided_by         TEXT NOT NULL DEFAULT '',
    decided_at         INTEGER NOT NULL DEFAULT 0,
    decision_note      TEXT NOT NULL DEFAULT '',
    account            TEXT NOT NULL DEFAULT '',
    changeset_id       INTEGER NOT NULL DEFAULT 0
);
INSERT INTO placement_access_requests_new
    SELECT id, identity, idp_subject, display_name, email, requested_projects, note, status,
           created_at, updated_at, decided_by, decided_at, decision_note, account, changeset_id
    FROM placement_access_requests;
DROP TABLE placement_access_requests;
ALTER TABLE placement_access_requests_new RENAME TO placement_access_requests;
CREATE UNIQUE INDEX IF NOT EXISTS idx_placement_access_requests_pending
    ON placement_access_requests(identity) WHERE status IN ('pending', 'approving');
CREATE INDEX IF NOT EXISTS idx_placement_access_requests_identity
    ON placement_access_requests(identity, id);
CREATE INDEX IF NOT EXISTS idx_placement_access_requests_status
    ON placement_access_requests(status, id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TABLE placement_access_requests_old (
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
INSERT INTO placement_access_requests_old
    SELECT id, identity, idp_subject, display_name, email, requested_projects, note,
           CASE status WHEN 'approving' THEN 'pending' ELSE status END,
           created_at, updated_at, decided_by, decided_at, decision_note, account, changeset_id
    FROM placement_access_requests;
DROP TABLE placement_access_requests;
ALTER TABLE placement_access_requests_old RENAME TO placement_access_requests;
CREATE UNIQUE INDEX IF NOT EXISTS idx_placement_access_requests_pending
    ON placement_access_requests(identity) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_placement_access_requests_identity
    ON placement_access_requests(identity, id);
CREATE INDEX IF NOT EXISTS idx_placement_access_requests_status
    ON placement_access_requests(status, id);
-- +goose StatementEnd
