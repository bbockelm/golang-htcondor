-- +goose Up
-- +goose StatementBegin

-- The access point a JupyterLab session's job is on, for a server that
-- fronts several (multi-AP mode). Every schedd interaction for the
-- session -- the status reads that reap it, an adoption after a restart
-- -- goes to this access point and no other. '' for rows written by a
-- single-AP server, which keep single-AP semantics: there the one schedd
-- is the session's, and in multi-AP mode such a row's job is not looked
-- for on any access point.
ALTER TABLE jupyter_sessions ADD COLUMN schedd TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE jupyter_sessions DROP COLUMN schedd;
-- +goose StatementEnd
