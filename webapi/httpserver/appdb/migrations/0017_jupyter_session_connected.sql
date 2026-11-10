-- +goose Up
-- +goose StatementBegin

-- Whether a JupyterLab session's helper has ever connected.
--
-- A restarted server adopts every live session, and the two kinds need
-- opposite treatment. One whose helper had connected lost its tunnel with
-- the last process and should dial back within the reconnect grace period,
-- so it is closed if it does not. One whose job has not started yet may
-- wait in the queue for hours, and closing it after a few minutes would
-- refuse its first dial and end the job. Set by the first accepted dial
-- (the nonce roll); 0 for rows written before this column existed.
ALTER TABLE jupyter_sessions ADD COLUMN connected INTEGER NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE jupyter_sessions DROP COLUMN connected;
-- +goose StatementEnd
