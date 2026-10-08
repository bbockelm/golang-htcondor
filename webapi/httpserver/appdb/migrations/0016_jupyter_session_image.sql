-- +goose Up
-- +goose StatementBegin

-- The image a JupyterLab session was launched with.
--
-- Held only in process memory until now, so a session re-adopted after a
-- restart came back without it and the detail page dropped the line naming
-- it. Empty for rows written before this column existed.
ALTER TABLE jupyter_sessions ADD COLUMN image TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE jupyter_sessions DROP COLUMN image;
-- +goose StatementEnd
