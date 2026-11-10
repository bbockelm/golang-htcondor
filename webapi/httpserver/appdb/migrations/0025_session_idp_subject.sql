-- +goose Up
-- +goose StatementBegin

-- The provider's subject for a placement-only session's sign-in, so the
-- sign-in's identity mapping can be re-run for that session once an
-- administrator onboards the person. '' on every other session.
ALTER TABLE http_sessions ADD COLUMN idp_subject TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE http_sessions DROP COLUMN idp_subject;
-- +goose StatementEnd
