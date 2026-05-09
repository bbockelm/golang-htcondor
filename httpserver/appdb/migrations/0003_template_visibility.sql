-- +goose Up
-- +goose StatementBegin

-- Adds a visibility column to user-saved templates. Two states:
--   "private" — only the owner sees it (default; matches pre-feature
--               behavior).
--   "shared"  — every authenticated user sees it in the picker. Only
--               the owner can edit or delete; everyone else can read
--               and load it as a starting point.
--
-- The column is non-nullable with a "private" default so existing rows
-- migrate without scanning user data: every row that was a private
-- template before stays private after.
--
-- An index on (visibility) accelerates the cross-user "list every
-- shared template" path on every list call. The picker fetches:
--   - all rows where owner == actor (private + shared, the user's own)
--   - all rows where owner != actor AND visibility = 'shared'
-- and the index makes the second clause fast even with many users.

ALTER TABLE templates_user ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private';
CREATE INDEX templates_user_visibility ON templates_user(visibility);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS templates_user_visibility;
ALTER TABLE templates_user DROP COLUMN visibility;

-- +goose StatementEnd
