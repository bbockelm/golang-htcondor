-- +goose Up
-- idp_sessions.session_id now stores the SHA-256 of the idp_session
-- cookie value, as http_sessions does since 0018. Rows written before
-- this hold raw cookie values; drop them for the same reason 0018 does.
-- Users of the built-in IdP sign in again.
DELETE FROM idp_sessions;

-- +goose Down
-- Hashed rows cannot be turned back into cookie values.
DELETE FROM idp_sessions;
