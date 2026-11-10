-- +goose Up
-- http_sessions.session_id now stores the SHA-256 of the session cookie
-- value rather than the value itself (see sessionKey in
-- httpserver/session.go). Rows written before this hold raw cookie
-- values, which no lookup will match any more; drop them rather than
-- hash them in place. Those values may already have been read from a
-- database file that was not mode 0600, and hashing them would keep
-- such sessions valid. The cost is one re-login per browser.
DELETE FROM http_sessions;

-- +goose Down
-- Hashed rows cannot be turned back into cookie values; drop them so
-- an older server does not keep rows it can never match.
DELETE FROM http_sessions;
