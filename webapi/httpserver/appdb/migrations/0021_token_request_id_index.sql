-- +goose Up
-- Revoking a grant, narrowing its scopes and checking that a token's
-- parent grant is still live all look tokens up by request_id, which
-- had no index, so each was a scan of the whole table.
CREATE INDEX IF NOT EXISTS idx_access_tokens_request ON oauth2_access_tokens(request_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_request ON oauth2_refresh_tokens(request_id);
CREATE INDEX IF NOT EXISTS idx_idp_access_tokens_request ON idp_access_tokens(request_id);
CREATE INDEX IF NOT EXISTS idx_idp_refresh_tokens_request ON idp_refresh_tokens(request_id);

-- +goose Down
DROP INDEX IF EXISTS idx_idp_refresh_tokens_request;
DROP INDEX IF EXISTS idx_idp_access_tokens_request;
DROP INDEX IF EXISTS idx_refresh_tokens_request;
DROP INDEX IF EXISTS idx_access_tokens_request;
