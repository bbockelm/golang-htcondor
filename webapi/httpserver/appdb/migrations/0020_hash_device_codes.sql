-- +goose Up
-- oauth2_device_codes.device_code now stores the SHA-256 of the device
-- code (see sessionKey in httpserver/session.go). Rows written before
-- this hold raw codes that no lookup will match. Device codes live ten
-- minutes, so dropping them costs at most one interrupted device login.
DELETE FROM oauth2_device_codes;

-- +goose Down
-- Hashed rows cannot be turned back into device codes.
DELETE FROM oauth2_device_codes;
