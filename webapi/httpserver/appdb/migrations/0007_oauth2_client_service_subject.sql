-- +goose Up
-- +goose StatementBegin

-- The client_credentials grant has no end user: the token represents the
-- client itself. To let such a token carry HTCondor authorization, the client
-- needs a service identity to assert as the IDTOKEN subject (the schedd then
-- enforces ALLOW_<LEVEL> against it, exactly as for a person). service_subject
-- holds that identity; it is required before client_credentials will issue a
-- token, so a service credential can never mint one for an empty/ambiguous
-- subject. Empty for every other client.
ALTER TABLE oauth2_clients ADD COLUMN service_subject TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE oauth2_clients DROP COLUMN service_subject;
-- +goose StatementEnd
