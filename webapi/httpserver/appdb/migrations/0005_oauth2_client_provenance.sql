-- +goose Up
-- +goose StatementBegin

-- OAuth2 client rows were unidentifiable in the admin UI. A client
-- registered dynamically gets an id of "client_<unixnano>", which says
-- nothing about who registered it or what it is, and the display name
-- the client sends at registration (RFC 7591 "client_name") was parsed,
-- echoed back in the registration response, and then dropped on the
-- floor. An admin auditing the list had the id and the redirect URIs and
-- nothing else.
--
-- These columns are all about provenance -- where a client came from,
-- what it calls itself, what an operator learned about it, and whether
-- it is still in use.

-- The RFC 7591 client_name from dynamic registration. Empty for clients
-- registered before this column existed and for seeded ones. Not unique:
-- two installs of the same app legitimately share a name.
ALTER TABLE oauth2_clients ADD COLUMN client_name TEXT NOT NULL DEFAULT '';

-- Free-text operator annotation, editable from the admin UI. This is
-- the escape hatch for every client whose provenance the software cannot
-- recover on its own -- notably the ones that predate this migration.
ALTER TABLE oauth2_clients ADD COLUMN notes TEXT NOT NULL DEFAULT '';

-- How the client came to exist. Three states, and the empty one is
-- meaningful:
--   'dynamic' registered through /mcp/oauth2/register (RFC 7591)
--   'seeded'  created by this server at startup (e.g. swagger-client)
--   ''        unknown; predates this column and does not match the
--             backfill below
-- Kept as a string rather than a boolean so "we don't know" stays
-- distinguishable from "not dynamic". A UI that renders '' as "not
-- dynamically registered" would be asserting something we never checked.
ALTER TABLE oauth2_clients ADD COLUMN origin TEXT NOT NULL DEFAULT '';

-- When this client last obtained a token. NULL means never, which for a
-- dynamically registered client usually means an app registered once and
-- never came back -- exactly the churn worth cleaning up.
ALTER TABLE oauth2_clients ADD COLUMN last_used_at TIMESTAMP;

-- JSON array of the most recent distinct subjects to obtain a token
-- through this client, newest first, capped at three. Denormalized on
-- purpose: it is written on a debounced background flush and read once
-- per admin page view, so a join table would be more moving parts for a
-- list that never exceeds three entries.
--
-- Note this is a rolling sample, not an audit log. Token issuance is
-- already recorded per token in oauth2_access_tokens; this exists so the
-- client list can answer "who is this thing acting for?" at a glance.
ALTER TABLE oauth2_clients ADD COLUMN recent_users TEXT NOT NULL DEFAULT '';

-- Backfill for rows that predate the column.
--
-- "client_<digits>" is the exact id format this server's own
-- registration handler generates (fmt.Sprintf("client_%d",
-- time.Now().UnixNano())), so matching it is reading back a structure we
-- wrote, not guessing from user-controlled data. GLOB rather than LIKE:
-- LIKE treats "_" as a single-character wildcard, which would also match
-- ids like "clientX123".
UPDATE oauth2_clients SET origin = 'dynamic' WHERE id GLOB 'client_[0-9]*';

-- The one client this server seeds itself, for the Swagger UI at /docs.
UPDATE oauth2_clients SET origin = 'seeded' WHERE id = 'swagger-client';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE oauth2_clients DROP COLUMN recent_users;
ALTER TABLE oauth2_clients DROP COLUMN last_used_at;
ALTER TABLE oauth2_clients DROP COLUMN origin;
ALTER TABLE oauth2_clients DROP COLUMN notes;
ALTER TABLE oauth2_clients DROP COLUMN client_name;

-- +goose StatementEnd
