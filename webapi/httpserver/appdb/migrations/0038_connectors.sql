-- +goose Up
-- +goose StatementBegin

-- Connectors: the third-party accounts this server connects to on a user's
-- behalf, so a job can use a credential the user granted.
--
-- Not to be confused with oauth2_clients, which is the opposite direction:
-- those are applications connecting TO this server's identity provider.
-- These are accounts this server connects to. See design_notes/CONNECTORS.md.
--
-- Two tables, because what a connector IS and what a user GRANTED have
-- different lifetimes and different blast radii. Keeping them apart is what
-- lets an operator revoke every credential for a connector -- a rotated or
-- leaked client secret -- without deleting the connector, and what lets a
-- connector's definition be edited without touching anybody's grant.

-- What a connector is, when this server is what declares it.
--
-- A connector the HTCondor configuration declares has NO row here.
-- Configuration wins where both speak, so a row that merely loses would be
-- a row an operator can edit to no effect -- they would change a form, see
-- it saved, and find out from a user that nothing happened. The admin page
-- reports a shadowed row rather than hiding it, and this table not carrying
-- one is the other half of that.
CREATE TABLE connectors (
    -- "<namespace>:<name>": builtin:gdrive, site:cryoem. The namespace is
    -- part of the key because builtin:gdrive and site:gdrive are different
    -- client registrations -- different applications -- and merging them
    -- would offer one's credential to the other.
    id                 TEXT NOT NULL,
    -- credd | vault | oauth2: who holds the OAuth2 client registration,
    -- which is what actually distinguishes the three bootstrap mechanisms.
    -- Only oauth2 stores anything in connector_credentials.
    kind               TEXT NOT NULL,

    client_id          TEXT NOT NULL DEFAULT '',
    -- Sealed like idp_rsa_keys and upstream_refresh_tokens, so one KEK
    -- covers every long-lived secret rather than each growing its own
    -- scheme. client_secret_dek is the wrapped data key when the value is
    -- sealed (HTTP_API_KEK_FILE), NULL when it is stored in the clear.
    --
    -- This column is WRITE-ONLY as far as every API is concerned: it is
    -- never rendered, not masked and not by length. secret_updated_at is
    -- what the admin page shows instead, because "when did this last
    -- change" is the question an operator actually has.
    client_secret      BLOB,
    client_secret_dek  BLOB,
    secret_updated_at  TIMESTAMP,

    -- Empty for a builtin: the shipped definition supplies them, and an
    -- operator should not have to know a provider's endpoints. A site
    -- connector must supply both.
    authorization_url  TEXT NOT NULL DEFAULT '',
    token_url          TEXT NOT NULL DEFAULT '',

    -- Space- or comma-separated. Empty for a builtin means the shipped
    -- default, which is the narrowest scope that works -- for Drive that is
    -- drive.file, and in direct transfer mode scope width is blast radius,
    -- because the token sits on an execute node.
    scopes             TEXT NOT NULL DEFAULT '',

    -- Who may use it. EMPTY MEANS NOBODY, not everyone: a connector puts a
    -- consent screen in front of a user and carries a client registration,
    -- and a blank column must not offer that to the whole access point. An
    -- operator who means everyone writes "*".
    groups             TEXT NOT NULL DEFAULT '',

    -- spool | direct. spool by default: this server fetches the bytes and
    -- no third-party token reaches an execute node, and it needs nothing
    -- deployed anywhere.
    transfer           TEXT NOT NULL DEFAULT 'spool',

    enabled            BOOLEAN NOT NULL DEFAULT 1,
    created_at         TIMESTAMP NOT NULL,
    updated_at         TIMESTAMP NOT NULL,
    PRIMARY KEY (id)
);

-- What one user granted for one connector.
--
-- oauth2 kind only. A credd connector leaves its credential in the credd and
-- a vault connector leaves a Vault token there; neither keeps anything here,
-- which is why this table is keyed by connector rather than by kind.
CREATE TABLE connector_credentials (
    -- Our user, as the session names them. The same choice
    -- upstream_refresh_tokens makes and for the same reason: where a
    -- deployment maps identities this is the local account, and keying on
    -- the provider's name for the user would file a credential under
    -- something no later lookup holds.
    subject            TEXT NOT NULL,
    connector          TEXT NOT NULL,
    -- The provider's own name for the user, recorded so a credential filed
    -- against the wrong row can be noticed rather than quietly applying one
    -- person's access to another.
    provider_subject   TEXT NOT NULL DEFAULT '',

    refresh_token      BLOB NOT NULL,
    refresh_token_dek  BLOB,

    -- What the provider actually granted, which is not always what was
    -- asked for. Recorded for the same reason 0011 records it: a provider
    -- that withheld a scope looks exactly like one that was never asked
    -- until you have this.
    granted_scopes     TEXT NOT NULL DEFAULT '',

    obtained_at        TIMESTAMP NOT NULL,
    -- When the refresh was last exchanged successfully. The maintenance
    -- loop reads it to rate-limit itself: a server refreshing on a timer
    -- must not turn its user list into steady load on somebody else's
    -- identity provider.
    last_refreshed_at  TIMESTAMP,
    -- When a job or the Picker last used it. This is what lets a user be
    -- told their connection needs renewing BEFORE a job holds, and what
    -- answers the operator's question of whether anyone uses this at all.
    -- The credd sweeps by last use and cannot report; this can.
    last_used_at       TIMESTAMP,

    PRIMARY KEY (subject, connector)
);

-- Every read is either one user's grant or one connector's grants: the
-- maintenance loop walks what is due, revoke walks one connector, and the
-- admin page counts per connector.
CREATE INDEX idx_connector_credentials_connector
    ON connector_credentials (connector);
CREATE INDEX idx_connector_credentials_refresh
    ON connector_credentials (last_refreshed_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS idx_connector_credentials_refresh;
DROP INDEX IF EXISTS idx_connector_credentials_connector;
DROP TABLE connector_credentials;
DROP TABLE connectors;

-- +goose StatementEnd
