-- +goose Up
-- +goose StatementBegin

-- The GECOS index inverted: subject -> local account.
--
-- Rebuilding it requires enumerating the whole account database, and a
-- container cannot do that for the first minutes of its life. The daemon
-- and its SSSD sidecar start together, and SSSD serves no enumeration
-- until its own first pass over the directory finishes -- measured at
-- around three and a half minutes on the directory this was written for.
-- Every login arriving in that window was refused as corresponding to no
-- local account.
--
-- Keeping the last complete index here means a restarted daemon can
-- answer immediately from what it knew before, instead of from nothing.
--
-- This is a CACHE, never an authority. Restoring it does not skip any
-- check: a hit is still confirmed by name against the live account
-- database before it is believed, so an entry that has since changed or
-- disappeared cannot let anybody in. The row may be arbitrarily stale and
-- that is handled by the ordinary TTL, which the stored build time feeds.
--
-- Only a COMPLETE index is written. A partial one is missing accounts by
-- definition, so its ambiguity counts cannot be trusted, and persisting
-- it would let an outage outlive itself.
--
-- Contents are account names and GECOS fields -- the same thing getent
-- passwd shows any user on the access point -- so they are stored as
-- they are rather than through the envelope sealer.
CREATE TABLE identity_index (
    -- One row. The index is process-wide, not per-user.
    id INTEGER PRIMARY KEY CHECK (id = 1),
    -- The serialised idmap.Snapshot.
    snapshot TEXT NOT NULL,
    -- When the index was BUILT, not when it was written here. A restored
    -- index has to age from the former or it looks fresher than it is and
    -- suppresses the rebuild that should correct it.
    built_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE identity_index;
-- +goose StatementEnd
