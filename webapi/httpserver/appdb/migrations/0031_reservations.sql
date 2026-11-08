-- +goose Up
-- +goose StatementBegin

-- A reservation holds cores for a project at recurring times: a class, a
-- demo, anything with a timetable. The controller reads these rows, works
-- out which machines to hold back, and frees the seats by the bell.
CREATE TABLE reservations (
    id          TEXT      PRIMARY KEY,
    -- ProjectName a job must carry to take a seat. Deliberately not part
    -- of any machine attribute name: the startd cannot forget an
    -- attribute, so per-reservation names would accumulate forever.
    project     TEXT      NOT NULL,
    -- The submit file describing one seat. Rendered through the real
    -- submit machinery to get the seat's shape and Requirements.
    submit      TEXT      NOT NULL,
    -- Seats held during a window; also the cap on how many the project
    -- may occupy at once. Standing is kept between windows.
    seats       INTEGER   NOT NULL,
    standing    INTEGER   NOT NULL DEFAULT 0,
    -- All three in seconds. Lead is how far ahead the controller starts
    -- holding cores back; six hours is where the measured benefit
    -- saturates. Hold is how long unclaimed seats stay reserved after
    -- the window opens.
    duration_s  INTEGER   NOT NULL,
    lead_s      INTEGER   NOT NULL,
    hold_s      INTEGER   NOT NULL DEFAULT 0,
    -- Five-field cron, read in the named IANA zone so a class at 14:00
    -- stays at 14:00 when the UTC offset changes under it.
    schedule    TEXT      NOT NULL,
    timezone    TEXT      NOT NULL DEFAULT 'Local',
    enabled     INTEGER   NOT NULL DEFAULT 1,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- The controller sweeps the enabled rows every tick.
CREATE INDEX reservations_enabled ON reservations (enabled);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX reservations_enabled;
DROP TABLE reservations;

-- +goose StatementEnd
