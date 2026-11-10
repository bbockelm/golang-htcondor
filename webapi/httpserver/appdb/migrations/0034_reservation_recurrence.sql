-- +goose Up
-- +goose StatementBegin

-- A reservation can be timed by a structured recurrence, or by nothing
-- at all.
--
-- The cron expression in `schedule` cannot say "every other Tuesday" or
-- "the last Friday of the month": its day-of-week field is a set of
-- weekday indices, so a step of two on it means every other weekday
-- index rather than every other week, and it has no way to count
-- weekdays within a month. Those two requests are why there is a second
-- representation rather than a longer cron parser.
--
-- schedule_kind is what decides which one is read -- 'cron' for the
-- expression, 'recurrence' for the JSON, 'always' for a reservation
-- that holds its capacity continuously and has no windows. Defaulting
-- it to 'cron' is what keeps every row written before this migration
-- meaning exactly what it meant.
--
-- The recurrence is stored as JSON rather than as a column per field.
-- It is read and written whole, never queried against -- the controller
-- enumerates occurrences in Go, and no query asks which reservations
-- fall on a Tuesday -- so columns would buy nothing and cost a
-- migration for every field the form grows. The time zone stays in
-- `timezone`, shared with the cron form: one reservation has one zone,
-- and two places to say it is one place for them to disagree.
--
-- An always-on reservation leaves both `schedule` and `recurrence`
-- empty. `schedule` is NOT NULL with no default, so it is written as
-- the empty string rather than left out, and nothing parses it for a
-- kind that does not read it.
ALTER TABLE reservations ADD COLUMN schedule_kind TEXT NOT NULL DEFAULT 'cron';
ALTER TABLE reservations ADD COLUMN recurrence    TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE reservations DROP COLUMN schedule_kind;
ALTER TABLE reservations DROP COLUMN recurrence;

-- +goose StatementEnd
