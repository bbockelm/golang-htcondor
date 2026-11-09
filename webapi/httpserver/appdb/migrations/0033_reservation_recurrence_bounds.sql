-- +goose Up
-- +goose StatementBegin

-- A recurrence can start and stop.
--
-- A cron expression says when a reservation happens but not for how
-- long it goes on, so a class booked for one term would hold capacity
-- every Monday for ever. These three bound it: no occurrence begins
-- before starts_unix, none begins at or after ends_unix, and
-- occurrences counts scheduled starts from starts_unix -- which is not
-- the same as windows, since occurrences close together are merged into
-- one hold.
--
-- Unix seconds rather than a timestamp because the controller compares
-- instants, and zero rather than NULL because zero is already the Go
-- zero time's role here: an epoch reservation is not a thing anyone
-- books, and a NOT NULL default keeps every row written before this one
-- unbounded, which is what it was.
--
-- An end date and a count of occurrences are two ways of saying the same
-- thing and the model rejects both at once, so only one of these two
-- columns is ever set.
ALTER TABLE reservations ADD COLUMN starts_unix  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE reservations ADD COLUMN ends_unix    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE reservations ADD COLUMN occurrences  INTEGER NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE reservations DROP COLUMN starts_unix;
ALTER TABLE reservations DROP COLUMN ends_unix;
ALTER TABLE reservations DROP COLUMN occurrences;

-- +goose StatementEnd
