-- +goose Up
-- +goose StatementBegin

-- A watch for a live job state (running, held, a custom in-queue
-- condition) can only be satisfied while the job is in the queue. When
-- every job it selects leaves without that state ever being observed,
-- the watch is not waiting for something yet to happen -- it is waiting
-- for something that can no longer happen.
--
-- Such a watch fires, so whoever is blocked on it is released, and this
-- flag is what keeps that firing honest: it marks the answer as "the
-- state never occurred", as against the ordinary firing that means it
-- did. Persisted for the same reason as `undetermined`: check_watches
-- reloads from this table, so a verdict held only in memory would be
-- lost before anyone read it.
ALTER TABLE job_watches ADD COLUMN unsatisfiable BOOLEAN NOT NULL DEFAULT 0;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE job_watches DROP COLUMN unsatisfiable;
-- +goose StatementEnd
