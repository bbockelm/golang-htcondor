-- +goose Up
-- +goose StatementBegin

-- A reservation has an owner as well as a project.
--
-- The project is what a job carries to claim a seat; the owner is the
-- person the capacity is held for -- the teacher of the class, not the
-- students. The two are separate because HTCondor's own persistent
-- claims hang off a user record and are matched against both: a claim
-- held for an owner serves that owner's jobs and any job of the owner's
-- project, which is exactly a class and its students.
--
-- Empty on rows written before this, which the controller reads as
-- "project only" and the admin page prompts to fill in. Defaulting it to
-- anything else would attribute somebody's capacity to a person who
-- never asked for it.
ALTER TABLE reservations ADD COLUMN owner TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE reservations DROP COLUMN owner;

-- +goose StatementEnd
