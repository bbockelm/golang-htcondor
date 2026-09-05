-- +goose Up
-- +goose StatementBegin

-- Job watches are registered interests: "tell me when cluster 42
-- finishes", "tell me if anything goes on hold". A caller registers
-- one, stops asking, and comes back later for the answer.
--
-- They live in SQL rather than a map because the caller is usually an
-- LLM agent, and an agent's absence is the normal case, not the
-- exception. It may come back in seconds, in hours, or as a different
-- session; the daemon may restart in between. A watch that did not
-- survive a restart would fail in the worst way available -- silently,
-- and only for the agents that waited longest.

CREATE TABLE job_watches (
    -- Opaque id handed back to the caller. Not the rowid: a caller may
    -- hold it across restarts and it appears in tool output.
    id TEXT PRIMARY KEY,
    -- The identity that registered it. Every read is filtered on this
    -- column: the evaluator queries jobs as the daemon, with none of
    -- the schedd's per-caller ACL behind it, so the owner recorded here
    -- is the only thing confining a watch to its registrant.
    owner TEXT NOT NULL,
    -- Caller-supplied name, echoed back so an agent holding several
    -- watches can tell them apart without decoding the constraint.
    label TEXT NOT NULL DEFAULT '',

    -- ClassAd expression selecting which jobs are in scope. Stored as
    -- written so it can be shown back to the caller unchanged; it is
    -- re-parsed on load, and a row that no longer parses is a load
    -- error rather than a watch that silently matches nothing.
    constraint_expr TEXT NOT NULL,
    -- One of the closed event vocabulary (done, succeeded, failed,
    -- held, running, custom). Text rather than an integer so a stored
    -- row is readable, and so an unknown value from a future version
    -- fails loudly on load instead of aliasing onto a valid event.
    event TEXT NOT NULL,
    -- The ClassAd expression for event='custom'; empty otherwise.
    condition_expr TEXT NOT NULL DEFAULT '',
    -- 'any' or 'all'.
    mode TEXT NOT NULL,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Every job this watch has ever selected, as a JSON array of
    -- {cluster_id, proc_id}. This is the watch's memory and it is
    -- load-bearing, not a cache: a finished job is DESTROYED from the
    -- queue by the schedd, so "it was here and now it is gone" is the
    -- primary evidence that terminal events have happened. Lose this
    -- across a restart and a job that finished during the outage is
    -- neither tracked nor yet in history, and the watch misses it
    -- permanently.
    tracked_json TEXT NOT NULL DEFAULT '[]',

    -- When every tracked job was first seen to have left the queue with
    -- its outcome unexplained. It starts the grace period after which a
    -- succeeded/failed watch stops waiting for a history row that may
    -- never come and reports what it does know. NULL while any job is
    -- running, or while outcomes are resolving normally.
    all_ended_at TIMESTAMP,

    -- When the watch was first satisfied, and what satisfied it.
    -- fired_at NULL means it has not fired.
    fired_at TIMESTAMP,
    -- Set when the watch fired without being able to establish the
    -- outcome: the jobs are known to have ended and nothing could say
    -- how. The answer is still worth delivering -- silence is the one
    -- result an agent misreads, because it looks like "still running".
    undetermined BOOLEAN NOT NULL DEFAULT 0,
    -- JSON array of the matching jobs, capped -- a watch over a
    -- 100k-job cluster summarizes rather than storing the cluster.
    matched_json TEXT NOT NULL DEFAULT '[]',
    -- The true count behind that capped list, so "everything failed"
    -- does not lose the "everything".
    matched_total INTEGER NOT NULL DEFAULT 0,

    -- When a caller last read the outcome. Recorded rather than acted
    -- on: a fired watch stays readable so a later session, or the same
    -- one after losing its context, can still find out what happened.
    delivered_at TIMESTAMP,

    -- When this watch stops being evaluated and becomes eligible for
    -- pruning. Every watch has one: an agent that registers a watch and
    -- never returns is the common case, and without an expiry the
    -- evaluator's work grows without bound for answers nobody will read.
    expires_at TIMESTAMP NOT NULL
);

-- The evaluator's sweep: everything still live, oldest first.
CREATE INDEX job_watches_live ON job_watches(expires_at) WHERE fired_at IS NULL;
-- The caller's "what happened while I was gone", which is always
-- scoped to one owner.
CREATE INDEX job_watches_owner ON job_watches(owner, fired_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS job_watches_owner;
DROP INDEX IF EXISTS job_watches_live;
DROP TABLE IF EXISTS job_watches;

-- +goose StatementEnd
