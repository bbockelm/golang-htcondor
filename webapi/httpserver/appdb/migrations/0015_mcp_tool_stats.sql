-- +goose Up
-- MCP tool-call statistics, flushed periodically and at shutdown so the
-- counters survive a restart.
--
-- Stored VERBATIM: the real user name and the real client string, not
-- the bounded label values /metrics renders. This table is the durable
-- record and the one an operator queries directly; the Prometheus label
-- space is a projection of it, applied at scrape time.
--
-- One row per (tool, actor, client, outcome). The row is a cumulative
-- total, not an event log: an access point serving a busy pool would
-- otherwise write a row per tool call forever, and nothing here needs
-- per-call granularity -- the server's own MCP logs have that, with a
-- trace id.
CREATE TABLE IF NOT EXISTS mcp_tool_stats (
    tool                 TEXT    NOT NULL,
    -- "actor" rather than "user": it matches the MCP log field of the
    -- same meaning, and USER is a keyword in enough SQL dialects to be
    -- worth avoiding in a schema that may be read by other tools.
    actor                TEXT    NOT NULL,
    client               TEXT    NOT NULL,
    outcome              TEXT    NOT NULL,
    calls                INTEGER NOT NULL DEFAULT 0,
    duration_sum_seconds REAL    NOT NULL DEFAULT 0,
    -- JSON array of per-bucket counts, index-aligned with the server's
    -- histogram boundaries. Opaque to SQL on purpose: it exists only to
    -- restore the Prometheus histogram exactly across a restart, and
    -- the aggregates an operator queries are the columns beside it.
    -- A boundary change makes an old array the wrong length, which the
    -- loader resizes rather than discarding the history over.
    buckets              TEXT    NOT NULL DEFAULT '[]',
    last_call_at         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tool, actor, client, outcome)
);

-- The two orderings an operator actually asks for: "what is this user
-- doing" and "who uses this tool".
CREATE INDEX IF NOT EXISTS idx_mcp_tool_stats_actor ON mcp_tool_stats (actor, calls DESC);
CREATE INDEX IF NOT EXISTS idx_mcp_tool_stats_tool ON mcp_tool_stats (tool, calls DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_mcp_tool_stats_tool;
DROP INDEX IF EXISTS idx_mcp_tool_stats_actor;
DROP TABLE IF EXISTS mcp_tool_stats;
