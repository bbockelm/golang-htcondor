-- +goose Up
-- REST API request statistics, the same shape as mcp_tool_stats and
-- kept for the same reasons: flushed periodically and at shutdown so
-- the counters survive a restart.
--
-- A separate table rather than a kind column on the MCP one. The two
-- vocabularies differ -- an MCP call is ok/error/refused/unknown_tool,
-- a REST request is ok/denied/not_found/rate_limited/client_error/
-- error -- and the volumes differ by orders of magnitude, so sharing a
-- table would put every MCP query behind a scan of the web UI's
-- polling.
--
-- Stored VERBATIM: the real user name and the real client string, not
-- the bounded label values /metrics renders. This table is the durable
-- record and the one an operator queries directly; the Prometheus
-- label space is a projection of it, applied at scrape time.
--
-- One row per (endpoint, actor, client, outcome). The row is a
-- cumulative total, not an event log: an access point serving a busy
-- pool would otherwise write a row per request forever, and nothing
-- here needs per-request granularity -- the server's own HTTP logs
-- have that.
CREATE TABLE IF NOT EXISTS rest_endpoint_stats (
    -- "METHOD /route/template", e.g. "GET /api/v1/jobs/{id}". The
    -- method is part of the key because GET and DELETE on one path are
    -- different operations with different risk.
    endpoint             TEXT    NOT NULL,
    -- "actor" rather than "user", matching mcp_tool_stats: USER is a
    -- keyword in enough SQL dialects to be worth avoiding in a schema
    -- that may be read by other tools.
    actor                TEXT    NOT NULL,
    -- The web UI, an OAuth2 client id behind an "oauth:" prefix, an
    -- API key behind an "api key:" prefix, or a User-Agent product
    -- token. An id rather than a client's display name on purpose: a
    -- rename must not split a series in two.
    client               TEXT    NOT NULL,
    outcome              TEXT    NOT NULL,
    calls                INTEGER NOT NULL DEFAULT 0,
    duration_sum_seconds REAL    NOT NULL DEFAULT 0,
    -- JSON array of per-bucket counts, index-aligned with the server's
    -- histogram boundaries. Opaque to SQL on purpose: it backs the
    -- average and the percentile the admin page shows, and the
    -- aggregates an operator queries are the columns beside it. A
    -- boundary change makes an old array the wrong length, which the
    -- loader resizes rather than discarding the history over.
    buckets              TEXT    NOT NULL DEFAULT '[]',
    last_call_at         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (endpoint, actor, client, outcome)
);

-- The two orderings an operator actually asks for: "what is this user
-- doing" and "who calls this endpoint".
CREATE INDEX IF NOT EXISTS idx_rest_endpoint_stats_actor ON rest_endpoint_stats (actor, calls DESC);
CREATE INDEX IF NOT EXISTS idx_rest_endpoint_stats_endpoint ON rest_endpoint_stats (endpoint, calls DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_rest_endpoint_stats_endpoint;
DROP INDEX IF EXISTS idx_rest_endpoint_stats_actor;
DROP TABLE IF EXISTS rest_endpoint_stats;
