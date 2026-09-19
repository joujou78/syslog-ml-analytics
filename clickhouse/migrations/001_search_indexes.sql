-- Adds skip indexes to the already-deployed `events` table so free-text /
-- program / category / source-IP search stays fast without a second
-- database. See the comment above these same indexes in ../init.sql for
-- why each one exists -- this file only exists because ALTER is how you
-- add them to a table that's already holding data (a fresh install picks
-- them up straight from init.sql, so this file is a no-op for it).
--
-- Apply on net-flow with:
--   clickhouse-client --multiquery < clickhouse/migrations/001_search_indexes.sql
-- (add --user/--password if your ClickHouse install needs them)

ALTER TABLE syslog_ml.events
    ADD INDEX IF NOT EXISTS idx_message message TYPE tokenbf_v1(4096, 3, 0) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS idx_program program TYPE set(0) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS idx_category predicted_category TYPE set(0) GRANULARITY 4,
    ADD INDEX IF NOT EXISTS idx_source_ip source_ip TYPE bloom_filter() GRANULARITY 4;

-- Indexes only apply to parts written after they're added unless you
-- backfill them across existing data with MATERIALIZE INDEX. On a table
-- that's still small (test traffic so far), this is cheap; skip it if
-- `events` has grown very large and you'd rather let TTL age old,
-- unindexed parts out naturally over the 90-day retention window.
ALTER TABLE syslog_ml.events MATERIALIZE INDEX idx_message;
ALTER TABLE syslog_ml.events MATERIALIZE INDEX idx_program;
ALTER TABLE syslog_ml.events MATERIALIZE INDEX idx_category;
ALTER TABLE syslog_ml.events MATERIALIZE INDEX idx_source_ip;
