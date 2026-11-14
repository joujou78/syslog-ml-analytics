-- Confirmed live on net-flow as a real contributor to the disk-exhaustion
-- incident that blocked the Log Assistant indexer (see ml/log_assistant_
-- indexer.py's _is_systemic_failure and rsyslog/syslog-ml-raw.logrotate
-- for the other two fixes from that same incident): ClickHouse's own
-- internal diagnostic tables had NO retention configured at all (no TTL
-- clause in any of their `SHOW CREATE TABLE` output) and had grown to
-- ~6.84 GiB combined since this deployment's own install date -- more
-- than 8x the actual application data in syslog_ml.events (854 MiB at
-- the time this was found). These tables are pure operational/debugging
-- telemetry (every query ClickHouse itself has ever run, query-execution
-- traces, part-merge history, periodic internal metric snapshots) with
-- no ongoing value past a recent window -- nothing in this project ever
-- queries them for anything functional.
--
-- These are regular MergeTree tables under the hood (confirmed via
-- `SHOW CREATE TABLE system.query_log`), so a normal `ALTER TABLE ...
-- MODIFY TTL` applies to them exactly like any user table -- takes
-- effect immediately (ClickHouse's background merge process drops
-- expired parts on its own schedule, no manual OPTIMIZE needed, though
-- one is a safe way to force it sooner -- see this migration's own
-- follow-up comment below). 7 days is a generous window for recent
-- debugging while keeping size bounded; adjust if your own troubleshooting
-- needs a longer lookback.
--
-- Safe to re-run: MODIFY TTL is idempotent (re-applying the same TTL
-- expression is a no-op).
ALTER TABLE system.query_log MODIFY TTL event_date + INTERVAL 7 DAY;
ALTER TABLE system.trace_log MODIFY TTL event_date + INTERVAL 7 DAY;
ALTER TABLE system.part_log MODIFY TTL event_date + INTERVAL 7 DAY;
ALTER TABLE system.metric_log MODIFY TTL event_date + INTERVAL 7 DAY;
ALTER TABLE system.asynchronous_metric_log MODIFY TTL event_date + INTERVAL 7 DAY;
ALTER TABLE system.query_views_log MODIFY TTL event_date + INTERVAL 7 DAY;

-- MODIFY TTL only marks existing parts for future cleanup on their own
-- merge schedule -- it does not retroactively shrink what's already on
-- disk today. To reclaim the space immediately (confirmed live: this
-- migration's TTL alone doesn't free anything until ClickHouse gets
-- around to merging), force it per table, e.g.:
--   OPTIMIZE TABLE system.query_log FINAL;
--   OPTIMIZE TABLE system.trace_log FINAL;
--   OPTIMIZE TABLE system.part_log FINAL;
--   OPTIMIZE TABLE system.metric_log FINAL;
--   OPTIMIZE TABLE system.asynchronous_metric_log FINAL;
--   OPTIMIZE TABLE system.query_views_log FINAL;
-- Not included as unconditional statements in this migration -- an
-- OPTIMIZE ... FINAL is a heavier, synchronous rewrite of the whole
-- table, worth running by hand when there's headroom to do so rather
-- than as a blind, always-run step.
