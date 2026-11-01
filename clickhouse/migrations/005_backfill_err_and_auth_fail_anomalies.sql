-- Retroactively applies two anomaly-detection fixes (see ml/anomaly_
-- signals.py and ml/labeling_rules.py for the code change, and the
-- user-requested Cisco trap-coverage catalog that confirmed both gaps)
-- to rows already in ClickHouse. Both signals are per-event/stateless
-- (severity or message text alone), computed once at insert time by
-- consumer.py and never revisited for a row already written -- the code
-- fix alone only changes newly-ingested events going forward, so this
-- one-off backfill applies the same corrected logic to the existing
-- backlog.
--
-- Guarded by `NOT has(anomaly_reasons, '<reason>')` on both statements,
-- same idiom ml/template_mix_anomaly.py's own retroactive tagging
-- already uses -- safe to re-run; a second run is a no-op for rows
-- already tagged.
--
-- These are heavier than the schema-only migrations before this one: an
-- ALTER TABLE UPDATE rewrites every affected part, and `events` has no
-- TTL (full history, partitioned by day). Check impact and current
-- mutation load before running -- see the README/this migration's own
-- commit message for the exact dry-run queries -- and prefer running
-- during a quieter period if the host is already under sustained
-- ClickHouse load.
--
-- Apply on net-flow with:
--   clickhouse-client --multiquery < clickhouse/migrations/005_backfill_err_and_auth_fail_anomalies.sql

-- 1) "err" (severity rank 3, see ml/labeling_rules.py's SEVERITY_ORDER)
--    is now always-anomalous (ALWAYS_ANOMALOUS_SEVERITIES in ml/anomaly_
--    signals.py). Confirmed gaps this closes: %STORM_CONTROL-3-FILTERED
--    (66,312 rows, was only 14.6% flagged) and %ENVM-3-FAN_FAILED_ERR
--    (5,393 rows, was only 1% flagged), among others at this severity
--    across every vendor, not just the Cisco-style messages the catalog
--    happened to parse mnemonics from.
ALTER TABLE syslog_ml.events
UPDATE
    anomaly_reasons = arrayConcat(anomaly_reasons, ['always_severe']),
    is_anomaly = 1
WHERE severity = 'err'
  AND NOT has(anomaly_reasons, 'always_severe');

-- 2) The SECURITY category pattern (ml/labeling_rules.py, shared with
--    ml/anomaly_signals.py's is_security_content) now also matches
--    authentication-failure wording. Confirmed gap this closes: %SYS-5-
--    PRIV_AUTH_FAIL (3,135 rows, was only 14.2% flagged), plus %DOT1X-5-
--    FAIL and %SEC_LOGIN-4-LOGIN_FAILED's own message text.
--
-- Expressed as two separate match() calls rather than the single
-- alternation labeling_rules.py uses -- ClickHouse's match() is RE2, not
-- Python's re module, and while both patterns are simple enough to be
-- equivalent, verifying each clause independently here doesn't rely on
-- that assumption holding across engines. (?i) makes each case-
-- insensitive, matching re.I on the Python side.
ALTER TABLE syslog_ml.events
UPDATE
    anomaly_reasons = arrayConcat(anomaly_reasons, ['security_content']),
    is_anomaly = 1
WHERE (match(message, '(?i)authentication.{0,40}failed') OR match(message, '(?i)login\\s+failed'))
  AND NOT has(anomaly_reasons, 'security_content');
