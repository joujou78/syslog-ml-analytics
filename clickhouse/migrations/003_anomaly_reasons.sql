-- Adds anomaly_reasons to the already-deployed `events` table -- which
-- signal(s) triggered is_anomaly (rare_template | always_severe |
-- severity_spike | security_content | volume_spike), not just the bare
-- flag. See ../init.sql's comment on this column and
-- ml/anomaly_signals.py / consumer.py's DeviceBaselineCache for the logic.
--
-- Apply on net-flow with:
--   clickhouse-client --multiquery < clickhouse/migrations/003_anomaly_reasons.sql

ALTER TABLE syslog_ml.events
    ADD COLUMN IF NOT EXISTS anomaly_reasons Array(LowCardinality(String)) DEFAULT [] AFTER is_anomaly;
