-- Adds the vendor_source column to the already-deployed `events` table, so
-- passive (message-format) vendor guesses can be told apart from an
-- SNMP-verified vendor. See ../init.sql's comment on this column, and
-- ml/vendor_signatures.py for the detection logic.
--
-- Apply on net-flow with:
--   clickhouse-client --multiquery < clickhouse/migrations/002_vendor_source.sql

ALTER TABLE syslog_ml.events
    ADD COLUMN IF NOT EXISTS vendor_source LowCardinality(String) DEFAULT 'unknown' AFTER vendor;
