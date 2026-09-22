-- Adds relayed_via to the already-deployed `events` table -- for events
-- whose source_ip has been substituted with an origin device IP embedded
-- in reported_hostname (see ml/consumer.py's RELAY_SOURCE_IPS and
-- resolve_identity), this holds the relay's own network-level source_ip
-- that the event actually arrived from, so that substitution stays
-- traceable instead of silently discarding the network-level sender.
-- See ../init.sql's comment on this column.
--
-- Apply on net-flow with:
--   clickhouse-client --multiquery < clickhouse/migrations/004_relayed_via.sql

ALTER TABLE syslog_ml.events
    ADD COLUMN IF NOT EXISTS relayed_via String DEFAULT '' AFTER reported_hostname;
