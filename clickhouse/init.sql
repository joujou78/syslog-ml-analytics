CREATE DATABASE IF NOT EXISTS syslog_ml;

-- One row per known device IP. ReplacingMergeTree so re-resolving an IP
-- (SNMP re-poll, or a syslog-reported hostname arriving later) just
-- overwrites the previous row on the next merge, keyed by ip.
CREATE TABLE IF NOT EXISTS syslog_ml.device_inventory
(
    ip                  String,
    hostname            String,
    vendor              LowCardinality(String) DEFAULT 'unknown',
    model               String DEFAULT '',
    resolution_method   LowCardinality(String),  -- 'snmp' | 'syslog_reported' | 'unresolved'
    first_seen          DateTime64(3),
    last_resolved       DateTime64(3)
)
ENGINE = ReplacingMergeTree(last_resolved)
ORDER BY ip;

CREATE TABLE IF NOT EXISTS syslog_ml.events
(
    event_time          DateTime64(3),
    received_at         DateTime64(3) DEFAULT now64(3),
    source_ip           String,
    hostname            String,             -- best-known identity: see resolution_method
    reported_hostname   String,             -- raw hostname string the device put in the syslog message, unverified
    vendor              LowCardinality(String) DEFAULT 'unknown',
    vendor_source       LowCardinality(String) DEFAULT 'unknown', -- 'snmp' (verified) | 'passive' (guessed from message format, see ml/vendor_signatures.py) | 'unknown'
    model               String DEFAULT '',
    resolution_method   LowCardinality(String),
    facility            LowCardinality(String),
    severity            LowCardinality(String),
    severity_num        UInt8,
    program             LowCardinality(String),
    pid                 Nullable(UInt32),
    message             String,
    template_id         String,
    template             String,
    predicted_category  LowCardinality(String),
    predicted_confidence Float32,
    is_anomaly          UInt8 DEFAULT 0,
    raw                 String,

    -- Secondary (skip) indexes: `events` is a *columnar* store ordered by
    -- (event_time, hostname, severity), so a query that filters on other
    -- columns without a time range -- e.g. the planned log-search UI
    -- filtering by program or free-text keyword -- would otherwise have to
    -- scan every granule. These let ClickHouse skip granules that can't
    -- match, without a second database or a separate search engine.
    INDEX idx_message message TYPE tokenbf_v1(4096, 3, 0) GRANULARITY 4,
    INDEX idx_program program TYPE set(0) GRANULARITY 4,
    INDEX idx_category predicted_category TYPE set(0) GRANULARITY 4,
    INDEX idx_source_ip source_ip TYPE bloom_filter() GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (event_time, hostname, severity)
TTL toDateTime(event_time) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Pre-aggregated per-minute rollup so Grafana panels stay fast even once
-- `events` holds hundreds of millions of rows.
CREATE MATERIALIZED VIEW IF NOT EXISTS syslog_ml.events_by_minute
ENGINE = SummingMergeTree
PARTITION BY toYYYYMMDD(minute)
ORDER BY (minute, hostname, vendor, severity, predicted_category)
AS
SELECT
    toStartOfMinute(event_time) AS minute,
    hostname,
    vendor,
    severity,
    predicted_category,
    count()                      AS event_count,
    sum(is_anomaly)              AS anomaly_count,
    sum(resolution_method = 'unresolved') AS unresolved_count
FROM syslog_ml.events
GROUP BY minute, hostname, vendor, severity, predicted_category;
