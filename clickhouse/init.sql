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
    source_ip           String,             -- effective device identity: substituted with the origin IP embedded in reported_hostname for events relayed through a RELAY_SOURCE_IPS entry (see ml/consumer.py's resolve_identity) -- not always the raw network-level sender
    hostname            String,             -- best-known identity: see resolution_method
    reported_hostname   String,             -- raw hostname string the device put in the syslog message, unverified
    relayed_via         String DEFAULT '',  -- if non-empty, the relay's network-level source_ip this event actually arrived from (source_ip above is the origin device it was relayed for, not the relay itself)
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
    anomaly_reasons     Array(LowCardinality(String)) DEFAULT [], -- which signal(s) fired: rare_template | always_severe | severity_spike | security_content | volume_spike | unusual_template_mix -- see ml/anomaly_signals.py, consumer.py's DeviceBaselineCache, and ml/template_mix_anomaly.py
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
-- No TTL: retained indefinitely by explicit choice. Disk usage on
-- whatever host runs ClickHouse grows without bound as long as the
-- pipeline runs -- monitor free disk yourself; nothing here enforces a
-- ceiling. If retention ever needs bounding again, add back
-- `TTL toDateTime(event_time) + INTERVAL <n> DAY` (existing rows aren't
-- retroactively deleted just by having briefly had a shorter TTL earlier
-- and then removing it -- only while a TTL clause is actually in effect
-- does ClickHouse's background merge process drop expired parts).
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

-- Windowed template-mix anomaly scores (see ml/template_mix_anomaly.py).
-- Distinct from `events.anomaly_reasons` (per-event, evaluated inline as
-- each message arrives): this is a per-(device, time window) signal that
-- can only be judged once a window's worth of data exists, so it's
-- computed by a periodic batch job, not at insert time. One row per
-- window per device, scored exactly once (the detector's own checkpoint
-- ensures a window is never re-evaluated once scored, even as its
-- device's model improves with more history later -- deliberately, to
-- avoid re-scoring and re-writing a device's entire history every cycle).
-- ReplacingMergeTree(scored_at) exists only to dedupe the rare case where
-- a checkpoint-load failure after a restart causes a brief backfill
-- overlap, not for routine ongoing rescoring.
CREATE TABLE IF NOT EXISTS syslog_ml.device_window_anomalies
(
    window_start        DateTime,
    source_ip           String,
    vendor              LowCardinality(String) DEFAULT 'unknown',
    model_scope         LowCardinality(String), -- 'device' | 'vendor' -- which model actually scored this window (see README's "hybrid" note)
    anomaly_score        Float32,                -- IsolationForest decision_function output; more negative = more anomalous
    is_anomaly           UInt8,
    event_count          UInt32,                 -- events observed in this device's window, for context alongside the score
    scored_at            DateTime64(3) DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(scored_at)
PARTITION BY toYYYYMMDD(window_start)
ORDER BY (source_ip, window_start)
-- No TTL, same choice and same caveat as `events` above -- kept
-- consistent so an old flagged window's score/model_scope context doesn't
-- disappear while the event it tagged (unusual_template_mix) is retained
-- forever.
SETTINGS index_granularity = 8192;
