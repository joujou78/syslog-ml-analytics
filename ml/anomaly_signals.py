"""
Stateless anomaly signals -- the two that need history per device
(severity_spike, volume_spike) live in DeviceBaselineCache in consumer.py,
since they need a periodically-refreshed ClickHouse-backed baseline, not
just a pure function of one message.

An event's `anomaly_reasons` is the list of every signal below that fired
for it (empty list if none did); `is_anomaly` is just "was the list
non-empty", kept as a plain 0/1 so existing alert rules filtering on it
keep working unchanged. Tracking *which* signal fired, not just a single
flag, follows the same "always label confidence/reason, never just a bare
verdict" principle already used for resolution_method and vendor_source.
"""
import re

from labeling_rules import CATEGORY_RULES

ALWAYS_ANOMALOUS_SEVERITIES = {"emerg", "alert", "crit"}

# Reused, not duplicated: the same SECURITY rule the category classifier's
# weak-supervision already uses (see labeling_rules.py) -- tune it there,
# not here, so the two stay in sync.
_SECURITY_PATTERN: re.Pattern = next(pattern for category, pattern in CATEGORY_RULES if category == "SECURITY")


def is_always_severe(severity: str) -> bool:
    return (severity or "").lower() in ALWAYS_ANOMALOUS_SEVERITIES


def is_security_content(message: str) -> bool:
    return bool(_SECURITY_PATTERN.search(message or ""))
