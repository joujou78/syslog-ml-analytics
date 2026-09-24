"""
Windowed template-mix anomaly detection (runs inside the classifier's main
loop, see consumer.py).

Every other anomaly signal in this pipeline (rare_template, always_severe,
security_content, severity_spike, volume_spike) is evaluated per-event, at
insert time, using an already-computed baseline. This one is different: it
asks "does this device's *mix* of Drain3 templates over the last few
minutes look like its normal mix, or has the distribution shifted?" -- a
question that can only be answered once a window's worth of data exists,
so it's inherently a periodic batch job, not something to check inline as
each message arrives.

Approach (same shape as loglizer's classic log-anomaly-detection method,
adapted to a live per-device setting instead of an offline benchmark):
  1. Bucket recent events into fixed-size time windows per device.
  2. For each window, build a feature vector = count of each of that
     device's top-K most frequent templates, plus one "other" bucket for
     everything else -- bounded dimensionality even as new Drain3
     templates keep appearing over time.
  3. Fit an IsolationForest per device on its own window history, and
     separately a per-vendor IsolationForest pooled across every device of
     that vendor (see TemplateMixAnomalyDetector's docstring for why: a
     hybrid so low-traffic devices that never accumulate enough history of
     their own still get scored against *something* meaningful).
  4. Score each newly-completed window against whichever model applies.

Flagged windows are written to syslog_ml.device_window_anomalies (a
per-window view -- see clickhouse/init.sql), AND, since that alone
wouldn't integrate with the existing per-event anomaly_reasons/is_anomaly
columns that Log Search and Alerts already filter on, a targeted
ALTER TABLE ... UPDATE retroactively tags just that device's rows within
that specific window. This mutation only ever fires for windows actually
flagged anomalous (expected to be a small fraction of all windows), never
for the (much larger) common case of a normal window, so it stays cheap
in practice despite ClickHouse mutations being relatively heavy in
general.
"""
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import numpy as np
from sklearn.ensemble import IsolationForest

log = logging.getLogger("template_mix_anomaly")

WINDOW_MINUTES = int(os.environ.get("TEMPLATE_MIX_WINDOW_MINUTES", "5"))
LOOKBACK_DAYS = int(os.environ.get("TEMPLATE_MIX_LOOKBACK_DAYS", "7"))
REFRESH_SECONDS = float(os.environ.get("TEMPLATE_MIX_REFRESH_SECONDS", "900"))
TOP_K_TEMPLATES = int(os.environ.get("TEMPLATE_MIX_TOP_K_TEMPLATES", "50"))
# Below this many of its own windows, a device isn't scored against its own
# model -- not enough history yet to know what "normal" looks like for it
# specifically. It falls back to its vendor's pooled model instead, if that
# has enough data; otherwise it just isn't scored at all this cycle.
MIN_WINDOWS_FOR_DEVICE = int(os.environ.get("TEMPLATE_MIX_MIN_WINDOWS_FOR_DEVICE", "30"))
MIN_WINDOWS_FOR_VENDOR = int(os.environ.get("TEMPLATE_MIX_MIN_WINDOWS_FOR_VENDOR", "30"))
# IsolationForest's contamination="auto" sets its decision threshold from a
# fixed formula in the original paper, not from an estimate of this data's
# actual anomaly rate -- verified empirically here to over-flag by 20-30%
# on realistic-noise window data, far too high for a signal meant to be
# rare. An explicit low value is the conventional choice for genuinely rare
# anomalies and matches observed behavior much better in testing.
CONTAMINATION = float(os.environ.get("TEMPLATE_MIX_CONTAMINATION", "0.01"))

_INSERT_COLUMNS = ["window_start", "source_ip", "vendor", "model_scope", "anomaly_score", "is_anomaly", "event_count"]


def _window_floor(dt: datetime) -> datetime:
    epoch = dt.replace(tzinfo=None)
    minutes = (epoch.minute // WINDOW_MINUTES) * WINDOW_MINUTES
    return epoch.replace(minute=minutes, second=0, microsecond=0)


def _vectorize(window_counts: dict[str, int], top_k: list[str]) -> list[float]:
    """window_counts: template_id -> count for one window. Projects it into
    the fixed [top_k[0]_share, ..., top_k[-1]_share, other_share] shape --
    each template's SHARE of the window's total events, not its raw count.

    Raw counts would conflate volume with mix: the vendor-pooled fallback
    model in particular is trained across devices whose overall traffic
    volume can differ by orders of magnitude, so a low-traffic device
    would look "anomalous" against a model shaped by a high-traffic
    device's much larger raw numbers on every single window, even when
    its own proportional mix hasn't changed at all. Volume shifts are
    already a separate, dedicated signal (volume_spike in
    DeviceBaselineCache) -- this one should only fire on a genuine change
    in *what* a device logs, not *how much*.
    """
    top_k_set = set(top_k)
    total = sum(window_counts.values())
    if total == 0:
        return [0.0] * (len(top_k) + 1)
    vector = [window_counts.get(t, 0) / total for t in top_k]
    other = sum(count for template, count in window_counts.items() if template not in top_k_set)
    vector.append(other / total)
    return vector


def _top_k_templates(samples: list[dict[str, int]], k: int) -> list[str]:
    totals: dict[str, int] = defaultdict(int)
    for window_counts in samples:
        for template, count in window_counts.items():
            totals[template] += count
    return [t for t, _ in sorted(totals.items(), key=lambda item: item[1], reverse=True)[:k]]


class TemplateMixAnomalyDetector:
    def __init__(self, client):
        self.client = client
        self._last_refresh = 0.0
        # source_ip -> latest window_start already scored, so a restart or
        # an occasionally-delayed cycle resumes from where it left off
        # instead of either re-scoring everything or leaving a gap.
        self._last_scored: dict[str, datetime] = {}
        self._loaded_last_scored = False

    def _load_last_scored(self):
        try:
            result = self.client.query(
                "SELECT source_ip, max(window_start) FROM syslog_ml.device_window_anomalies GROUP BY source_ip"
            )
            self._last_scored = {row[0]: row[1] for row in result.result_rows}
            log.info("Loaded prior scoring checkpoint for %d device(s)", len(self._last_scored))
        except Exception:
            log.exception("Could not load prior template-mix scoring checkpoint, starting from a full backfill")
        self._loaded_last_scored = True

    def refresh_if_stale(self):
        if not self._loaded_last_scored:
            self._load_last_scored()
        if time.monotonic() - self._last_refresh < REFRESH_SECONDS:
            return
        try:
            self._run_cycle()
        except Exception:
            log.exception("Template-mix anomaly cycle failed, will retry next cycle")
        self._last_refresh = time.monotonic()

    def _run_cycle(self):
        now = datetime.now(timezone.utc)
        current_window_start = _window_floor(now)  # still filling -- excluded, not yet complete

        result = self.client.query(f"""
            SELECT source_ip, toStartOfInterval(event_time, INTERVAL {WINDOW_MINUTES} MINUTE) AS window_start,
                   template_id, any(vendor) AS vendor, count() AS cnt
            FROM syslog_ml.events
            WHERE event_time >= now() - INTERVAL {LOOKBACK_DAYS} DAY AND event_time < %(current_window_start)s
            GROUP BY source_ip, window_start, template_id
        """, parameters={"current_window_start": current_window_start})

        # source_ip -> window_start -> template_id -> count
        by_device: dict[str, dict[datetime, dict[str, int]]] = defaultdict(lambda: defaultdict(dict))
        device_vendor: dict[str, str] = {}
        for source_ip, window_start, template_id, vendor, cnt in result.result_rows:
            by_device[source_ip][window_start][template_id] = cnt
            if vendor and vendor != "unknown":
                device_vendor[source_ip] = vendor

        if not by_device:
            return

        # Pool every device's windows into its vendor's sample population,
        # for the fallback model -- each (device, window) is one sample, so
        # a vendor's model reflects the range of normal across its whole
        # fleet, not just one device's history.
        vendor_samples: dict[str, list[dict[str, int]]] = defaultdict(list)
        for source_ip, windows in by_device.items():
            vendor = device_vendor.get(source_ip)
            if vendor:
                vendor_samples[vendor].extend(windows.values())

        vendor_models: dict[str, tuple[IsolationForest, list[str]]] = {}
        for vendor, samples in vendor_samples.items():
            if len(samples) < MIN_WINDOWS_FOR_VENDOR:
                continue
            top_k = _top_k_templates(samples, TOP_K_TEMPLATES)
            matrix = np.array([_vectorize(s, top_k) for s in samples])
            model = IsolationForest(n_estimators=100, contamination=CONTAMINATION, random_state=42)
            model.fit(matrix)
            vendor_models[vendor] = (model, top_k)
        log.info("Trained %d vendor-level template-mix model(s)", len(vendor_models))

        rows_to_insert = []
        newly_flagged: list[tuple[str, datetime]] = []  # for the retroactive event tag
        trained_devices = 0

        for source_ip, windows in by_device.items():
            sorted_windows = sorted(windows.items())
            vendor = device_vendor.get(source_ip, "unknown")

            model, top_k, model_scope = None, None, None
            if len(sorted_windows) >= MIN_WINDOWS_FOR_DEVICE:
                samples = [counts for _, counts in sorted_windows]
                top_k = _top_k_templates(samples, TOP_K_TEMPLATES)
                device_model = IsolationForest(n_estimators=100, contamination=CONTAMINATION, random_state=42)
                device_model.fit(np.array([_vectorize(s, top_k) for s in samples]))
                model, model_scope = device_model, "device"
                trained_devices += 1
            elif vendor in vendor_models:
                model, top_k = vendor_models[vendor]
                model_scope = "vendor"

            if model is None:
                continue  # not enough history anywhere yet for this device

            last_scored = self._last_scored.get(source_ip)
            new_windows = [(w, c) for w, c in sorted_windows if last_scored is None or w > last_scored]

            for window_start, counts in new_windows:
                vector = np.array([_vectorize(counts, top_k)])
                is_anomaly = bool(model.predict(vector)[0] == -1)
                score = float(model.decision_function(vector)[0])
                event_count = sum(counts.values())

                rows_to_insert.append(
                    [window_start, source_ip, vendor, model_scope, score, int(is_anomaly), event_count]
                )
                if is_anomaly:
                    newly_flagged.append((source_ip, window_start))
                self._last_scored[source_ip] = window_start

        if rows_to_insert:
            self.client.insert("syslog_ml.device_window_anomalies", rows_to_insert, column_names=_INSERT_COLUMNS)
        log.info(
            "Template-mix anomaly cycle: %d device model(s), %d vendor model(s), %d window(s) scored, %d flagged",
            trained_devices, len(vendor_models), len(rows_to_insert), len(newly_flagged),
        )

        for source_ip, window_start in newly_flagged:
            self._tag_events(source_ip, window_start)

    def _tag_events(self, source_ip: str, window_start: datetime):
        window_end = window_start + timedelta(minutes=WINDOW_MINUTES)
        try:
            self.client.command("""
                ALTER TABLE syslog_ml.events UPDATE
                    anomaly_reasons = arrayConcat(anomaly_reasons, ['unusual_template_mix']),
                    is_anomaly = 1
                WHERE source_ip = %(source_ip)s
                  AND event_time >= %(window_start)s AND event_time < %(window_end)s
                  AND NOT has(anomaly_reasons, 'unusual_template_mix')
            """, parameters={"source_ip": source_ip, "window_start": window_start, "window_end": window_end})
        except Exception:
            log.exception("Failed to tag events for flagged window %s @ %s", source_ip, window_start)
