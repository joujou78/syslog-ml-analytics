"""
Per-device Drain3-template transition anomaly detection (runs inside the
classifier's main loop, see consumer.py) -- the sequence-order counterpart
to template_mix_anomaly.py's TemplateMixAnomalyDetector.

Motivation (see the DeepLog assessment this follows up on): every other
anomaly signal in this pipeline looks at *what* a device is logging --
individually rare templates (rare_template), a shifted mix of templates
over a window (unusual_template_mix), overall severity/volume -- but none
of them look at *order*. A device that logs template B right after
template A a thousand times, then one day logs template C right after A
instead, can look completely normal to all of those: C might not be a rare
template on its own, and one window's mix might not shift enough to trip
IsolationForest. DeepLog (Du et al., CCS'17) addresses exactly this with an
LSTM that predicts the next event ID from a fixed-size window of prior
event IDs and flags a mismatch against its top-k predictions.

This module borrows DeepLog's core idea -- flag a transition that didn't
look like it belonged, given what came before -- without adopting DeepLog
itself, for two reasons specific to this project:

  1. Open-ended vocabulary. DeepLog's embedding layer needs a fixed event
     vocabulary size decided up front. Drain3 (see ml/consumer.py's
     `miner`) keeps minting new template IDs indefinitely as new log
     formats appear -- there is no fixed vocabulary to size an embedding
     table against, short of periodically retraining and redeploying a
     whole neural net whenever Drain3's cluster set changes. A dict-keyed
     transition-count table (below) has no such ceiling: an unseen
     template_id is just a key that hasn't been seen as a "from" or "to"
     state yet, exactly like `rare_template`'s cluster_size check already
     handles unseen templates elsewhere in this pipeline.
  2. Dependency and interpretability cost. DeepLog means adding PyTorch
     (a large dependency this otherwise-scikit-learn/numpy pipeline
     doesn't have) for a result that's fundamentally a probability
     estimate anyway -- a first-order Markov chain over template_id
     transitions gives the same "how likely was this transition, given
     what this device (or its vendor fleet) normally does" answer, at
     orders of magnitude less code and zero new dependencies, and every
     flagged transition's reason is a plain conditional probability
     that's directly explainable in the alert (`P(curr|prev) = 0.003%`),
     consistent with anomaly_reasons' "always label confidence/reason,
     never just a bare verdict" principle (see anomaly_signals.py).

Order-1 (bigram) rather than DeepLog's typical order-N window: this
pipeline's traffic mixes many devices' templates in event-arrival order
already (see AcsMultipartReassembler upstream in consumer.py for one
example of why event order per source can be complex) -- committing to a
single prev->curr pair per device keeps the model correct without needing
to reason about how far back a longer window should legitimately look
per-device. Nothing here rules out extending PROBABILITY_THRESHOLD /
order in a later pass if order-1 proves too coarse in practice.

Every model is trained on history strictly BEFORE the transitions it then
scores, never on them -- confirmed necessary in real testing, not just a
theoretical nicety: training on the same batch being scored folds a
genuinely novel transition into its own count, and Laplace smoothing
treats "seen once, right now" very differently from "seen zero times
ever," which meant a real single-occurrence anomaly scored ABOVE
PROBABILITY_THRESHOLD instead of below it. See `_run_cycle`'s prior/new
split for how this is enforced (the exception is a device's very first,
cold-start cycle, which has no prior history to hold back).

Two-tier device/vendor fallback, same shape and same rationale as
TemplateMixAnomalyDetector: a low-traffic device may never accumulate
enough of its own transitions to know what's normal for it specifically,
so it borrows its vendor's pooled transition table instead.
"""
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

log = logging.getLogger("sequence_anomaly")

LOOKBACK_DAYS = int(os.environ.get("SEQUENCE_ANOMALY_LOOKBACK_DAYS", "7"))
REFRESH_SECONDS = float(os.environ.get("SEQUENCE_ANOMALY_REFRESH_SECONDS", "900"))
# Below this many of its own observed transitions, a device isn't scored
# against its own model -- mirrors TemplateMixAnomalyDetector's
# MIN_WINDOWS_FOR_DEVICE for the same reason (not enough history yet to
# know what "normal" looks like for it specifically).
MIN_TRANSITIONS_FOR_DEVICE = int(os.environ.get("SEQUENCE_ANOMALY_MIN_TRANSITIONS_FOR_DEVICE", "200"))
MIN_TRANSITIONS_FOR_VENDOR = int(os.environ.get("SEQUENCE_ANOMALY_MIN_TRANSITIONS_FOR_VENDOR", "200"))
# A transition observed less often than this fraction of the time it could
# have occurred (given how often its "from" template appears) is flagged.
# Deliberately low and explicit rather than an auto-fit threshold (see
# template_mix_anomaly.py's CONTAMINATION comment on why IsolationForest's
# "auto" over-flags on this pipeline's real traffic) -- 0.5% means "this
# transition happens less than 1 time in 200 that this template appears",
# a genuinely rare follow-on, not just below-average.
PROBABILITY_THRESHOLD = float(os.environ.get("SEQUENCE_ANOMALY_PROBABILITY_THRESHOLD", "0.005"))
# Laplace (add-one) smoothing constant, so a transition that simply never
# appeared in training isn't scored as *exactly* zero probability (which
# would make PROBABILITY_THRESHOLD meaningless for it -- 0.0 < any positive
# threshold is always true) but instead as "rarer than anything actually
# observed," which sorts below every real observed transition and is still
# reliably caught by the threshold above.
LAPLACE_ALPHA = 1.0

_INSERT_COLUMNS = [
    "transition_time", "source_ip", "vendor", "model_scope",
    "prev_template_id", "curr_template_id", "transition_probability", "is_anomaly",
]


class _TransitionModel:
    """prev_template_id -> {curr_template_id: count}, plus prev_template_id
    -> total count seen as a "from" state -- everything this needs to
    answer "how likely is curr given prev" with Laplace smoothing."""

    def __init__(self, counts: dict[str, dict[str, int]]):
        self.counts = counts
        self.totals = {prev: sum(curr_counts.values()) for prev, curr_counts in counts.items()}
        # Distinct curr values ever seen anywhere in this model -- the
        # smoothing denominator's vocabulary size. Global, not per-prev, so
        # a curr template that's common after some OTHER prev but never
        # after this one is smoothed the same way as a curr template that's
        # never been seen at all -- both are "not what usually follows
        # this specific prev," which is exactly what should be flagged.
        self.vocab_size = len({curr for curr_counts in counts.values() for curr in curr_counts})

    def probability(self, prev: str, curr: str) -> float:
        total = self.totals.get(prev, 0)
        count = self.counts.get(prev, {}).get(curr, 0)
        return (count + LAPLACE_ALPHA) / (total + LAPLACE_ALPHA * max(self.vocab_size, 1))


def _build_model(transition_counts: dict[str, dict[str, int]]) -> _TransitionModel:
    return _TransitionModel(transition_counts)


def _add_transition(counts: dict[str, dict[str, int]], prev: str, curr: str):
    counts.setdefault(prev, {})
    counts[prev][curr] = counts[prev].get(curr, 0) + 1


class SequenceAnomalyDetector:
    def __init__(self, client):
        self.client = client
        self._last_refresh = 0.0
        # source_ip -> latest event_time already scored as a "curr" half of
        # a transition, so a restart resumes without re-scoring (and
        # re-tagging) transitions already handled -- same idiom as
        # TemplateMixAnomalyDetector._last_scored.
        self._last_scored: dict[str, datetime] = {}
        self._loaded_last_scored = False

    def _load_last_scored(self):
        try:
            result = self.client.query(
                "SELECT source_ip, max(transition_time) FROM syslog_ml.device_sequence_anomalies GROUP BY source_ip"
            )
            self._last_scored = {row[0]: row[1] for row in result.result_rows}
            log.info("Loaded prior sequence-anomaly scoring checkpoint for %d device(s)", len(self._last_scored))
        except Exception:
            log.exception("Could not load prior sequence-anomaly scoring checkpoint, starting from a full backfill")
        self._loaded_last_scored = True

    def refresh_if_stale(self):
        if not self._loaded_last_scored:
            self._load_last_scored()
        if time.monotonic() - self._last_refresh < REFRESH_SECONDS:
            return
        try:
            self._run_cycle()
        except Exception:
            log.exception("Sequence-anomaly cycle failed, will retry next cycle")
        self._last_refresh = time.monotonic()

    def _run_cycle(self):
        result = self.client.query(f"""
            SELECT source_ip, any(vendor) AS vendor, groupArray(event_time) AS times, groupArray(template_id) AS templates
            FROM (
                SELECT source_ip, vendor, event_time, template_id
                FROM syslog_ml.events
                WHERE event_time >= now() - INTERVAL {LOOKBACK_DAYS} DAY
                ORDER BY source_ip, event_time
            )
            GROUP BY source_ip
        """)

        # source_ip -> ordered [(event_time, template_id), ...]
        by_device: dict[str, list[tuple[datetime, str]]] = {}
        device_vendor: dict[str, str] = {}
        for source_ip, vendor, times, templates in result.result_rows:
            by_device[source_ip] = list(zip(times, templates))
            if vendor and vendor != "unknown":
                device_vendor[source_ip] = vendor

        if not by_device:
            return

        # Split each device's transitions into "prior" (curr already scored
        # in an earlier cycle) and "new" (about to be scored this cycle),
        # and build every model from prior transitions ONLY -- deliberately
        # excluding the very transitions being scored against it. Training
        # on the same batch being scored would fold a genuinely
        # never-before-seen transition into its own count (Laplace
        # smoothing treats "seen once, right now" very differently from
        # "seen zero times ever"), diluting exactly the single-occurrence
        # anomaly this detector exists to catch. A brand-new device with no
        # checkpoint yet (last_scored is None) has no "prior" to separate
        # from "new" -- there, this necessarily falls back to training and
        # scoring its whole first backfill window together, the same
        # accepted cold-start limitation TemplateMixAnomalyDetector already
        # has for the identical reason.
        prior_counts: dict[str, dict[str, dict[str, int]]] = {}
        new_transitions: dict[str, list[tuple[str, str, datetime]]] = {}
        for source_ip, sequence in by_device.items():
            last_scored = self._last_scored.get(source_ip)
            counts: dict[str, dict[str, int]] = {}
            new_list: list[tuple[str, str, datetime]] = []
            for (_, prev), (curr_time, curr) in zip(sequence, sequence[1:]):
                if last_scored is None or curr_time <= last_scored:
                    _add_transition(counts, prev, curr)
                else:
                    new_list.append((prev, curr, curr_time))
            if last_scored is None:
                # Cold start: nothing held back as "new" above (the
                # condition never took the else branch) -- score the same
                # window just trained on, matching the documented
                # cold-start tradeoff above.
                new_list = [(prev, curr, curr_time) for (_, prev), (curr_time, curr) in zip(sequence, sequence[1:])]
            prior_counts[source_ip] = counts
            new_transitions[source_ip] = new_list

        vendor_counts: dict[str, dict[str, dict[str, int]]] = defaultdict(dict)
        vendor_transition_totals: dict[str, int] = defaultdict(int)
        for source_ip, counts in prior_counts.items():
            vendor = device_vendor.get(source_ip)
            if not vendor:
                continue
            transitions = sum(sum(c.values()) for c in counts.values())
            vendor_transition_totals[vendor] += transitions
            for prev, curr_counts in counts.items():
                for curr, n in curr_counts.items():
                    vendor_counts[vendor].setdefault(prev, {})
                    vendor_counts[vendor][prev][curr] = vendor_counts[vendor][prev].get(curr, 0) + n

        vendor_models: dict[str, _TransitionModel] = {
            vendor: _build_model(counts)
            for vendor, counts in vendor_counts.items()
            if vendor_transition_totals[vendor] >= MIN_TRANSITIONS_FOR_VENDOR
        }
        log.info("Trained %d vendor-level sequence model(s)", len(vendor_models))

        rows_to_insert = []
        newly_flagged: list[tuple[str, datetime, str]] = []  # (source_ip, event_time, curr_template) to tag
        trained_devices = 0

        for source_ip, new_list in new_transitions.items():
            counts = prior_counts[source_ip]
            own_transitions = sum(sum(c.values()) for c in counts.values())
            vendor = device_vendor.get(source_ip, "unknown")

            model, model_scope = None, None
            if own_transitions >= MIN_TRANSITIONS_FOR_DEVICE:
                model, model_scope = _build_model(counts), "device"
                trained_devices += 1
            elif vendor in vendor_models:
                model, model_scope = vendor_models[vendor], "vendor"

            if model is None:
                continue  # not enough history anywhere yet for this device

            checkpoint_advance = self._last_scored.get(source_ip)

            for prev, curr, curr_time in new_list:
                probability = model.probability(prev, curr)
                is_anomaly = probability < PROBABILITY_THRESHOLD
                rows_to_insert.append(
                    [curr_time, source_ip, vendor, model_scope, prev, curr, probability, int(is_anomaly)]
                )
                if is_anomaly:
                    newly_flagged.append((source_ip, curr_time, curr))
                if checkpoint_advance is None or curr_time > checkpoint_advance:
                    checkpoint_advance = curr_time

            if checkpoint_advance is not None:
                self._last_scored[source_ip] = checkpoint_advance

        if rows_to_insert:
            self.client.insert("syslog_ml.device_sequence_anomalies", rows_to_insert, column_names=_INSERT_COLUMNS)
        log.info(
            "Sequence-anomaly cycle: %d device model(s), %d vendor model(s), %d transition(s) scored, %d flagged",
            trained_devices, len(vendor_models), len(rows_to_insert), len(newly_flagged),
        )

        for source_ip, event_time, curr_template in newly_flagged:
            self._tag_event(source_ip, event_time, curr_template)

    def _tag_event(self, source_ip: str, event_time: datetime, curr_template: str):
        # Matches on (source_ip, event_time, template_id) rather than
        # event_time alone -- narrows, but doesn't eliminate, the same
        # same-millisecond-tie ambiguity documented in
        # log_assistant_indexer.py's _fetch_exact_timestamp: two distinct
        # events from one device with the same template_id in the same
        # millisecond both get tagged, which is harmless here (both would
        # need the same anomalous transition to have produced the same
        # curr_template in the first place).
        try:
            self.client.command("""
                ALTER TABLE syslog_ml.events UPDATE
                    anomaly_reasons = arrayConcat(anomaly_reasons, ['unusual_transition']),
                    is_anomaly = 1
                WHERE source_ip = %(source_ip)s
                  AND event_time = %(event_time)s
                  AND template_id = %(curr_template)s
                  AND NOT has(anomaly_reasons, 'unusual_transition')
            """, parameters={"source_ip": source_ip, "event_time": event_time, "curr_template": curr_template})
        except Exception:
            log.exception("Failed to tag event for flagged transition %s @ %s", source_ip, event_time)
