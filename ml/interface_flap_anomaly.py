"""
Interface up/down "flapping" detection -- the eighth anomaly signal,
alongside anomaly_signals.py's stateless two and consumer.py's
DeviceBaselineCache pair, ml/template_mix_anomaly.py, and
ml/sequence_anomaly.py.

None of the other seven reliably catch a real hardware interface
repeatedly cycling down/up in a short window. `volume_spike` (see
consumer.py's DeviceBaselineCache) only catches it incidentally, and only
if the flapping is frequent enough to push the device 5x above its own
baseline rate -- a device that otherwise logs little can flap a handful
of times without ever tripping it. This signal is built directly from a
real example: a live "Ask" query surfaced `ether1` on
`MKT_SOC-MUTUELLE_link2[SNFL]_TO_SNFL` going down twice 18 seconds apart,
which none of the existing seven signals called out on its own.

Unlike unusual_template_mix/unusual_transition (retrospective, scored via
a mutation once a window closes), this is inline like rare_template/
always_severe/security_content: a sliding window of this device+interface's
own recent down-transitions, kept in memory, checked as each event arrives.

Interface/state extraction is deliberately narrow and evidence-based,
matching vendor_signatures.py's own stated methodology (patterns
"corrected/extended against real messages sampled from this deployment's
own traffic, not just vendor docs"): only RouterOS's confirmed
`ether<N> link up|down` format is recognized right now -- the same
pattern vendor_signatures.py already uses to detect mikrotik. Add more
(pattern, description) entries below as other vendors' real
interface-state message formats are confirmed in THIS deployment's actual
traffic. Guessing at Cisco/Juniper/etc. formats without evidence risks a
regex that looks plausible but never matches real messages here (fails
silently, not loudly) -- worse than simply not covering that vendor yet.
"""
import os
import re
from collections import defaultdict, deque
from datetime import datetime

# How far back a device+interface's down-transitions are counted. 15
# minutes by default: long enough to catch a real flapping episode, short
# enough that an interface which goes down once, stays down, and later
# recovers cleanly doesn't get flagged just because it happened to log a
# few unrelated down events far apart in its history.
FLAP_WINDOW_SECONDS = float(os.environ.get("INTERFACE_FLAP_WINDOW_SECONDS", str(15 * 60)))
# 3+ down-transitions within the window is "flapping" -- a single down
# (however disruptive) isn't a pattern yet; two could just be a normal
# maintenance blip (down, then back up); three or more in quick succession
# is a real, actionable oscillation. Confirmed against the ether1 example
# above (two downs in 18 seconds already looked wrong to a human reading
# the logs) -- tune via env var if real traffic shows this is too
# sensitive/lax once it's actually running.
FLAP_MIN_DOWN_TRANSITIONS = int(os.environ.get("INTERFACE_FLAP_MIN_DOWN_TRANSITIONS", "3"))

_INTERFACE_SIGNATURES = [
    (re.compile(r"\b(ether\d+) link (up|down)\b"), "RouterOS interface up/down message"),
]


def _extract_interface_state(message: str):
    """Returns (interface, state) -- state is "up" or "down" -- if
    `message` matches a known interface up/down format, else None."""
    message = (message or "").strip()
    for pattern, _description in _INTERFACE_SIGNATURES:
        match = pattern.search(message)
        if match:
            return match.group(1), match.group(2)
    return None


class InterfaceFlapDetector:
    """Per (source_ip, interface) sliding window of recent "down" event
    timestamps. Keyed by the event's own `event_time`, not wall-clock
    processing time -- consumer.py is a real-time tailer so the two are
    normally the same, but using event_time keeps this correct even if
    the classifier is ever catching up on a backlog (where messages that
    really happened minutes apart get processed back-to-back).

    Bounded in practice, not just in theory: Docker veth churn (the kind
    of interface name that could otherwise blow this up) is already
    dropped upstream in consumer.py's parse_record(), so only real
    hardware interfaces reach here, and a device only ever has a handful
    of those.
    """

    def __init__(self):
        self._recent_downs: dict[tuple[str, str], deque] = defaultdict(deque)

    def is_flapping(self, source_ip: str, message: str, event_time: datetime) -> bool:
        extracted = _extract_interface_state(message)
        if extracted is None:
            return False
        interface, state = extracted
        if state != "down":
            return False

        window = self._recent_downs[(source_ip, interface)]
        window.append(event_time)
        while window and (event_time - window[0]).total_seconds() > FLAP_WINDOW_SECONDS:
            window.popleft()

        return len(window) >= FLAP_MIN_DOWN_TRANSITIONS
