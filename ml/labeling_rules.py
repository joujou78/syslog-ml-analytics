"""
Weak-supervision rules used to bootstrap training labels for the severity/
category classifier when no hand-labeled log data exists yet.

This is a starting point, not ground truth: the rules are generic keyword
patterns seen across common network/OS syslog sources (auth, kernel,
firewall, routing daemons, etc.). Expect to tune CATEGORY_RULES against a
sample of your own traffic before trusting the trained model's output —
treat early predictions as suggestions to review, not verified facts about
the network.
"""
import re

CATEGORIES = [
    "AUTH",
    "NETWORK",
    "HARDWARE",
    "SECURITY",
    "SYSTEM",
    "APPLICATION",
    "CONFIG",
    "UNKNOWN",
]

# Order matters: first matching pattern wins.
CATEGORY_RULES = [
    ("AUTH", re.compile(r"\b(login|logout|authentication|password|pam_unix|sshd|session opened|session closed)\b", re.I)),
    ("SECURITY", re.compile(r"\b(denied|blocked|intrusion|attack|malware|firewall|iptables|unauthorized|violation)\b", re.I)),
    ("HARDWARE", re.compile(r"\b(link (up|down)|interface (up|down)|fan|temperature|psu|power supply|disk (fail|error)|hardware)\b", re.I)),
    ("NETWORK", re.compile(r"\b(bgp|ospf|route|routing|neighbor|link-flap|packet loss|timeout|unreachable|vlan|spanning.tree)\b", re.I)),
    ("CONFIG", re.compile(r"\b(config(uration)? (changed|applied|saved|reload)|commit|rollback)\b", re.I)),
    ("APPLICATION", re.compile(r"\b(exception|stack trace|service (started|stopped|crashed)|failed to start)\b", re.I)),
    ("SYSTEM", re.compile(r"\b(kernel|cron|systemd|reboot|shutdown|out of memory|oom)\b", re.I)),
]

SEVERITY_ORDER = {
    "emerg": 0, "alert": 1, "crit": 2, "err": 3,
    "warning": 4, "notice": 5, "info": 6, "debug": 7,
}


def weak_label(message: str) -> str:
    for category, pattern in CATEGORY_RULES:
        if pattern.search(message):
            return category
    return "UNKNOWN"


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get((severity or "").lower(), 6)
