"""
Passive vendor detection from the raw syslog message *text* -- no SNMP
query, no credential needed. This exists for devices that haven't had an
SNMP credential added yet (see device_resolver.py): rather than leaving
vendor as "unknown" until someone gets around to that, it makes a
best-effort guess from each vendor's distinctive syslog message format.

This is a heuristic, not identity verification, and results are tagged
with vendor_source="passive" (vs "snmp" for a sysObjectID-verified vendor)
specifically so nothing downstream mistakes a format guess for a fact.
Two honest limitations:
  - A device can be configured to log in a non-default format, or a
    vendor can change its format across firmware versions -- these
    patterns are drawn from each vendor's commonly documented/observed
    syslog format, not verified against your specific devices.
  - Several vendors (Arista, HP, Dell) deliberately mimic Cisco's
    "%FACILITY-SEVERITY-MNEMONIC:" convention for CLI/tooling
    compatibility, so that pattern alone can't distinguish them --
    matches land in the "cisco_like" bucket rather than a specific vendor.
"""
import re

_SIGNATURES = [
    # (vendor, pattern, what it matches)
    ("juniper", re.compile(r"junos@2636\.1\.1\.1\.2"), "Junos structured-data field (2636 = Juniper's IANA enterprise number)"),
    ("paloalto", re.compile(r"^\d+,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},\d+,(TRAFFIC|THREAT|SYSTEM|CONFIG|HIPMATCH|GLOBALPROTECT|CORRELATION)"), "PAN-OS CSV log header"),
    ("fortinet", re.compile(r"\bdevname=\S+.*\blogid=\"?\d+\"?"), "FortiOS key=value log line with devname/logid fields"),
    ("mikrotik", re.compile(r"^[a-z0-9]+(,[a-z0-9]+)*,(info|warning|error|critical|debug)\b"), "RouterOS topic(s),severity prefix"),
    ("cisco_like", re.compile(r"^%[A-Z0-9_]+-\d-[A-Z0-9_]+:"), "%FACILITY-SEVERITY-MNEMONIC: convention (Cisco, and often mimicked by Arista/HP/Dell)"),
]


def detect_vendor(message: str) -> str:
    """Returns a vendor string, or 'unknown' if no signature matches."""
    for vendor, pattern, _description in _SIGNATURES:
        if pattern.search(message):
            return vendor
    return "unknown"
