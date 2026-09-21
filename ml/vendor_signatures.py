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
    vendor can change its format across firmware versions.
  - Several vendors (Arista, HP, Dell) deliberately mimic Cisco's
    "%FACILITY-SEVERITY-MNEMONIC:" convention for CLI/tooling
    compatibility, so that pattern alone can't distinguish them --
    matches land in the "cisco_like" bucket rather than a specific vendor.

The cisco_like and mikrotik patterns below were corrected/extended against
real messages sampled from this deployment's own traffic (not just vendor
docs): real Cisco IOS messages carry a sequence-number and timestamp
prefix before the "%FACILITY-..." marker (e.g. "023543: *Mar 22
12:06:38.718: %SW_MATM-4-MACFLAP_NOTIF: ..."), so the original version of
this pattern -- anchored to the start of the message -- never matched.
RouterOS's own default "topic,severity: message" prefix also isn't
present in the `message` field as delivered by this pipeline (rsyslog's
parsing already splits that off into other fields), so the mikrotik
patterns below match message *content* actually observed here instead:
interface up/down, wireless scan-list and client-status lines, PPP dialer
state, DHCP lease assignment, and admin login/logout.
"""
import re

_SIGNATURES = [
    # (vendor, pattern, what it matches)
    ("juniper", re.compile(r"junos@2636\.1\.1\.1\.2"), "Junos structured-data field (2636 = Juniper's IANA enterprise number)"),
    ("paloalto", re.compile(r"^\d+,\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2},\d+,(TRAFFIC|THREAT|SYSTEM|CONFIG|HIPMATCH|GLOBALPROTECT|CORRELATION)"), "PAN-OS CSV log header"),
    ("fortinet", re.compile(r"\bdevname=\S+.*\blogid=\"?\d+\"?"), "FortiOS key=value log line with devname/logid fields"),
    ("mikrotik", re.compile(r"^ether\d+ link (up|down)\b"), "RouterOS interface up/down message"),
    ("mikrotik", re.compile(r"\bon \d+ AP: (yes|no) SSID\b"), "RouterOS wireless scan-list entry"),
    ("mikrotik", re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}@wlan\d+\b", re.I), "RouterOS wireless client MAC associating on a wlan interface"),
    ("mikrotik", re.compile(r"^wlan\d+: (failed to select network|no network that satisfies connect-list|must select network)\b"), "RouterOS wireless client status message"),
    ("mikrotik", re.compile(r"^ppp-(in|out)\d+:"), "RouterOS PPP interface state message (dialing/authenticating/disconnecting)"),
    ("mikrotik", re.compile(r"\bassigned \d{1,3}(\.\d{1,3}){3} to [0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}\b"), "RouterOS DHCP server lease assignment"),
    ("mikrotik", re.compile(r"\blogged (in|out) from \S+ via \w+\b"), "RouterOS admin session login/logout message"),
    ("mikrotik", re.compile(r"^[a-z0-9]+(,[a-z0-9]+)*,(info|warning|error|critical|debug)\b"), "RouterOS topic(s),severity prefix (if not split into a separate field upstream)"),
    ("cisco_like", re.compile(r"%[A-Z0-9_]+-\d-[A-Z0-9_]+:"), "%FACILITY-SEVERITY-MNEMONIC: convention (Cisco, and often mimicked by Arista/HP/Dell) -- not anchored to message start since real devices often prefix a sequence number/timestamp first"),
]


def detect_vendor(message: str) -> str:
    """Returns a vendor string, or 'unknown' if no signature matches."""
    for vendor, pattern, _description in _SIGNATURES:
        if pattern.search(message):
            return vendor
    return "unknown"
