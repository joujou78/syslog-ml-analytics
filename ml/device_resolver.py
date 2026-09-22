"""
Device identity resolution: source IP -> hostname / vendor / model.

Credentials live in the web app's Postgres database (snmp_credentials
table, managed by admins through the web UI) rather than a flat file --
one source of truth, encrypted at rest, audited. This never guesses a
community string: it only attempts SNMP for an IP that has a matching row
(exact IP or CIDR match). Everything else falls back to the hostname the
device itself put in the syslog message, or finally the bare source IP --
always with `resolution_method` recorded so you can see exactly how
confident each row's identity is (and which devices still need a
credential added through the web UI).

A credential "pool" is the one exception worth calling out: a scope like
0.0.0.0/0 can hold many community-string candidates at once (added via
the web app's bulk import), for when an admin has a known, finite set of
communities in use across their devices but no per-IP mapping. Resolution
still only ever tries a community an admin explicitly entered as theirs
-- never an unknown/default string -- against an IP that has already sent
this VM syslog traffic. See resolve_with_discovery() and
save_discovered_credential() below.

Uses the net-snmp CLI (`snmpget`) via subprocess rather than a Python SNMP
library: it's what `apt install snmp` gives you natively on Ubuntu/Debian,
handles v1/v2c/v3 uniformly, and one subprocess call per OID is plenty fast
for periodic (not per-message) resolution.
"""
import ipaddress
import logging
import subprocess
import uuid

import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet

log = logging.getLogger("device_resolver")

SYS_NAME_OID = "1.3.6.1.2.1.1.5.0"
SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID_OID = "1.3.6.1.2.1.1.2.0"

# Well-known IANA private enterprise numbers (iana.org/assignments/enterprise-numbers).
# Not exhaustive — extend this as you encounter vendors it doesn't recognize;
# unmatched OIDs fall back to vendor="unknown" rather than a guess.
VENDOR_OID_PREFIXES = {
    "1.3.6.1.4.1.9.": "cisco",
    "1.3.6.1.4.1.2636.": "juniper",
    "1.3.6.1.4.1.12356.": "fortinet",
    "1.3.6.1.4.1.2011.": "huawei",
    "1.3.6.1.4.1.25461.": "paloalto",
    "1.3.6.1.4.1.30065.": "arista",
    "1.3.6.1.4.1.14988.": "mikrotik",
    "1.3.6.1.4.1.11.": "hp",
    "1.3.6.1.4.1.14823.": "aruba",
    "1.3.6.1.4.1.674.": "dell",
    "1.3.6.1.4.1.41112.": "ubiquiti",
    "1.3.6.1.4.1.8072.": "net-snmp",  # generic Linux/Unix hosts running net-snmp
}

SNMP_TIMEOUT_SECONDS = 3
SNMP_RETRIES = 1


def _clean(value, default=""):
    """Coerces a possibly-None/possibly-missing field to a stripped string."""
    return (value or default).strip()


class Credential:
    def __init__(self, row):
        self.network = ipaddress.ip_network(row["ip_or_cidr"], strict=False)
        self.version = _clean(row["version"]).lower()
        self.community = _clean(row.get("community"))
        self.v3_user = _clean(row.get("v3_user"))
        self.v3_level = _clean(row.get("v3_level"), "authPriv")
        self.v3_auth_proto = _clean(row.get("v3_auth_proto"), "SHA")
        self.v3_auth_pass = _clean(row.get("v3_auth_pass"))
        self.v3_priv_proto = _clean(row.get("v3_priv_proto"), "AES")
        self.v3_priv_pass = _clean(row.get("v3_priv_pass"))

    def contains(self, ip):
        try:
            return ipaddress.ip_address(ip) in self.network
        except ValueError:
            return False

    def snmpget_args(self):
        if self.version == "v3":
            return [
                "-v3", "-u", self.v3_user, "-l", self.v3_level,
                "-a", self.v3_auth_proto, "-A", self.v3_auth_pass,
                "-x", self.v3_priv_proto, "-X", self.v3_priv_pass,
            ]
        # net-snmp's -v flag takes exactly "1", "2c", or "3" -- not "v1"/
        # "v2c" as stored in the DB/UI (confirmed against a real local
        # snmpd: "-v v2c" fails with "Invalid version specified after -v
        # flag: v2c", exit 1, indistinguishable from a wrong community in
        # the logs -- this silently broke every v1/v2c resolution attempt
        # since the resolver was first written).
        return ["-v", self.version.lstrip("v"), "-c", self.community]


def load_credentials(database_url, encryption_key):
    """
    Returns a list of Credential objects, most-specific network first,
    read from the web app's snmp_credentials table and decrypted with the
    same Fernet key the web app uses to write them
    (SYSLOG_ML_CREDENTIAL_ENCRYPTION_KEY -- must match between both services).
    """
    fernet = Fernet(encryption_key.encode())

    def decrypt(ciphertext):
        return fernet.decrypt(ciphertext.encode()).decode() if ciphertext else None

    credentials = []
    try:
        conn = psycopg2.connect(database_url)
    except psycopg2.OperationalError:
        log.exception("Could not connect to the credentials database — SNMP resolution disabled this cycle")
        return []

    try:
        with conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT ip_or_cidr, version, community_encrypted,
                       v3_user, v3_level, v3_auth_proto, v3_auth_pass_encrypted,
                       v3_priv_proto, v3_priv_pass_encrypted
                FROM snmp_credentials
                """
            )
            for row in cur.fetchall():
                try:
                    credentials.append(Credential({
                        "ip_or_cidr": row["ip_or_cidr"],
                        "version": row["version"],
                        "community": decrypt(row["community_encrypted"]),
                        "v3_user": row["v3_user"],
                        "v3_level": row["v3_level"],
                        "v3_auth_proto": row["v3_auth_proto"],
                        "v3_auth_pass": decrypt(row["v3_auth_pass_encrypted"]),
                        "v3_priv_proto": row["v3_priv_proto"],
                        "v3_priv_pass": decrypt(row["v3_priv_pass_encrypted"]),
                    }))
                except (KeyError, ValueError) as exc:
                    log.warning("Skipping malformed credential row for %r: %s", row["ip_or_cidr"], exc)
    finally:
        conn.close()

    # Prefer exact /32 host entries over broader subnets when both match.
    credentials.sort(key=lambda c: c.network.num_addresses)
    return credentials


def find_credential(credentials, ip):
    for cred in credentials:
        if cred.contains(ip):
            return cred
    return None


def find_candidate_credentials(credentials, ip):
    """Like find_credential(), but returns every matching credential
    (already most-specific first, since `credentials` is pre-sorted) --
    used to try each pool candidate in turn rather than stopping at the
    first (possibly stale) match."""
    return [cred for cred in credentials if cred.contains(ip)]


def is_exact_host_credential(credential, ip):
    """True if this credential's scope already IS this specific IP (a
    /32 host entry), meaning there's nothing new to auto-save -- it was
    already a per-device credential, not a pool match."""
    return credential.network.num_addresses == 1 and str(credential.network.network_address) == ip


def _snmpget(ip, oid, credential):
    cmd = ["snmpget", "-O", "qv", "-t", str(SNMP_TIMEOUT_SECONDS), "-r", str(SNMP_RETRIES)]
    cmd += credential.snmpget_args()
    cmd += [ip, oid]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=SNMP_TIMEOUT_SECONDS * (SNMP_RETRIES + 2))
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip().strip('"')


def vendor_from_object_id(object_id):
    if not object_id:
        return "unknown"
    # net-snmp's default output translates the numeric root arc "1" to its
    # symbolic MIB name "iso" (e.g. "iso.3.6.1.4.1.14988.1" instead of
    # "1.3.6.1.4.1.14988.1") even with our -O qv flags -- that's the
    # always-loaded base SNMPv2-SMI MIB, not a private one, so every real
    # sysObjectID comes back this way. Normalize before matching, or every
    # prefix in VENDOR_OID_PREFIXES silently never matches.
    normalized = object_id.lstrip(".")
    if normalized.startswith("iso."):
        normalized = "1." + normalized[len("iso."):]
    for prefix, vendor in VENDOR_OID_PREFIXES.items():
        if normalized.startswith(prefix):
            return vendor
    return "unknown"


def resolve_via_snmp(ip, credential):
    """Returns (hostname, vendor, model) or None if SNMP didn't respond."""
    sys_name = _snmpget(ip, SYS_NAME_OID, credential)
    if sys_name is None:
        return None
    sys_descr = _snmpget(ip, SYS_DESCR_OID, credential) or ""
    sys_object_id = _snmpget(ip, SYS_OBJECT_ID_OID, credential) or ""
    vendor = vendor_from_object_id(sys_object_id)
    model = sys_descr[:200]
    return sys_name or ip, vendor, model


def resolve_with_discovery(ip, candidates):
    """
    Tries each candidate credential against `ip`, most specific first,
    until one gets a real SNMP response. Returns (result, matched_credential)
    or (None, None) if none worked. Never assumes a match -- every attempt
    is a real SNMP round-trip, and `candidates` only ever contains
    communities/users an admin explicitly entered (see load_credentials).
    """
    for credential in candidates:
        result = resolve_via_snmp(ip, credential)
        if result is not None:
            return result, credential
    return None, None


def save_discovered_credential(database_url, encryption_key, ip, credential):
    """
    Persists the credential that just worked for `ip` as that IP's own
    exact-host (/32) entry, so future cycles query it directly instead of
    re-trying the whole pool. Upserts by exact ip_or_cidr match rather than
    relying on a database constraint, since snmp_credentials.ip_or_cidr is
    deliberately not unique any more (a pool has many rows sharing one
    broad scope). Only ever called for v1/v2c (community-based) matches --
    v3 has no equivalent "pool of usernames" concept, so it always requires
    an exact per-device credential to begin with.
    """
    fernet = Fernet(encryption_key.encode())

    def encrypt(value):
        return fernet.encrypt(value.encode()).decode() if value else None

    try:
        conn = psycopg2.connect(database_url)
    except psycopg2.OperationalError:
        log.exception("Could not connect to the credentials database -- skipping auto-save for %s", ip)
        return

    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT id FROM snmp_credentials WHERE ip_or_cidr = %s", (ip,))
            existing = cur.fetchone()
            if existing:
                cur.execute(
                    """
                    UPDATE snmp_credentials
                    SET version = %s, community_encrypted = %s, auto_discovered = true, updated_at = now()
                    WHERE id = %s
                    """,
                    (credential.version, encrypt(credential.community), existing[0]),
                )
                log.info("Updated auto-discovered credential for %s (its community changed)", ip)
            else:
                cur.execute(
                    """
                    INSERT INTO snmp_credentials
                        (id, ip_or_cidr, version, community_encrypted, auto_discovered, created_at, updated_at)
                    VALUES (%s, %s, %s, %s, true, now(), now())
                    """,
                    (str(uuid.uuid4()), ip, credential.version, encrypt(credential.community)),
                )
                log.info("Auto-discovered and saved a credential for %s", ip)
    finally:
        conn.close()
