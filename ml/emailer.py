"""
Shared SMTP email helper for ml/evaluate_alerts.py and ml/daily_digest.py --
one place to configure an SMTP relay/server instead of duplicating
smtplib boilerplate in both. Deliberately plain smtplib against a
relay/server the operator already has (confirmed as the preferred option
for this deployment), not a transactional email API (SendGrid/SES/etc.)
-- no new account/API key needed, just point it at an existing mail
server the same way the rest of this project points at existing
ClickHouse/Postgres/OpenSearch instances.

Returns (sent, error) everywhere, same convention as evaluate_alerts.py's
and detect_silent_devices.py's notify_webhook: sent=True with no
recipients configured just means there was nothing to deliver, not that
delivery succeeded.
"""
import logging
import os
import smtplib
from email.mime.text import MIMEText

log = logging.getLogger("emailer")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
# STARTTLS (upgrade a plaintext connection) is the common case for port
# 587 against a relay/Office 365/Gmail -- SMTP_USE_SSL is for the less
# common implicit-TLS-from-the-start setup (typically port 465). Only one
# of the two should apply for a given server; SMTP_USE_SSL wins if both
# are somehow set, since starting inside an SSL connection and then also
# issuing STARTTLS would fail.
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() not in ("false", "0", "")
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "false").lower() not in ("false", "0", "")
SMTP_FROM_ADDRESS = os.environ.get("SMTP_FROM_ADDRESS", "")
SMTP_TIMEOUT_SECONDS = float(os.environ.get("SMTP_TIMEOUT_SECONDS", "10"))


def parse_recipients(recipients_env: str) -> list[str]:
    return [addr.strip() for addr in recipients_env.split(",") if addr.strip()]


def send_email(to_addresses: list[str], subject: str, body: str) -> tuple[bool, str | None]:
    """Returns (sent, error). sent=True with no recipients/no SMTP_HOST
    configured just means there was nothing to deliver -- same "not
    configured" vs "configured but failed" distinction every other
    notification path in this project already makes."""
    if not to_addresses:
        return True, None
    if not SMTP_HOST:
        log.warning("SMTP_HOST not configured, skipping email to %s", to_addresses)
        return True, None

    message = MIMEText(body, "plain", "utf-8")
    message["Subject"] = subject
    message["From"] = SMTP_FROM_ADDRESS or SMTP_USERNAME
    message["To"] = ", ".join(to_addresses)

    try:
        client_cls = smtplib.SMTP_SSL if SMTP_USE_SSL else smtplib.SMTP
        with client_cls(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as client:
            if SMTP_USE_TLS and not SMTP_USE_SSL:
                client.starttls()
            if SMTP_USERNAME:
                client.login(SMTP_USERNAME, SMTP_PASSWORD)
            client.sendmail(message["From"], to_addresses, message.as_string())
        return True, None
    except (smtplib.SMTPException, OSError) as exc:
        # OSError alongside SMTPException: a connection failure (wrong
        # host/port, network unreachable) raises a plain OSError/
        # socket.gaierror, not an smtplib-specific exception -- same
        # reasoning as evaluate_alerts.py catching requests.RequestException
        # for its webhook POSTs, just for a different transport.
        return False, str(exc)[:1000]
