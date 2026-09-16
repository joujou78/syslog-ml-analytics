"""
SNMP community strings and v3 passphrases are credentials, not just config —
they get encrypted at rest with Fernet (symmetric, authenticated) rather
than stored as plaintext columns. This only protects data at rest in
Postgres; it does not replace transport security or DB access controls.

Generate a real key for deployment with:
    python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
and set it as SYSLOG_ML_CREDENTIAL_ENCRYPTION_KEY. The default below is only
for local development and must never be used in production.
"""
from cryptography.fernet import Fernet

from app.core.config import settings

_fernet = Fernet(settings.credential_encryption_key.encode())


def encrypt_secret(plaintext: str | None) -> str | None:
    if not plaintext:
        return None
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str | None) -> str | None:
    if not ciphertext:
        return None
    return _fernet.decrypt(ciphertext.encode()).decode()
