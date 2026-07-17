"""
auth/totp_crypto.py — Chiffrement/déchiffrement des secrets TOTP au repos.

Les secrets TOTP sont chiffrés avec Fernet (AES-128-CBC + HMAC-SHA256)
avant stockage dans users.totp_secret / users.totp_pending_secret.
La clé est dérivée via HKDF-SHA256 depuis SETTINGS_ENCRYPTION_KEY
(ou JWT_SECRET_KEY en fallback).

Les valeurs chiffrées sont préfixées par "totp:" pour les distinguer
des secrets en clair hérités (migration transparente).
"""

import base64
import logging
import os

logger = logging.getLogger("auth.totp_crypto")

_PREFIX = "totp:"
_fernet = None
_fernet_key = None


def _derive():
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    secret = os.getenv("SETTINGS_ENCRYPTION_KEY") or os.getenv("JWT_SECRET_KEY", "change-me-in-production")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"repod-totp-v1",
        info=b"totp-secret-encryption",
    )
    raw = hkdf.derive(secret.encode("utf-8"))
    return Fernet(base64.urlsafe_b64encode(raw)), secret


def _get_fernet():
    global _fernet, _fernet_key
    secret = os.getenv("SETTINGS_ENCRYPTION_KEY") or os.getenv("JWT_SECRET_KEY", "change-me-in-production")
    if _fernet is not None and _fernet_key == secret:
        return _fernet
    _fernet, _fernet_key = _derive()
    return _fernet


def encrypt_totp_secret(plain: str) -> str:
    if not plain:
        return plain
    if plain.startswith(_PREFIX):
        return plain
    f = _get_fernet()
    encrypted = f.encrypt(plain.encode("utf-8")).decode("ascii")
    return _PREFIX + encrypted


def decrypt_totp_secret(stored: str) -> str:
    if not stored:
        return stored
    if not stored.startswith(_PREFIX):
        return stored
    f = _get_fernet()
    try:
        return f.decrypt(stored[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except Exception:
        logger.warning("Impossible de déchiffrer le secret TOTP — clé changée ?")
        return ""
