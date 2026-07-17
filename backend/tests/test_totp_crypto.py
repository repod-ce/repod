"""
Module : test_totp_crypto.py
Rôle   : Tests du chiffrement au repos des secrets TOTP (auth/totp_crypto.py).
         Vérifie le round-trip encrypt/decrypt, la rétrocompatibilité avec les
         secrets en clair hérités, et l'idempotence du préfixe.

Dépend : pytest, cryptography (Fernet)
"""

import os
import importlib

import pytest


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    # Clé déterministe pour des tests reproductibles
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", "test-totp-key-0123456789abcdef")
    import auth.totp_crypto as tc
    importlib.reload(tc)
    # réinitialise le cache d'instance Fernet
    tc._fernet = None
    tc._fernet_key = None
    return tc


def test_round_trip(_key):
    secret = "JBSWY3DPEHPK3PXP"
    enc = _key.encrypt_totp_secret(secret)
    assert enc.startswith("totp:")
    assert enc != secret
    assert _key.decrypt_totp_secret(enc) == secret


def test_plaintext_legacy_is_returned_as_is(_key):
    # Un secret hérité (sans préfixe) est lisible tel quel
    legacy = "JBSWY3DPEHPK3PXP"
    assert _key.decrypt_totp_secret(legacy) == legacy


def test_encrypt_idempotent(_key):
    # Re-chiffrer une valeur déjà chiffrée ne double pas le préfixe
    enc = _key.encrypt_totp_secret("ABCD")
    again = _key.encrypt_totp_secret(enc)
    assert again == enc


def test_empty_passthrough(_key):
    assert _key.encrypt_totp_secret("") == ""
    assert _key.decrypt_totp_secret("") == ""
    assert _key.encrypt_totp_secret(None) is None


def test_wrong_key_fails_gracefully(monkeypatch):
    import auth.totp_crypto as tc
    importlib.reload(tc)
    tc._fernet = None; tc._fernet_key = None
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", "key-A-aaaaaaaaaaaaaaaaaaaaaaaa")
    enc = tc.encrypt_totp_secret("SECRET123")

    # Change la clé → le déchiffrement échoue mais ne lève pas (retourne "")
    monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", "key-B-bbbbbbbbbbbbbbbbbbbbbbbb")
    tc._fernet = None; tc._fernet_key = None
    assert tc.decrypt_totp_secret(enc) == ""


def test_two_secrets_differ(_key):
    a = _key.encrypt_totp_secret("AAAA")
    b = _key.encrypt_totp_secret("BBBB")
    assert a != b
