"""
Module : test_settings_encryption.py
Rôle   : Sprint 3 — Tests du chiffrement Fernet des secrets dans settings.json.

Scénarios couverts :
  - Dérivation de clé déterministe via HKDF-SHA256
  - Chiffrement d'un secret → préfixe 'enc:'
  - Déchiffrement transparent du préfixe 'enc:'
  - Valeur en clair passthrough (rétrocompatibilité)
  - Chaîne vide non chiffrée
  - Mauvaise JWT_SECRET_KEY → retourne chaîne vide (pas d'exception)
  - _encrypt_secrets / _decrypt_secrets sur dicts imbriqués
  - update_settings chiffre sur le disque
  - get_settings déchiffre de manière transparente
  - Seuls smtp_password, bind_password, client_secret sont chiffrés
  - Champs non-secret non modifiés

Dépend : pytest
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_settings_enc_test_")
os.environ["JWT_SECRET_KEY"] = "test-hkdf-key-for-settings-encrypt"
os.environ["SETTINGS_PATH"]  = f"{_TMP}/settings.json"
os.environ.setdefault("AUTH_DB_PATH",  f"{_TMP}/users.db")
os.environ.setdefault("MANIFEST_DIR",  _TMP)
os.environ.setdefault("POOL_DIR",      _TMP)

# ── Imports ───────────────────────────────────────────────────────────────────
import importlib
import json
from pathlib import Path

import pytest

import services.settings as settings_mod
importlib.reload(settings_mod)   # force reload avec les bonnes env vars


# ════════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════════

def _fresh_path(name: str = "settings.json") -> Path:
    """Retourne un chemin settings.json unique pour chaque test."""
    p = Path(_TMP) / name
    p.unlink(missing_ok=True)
    return p


def _set_settings_path(path: Path):
    settings_mod.SETTINGS_PATH = path
    # Invalider le cache Fernet si nécessaire
    settings_mod._fernet_instance = None


# ════════════════════════════════════════════════════════════════════════════════
# Tests primitives de chiffrement
# ════════════════════════════════════════════════════════════════════════════════

class TestEncryptDecryptPrimitives:

    def test_encrypt_returns_enc_prefix(self):
        """_encrypt_value retourne une chaîne commençant par 'enc:'."""
        enc = settings_mod._encrypt_value("my-secret")
        assert enc.startswith("enc:"), f"Préfixe manquant : {enc[:30]}"

    def test_encrypt_decrypt_roundtrip(self):
        """_decrypt_value(_encrypt_value(x)) == x."""
        for secret in ["password123", "p@$$w0rd!", "résumé-secret", "a" * 200]:
            enc = settings_mod._encrypt_value(secret)
            assert settings_mod._decrypt_value(enc) == secret

    def test_encrypt_empty_string_passthrough(self):
        """_encrypt_value('') retourne '' sans chiffrement (pas de token vide)."""
        assert settings_mod._encrypt_value("") == ""

    def test_decrypt_plaintext_passthrough(self):
        """_decrypt_value sans préfixe 'enc:' retourne la valeur telle quelle."""
        assert settings_mod._decrypt_value("plain-password") == "plain-password"
        assert settings_mod._decrypt_value("") == ""

    def test_ciphertext_is_not_plaintext(self):
        """Le texte chiffré ne contient pas le secret en clair."""
        secret = "ultra-secret-password"
        enc = settings_mod._encrypt_value(secret)
        assert secret not in enc

    def test_two_encryptions_differ(self):
        """Fernet est non-déterministe (IV aléatoire) → deux chiffrements diffèrent."""
        enc1 = settings_mod._encrypt_value("same-secret")
        enc2 = settings_mod._encrypt_value("same-secret")
        assert enc1 != enc2

    def test_wrong_key_returns_empty_string(self):
        """Déchiffrement avec une mauvaise clé → '' (pas d'exception)."""
        enc = settings_mod._encrypt_value("secret")
        # Changer la clé temporairement
        old_key = os.environ["JWT_SECRET_KEY"]
        os.environ["JWT_SECRET_KEY"] = "completely-different-key-xyz"
        settings_mod._fernet_instance = None  # invalider le cache
        result = settings_mod._decrypt_value(enc)
        # Restaurer
        os.environ["JWT_SECRET_KEY"] = old_key
        settings_mod._fernet_instance = None
        assert result == "", f"Attendu '', obtenu {result!r}"

    def test_hkdf_key_is_deterministic(self):
        """La même JWT_SECRET_KEY produit toujours le même Fernet (clé déterministe)."""
        settings_mod._fernet_instance = None
        f1 = settings_mod._get_fernet()
        settings_mod._fernet_instance = None
        f2 = settings_mod._get_fernet()
        # Chiffrer avec f1, déchiffrer avec f2
        token = f1.encrypt(b"test-determinism")
        assert f2.decrypt(token) == b"test-determinism"


# ════════════════════════════════════════════════════════════════════════════════
# Tests SETTINGS_ENCRYPTION_KEY (clé dédiée + repli legacy JWT_SECRET_KEY)
# ════════════════════════════════════════════════════════════════════════════════

class TestSettingsEncryptionKey:

    def _reset_caches(self):
        settings_mod._fernet_instance = None
        settings_mod._fernet_key_used = None
        settings_mod._legacy_fernet_instance = None
        settings_mod._legacy_fernet_key_used = None

    def teardown_method(self):
        os.environ.pop("SETTINGS_ENCRYPTION_KEY", None)
        self._reset_caches()

    def test_uses_settings_encryption_key_when_set(self):
        """Si SETTINGS_ENCRYPTION_KEY est défini, il prime sur JWT_SECRET_KEY."""
        os.environ["SETTINGS_ENCRYPTION_KEY"] = "dedicated-settings-key"
        self._reset_caches()
        enc = settings_mod._encrypt_value("secret")
        assert settings_mod._decrypt_value(enc) == "secret"

        # Une JWT_SECRET_KEY différente ne casse pas le déchiffrement
        old_jwt = os.environ["JWT_SECRET_KEY"]
        os.environ["JWT_SECRET_KEY"] = "rotated-jwt-key"
        self._reset_caches()
        assert settings_mod._decrypt_value(enc) == "secret"
        os.environ["JWT_SECRET_KEY"] = old_jwt

    def test_legacy_fallback_decrypts_value_encrypted_with_jwt_secret(self):
        """Une valeur chiffrée avant l'introduction de SETTINGS_ENCRYPTION_KEY
        (avec JWT_SECRET_KEY) reste déchiffrable une fois SETTINGS_ENCRYPTION_KEY défini."""
        self._reset_caches()
        enc = settings_mod._encrypt_value("legacy-secret")  # chiffré avec JWT_SECRET_KEY

        os.environ["SETTINGS_ENCRYPTION_KEY"] = "dedicated-settings-key"
        self._reset_caches()
        assert settings_mod._decrypt_value(enc) == "legacy-secret"

    def test_unrecoverable_value_returns_empty_string(self):
        """Valeur chiffrée avec une clé totalement différente → '' (pas d'exception)."""
        old_jwt = os.environ["JWT_SECRET_KEY"]
        os.environ["JWT_SECRET_KEY"] = "some-other-key"
        self._reset_caches()
        enc = settings_mod._encrypt_value("unrecoverable")
        os.environ["JWT_SECRET_KEY"] = old_jwt

        os.environ["SETTINGS_ENCRYPTION_KEY"] = "dedicated-settings-key"
        self._reset_caches()
        assert settings_mod._decrypt_value(enc) == ""


# ════════════════════════════════════════════════════════════════════════════════
# Tests _walk_secrets (_encrypt_secrets / _decrypt_secrets)
# ════════════════════════════════════════════════════════════════════════════════

class TestWalkSecrets:

    def test_smtp_password_encrypted(self):
        """smtp_password est chiffré."""
        data = {"email": {"smtp_host": "smtp.example.com", "smtp_password": "secret"}}
        out = settings_mod._encrypt_secrets(data)
        assert out["email"]["smtp_password"].startswith("enc:")

    def test_bind_password_encrypted(self):
        """bind_password est chiffré."""
        data = {"ldap": {"bind_dn": "cn=admin,dc=example,dc=com", "bind_password": "ldap-secret"}}
        out = settings_mod._encrypt_secrets(data)
        assert out["ldap"]["bind_password"].startswith("enc:")

    def test_client_secret_encrypted(self):
        """client_secret est chiffré."""
        data = {"oidc": {"client_id": "my-app", "client_secret": "oidc-secret"}}
        out = settings_mod._encrypt_secrets(data)
        assert out["oidc"]["client_secret"].startswith("enc:")

    def test_non_secret_fields_unchanged(self):
        """Les champs non-secret ne sont pas modifiés."""
        data = {
            "email": {"smtp_host": "smtp.example.com", "smtp_port": 587, "smtp_password": "pw"},
            "ldap":  {"host": "ldap.internal", "port": 389, "bind_password": "lp"},
        }
        out = settings_mod._encrypt_secrets(data)
        assert out["email"]["smtp_host"] == "smtp.example.com"
        assert out["email"]["smtp_port"] == 587
        assert out["ldap"]["host"] == "ldap.internal"
        assert out["ldap"]["port"] == 389

    def test_encrypt_decrypt_nested_roundtrip(self):
        """Aller-retour complet sur un dict imbriqué multi-niveaux."""
        data = {
            "email": {"smtp_password": "mail-secret", "smtp_host": "host"},
            "ldap":  {"bind_password": "ldap-secret", "bind_dn": "cn=x"},
            "oidc":  {"client_secret": "oidc-secret", "client_id": "app"},
        }
        encrypted = settings_mod._encrypt_secrets(data)
        decrypted = settings_mod._decrypt_secrets(encrypted)
        assert decrypted["email"]["smtp_password"] == "mail-secret"
        assert decrypted["ldap"]["bind_password"]  == "ldap-secret"
        assert decrypted["oidc"]["client_secret"]  == "oidc-secret"
        # Non-secrets inchangés
        assert decrypted["email"]["smtp_host"]  == "host"
        assert decrypted["ldap"]["bind_dn"]     == "cn=x"
        assert decrypted["oidc"]["client_id"]   == "app"

    def test_empty_secret_not_encrypted(self):
        """Un secret vide n'est pas chiffré (champ vide inchangé)."""
        data = {"email": {"smtp_password": ""}}
        out = settings_mod._encrypt_secrets(data)
        assert out["email"]["smtp_password"] == ""

    def test_plaintext_secret_decrypts_as_is(self):
        """Une valeur en clair sans préfixe 'enc:' est retournée telle quelle (rétrocompat)."""
        data = {"email": {"smtp_password": "plain-old-password"}}
        out = settings_mod._decrypt_secrets(data)
        assert out["email"]["smtp_password"] == "plain-old-password"


# ════════════════════════════════════════════════════════════════════════════════
# Tests intégration : update_settings / get_settings
# ════════════════════════════════════════════════════════════════════════════════

class TestSettingsFileEncryption:

    @pytest.fixture(autouse=True)
    def use_tmp_path(self, tmp_path):
        """Chaque test utilise son propre fichier settings.json."""
        _set_settings_path(tmp_path / "settings.json")
        yield
        _set_settings_path(_fresh_path("settings.json"))

    def test_update_settings_encrypts_on_disk(self):
        """update_settings écrit les secrets chiffrés sur le disque."""
        settings_mod.update_settings({
            "email": {"smtp_password": "disk-secret", "smtp_host": "host.example.com"},
        })
        raw = json.loads(settings_mod.SETTINGS_PATH.read_text())
        assert raw["email"]["smtp_password"].startswith("enc:"), (
            "smtp_password devrait être chiffré sur le disque"
        )

    def test_update_settings_does_not_encrypt_empty(self):
        """Un secret vide reste vide sur le disque (pas de 'enc:' pour chaîne vide)."""
        settings_mod.update_settings({"email": {"smtp_password": ""}})
        raw = json.loads(settings_mod.SETTINGS_PATH.read_text())
        assert raw["email"]["smtp_password"] == ""

    def test_update_settings_returns_decrypted(self):
        """update_settings retourne les paramètres déchiffrés (pas le contenu du disque)."""
        result = settings_mod.update_settings({
            "email": {"smtp_password": "return-secret"},
        })
        assert result["email"]["smtp_password"] == "return-secret"

    def test_get_settings_decrypts_transparently(self):
        """get_settings lit le fichier et déchiffre les secrets automatiquement."""
        settings_mod.update_settings({"email": {"smtp_password": "transparent-secret"}})
        loaded = settings_mod.get_settings()
        assert loaded["email"]["smtp_password"] == "transparent-secret"

    def test_non_secret_fields_unchanged_on_disk(self):
        """Les champs non-secret sont écrits en clair sur le disque."""
        settings_mod.update_settings({
            "email": {"smtp_host": "smtp.internal", "smtp_port": 465, "smtp_password": "pw"},
        })
        raw = json.loads(settings_mod.SETTINGS_PATH.read_text())
        assert raw["email"]["smtp_host"] == "smtp.internal"
        assert raw["email"]["smtp_port"] == 465

    def test_plaintext_secret_on_disk_is_decrypted_as_is(self):
        """
        Un secret en clair dans un vieux settings.json est retourné tel quel
        (rétrocompatibilité — sera chiffré à la prochaine écriture).
        """
        # Écrire manuellement un settings sans chiffrement
        legacy = {"email": {"smtp_password": "old-plain-text", "smtp_host": "h"}}
        settings_mod.SETTINGS_PATH.write_text(json.dumps(legacy))
        loaded = settings_mod.get_settings()
        assert loaded["email"]["smtp_password"] == "old-plain-text"

    def test_rewrite_migrates_plaintext_to_encrypted(self):
        """
        Lire un settings en clair puis le réécrire → le secret est chiffré.
        Simule la migration automatique au premier update post-déploiement.
        """
        legacy = {"email": {"smtp_password": "migrate-me", "smtp_host": "h"}}
        settings_mod.SETTINGS_PATH.write_text(json.dumps(legacy))
        # Un update (même vide) déclenche une écriture avec chiffrement
        settings_mod.update_settings({"app_url": "http://localhost:3003"})
        raw = json.loads(settings_mod.SETTINGS_PATH.read_text())
        assert raw["email"]["smtp_password"].startswith("enc:"), (
            "Le mot de passe devrait être chiffré après réécriture"
        )

    def test_all_three_secrets_encrypted_together(self):
        """Les trois champs secrets sont tous chiffrés dans le même fichier."""
        settings_mod.update_settings({
            "email": {"smtp_password": "mail-pw"},
            "ldap":  {"bind_password": "ldap-pw"},
            "oidc":  {"client_secret": "oidc-sec"},
        })
        raw = json.loads(settings_mod.SETTINGS_PATH.read_text())
        assert raw["email"]["smtp_password"].startswith("enc:")
        assert raw["ldap"]["bind_password"].startswith("enc:")
        assert raw["oidc"]["client_secret"].startswith("enc:")

    def test_settings_path_missing_returns_defaults(self):
        """Pas de fichier settings.json → retourne les valeurs par défaut."""
        settings_mod.SETTINGS_PATH.unlink(missing_ok=True)
        defaults = settings_mod.get_settings()
        assert defaults["email"]["smtp_password"] == ""
