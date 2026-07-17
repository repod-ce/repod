"""
Module : test_mfa_totp.py
Rôle   : P2-3 — MFA TOTP
         Vérifie auth/mfa.py (service TOTP), les colonnes MFA dans users,
         le token temporaire MFA dans auth/jwt.py, et la présence des
         endpoints dans auth/router.py (source inspection).

Flux attendu :
  1. POST /api/v1/auth/token     → si MFA activé : {mfa_required:true, mfa_token}
  2. POST /api/v1/auth/mfa/authenticate → {mfa_token, totp_code} → {access_token}

Dépend : pytest, pyotp, PyJWT
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_mfa_test_")
os.environ["AUTH_DB_PATH"]   = f"{_TMP}/users.db"
os.environ["JWT_SECRET_KEY"] = "mfa-test-secret-key-for-pytest"
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR",     _TMP)
os.environ.setdefault("SECURITY_CACHE_DIR", _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
import base64
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

import jwt as jose_jwt  # PyJWT — API encode/decode identique à python-jose pour HS256
import pyotp
import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# Source inspection — auth/router.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestRouterMfaEndpoints:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "auth" / "router.py"
        assert p.exists()
        return p.read_text()

    def test_mfa_setup_endpoint_present(self):
        """
        ❌ ROUGE avant fix : endpoint /mfa/setup absent
        ✅ VERT après fix  : POST /mfa/setup présent dans auth/router.py
        """
        assert "/mfa/setup" in self._src(), (
            "auth/router.py doit définir POST /mfa/setup (P2-3)"
        )

    def test_mfa_confirm_endpoint_present(self):
        """POST /mfa/confirm doit être présent pour activer le MFA après vérification."""
        assert "/mfa/confirm" in self._src(), (
            "auth/router.py doit définir POST /mfa/confirm"
        )

    def test_mfa_authenticate_endpoint_present(self):
        """POST /mfa/authenticate — step 2 du login (submit TOTP code)."""
        assert "/mfa/authenticate" in self._src(), (
            "auth/router.py doit définir POST /mfa/authenticate"
        )

    def test_mfa_disable_endpoint_present(self):
        """POST /mfa/disable — désactiver le MFA."""
        assert "/mfa/disable" in self._src(), (
            "auth/router.py doit définir POST /mfa/disable"
        )

    def test_login_handles_mfa_required(self):
        """login() doit tester si MFA est activé et retourner mfa_required."""
        assert "mfa_required" in self._src(), (
            "auth/router.py doit gérer mfa_required dans la route de login"
        )

    def test_mfa_service_imported_in_router(self):
        """auth.mfa est importé dans router.py."""
        src = self._src()
        assert "from .mfa import" in src or "from auth.mfa import" in src or "import mfa" in src, (
            "router.py doit importer le service MFA"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# auth/mfa.py — module service
# ═══════════════════════════════════════════════════════════════════════════════

class TestMfaModule:

    def test_module_exists(self):
        """
        ❌ ROUGE avant fix : auth/mfa.py n'existe pas
        ✅ VERT après fix  : module présent
        """
        p = Path(__file__).parent.parent / "auth" / "mfa.py"
        assert p.exists(), "auth/mfa.py doit être créé (P2-3)"

    def test_generate_totp_secret_importable(self):
        """generate_totp_secret() doit être importable."""
        from auth.mfa import generate_totp_secret
        assert callable(generate_totp_secret)

    def test_verify_totp_importable(self):
        """verify_totp() doit être importable."""
        from auth.mfa import verify_totp
        assert callable(verify_totp)

    def test_get_totp_uri_importable(self):
        """get_totp_uri() doit être importable."""
        from auth.mfa import get_totp_uri
        assert callable(get_totp_uri)

    def test_generate_qr_code_base64_importable(self):
        """generate_qr_code_base64() doit être importable."""
        from auth.mfa import generate_qr_code_base64
        assert callable(generate_qr_code_base64)


# ═══════════════════════════════════════════════════════════════════════════════
# generate_totp_secret()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateTotpSecret:

    def test_returns_string(self):
        """Retourne une chaîne non vide."""
        from auth.mfa import generate_totp_secret
        secret = generate_totp_secret()
        assert isinstance(secret, str)
        assert len(secret) > 0

    def test_secret_is_valid_base32(self):
        """Le secret est encodé en base32 (peut être utilisé par pyotp)."""
        from auth.mfa import generate_totp_secret
        secret = generate_totp_secret()
        # pyotp doit pouvoir créer un TOTP avec ce secret
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert code.isdigit() and len(code) == 6

    def test_two_secrets_differ(self):
        """Chaque appel génère un secret différent."""
        from auth.mfa import generate_totp_secret
        s1 = generate_totp_secret()
        s2 = generate_totp_secret()
        assert s1 != s2

    def test_secret_is_at_least_16_chars(self):
        """RFC 6238 recommande au moins 16 bytes (≈ 26 chars base32)."""
        from auth.mfa import generate_totp_secret
        secret = generate_totp_secret()
        assert len(secret) >= 16


# ═══════════════════════════════════════════════════════════════════════════════
# verify_totp()
# ═══════════════════════════════════════════════════════════════════════════════

class TestVerifyTotp:

    def test_valid_code_returns_true(self):
        """
        ❌ ROUGE avant fix : verify_totp n'existe pas
        ✅ VERT après fix  : code TOTP courant → True
        """
        from auth.mfa import verify_totp
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        assert verify_totp(secret, current_code) is True

    def test_wrong_code_returns_false(self):
        """Code TOTP incorrect → False."""
        from auth.mfa import verify_totp
        secret = pyotp.random_base32()
        assert verify_totp(secret, "000000") is False

    def test_returns_bool(self):
        """Retourne un bool strict (pas juste truthy)."""
        from auth.mfa import verify_totp
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        result = verify_totp(secret, totp.now())
        assert isinstance(result, bool)

    def test_malformed_code_returns_false(self):
        """Code non numérique ou mauvaise longueur → False, pas d'exception."""
        from auth.mfa import verify_totp
        secret = pyotp.random_base32()
        assert verify_totp(secret, "abc") is False
        assert verify_totp(secret, "") is False
        assert verify_totp(secret, "12345678") is False

    def test_invalid_secret_returns_false(self):
        """Secret invalide → False, pas d'exception."""
        from auth.mfa import verify_totp
        assert verify_totp("not-valid-base32!!!", "123456") is False


# ═══════════════════════════════════════════════════════════════════════════════
# get_totp_uri()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGetTotpUri:

    def test_uri_scheme(self):
        """L'URI commence par otpauth://totp/."""
        from auth.mfa import get_totp_uri
        secret = pyotp.random_base32()
        uri = get_totp_uri(secret, "alice", "repod")
        assert uri.startswith("otpauth://totp/"), f"URI incorrecte : {uri[:40]}"

    def test_uri_contains_username(self):
        """L'URI contient le nom d'utilisateur."""
        from auth.mfa import get_totp_uri
        secret = pyotp.random_base32()
        uri = get_totp_uri(secret, "bob", "repod")
        assert "bob" in uri

    def test_uri_contains_issuer(self):
        """L'URI contient l'émetteur (issuer)."""
        from auth.mfa import get_totp_uri
        secret = pyotp.random_base32()
        uri = get_totp_uri(secret, "alice", "MyApp")
        assert "MyApp" in uri

    def test_uri_contains_secret(self):
        """L'URI contient le secret."""
        from auth.mfa import get_totp_uri
        secret = pyotp.random_base32()
        uri = get_totp_uri(secret, "alice", "repod")
        assert secret in uri


# ═══════════════════════════════════════════════════════════════════════════════
# generate_qr_code_base64()
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateQrCodeBase64:

    def test_returns_non_empty_string(self):
        """
        ❌ ROUGE avant fix : generate_qr_code_base64 n'existe pas
        ✅ VERT après fix  : retourne une chaîne base64 non vide
        """
        from auth.mfa import generate_qr_code_base64, get_totp_uri
        secret = pyotp.random_base32()
        uri = get_totp_uri(secret, "alice", "repod")
        b64 = generate_qr_code_base64(uri)
        assert isinstance(b64, str)
        assert len(b64) > 0

    def test_output_is_valid_base64(self):
        """La sortie est du base64 valide (décodable)."""
        from auth.mfa import generate_qr_code_base64, get_totp_uri
        secret = pyotp.random_base32()
        uri = get_totp_uri(secret, "alice", "repod")
        b64 = generate_qr_code_base64(uri)
        # Ne doit pas lever d'exception
        decoded = base64.b64decode(b64)
        assert len(decoded) > 0

    def test_output_is_png(self):
        """Le contenu décodé est un PNG (magic bytes \\x89PNG)."""
        from auth.mfa import generate_qr_code_base64, get_totp_uri
        secret = pyotp.random_base32()
        uri = get_totp_uri(secret, "alice", "repod")
        b64 = generate_qr_code_base64(uri)
        decoded = base64.b64decode(b64)
        assert decoded[:4] == b"\x89PNG", "Le QR code doit être un PNG"


# ═══════════════════════════════════════════════════════════════════════════════
# auth/jwt.py — create_mfa_token()
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateMfaToken:

    def test_create_mfa_token_importable(self):
        """
        ❌ ROUGE avant fix : create_mfa_token n'existe pas dans auth/jwt.py
        ✅ VERT après fix  : importable et appelable
        """
        from auth.jwt import create_mfa_token
        assert callable(create_mfa_token)

    def test_mfa_token_is_string(self):
        """Retourne une chaîne JWT."""
        from auth.jwt import create_mfa_token
        token = create_mfa_token("alice", "admin")
        assert isinstance(token, str)
        assert len(token.split(".")) == 3

    def test_mfa_token_has_mfa_scope(self):
        """Le payload contient scope='mfa_required'."""
        from auth.jwt import create_mfa_token
        from auth.config import SECRET_KEY, ALGORITHM
        token = create_mfa_token("alice", "admin")
        payload = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload.get("scope") == "mfa_required"

    def test_mfa_token_has_short_expiry(self):
        """Le token MFA expire dans ≤ 10 minutes (token temporaire)."""
        from auth.jwt import create_mfa_token
        from auth.config import SECRET_KEY, ALGORITHM
        token = create_mfa_token("alice", "admin")
        payload = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        delta_minutes = (exp - datetime.now(timezone.utc)).total_seconds() / 60
        assert delta_minutes <= 10, (
            f"Le token MFA doit expirer dans ≤ 10 minutes, obtenu : {delta_minutes:.1f}min"
        )

    def test_mfa_token_contains_username(self):
        """Le payload contient sub=username."""
        from auth.jwt import create_mfa_token
        from auth.config import SECRET_KEY, ALGORITHM
        token = create_mfa_token("bob", "reader")
        payload = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == "bob"
        assert payload["role"] == "reader"

    def test_regular_token_not_usable_as_mfa_token(self):
        """Un vrai JWT (scope absent) n'a pas le scope mfa_required."""
        from auth.jwt import create_access_token
        from auth.config import SECRET_KEY, ALGORITHM
        token = create_access_token({"sub": "alice", "role": "admin"})
        payload = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload.get("scope") != "mfa_required"


# ═══════════════════════════════════════════════════════════════════════════════
# auth/users.py — colonnes MFA
# ═══════════════════════════════════════════════════════════════════════════════

class TestUsersMfaColumns:

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "auth" / "users.py"
        assert p.exists()
        return p.read_text()

    def test_mfa_enabled_column_in_schema(self):
        """
        ❌ ROUGE avant fix : colonne mfa_enabled absente du schéma SQLite
        ✅ VERT après fix  : colonne présente dans init_db()
        """
        assert "mfa_enabled" in self._src(), (
            "auth/users.py doit ajouter la colonne mfa_enabled à la table users"
        )

    def test_totp_secret_column_in_schema(self):
        """Colonne totp_secret présente dans le schéma."""
        assert "totp_secret" in self._src(), (
            "auth/users.py doit ajouter la colonne totp_secret à la table users"
        )

    def test_get_mfa_info_function_exists(self):
        """Fonction get_mfa_info() ou équivalent présente dans users.py."""
        src = self._src()
        assert "mfa_info" in src or "get_mfa" in src or "set_mfa" in src or "enable_mfa" in src, (
            "auth/users.py doit exposer des fonctions de gestion MFA"
        )
