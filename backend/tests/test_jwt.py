"""
Module : test_jwt.py
Rôle   : P1-B — Tests des tokens JWT (création, décodage, expiration)
         Vérifie create_access_token() et decode_token() sans passer
         par les routes HTTP.

Dépend : pytest, PyJWT
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_jwt_test_")
os.environ.setdefault("JWT_SECRET_KEY",       "test-secret-key-for-pytest-only")
os.environ.setdefault("JWT_EXPIRE_MINUTES",    "60")
os.environ.setdefault("MANIFEST_DIR",          _TMP)
os.environ.setdefault("POOL_DIR",              _TMP)
os.environ.setdefault("AUTH_DB_PATH",          f"{_TMP}/users.db")

# ── Imports normaux ────────────────────────────────────────────────────────────
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import jwt as jose_jwt  # PyJWT — API encode/decode identique à python-jose pour HS256
import pytest

from auth.jwt import create_access_token, decode_token
from auth.config import SECRET_KEY, ALGORITHM


# ═══════════════════════════════════════════════════════════════════════════════
# create_access_token()
# ═══════════════════════════════════════════════════════════════════════════════

class TestCreateAccessToken:

    def test_returns_string(self):
        """create_access_token() retourne une chaîne (JWT encodé)."""
        token = create_access_token({"sub": "alice", "role": "admin"})
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_has_three_parts(self):
        """Un JWT valide a exactement 3 parties séparées par des points."""
        token = create_access_token({"sub": "alice", "role": "admin"})
        parts = token.split(".")
        assert len(parts) == 3, f"JWT malformé : {token[:30]}…"

    def test_token_contains_sub(self):
        """Le payload contient le champ sub."""
        token = create_access_token({"sub": "bob", "role": "reader"})
        payload = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == "bob"

    def test_token_contains_role(self):
        """Le payload contient le champ role."""
        token = create_access_token({"sub": "carol", "role": "auditor"})
        payload = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["role"] == "auditor"

    def test_token_contains_expiration(self):
        """Le payload contient exp (timestamp d'expiration futur)."""
        token = create_access_token({"sub": "alice", "role": "admin"})
        payload = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert "exp" in payload
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        assert exp > datetime.now(timezone.utc)

    def test_expiration_is_approximately_correct(self):
        """L'expiration est dans JWT_EXPIRE_MINUTES ± 1 minute."""
        import auth.config as cfg
        token = create_access_token({"sub": "alice", "role": "admin"})
        payload = jose_jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        now = datetime.now(timezone.utc)
        delta = (exp - now).total_seconds() / 60
        assert cfg.ACCESS_TOKEN_EXPIRE_MINUTES - 1 <= delta <= cfg.ACCESS_TOKEN_EXPIRE_MINUTES + 1

    def test_two_tokens_for_same_user_differ_if_time_differs(self):
        """
        Deux tokens créés à des instants différents ont des exp différentes
        → tokens différents.
        """
        t1 = create_access_token({"sub": "alice", "role": "admin"})
        # Simuler 1 seconde d'écart
        future = datetime.now(timezone.utc) + timedelta(seconds=1)
        with patch("auth.jwt.datetime") as mock_dt:
            mock_dt.now.return_value = future
            mock_dt.side_effect = None
            t2 = create_access_token({"sub": "alice", "role": "admin"})
        assert t1 != t2


# ═══════════════════════════════════════════════════════════════════════════════
# decode_token()
# ═══════════════════════════════════════════════════════════════════════════════

class TestDecodeToken:

    def test_valid_token_returns_dict(self):
        """Token valide → dict avec username et role."""
        token = create_access_token({"sub": "alice", "role": "admin"})
        result = decode_token(token)
        assert result is not None
        assert result["username"] == "alice"
        assert result["role"] == "admin"

    def test_full_name_included_if_present(self):
        """full_name est inclus dans le résultat si présent dans le payload."""
        token = create_access_token({"sub": "alice", "role": "admin", "full_name": "Alice Martin"})
        result = decode_token(token)
        assert result["full_name"] == "Alice Martin"

    def test_full_name_defaults_to_empty_string(self):
        """full_name vaut '' si absent du payload."""
        token = create_access_token({"sub": "bob", "role": "reader"})
        result = decode_token(token)
        assert result["full_name"] == ""

    def test_invalid_token_returns_none(self):
        """Token invalide (chaîne aléatoire) → None, pas d'exception."""
        assert decode_token("this.is.not.a.valid.jwt") is None

    def test_empty_string_returns_none(self):
        """Chaîne vide → None."""
        assert decode_token("") is None

    def test_tampered_signature_returns_none(self):
        """Token avec signature modifiée → None."""
        token = create_access_token({"sub": "alice", "role": "admin"})
        # Modifier le premier caractère de la partie signature (après le 2e point).
        # NOTE : changer uniquement le DERNIER caractère base64url est non fiable
        # car les 2 bits de padding peuvent être ignorés par le décodeur → faux positif.
        parts = token.split(".")
        sig = parts[2]
        new_first = "A" if sig[0] != "A" else "B"
        tampered = ".".join(parts[:2] + [new_first + sig[1:]])
        assert decode_token(tampered) is None

    def test_wrong_secret_returns_none(self):
        """Token signé avec un autre secret → None."""
        token = jose_jwt.encode(
            {"sub": "hacker", "role": "admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            "wrong-secret",
            algorithm=ALGORITHM,
        )
        assert decode_token(token) is None

    def test_expired_token_returns_none(self):
        """Token expiré → None."""
        # Créer un token déjà expiré
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        expired_token = jose_jwt.encode(
            {"sub": "alice", "role": "admin", "exp": past},
            SECRET_KEY,
            algorithm=ALGORITHM,
        )
        assert decode_token(expired_token) is None

    def test_token_without_sub_returns_none(self):
        """Token sans champ 'sub' → None (utilisateur non identifiable)."""
        token = jose_jwt.encode(
            {"role": "admin", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            SECRET_KEY,
            algorithm=ALGORITHM,
        )
        assert decode_token(token) is None

    def test_role_defaults_to_reader(self):
        """Token sans champ role → role='reader' par défaut."""
        token = jose_jwt.encode(
            {"sub": "unknown_role_user", "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
            SECRET_KEY,
            algorithm=ALGORITHM,
        )
        result = decode_token(token)
        assert result is not None
        assert result["role"] == "reader"
