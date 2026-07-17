# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_jwt_revocation.py
Rôle   : Révocation de JWT (table revoked_tokens, claim jti, POST /auth/logout)

Vérifie :
  - create_access_token() embarque un claim 'jti' unique
  - decode_token() retourne 'jti' dans le résultat
  - revoke_jti() + is_revoked() (auth.token_revocation)
  - decode_token() rejette un token dont le jti est révoqué
  - get_token_claims() décode sans vérifier la révocation (idempotence logout)
  - purge_expired() supprime les entrées expirées
  - POST /auth/logout révoque le JWT courant (test d'intégration HTTP)

Dépend : pytest, PyJWT (autouse db_test_engine fixture de conftest.py)
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_jwt_revoc_test_")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-pytest-only")
os.environ.setdefault("JWT_EXPIRE_MINUTES", "60")
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR", _TMP)
os.environ.setdefault("AUDIT_DIR", _TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
from datetime import datetime, timedelta, timezone

import pytest

from auth.jwt import create_access_token, decode_token, get_token_claims
from auth.token_revocation import revoke_jti, is_revoked, purge_expired


# ═══════════════════════════════════════════════════════════════════════════════
# create_access_token() — claim jti
# ═══════════════════════════════════════════════════════════════════════════════

class TestJtiClaim:

    def test_token_has_jti_claim(self):
        token = create_access_token({"sub": "alice", "role": "admin"})
        claims = get_token_claims(token)
        assert claims is not None
        assert "jti" in claims
        assert len(claims["jti"]) > 0

    def test_two_tokens_have_different_jti(self):
        t1 = create_access_token({"sub": "alice", "role": "admin"})
        t2 = create_access_token({"sub": "alice", "role": "admin"})
        c1, c2 = get_token_claims(t1), get_token_claims(t2)
        assert c1["jti"] != c2["jti"]

    def test_decode_token_includes_jti(self):
        token = create_access_token({"sub": "alice", "role": "admin"})
        result = decode_token(token)
        assert result is not None
        assert "jti" in result
        assert result["jti"] == get_token_claims(token)["jti"]


# ═══════════════════════════════════════════════════════════════════════════════
# auth.token_revocation — revoke_jti / is_revoked / purge_expired
# ═══════════════════════════════════════════════════════════════════════════════

class TestTokenRevocationService:

    def test_jti_not_revoked_by_default(self):
        assert is_revoked("some-random-jti-not-in-db") is False

    def test_revoke_then_is_revoked(self):
        jti = "test-jti-revoke-001"
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        revoke_jti(jti, "alice", future)
        assert is_revoked(jti) is True

    def test_revoke_idempotent(self):
        """Révoquer deux fois le même jti ne lève pas d'exception (ON CONFLICT DO NOTHING)."""
        jti = "test-jti-revoke-idempotent"
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        revoke_jti(jti, "alice", future)
        revoke_jti(jti, "alice", future)  # ne doit pas lever
        assert is_revoked(jti) is True

    def test_revoke_empty_jti_is_noop(self):
        """jti vide/None → noop, pas d'exception."""
        revoke_jti("", "alice", datetime.now(timezone.utc))
        assert is_revoked("") is False
        assert is_revoked(None) is False

    def test_purge_expired_removes_old_entries(self):
        jti = "test-jti-expired-001"
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        revoke_jti(jti, "alice", past)
        assert is_revoked(jti) is True

        deleted = purge_expired()
        assert deleted >= 1
        assert is_revoked(jti) is False

    def test_purge_expired_keeps_future_entries(self):
        jti = "test-jti-future-001"
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        revoke_jti(jti, "alice", future)

        purge_expired()
        assert is_revoked(jti) is True


# ═══════════════════════════════════════════════════════════════════════════════
# decode_token() rejette les tokens révoqués
# ═══════════════════════════════════════════════════════════════════════════════

class TestDecodeTokenRevocation:

    def test_decode_token_rejects_revoked_jti(self):
        token = create_access_token({"sub": "bob", "role": "reader"})
        claims = get_token_claims(token)

        # Avant révocation : décodage OK
        assert decode_token(token) is not None

        # Révoquer le jti
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        revoke_jti(claims["jti"], "bob", future)

        # Après révocation : decode_token retourne None
        assert decode_token(token) is None

    def test_get_token_claims_works_after_revocation(self):
        """get_token_claims() ignore la révocation — utilisé pour le logout idempotent."""
        token = create_access_token({"sub": "carol", "role": "reader"})
        claims = get_token_claims(token)
        future = datetime.now(timezone.utc) + timedelta(hours=1)
        revoke_jti(claims["jti"], "carol", future)

        # decode_token → None (révoqué), mais get_token_claims fonctionne toujours
        assert decode_token(token) is None
        assert get_token_claims(token)["sub"] == "carol"


# ═══════════════════════════════════════════════════════════════════════════════
# POST /auth/logout — test d'intégration HTTP
# ═══════════════════════════════════════════════════════════════════════════════

class TestLogoutEndpoint:

    @pytest.fixture
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from auth.router import router as auth_router
        from auth.users import create_user, get_user_any

        # Le moteur SQLite in-memory autouse (db_test_engine, conftest.py) utilise
        # StaticPool + check_same_thread=False — partageable avec le thread
        # FastAPI TestClient (decode_token() interroge revoked_tokens à chaque requête).
        if not get_user_any("logout_user"):
            create_user("logout_user", "Str0ngP@ssw0rd!", role="reader")

        app = FastAPI()
        app.include_router(auth_router)
        return TestClient(app)

    def test_logout_revokes_token(self, client):
        token = create_access_token({"sub": "logout_user", "role": "reader"})
        claims = get_token_claims(token)

        resp = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "logged_out"

        assert is_revoked(claims["jti"]) is True
        # Le token est désormais rejeté
        assert decode_token(token) is None

    def test_logout_without_token_returns_401(self, client):
        resp = client.post("/auth/logout")
        assert resp.status_code == 401

    def test_logout_revoked_token_is_idempotent(self, client):
        """Appeler /auth/logout deux fois avec le même token ne doit pas lever d'erreur."""
        token = create_access_token({"sub": "logout_user", "role": "reader"})
        first = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert first.status_code == 200

        # Le 2e appel échoue à 401 car decode_token rejette désormais le token révoqué
        # (get_current_user_full dépend de decode_token via _parse_token)
        second = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert second.status_code == 401
