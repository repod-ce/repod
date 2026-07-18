"""
tests/test_security_sprint83.py — Audit sécurité Sprint 8.3

Couverture :
  SEC-1 — MFA token scope bypass (decode_token rejette scope=mfa_required)
  SEC-2 — Path traversal dans _path(pending_id)
  SEC-3 — Headers de sécurité HTTP (SecurityHeadersMiddleware)
  SEC-4 — Validation UUID v4 stricte (_validate_pending_id)

Chaque classe de test est indépendante et ne nécessite pas de vrai dépôt.
"""

import os
import re
import tempfile

_TMP = tempfile.mkdtemp(prefix="repod_sec83_")
os.environ.setdefault("PENDING_PROMOTIONS_DIR", os.path.join(_TMP, "pending"))
os.environ.setdefault("AUTH_DB_PATH",   os.path.join(_TMP, "users.db"))
os.environ.setdefault("MANIFEST_DIR",   _TMP)
os.environ.setdefault("POOL_DIR",       _TMP)
os.environ.setdefault("INVENTORY_DB",   os.path.join(_TMP, "inv.db"))
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-sprint83")

import pytest


# ═════════════════════════════════════════════════════════════════════════════
# SEC-1 — MFA token scope bypass
# ═════════════════════════════════════════════════════════════════════════════

class TestMfaScopeBypass:
    """
    Vérifie que decode_token() refuse les tokens portant scope='mfa_required'.
    Ces tokens intermédiaires ne doivent jamais donner accès aux endpoints.
    """

    def test_mfa_token_rejected_by_decode_token(self):
        """Un token MFA (scope=mfa_required) doit retourner None."""
        from auth.jwt import create_mfa_token, decode_token
        mfa_tok = create_mfa_token("alice", "admin")
        result = decode_token(mfa_tok)
        assert result is None, (
            "FAILLE SEC-1 : decode_token a accepté un token MFA intermédiaire "
            "(scope=mfa_required) — bypass d'authentification possible."
        )

    def test_normal_access_token_accepted(self):
        """Un token d'accès normal (sans scope) doit être accepté."""
        from auth.jwt import create_access_token, decode_token
        tok = create_access_token({"sub": "bob", "role": "maintainer"})
        result = decode_token(tok)
        assert result is not None
        assert result["username"] == "bob"
        assert result["role"] == "maintainer"

    def test_mfa_token_has_correct_scope(self):
        """Le token MFA doit bien contenir scope=mfa_required (pré-condition)."""
        import jwt as pyjwt
        from auth.jwt import create_mfa_token
        from auth.config import SECRET_KEY, ALGORITHM
        mfa_tok = create_mfa_token("carol", "reader")
        payload = pyjwt.decode(mfa_tok, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload.get("scope") == "mfa_required"

    def test_access_token_has_no_scope(self):
        """Un token d'accès normal ne doit pas avoir de scope."""
        import jwt as pyjwt
        from auth.jwt import create_access_token
        from auth.config import SECRET_KEY, ALGORITHM
        tok = create_access_token({"sub": "dave", "role": "admin"})
        payload = pyjwt.decode(tok, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload.get("scope") is None

    def test_tampered_token_with_scope_removed_rejected(self):
        """Un token forgé avec le payload d'un MFA mais scope absent ne passe pas
        car il ne peut pas être signé avec le bon secret."""
        import jwt as pyjwt
        from auth.jwt import decode_token
        # Forger un token avec secret différent → signature invalide
        fake = pyjwt.encode(
            {"sub": "eve", "role": "admin"},
            "wrong-secret",
            algorithm="HS256",
        )
        assert decode_token(fake) is None


# ═════════════════════════════════════════════════════════════════════════════
# SEC-2 — Path traversal dans _path(pending_id)
# ═════════════════════════════════════════════════════════════════════════════

class TestPathTraversal:
    """
    Vérifie que _path() et _validate_pending_id() bloquent toute tentative
    de traversal de chemin via le paramètre pending_id.
    """

    def test_valid_uuid_accepted(self):
        """Un UUID v4 valide doit être accepté sans erreur."""
        from services.pending_promotions import _validate_pending_id
        _validate_pending_id("550e8400-e29b-41d4-a716-446655440000")  # pas d'exception

    def test_traversal_dotdot_rejected(self):
        """../../../etc/passwd doit être rejeté."""
        from services.pending_promotions import _validate_pending_id
        with pytest.raises(ValueError, match="UUID v4"):
            _validate_pending_id("../../../etc/passwd")

    def test_traversal_slash_rejected(self):
        """Un pending_id contenant / doit être rejeté."""
        from services.pending_promotions import _validate_pending_id
        with pytest.raises(ValueError):
            _validate_pending_id("valid-prefix/../../shadow")

    def test_null_byte_rejected(self):
        """Un pending_id contenant un null byte doit être rejeté."""
        from services.pending_promotions import _validate_pending_id
        with pytest.raises(ValueError):
            _validate_pending_id("550e8400-e29b-41d4-a716-446655440000\x00.extra")

    def test_empty_string_rejected(self):
        """Une chaîne vide doit être rejetée."""
        from services.pending_promotions import _validate_pending_id
        with pytest.raises(ValueError):
            _validate_pending_id("")

    def test_uuid_v1_rejected(self):
        """Un UUID v1 (version≠4) doit être rejeté."""
        from services.pending_promotions import _validate_pending_id
        # UUID v1 : 4ème groupe commence par 1 au lieu de 4
        with pytest.raises(ValueError):
            _validate_pending_id("550e8400-e29b-11d4-a716-446655440000")

    def test_url_encoded_traversal_rejected(self):
        """%2F..%2F.. (URL-encodé) doit être rejeté."""
        from services.pending_promotions import _validate_pending_id
        with pytest.raises(ValueError):
            _validate_pending_id("%2F..%2F..%2Fetc%2Fpasswd")

    def test_path_stays_inside_pending_dir(self):
        """Le chemin résolu doit rester à l'intérieur de PENDING_DIR."""
        import os
        from services.pending_promotions import _path, PENDING_DIR
        p = _path("550e8400-e29b-41d4-a716-446655440000")
        pending_dir_resolved = str(PENDING_DIR.resolve())
        assert str(p).startswith(pending_dir_resolved), (
            f"Chemin {p!r} hors de PENDING_DIR {pending_dir_resolved!r}"
        )

    def test_get_pending_invalid_id_returns_none(self):
        """get_pending() avec un ID invalide retourne None (pas d'exception non gérée)."""
        from services.pending_promotions import get_pending
        # L'ID invalide lève ValueError dans _path → get_pending doit retourner None
        result = get_pending("../../../etc/passwd")
        assert result is None

    def test_update_pending_invalid_id_returns_none(self):
        """update_pending() avec un ID invalide retourne None."""
        from services.pending_promotions import update_pending
        result = update_pending("../../../etc/passwd", status="approved")
        assert result is None

    def test_delete_pending_invalid_id_returns_false(self):
        """delete_pending() avec un ID invalide retourne False."""
        from services.pending_promotions import delete_pending
        result = delete_pending("../../../etc/passwd")
        assert result is False


# ═════════════════════════════════════════════════════════════════════════════
# SEC-3 — Headers de sécurité HTTP
# ═════════════════════════════════════════════════════════════════════════════

class TestSecurityHeaders:
    """
    Vérifie que SecurityHeadersMiddleware injecte les bons headers sur
    chaque réponse via une micro-app ASGI de test.
    """

    @pytest.fixture(autouse=True)
    def _app(self):
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.responses import PlainTextResponse
        from starlette.testclient import TestClient
        from middleware.security_headers import SecurityHeadersMiddleware

        async def homepage(request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route("/", homepage)])
        app.add_middleware(SecurityHeadersMiddleware)
        self.client = TestClient(app, raise_server_exceptions=True)

    def test_x_content_type_options(self):
        r = self.client.get("/")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self):
        r = self.client.get("/")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_x_xss_protection(self):
        r = self.client.get("/")
        assert r.headers.get("X-XSS-Protection") == "1; mode=block"

    def test_referrer_policy(self):
        r = self.client.get("/")
        assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    def test_permissions_policy(self):
        r = self.client.get("/")
        pp = r.headers.get("Permissions-Policy", "")
        assert "geolocation=()" in pp
        assert "camera=()" in pp

    def test_cross_origin_opener_policy(self):
        r = self.client.get("/")
        assert r.headers.get("Cross-Origin-Opener-Policy") == "same-origin"

    def test_content_security_policy_present(self):
        """CSP-1 — un header CSP est présent (défense en profondeur API directe)."""
        r = self.client.get("/")
        csp = r.headers.get("Content-Security-Policy", "")
        assert csp != ""
        assert "frame-ancestors 'none'" in csp

    def test_content_security_policy_strict_in_production(self, monkeypatch):
        """En production (ENV=production), la CSP doit être 'default-src none'."""
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.responses import PlainTextResponse
        from starlette.testclient import TestClient
        import importlib
        import middleware.security_headers as shm

        monkeypatch.setenv("ENV", "production")
        importlib.reload(shm)

        async def homepage(request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route("/", homepage)])
        app.add_middleware(shm.SecurityHeadersMiddleware)
        client = TestClient(app)
        r = client.get("/")
        assert r.headers.get("Content-Security-Policy", "").startswith("default-src 'none'")

        monkeypatch.delenv("ENV", raising=False)
        importlib.reload(shm)

    def test_headers_not_override_existing(self):
        """setdefault ne doit pas écraser un header déjà positionné par la route."""
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.responses import PlainTextResponse
        from starlette.testclient import TestClient
        from middleware.security_headers import SecurityHeadersMiddleware

        async def custom(request):
            resp = PlainTextResponse("ok")
            resp.headers["X-Frame-Options"] = "SAMEORIGIN"  # valeur custom
            return resp

        app = Starlette(routes=[Route("/", custom)])
        app.add_middleware(SecurityHeadersMiddleware)
        client = TestClient(app)
        r = client.get("/")
        # Le middleware utilise setdefault → ne doit pas écraser
        assert r.headers.get("X-Frame-Options") == "SAMEORIGIN"

    def test_disabled_via_env(self, monkeypatch):
        """SECURITY_HEADERS_DISABLED=1 désactive l'injection des headers."""
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.responses import PlainTextResponse
        from starlette.testclient import TestClient
        import importlib
        import middleware.security_headers as shm

        monkeypatch.setenv("SECURITY_HEADERS_DISABLED", "1")
        # Recharger le module pour prendre en compte la variable
        importlib.reload(shm)

        async def homepage(request):
            return PlainTextResponse("ok")

        app = Starlette(routes=[Route("/", homepage)])
        app.add_middleware(shm.SecurityHeadersMiddleware)
        client = TestClient(app)
        r = client.get("/")
        assert "X-Frame-Options" not in r.headers

        # Remettre la variable à 0 pour ne pas polluer les autres tests
        monkeypatch.delenv("SECURITY_HEADERS_DISABLED")
        importlib.reload(shm)


# ═════════════════════════════════════════════════════════════════════════════
# SEC-4 — Validation UUID : cas limites
# ═════════════════════════════════════════════════════════════════════════════

class TestUuidValidation:
    """Tests sur les cas limites du pattern UUID v4."""

    @pytest.mark.parametrize("valid_uuid", [
        "550e8400-e29b-41d4-a716-446655440000",
        "6ba7b810-9dad-41d1-80b4-00c04fd430c8",  # UUID v4 ?
        "00000000-0000-4000-8000-000000000000",
        "FFFFFFFF-FFFF-4FFF-BFFF-FFFFFFFFFFFF",
    ])
    def test_valid_uuids_accepted(self, valid_uuid):
        from services.pending_promotions import _validate_pending_id
        # Doit passer sans exception
        _validate_pending_id(valid_uuid)

    @pytest.mark.parametrize("bad_id", [
        "../etc/passwd",
        "../../shadow",
        "/absolute/path",
        "id with spaces",
        "550e8400e29b41d4a716446655440000",     # sans tirets
        "550e8400-e29b-41d4-a716-44665544000",  # trop court
        "550e8400-e29b-41d4-a716-4466554400000",# trop long
        "550e8400-e29b-31d4-a716-446655440000", # UUID v3 (pas v4)
        "not-a-uuid-at-all",
        "",
        "None",
        "null",
    ])
    def test_invalid_ids_rejected(self, bad_id):
        from services.pending_promotions import _validate_pending_id
        with pytest.raises(ValueError):
            _validate_pending_id(bad_id)
