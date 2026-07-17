"""
Tests unitaires — services/rate_limits.py

Couverture :
  • TestRoleLimits         (7)  — constantes, structure, tous les rôles
  • TestExtractRole        (6)  — pas de token, bearer invalide, rôles valides
  • TestGetUserKey         (5)  — utilisateurs authentifiés vs anonymes, IP fallback
  • TestMakeRoleLimit      (8)  — factory, catégories, rôles dynamiques, ValueError
  • TestGetLimitsForRole   (4)  — rôles connus, inconnus, retour dict
  • TestRateLimitHandler   (5)  — réponse 429 structurée, header Retry-After
"""

from unittest.mock import MagicMock, patch

import pytest

from services.rate_limits import (
    ROLE_LIMITS,
    _DEFAULT_ROLE,
    _VALID_CATEGORIES,
    _extract_role,
    _extract_username,
    get_all_role_limits,
    get_limits_for_role,
    get_user_key,
    make_role_limit,
    rate_limit_exceeded_handler,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_request(auth_header: str = "", client_host: str = "1.2.3.4") -> MagicMock:
    """Fabrique un faux objet Request avec les attributs utilisés."""
    req = MagicMock()
    req.headers = {"Authorization": auth_header} if auth_header else {}
    req.client = MagicMock()
    req.client.host = client_host
    req.method = "POST"
    req.url.path = "/api/v1/test"
    return req


def _make_bearer(username: str, role: str) -> str:
    """Génère un vrai JWT Bearer pour les tests."""
    from auth.jwt import create_access_token
    token = create_access_token({"sub": username, "role": role})
    return f"Bearer {token}"


# ═════════════════════════════════════════════════════════════════════════════
# 1. TestRoleLimits
# ═════════════════════════════════════════════════════════════════════════════

class TestRoleLimits:
    def test_all_roles_defined(self):
        expected_roles = {"admin", "maintainer", "uploader", "auditor", "reader", "anonymous"}
        assert set(ROLE_LIMITS.keys()) == expected_roles

    def test_all_categories_present_per_role(self):
        for role, limits in ROLE_LIMITS.items():
            assert set(limits.keys()) == _VALID_CATEGORIES, (
                f"Catégories manquantes pour le rôle {role!r}"
            )

    def test_limit_format_valid(self):
        """Chaque limite doit être au format '{count}/{period}'."""
        import re
        pattern = re.compile(r"^\d+/(second|minute|hour|day)$")
        for role, limits in ROLE_LIMITS.items():
            for cat, val in limits.items():
                assert pattern.match(val), (
                    f"Format invalide pour {role}/{cat} : {val!r}"
                )

    def test_admin_higher_than_reader(self):
        """Les admins doivent avoir des limites plus élevées que les readers."""
        def _count(limit_str: str) -> int:
            return int(limit_str.split("/")[0])

        for cat in _VALID_CATEGORIES:
            assert _count(ROLE_LIMITS["admin"][cat]) > _count(ROLE_LIMITS["reader"][cat])

    def test_uploader_higher_upload_than_reader(self):
        def _count(s): return int(s.split("/")[0])
        assert _count(ROLE_LIMITS["uploader"]["upload"]) > _count(ROLE_LIMITS["reader"]["upload"])

    def test_anonymous_tightest_upload(self):
        def _count(s): return int(s.split("/")[0])
        anon = _count(ROLE_LIMITS["anonymous"]["upload"])
        for role in ROLE_LIMITS:
            assert _count(ROLE_LIMITS[role]["upload"]) >= anon, (
                f"{role} should have upload limit >= anonymous"
            )

    def test_default_role_is_anonymous(self):
        assert _DEFAULT_ROLE == "anonymous"
        assert _DEFAULT_ROLE in ROLE_LIMITS


# ═════════════════════════════════════════════════════════════════════════════
# 2. TestExtractRole
# ═════════════════════════════════════════════════════════════════════════════

class TestExtractRole:
    def test_no_auth_header_returns_anonymous(self):
        req = _make_request()
        assert _extract_role(req) == "anonymous"

    def test_non_bearer_returns_anonymous(self):
        req = _make_request(auth_header="Basic dXNlcjpwYXNz")
        assert _extract_role(req) == "anonymous"

    def test_invalid_jwt_returns_anonymous(self):
        req = _make_request(auth_header="Bearer not.a.jwt")
        assert _extract_role(req) == "anonymous"

    def test_valid_admin_token(self):
        req = _make_request(auth_header=_make_bearer("alice", "admin"))
        assert _extract_role(req) == "admin"

    def test_valid_reader_token(self):
        req = _make_request(auth_header=_make_bearer("bob", "reader"))
        assert _extract_role(req) == "reader"

    def test_valid_uploader_token(self):
        req = _make_request(auth_header=_make_bearer("ci", "uploader"))
        assert _extract_role(req) == "uploader"


# ═════════════════════════════════════════════════════════════════════════════
# 3. TestGetUserKey
# ═════════════════════════════════════════════════════════════════════════════

class TestGetUserKey:
    def test_anonymous_uses_ip(self):
        req = _make_request(client_host="10.0.0.1")
        key = get_user_key(req)
        assert key == "ip:10.0.0.1"

    def test_authenticated_uses_username(self):
        req = _make_request(auth_header=_make_bearer("alice", "admin"))
        key = get_user_key(req)
        assert key.startswith("user:alice:")

    def test_authenticated_includes_role(self):
        req = _make_request(auth_header=_make_bearer("alice", "admin"))
        key = get_user_key(req)
        assert ":admin" in key

    def test_different_users_different_keys(self):
        req1 = _make_request(auth_header=_make_bearer("alice", "admin"))
        req2 = _make_request(auth_header=_make_bearer("bob", "reader"))
        assert get_user_key(req1) != get_user_key(req2)

    def test_no_client_fallback(self):
        req = _make_request()
        req.client = None
        req.headers = {}
        key = get_user_key(req)
        assert key == "ip:unknown"


# ═════════════════════════════════════════════════════════════════════════════
# 4. TestMakeRoleLimit
# ═════════════════════════════════════════════════════════════════════════════

class TestMakeRoleLimit:
    def test_upload_category_returns_callable(self):
        fn = make_role_limit("upload")
        assert callable(fn)

    def test_read_category_returns_callable(self):
        fn = make_role_limit("read")
        assert callable(fn)

    def test_write_category_returns_callable(self):
        fn = make_role_limit("write")
        assert callable(fn)

    def test_unknown_category_raises(self):
        with pytest.raises(ValueError, match="Catégorie inconnue"):
            make_role_limit("delete")

    def test_admin_gets_high_upload_limit(self):
        # make_role_limit retourne un callable(key: str) — slowapi passe get_user_key(request)
        from services.rate_limits import get_user_key
        fn = make_role_limit("upload")
        req = _make_request(auth_header=_make_bearer("admin", "admin"))
        limit = fn(get_user_key(req))
        assert limit == ROLE_LIMITS["admin"]["upload"]

    def test_reader_gets_low_upload_limit(self):
        from services.rate_limits import get_user_key
        fn = make_role_limit("upload")
        req = _make_request(auth_header=_make_bearer("bob", "reader"))
        limit = fn(get_user_key(req))
        assert limit == ROLE_LIMITS["reader"]["upload"]

    def test_anonymous_gets_anonymous_limit(self):
        from services.rate_limits import get_user_key
        fn = make_role_limit("upload")
        req = _make_request()  # no auth
        limit = fn(get_user_key(req))
        assert limit == ROLE_LIMITS["anonymous"]["upload"]

    def test_callable_has_meaningful_name(self):
        fn = make_role_limit("upload")
        assert "upload" in fn.__name__


# ═════════════════════════════════════════════════════════════════════════════
# 5. TestGetLimitsForRole
# ═════════════════════════════════════════════════════════════════════════════

class TestGetLimitsForRole:
    def test_known_role_returns_dict(self):
        limits = get_limits_for_role("admin")
        assert isinstance(limits, dict)
        assert set(limits.keys()) == _VALID_CATEGORIES

    def test_unknown_role_falls_back_to_anonymous(self):
        limits = get_limits_for_role("superuser_nonexistent")
        assert limits == ROLE_LIMITS["anonymous"]

    def test_returns_copy_not_reference(self):
        limits = get_limits_for_role("admin")
        limits["upload"] = "99999/minute"
        assert ROLE_LIMITS["admin"]["upload"] != "99999/minute"

    def test_get_all_role_limits_covers_all_roles(self):
        all_limits = get_all_role_limits()
        assert set(all_limits.keys()) == set(ROLE_LIMITS.keys())


# ═════════════════════════════════════════════════════════════════════════════
# 6. TestRateLimitHandler
# ═════════════════════════════════════════════════════════════════════════════

class TestRateLimitHandler:
    def _make_exc(self, retry_after=None, limit=None):
        exc = MagicMock()
        exc.retry_after = retry_after
        exc.limit = limit
        return exc

    def _make_req(self):
        req = MagicMock()
        req.method = "POST"
        req.url.path = "/api/v1/upload"
        req.client = MagicMock()
        req.client.host = "192.168.1.1"
        return req

    def test_returns_429(self):
        resp = rate_limit_exceeded_handler(
            self._make_req(), self._make_exc(retry_after=30, limit="20/minute")
        )
        assert resp.status_code == 429

    def test_body_is_json_with_error_key(self):
        import json
        resp = rate_limit_exceeded_handler(
            self._make_req(), self._make_exc(retry_after=30, limit="20/minute")
        )
        body = json.loads(resp.body)
        assert "detail" in body
        assert body["detail"]["error"] == "rate_limit_exceeded"

    def test_retry_after_in_header(self):
        resp = rate_limit_exceeded_handler(
            self._make_req(), self._make_exc(retry_after=42, limit="5/minute")
        )
        assert resp.headers.get("retry-after") == "42"

    def test_no_retry_after_no_header(self):
        resp = rate_limit_exceeded_handler(
            self._make_req(), self._make_exc(retry_after=None)
        )
        assert "retry-after" not in resp.headers

    def test_limit_in_body(self):
        import json
        resp = rate_limit_exceeded_handler(
            self._make_req(), self._make_exc(retry_after=10, limit="30/minute")
        )
        body = json.loads(resp.body)
        assert "30/minute" in body["detail"]["limit"]
