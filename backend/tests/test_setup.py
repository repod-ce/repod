"""
Tests unitaires — services/setup.py + routers/setup_router.py

Couverture :
  • TestIsSetupDone       (6)  — DB absente, table vide, admin inexistant, admin présent
  • TestGetSetupStatus    (3)  — champs retournés, needs_setup inversé
  • TestRunSetup          (9)  — succès, déjà fait, username court, mdp court, app_url
  • TestSetupRouter       (9)  — GET status, POST success, POST 409, POST 400 validations
"""

import os
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient  # noqa: F401 — used in client fixture indirectly

os.environ.setdefault("JWT_SECRET_KEY", "test-secret-for-setup")

# ── module under test ─────────────────────────────────────────────────────────
import services.setup as setup_mod
from services.setup import (
    SetupAlreadyDoneError,
    SetupError,
    get_setup_status,
    is_setup_done,
    run_setup,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _db_count(count):
    """Fake db_conn() returning the given COUNT(*) scalar."""
    mock_conn = MagicMock()
    mock_conn.execute.return_value.scalar.return_value = count

    @contextmanager
    def _cm():
        yield mock_conn

    return patch("services.setup.db_conn", _cm)


def _db_error():
    """Fake db_conn() that raises on __enter__."""
    @contextmanager
    def _cm():
        raise Exception("DB unavailable")
        yield  # pragma: no cover

    return patch("services.setup.db_conn", _cm)


# ═════════════════════════════════════════════════════════════════════════════
# 1. TestIsSetupDone
# ═════════════════════════════════════════════════════════════════════════════

class TestIsSetupDone:
    def test_db_unavailable_returns_false(self):
        """DB inaccessible → False (exception catchée)."""
        with _db_error():
            assert is_setup_done() is False

    def test_no_admin_returns_false(self):
        """Aucun admin actif en DB → False."""
        with _db_count(0):
            assert is_setup_done() is False

    def test_admin_present_returns_true(self):
        """Admin actif présent → True."""
        with _db_count(1):
            assert is_setup_done() is True

    def test_inactive_admin_counted_zero_returns_false(self):
        """COUNT(*) retourne 0 → False (admin inactif filtré par WHERE)."""
        with _db_count(0):
            assert is_setup_done() is False

    def test_corrupt_db_returns_false(self):
        """Exception DB (table absente, etc.) → False."""
        with _db_error():
            assert is_setup_done() is False

    def test_multiple_admins_returns_true(self):
        """Plusieurs admins → True."""
        with _db_count(3):
            assert is_setup_done() is True


# ═════════════════════════════════════════════════════════════════════════════
# 2. TestGetSetupStatus
# ═════════════════════════════════════════════════════════════════════════════

class TestGetSetupStatus:
    def test_not_done_fields(self):
        with _db_count(0):
            status = get_setup_status()
        assert status["setup_done"] is False
        assert status["needs_setup"] is True
        assert "checked_at" in status

    def test_done_fields(self):
        with _db_count(1):
            status = get_setup_status()
        assert status["setup_done"] is True
        assert status["needs_setup"] is False

    def test_checked_at_is_iso(self):
        from datetime import datetime
        with _db_count(0):
            status = get_setup_status()
        datetime.fromisoformat(status["checked_at"])


# ═════════════════════════════════════════════════════════════════════════════
# 3. TestRunSetup
# ═════════════════════════════════════════════════════════════════════════════

class TestRunSetup:
    def _mock_not_done(self):
        return patch.object(setup_mod, "is_setup_done", return_value=False)

    def _mock_done(self):
        return patch.object(setup_mod, "is_setup_done", return_value=True)

    def test_success_returns_token(self):
        with (
            self._mock_not_done(),
            patch("auth.users.create_user", return_value={"username": "admin", "role": "admin"}),
            patch("auth.jwt.create_access_token", return_value="jwt-token-xxx"),
        ):
            result = run_setup("admin", "password123")

        assert result["admin_username"] == "admin"
        assert result["access_token"] == "jwt-token-xxx"
        assert result["token_type"] == "bearer"
        assert "message" in result

    def test_already_done_raises(self):
        with self._mock_done():
            with pytest.raises(SetupAlreadyDoneError):
                run_setup("admin", "password123")

    def test_username_too_short_raises(self):
        with self._mock_not_done():
            with pytest.raises(SetupError, match="court"):
                run_setup("ab", "password123")

    def test_empty_username_raises(self):
        with self._mock_not_done():
            with pytest.raises(SetupError):
                run_setup("", "password123")

    def test_password_too_short_raises(self):
        with self._mock_not_done():
            with pytest.raises(SetupError, match="court"):
                run_setup("admin", "short")

    def test_empty_password_raises(self):
        with self._mock_not_done():
            with pytest.raises(SetupError):
                run_setup("admin", "")

    def test_app_url_saved_in_settings(self):
        mock_update = MagicMock()
        with (
            self._mock_not_done(),
            patch("auth.users.create_user", return_value={}),
            patch("auth.jwt.create_access_token", return_value="tok"),
            patch("services.settings.update_settings", mock_update),
        ):
            run_setup("admin", "password123", app_url="https://repod.example.com")

        mock_update.assert_called_once_with({"app_url": "https://repod.example.com"})

    def test_app_url_trailing_slash_stripped(self):
        mock_update = MagicMock()
        with (
            self._mock_not_done(),
            patch("auth.users.create_user", return_value={}),
            patch("auth.jwt.create_access_token", return_value="tok"),
            patch("services.settings.update_settings", mock_update),
        ):
            run_setup("admin", "password123", app_url="https://repod.example.com/")

        call_args = mock_update.call_args[0][0]
        assert not call_args["app_url"].endswith("/")

    def test_no_app_url_skips_settings(self):
        mock_update = MagicMock()
        with (
            self._mock_not_done(),
            patch("auth.users.create_user", return_value={}),
            patch("auth.jwt.create_access_token", return_value="tok"),
            patch("services.settings.update_settings", mock_update),
        ):
            run_setup("admin", "password123")

        mock_update.assert_not_called()


# ═════════════════════════════════════════════════════════════════════════════
# 4. TestSetupRouter (via TestClient)
# ═════════════════════════════════════════════════════════════════════════════

@pytest.fixture()
def client():
    """
    TestClient minimal avec seulement le setup_router.
    Chargement isolé pour éviter les imports en cascade.
    """
    import importlib.util
    from fastapi import FastAPI

    spec = importlib.util.spec_from_file_location(
        "setup_router_isolated",
        Path(__file__).parent.parent / "routers" / "setup_router.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    app = FastAPI()
    app.include_router(mod.router, prefix="/api/v1")
    return TestClient(app)


class TestSetupRouter:
    def test_get_status_not_done(self, client):
        with patch.object(setup_mod, "is_setup_done", return_value=False):
            resp = client.get("/api/v1/setup/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["setup_done"] is False
        assert data["needs_setup"] is True

    def test_get_status_done(self, client):
        with patch.object(setup_mod, "is_setup_done", return_value=True):
            resp = client.get("/api/v1/setup/status")
        assert resp.status_code == 200
        assert resp.json()["setup_done"] is True

    def test_post_setup_success(self, client):
        with (
            patch.object(setup_mod, "is_setup_done", return_value=False),
            patch("auth.users.create_user", return_value={}),
            patch("auth.jwt.create_access_token", return_value="tok123"),
        ):
            resp = client.post(
                "/api/v1/setup/",
                json={
                    "admin_username": "admin",
                    "admin_password": "strongpass",
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_token"] == "tok123"
        assert data["admin_username"] == "admin"
        assert data["token_type"] == "bearer"

    def test_post_setup_requires_token_when_set(self, client):
        """Si SETUP_TOKEN est défini, POST /setup sans header X-Setup-Token → 403."""
        with (
            patch.object(setup_mod, "is_setup_done", return_value=False),
            patch.dict(os.environ, {"SETUP_TOKEN": "s3cr3t"}),
        ):
            resp = client.post(
                "/api/v1/setup/",
                json={"admin_username": "admin", "admin_password": "strongpass"},
            )
        assert resp.status_code == 403

    def test_post_setup_with_wrong_token_403(self, client):
        with (
            patch.object(setup_mod, "is_setup_done", return_value=False),
            patch.dict(os.environ, {"SETUP_TOKEN": "s3cr3t"}),
        ):
            resp = client.post(
                "/api/v1/setup/",
                json={"admin_username": "admin", "admin_password": "strongpass"},
                headers={"X-Setup-Token": "wrong"},
            )
        assert resp.status_code == 403

    def test_post_setup_with_correct_token_succeeds(self, client):
        with (
            patch.object(setup_mod, "is_setup_done", return_value=False),
            patch("auth.users.create_user", return_value={}),
            patch("auth.jwt.create_access_token", return_value="tok"),
            patch.dict(os.environ, {"SETUP_TOKEN": "s3cr3t"}),
        ):
            resp = client.post(
                "/api/v1/setup/",
                json={"admin_username": "admin", "admin_password": "strongpass"},
                headers={"X-Setup-Token": "s3cr3t"},
            )
        assert resp.status_code == 200

    def test_post_setup_already_done_409(self, client):
        with patch.object(setup_mod, "is_setup_done", return_value=True):
            resp = client.post(
                "/api/v1/setup/",
                json={"admin_username": "admin", "admin_password": "strongpass"},
            )
        assert resp.status_code == 409

    def test_post_setup_username_too_short_400(self, client):
        """Pydantic min_length=3 — validation avant même d'atteindre run_setup."""
        resp = client.post(
            "/api/v1/setup/",
            json={"admin_username": "ab", "admin_password": "strongpass"},
        )
        assert resp.status_code == 422

    def test_post_setup_password_too_short_422(self, client):
        resp = client.post(
            "/api/v1/setup/",
            json={"admin_username": "admin", "admin_password": "short"},
        )
        assert resp.status_code == 422

    def test_post_setup_with_app_url(self, client):
        mock_update = MagicMock()
        with (
            patch.object(setup_mod, "is_setup_done", return_value=False),
            patch("auth.users.create_user", return_value={}),
            patch("auth.jwt.create_access_token", return_value="tok"),
            patch("services.settings.update_settings", mock_update),
        ):
            resp = client.post(
                "/api/v1/setup/",
                json={
                    "admin_username": "admin",
                    "admin_password": "strongpass",
                    "app_url": "https://apt.company.com",
                },
            )
        assert resp.status_code == 200
        mock_update.assert_called_once()

    def test_post_setup_optional_fields(self, client):
        """admin_email et admin_full_name sont optionnels."""
        with (
            patch.object(setup_mod, "is_setup_done", return_value=False),
            patch("auth.users.create_user", return_value={}) as mock_create,
            patch("auth.jwt.create_access_token", return_value="tok"),
        ):
            resp = client.post(
                "/api/v1/setup/",
                json={
                    "admin_username": "admin",
                    "admin_password": "strongpass",
                    "admin_email": "admin@example.com",
                    "admin_full_name": "Super Admin",
                },
            )
        assert resp.status_code == 200
        call_kwargs = mock_create.call_args[1]
        assert call_kwargs.get("email") == "admin@example.com"
        assert call_kwargs.get("full_name") == "Super Admin"

    def test_status_no_auth_required(self, client):
        """Le endpoint status ne doit pas requérir d'authentification."""
        with patch.object(setup_mod, "is_setup_done", return_value=False):
            resp = client.get("/api/v1/setup/status")
        assert resp.status_code == 200
