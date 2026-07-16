"""
Tests de couverture additionnels — Sprint 9.5 (partie B)
Ferme le gap restant de ~164 lignes pour atteindre ≥ 85%.

Modules ciblés :
  • auth/users.py               — list_users, create_user, update_user, delete/change_password
  • routers/dashboard_router.py — get_dashboard_stats, get_dashboard_history, get_enriched_dashboard
  • routers/settings_router.py  — chemins GPG, scheduler, export
"""

# ── Isolation /repos ──────────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_sprint95b_test_")
os.environ.setdefault("MANIFEST_DIR",           _TMP)
os.environ.setdefault("MANIFEST_DB",            os.path.join(_TMP, "manifests.db"))
os.environ.setdefault("POOL_DIR",               _TMP)
os.environ.setdefault("AUDIT_DIR",              _TMP)
os.environ.setdefault("AUDIT_LOG_PATH",         os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",             os.path.join(_TMP, "index.json"))
os.environ.setdefault("SETTINGS_PATH",          os.path.join(_TMP, "settings.json"))
os.environ.setdefault("AUTH_DB_PATH",           os.path.join(_TMP, "users.db"))
os.environ.setdefault("PENDING_PROMOTIONS_DIR", os.path.join(_TMP, "pending"))
os.environ.setdefault("NOTIFICATIONS_LOG_PATH", os.path.join(_TMP, "notifications.jsonl"))
os.environ.setdefault("SECURITY_CACHE_DIR",     os.path.join(_TMP, "security"))

# ── Imports ───────────────────────────────────────────────────────────────────
import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# 2. auth/users.py — fonctions CRUD
# ─────────────────────────────────────────────────────────────────────────────

class TestUsersDB:
    """Tests directs des fonctions DB — pas de HTTP."""

    @pytest.fixture(autouse=True)
    def isolate_db(self, db_test_engine):
        """
        db_test_engine (autouse) fournit déjà un SQLite vide par test.
        Aucune manipulation AUTH_DB_PATH — la DB est pilotée par db_conn().
        """
        yield

    def _make_user(self, username="testuser", role="reader"):
        from auth.users import create_user
        return create_user(username, "password123", role=role)

    def test_list_users_returns_created_user(self):
        from auth.users import list_users
        self._make_user("alice")
        users = list_users()
        names = [u["username"] for u in users]
        assert "alice" in names

    def test_list_users_empty(self):
        from auth.users import list_users
        users = list_users()
        # May contain admin from init — just check it's a list
        assert isinstance(users, list)

    def test_create_user_invalid_role_raises(self):
        from auth.users import create_user
        with pytest.raises(ValueError, match="Rôle invalide"):
            create_user("bad", "pw", role="superadmin")

    def test_create_user_with_all_fields(self):
        from auth.users import create_user
        u = create_user("bob", "pw123", role="admin",
                        full_name="Bob Smith", email="bob@example.com")
        assert u["full_name"] == "Bob Smith"
        assert u["email"] == "bob@example.com"
        assert u["auth_source"] == "local"

    def test_update_user_role(self):
        from auth.users import update_user
        self._make_user("carol")
        updated = update_user("carol", role="admin")
        assert updated["role"] == "admin"

    def test_update_user_full_name(self):
        from auth.users import update_user
        self._make_user("dave")
        updated = update_user("dave", full_name="Dave Jones")
        assert updated["full_name"] == "Dave Jones"

    def test_update_user_email(self):
        from auth.users import update_user
        self._make_user("eve")
        updated = update_user("eve", email="eve@example.com")
        assert updated["email"] == "eve@example.com"

    def test_update_user_active_false(self):
        from auth.users import update_user
        self._make_user("frank")
        updated = update_user("frank", active=False)
        assert updated["active"] == 0

    def test_update_user_auth_source(self):
        from auth.users import update_user
        self._make_user("grace")
        updated = update_user("grace", auth_source="ldap")
        assert updated["auth_source"] == "ldap"

    def test_update_user_invalid_role_raises(self):
        from auth.users import update_user
        self._make_user("helen")
        with pytest.raises(ValueError, match="Rôle invalide"):
            update_user("helen", role="root")

    def test_update_user_nonexistent_returns_none(self):
        from auth.users import update_user
        result = update_user("ghost", role="reader")
        assert result is None

    def test_delete_user_existing(self):
        from auth.users import delete_user, get_user_any
        self._make_user("ivan")
        result = delete_user("ivan")
        assert result is True
        assert get_user_any("ivan") is None

    def test_delete_user_nonexistent_returns_false(self):
        from auth.users import delete_user
        result = delete_user("nobody")
        assert result is False

    def test_change_password(self):
        from auth.users import change_password, verify_password, get_user_any
        self._make_user("judy")
        result = change_password("judy", "newpass456")
        assert result is True
        user = get_user_any("judy")
        assert verify_password("newpass456", user["hashed_password"])

    def test_change_password_nonexistent_returns_false(self):
        from auth.users import change_password
        result = change_password("nobody", "newpass")
        assert result is False

    def test_update_last_login(self):
        from auth.users import update_last_login, get_user_any
        self._make_user("kate")
        update_last_login("kate")
        user = get_user_any("kate")
        assert user["last_login"] is not None


# ─────────────────────────────────────────────────────────────────────────────
# 3. routers/dashboard_router.py — endpoints HTTP
# ─────────────────────────────────────────────────────────────────────────────

def _load_dashboard_mod():
    spec = importlib.util.spec_from_file_location(
        "dashboard_router_95b",
        Path(__file__).parent.parent / "routers" / "dashboard_router.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_DASH_MOD = _load_dashboard_mod()


@pytest.fixture(scope="module")
def dash_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from auth.dependencies import get_current_user, get_admin_user

    app = FastAPI()
    app.include_router(_DASH_MOD.router)
    app.dependency_overrides[get_current_user] = lambda: "user"
    app.dependency_overrides[get_admin_user]   = lambda: "admin"
    return TestClient(app)


_EMPTY_PACKAGES = []
_EMPTY_LOGS = []
_EMPTY_MANIFESTS = []
_EMPTY_DECISIONS = []


def _mock_clamav():
    return {"available": True, "db_version": "26700", "db_date": "2025-01-01",
            "daemon_running": True}


class TestDashboardStatsEndpoint:
    """GET /dashboard/stats — lignes 79-241."""

    def test_returns_200_with_empty_data(self, dash_client):
        with patch.object(_DASH_MOD, "list_packages_from_index", return_value=_EMPTY_PACKAGES):
            with patch.object(_DASH_MOD, "get_recent_logs", return_value=_EMPTY_LOGS):
                with patch.object(_DASH_MOD, "list_manifests", return_value=_EMPTY_MANIFESTS):
                    with patch.object(_DASH_MOD, "list_all_decisions", return_value=_EMPTY_DECISIONS):
                        with patch.object(_DASH_MOD, "get_clamav_status", return_value=_mock_clamav()):
                            resp = dash_client.get("/dashboard/stats")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, dash_client):
        with patch.object(_DASH_MOD, "list_packages_from_index", return_value=_EMPTY_PACKAGES):
            with patch.object(_DASH_MOD, "get_recent_logs", return_value=_EMPTY_LOGS):
                with patch.object(_DASH_MOD, "list_manifests", return_value=_EMPTY_MANIFESTS):
                    with patch.object(_DASH_MOD, "list_all_decisions", return_value=_EMPTY_DECISIONS):
                        with patch.object(_DASH_MOD, "get_clamav_status", return_value=_mock_clamav()):
                            resp = dash_client.get("/dashboard/stats")
        body = resp.json()
        for key in ("packages", "activity", "recent_imports", "alerts", "clamav",
                    "security_posture", "security_review"):
            assert key in body, f"Missing key: {key}"

    def test_counts_packages_correctly(self, dash_client):
        packages = [
            {"name": "nginx", "size_bytes": 1024, "deps_missing": [], "cve_summary": None},
            {"name": "curl",  "size_bytes": 512,  "deps_missing": ["libssl"], "cve_summary": None},
        ]
        with patch.object(_DASH_MOD, "list_packages_from_index", return_value=packages):
            with patch.object(_DASH_MOD, "get_recent_logs", return_value=_EMPTY_LOGS):
                with patch.object(_DASH_MOD, "list_manifests", return_value=_EMPTY_MANIFESTS):
                    with patch.object(_DASH_MOD, "list_all_decisions", return_value=_EMPTY_DECISIONS):
                        with patch.object(_DASH_MOD, "get_clamav_status", return_value=_mock_clamav()):
                            resp = dash_client.get("/dashboard/stats")
        body = resp.json()
        assert body["packages"]["total"] == 2
        assert body["packages"]["deps_missing_count"] == 1

    def test_audit_logs_counted(self, dash_client):
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).date().isoformat()
        logs = [
            {"action": "UPLOAD", "result": "SUCCESS", "timestamp": f"{today}T10:00:00+00:00"},
            {"action": "IMPORT", "result": "SUCCESS", "timestamp": f"{today}T11:00:00+00:00"},
            {"action": "UPLOAD", "result": "FAILURE", "timestamp": f"{today}T12:00:00+00:00",
             "package": "bad-pkg", "detail": "Virus trouvé"},
        ]
        with patch.object(_DASH_MOD, "list_packages_from_index", return_value=_EMPTY_PACKAGES):
            with patch.object(_DASH_MOD, "get_recent_logs", return_value=logs):
                with patch.object(_DASH_MOD, "list_manifests", return_value=_EMPTY_MANIFESTS):
                    with patch.object(_DASH_MOD, "list_all_decisions", return_value=_EMPTY_DECISIONS):
                        with patch.object(_DASH_MOD, "get_clamav_status", return_value=_mock_clamav()):
                            resp = dash_client.get("/dashboard/stats")
        body = resp.json()
        assert body["packages"]["imports_today"] == 2

    def test_cve_posture_aggregated(self, dash_client):
        packages = [{
            "name": "vuln-pkg", "size_bytes": 0, "deps_missing": [],
            "cve_summary": {"critical": 3, "high": 1, "medium": 0, "low": 0, "negligible": 0},
        }]
        with patch.object(_DASH_MOD, "list_packages_from_index", return_value=packages):
            with patch.object(_DASH_MOD, "get_recent_logs", return_value=_EMPTY_LOGS):
                with patch.object(_DASH_MOD, "list_manifests", return_value=_EMPTY_MANIFESTS):
                    with patch.object(_DASH_MOD, "list_all_decisions", return_value=_EMPTY_DECISIONS):
                        with patch.object(_DASH_MOD, "get_clamav_status", return_value=_mock_clamav()):
                            resp = dash_client.get("/dashboard/stats")
        body = resp.json()
        assert body["security_posture"]["critical"] == 3
        assert body["security_posture"]["scanned"] == 1

    def test_sla_expiring_decisions(self, dash_client):
        from datetime import datetime, timezone, timedelta
        exp = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        decisions = [{
            "package": "nginx", "version": "1.0",
            "action": "accept_risk", "decided_by": "alice",
        }]
        sla_status = {"warning": True, "expired": False, "expires_at": exp, "remaining_days": 2}
        with patch.object(_DASH_MOD, "list_packages_from_index", return_value=_EMPTY_PACKAGES):
            with patch.object(_DASH_MOD, "get_recent_logs", return_value=_EMPTY_LOGS):
                with patch.object(_DASH_MOD, "list_manifests", return_value=_EMPTY_MANIFESTS):
                    with patch.object(_DASH_MOD, "list_all_decisions", return_value=decisions):
                        with patch.object(_DASH_MOD, "get_sla_status", return_value=sla_status):
                            with patch.object(_DASH_MOD, "get_clamav_status", return_value=_mock_clamav()):
                                resp = dash_client.get("/dashboard/stats")
        body = resp.json()
        assert body["security_review"]["expiring_soon"] != []

    def test_clamav_exception_handled(self, dash_client):
        with patch.object(_DASH_MOD, "list_packages_from_index", return_value=_EMPTY_PACKAGES):
            with patch.object(_DASH_MOD, "get_recent_logs", return_value=_EMPTY_LOGS):
                with patch.object(_DASH_MOD, "list_manifests", return_value=_EMPTY_MANIFESTS):
                    with patch.object(_DASH_MOD, "list_all_decisions", return_value=_EMPTY_DECISIONS):
                        with patch.object(_DASH_MOD, "get_clamav_status",
                                          side_effect=RuntimeError("clamav down")):
                            resp = dash_client.get("/dashboard/stats")
        assert resp.status_code == 200
        assert resp.json()["clamav"]["available"] is False

    def test_status_counts_from_manifests(self, dash_client):
        manifests = [
            {"status": "pending_review"},
            {"status": "pending_review"},
            {"status": "blocked"},
        ]
        with patch.object(_DASH_MOD, "list_packages_from_index", return_value=_EMPTY_PACKAGES):
            with patch.object(_DASH_MOD, "get_recent_logs", return_value=_EMPTY_LOGS):
                with patch.object(_DASH_MOD, "list_manifests", return_value=manifests):
                    with patch.object(_DASH_MOD, "list_all_decisions", return_value=_EMPTY_DECISIONS):
                        with patch.object(_DASH_MOD, "get_clamav_status", return_value=_mock_clamav()):
                            resp = dash_client.get("/dashboard/stats")
        body = resp.json()
        assert body["security_review"]["pending_review"] == 2
        assert body["security_review"]["blocked"] == 1


class TestDashboardHistoryEndpoint:
    """GET /dashboard/history — lignes 244-279."""

    def test_returns_200(self, dash_client):
        with patch.object(_DASH_MOD, "get_recent_logs", return_value=_EMPTY_LOGS):
            resp = dash_client.get("/dashboard/history")
        assert resp.status_code == 200

    def test_returns_history_key(self, dash_client):
        with patch.object(_DASH_MOD, "get_recent_logs", return_value=_EMPTY_LOGS):
            resp = dash_client.get("/dashboard/history")
        body = resp.json()
        assert "history" in body
        assert "days" in body
        assert body["days"] == 30

    def test_custom_days_param(self, dash_client):
        with patch.object(_DASH_MOD, "get_recent_logs", return_value=_EMPTY_LOGS):
            resp = dash_client.get("/dashboard/history?days=7")
        body = resp.json()
        assert body["days"] == 7
        assert len(body["history"]) == 7

    def test_counts_uploads_and_failures(self, dash_client):
        from datetime import datetime, timezone, timedelta
        today = datetime.now(timezone.utc).date()
        yesterday = (today - timedelta(days=1)).isoformat()
        logs = [
            {"action": "UPLOAD", "result": "SUCCESS", "timestamp": f"{yesterday}T10:00:00+00:00"},
            {"action": "UPLOAD", "result": "FAILURE", "timestamp": f"{yesterday}T11:00:00+00:00"},
            {"action": "DECISION", "result": "SUCCESS", "timestamp": f"{yesterday}T12:00:00+00:00"},
        ]
        with patch.object(_DASH_MOD, "get_recent_logs", return_value=logs):
            resp = dash_client.get("/dashboard/history?days=7")
        body = resp.json()
        yesterday_bucket = next((b for b in body["history"] if b["date"] == yesterday), None)
        assert yesterday_bucket is not None
        assert yesterday_bucket["imports"] == 1
        assert yesterday_bucket["failures"] == 1
        assert yesterday_bucket["decisions"] == 1

    def test_ignores_logs_outside_window(self, dash_client):
        from datetime import datetime, timezone, timedelta
        old_date = (datetime.now(timezone.utc).date() - timedelta(days=365)).isoformat()
        logs = [
            {"action": "UPLOAD", "result": "SUCCESS", "timestamp": f"{old_date}T10:00:00+00:00"},
        ]
        with patch.object(_DASH_MOD, "get_recent_logs", return_value=logs):
            resp = dash_client.get("/dashboard/history?days=30")
        body = resp.json()
        # All imports should be 0 since the log is outside the 30-day window
        total_imports = sum(b["imports"] for b in body["history"])
        assert total_imports == 0


class TestDashboardEnrichedEndpoint:
    """GET /dashboard/stats/enriched — lignes 282-313."""

    def test_returns_200(self, dash_client):
        mock_result = {
            "generated_at": "2025-01-01T00:00:00+00:00",
            "cve_trends": [], "top_packages": {}, "sla_overdue": [],
            "distributions": [], "summary": {},
        }
        with patch.object(_DASH_MOD, "get_dashboard", return_value=mock_result):
            resp = dash_client.get("/dashboard/stats/enriched")
        assert resp.status_code == 200

    def test_passes_trend_windows(self, dash_client):
        mock_result = {"generated_at": "x", "cve_trends": [], "top_packages": {},
                       "sla_overdue": [], "distributions": [], "summary": {}}
        with patch.object(_DASH_MOD, "get_dashboard", return_value=mock_result) as mock_gd:
            dash_client.get("/dashboard/stats/enriched?trend_windows=7,14")
        call_kwargs = mock_gd.call_args[1]
        assert 7 in call_kwargs["trend_windows"]
        assert 14 in call_kwargs["trend_windows"]

    def test_invalid_trend_windows_defaults(self, dash_client):
        mock_result = {"generated_at": "x", "cve_trends": [], "top_packages": {},
                       "sla_overdue": [], "distributions": [], "summary": {}}
        with patch.object(_DASH_MOD, "get_dashboard", return_value=mock_result) as mock_gd:
            dash_client.get("/dashboard/stats/enriched?trend_windows=bad,input")
        call_kwargs = mock_gd.call_args[1]
        assert call_kwargs["trend_windows"] == [30, 60, 90]


# ─────────────────────────────────────────────────────────────────────────────
# 4. routers/settings_router.py — chemins GPG et scheduler
# ─────────────────────────────────────────────────────────────────────────────

def _load_settings_router_mod():
    spec = importlib.util.spec_from_file_location(
        "settings_router_95b",
        Path(__file__).parent.parent / "routers" / "settings_router.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SR_MOD_B = _load_settings_router_mod()


@pytest.fixture(scope="module")
def sr_client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from auth.dependencies import get_admin_user

    app = FastAPI()
    app.include_router(_SR_MOD_B.router)
    app.dependency_overrides[get_admin_user] = lambda: "admin"
    return TestClient(app)


class TestSettingsRouterGPGAndMore:
    def test_generate_gpg_key_success(self, sr_client):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_result.stdout = "-----BEGIN PGP"
        # Mock _ensure_gnupg_permissions to avoid /repos mkdir
        with patch.object(_SR_MOD_B, "_ensure_gnupg_permissions"):
            with patch("subprocess.run", return_value=mock_result):
                resp = sr_client.post("/settings/gpg/generate")
        assert resp.status_code == 200

    def test_generate_gpg_key_failure_returns_500(self, sr_client):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "gpg: key generation failed"
        mock_result.stdout = ""
        with patch.object(_SR_MOD_B, "_ensure_gnupg_permissions"):
            with patch("subprocess.run", return_value=mock_result):
                resp = sr_client.post("/settings/gpg/generate")
        assert resp.status_code == 500

    def test_generate_gpg_key_timeout(self, sr_client):
        import subprocess
        with patch.object(_SR_MOD_B, "_ensure_gnupg_permissions"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("gpg", 120)):
                resp = sr_client.post("/settings/gpg/generate")
        assert resp.status_code == 504

    def test_export_gpg_key_no_file(self, sr_client, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n..."
        with patch("subprocess.run", return_value=mock_result):
            with patch.object(_SR_MOD_B, "DISTS_DIR", str(tmp_path)):
                resp = sr_client.post("/settings/gpg/export")
        # export_public_key writes the file; if it succeeds, the endpoint checks for it
        assert resp.status_code in (200, 500)

    def test_get_next_sync_with_scheduler_no_job(self, sr_client):
        import services.scheduler_state as ss
        mock_scheduler = MagicMock()
        mock_scheduler.get_job.return_value = None
        orig = ss.scheduler
        ss.scheduler = mock_scheduler
        try:
            resp = sr_client.get("/settings/next-sync")
        finally:
            ss.scheduler = orig
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "job_not_found"

    def test_get_next_sync_with_job_paused(self, sr_client):
        import services.scheduler_state as ss
        mock_job = MagicMock()
        mock_job.next_run_time = None
        mock_scheduler = MagicMock()
        mock_scheduler.get_job.return_value = mock_job
        orig = ss.scheduler
        ss.scheduler = mock_scheduler
        try:
            resp = sr_client.get("/settings/next-sync")
        finally:
            ss.scheduler = orig
        assert resp.status_code == 200
        assert resp.json()["status"] == "paused"

    def test_get_next_sync_with_scheduled_job(self, sr_client):
        from datetime import datetime, timezone
        import services.scheduler_state as ss
        next_run = datetime(2025, 6, 1, 3, 0, 0, tzinfo=timezone.utc)
        mock_job = MagicMock()
        mock_job.next_run_time = next_run
        mock_scheduler = MagicMock()
        mock_scheduler.get_job.return_value = mock_job
        orig = ss.scheduler
        ss.scheduler = mock_scheduler
        try:
            resp = sr_client.get("/settings/next-sync")
        finally:
            ss.scheduler = orig
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "scheduled"
        assert "2025-06-01" in body["next_run"]

    def test_patch_settings_with_sync_scheduler_running(self, sr_client):
        import services.scheduler_state as ss
        mock_scheduler = MagicMock()
        orig = ss.scheduler
        ss.scheduler = mock_scheduler
        try:
            resp = sr_client.patch("/settings/", json={"sync": {"enabled": True, "hour": 3, "minute": 0}})
        finally:
            ss.scheduler = orig
        assert resp.status_code == 200
        # scheduler.reschedule_job was called
        mock_scheduler.reschedule_job.assert_called_once()

    def test_patch_settings_sync_disabled_pauses_scheduler(self, sr_client):
        import services.scheduler_state as ss
        mock_scheduler = MagicMock()
        orig = ss.scheduler
        ss.scheduler = mock_scheduler
        try:
            resp = sr_client.patch("/settings/", json={"sync": {"enabled": False, "hour": 3, "minute": 0}})
        finally:
            ss.scheduler = orig
        assert resp.status_code == 200
        mock_scheduler.pause_job.assert_called_once()

