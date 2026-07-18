"""
Tests unitaires — routers/health_router.py (version enrichie)

Couverture :
  • TestCheckDir          (5)  — répertoire existant, absent, disk usage
  • TestCheckPostgres     (3)  — DB joignable, DB inaccessible
  • TestCheckAuthDb       (3)  — ok, erreur DB, résultat dict
  • TestCheckClamav       (4)  — binaire OK, absent, timeout
  • TestCheckReprepro     (3)  — binaire OK, absent
  • TestCheckGpg          (4)  — clé présente, absente, gpg absent
  • TestCheckScheduler    (3)  — scheduler actif, None
  • TestComputeStatus     (5)  — healthy, degraded, unhealthy, mixed
  • TestHealthEndpoints   (8)  — GET /health, /health/live, /health/ready codes HTTP
"""

import importlib.util
import json
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ── Chargement isolé (évite routers/__init__.py → /repos) ────────────────────

def _load_health_router():
    spec = importlib.util.spec_from_file_location(
        "health_router_isolated",
        Path(__file__).parent.parent / "routers" / "health_router.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


health_mod = _load_health_router()


@pytest.fixture(scope="module")
def client():
    app = FastAPI()
    app.include_router(health_mod.router)
    return TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
# 1. TestCheckDir
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckDir:
    def test_existing_dir_ok(self, tmp_path):
        result = health_mod._check_dir(tmp_path)
        assert result["ok"] is True
        assert "free_gb" in result

    def test_absent_dir_not_ok(self, tmp_path):
        result = health_mod._check_dir(tmp_path / "nonexistent")
        assert result["ok"] is False

    def test_path_included_in_result(self, tmp_path):
        result = health_mod._check_dir(tmp_path)
        assert "path" in result

    def test_disk_usage_present_for_existing(self, tmp_path):
        result = health_mod._check_dir(tmp_path)
        assert result["free_gb"] is not None
        assert result["total_gb"] is not None
        assert result["used_pct"] is not None

    def test_disk_usage_none_for_absent(self, tmp_path):
        result = health_mod._check_dir(tmp_path / "missing")
        assert result["free_gb"] is None


# ─────────────────────────────────────────────────────────────────────────────
# 2. TestCheckPostgres  (anciennement TestCheckSqlite)
# ─────────────────────────────────────────────────────────────────────────────

def _db_ok():
    """db_conn() mock retournant ok=True."""
    mock_conn = MagicMock()
    mock_conn.execute.return_value.scalar.return_value = 0

    @contextmanager
    def _cm():
        yield mock_conn

    return patch("db.engine.db_conn", _cm)


def _db_fail():
    """db_conn() mock levant une exception."""
    @contextmanager
    def _cm():
        raise Exception("DB unreachable")
        yield  # pragma: no cover

    return patch("db.engine.db_conn", _cm)


class TestCheckPostgres:
    def test_ok_when_db_reachable(self):
        """_check_postgres retourne ok=True si la DB répond."""
        with _db_ok():
            result = health_mod._check_postgres()
        assert result["ok"] is True

    def test_not_ok_when_db_unreachable(self):
        """_check_postgres retourne ok=False si la DB est inaccessible."""
        with _db_fail():
            result = health_mod._check_postgres()
        assert result["ok"] is False

    def test_result_is_dict(self):
        with _db_ok():
            result = health_mod._check_postgres()
        assert isinstance(result, dict)


# ─────────────────────────────────────────────────────────────────────────────
# 3. TestCheckAuthDb
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckAuthDb:
    def test_db_error_returns_not_ok(self):
        """_check_auth_db retourne ok=False si db_conn échoue."""
        @contextmanager
        def _bad_cm():
            raise Exception("no DB")
            yield  # pragma: no cover
        with patch("db.engine.db_conn", _bad_cm):
            result = health_mod._check_auth_db()
        assert result["ok"] is False

    def test_db_ok_returns_ok(self):
        """_check_auth_db retourne ok=True si la table users est accessible."""
        mock_conn = MagicMock()
        mock_conn.execute.return_value.scalar.return_value = 3

        @contextmanager
        def _good_cm():
            yield mock_conn

        with patch("db.engine.db_conn", _good_cm):
            result = health_mod._check_auth_db()
        assert result["ok"] is True

    def test_result_is_dict(self):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.scalar.return_value = 0

        @contextmanager
        def _cm():
            yield mock_conn

        with patch("db.engine.db_conn", _cm):
            result = health_mod._check_auth_db()
        assert isinstance(result, dict)


# ─────────────────────────────────────────────────────────────────────────────
# 4. TestCheckClamav
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckClamav:
    def test_clamav_present(self):
        mock_run = MagicMock()
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = b"ClamAV 1.2.3/26857"
        with patch("subprocess.run", mock_run):
            result = health_mod._check_clamav()
        assert result["ok"] is True
        assert result["version"] is not None

    def test_clamav_absent(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = health_mod._check_clamav()
        assert result["ok"] is False
        assert "introuvable" in result.get("error", "")

    def test_clamav_nonzero_return(self):
        mock_run = MagicMock()
        mock_run.return_value.returncode = 1
        mock_run.return_value.stdout = b""
        with patch("subprocess.run", mock_run):
            result = health_mod._check_clamav()
        assert result["ok"] is False

    def test_clamav_timeout(self):
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("clamscan", 3)):
            result = health_mod._check_clamav()
        assert result["ok"] is False


# ─────────────────────────────────────────────────────────────────────────────
# 5. TestCheckReprepro
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckReprepro:
    def test_reprepro_present(self):
        mock_run = MagicMock()
        mock_run.return_value.stdout = b"reprepro version 5.3.0\n"
        mock_run.return_value.stderr = b""
        with patch("subprocess.run", mock_run):
            result = health_mod._check_reprepro()
        assert result["ok"] is True

    def test_reprepro_absent(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = health_mod._check_reprepro()
        assert result["ok"] is False
        assert "introuvable" in result.get("error", "")

    def test_result_has_version_key(self):
        mock_run = MagicMock()
        mock_run.return_value.stdout = b"reprepro version 5.3.0\n"
        mock_run.return_value.stderr = b""
        with patch("subprocess.run", mock_run):
            result = health_mod._check_reprepro()
        assert "version" in result


# ─────────────────────────────────────────────────────────────────────────────
# 6. TestCheckGpg
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckGpg:
    def test_gpg_key_present(self):
        mock_run = MagicMock()
        mock_run.return_value.stdout = (
            b"sec:u:4096:1:ABCD1234:...\n"
            b"fpr:::::::::ABCD1234567890ABCD:\n"
        )
        with patch("subprocess.run", mock_run):
            result = health_mod._check_gpg()
        assert result["ok"] is True
        assert "fingerprint" in result

    def test_gpg_no_key(self):
        mock_run = MagicMock()
        mock_run.return_value.stdout = b""  # aucune ligne sec:
        with patch("subprocess.run", mock_run):
            result = health_mod._check_gpg()
        assert result["ok"] is False

    def test_gpg_binary_absent(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = health_mod._check_gpg()
        assert result["ok"] is False
        assert "introuvable" in result.get("error", "")

    def test_gpg_does_not_raise(self):
        with patch("subprocess.run", side_effect=Exception("gpg exploded")):
            result = health_mod._check_gpg()
        assert result["ok"] is False


# ─────────────────────────────────────────────────────────────────────────────
# 7. TestCheckScheduler
# ─────────────────────────────────────────────────────────────────────────────

class TestCheckScheduler:
    def test_scheduler_none_not_ok(self):
        with patch("services.scheduler_state.scheduler", None), \
             patch("services.leader_election.is_leader", return_value=True):
            result = health_mod._check_scheduler()
        assert result["ok"] is False

    def test_scheduler_none_passive_replica_ok(self):
        """Sur une réplique passive (HA actif-passif), l'absence de scheduler est attendue."""
        with patch("services.scheduler_state.scheduler", None), \
             patch("services.leader_election.is_leader", return_value=False):
            result = health_mod._check_scheduler()
        assert result["ok"] is True
        assert result["jobs"] == []

    def test_scheduler_running_ok(self):
        fake_job = MagicMock()
        fake_job.id = "job1"
        fake_job.name = "Test Job"
        fake_job.next_run_time = None
        fake_sched = MagicMock()
        fake_sched.get_jobs.return_value = [fake_job]
        with patch("services.scheduler_state.scheduler", fake_sched):
            result = health_mod._check_scheduler()
        assert result["ok"] is True
        assert len(result["jobs"]) == 1

    def test_scheduler_jobs_list(self):
        fake_sched = MagicMock()
        fake_sched.get_jobs.return_value = []
        with patch("services.scheduler_state.scheduler", fake_sched):
            result = health_mod._check_scheduler()
        assert result["jobs"] == []


# ─────────────────────────────────────────────────────────────────────────────
# 8. TestComputeStatus
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeStatus:
    def _checks(self, critical_ok=True, non_critical_ok=True):
        return {
            "critical":     {"db": {"ok": critical_ok}},
            "non_critical": {"clamav": {"ok": non_critical_ok}},
            "info":         {},
        }

    def test_all_ok_is_healthy(self):
        assert health_mod._compute_status(self._checks(True, True)) == "healthy"

    def test_critical_fail_is_unhealthy(self):
        assert health_mod._compute_status(self._checks(False, True)) == "unhealthy"

    def test_non_critical_fail_is_degraded(self):
        assert health_mod._compute_status(self._checks(True, False)) == "degraded"

    def test_both_fail_is_unhealthy(self):
        # unhealthy prend le dessus sur degraded
        assert health_mod._compute_status(self._checks(False, False)) == "unhealthy"

    def test_multiple_critical_any_fail(self):
        checks = {
            "critical": {
                "manifests": {"ok": True},
                "pool":      {"ok": False},  # un KO suffit
            },
            "non_critical": {"clamav": {"ok": True}},
            "info": {},
        }
        assert health_mod._compute_status(checks) == "unhealthy"


# ─────────────────────────────────────────────────────────────────────────────
# 9. TestHealthEndpoints (via TestClient)
# ─────────────────────────────────────────────────────────────────────────────

def _all_ok_checks():
    ok = {"ok": True}
    return {
        "critical":     {k: ok for k in ("manifests", "pool", "auth_db", "manifest_db")},
        "non_critical": {k: ok for k in ("audit", "clamav", "reprepro", "gpg", "scheduler")},
        "info":         {"packages": ok, "license": ok, "setup": ok},
    }


def _critical_fail_checks():
    checks = _all_ok_checks()
    checks["critical"]["auth_db"] = {"ok": False, "error": "DB unavailable"}
    return checks


class TestHealthEndpoints:
    def test_live_always_200(self, client):
        resp = client.get("/health/live")
        assert resp.status_code == 200
        assert resp.json()["alive"] is True

    def test_live_has_timestamp(self, client):
        resp = client.get("/health/live")
        assert "timestamp" in resp.json()

    def test_health_healthy_200(self, client):
        with patch.object(health_mod, "_run_all_checks", return_value=_all_ok_checks()):
            resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_health_unhealthy_503(self, client):
        with patch.object(health_mod, "_run_all_checks", return_value=_critical_fail_checks()):
            resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.json()["status"] == "unhealthy"

    def test_health_degraded_200(self, client):
        checks = _all_ok_checks()
        checks["non_critical"]["clamav"] = {"ok": False, "error": "absent"}
        with patch.object(health_mod, "_run_all_checks", return_value=checks):
            resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "degraded"

    def test_health_has_checks_key(self, client):
        with patch.object(health_mod, "_run_all_checks", return_value=_all_ok_checks()):
            resp = client.get("/health")
        assert "checks" in resp.json()

    def test_ready_200_when_critical_ok(self, client):
        with (
            patch.object(health_mod, "_check_dir", return_value={"ok": True}),
            patch.object(health_mod, "_check_auth_db", return_value={"ok": True}),
            patch.object(health_mod, "_check_manifest_db", return_value={"ok": True}),
        ):
            resp = client.get("/health/ready")
        assert resp.status_code == 200
        assert resp.json()["ready"] is True

    def test_ready_503_when_critical_fail(self, client):
        with (
            patch.object(health_mod, "_check_dir", return_value={"ok": True}),
            patch.object(health_mod, "_check_auth_db", return_value={"ok": False, "error": "KO"}),
            patch.object(health_mod, "_check_manifest_db", return_value={"ok": True}),
        ):
            resp = client.get("/health/ready")
        assert resp.status_code == 503
        assert resp.json()["ready"] is False
        assert "failing" in resp.json()
