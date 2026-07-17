"""
Tests pour le mirroir planifié sécurisé :
  - settings.py : section "mirror" (defaults opt-in, is_mirror_source_enabled)
  - mirror_manager.py : MirrorJob / MirrorManager (lifecycle, cancel, counts)
  - mirror.py : _distribution_for_source, run_scheduled_mirror (skip / mapping)
  - importer_*.py : import_one() reste utilisable (régression du refactor)
"""
import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest

os.environ.setdefault("AUDIT_DIR", tempfile.mkdtemp(prefix="repod-test-audit-"))

from services.settings import get_settings, is_mirror_source_enabled
from services.mirror_manager import MirrorJob, MirrorManager
from services import mirror as mirror_module


# ─── settings.py ──────────────────────────────────────────────────────────────

def test_default_mirror_settings_present():
    cfg = get_settings()["mirror"]
    assert cfg["enabled"] is False
    assert "hour" in cfg and "minute" in cfg
    assert "max_packages_per_run" in cfg
    assert "max_runtime_minutes" in cfg
    assert "min_free_disk_gb" in cfg
    assert isinstance(cfg["sources"], dict)
    assert cfg["sources"]  # au moins une source listée
    # opt-in : tout est désactivé par défaut
    assert all(v is False for v in cfg["sources"].values())


def test_is_mirror_source_enabled_default_false():
    cfg = get_settings()["mirror"]
    any_source_id = next(iter(cfg["sources"]))
    assert is_mirror_source_enabled(any_source_id) is False


def test_is_mirror_source_enabled_unknown_source():
    assert is_mirror_source_enabled("does-not-exist") is False


# ─── MirrorJob ────────────────────────────────────────────────────────────────

def test_mirror_job_emit_and_to_dict():
    job = MirrorJob("abc123", "ubuntu-jammy", "Ubuntu 22.04 (Jammy) main", "jammy")
    job.emit("info", "hello")
    job.total = 10
    job.added_count = 3

    d = job.to_dict()
    assert d["job_id"] == "abc123"
    assert d["source_id"] == "ubuntu-jammy"
    assert d["status"] == "running"
    assert d["total"] == 10
    assert d["added_count"] == 3
    assert d["log_count"] == 1


def test_mirror_job_cancel_running_only():
    job = MirrorJob("abc", "src", "Label", "jammy")
    assert job.cancel() is True
    assert job._stop.is_set()

    job.status = "done"
    job2 = MirrorJob("def", "src", "Label", "jammy")
    job2.status = "done"
    assert job2.cancel() is False


def test_mirror_job_iter_stream_terminates_when_done():
    job = MirrorJob("abc", "src", "Label", "jammy")
    job.emit("info", "line1")
    job.status = "done"

    lines = list(job.iter_stream(from_index=0))
    assert lines[0] == "data: info|line1\n\n"
    assert lines[-1] == "data: done|DONE\n\n"


# ─── MirrorManager ────────────────────────────────────────────────────────────

@pytest.fixture
def manager():
    return MirrorManager()


def _fake_packages(n):
    return [{"name": f"pkg{i}", "version": "1.0", "format": "deb"} for i in range(n)]


def test_start_job_runs_and_counts_results(manager):
    packages = _fake_packages(4)

    results = [
        {"status": "added", "name": "pkg0", "version": "1.0", "message": "ajouté au repo"},
        {"status": "pending_review", "name": "pkg1", "version": "1.0", "message": "en attente"},
        {"status": "blocked", "name": "pkg2", "version": "1.0", "message": "bloqué"},
        {"status": "skipped", "name": "pkg3", "version": "1.0", "message": "déjà présent"},
    ]

    with patch("services.package_index.DEFAULT_SOURCES", [{"id": "ubuntu-jammy", "label": "Ubuntu Jammy"}]), \
         patch("services.package_index.sync_source", return_value={"status": "ok"}), \
         patch("services.package_index.list_packages_by_source", return_value=packages), \
         patch("services.importer.import_one", side_effect=results), \
         patch("services.audit.log") as audit_mock:

        job = manager.start_job("ubuntu-jammy", "jammy", user="tester")
        job_thread_done = job
        # Le job tourne dans un thread daemon : attendre sa fin.
        for _ in range(50):
            if job_thread_done.status != "running":
                break
            import time
            time.sleep(0.05)

    d = job.to_dict()
    assert d["status"] == "done"
    assert d["total"] == 4
    assert d["done_count"] == 4
    assert d["added_count"] == 1
    assert d["pending_count"] == 1
    assert d["blocked_count"] == 1
    assert d["skipped_count"] == 1
    assert d["error_count"] == 0
    audit_mock.assert_called_once()


def test_start_job_unknown_source_errors(manager):
    with patch("services.package_index.DEFAULT_SOURCES", []):
        job = manager.start_job("does-not-exist", "jammy", user="tester")
        for _ in range(50):
            if job.status != "running":
                break
            import time
            time.sleep(0.05)

    assert job.status == "error"


def test_start_job_returns_existing_active_job(manager):
    """Un seul job de mirroir actif à la fois."""
    job1 = MirrorJob("job1", "ubuntu-jammy", "Ubuntu Jammy", "jammy")
    manager._jobs["job1"] = job1  # status="running" par défaut

    with patch("services.package_index.DEFAULT_SOURCES", [{"id": "other", "label": "Other"}]):
        job2 = manager.start_job("other", "jammy", user="tester")

    assert job2.job_id == job1.job_id


def test_list_jobs_and_get_job(manager):
    job = MirrorJob("xyz", "ubuntu-jammy", "Ubuntu Jammy", "jammy")
    job.status = "done"
    manager._jobs["xyz"] = job

    assert manager.get_job("xyz") is job
    assert manager.get_job("missing") is None

    jobs = manager.list_jobs()
    assert any(j["job_id"] == "xyz" for j in jobs)


# ─── mirror.py ────────────────────────────────────────────────────────────────

def test_distribution_for_source_apt_uses_mapping():
    source = {"id": "ubuntu-jammy", "distro": "jammy"}
    with patch.object(mirror_module, "detect_distribution_from_source", return_value="jammy") as m:
        assert mirror_module._distribution_for_source(source) == "jammy"
        m.assert_called_once_with("ubuntu-jammy")


def test_distribution_for_source_apk_uses_distro_field():
    source = {"id": "alpine3.21-main", "format": "apk", "distro": "alpine3.21"}
    with patch.object(mirror_module, "detect_distribution_from_source") as m:
        assert mirror_module._distribution_for_source(source) == "alpine3.21"
        m.assert_not_called()


def test_run_scheduled_mirror_skips_when_disabled():
    with patch("services.mirror.get_settings", return_value={"mirror": {"enabled": False}}):
        result = mirror_module.run_scheduled_mirror()
    assert result == {"skipped": True}


def test_run_scheduled_mirror_skips_when_no_sources_enabled():
    cfg = {"mirror": {"enabled": True, "sources": {"ubuntu-jammy": False}}}
    with patch("services.mirror.get_settings", return_value=cfg):
        result = mirror_module.run_scheduled_mirror()
    assert result == {"skipped": True, "reason": "no sources enabled"}


def test_run_scheduled_mirror_starts_job_for_enabled_source():
    cfg = {
        "mirror": {
            "enabled": True,
            "sources": {"ubuntu-jammy": True},
            "max_packages_per_run": 50,
            "max_runtime_minutes": 90,
        }
    }
    source = {"id": "ubuntu-jammy", "label": "Ubuntu Jammy", "distro": "jammy"}

    fake_job = MagicMock()
    fake_job.status = "done"
    fake_job.to_dict.return_value = {
        "label": "Ubuntu Jammy", "added_count": 2, "pending_count": 0,
        "blocked_count": 0, "error_count": 0, "total": 2,
    }

    with patch("services.mirror.get_settings", return_value=cfg), \
         patch("services.mirror.DEFAULT_SOURCES", [source]), \
         patch.object(mirror_module.mirror_manager, "start_job", return_value=fake_job) as start_mock:

        result = mirror_module.run_scheduled_mirror()

    start_mock.assert_called_once_with("ubuntu-jammy", "jammy", user="scheduler", limit=50)
    assert result["skipped"] is False
    assert len(result["sources"]) == 1
    assert result["total_pending"] == 0
    assert result["total_blocked"] == 0
