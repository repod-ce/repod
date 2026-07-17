"""
Tests unitaires — tri explicite (`sort=desc|asc`) sur GET /artifacts/audit/logs.

get_recent_logs() (utilisé sans filtre `package`) renvoie les entrées du plus
récent au plus ancien, tandis que get_package_history() (utilisé avec un
filtre `package`) renvoie l'ordre inverse — cette asymétrie faisait que le
paramètre `sort` de la route ne pouvait pas se reposer sur l'ordre implicite
de la source. Ces tests couvrent le tri explicite ajouté au niveau du router.
"""

import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_audit_sort_test_")
os.environ.setdefault("MANIFEST_DIR",           _TMP)
os.environ.setdefault("MANIFEST_DB",            os.path.join(_TMP, "manifests.db"))
os.environ.setdefault("POOL_DIR",               _TMP)
os.environ.setdefault("AUDIT_DIR",              _TMP)
os.environ.setdefault("AUDIT_LOG_PATH",         os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",             os.path.join(_TMP, "index.json"))
os.environ.setdefault("SETTINGS_PATH",          os.path.join(_TMP, "settings.json"))
os.environ.setdefault("AUTH_DB_PATH",           os.path.join(_TMP, "users.db"))
os.environ.setdefault("PENDING_PROMOTIONS_DIR", os.path.join(_TMP, "pending"))

import importlib.util
from pathlib import Path
from unittest.mock import patch

import pytest


def _load_artifacts_router():
    spec = importlib.util.spec_from_file_location(
        "artifacts_isolated_audit_sort",
        Path(__file__).parent.parent / "routers" / "artifacts.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def artifacts_mod():
    return _load_artifacts_router()


@pytest.fixture(scope="module")
def client(artifacts_mod):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from auth.dependencies import get_auditor_user

    app = FastAPI()
    app.include_router(artifacts_mod.router)
    app.dependency_overrides[get_auditor_user] = lambda: "auditor"
    return TestClient(app)


def _entries():
    """Volontairement dans le désordre pour prouver que le tri est explicite."""
    return [
        {"timestamp": "2026-01-02T10:00:00+00:00", "action": "UPLOAD", "user": "alice", "result": "SUCCESS", "package": "nginx"},
        {"timestamp": "2026-01-01T10:00:00+00:00", "action": "UPLOAD", "user": "bob",   "result": "SUCCESS", "package": "curl"},
        {"timestamp": "2026-01-03T10:00:00+00:00", "action": "DELETE", "user": "alice", "result": "SUCCESS", "package": "vim"},
    ]


class TestSortNoPackageFilter:
    """Sans filtre package -> get_recent_logs()."""

    def test_default_is_desc(self, client, artifacts_mod):
        with patch.object(artifacts_mod, "get_recent_logs", return_value=_entries()):
            resp = client.get("/artifacts/audit/logs")
        assert resp.status_code == 200
        items = resp.json()["items"]
        stamps = [i["timestamp"] for i in items]
        assert stamps == sorted(stamps, reverse=True)

    def test_explicit_desc(self, client, artifacts_mod):
        with patch.object(artifacts_mod, "get_recent_logs", return_value=_entries()):
            resp = client.get("/artifacts/audit/logs?sort=desc")
        stamps = [i["timestamp"] for i in resp.json()["items"]]
        assert stamps == sorted(stamps, reverse=True)

    def test_explicit_asc(self, client, artifacts_mod):
        with patch.object(artifacts_mod, "get_recent_logs", return_value=_entries()):
            resp = client.get("/artifacts/audit/logs?sort=asc")
        stamps = [i["timestamp"] for i in resp.json()["items"]]
        assert stamps == sorted(stamps)

    def test_invalid_sort_rejected(self, client, artifacts_mod):
        with patch.object(artifacts_mod, "get_recent_logs", return_value=_entries()):
            resp = client.get("/artifacts/audit/logs?sort=bogus")
        assert resp.status_code == 422


class TestSortWithPackageFilter:
    """Avec filtre package -> get_package_history(), ordre de base inversé."""

    def test_asc_with_package_filter(self, client, artifacts_mod):
        with patch.object(artifacts_mod, "get_package_history", return_value=_entries()):
            resp = client.get("/artifacts/audit/logs?package=nginx&sort=asc")
        stamps = [i["timestamp"] for i in resp.json()["items"]]
        assert stamps == sorted(stamps)

    def test_desc_with_package_filter(self, client, artifacts_mod):
        with patch.object(artifacts_mod, "get_package_history", return_value=_entries()):
            resp = client.get("/artifacts/audit/logs?package=nginx&sort=desc")
        stamps = [i["timestamp"] for i in resp.json()["items"]]
        assert stamps == sorted(stamps, reverse=True)
