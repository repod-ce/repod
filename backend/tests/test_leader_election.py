"""
Module : test_leader_election.py
Rôle   : Couvre services/leader_election.py (HA actif-passif) :
  - acquire_leadership() / is_leader() sur SQLite (moteur de test) → leader=True
  - require_leader : no-op si leader, HTTPException(503) sinon
  - GET /health expose info.ha (is_leader, instance_id, scheduler_active)
  - Endpoints leader-only (sync/start, mirror/start/{id}) renvoient 503
    quand is_leader() == False
Dépend : pytest, fastapi.testclient, unittest.mock
"""
import os
import tempfile
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Depends, HTTPException
from fastapi.testclient import TestClient

# ── Environnement AVANT tout import applicatif ────────────────────────────────
_TMP = tempfile.mkdtemp(prefix="repod_leader_election_")
os.environ.setdefault("MANIFEST_DIR",       _TMP)
os.environ.setdefault("POOL_DIR",           os.path.join(_TMP, "pool"))
os.environ.setdefault("STAGING_INCOMING",   os.path.join(_TMP, "staging", "incoming"))
os.environ.setdefault("STAGING_QUARANTINE", os.path.join(_TMP, "staging", "quarantine"))
os.environ.setdefault("INDEX_PATH",         os.path.join(_TMP, "index.json"))
os.environ.setdefault("AUDIT_DIR",          _TMP)
os.environ.setdefault("SECURITY_CACHE_DIR", os.path.join(_TMP, "security"))
os.environ.setdefault("JWT_SECRET_KEY",     "test-secret-leader-election")

import services.leader_election as leader_election
from services.leader_election import acquire_leadership, is_leader, require_leader

import routers.import_router as import_mod
from routers.health_router import router as health_router

from auth.dependencies import (
    get_current_user,
    get_maintainer_user,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Élection de leader — moteur SQLite (db_test_engine, autouse)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAcquireLeadership:

    def test_sqlite_engine_is_always_leader(self):
        """Sur SQLite (moteur de test), acquire_leadership() retourne toujours True."""
        assert acquire_leadership() is True
        assert is_leader() is True

    def test_postgres_dialect_check(self):
        """_is_postgres() reflète le dialect du moteur courant (sqlite en test)."""
        assert leader_election._is_postgres() is False


# ═══════════════════════════════════════════════════════════════════════════════
# require_leader — dépendance FastAPI
# ═══════════════════════════════════════════════════════════════════════════════

class TestRequireLeader:

    def test_no_op_when_leader(self):
        with patch.object(leader_election, "_is_leader", True):
            # Ne lève pas
            require_leader()

    def test_raises_503_when_not_leader(self):
        with patch.object(leader_election, "_is_leader", False):
            with pytest.raises(HTTPException) as exc_info:
                require_leader()
        assert exc_info.value.status_code == 503


# ═══════════════════════════════════════════════════════════════════════════════
# GET /health → info.ha
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def health_client():
    app = FastAPI()
    app.include_router(health_router)
    return TestClient(app, raise_server_exceptions=False)


class TestHealthHA:

    def test_health_includes_ha_info(self, health_client):
        acquire_leadership()
        r = health_client.get("/health")
        assert r.status_code == 200
        ha = r.json()["checks"]["info"]["ha"]
        assert ha["ok"] is True
        assert ha["is_leader"] is True
        assert ha["instance_id"] == leader_election.INSTANCE_ID
        assert "scheduler_active" in ha

    def test_health_ha_reflects_passive_replica(self, health_client):
        with patch.object(leader_election, "_is_leader", False):
            r = health_client.get("/health")
        assert r.status_code == 200
        ha = r.json()["checks"]["info"]["ha"]
        assert ha["is_leader"] is False


# ═══════════════════════════════════════════════════════════════════════════════
# Endpoints leader-only → 503 sur réplique passive
# ═══════════════════════════════════════════════════════════════════════════════

def _make_app(router, overrides: dict) -> TestClient:
    app = FastAPI()
    app.include_router(router)
    for dep, value in overrides.items():
        app.dependency_overrides[dep] = (lambda v=value: v)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def import_client():
    return _make_app(
        import_mod.router,
        {get_maintainer_user: "maintainer_alice", get_current_user: "maintainer_alice"},
    )


class TestLeaderOnlyEndpoints:

    def test_sync_start_503_when_not_leader(self, import_client):
        with patch.object(leader_election, "_is_leader", False):
            r = import_client.post("/import/sync/start")
        assert r.status_code == 503

    def test_sync_start_ok_when_leader(self, import_client):
        with patch.object(leader_election, "_is_leader", True), \
             patch("services.sync_manager.sync_manager.start_job") as start_job:
            start_job.return_value.job_id = "job-1"
            start_job.return_value.label = "all"
            start_job.return_value.status = "running"
            start_job.return_value.total = 0
            start_job.return_value.logs = []
            r = import_client.post("/import/sync/start")
        assert r.status_code != 503

    def test_mirror_start_503_when_not_leader(self, import_client):
        with patch.object(leader_election, "_is_leader", False):
            r = import_client.post("/import/mirror/start/debian-bookworm-main")
        assert r.status_code == 503
