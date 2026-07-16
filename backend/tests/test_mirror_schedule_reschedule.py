# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_mirror_schedule_reschedule.py
Rôle   : routers/import_router.py:update_mirror_schedule() (POST
         /import/mirror/schedule) — la replanification à chaud du job
         APScheduler mirror_daily était enveloppée dans un `except Exception:
         pass` : si scheduler.reschedule_job()/pause_job()/resume_job()
         échouait (job non enregistré, arguments cron invalides, replica
         passif sans scheduler actif malgré la vérification is not None...),
         l'endpoint renvoyait quand même 200 avec la configuration "mise à
         jour" — alors que le job continuait de tourner sur l'ancien horaire
         jusqu'au prochain redémarrage du backend, sans aucun moyen de le
         savoir depuis la réponse de l'API.

         Ces tests couvrent le correctif : la nouvelle configuration reste
         toujours persistée (update_settings() n'est jamais concerné par cet
         échec), mais un échec de replanification à chaud est maintenant
         exposé via reschedule_warning dans la réponse, loggé, et audité.

Dépend : pytest, unittest.mock.patch, db_test_engine (fixture conftest.py,
         SQLite in-memory, autouse).
"""
from unittest.mock import MagicMock, patch

import pytest


def _client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from slowapi.errors import RateLimitExceeded

    from auth.dependencies import get_admin_user
    from limiter import limiter
    from routers.import_router import router as import_router
    from services.rate_limits import rate_limit_exceeded_handler

    app = FastAPI()
    # @limiter.limit() sur l'endpoint requiert app.state.limiter + le handler
    # d'exception associé (slowapi) pour ne pas planter au premier appel.
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    app.include_router(import_router)
    app.dependency_overrides[get_admin_user] = lambda: "admin_test"
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture
def client(db_test_engine):
    # Le limiter slowapi est un singleton partagé au niveau module — sans
    # reset, les appels des tests précédents (même IP de test "testclient")
    # s'accumulent et finissent par déclencher un 429 sans rapport avec ce
    # qui est testé ici.
    from limiter import limiter
    limiter.reset()
    return _client()


class TestRescheduleFailureIsSurfaced:

    def test_reschedule_failure_returns_warning_not_silent_200(self, client):
        """C'est le bug corrigé : reschedule_job() qui échoue doit
        maintenant apparaître dans la réponse — avant le correctif, cette
        même configuration aurait produit un 200 sans aucune trace."""
        import services.scheduler_state as sched_state

        mock_scheduler = MagicMock()
        mock_scheduler.reschedule_job.side_effect = RuntimeError("Job 'mirror_daily' n'existe pas")

        with patch.object(sched_state, "scheduler", mock_scheduler):
            resp = client.post("/import/mirror/schedule", json={"enabled": True, "hour": 5, "minute": 15})

        assert resp.status_code == 200
        data = resp.json()
        assert "reschedule_warning" in data
        assert "redémarrage" in data["reschedule_warning"]

    def test_settings_still_persisted_despite_reschedule_failure(self, client):
        """La configuration doit être enregistrée même si la replanification
        à chaud échoue — ce n'est qu'une optimisation, pas la source de
        vérité (qui est settings.json, relu par APScheduler au redémarrage)."""
        import services.scheduler_state as sched_state
        from services.settings import get_settings

        mock_scheduler = MagicMock()
        mock_scheduler.reschedule_job.side_effect = RuntimeError("boom")

        with patch.object(sched_state, "scheduler", mock_scheduler):
            resp = client.post("/import/mirror/schedule", json={"enabled": True, "hour": 7, "minute": 45})

        assert resp.status_code == 200
        assert resp.json()["hour"] == 7
        assert resp.json()["minute"] == 45
        assert get_settings()["mirror"]["hour"] == 7

    def test_successful_reschedule_has_no_warning(self, client):
        """Non-régression : le chemin nominal (reschedule_job() réussit) ne
        doit jamais inclure reschedule_warning."""
        import services.scheduler_state as sched_state

        mock_scheduler = MagicMock()  # aucun side_effect → toutes les méthodes réussissent

        with patch.object(sched_state, "scheduler", mock_scheduler):
            resp = client.post("/import/mirror/schedule", json={"enabled": True, "hour": 3, "minute": 0})

        assert resp.status_code == 200
        assert "reschedule_warning" not in resp.json()
        mock_scheduler.reschedule_job.assert_called_once()
        mock_scheduler.resume_job.assert_called_once_with("mirror_daily")

    def test_disabling_mirror_pauses_job_not_reschedules(self, client):
        import services.scheduler_state as sched_state

        mock_scheduler = MagicMock()

        with patch.object(sched_state, "scheduler", mock_scheduler):
            resp = client.post("/import/mirror/schedule", json={"enabled": False})

        assert resp.status_code == 200
        mock_scheduler.pause_job.assert_called_once_with("mirror_daily")
        mock_scheduler.reschedule_job.assert_not_called()

    def test_pause_failure_also_surfaced(self, client):
        """Le même bug existait côté pause_job() (branche enabled=False) —
        pas seulement reschedule_job()."""
        import services.scheduler_state as sched_state

        mock_scheduler = MagicMock()
        mock_scheduler.pause_job.side_effect = RuntimeError("Job introuvable")

        with patch.object(sched_state, "scheduler", mock_scheduler):
            resp = client.post("/import/mirror/schedule", json={"enabled": False})

        assert resp.status_code == 200
        assert "reschedule_warning" in resp.json()

    def test_no_scheduler_instance_no_warning(self, client):
        """Sur un replica passif (scheduler_state.scheduler is None), il n'y
        a rien à replanifier — comportement inchangé, pas un cas d'échec."""
        import services.scheduler_state as sched_state

        with patch.object(sched_state, "scheduler", None):
            resp = client.post("/import/mirror/schedule", json={"enabled": True, "hour": 2, "minute": 0})

        assert resp.status_code == 200
        assert "reschedule_warning" not in resp.json()

    def test_empty_patch_returns_current_config_without_touching_scheduler(self, client):
        """Un corps vide ({}) ne doit rien tenter de replanifier."""
        import services.scheduler_state as sched_state

        mock_scheduler = MagicMock()

        with patch.object(sched_state, "scheduler", mock_scheduler):
            resp = client.post("/import/mirror/schedule", json={})

        assert resp.status_code == 200
        mock_scheduler.reschedule_job.assert_not_called()
        mock_scheduler.pause_job.assert_not_called()
