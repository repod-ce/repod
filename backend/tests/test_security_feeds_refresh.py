# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Tests pour le rafraîchissement automatique des bases de sécurité
(Grype / KEV / EPSS) — voir services/cve_enrichment.py:refresh_epss_bulk()
et son intégration dans services/security_sync.py:run_security_sync() +
routers/scan_router.py:feeds_refresh().
"""
import json
import os
import time
from unittest.mock import MagicMock, patch

import pytest


# ═════════════════════════════════════════════════════════════════════════════
# 1. TestRefreshEpssBulk — services/cve_enrichment.py
# ═════════════════════════════════════════════════════════════════════════════

class TestRefreshEpssBulk:
    def test_success_saves_cache_and_returns_count(self):
        from services import cve_enrichment as ce

        fake_resp = MagicMock()
        fake_resp.raise_for_status.return_value = None
        fake_resp.json.return_value = {
            "data": [
                {"cve": "CVE-2024-0001", "epss": "0.9123", "percentile": "0.995"},
                {"cve": "CVE-2024-0002", "epss": "0.01", "percentile": "0.20"},
            ]
        }

        with patch.object(ce, "_get_with_retry", return_value=fake_resp) as mock_get, \
             patch.object(ce, "_save_epss_cache") as mock_save:
            ok, count = ce.refresh_epss_bulk(days=30, limit=10000)

        assert ok is True
        assert count == 2
        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        assert kwargs["params"] == {"days": 30, "limit": 10000}
        saved_scores = mock_save.call_args[0][0]
        assert saved_scores["CVE-2024-0001"]["score"] == pytest.approx(0.9123)
        assert saved_scores["CVE-2024-0002"]["percentile"] == pytest.approx(0.20)

    def test_network_failure_keeps_cache_and_returns_false(self):
        from services import cve_enrichment as ce

        with patch.object(ce, "_get_with_retry", side_effect=ConnectionError("boom")), \
             patch.object(ce, "_save_epss_cache") as mock_save:
            ok, count = ce.refresh_epss_bulk()

        assert ok is False
        assert count == 0
        mock_save.assert_not_called()

    def test_http_error_status_keeps_cache_and_returns_false(self):
        from services import cve_enrichment as ce

        fake_resp = MagicMock()
        fake_resp.raise_for_status.side_effect = Exception("500 Server Error")

        with patch.object(ce, "_get_with_retry", return_value=fake_resp), \
             patch.object(ce, "_save_epss_cache") as mock_save:
            ok, count = ce.refresh_epss_bulk()

        assert ok is False
        assert count == 0
        mock_save.assert_not_called()

    def test_entries_without_cve_field_are_skipped(self):
        from services import cve_enrichment as ce

        fake_resp = MagicMock()
        fake_resp.raise_for_status.return_value = None
        fake_resp.json.return_value = {
            "data": [
                {"cve": "CVE-2024-0001", "epss": "0.5", "percentile": "0.5"},
                {"epss": "0.9", "percentile": "0.9"},  # pas de "cve" → ignoré
            ]
        }

        with patch.object(ce, "_get_with_retry", return_value=fake_resp), \
             patch.object(ce, "_save_epss_cache") as mock_save:
            ok, count = ce.refresh_epss_bulk()

        assert ok is True
        assert count == 1
        assert "CVE-2024-0001" in mock_save.call_args[0][0]


# ═════════════════════════════════════════════════════════════════════════════
# 2. TestRunSecuritySyncFeedsRefresh — services/security_sync.py
# ═════════════════════════════════════════════════════════════════════════════

class TestRunSecuritySyncFeedsRefresh:
    def _patched(self, **overrides):
        """Patch les dépendances de run_security_sync() avec des valeurs par défaut sûres."""
        from services import security_sync as ss

        defaults = dict(
            update_grype_db=MagicMock(return_value={"ok": True, "output": ""}),
            refresh_kev=MagicMock(return_value=True),
            refresh_epss_bulk=MagicMock(return_value=(True, 42)),
            sync_source=MagicMock(return_value={"status": "ok", "pkg_count": 10}),
            get_settings=MagicMock(return_value={"sources": {}}),
        )
        defaults.update(overrides)
        return ss, defaults

    def test_kev_and_epss_refreshed_on_every_run(self, monkeypatch):
        ss, mocks = self._patched()
        with patch.object(ss, "update_grype_db", mocks["update_grype_db"]), \
             patch.object(ss, "refresh_kev", mocks["refresh_kev"]), \
             patch.object(ss, "refresh_epss_bulk", mocks["refresh_epss_bulk"]), \
             patch.object(ss, "sync_source", mocks["sync_source"]), \
             patch.object(ss, "get_settings", mocks["get_settings"]), \
             patch.object(ss, "audit_log") as mock_audit:
            ss.run_security_sync()

        mocks["refresh_kev"].assert_called_once()
        mocks["refresh_epss_bulk"].assert_called_once()

        audit_events = [c.args[0] for c in mock_audit.call_args_list]
        assert "KEV_UPDATE" in audit_events
        assert "EPSS_UPDATE" in audit_events

    def test_kev_failure_does_not_abort_sync(self, monkeypatch):
        """Un échec KEV ne doit ni lever d'exception ni empêcher le reste de la synchro."""
        ss, mocks = self._patched(refresh_kev=MagicMock(return_value=False))
        with patch.object(ss, "update_grype_db", mocks["update_grype_db"]), \
             patch.object(ss, "refresh_kev", mocks["refresh_kev"]), \
             patch.object(ss, "refresh_epss_bulk", mocks["refresh_epss_bulk"]), \
             patch.object(ss, "sync_source", mocks["sync_source"]), \
             patch.object(ss, "get_settings", mocks["get_settings"]), \
             patch.object(ss, "audit_log") as mock_audit:
            result = ss.run_security_sync()

        mocks["refresh_epss_bulk"].assert_called_once()
        assert "sources" in result

        kev_calls = [c for c in mock_audit.call_args_list if c.args[0] == "KEV_UPDATE"]
        assert len(kev_calls) == 1
        assert kev_calls[0].args[2] == "WARNING"

    def test_epss_failure_does_not_abort_sync(self, monkeypatch):
        ss, mocks = self._patched(refresh_epss_bulk=MagicMock(return_value=(False, 0)))
        with patch.object(ss, "update_grype_db", mocks["update_grype_db"]), \
             patch.object(ss, "refresh_kev", mocks["refresh_kev"]), \
             patch.object(ss, "refresh_epss_bulk", mocks["refresh_epss_bulk"]), \
             patch.object(ss, "sync_source", mocks["sync_source"]), \
             patch.object(ss, "get_settings", mocks["get_settings"]), \
             patch.object(ss, "audit_log") as mock_audit:
            result = ss.run_security_sync()

        mocks["refresh_kev"].assert_called_once()
        assert "sources" in result

        epss_calls = [c for c in mock_audit.call_args_list if c.args[0] == "EPSS_UPDATE"]
        assert len(epss_calls) == 1
        assert epss_calls[0].args[2] == "WARNING"

    def test_grype_kev_epss_all_run_independently(self, monkeypatch):
        """Grype échoue, KEV/EPSS réussissent quand même — aucune dépendance entre les trois."""
        ss, mocks = self._patched(
            update_grype_db=MagicMock(return_value={"ok": False, "output": "disk full"})
        )
        with patch.object(ss, "update_grype_db", mocks["update_grype_db"]), \
             patch.object(ss, "refresh_kev", mocks["refresh_kev"]), \
             patch.object(ss, "refresh_epss_bulk", mocks["refresh_epss_bulk"]), \
             patch.object(ss, "sync_source", mocks["sync_source"]), \
             patch.object(ss, "get_settings", mocks["get_settings"]):
            ss.run_security_sync()

        mocks["refresh_kev"].assert_called_once()
        mocks["refresh_epss_bulk"].assert_called_once()


# ═════════════════════════════════════════════════════════════════════════════
# 3. TestFeedsRefreshEndpoint — routers/scan_router.py (régression post-refactor)
# ═════════════════════════════════════════════════════════════════════════════

class TestFeedsRefreshEndpointUsesSharedFunction:
    def _client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from routers import scan_router
        from auth.dependencies import get_admin_user

        app = FastAPI()
        app.include_router(scan_router.router, prefix="/api/v1")
        app.dependency_overrides[get_admin_user] = lambda: "admin_test"
        return TestClient(app), scan_router

    def test_feeds_refresh_calls_refresh_epss_bulk(self):
        client, scan_router = self._client()

        with patch("services.cve_enrichment.refresh_kev", return_value=True), \
             patch("services.cve_enrichment.get_kev_meta",
                   return_value={"total": 5, "catalog_version": "2026.01.01"}), \
             patch("services.cve_enrichment.refresh_epss_bulk",
                   return_value=(True, 123)) as mock_epss, \
             patch("services.audit.log"):
            resp = client.post("/api/v1/security/feeds/refresh")

        assert resp.status_code == 200
        body = resp.text
        assert "123 scores charges" in body
        mock_epss.assert_called_once()

    def test_feeds_refresh_epss_failure_reports_warning_not_crash(self):
        client, scan_router = self._client()

        with patch("services.cve_enrichment.refresh_kev", return_value=True), \
             patch("services.cve_enrichment.get_kev_meta",
                   return_value={"total": 5, "catalog_version": "2026.01.01"}), \
             patch("services.cve_enrichment.refresh_epss_bulk",
                   return_value=(False, 0)), \
             patch("services.audit.log"):
            resp = client.post("/api/v1/security/feeds/refresh")

        assert resp.status_code == 200
        assert "WARN" in resp.text
        assert "impossible de recuperer les scores" in resp.text


# ═════════════════════════════════════════════════════════════════════════════
# 4. TestConfigurableTtl — settings.security.{kev,epss}_ttl_hours réellement lus
# ═════════════════════════════════════════════════════════════════════════════

class TestConfigurableTtl:
    def test_get_ttl_hours_reads_from_settings(self):
        from services import cve_enrichment as ce

        with patch("services.settings.get_settings",
                   return_value={"security": {"kev_ttl_hours": 6}}):
            assert ce._get_ttl_hours("kev_ttl_hours") == 6

    def test_get_ttl_hours_falls_back_to_default_when_key_absent(self):
        from services import cve_enrichment as ce

        with patch("services.settings.get_settings", return_value={"security": {}}):
            assert ce._get_ttl_hours("kev_ttl_hours") == ce.CACHE_TTL_HOURS

    def test_get_ttl_hours_falls_back_to_default_when_section_absent(self):
        from services import cve_enrichment as ce

        with patch("services.settings.get_settings", return_value={}):
            assert ce._get_ttl_hours("epss_ttl_hours") == ce.CACHE_TTL_HOURS

    def test_get_ttl_hours_falls_back_on_settings_error(self):
        from services import cve_enrichment as ce

        with patch("services.settings.get_settings", side_effect=RuntimeError("boom")):
            assert ce._get_ttl_hours("epss_ttl_hours") == ce.CACHE_TTL_HOURS

    def test_get_kev_meta_honours_configured_ttl(self, tmp_path):
        from services import cve_enrichment as ce

        cache_path = tmp_path / "kev_cache.json"
        cache_path.write_text(json.dumps({
            "cve_ids": ["CVE-2024-0001"], "total": 1,
            "fetched_at": "2026-01-01T00:00:00Z", "catalog_version": "v1",
        }))
        old = time.time() - 2 * 3600  # cache vieux de 2h
        os.utime(cache_path, (old, old))

        with patch.object(ce, "KEV_CACHE_PATH", cache_path), \
             patch("services.settings.get_settings",
                   return_value={"security": {"kev_ttl_hours": 6}}):
            meta = ce.get_kev_meta()
        assert meta["ttl_hours"] == 6
        assert meta["cache_fresh"] is True  # 2h < TTL 6h

        with patch.object(ce, "KEV_CACHE_PATH", cache_path), \
             patch("services.settings.get_settings",
                   return_value={"security": {"kev_ttl_hours": 1}}):
            meta = ce.get_kev_meta()
        assert meta["ttl_hours"] == 1
        assert meta["cache_fresh"] is False  # 2h > TTL 1h

    def test_get_epss_meta_honours_configured_ttl(self, tmp_path):
        from services import cve_enrichment as ce

        cache_path = tmp_path / "epss_cache.json"
        cache_path.write_text(json.dumps({
            "scores": {"CVE-2024-0001": {"score": 0.5, "percentile": 0.5}},
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        old = time.time() - 2 * 3600
        os.utime(cache_path, (old, old))

        with patch.object(ce, "EPSS_CACHE_PATH", cache_path), \
             patch("services.settings.get_settings",
                   return_value={"security": {"epss_ttl_hours": 1}}):
            meta = ce.get_epss_meta()
        assert meta["ttl_hours"] == 1
        assert meta["cache_fresh"] is False
        assert meta["count"] == 1

    def test_get_epss_scores_skips_network_when_within_configured_ttl(self, tmp_path):
        """Un TTL configuré plus long doit éviter un appel réseau évitable."""
        from services import cve_enrichment as ce

        cache_path = tmp_path / "epss_cache.json"
        cache_path.write_text(json.dumps({
            "scores": {"CVE-2024-0001": {"score": 0.42, "percentile": 0.9}},
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        old = time.time() - 2 * 3600
        os.utime(cache_path, (old, old))

        with patch.object(ce, "EPSS_CACHE_PATH", cache_path), \
             patch("services.settings.get_settings",
                   return_value={"security": {"epss_ttl_hours": 6}}), \
             patch.object(ce, "_get_with_retry") as mock_get:
            result = ce.get_epss_scores(["CVE-2024-0001"])

        mock_get.assert_not_called()
        assert result["CVE-2024-0001"]["score"] == pytest.approx(0.42)

    def test_get_epss_scores_refetches_when_ttl_shortened(self, tmp_path):
        """Un TTL configuré plus court doit forcer un re-fetch d'un cache par ailleurs frais."""
        from services import cve_enrichment as ce

        cache_path = tmp_path / "epss_cache.json"
        cache_path.write_text(json.dumps({
            "scores": {"CVE-2024-0001": {"score": 0.1, "percentile": 0.1}},
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        old = time.time() - 2 * 3600
        os.utime(cache_path, (old, old))

        fake_resp = MagicMock()
        fake_resp.raise_for_status.return_value = None
        fake_resp.json.return_value = {
            "data": [{"cve": "CVE-2024-0001", "epss": "0.9", "percentile": "0.99"}]
        }

        with patch.object(ce, "EPSS_CACHE_PATH", cache_path), \
             patch("services.settings.get_settings",
                   return_value={"security": {"epss_ttl_hours": 1}}), \
             patch.object(ce, "_get_with_retry", return_value=fake_resp) as mock_get:
            result = ce.get_epss_scores(["CVE-2024-0001"])

        mock_get.assert_called_once()
        assert result["CVE-2024-0001"]["score"] == pytest.approx(0.9)

    def test_feeds_status_endpoint_returns_per_source_ttl(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from routers import scan_router
        from auth.dependencies import get_current_user

        app = FastAPI()
        app.include_router(scan_router.router, prefix="/api/v1")
        app.dependency_overrides[get_current_user] = lambda: "user_test"
        client = TestClient(app)

        with patch("services.cve_enrichment.get_kev_meta",
                   return_value={"total": 0, "fetched_at": None, "catalog_version": "",
                                  "ttl_hours": 6, "cache_fresh": True}), \
             patch("services.cve_enrichment.get_epss_meta",
                   return_value={"count": 0, "updated_at": None,
                                  "ttl_hours": 2, "cache_fresh": False}):
            resp = client.get("/api/v1/security/feeds/status")

        assert resp.status_code == 200
        body = resp.json()
        assert body["kev"]["ttl_hours"] == 6
        assert body["kev"]["fresh"] is True
        assert body["epss"]["ttl_hours"] == 2
        assert body["epss"]["fresh"] is False
