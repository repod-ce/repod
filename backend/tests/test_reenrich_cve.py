"""
Module : test_reenrich_cve.py
Rôle   : services/manifest.py:reenrich_manifest_cve() — ré-enrichissement
         EPSS/KEV des manifests déjà scannés, sans relancer Grype. Voir le
         docstring de reenrich_manifest_cve() pour le bug réel que ça
         corrige (EPSS figé à 0% indéfiniment).

Dépend : pytest, conftest.db_test_engine (SQLite in-memory de test), unittest.mock
"""
import time
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from auth.roles import seed_builtin_roles
from auth.users import create_user
from services.manifest import (
    invalidate_manifest_cache,
    load_manifest,
    reenrich_manifest_cve,
    save_manifest,
)


@pytest.fixture(autouse=True)
def _clear_manifest_cache():
    """
    list_manifests() a un cache in-memory (MANIFEST_CACHE_TTL) qui n'est
    jamais invalidé par le TRUNCATE SQL direct de db_test_engine (seul
    save_manifest() déclenche invalidate_manifest_cache()) — sans ce
    fixture, un manifest créé par un test précédent reste visible dans le
    cache d'un test suivant même après le TRUNCATE.
    """
    invalidate_manifest_cache()
    yield
    invalidate_manifest_cache()


def _manifest(name="curltest", version="1.0-1", arch="amd64", cve_results=None):
    return {
        "name": name,
        "version": version,
        "arch": arch,
        "section": "test",
        "description": "test package",
        "maintainer": "",
        "installed_size_kb": 0,
        "file_size_bytes": 0,
        "filename": f"{name}_{version}_{arch}.deb",
        "type": "deb",
        "distribution": "jammy",
        "source": {"imported_by": "test", "imported_at": "2026-07-22T00:00:00+00:00", "import_method": "upload"},
        "integrity": {},
        "dependencies": [],
        "status": "validated",
        "tags": [],
        "validation_steps": [],
        "cve_results": cve_results or [],
    }


class TestReenrichManifestCve:

    def test_no_manifests_with_cve_returns_zero(self, db_test_engine):
        save_manifest(_manifest("nocve", cve_results=[]))
        result = reenrich_manifest_cve()
        assert result["updated"] == 0
        assert result["manifests_with_cve"] == 0

    def test_updates_epss_from_cache_without_touching_cve_list_or_description(self, db_test_engine):
        """
        Régression directe du bug réel : une CVE avec epss_percent=0
        (figée au moment du scan) doit récupérer le vrai score une fois
        le cache EPSS rafraîchi — sans que l'ID de la CVE, sa description
        ou sa sévérité (des champs qui ne viennent QUE d'un scan Grype
        réel, jamais de l'enrichissement) ne changent.
        """
        cve = {
            "id": "CVE-2026-11856",
            "severity": "Medium",
            "cvss": None,
            "description": "",
            "package_name": "curltest",
            "package_version": "1.0-1",
            "package_type": "deb",
            "fix_state": "not-fixed",
            "fix_versions": [],
            "urls": [],
            "epss": 0.0,
            "epss_percent": 0.0,
            "epss_label": "Faible",
            "in_kev": False,
            "epss_percentile": 0.0,
        }
        save_manifest(_manifest(cve_results=[cve]))

        with patch("services.cve_enrichment.get_epss_scores") as mock_epss, \
             patch("services.cve_enrichment.get_kev_set") as mock_kev:
            mock_epss.return_value = {"CVE-2026-11856": {"score": 0.01064, "percentile": 0.6098}}
            mock_kev.return_value = set()
            result = reenrich_manifest_cve()

        assert result["updated"] == 1
        assert result["manifests_with_cve"] == 1

        updated = load_manifest("curltest", "1.0-1", "amd64")
        updated_cve = updated["cve_results"][0]
        assert updated_cve["id"] == "CVE-2026-11856"           # inchangé
        assert updated_cve["severity"] == "Medium"              # inchangé
        assert updated_cve["description"] == ""                 # inchangé (pas de scan Grype relancé)
        assert updated_cve["epss_percent"] == 1.06               # mis à jour
        assert updated_cve["epss"] == pytest.approx(0.01064)

    def test_epss_kev_fetched_once_for_all_manifests_not_once_per_manifest(self, db_test_engine):
        """
        Optimisation attendue : get_epss_scores()/get_kev_set() doivent être
        appelés UNE SEULE fois pour tout le lot, pas une fois par manifest
        (le catalogue peut compter plusieurs centaines de paquets).
        """
        save_manifest(_manifest("pkg-a", cve_results=[{"id": "CVE-2026-0001", "epss_percent": 0.0}]))
        save_manifest(_manifest("pkg-b", cve_results=[{"id": "CVE-2026-0002", "epss_percent": 0.0}]))
        save_manifest(_manifest("pkg-c", cve_results=[{"id": "CVE-2026-0003", "epss_percent": 0.0}]))

        with patch("services.cve_enrichment.get_epss_scores") as mock_epss, \
             patch("services.cve_enrichment.get_kev_set") as mock_kev:
            mock_epss.return_value = {}
            mock_kev.return_value = set()
            result = reenrich_manifest_cve()

        assert mock_epss.call_count == 1
        assert mock_kev.call_count == 1
        assert result["updated"] == 3

    def test_manifest_without_cve_results_is_skipped(self, db_test_engine):
        save_manifest(_manifest("clean-pkg", cve_results=[]))
        save_manifest(_manifest("vuln-pkg", cve_results=[{"id": "CVE-2026-9999", "epss_percent": 0.0}]))

        with patch("services.cve_enrichment.get_epss_scores") as mock_epss, \
             patch("services.cve_enrichment.get_kev_set") as mock_kev:
            mock_epss.return_value = {}
            mock_kev.return_value = set()
            result = reenrich_manifest_cve()

        assert result["manifests_with_cve"] == 1
        assert result["updated"] == 1

    def test_enrichment_failure_is_non_fatal(self, db_test_engine):
        """Même comportement "best-effort" que enrich_cve_list() lui-même —
        un échec réseau/cache ne doit jamais faire planter le ré-enrichissement,
        juste laisser les scores existants inchangés (0.0 par défaut)."""
        save_manifest(_manifest(cve_results=[{"id": "CVE-2026-1234", "epss_percent": 0.0}]))

        with patch("services.cve_enrichment.get_epss_scores", side_effect=Exception("network down")), \
             patch("services.cve_enrichment.get_kev_set", side_effect=Exception("network down")):
            result = reenrich_manifest_cve()

        assert result["updated"] == 1  # le manifest est bien "traité", juste sans nouveau score


class TestReenrichCveEndpoint:
    """POST /admin/reenrich-cve (routers/artifacts.py)."""

    def _client(self) -> TestClient:
        from routers.artifacts import router as artifacts_router

        app = FastAPI()
        app.include_router(artifacts_router, prefix="/api/v1")
        return TestClient(app, raise_server_exceptions=False)

    def _auth_header(self, username: str, role: str) -> dict:
        from auth.jwt import create_access_token
        token = create_access_token({"sub": username, "role": role})
        return {"Authorization": f"Bearer {token}"}

    def test_maintainer_triggers_background_reenrich(self, db_test_engine):
        seed_builtin_roles()
        create_user("maint1", "Passw0rd!23", "maintainer")
        client = self._client()

        with patch("routers.artifacts.reenrich_manifest_cve") as mock_reenrich:
            mock_reenrich.return_value = {"updated": 0, "manifests_with_cve": 0, "cve_ids_checked": 0}
            r = client.post("/api/v1/artifacts/admin/reenrich-cve", headers=self._auth_header("maint1", "maintainer"))
            assert r.status_code == 202
            # Le thread démarre en arrière-plan — laisser une fenêtre courte
            # pour qu'il s'exécute avant de vérifier l'appel.
            time.sleep(0.3)

        mock_reenrich.assert_called_once()

    def test_reader_forbidden(self, db_test_engine):
        seed_builtin_roles()
        create_user("reader1", "Passw0rd!23", "reader")
        client = self._client()
        r = client.post("/api/v1/artifacts/admin/reenrich-cve", headers=self._auth_header("reader1", "reader"))
        assert r.status_code == 403
