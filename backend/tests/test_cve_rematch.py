"""
Module : test_cve_rematch.py
Rôle   : services/cve_rematch.py — re-matching CVE périodique via SBOM
         stocké (Grype seul, APT/RPM/APK).

         Couvre : rematch_one() (SBOM absent → skip ; CVE nouvelle
         dépassant cve_policy → pending_review ; CVE déjà connue disparue
         du nouveau matching (base Grype corrigée) → pas de décision, juste
         rafraîchissement de cve_results ; CVE nouvelle sous le seuil de
         policy → reste validated ; erreur grype → status error), et
         run_cve_rematch() (borne max_artifacts, comptage
         scanned/flagged/errors/skipped).

Dépend : pytest, conftest.db_test_engine (SQLite in-memory de test), unittest.mock
"""
import json
from unittest.mock import MagicMock, patch

from services.cve_rematch import rematch_one, run_cve_rematch
from services.manifest import load_manifest, save_manifest

_POLICY = {"critical": "block", "high": "review", "medium": "warn", "low": "allow"}


def _manifest(name="curltest", version="1.0-1", arch="amd64", cve_results=None, status="validated"):
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
        "status": status,
        "tags": [],
        "validation_steps": [],
        "cve_results": cve_results or [],
    }


def _publish(**kwargs) -> dict:
    manifest = _manifest(**kwargs)
    save_manifest(manifest)
    return load_manifest(manifest["name"], manifest["version"], manifest["arch"])


def _grype_match(cve_id, severity="High"):
    return {
        "vulnerability": {"id": cve_id, "severity": severity, "fix": {}, "urls": []},
        "artifact": {"name": "curltest", "version": "1.0-1", "type": "deb"},
    }


def _grype_json(matches):
    return json.dumps({"matches": matches})


def _mock_subprocess(stdout, returncode=0):
    r = MagicMock()
    r.returncode = returncode
    r.stdout = stdout
    r.stderr = ""
    return r


class TestRematchOne:

    def test_no_sbom_stored_is_skipped(self, db_test_engine):
        manifest = _publish()
        with patch("services.component_sbom.load_component_sbom", return_value=None):
            result = rematch_one(manifest)
        assert result["status"] == "skipped"

    def test_newly_appeared_cve_breaching_policy_triggers_pending_review(self, db_test_engine):
        manifest = _publish(cve_results=[])
        grype_output = _grype_json([_grype_match("CVE-2026-9999", "High")])
        with patch("services.component_sbom.load_component_sbom", return_value={"components": []}), \
             patch("services.cve_rematch.subprocess.run", return_value=_mock_subprocess(grype_output)), \
             patch("services.cve_enrichment.get_epss_scores", return_value={}), \
             patch("services.cve_enrichment.get_kev_set", return_value=set()), \
             patch("services.settings.get_settings", return_value={"cve_policy": _POLICY}):
            result = rematch_one(manifest)

        assert result["status"] == "pending_review"
        reloaded = load_manifest("curltest", "1.0-1", "amd64")
        assert reloaded["status"] == "pending_review"
        assert reloaded["last_rematch_at"]
        assert {c["id"] for c in reloaded["cve_results"]} == {"CVE-2026-9999"}

    def test_known_cve_disappearing_does_not_retrigger_decision(self, db_test_engine):
        """Une CVE déjà connue qui disparaît du nouveau matching (base Grype
        corrigée depuis) ne doit jamais rouvrir une révision — cve_results
        est simplement rafraîchi avec le nouveau set (vide ici)."""
        manifest = _publish(cve_results=[{"id": "CVE-2026-OLD", "severity": "Critical"}])
        grype_output = _grype_json([])  # plus aucune correspondance
        with patch("services.component_sbom.load_component_sbom", return_value={"components": []}), \
             patch("services.cve_rematch.subprocess.run", return_value=_mock_subprocess(grype_output)), \
             patch("services.cve_enrichment.get_epss_scores", return_value={}), \
             patch("services.cve_enrichment.get_kev_set", return_value=set()), \
             patch("services.settings.get_settings", return_value={"cve_policy": _POLICY}):
            result = rematch_one(manifest)

        assert result["status"] == "validated"
        reloaded = load_manifest("curltest", "1.0-1", "amd64")
        assert reloaded["status"] == "validated"
        assert reloaded["cve_results"] == []

    def test_newly_appeared_cve_under_policy_stays_validated(self, db_test_engine):
        manifest = _publish(cve_results=[])
        grype_output = _grype_json([_grype_match("CVE-2026-1111", "Low")])
        with patch("services.component_sbom.load_component_sbom", return_value={"components": []}), \
             patch("services.cve_rematch.subprocess.run", return_value=_mock_subprocess(grype_output)), \
             patch("services.cve_enrichment.get_epss_scores", return_value={}), \
             patch("services.cve_enrichment.get_kev_set", return_value=set()), \
             patch("services.settings.get_settings", return_value={"cve_policy": _POLICY}):
            result = rematch_one(manifest)

        assert result["status"] == "validated"
        reloaded = load_manifest("curltest", "1.0-1", "amd64")
        assert reloaded["status"] == "validated"

    def test_grype_error_returns_error_status(self, db_test_engine):
        manifest = _publish(cve_results=[])
        with patch("services.component_sbom.load_component_sbom", return_value={"components": []}), \
             patch("services.cve_rematch.subprocess.run", return_value=_mock_subprocess("", returncode=2)):
            result = rematch_one(manifest)
        assert result["status"] == "error"


class TestRunCveRematch:

    def test_respects_max_artifacts(self, db_test_engine):
        for i in range(5):
            _publish(name=f"pkg-{i}", cve_results=[{"id": "CVE-2026-0001", "severity": "Low"}])

        with patch("services.cve_rematch.rematch_one", return_value={"status": "skipped"}) as mock_one:
            summary = run_cve_rematch(max_artifacts=2)

        assert mock_one.call_count == 2
        assert summary["skipped"] == 2

    def test_counts_scanned_flagged_errors(self, db_test_engine):
        for i in range(3):
            _publish(name=f"pkg-{i}", cve_results=[])

        results = iter([
            {"status": "validated"},
            {"status": "pending_review"},
            {"status": "error"},
        ])
        with patch("services.cve_rematch.rematch_one", side_effect=lambda m: next(results)):
            summary = run_cve_rematch(max_artifacts=10)

        assert summary["scanned"] == 3
        assert summary["flagged"] == 1
        assert summary["errors"] == 1
