# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_importer_pending_review_gate.py
Rôle   : services/importer_rpm.py et services/importer_apk.py:import_one() ne
         vérifiaient jamais validation.cve_status == "pending_review" avant de
         publier le paquet — seul `not validation.passed` était testé, or
         `pending_review` laisse `passed=True` (seul `blocked` le force à
         False, voir validator_rpm.py/validator_apk.py). Un paquet RPM/APK
         importé depuis internet avec une CVE en politique "review" était donc
         publié directement dans le dépôt (add-rpm.sh / apk_add_package()),
         contournant entièrement la révision RSSI — alors que le même cas est
         correctement bloqué pour l'upload manuel (routers/upload.py) et pour
         l'import APT (services/importer_apt.py, qui sert de référence ici).

         Ces tests verrouillent le correctif : import_one() doit retourner
         status="pending_review" sans jamais appeler le script de publication,
         et le manifest doit porter status="pending_review".

Dépend : pytest, unittest.mock.patch — aucun subprocess/réseau réel.
"""
import importlib
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _fresh_validator_module():
    """
    tests/test_format_router.py recharge services.format_router en supprimant
    aussi services.validator de sys.modules (_reload_format_router()), sans
    jamais le ré-importer lui-même ensuite — le paquet `services` garde alors
    un attribut `validator` orphelin pointant sur l'ancien objet module.
    unittest.mock.patch("services.validator.X", ...) résout sa cible via
    getattr(package, "validator") *avant* de retomber sur sys.modules, donc
    quand ce test tourne après test_format_router.py, patch() finit par
    patcher cet objet orphelin — jamais celui qu'un `import` natif ultérieur
    (comme le `from services.validator import run_validation_pipeline` local
    dans import_one()) résoudrait réellement, désynchronisant silencieusement
    le mock du code sous test. Un reload natif ici avant chaque test force la
    cohérence entre sys.modules et l'attribut du paquet parent.
    """
    if "services.validator" in sys.modules:
        importlib.reload(sys.modules["services.validator"])
    else:
        import services.validator  # noqa: F401


def _fake_manifest(name="webapp", version="1.0-1"):
    return {
        "name": name,
        "version": version,
        "arch": "x86_64",
        "integrity": {"sha256": "deadbeef"},
    }


class TestRpmImportOnePendingReviewGate:
    def _validation(self, cve_status):
        v = MagicMock()
        v.passed = True
        v.cve_status = cve_status
        v.steps = [{"name": "cve", "passed": True, "message": "Grype — 1 High · Révision RSSI requise"}]
        v.deps = []
        v.cve_results = [{"id": "CVE-2026-0001", "severity": "High"}]
        return v

    def test_pending_review_is_not_published(self):
        import services.importer_rpm as imp

        with tempfile.TemporaryDirectory() as tmp:
            rpm_path = Path(tmp) / "src" / "webapp-1.0-1.x86_64.rpm"
            rpm_path.parent.mkdir()
            rpm_path.write_bytes(b"fake-rpm")
            pool_dir = Path(tmp) / "pool"
            pool_dir.mkdir()

            with patch("services.importer_rpm.POOL_DIR", pool_dir), \
                 patch("services.importer_rpm._download_rpm",
                       return_value=(rpm_path, "test-source", "deadbeef")), \
                 patch("services.indexer.get_package_info", return_value=None), \
                 patch("services.validator.run_validation_pipeline",
                       return_value=self._validation("pending_review")), \
                 patch("services.manifest.generate_manifest", return_value=_fake_manifest()), \
                 patch("services.manifest.save_manifest") as mock_save, \
                 patch("services.indexer.add_to_index") as mock_index, \
                 patch("services.audit.log") as mock_audit, \
                 patch("subprocess.run") as mock_subproc:

                result = imp.import_one({"name": "webapp"}, "almalinux9", "tester")

        assert result["status"] == "pending_review"
        assert "révision RSSI" in result["message"]
        mock_subproc.assert_not_called(), "add-rpm.sh ne doit jamais être invoqué pour un paquet en révision"
        saved_manifest = mock_save.call_args[0][0]
        assert saved_manifest["status"] == "pending_review"
        mock_index.assert_called_once()
        assert mock_audit.call_args[0][2] == "PENDING_REVIEW"

    def test_approved_still_publishes(self):
        """Non-régression : un paquet approuvé continue d'être publié normalement."""
        import services.importer_rpm as imp

        with tempfile.TemporaryDirectory() as tmp:
            rpm_path = Path(tmp) / "src" / "webapp-1.0-1.x86_64.rpm"
            rpm_path.parent.mkdir()
            rpm_path.write_bytes(b"fake-rpm")
            pool_dir = Path(tmp) / "pool"
            pool_dir.mkdir()

            with patch("services.importer_rpm.POOL_DIR", pool_dir), \
                 patch("services.importer_rpm._download_rpm",
                       return_value=(rpm_path, "test-source", "deadbeef")), \
                 patch("services.indexer.get_package_info", return_value=None), \
                 patch("services.validator.run_validation_pipeline",
                       return_value=self._validation("approved")), \
                 patch("services.manifest.generate_manifest", return_value=_fake_manifest()), \
                 patch("services.manifest.save_manifest") as mock_save, \
                 patch("services.indexer.add_to_index"), \
                 patch("services.audit.log"), \
                 patch("subprocess.run", return_value=MagicMock(returncode=0)) as mock_subproc:

                result = imp.import_one({"name": "webapp"}, "almalinux9", "tester")

        assert result["status"] == "added"
        mock_subproc.assert_called_once()
        saved_manifest = mock_save.call_args[0][0]
        assert saved_manifest["status"] == "validated"

    def test_import_package_loop_handles_pending_review_without_crash(self):
        """import_package() catégorisait pending_review dans le else 'added' générique,
        ce qui provoquait un KeyError (filename/size_bytes absents de ce statut)."""
        import services.importer_rpm as imp

        fake_result = {
            "status": "pending_review", "name": "webapp", "version": "1.0-1",
            "message": "en attente révision RSSI (non publié)", "steps": [],
        }
        deps_info = {"success": True, "packages": [{"name": "webapp", "already_in_repo": False}],
                     "unresolved": []}

        with patch("services.importer_rpm.import_one", return_value=fake_result):
            result = imp.import_package("webapp", "almalinux9", "tester", deps_info=deps_info)

        assert result["success"] is True
        assert result["pending_review"] == 1
        assert result["pending_review_details"] == [{"name": "webapp", "version": "1.0-1"}]
        assert result["imported"] == 0


class TestApkImportOnePendingReviewGate:
    def _validation(self, cve_status):
        v = MagicMock()
        v.passed = True
        v.cve_status = cve_status
        v.steps = [{"name": "cve", "passed": True, "message": "Grype — 1 High · Révision RSSI requise"}]
        v.deps = []
        v.cve_results = [{"id": "CVE-2026-0002", "severity": "High"}]
        return v

    def test_pending_review_is_not_published(self):
        import services.importer_apk as imp

        pkg_name = "webapp-pending-test"
        with tempfile.TemporaryDirectory() as tmp:
            apk_path = Path(tmp) / "src" / f"{pkg_name}-1.0-r1.apk"
            apk_path.parent.mkdir()
            apk_path.write_bytes(b"fake-apk")
            pool_dir = Path(tmp) / "pool"
            pool_dir.mkdir()

            with patch("services.importer_apk.POOL_DIR", pool_dir), \
                 patch("services.importer_apk._download_apk",
                       return_value=(apk_path, "test-source", "deadbeef")), \
                 patch("services.validator.run_validation_pipeline",
                       return_value=self._validation("pending_review")), \
                 patch("services.manifest.generate_manifest", return_value=_fake_manifest(name=pkg_name)), \
                 patch("services.manifest.save_manifest") as mock_save, \
                 patch("services.indexer.add_to_index") as mock_index, \
                 patch("services.audit.log") as mock_audit, \
                 patch("services.distributions_apk.add_package") as mock_add_pkg:

                result = imp.import_one({"name": pkg_name}, "alpine3.19", "tester")

        assert result["status"] == "pending_review"
        assert "révision RSSI" in result["message"]
        mock_add_pkg.assert_not_called(), "apk_add_package() ne doit jamais être invoqué pour un paquet en révision"
        saved_manifest = mock_save.call_args[0][0]
        assert saved_manifest["status"] == "pending_review"
        mock_index.assert_called_once()
        assert mock_audit.call_args[0][2] == "PENDING_REVIEW"

    def test_approved_still_publishes(self):
        """Non-régression : un paquet approuvé continue d'être publié normalement."""
        import services.importer_apk as imp

        pkg_name = "webapp-approved-test"
        with tempfile.TemporaryDirectory() as tmp:
            apk_path = Path(tmp) / "src" / f"{pkg_name}-1.0-r1.apk"
            apk_path.parent.mkdir()
            apk_path.write_bytes(b"fake-apk")
            pool_dir = Path(tmp) / "pool"
            pool_dir.mkdir()

            with patch("services.importer_apk.POOL_DIR", pool_dir), \
                 patch("services.importer_apk._download_apk",
                       return_value=(apk_path, "test-source", "deadbeef")), \
                 patch("services.validator.run_validation_pipeline",
                       return_value=self._validation("approved")), \
                 patch("services.manifest.generate_manifest", return_value=_fake_manifest(name=pkg_name)), \
                 patch("services.manifest.save_manifest") as mock_save, \
                 patch("services.indexer.add_to_index"), \
                 patch("services.audit.log"), \
                 patch("services.distributions_apk.add_package", return_value=(True, "ok")) as mock_add_pkg:

                result = imp.import_one({"name": pkg_name}, "alpine3.19", "tester")

        assert result["status"] == "added"
        mock_add_pkg.assert_called_once()
        saved_manifest = mock_save.call_args[0][0]
        assert saved_manifest["status"] == "validated"
