"""
Module : test_health_checks.py
Rôle   : P0-B — Vérifie que get_clamav_status est dans services/health_checks.py
         et que les routers importent depuis le bon module.

Expose : TestClamavStatusFunction · TestRouterImports
Dépend : pytest, unittest.mock
"""
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from services.health_checks import get_clamav_status


# ═══════════════════════════════════════════════════════════════════════════════
# get_clamav_status — comportements unitaires
# ═══════════════════════════════════════════════════════════════════════════════

class TestClamavStatusFunction:
    """
    get_clamav_status() doit retourner un dict avec les clés attendues
    sans lever d'exception, même si clamscan/pgrep sont absents.
    """

    def test_returns_dict_with_expected_keys(self):
        """La fonction retourne toujours un dict avec les 7 clés standard."""
        with patch("subprocess.run",
                   return_value=MagicMock(returncode=1, stdout="", stderr="")):
            result = get_clamav_status()
        expected_keys = {"available", "version", "db_version", "db_date",
                         "db_files", "daemon_running", "cooldown_until"}
        assert set(result.keys()) == expected_keys

    def test_unavailable_when_clamscan_not_found(self):
        """clamscan absent → available=False, version=None."""
        with patch("subprocess.run",
                   return_value=MagicMock(returncode=1, stdout="", stderr="")):
            result = get_clamav_status()
        assert result["available"] is False
        assert result["version"] is None

    def test_available_when_clamscan_returns_version(self):
        """clamscan présent → available=True, version et db_version extraits."""
        version_output = "ClamAV 1.4.3/27969/Sun Apr 12 06:24:30 2026\n"
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=version_output, stderr=""),  # clamscan
                MagicMock(returncode=0, stdout="", stderr=""),              # pgrep
            ]
            result = get_clamav_status()
        assert result["available"] is True
        assert result["version"] == "1.4.3"
        assert result["db_version"] == "27969"

    def test_no_exception_on_subprocess_error(self):
        """Exception subprocess → absorbée, retourne un dict valide."""
        with patch("subprocess.run", side_effect=Exception("no binary")):
            result = get_clamav_status()
        assert isinstance(result, dict)
        assert result["available"] is False

    def test_daemon_running_true_when_pgrep_succeeds(self):
        """freshclam daemon détecté via pgrep → daemon_running=True."""
        version_output = "ClamAV 1.4.3/27969/Sun Apr 12 06:24:30 2026\n"
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=version_output, stderr=""),  # clamscan
                MagicMock(returncode=0, stdout="1234", stderr=""),          # pgrep → trouvé
            ]
            result = get_clamav_status()
        assert result["daemon_running"] is True

    def test_daemon_running_false_when_pgrep_fails(self):
        """freshclam non trouvé par pgrep → daemon_running=False."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=1, stdout="", stderr=""),  # clamscan absent
                MagicMock(returncode=1, stdout="", stderr=""),  # pgrep → absent
            ]
            result = get_clamav_status()
        assert result["daemon_running"] is False

    def test_db_files_empty_when_dir_missing(self):
        """Répertoire DB absent → db_files=[]."""
        with patch("subprocess.run",
                   return_value=MagicMock(returncode=1, stdout="", stderr="")):
            with patch("services.health_checks.CLAMAV_DB_DIR") as mock_dir:
                mock_dir.exists.return_value = False
                result = get_clamav_status()
        assert result["db_files"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# Inspection du source — imports corrects dans les routers
# ═══════════════════════════════════════════════════════════════════════════════

class TestRouterImports:
    """
    Vérifie que les routers importent get_clamav_status depuis services.health_checks
    et non depuis un autre router (anti-pattern éliminé).
    """

    @staticmethod
    def _read(name: str) -> str:
        p = Path(__file__).parent.parent / "routers" / name
        assert p.exists(), f"{name} introuvable"
        return p.read_text()

    def test_dashboard_router_imports_from_health_checks(self):
        """
        ❌ ROUGE avant fix : dashboard_router.py importe _get_clamav_status
           depuis routers.security_router (import inter-router d'une fonction _privée)
        ✅ VERT après fix  : import depuis services.health_checks
        """
        src = self._read("dashboard_router.py")
        assert "from services.health_checks import" in src, (
            "dashboard_router.py doit importer depuis services.health_checks, "
            "pas depuis routers.security_router"
        )

    def test_dashboard_router_no_longer_imports_from_security_router(self):
        """Plus aucun import de security_router dans dashboard_router."""
        src = self._read("dashboard_router.py")
        assert "from routers.security_router" not in src, (
            "L'import inter-router (dashboard → security_router) doit être supprimé"
        )

    def test_security_router_imports_from_health_checks(self):
        """
        scan_router.py (sous-router de /security) utilise get_clamav_status
        (endpoint /clamav/status).
        ✅ Doit importer depuis services.health_checks.

        Note : depuis le découpage de security_router.py en sous-routers
        (cve_router/decision_router/scan_router), l'endpoint ClamAV vit dans
        scan_router.py.
        """
        src = self._read("scan_router.py")
        assert "from services.health_checks import" in src, (
            "scan_router.py doit importer get_clamav_status depuis services.health_checks"
        )

    def test_security_router_no_longer_defines_private_function(self):
        """
        La fonction _get_clamav_status ne doit plus être définie dans security_router.py
        ni dans ses sous-routers (elle est maintenant dans services/health_checks.py).
        """
        for name in ("security_router.py", "scan_router.py"):
            src = self._read(name)
            assert "def _get_clamav_status" not in src, (
                f"_get_clamav_status doit être retirée de {name} "
                "et déplacée dans services/health_checks.py"
            )
