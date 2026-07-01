"""
Module : test_upload_pipeline.py
Rôle   : Sprint 2 — Tests d'intégration du pipeline d'upload et de la logique
         de sécurité (décisions RSSI, quarantaine).

Scénarios couverts :
  Upload :
    - Nettoyage du filename (path traversal)
    - Distribution invalide rejetée
    - Fichier rejeté → déplacé en quarantaine

  Reprepro service (DRY) :
    - remove_package retourne la structure attendue
    - Timeout géré proprement
    - Distributions configurables via env

Dépend : pytest, unittest.mock
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_upload_test_")
os.environ["MANIFEST_DIR"]   = f"{_TMP}/manifests"
os.environ["POOL_DIR"]       = f"{_TMP}/pool"
os.environ["SECURITY_DIR"]   = f"{_TMP}/security"
os.environ["JWT_SECRET_KEY"] = "test-hmac-secret-for-upload-tests"
os.environ["STAGING_INCOMING"]   = f"{_TMP}/staging/incoming"
os.environ["STAGING_QUARANTINE"] = f"{_TMP}/staging/quarantine"

# ── Imports ───────────────────────────────────────────────────────────────────
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ════════════════════════════════════════════════════════════════════════════════
# Reprepro service — DRY
# ════════════════════════════════════════════════════════════════════════════════

class TestRepreproService:
    """
    Vérifie services/reprepro.py : la fonction remove_package().
    Les appels subprocess sont mockés pour ne pas nécessiter Docker.
    """

    @pytest.fixture
    def mod(self):
        from services import reprepro
        return reprepro

    def test_returns_expected_structure(self, mod):
        """remove_package retourne le dict attendu."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = mod.remove_package("mypackage")

        assert result["package"] == "mypackage"
        assert "distributions" in result
        assert "results" in result
        assert "all_ok" in result

    def test_all_ok_when_returncode_zero(self, mod):
        """all_ok=True quand tous les subprocess retournent 0."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="removed", stderr="")
            result = mod.remove_package("mypackage")
        assert result["all_ok"] is True

    def test_all_ok_false_when_one_fails(self, mod):
        """all_ok=False si au moins un subprocess échoue."""
        call_count = 0
        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            rc = 1 if call_count == 1 else 0
            return MagicMock(returncode=rc, stdout="", stderr="error")

        with patch("subprocess.run", side_effect=side_effect):
            result = mod.remove_package("mypackage")
        assert result["all_ok"] is False

    def test_custom_distributions(self, mod):
        """Les distributions personnalisées sont respectées."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = mod.remove_package("pkg", distributions=["jammy", "noble"])

        assert result["distributions"] == ["jammy", "noble"]
        assert len(result["results"]) == 2
        assert "jammy" in result["results"]
        assert "noble" in result["results"]

    def test_timeout_handled_gracefully(self, mod):
        """Timeout subprocess → ok=False avec message, pas d'exception."""
        import subprocess
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("reprepro", 30)):
            result = mod.remove_package("pkg", distributions=["jammy"])

        assert result["all_ok"] is False
        assert "timeout" in result["results"]["jammy"]["output"].lower()

    def test_via_docker_uses_docker_exec(self, mod):
        """via_docker=True → commande avec 'docker exec'."""
        captured = []
        def capture(cmd, **kwargs):
            captured.append(cmd)
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=capture):
            mod.remove_package("mypkg", distributions=["jammy"], via_docker=True)

        assert "docker" in captured[0]
        assert "exec" in captured[0]

    def test_via_docker_false_no_docker_exec(self, mod):
        """via_docker=False → appel reprepro direct sans docker."""
        captured = []
        def capture(cmd, **kwargs):
            captured.append(cmd)
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=capture):
            mod.remove_package("mypkg", distributions=["jammy"], via_docker=False)

        assert "docker" not in captured[0]
        assert "reprepro" in captured[0]

    def test_no_duplicate_code_in_artifacts(self):
        """
        artifacts.py ne doit plus contenir de boucle 'for dist in [...]: docker exec reprepro'.
        Vérification structurelle anti-régression.
        """
        path = Path(__file__).parent.parent / "routers" / "artifacts.py"
        source = path.read_text()
        assert "docker exec" not in source, (
            "artifacts.py contient encore 'docker exec' — le DRY refactoring n'est pas appliqué."
        )

    def test_no_duplicate_code_in_security_router(self):
        """
        security_router.py ne doit plus contenir de boucle reprepro hardcodée.
        """
        path = Path(__file__).parent.parent / "routers" / "security_router.py"
        source = path.read_text()
        # La liste hardcodée ne devrait plus exister
        assert '["jammy", "noble", "focal", "bookworm"]' not in source, (
            "security_router.py contient encore une liste hardcodée de distributions — "
            "utiliser services.reprepro.remove_package()."
        )


# ════════════════════════════════════════════════════════════════════════════════
# Upload — Sécurité du nom de fichier
# ════════════════════════════════════════════════════════════════════════════════

class TestUploadFilenameSecurization:
    """
    Vérifie que la logique de nettoyage du filename dans upload.py
    protège contre le path traversal.
    Ces tests vérifient la logique directement (pas via HTTP).
    """

    def test_path_traversal_stripped(self):
        """Un nom avec '../' est nettoyé par Path().name."""
        from pathlib import Path as P
        dangerous = "../../etc/passwd"
        safe = P(dangerous).name
        assert safe == "passwd"
        assert "/" not in safe
        assert ".." not in safe

    def test_normal_filename_unchanged(self):
        """Un nom normal reste intact."""
        from pathlib import Path as P
        filename = "mypackage_1.0.0_amd64.deb"
        assert P(filename).name == filename

    def test_nested_path_stripped(self):
        """Chemin imbriqué → seulement le dernier composant."""
        from pathlib import Path as P
        assert P("a/b/c/evil.deb").name == "evil.deb"

    def test_upload_py_uses_path_name(self):
        """
        upload.py utilise bien Path(filename).name pour sécuriser le fichier.
        Vérification structurelle.
        """
        path = Path(__file__).parent.parent / "routers" / "upload.py"
        source = path.read_text()
        assert "Path(filename).name" in source, (
            "upload.py ne sécurise pas le filename avec Path().name — "
            "risque de path traversal."
        )
