"""
Module : test_grype_nonblocking.py
Rôle   : P1-C — Vérifie que l'analyse Grype (≤ 300 s) ne bloque pas l'event loop
         FastAPI et que les cas limites du scanner CVE sont gérés sans exception.

Deux familles de tests :
  TestUploadNonBlocking — inspection du code source d'upload.py
  TestValidateCveGrype  — tests unitaires de services/validator.py

Dépend : pytest, unittest.mock
"""

# ── Chemins temp avant tout import de services (manifest.py crée /repos/…) ──
import os
import tempfile as _tmp_mod

_TEST_TMP = _tmp_mod.mkdtemp(prefix="repod_test_")
os.environ.setdefault("MANIFEST_DIR",        _TEST_TMP)
os.environ.setdefault("POOL_DIR",            _TEST_TMP)
os.environ.setdefault("STAGING_INCOMING",    _TEST_TMP)
os.environ.setdefault("STAGING_QUARANTINE",  _TEST_TMP)

# ── Imports normaux ────────────────────────────────────────────────────────────
import json
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest

from services.validator import validate_cve_grype, ValidationResult


# ── Helpers ───────────────────────────────────────────────────────────────────

def _result() -> ValidationResult:
    return ValidationResult()


def _grype_json(matches: list) -> str:
    return json.dumps({"matches": matches})


def _make_match(severity: str, cve_id: str = "CVE-2024-9999") -> dict:
    return {
        "vulnerability": {
            "id":          cve_id,
            "severity":    severity,
            "description": "Test vulnerability",
            "fix":         {"state": "fixed", "versions": ["1.2.3"]},
            "urls":        [],
            "cvss":        [],
        },
        "artifact": {"name": "libtest", "version": "1.0", "type": "deb"},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Inspection du source — architecture non-bloquante dans upload.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestUploadNonBlocking:
    """
    Vérifie que upload.py délègue les appels bloquants (Grype, reprepro) au
    thread pool via asyncio.to_thread afin de ne pas bloquer l'event loop.
    """

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "routers" / "upload.py"
        assert p.exists(), "routers/upload.py introuvable"
        return p.read_text()

    def test_asyncio_to_thread_present_in_upload(self):
        """
        ❌ ROUGE avant fix : run_validation_pipeline appelé directement dans async def
           → bloque l'event loop jusqu'à 300 s (timeout Grype)
        ✅ VERT après fix  : asyncio.to_thread encapsule l'appel bloquant
        """
        assert "asyncio.to_thread" in self._src(), (
            "upload.py doit utiliser asyncio.to_thread pour décharger "
            "run_validation_pipeline (Grype bloque jusqu'à 300 s)"
        )

    def test_sse_generator_is_async(self):
        """
        ❌ ROUGE avant fix : _upload_stream_generator est sync → ne peut pas await
        ✅ VERT après fix  : async def → peut utiliser await asyncio.to_thread
        """
        assert "async def _upload_stream_generator" in self._src(), (
            "_upload_stream_generator doit être async pour pouvoir "
            "utiliser await asyncio.to_thread à l'intérieur"
        )

    def test_reprepro_call_also_offloaded(self):
        """
        reprepro (add-deb.sh) peut prendre plusieurs secondes — doit aussi
        passer par asyncio.to_thread, pas seulement Grype.
        Le source doit contenir au moins 2 occurrences de asyncio.to_thread.
        """
        count = self._src().count("asyncio.to_thread")
        assert count >= 2, (
            f"upload.py contient {count} occurrence(s) de asyncio.to_thread ; "
            "au moins 2 attendues : run_validation_pipeline + subprocess reprepro"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Inspection du source — timeout 300 s dans validator.py
# ═══════════════════════════════════════════════════════════════════════════════

class TestGrypeTimeout300:
    """Vérifie la présence du timeout dans le code source du validator."""

    def test_grype_subprocess_has_300s_timeout_in_source(self):
        """Le subprocess grype est lancé avec timeout=300 (5 min maximum).
        validator.py est un dispatcher — la constante est dans validator_apt.py."""
        # Vérifier le dispatcher ou le module APT spécifique
        base = Path(__file__).parent.parent / "services"
        apt_validator = base / "validator_apt.py"
        dispatcher = base / "validator.py"
        # Au moins l'un des deux doit contenir timeout=300
        found = (
            (apt_validator.exists() and "timeout=300" in apt_validator.read_text())
            or "timeout=300" in dispatcher.read_text()
        )
        assert found, "validator_apt.py (ou validator.py) doit lancer grype avec timeout=300"


# ═══════════════════════════════════════════════════════════════════════════════
# Unit tests — validate_cve_grype comportements limites
# ═══════════════════════════════════════════════════════════════════════════════

class TestValidateCveGrype:
    """
    Tests unitaires de validate_cve_grype.
    subprocess.run est systématiquement mocké — aucun binaire requis.
    """

    # ── Grype absent ──────────────────────────────────────────────────────────

    def test_grype_not_found_adds_graceful_step(self):
        """
        grype absent du PATH → step 'cve' ajouté avec passed=True, pipeline non bloqué.
        """
        result = _result()
        with patch("subprocess.run",
                   return_value=MagicMock(returncode=1, stdout="", stderr="")):
            validate_cve_grype("/tmp/test.deb", result)

        cve_step = next((s for s in result.steps if s["name"] == "cve"), None)
        assert cve_step is not None, "Un step 'cve' doit être ajouté même si grype est absent"
        assert cve_step["passed"] is True
        assert result.passed is True

    # ── Timeout ───────────────────────────────────────────────────────────────

    def test_grype_timeout_adds_warning_not_failure(self):
        """
        ❌ Risque : TimeoutExpired non catchée → 500 sur l'upload
        ✅ Attendu : step warning ajouté, pipeline non bloqué, passed=True
        """
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                # which grype → trouvé
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                # grype scan → timeout après 300 s
                subprocess.TimeoutExpired("grype", 300),
            ]
            validate_cve_grype("/tmp/test.deb", result)

        cve_step = next((s for s in result.steps if s["name"] == "cve"), None)
        assert cve_step is not None
        assert cve_step["passed"] is True, "Timeout Grype ne doit pas bloquer le pipeline"
        assert result.passed is True

    def test_grype_subprocess_called_with_300s_timeout(self):
        """Le subprocess grype est lancé avec timeout=300 (vérification runtime)."""
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                MagicMock(returncode=0, stdout=_grype_json([]), stderr=""),
            ]
            validate_cve_grype("/tmp/test.deb", result)

        assert mock_run.call_count == 2
        grype_call_kwargs = mock_run.call_args_list[1].kwargs
        assert grype_call_kwargs.get("timeout") == 300, (
            f"timeout attendu=300, obtenu={grype_call_kwargs.get('timeout')}"
        )

    # ── Code retour inattendu ─────────────────────────────────────────────────

    def test_grype_unexpected_returncode_adds_warning(self):
        """rc ∉ {0, 1} (erreur interne Grype) → step warning, passed=True."""
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                MagicMock(returncode=2, stdout="", stderr="grype internal error"),
            ]
            validate_cve_grype("/tmp/test.deb", result)

        cve_step = next((s for s in result.steps if s["name"] == "cve"), None)
        assert cve_step is not None
        assert cve_step["passed"] is True
        assert result.passed is True

    # ── JSON malformé ─────────────────────────────────────────────────────────

    def test_grype_malformed_json_adds_warning(self):
        """JSON de sortie invalide → step warning, pas d'exception non catchée."""
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                MagicMock(returncode=0, stdout="not json {{{", stderr=""),
            ]
            validate_cve_grype("/tmp/test.deb", result)

        cve_step = next((s for s in result.steps if s["name"] == "cve"), None)
        assert cve_step is not None
        assert cve_step["passed"] is True

    # ── Cas nominaux ──────────────────────────────────────────────────────────

    def test_grype_zero_cve_sets_approved_status(self):
        """0 CVE détectée → cve_status='approved', step passed=True."""
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                MagicMock(returncode=0, stdout=_grype_json([]), stderr=""),
            ]
            validate_cve_grype("/tmp/test.deb", result)

        assert result.cve_status == "approved"
        cve_step = next((s for s in result.steps if s["name"] == "cve"), None)
        assert cve_step["passed"] is True

    def test_grype_critical_cve_with_block_policy_sets_blocked(self):
        """CVE Critical + policy block → cve_status='blocked', step passed=False."""
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                MagicMock(
                    returncode=1,
                    stdout=_grype_json([_make_match("Critical")]),
                    stderr="",
                ),
            ]
            validate_cve_grype(
                "/tmp/test.deb", result,
                cve_policy={"critical": "block", "high": "review"},
                auto_enrich=False,
            )

        assert result.cve_status == "blocked"
        cve_step = next((s for s in result.steps if s["name"] == "cve"), None)
        assert cve_step["passed"] is False

    def test_grype_high_cve_with_review_policy_sets_pending_review(self):
        """CVE High + policy review → cve_status='pending_review', pipeline non bloqué."""
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                MagicMock(
                    returncode=1,
                    stdout=_grype_json([_make_match("High")]),
                    stderr="",
                ),
            ]
            validate_cve_grype(
                "/tmp/test.deb", result,
                cve_policy={"critical": "block", "high": "review"},
                auto_enrich=False,
            )

        assert result.cve_status == "pending_review"
        assert result.passed is True  # pending_review ≠ bloqué
        cve_step = next((s for s in result.steps if s["name"] == "cve"), None)
        assert cve_step["passed"] is True  # l'étape CVE n'échoue pas (pas de blocage)

    def test_grype_distro_flag_passed_to_subprocess(self):
        """Si distro='jammy', --distro ubuntu:22.04 est passé à grype."""
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                MagicMock(returncode=0, stdout=_grype_json([]), stderr=""),
            ]
            validate_cve_grype("/tmp/test.deb", result, distro="jammy")

        grype_cmd = mock_run.call_args_list[1].args[0]
        assert "--distro" in grype_cmd
        idx = grype_cmd.index("--distro")
        assert grype_cmd[idx + 1] == "ubuntu:22.04"

    def test_grype_match_with_cvss_data_extracts_score(self):
        """
        CVE avec données CVSS → _extract_cvss extrait le score et le stocke
        dans cve_results[0]['cvss'].
        """
        match = {
            "vulnerability": {
                "id":          "CVE-2024-1234",
                "severity":    "High",
                "description": "test vuln",
                "fix":         {"state": "fixed", "versions": ["1.1"]},
                "urls":        [],
                "cvss":        [{"metrics": {"baseScore": 8.1}}],
            },
            "artifact": {"name": "libssl", "version": "1.0", "type": "deb"},
        }
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                MagicMock(returncode=1, stdout=_grype_json([match]), stderr=""),
            ]
            validate_cve_grype("/tmp/test.deb", result, auto_enrich=False)

        assert len(result.cve_results) == 1
        assert result.cve_results[0]["cvss"] == 8.1

    def test_grype_compat_mode_fail_on_critical_blocks(self):
        """
        Mode compat (pas de cve_policy) + fail_on='critical' + CVE Critical
        → cve_status='blocked', step passed=False.
        """
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                MagicMock(
                    returncode=1,
                    stdout=_grype_json([_make_match("Critical")]),
                    stderr="",
                ),
            ]
            validate_cve_grype(
                "/tmp/test.deb", result,
                fail_on="critical",
                cve_policy=None,
                auto_enrich=False,
            )

        assert result.cve_status == "blocked"
        cve_step = next((s for s in result.steps if s["name"] == "cve"), None)
        assert cve_step["passed"] is False

    def test_grype_compat_mode_fail_on_high_no_critical_passes(self):
        """
        Mode compat + fail_on='high' + seul CVE Medium → cve_status='approved'.
        """
        result = _result()
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout="/usr/local/bin/grype", stderr=""),
                MagicMock(
                    returncode=1,
                    stdout=_grype_json([_make_match("Medium")]),
                    stderr="",
                ),
            ]
            validate_cve_grype(
                "/tmp/test.deb", result,
                fail_on="high",
                cve_policy=None,
                auto_enrich=False,
            )

        assert result.cve_status == "approved"
        assert result.passed is True
