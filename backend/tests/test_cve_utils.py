"""
Module : test_cve_utils.py
Rôle   : Tests unitaires de services/cve_utils.py
         P0-A — Élimination de la duplication de la logique CVE dans upload.py

Expose : TestComputeCveSummary · TestUploadUsesUtils
Dépend : pytest
"""
from pathlib import Path

import pytest

from services.cve_utils import compute_cve_summary


# ═══════════════════════════════════════════════════════════════════════════════
# compute_cve_summary
# ═══════════════════════════════════════════════════════════════════════════════

class TestComputeCveSummary:
    """
    compute_cve_summary(cve_results) → (cve_counts, kev_count, worst_severity)

    Remplace le bloc dupliqué dans upload.py (route JSON L153-162 et SSE L311-317).
    """

    def test_empty_list_returns_empty_counts_and_none(self):
        """Liste vide → counts vide, kev=0, worst=None."""
        counts, kev, worst = compute_cve_summary([])
        assert counts == {}
        assert kev == 0
        assert worst is None

    def test_single_critical_cve(self):
        """1 CVE Critical → counts={'Critical': 1}, worst='Critical'."""
        cves = [{"severity": "Critical", "in_kev": False}]
        counts, kev, worst = compute_cve_summary(cves)
        assert counts == {"Critical": 1}
        assert kev == 0
        assert worst == "Critical"

    def test_mixed_severities_counts_all(self):
        """Plusieurs CVE de sévérités différentes → tous comptés."""
        cves = [
            {"severity": "Critical", "in_kev": False},
            {"severity": "High",     "in_kev": False},
            {"severity": "High",     "in_kev": False},
            {"severity": "Medium",   "in_kev": False},
        ]
        counts, kev, worst = compute_cve_summary(cves)
        assert counts["Critical"] == 1
        assert counts["High"] == 2
        assert counts["Medium"] == 1
        assert kev == 0

    def test_worst_severity_follows_standard_order(self):
        """worst = sévérité la plus haute selon Critical > High > Medium > Low > Negligible."""
        cves = [
            {"severity": "Low",    "in_kev": False},
            {"severity": "Medium", "in_kev": False},
            {"severity": "High",   "in_kev": False},
        ]
        _, _, worst = compute_cve_summary(cves)
        assert worst == "High"

    def test_only_negligible_worst_is_negligible(self):
        """Si seul Negligible → worst='Negligible'."""
        cves = [{"severity": "Negligible", "in_kev": False}]
        _, _, worst = compute_cve_summary(cves)
        assert worst == "Negligible"

    def test_kev_count_only_counts_in_kev_true(self):
        """kev_count = nb de CVE avec in_kev=True."""
        cves = [
            {"severity": "Critical", "in_kev": True},
            {"severity": "High",     "in_kev": False},
            {"severity": "High",     "in_kev": True},
        ]
        _, kev, _ = compute_cve_summary(cves)
        assert kev == 2

    def test_missing_in_kev_field_treated_as_false(self):
        """CVE sans champ in_kev → ne compte pas dans kev_count."""
        cves = [{"severity": "Critical"}]  # pas de in_kev
        _, kev, _ = compute_cve_summary(cves)
        assert kev == 0

    def test_unknown_severity_counted_but_not_worst(self):
        """Sévérité inconnue → comptée dans counts, ne devient pas worst si d'autres existent."""
        cves = [
            {"severity": "Unknown", "in_kev": False},
            {"severity": "Low",     "in_kev": False},
        ]
        counts, _, worst = compute_cve_summary(cves)
        assert counts.get("Unknown") == 1
        assert worst == "Low"  # Low est dans la liste standard, Unknown non

    def test_returns_tuple_of_three(self):
        """Retourne bien un tuple (dict, int, str|None)."""
        result = compute_cve_summary([])
        assert isinstance(result, tuple)
        assert len(result) == 3
        counts, kev, worst = result
        assert isinstance(counts, dict)
        assert isinstance(kev, int)


# ═══════════════════════════════════════════════════════════════════════════════
# Non-régression : upload.py utilise cve_utils (pas de duplication)
# ═══════════════════════════════════════════════════════════════════════════════

class TestUploadUsesCveUtils:
    """
    Vérifie que upload.py importe compute_cve_summary depuis cve_utils
    et ne redéfinit plus la logique en ligne.
    """

    @staticmethod
    def _src() -> str:
        p = Path(__file__).parent.parent / "routers" / "upload.py"
        assert p.exists()
        return p.read_text()

    def test_upload_imports_compute_cve_summary(self):
        """
        ❌ ROUGE avant fix : logique CVE dupliquée en ligne dans upload.py
        ✅ VERT après fix  : import depuis services.cve_utils
        """
        assert "compute_cve_summary" in self._src(), (
            "upload.py doit importer compute_cve_summary depuis services.cve_utils"
        )

    def test_upload_does_not_redeclare_sev_order(self):
        """
        La liste _sev_order / _sev ne doit plus être déclarée dans upload.py
        (elle est maintenant encapsulée dans cve_utils.py).
        """
        src = self._src()
        assert "_sev_order" not in src and "_sev " not in src, (
            "upload.py ne doit plus déclarer _sev_order — utiliser compute_cve_summary"
        )
