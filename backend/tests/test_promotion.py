"""
Tests unitaires — services/promotion.py

Couverture :
  • TestEvaluateCvePolicy        (8)  — no scan, blocked, pending_review, warn, allow, mixed
  • TestGetPromotableTargets     (3)  — cibles valides, exclusion source
  • TestUpdateIndexPromoted      (4)  — ajout, doublon, paquet absent, version absente
  • TestPromote                  (12) — succès, déjà présent, blocked, pending_review,
                                        force review, force block, distrib invalide,
                                        paquet introuvable, reprepro error, audit trail
"""

# ── Isolation des chemins (avant tout import qui touche /repos) ───────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_promo_test_")
os.environ.setdefault("MANIFEST_DIR",   _TMP)
os.environ.setdefault("POOL_DIR",       _TMP)
os.environ.setdefault("AUDIT_DIR",      _TMP)
os.environ.setdefault("AUDIT_LOG_PATH", os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",     os.path.join(_TMP, "index.json"))
os.environ.setdefault("SETTINGS_PATH",  os.path.join(_TMP, "settings.json"))
os.environ.setdefault("AUTH_DB_PATH",   os.path.join(_TMP, "users.db"))

# ── Imports ───────────────────────────────────────────────────────────────────
from unittest.mock import MagicMock, patch

import pytest

import services.promotion as promo_mod
from services.promotion import (
    PromotionError,
    _update_index_promoted_distributions,
    evaluate_cve_policy,
    get_promotable_targets,
    promote,
)
import services.indexer as idx_mod


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _cve(critical=0, high=0, medium=0, low=0, negligible=0):
    return {
        "scanned":    True,
        "passed":     (critical + high) == 0,
        "critical":   critical,
        "high":       high,
        "medium":     medium,
        "low":        low,
        "negligible": negligible,
    }


def _policy(critical="block", high="review", medium="warn", low="allow", negligible="allow"):
    return {
        "critical":   critical,
        "high":       high,
        "medium":     medium,
        "low":        low,
        "negligible": negligible,
    }


# ═════════════════════════════════════════════════════════════════════════════
# 1. TestEvaluateCvePolicy
# ═════════════════════════════════════════════════════════════════════════════

class TestEvaluateCvePolicy:
    def test_no_cve_summary_approved(self):
        result = evaluate_cve_policy(None)
        assert result["verdict"] == "approved"

    def test_empty_cve_approved(self):
        result = evaluate_cve_policy(_cve())
        assert result["verdict"] == "approved"

    def test_critical_with_block_policy_blocked(self):
        with patch.object(promo_mod, "_get_cve_policy", return_value=_policy()):
            result = evaluate_cve_policy(_cve(critical=2))
        assert result["verdict"] == "blocked"
        assert len(result["blocking"]) > 0

    def test_high_with_review_policy_pending(self):
        with patch.object(promo_mod, "_get_cve_policy", return_value=_policy()):
            result = evaluate_cve_policy(_cve(high=3))
        assert result["verdict"] == "pending_review"
        assert len(result["reviewing"]) > 0

    def test_medium_with_warn_policy_approved_with_warnings(self):
        with patch.object(promo_mod, "_get_cve_policy", return_value=_policy()):
            result = evaluate_cve_policy(_cve(medium=5))
        assert result["verdict"] == "approved"
        assert len(result["warnings"]) > 0

    def test_low_with_allow_policy_approved(self):
        with patch.object(promo_mod, "_get_cve_policy", return_value=_policy()):
            result = evaluate_cve_policy(_cve(low=10))
        assert result["verdict"] == "approved"
        assert result["warnings"] == []

    def test_block_takes_priority_over_review(self):
        with patch.object(promo_mod, "_get_cve_policy", return_value=_policy()):
            result = evaluate_cve_policy(_cve(critical=1, high=3))
        assert result["verdict"] == "blocked"

    def test_all_allow_policy_approved(self):
        all_allow = _policy(critical="allow", high="allow", medium="allow")
        with patch.object(promo_mod, "_get_cve_policy", return_value=all_allow):
            result = evaluate_cve_policy(_cve(critical=5, high=10, medium=20))
        assert result["verdict"] == "approved"


# ═════════════════════════════════════════════════════════════════════════════
# 2. TestGetPromotableTargets
# ═════════════════════════════════════════════════════════════════════════════

class TestGetPromotableTargets:
    def test_excludes_source(self):
        targets = get_promotable_targets("jammy")
        assert "jammy" not in targets

    def test_includes_other_distros(self):
        targets = get_promotable_targets("jammy")
        assert len(targets) >= 1

    def test_returns_list(self):
        targets = get_promotable_targets("noble")
        assert isinstance(targets, list)


# ═════════════════════════════════════════════════════════════════════════════
# 3. TestUpdateIndexPromoted
# ═════════════════════════════════════════════════════════════════════════════

class TestUpdateIndexPromoted:
    def _make_index(self, name="nginx", version="1.0", existing_promoted=None):
        return {
            "packages": {
                name: {
                    "versions": {
                        version: {
                            "arch": "amd64",
                            "distribution": "jammy",
                            "promoted_distributions": list(existing_promoted or []),
                        }
                    },
                    "latest": version,
                }
            },
            "version": "1.0",
        }

    def test_adds_distribution(self):
        idx = self._make_index()
        saved = {}
        with (
            patch.object(idx_mod, "_load_index", return_value=idx),
            patch.object(idx_mod, "_save_index", lambda i: saved.update(i)),
        ):
            _update_index_promoted_distributions("nginx", "1.0", "noble")

        promoted = saved["packages"]["nginx"]["versions"]["1.0"]["promoted_distributions"]
        assert "noble" in promoted

    def test_no_duplicate(self):
        idx = self._make_index(existing_promoted=["noble"])
        saved = {}
        with (
            patch.object(idx_mod, "_load_index", return_value=idx),
            patch.object(idx_mod, "_save_index", lambda i: saved.update(i)),
        ):
            _update_index_promoted_distributions("nginx", "1.0", "noble")

        promoted = saved["packages"]["nginx"]["versions"]["1.0"]["promoted_distributions"]
        assert promoted.count("noble") == 1

    def test_absent_package_no_error(self):
        empty_idx = {"packages": {}, "version": "1.0"}
        with (
            patch.object(idx_mod, "_load_index", return_value=empty_idx),
            patch.object(idx_mod, "_save_index"),
        ):
            _update_index_promoted_distributions("nonexistent", "1.0", "noble")

    def test_absent_version_no_error(self):
        idx = self._make_index()
        with (
            patch.object(idx_mod, "_load_index", return_value=idx),
            patch.object(idx_mod, "_save_index"),
        ):
            _update_index_promoted_distributions("nginx", "9.9.9", "noble")


# ═════════════════════════════════════════════════════════════════════════════
# 4. TestPromote
# ═════════════════════════════════════════════════════════════════════════════

class TestPromote:
    def _pkg_info(self, version="1.24", cve=None):
        return {
            "latest": version,
            "versions": {
                version: {
                    "arch": "amd64",
                    "distribution": "jammy",
                    "cve_summary": cve,
                }
            },
        }

    # Lazy imports in promote() → patch the source modules, not services.promotion
    def _base_patches(self, pkg_info, reprepro_result=(True, "ok promu")):
        return [
            patch("services.indexer.get_package_info", return_value=pkg_info),
            patch("services.distributions.promote_package", return_value=reprepro_result),
            patch("services.audit.log"),
            patch.object(idx_mod, "_load_index", return_value={"packages": {}, "version": "1.0"}),
            patch.object(idx_mod, "_save_index"),
            patch.object(promo_mod, "_get_cve_policy", return_value=_policy()),
        ]

    def test_approved_returns_status(self):
        info = self._pkg_info(cve=None)
        with (
            patch("services.indexer.get_package_info", return_value=info),
            patch("services.distributions.promote_package", return_value=(True, "ok")),
            patch("services.audit.log"),
            patch.object(idx_mod, "_load_index", return_value={"packages": {}, "version": "1.0"}),
            patch.object(idx_mod, "_save_index"),
            patch.object(promo_mod, "_get_cve_policy", return_value=_policy()),
        ):
            result = promote("nginx", "jammy", "noble", "alice")
        assert result["status"] == "approved"

    def test_already_present_status(self):
        info = self._pkg_info(cve=None)
        with (
            patch("services.indexer.get_package_info", return_value=info),
            patch("services.distributions.promote_package", return_value=(True, "already present")),
            patch("services.audit.log"),
            patch.object(idx_mod, "_load_index", return_value={"packages": {}, "version": "1.0"}),
            patch.object(idx_mod, "_save_index"),
            patch.object(promo_mod, "_get_cve_policy", return_value=_policy()),
        ):
            result = promote("nginx", "jammy", "noble", "alice")
        assert result["status"] == "already_present"

    def test_blocked_by_critical_cve(self):
        info = self._pkg_info(cve=_cve(critical=2))
        with (
            patch("services.indexer.get_package_info", return_value=info),
            patch("services.audit.log"),
            patch.object(promo_mod, "_get_cve_policy", return_value=_policy()),
        ):
            result = promote("nginx", "jammy", "noble", "alice")
        assert result["status"] == "blocked"

    def test_pending_review_with_high_cve(self):
        info = self._pkg_info(cve=_cve(high=3))
        with (
            patch("services.indexer.get_package_info", return_value=info),
            patch("services.audit.log"),
            patch.object(promo_mod, "_get_cve_policy", return_value=_policy()),
        ):
            result = promote("nginx", "jammy", "noble", "alice")
        assert result["status"] == "pending_review"

    def test_force_bypasses_pending_review(self):
        info = self._pkg_info(cve=_cve(high=3))
        with (
            patch("services.indexer.get_package_info", return_value=info),
            patch("services.distributions.promote_package", return_value=(True, "ok")),
            patch("services.audit.log"),
            patch.object(idx_mod, "_load_index", return_value={"packages": {}, "version": "1.0"}),
            patch.object(idx_mod, "_save_index"),
            patch.object(promo_mod, "_get_cve_policy", return_value=_policy()),
        ):
            result = promote("nginx", "jammy", "noble", "admin",
                             force=True, justification="maintenance urgente")
        assert result["status"] in ("approved", "already_present")

    def test_force_does_not_bypass_blocked(self):
        """force=True contourne 'review' mais pas 'block'."""
        info = self._pkg_info(cve=_cve(critical=1))
        with (
            patch("services.indexer.get_package_info", return_value=info),
            patch("services.distributions.promote_package", return_value=(True, "ok")),
            patch("services.audit.log"),
            patch.object(promo_mod, "_get_cve_policy", return_value=_policy()),
        ):
            result = promote("nginx", "jammy", "noble", "admin", force=True)
        assert result["status"] == "blocked"

    def test_invalid_from_dist_raises(self):
        with pytest.raises(PromotionError, match="source"):
            promote("nginx", "invalid_dist", "noble", "alice")

    def test_invalid_to_dist_raises(self):
        with pytest.raises(PromotionError, match="cible"):
            promote("nginx", "jammy", "invalid_dist", "alice")

    def test_same_dist_raises(self):
        with pytest.raises(PromotionError, match="différentes"):
            promote("nginx", "jammy", "jammy", "alice")

    def test_package_not_found_raises(self):
        with patch("services.indexer.get_package_info", return_value=None):
            with pytest.raises(PromotionError, match="introuvable"):
                promote("nonexistent", "jammy", "noble", "alice")

    def test_reprepro_failure_raises(self):
        info = self._pkg_info(cve=None)
        with (
            patch("services.indexer.get_package_info", return_value=info),
            patch("services.distributions.promote_package", return_value=(False, "reprepro error")),
            patch("services.audit.log"),
            patch.object(promo_mod, "_get_cve_policy", return_value=_policy()),
        ):
            with pytest.raises(PromotionError, match="reprepro"):
                promote("nginx", "jammy", "noble", "alice")

    def test_audit_log_called_on_success(self):
        info = self._pkg_info(cve=None)
        mock_audit = MagicMock()
        with (
            patch("services.indexer.get_package_info", return_value=info),
            patch("services.distributions.promote_package", return_value=(True, "ok")),
            patch("services.audit.log", mock_audit),
            patch.object(idx_mod, "_load_index", return_value={"packages": {}, "version": "1.0"}),
            patch.object(idx_mod, "_save_index"),
            patch.object(promo_mod, "_get_cve_policy", return_value=_policy()),
        ):
            promote("nginx", "jammy", "noble", "alice")
        mock_audit.assert_called_once()
        args = mock_audit.call_args[0]
        assert args[0] == "PROMOTE"
        assert args[1] == "alice"
