"""
Tests unitaires — Sprint 5.4 : tableau de bord enrichi

Couverture :
  • TestGetCveTrends          (8)  — fenêtres, filtrage par date, accumulation CVE
  • TestGetTopPackages        (6)  — tri par versions/taille/récents, limite
  • TestGetSlaOverdue         (7)  — âge SLA, statut non-pending ignoré, tri, settings
  • TestGetDistributionStats  (6)  — regroupement par dist, promotions, tri
  • TestGetDashboard          (5)  — agrégation, summary, generated_at
  • TestEnrichedEndpoint      (6)  — HTTP 200, paramètres query, auth
"""

# ── Isolation /repos ──────────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_dashboard_test_")
os.environ.setdefault("MANIFEST_DIR",        _TMP)
os.environ.setdefault("MANIFEST_DB",         os.path.join(_TMP, "manifests.db"))
os.environ.setdefault("POOL_DIR",            _TMP)
os.environ.setdefault("AUDIT_DIR",           _TMP)
os.environ.setdefault("AUDIT_LOG_PATH",      os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",          os.path.join(_TMP, "index.json"))
os.environ.setdefault("SETTINGS_PATH",       os.path.join(_TMP, "settings.json"))
os.environ.setdefault("AUTH_DB_PATH",        os.path.join(_TMP, "users.db"))
os.environ.setdefault("SECURITY_CACHE_DIR",  _TMP)

# ── Imports ───────────────────────────────────────────────────────────────────
import importlib.util
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

import services.dashboard as dash_mod
from services.dashboard import (
    get_cve_trends,
    get_top_packages,
    get_sla_overdue,
    get_distribution_stats,
    get_dashboard,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _days_ago_iso(days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

def _cve(critical=0, high=0, medium=0, low=0, negligible=0) -> dict:
    return {
        "critical": critical, "high": high, "medium": medium,
        "low": low, "negligible": negligible,
    }

def _make_version(
    imported_at: str | None = None,
    status: str = "validated",
    distribution: str = "jammy",
    cve: dict | None = None,
    size_bytes: int = 100_000,
    promoted: list | None = None,
) -> dict:
    return {
        "arch":         "amd64",
        "distribution": distribution,
        "filename":     "pkg.deb",
        "sha256":       "abc",
        "size_bytes":   size_bytes,
        "imported_at":  imported_at or _now_iso(),
        "imported_by":  "alice",
        "status":       status,
        "cve_summary":  cve,
        "promoted_distributions": promoted or [],
    }

def _make_index(**packages) -> dict:
    """
    packages: {name: {version_str: version_meta_dict}}
    """
    pkgs = {}
    for name, versions in packages.items():
        pkgs[name] = {
            "latest":   sorted(versions.keys())[-1],
            "versions": versions,
        }
    return {"packages": pkgs, "version": "1.0"}


# ═════════════════════════════════════════════════════════════════════════════
# 1. TestGetCveTrends
# ═════════════════════════════════════════════════════════════════════════════

class TestGetCveTrends:
    def test_returns_one_entry_per_window(self):
        idx = _make_index()
        with patch("services.indexer.get_index", return_value=idx):
            result = get_cve_trends([30, 60])
        assert len(result) == 2
        windows = [r["window_days"] for r in result]
        assert 30 in windows and 60 in windows

    def test_default_windows_30_60_90(self):
        idx = _make_index()
        with patch("services.indexer.get_index", return_value=idx):
            result = get_cve_trends()
        assert [r["window_days"] for r in result] == [30, 60, 90]

    def test_counts_recent_imports(self):
        idx = _make_index(
            nginx={"1.0": _make_version(imported_at=_days_ago_iso(5))},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_cve_trends([30])
        assert result[0]["packages_imported"] == 1

    def test_excludes_old_imports(self):
        idx = _make_index(
            nginx={"1.0": _make_version(imported_at=_days_ago_iso(40))},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_cve_trends([30])
        assert result[0]["packages_imported"] == 0

    def test_aggregates_cve_totals(self):
        idx = _make_index(
            nginx={"1.0": _make_version(
                imported_at=_days_ago_iso(5),
                cve=_cve(critical=2, high=3),
            )},
            apache={"2.4": _make_version(
                imported_at=_days_ago_iso(10),
                cve=_cve(critical=1),
            )},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_cve_trends([30])
        totals = result[0]["cve_totals"]
        assert totals["critical"] == 3
        assert totals["high"] == 3

    def test_packages_with_critical_count(self):
        idx = _make_index(
            nginx={"1.0": _make_version(imported_at=_days_ago_iso(5), cve=_cve(critical=1))},
            apache={"2.4": _make_version(imported_at=_days_ago_iso(5), cve=_cve(high=2))},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_cve_trends([30])
        assert result[0]["packages_with_critical"] == 1
        assert result[0]["packages_with_high"] == 1

    def test_no_cve_zeros(self):
        idx = _make_index(
            nginx={"1.0": _make_version(imported_at=_days_ago_iso(5), cve=None)},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_cve_trends([30])
        totals = result[0]["cve_totals"]
        assert all(v == 0 for v in totals.values())

    def test_period_start_in_result(self):
        idx = _make_index()
        with patch("services.indexer.get_index", return_value=idx):
            result = get_cve_trends([30])
        assert "period_start" in result[0]
        assert datetime.fromisoformat(result[0]["period_start"])


# ═════════════════════════════════════════════════════════════════════════════
# 2. TestGetTopPackages
# ═════════════════════════════════════════════════════════════════════════════

class TestGetTopPackages:
    def test_structure_keys(self):
        idx = _make_index()
        with patch("services.indexer.get_index", return_value=idx):
            result = get_top_packages()
        for key in ("by_versions", "by_size", "recently_added"):
            assert key in result

    def test_sorted_by_versions(self):
        idx = _make_index(
            nginx={"1.0": _make_version(), "2.0": _make_version()},
            apache={"2.4": _make_version()},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_top_packages()
        by_ver = result["by_versions"]
        assert by_ver[0]["name"] == "nginx"
        assert by_ver[0]["version_count"] == 2

    def test_sorted_by_size(self):
        idx = _make_index(
            nginx={"1.0": _make_version(size_bytes=1_000_000)},
            apache={"2.4": _make_version(size_bytes=100)},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_top_packages()
        assert result["by_size"][0]["name"] == "nginx"

    def test_limit_respected(self):
        versions = {f"{i}.0": _make_version() for i in range(20)}
        idx = _make_index(nginx=versions)
        with patch("services.indexer.get_index", return_value=idx):
            result = get_top_packages(limit=5)
        assert len(result["by_versions"]) <= 5

    def test_recently_added_newest_first(self):
        idx = _make_index(
            nginx={"1.0": _make_version(imported_at=_days_ago_iso(10))},
            apache={"2.4": _make_version(imported_at=_days_ago_iso(1))},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_top_packages()
        assert result["recently_added"][0]["name"] == "apache"

    def test_empty_index(self):
        idx = {"packages": {}, "version": "1.0"}
        with patch("services.indexer.get_index", return_value=idx):
            result = get_top_packages()
        assert result["by_versions"] == []


# ═════════════════════════════════════════════════════════════════════════════
# 3. TestGetSlaOverdue
# ═════════════════════════════════════════════════════════════════════════════

class TestGetSlaOverdue:
    def test_pending_review_over_sla_returned(self):
        idx = _make_index(
            nginx={"1.0": _make_version(
                status="pending_review",
                imported_at=_days_ago_iso(10),
            )}
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_sla_overdue(max_age_days=7)
        assert len(result) == 1
        assert result[0]["name"] == "nginx"

    def test_pending_review_within_sla_ignored(self):
        idx = _make_index(
            nginx={"1.0": _make_version(
                status="pending_review",
                imported_at=_days_ago_iso(3),
            )}
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_sla_overdue(max_age_days=7)
        assert result == []

    def test_validated_status_ignored(self):
        idx = _make_index(
            nginx={"1.0": _make_version(
                status="validated",
                imported_at=_days_ago_iso(30),
            )}
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_sla_overdue(max_age_days=7)
        assert result == []

    def test_sorted_oldest_first(self):
        idx = _make_index(
            a={"1.0": _make_version(status="pending_review", imported_at=_days_ago_iso(20))},
            b={"1.0": _make_version(status="pending_review", imported_at=_days_ago_iso(30))},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_sla_overdue(max_age_days=7)
        assert result[0]["age_days"] >= result[1]["age_days"]

    def test_max_age_zero_returns_empty(self):
        idx = _make_index(
            nginx={"1.0": _make_version(status="pending_review", imported_at=_days_ago_iso(100))}
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_sla_overdue(max_age_days=0)
        assert result == []

    def test_reads_sla_from_settings(self):
        idx = _make_index(
            nginx={"1.0": _make_version(status="pending_review", imported_at=_days_ago_iso(10))}
        )
        settings = {"sla": {"review_max_age_days": 7}}
        with (
            patch("services.indexer.get_index", return_value=idx),
            patch("services.settings.get_settings", return_value=settings),
        ):
            result = get_sla_overdue()
        # 10j > 7j → doit apparaître
        assert len(result) == 1

    def test_result_has_required_keys(self):
        idx = _make_index(
            nginx={"1.0": _make_version(status="pending_review", imported_at=_days_ago_iso(10))}
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_sla_overdue(max_age_days=7)
        for key in ("name", "version", "age_days", "imported_at", "status"):
            assert key in result[0]


# ═════════════════════════════════════════════════════════════════════════════
# 4. TestGetDistributionStats
# ═════════════════════════════════════════════════════════════════════════════

class TestGetDistributionStats:
    def test_groups_by_distribution(self):
        idx = _make_index(
            nginx={"1.0": _make_version(distribution="jammy")},
            apache={"2.4": _make_version(distribution="noble")},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_distribution_stats()
        dists = [e["distribution"] for e in result]
        assert "jammy" in dists
        assert "noble" in dists

    def test_counts_unique_packages(self):
        idx = _make_index(
            nginx={"1.0": _make_version(distribution="jammy"),
                   "2.0": _make_version(distribution="jammy")},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_distribution_stats()
        jammy = next(e for e in result if e["distribution"] == "jammy")
        assert jammy["package_count"] == 1  # nginx apparaît 2× mais 1 unique
        assert jammy["version_count"] == 2

    def test_includes_promoted_distributions(self):
        idx = _make_index(
            nginx={"1.0": _make_version(
                distribution="jammy",
                promoted=["noble"],
            )},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_distribution_stats()
        dists = {e["distribution"] for e in result}
        assert "noble" in dists

    def test_sorted_by_package_count_desc(self):
        idx = _make_index(
            a={"1.0": _make_version(distribution="jammy")},
            b={"1.0": _make_version(distribution="jammy")},
            c={"1.0": _make_version(distribution="noble")},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_distribution_stats()
        # jammy doit être en premier (2 paquets vs 1)
        assert result[0]["distribution"] == "jammy"

    def test_cve_aggregated_per_dist(self):
        idx = _make_index(
            nginx={"1.0": _make_version(
                distribution="jammy",
                cve=_cve(critical=2, high=1),
            )},
        )
        with patch("services.indexer.get_index", return_value=idx):
            result = get_distribution_stats()
        jammy = next(e for e in result if e["distribution"] == "jammy")
        assert jammy["cve_totals"]["critical"] == 2
        assert jammy["packages_with_critical"] == 1

    def test_empty_index(self):
        idx = {"packages": {}, "version": "1.0"}
        with patch("services.indexer.get_index", return_value=idx):
            result = get_distribution_stats()
        assert result == []


# ═════════════════════════════════════════════════════════════════════════════
# 5. TestGetDashboard
# ═════════════════════════════════════════════════════════════════════════════

class TestGetDashboard:
    def _idx(self):
        return _make_index(
            nginx={"1.0": _make_version(imported_at=_days_ago_iso(5))},
            apache={"2.4": _make_version(
                status="pending_review",
                imported_at=_days_ago_iso(15),
                cve=_cve(critical=1),
            )},
        )

    def test_has_required_keys(self):
        with patch("services.indexer.get_index", return_value=self._idx()):
            result = get_dashboard()
        for key in ("generated_at", "cve_trends", "top_packages",
                    "sla_overdue", "distributions", "summary"):
            assert key in result

    def test_summary_total_packages(self):
        with patch("services.indexer.get_index", return_value=self._idx()):
            result = get_dashboard()
        assert result["summary"]["total_packages"] == 2

    def test_summary_total_versions(self):
        with patch("services.indexer.get_index", return_value=self._idx()):
            result = get_dashboard()
        assert result["summary"]["total_versions"] == 2

    def test_summary_sla_overdue_count(self):
        with patch("services.indexer.get_index", return_value=self._idx()):
            result = get_dashboard(sla_max_age_days=7)
        # apache est pending_review depuis 15j > 7j SLA
        assert result["summary"]["sla_overdue_count"] >= 1

    def test_generated_at_is_iso(self):
        with patch("services.indexer.get_index", return_value=self._idx()):
            result = get_dashboard()
        datetime.fromisoformat(result["generated_at"])


# ═════════════════════════════════════════════════════════════════════════════
# 6. TestEnrichedEndpoint
# ═════════════════════════════════════════════════════════════════════════════

def _load_dashboard_router():
    spec = importlib.util.spec_from_file_location(
        "dashboard_router_isolated",
        Path(__file__).parent.parent / "routers" / "dashboard_router.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def dash_router_mod():
    return _load_dashboard_router()


@pytest.fixture(scope="module")
def enriched_client(dash_router_mod):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from auth.dependencies import get_current_user

    app = FastAPI()
    app.include_router(dash_router_mod.router)
    app.dependency_overrides[get_current_user] = lambda: "alice"

    return TestClient(app)


_MOCK_DASHBOARD = {
    "generated_at": "2026-01-01T00:00:00+00:00",
    "cve_trends":   [{"window_days": 30, "packages_imported": 0,
                      "cve_totals": {"critical": 0, "high": 0, "medium": 0,
                                     "low": 0, "negligible": 0},
                      "packages_with_critical": 0, "packages_with_high": 0,
                      "period_start": "2025-12-01T00:00:00+00:00"}],
    "top_packages": {"by_versions": [], "by_size": [], "recently_added": []},
    "sla_overdue":  [],
    "distributions": [],
    "summary": {"total_packages": 0, "total_versions": 0,
                "sla_overdue_count": 0, "critical_packages": 0},
}


class TestEnrichedEndpoint:
    def test_returns_200(self, enriched_client, dash_router_mod):
        with patch.object(dash_router_mod, "get_dashboard", return_value=_MOCK_DASHBOARD):
            resp = enriched_client.get("/dashboard/stats/enriched")
        assert resp.status_code == 200

    def test_response_has_summary(self, enriched_client, dash_router_mod):
        with patch.object(dash_router_mod, "get_dashboard", return_value=_MOCK_DASHBOARD):
            resp = enriched_client.get("/dashboard/stats/enriched")
        assert "summary" in resp.json()

    def test_trend_windows_query_param(self, enriched_client, dash_router_mod):
        from unittest.mock import MagicMock
        mock_gc = MagicMock(return_value=_MOCK_DASHBOARD)
        with patch.object(dash_router_mod, "get_dashboard", mock_gc):
            enriched_client.get("/dashboard/stats/enriched?trend_windows=7,14")
        call_kwargs = mock_gc.call_args[1]
        assert call_kwargs.get("trend_windows") == [7, 14]

    def test_top_limit_query_param(self, enriched_client, dash_router_mod):
        from unittest.mock import MagicMock
        mock_gc = MagicMock(return_value=_MOCK_DASHBOARD)
        with patch.object(dash_router_mod, "get_dashboard", mock_gc):
            enriched_client.get("/dashboard/stats/enriched?top_limit=5")
        call_kwargs = mock_gc.call_args[1]
        assert call_kwargs.get("top_limit") == 5

    def test_sla_max_age_query_param(self, enriched_client, dash_router_mod):
        from unittest.mock import MagicMock
        mock_gc = MagicMock(return_value=_MOCK_DASHBOARD)
        with patch.object(dash_router_mod, "get_dashboard", mock_gc):
            enriched_client.get("/dashboard/stats/enriched?sla_max_age_days=3")
        call_kwargs = mock_gc.call_args[1]
        assert call_kwargs.get("sla_max_age_days") == 3

    def test_auth_required_without_override(self, dash_router_mod):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(dash_router_mod.router)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/dashboard/stats/enriched")
        assert resp.status_code in (401, 403, 422)
