"""
Tests unitaires — Sprint 5.2 : rétention par âge (min_version_age_days)

Couverture :
  • TestVersionAgeDays        (5)  — date présente, absente, calcul approx, futur
  • TestEnforceVersionLimit   (12) — min_age_days protège les jeunes, dry_run,
                                     version latest jamais supprimée, max=0 désactivé,
                                     max >= count → rien, age=inf éligible
  • TestRunVersionGC          (8)  — lit settings, min_age_days depuis settings,
                                     dry_run propagé, max=0 désactivé, skipped compté
  • TestGCPreviewEndpoint     (6)  — GET /admin/gc-preview → 200, dry_run=True,
                                     paramètres query, auth requise
"""

# ── Isolation /repos ──────────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_retention_test_")
os.environ.setdefault("MANIFEST_DIR",   _TMP)
os.environ.setdefault("MANIFEST_DB",    os.path.join(_TMP, "manifests.db"))
os.environ.setdefault("POOL_DIR",       _TMP)
os.environ.setdefault("AUDIT_DIR",      _TMP)
os.environ.setdefault("AUDIT_LOG_PATH", os.path.join(_TMP, "audit.log"))
os.environ.setdefault("INDEX_PATH",     os.path.join(_TMP, "index.json"))
os.environ.setdefault("SETTINGS_PATH",  os.path.join(_TMP, "settings.json"))
os.environ.setdefault("AUTH_DB_PATH",   os.path.join(_TMP, "users.db"))

# ── Imports ───────────────────────────────────────────────────────────────────
import importlib.util
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import services.snapshots as snap_mod
from services.snapshots import (
    _version_age_days,
    _parse_imported_at,
    enforce_version_limit,
    run_version_gc,
)
import services.indexer as idx_mod


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _days_ago_iso(days: float) -> str:
    dt = datetime.now(timezone.utc) - timedelta(days=days)
    return dt.isoformat()

def _make_version_info(imported_at: str | None = None) -> dict:
    return {
        "arch":         "amd64",
        "distribution": "jammy",
        "filename":     "nginx_1.0_amd64.deb",
        "sha256":       "abc123",
        "size_bytes":   100000,
        "imported_at":  imported_at or "",
        "imported_by":  "alice",
        "status":       "validated",
    }

def _make_index(name="nginx", versions: dict | None = None, latest="2.0") -> dict:
    """
    versions: {ver_str: days_ago_float | None}
    None → no imported_at (age = +inf)
    """
    vs = {}
    for ver, age in (versions or {"2.0": 0.5, "1.0": 5.0}).items():
        imported = _days_ago_iso(age) if age is not None else ""
        vs[ver] = _make_version_info(imported)
    return {
        "packages": {
            name: {
                "latest":   latest,
                "versions": vs,
            }
        },
        "version": "1.0",
    }


# ═════════════════════════════════════════════════════════════════════════════
# 1. TestVersionAgeDays
# ═════════════════════════════════════════════════════════════════════════════

class TestVersionAgeDays:
    def test_no_imported_at_returns_inf(self):
        info = _make_version_info(imported_at="")
        assert _version_age_days(info) == float("inf")

    def test_none_imported_at_returns_inf(self):
        info = _make_version_info(imported_at=None)
        assert _version_age_days(info) == float("inf")

    def test_recent_version_age_is_small(self):
        info = _make_version_info(imported_at=_days_ago_iso(1))
        age = _version_age_days(info)
        assert 0.9 < age < 1.1

    def test_old_version_age_is_large(self):
        info = _make_version_info(imported_at=_days_ago_iso(30))
        age = _version_age_days(info)
        assert 29.9 < age < 30.1

    def test_future_date_returns_small_positive_or_zero(self):
        # Une date légèrement dans le futur (horloge skew) → âge ≈ 0
        future = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        info = _make_version_info(imported_at=future)
        age = _version_age_days(info)
        assert age < 0.1  # juste avant 0 ou ≈ 0


# ═════════════════════════════════════════════════════════════════════════════
# 2. TestEnforceVersionLimit
# ═════════════════════════════════════════════════════════════════════════════

class TestEnforceVersionLimit:

    def _base_patches(self, index):
        from services.manifest import MANIFEST_DIR
        return [
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
            patch("services.indexer.get_package_info",
                  return_value=index["packages"].get("nginx")),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
        ]

    # ── max_versions=0 → désactivé ────────────────────────────────────────────

    def test_max_zero_returns_empty(self):
        result = enforce_version_limit("nginx", 0)
        assert result == []

    # ── max >= count → rien supprimé ─────────────────────────────────────────

    def test_max_gte_count_returns_empty(self):
        idx = _make_index(versions={"1.0": 10, "2.0": 1}, latest="2.0")
        pkg = idx["packages"]["nginx"]
        with patch("services.indexer.get_package_info", return_value=pkg):
            result = enforce_version_limit("nginx", 5)
        assert result == []

    # ── version latest jamais supprimée ──────────────────────────────────────

    def test_latest_never_deleted(self):
        # 3 versions, max=1 → 2 à supprimer, latest préservée
        idx = _make_index(
            versions={"1.0": 20, "1.5": 10, "2.0": 1},
            latest="2.0",
        )
        pkg = idx["packages"]["nginx"]
        with (
            patch("services.indexer.get_package_info", return_value=pkg),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = enforce_version_limit("nginx", 1)
        deleted_versions = [r["version"] for r in result]
        assert "2.0" not in deleted_versions
        assert len(result) == 2

    # ── suppression normale ───────────────────────────────────────────────────

    def test_deletes_oldest_versions(self):
        idx = _make_index(
            versions={"1.0": 30, "1.5": 15, "2.0": 1},
            latest="2.0",
        )
        pkg = idx["packages"]["nginx"]
        with (
            patch("services.indexer.get_package_info", return_value=pkg),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = enforce_version_limit("nginx", 2)
        # Seule 1.0 (la plus ancienne) doit être supprimée
        assert len(result) == 1
        assert result[0]["version"] == "1.0"

    # ── min_age_days protège les versions récentes ────────────────────────────

    def test_min_age_days_protects_young_version(self):
        # 3 versions : 2.0=latest(0.5j), 1.5=5j, 1.0=20j  → max=1 → 2 candidates
        # min_age_days=7 → 1.5 (5j) protégée, seule 1.0 éligible
        idx = _make_index(
            versions={"1.0": 20, "1.5": 5, "2.0": 0.5},
            latest="2.0",
        )
        pkg = idx["packages"]["nginx"]
        with (
            patch("services.indexer.get_package_info", return_value=pkg),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = enforce_version_limit("nginx", 1, min_age_days=7)

        skipped = [r for r in result if r["skipped_too_young"]]
        deleted  = [r for r in result if not r["skipped_too_young"]]
        assert len(skipped) == 1
        assert skipped[0]["version"] == "1.5"
        assert len(deleted) == 1
        assert deleted[0]["version"] == "1.0"

    def test_min_age_days_protects_all_young(self):
        # Toutes les versions non-latest ont moins de 3 jours → aucune suppression réelle
        idx = _make_index(
            versions={"1.0": 1, "2.0": 0.1},
            latest="2.0",
        )
        pkg = idx["packages"]["nginx"]
        with (
            patch("services.indexer.get_package_info", return_value=pkg),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = enforce_version_limit("nginx", 1, min_age_days=3)

        # 1.0 a 1 jour < min_age_days=3 → skipped
        assert len(result) == 1
        assert result[0]["skipped_too_young"] is True

    def test_min_age_zero_deletes_immediately(self):
        idx = _make_index(
            versions={"1.0": 0.1, "2.0": 0.01},
            latest="2.0",
        )
        pkg = idx["packages"]["nginx"]
        with (
            patch("services.indexer.get_package_info", return_value=pkg),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = enforce_version_limit("nginx", 1, min_age_days=0)
        # min_age_days=0 → suppression immédiate, pas de protection
        assert len(result) == 1
        assert result[0]["skipped_too_young"] is False

    # ── âge=+inf éligible même avec min_age_days ─────────────────────────────

    def test_inf_age_eligible_despite_min_age(self):
        # Version sans imported_at → age=+inf → toujours éligible
        idx = _make_index(
            versions={"1.0": None, "2.0": 0.5},
            latest="2.0",
        )
        pkg = idx["packages"]["nginx"]
        with (
            patch("services.indexer.get_package_info", return_value=pkg),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = enforce_version_limit("nginx", 1, min_age_days=365)
        # 1.0 a age=+inf donc jamais protégée par min_age_days
        assert len(result) == 1
        assert result[0]["version"] == "1.0"
        assert result[0]["skipped_too_young"] is False

    # ── dry_run ───────────────────────────────────────────────────────────────

    def test_dry_run_returns_candidates_without_deleting(self):
        idx = _make_index(
            versions={"1.0": 30, "2.0": 1},
            latest="2.0",
        )
        pkg = idx["packages"]["nginx"]
        mock_remove = MagicMock()
        mock_delete_db = MagicMock()
        with (
            patch("services.indexer.get_package_info", return_value=pkg),
            patch("services.indexer.remove_from_index", mock_remove),
            patch("services.manifest.delete_manifest_from_db", mock_delete_db),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = enforce_version_limit("nginx", 1, dry_run=True)

        # Candidat retourné mais rien supprimé
        assert len(result) == 1
        assert result[0]["deleted_deb"] is False
        assert result[0]["deleted_manifest"] is False
        assert result[0]["skipped_too_young"] is False
        mock_remove.assert_not_called()
        mock_delete_db.assert_not_called()

    def test_dry_run_with_min_age_shows_skipped(self):
        idx = _make_index(
            versions={"1.0": 1, "2.0": 0.5},
            latest="2.0",
        )
        pkg = idx["packages"]["nginx"]
        with (
            patch("services.indexer.get_package_info", return_value=pkg),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = enforce_version_limit("nginx", 1, min_age_days=5, dry_run=True)
        # dry_run + min_age → skipped_too_young=True, pas d'erreur
        assert len(result) == 1
        assert result[0]["skipped_too_young"] is True

    def test_result_contains_age_days(self):
        idx = _make_index(
            versions={"1.0": 10, "2.0": 1},
            latest="2.0",
        )
        pkg = idx["packages"]["nginx"]
        with (
            patch("services.indexer.get_package_info", return_value=pkg),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = enforce_version_limit("nginx", 1, dry_run=True)
        assert "age_days" in result[0]
        assert result[0]["age_days"] > 0


# ═════════════════════════════════════════════════════════════════════════════
# 3. TestRunVersionGC
# ═════════════════════════════════════════════════════════════════════════════

class TestRunVersionGC:

    def _patches(self, index, settings=None):
        default_settings = {
            "versioning": {
                "max_versions_per_package": 3,
                "min_version_age_days": 7,
            }
        }
        return [
            patch("services.indexer.get_index", return_value=index),
            patch("services.indexer.get_package_info",
                  side_effect=lambda name: index["packages"].get(name)),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch("services.settings.get_settings", return_value=settings or default_settings),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ]

    def test_reads_max_from_settings(self):
        idx = _make_index(versions={"1.0": 30, "1.5": 15, "2.0": 1}, latest="2.0")
        with (
            patch("services.indexer.get_index", return_value=idx),
            patch("services.indexer.get_package_info",
                  return_value=idx["packages"]["nginx"]),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch("services.settings.get_settings", return_value={
                "versioning": {"max_versions_per_package": 2, "min_version_age_days": 0}
            }),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = run_version_gc()
        assert result["max_versions"] == 2

    def test_reads_min_age_from_settings(self):
        idx = _make_index(versions={"1.0": 5, "2.0": 1}, latest="2.0")
        with (
            patch("services.indexer.get_index", return_value=idx),
            patch("services.indexer.get_package_info",
                  return_value=idx["packages"]["nginx"]),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch("services.settings.get_settings", return_value={
                "versioning": {"max_versions_per_package": 1, "min_version_age_days": 10}
            }),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = run_version_gc()
        assert result["min_age_days"] == 10
        # 1.0 a 5 jours < 10 → skipped
        assert result["versions_deleted"] == 0
        assert result["versions_skipped"] == 1

    def test_max_zero_disables_gc(self):
        idx = _make_index(versions={"1.0": 30, "2.0": 1}, latest="2.0")
        with (
            patch("services.indexer.get_index", return_value=idx),
            patch("services.settings.get_settings", return_value={
                "versioning": {"max_versions_per_package": 0}
            }),
        ):
            result = run_version_gc()
        assert result["versions_deleted"] == 0
        assert result["packages_checked"] == 0
        assert "note" in result

    def test_dry_run_propagated(self):
        idx = _make_index(versions={"1.0": 30, "2.0": 1}, latest="2.0")
        mock_enforce = MagicMock(return_value=[])
        with (
            patch("services.indexer.get_index", return_value=idx),
            patch("services.settings.get_settings", return_value={
                "versioning": {"max_versions_per_package": 1, "min_version_age_days": 0}
            }),
            patch.object(snap_mod, "enforce_version_limit", mock_enforce),
        ):
            run_version_gc(dry_run=True)
        # Vérifie que dry_run=True a bien été passé
        call_kwargs = mock_enforce.call_args_list[0][1]
        assert call_kwargs.get("dry_run") is True

    def test_dry_run_in_result(self):
        idx = _make_index(versions={"1.0": 30, "2.0": 1}, latest="2.0")
        with (
            patch("services.indexer.get_index", return_value=idx),
            patch("services.indexer.get_package_info",
                  return_value=idx["packages"]["nginx"]),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch("services.settings.get_settings", return_value={
                "versioning": {"max_versions_per_package": 1, "min_version_age_days": 0}
            }),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = run_version_gc(dry_run=True)
        assert result["dry_run"] is True
        assert result["versions_deleted"] == 0  # dry_run = pas de suppression comptée

    def test_skipped_counted_separately(self):
        idx = _make_index(
            versions={"1.0": 3, "1.5": 1, "2.0": 0.5},
            latest="2.0",
        )
        with (
            patch("services.indexer.get_index", return_value=idx),
            patch("services.indexer.get_package_info",
                  return_value=idx["packages"]["nginx"]),
            patch("services.indexer.remove_from_index"),
            patch("services.manifest.delete_manifest_from_db"),
            patch("services.settings.get_settings", return_value={
                "versioning": {"max_versions_per_package": 1, "min_version_age_days": 5}
            }),
            patch.object(snap_mod, "POOL_DIR", Path(_TMP)),
        ):
            result = run_version_gc()
        # 1.0=3j et 1.5=1j, tous deux < min_age_days=5
        assert result["versions_skipped"] == 2
        assert result["versions_deleted"] == 0

    def test_override_params_take_precedence(self):
        idx = _make_index(versions={"1.0": 30, "2.0": 1}, latest="2.0")
        mock_enforce = MagicMock(return_value=[])
        with (
            patch("services.indexer.get_index", return_value=idx),
            patch("services.settings.get_settings", return_value={
                "versioning": {"max_versions_per_package": 10, "min_version_age_days": 0}
            }),
            patch.object(snap_mod, "enforce_version_limit", mock_enforce),
        ):
            run_version_gc(max_versions=2, min_age_days=14)
        call_args = mock_enforce.call_args_list[0]
        assert call_args[0][1] == 2          # max_versions positional
        assert call_args[1]["min_age_days"] == 14

    def test_result_has_required_keys(self):
        idx = {"packages": {}, "version": "1.0"}
        with (
            patch("services.indexer.get_index", return_value=idx),
            patch("services.settings.get_settings", return_value={
                "versioning": {"max_versions_per_package": 5, "min_version_age_days": 0}
            }),
        ):
            result = run_version_gc()
        for key in ("ran_at", "max_versions", "min_age_days", "dry_run",
                    "packages_checked", "versions_deleted", "versions_skipped", "details"):
            assert key in result, f"Clé manquante : {key}"


# ═════════════════════════════════════════════════════════════════════════════
# 4. TestGCPreviewEndpoint
# ═════════════════════════════════════════════════════════════════════════════

def _load_artifacts_router():
    spec = importlib.util.spec_from_file_location(
        "artifacts_isolated",
        Path(__file__).parent.parent / "routers" / "artifacts.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def artifacts_mod():
    return _load_artifacts_router()


@pytest.fixture(scope="module")
def gc_client(artifacts_mod):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(artifacts_mod.router)

    # Bypass auth
    from auth.dependencies import get_admin_user
    app.dependency_overrides[get_admin_user] = lambda: "admin"

    return TestClient(app)


_EMPTY_GC_RESULT = {
    "ran_at":           "2026-01-01T00:00:00+00:00",
    "max_versions":     5,
    "min_age_days":     0,
    "dry_run":          True,
    "packages_checked": 0,
    "versions_deleted": 0,
    "versions_skipped": 0,
    "details":          [],
}


class TestGCPreviewEndpoint:
    """
    L'endpoint est monté sous le préfixe /artifacts du router.
    Le mock doit cibler le symbole importé dans le module artifacts isolé.
    """

    def test_returns_200(self, gc_client, artifacts_mod):
        with patch.object(artifacts_mod, "run_version_gc", return_value=_EMPTY_GC_RESULT):
            resp = gc_client.get("/artifacts/admin/gc-preview")
        assert resp.status_code == 200

    def test_dry_run_true_in_call(self, gc_client, artifacts_mod):
        mock_gc = MagicMock(return_value=_EMPTY_GC_RESULT)
        with patch.object(artifacts_mod, "run_version_gc", mock_gc):
            gc_client.get("/artifacts/admin/gc-preview")
        call_kwargs = mock_gc.call_args[1]
        assert call_kwargs.get("dry_run") is True

    def test_max_versions_query_param(self, gc_client, artifacts_mod):
        mock_gc = MagicMock(return_value=_EMPTY_GC_RESULT)
        with patch.object(artifacts_mod, "run_version_gc", mock_gc):
            gc_client.get("/artifacts/admin/gc-preview?max_versions=3")
        call_kwargs = mock_gc.call_args[1]
        assert call_kwargs.get("max_versions") == 3

    def test_min_age_days_query_param(self, gc_client, artifacts_mod):
        mock_gc = MagicMock(return_value=_EMPTY_GC_RESULT)
        with patch.object(artifacts_mod, "run_version_gc", mock_gc):
            gc_client.get("/artifacts/admin/gc-preview?min_age_days=7")
        call_kwargs = mock_gc.call_args[1]
        assert call_kwargs.get("min_age_days") == 7

    def test_response_contains_dry_run_key(self, gc_client, artifacts_mod):
        with patch.object(artifacts_mod, "run_version_gc", return_value=_EMPTY_GC_RESULT):
            resp = gc_client.get("/artifacts/admin/gc-preview")
        body = resp.json()
        assert "dry_run" in body

    def test_auth_required_without_override(self, artifacts_mod):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(artifacts_mod.router)
        # Pas d'override → auth requise
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/artifacts/admin/gc-preview")
        assert resp.status_code in (401, 403, 422)
