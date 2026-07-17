"""
Module : test_snapshots.py
Rôle   : Sprint 3.5 — Tests des snapshots historiques de paquets.

Scénarios couverts :
  get_version_history() :
    - Retourne toutes les versions triées par date descendante
    - La version la plus récente est is_latest=True
    - pool_available reflète l'existence du .deb
    - Retourne [] pour un paquet inconnu

  get_snapshot() :
    - Retourne le manifest d'une version spécifique
    - Retourne None pour une version inconnue
    - Gère arch explicite

  compare_versions() :
    - size_change_bytes = v2.size - v1.size
    - new_deps / removed_deps détecte les changements
    - sha256_changed détecte le changement d'intégrité
    - description_changed détecte le changement de description
    - error si version inconnue

  enforce_version_limit() :
    - Supprime les versions excédentaires (plus anciennes)
    - Ne supprime jamais la version latest
    - max_versions=0 → désactivé
    - max_versions >= count → rien supprimé
    - Retourne la liste des versions supprimées

  run_version_gc() :
    - Applique enforce_version_limit sur tous les paquets
    - Respecte max_versions_per_package du settings
    - max_versions=0 → aucune suppression

  Intégration :
    - Deux uploads successifs → deux versions conservées
    - enforce_version_limit(max=1) → garde uniquement la dernière

Dépend : pytest, unittest.mock
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import os
import tempfile as _tmp_mod

_TMP = _tmp_mod.mkdtemp(prefix="repod_snapshots_test_")
os.environ["MANIFEST_DIR"]   = f"{_TMP}/manifests"
os.environ["POOL_DIR"]       = f"{_TMP}/pool"
os.environ["INDEX_PATH"]     = f"{_TMP}/manifests/index.json"
os.environ["SETTINGS_PATH"]  = f"{_TMP}/settings.json"
os.environ["JWT_SECRET_KEY"] = "test-secret-for-snapshots-tests"
os.environ.setdefault("AUTH_DB_PATH", f"{_TMP}/users.db")

# ── Imports ───────────────────────────────────────────────────────────────────
import importlib
import json
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

# Importer et reconfigurer les modules
import services.snapshots as snapshots_mod
import services.indexer as indexer_mod
import services.manifest as manifest_mod

_MANIFEST_DIR = Path(f"{_TMP}/manifests")
_POOL_DIR     = Path(f"{_TMP}/pool")
_MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
_POOL_DIR.mkdir(parents=True, exist_ok=True)

# Patch des chemins module-level
manifest_mod.MANIFEST_DIR = _MANIFEST_DIR
indexer_mod.INDEX_PATH    = Path(f"{_TMP}/manifests/index.json")
snapshots_mod.POOL_DIR    = _POOL_DIR


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_manifest(
    name: str,
    version: str,
    arch: str = "amd64",
    description: str = "Test package",
    deps: list | None = None,
    imported_at: str | None = None,
    file_size_bytes: int = 1024,
) -> dict:
    return {
        "name": name, "version": version, "arch": arch,
        "distribution": "jammy", "section": "main",
        "description": description, "maintainer": "test@test.local",
        "installed_size_kb": 100, "file_size_bytes": file_size_bytes,
        "filename": f"{name}_{version}_{arch}.deb", "type": "deb",
        "source": {
            "imported_by": "ci",
            "imported_at": imported_at or datetime.now(timezone.utc).isoformat(),
            "import_method": "upload",
            "import_group": None,
        },
        "integrity": {
            "sha256": f"sha256-{name}-{version}",
            "sha512": f"sha512-{name}-{version}",
            "gpg_signed": False,
        },
        "dependencies": deps or [{"name": "libc6"}],
        "status": "validated", "tags": [],
        "validation_steps": [], "cve_results": [],
    }


def _create_deb(name: str, version: str, arch: str = "amd64") -> Path:
    """Crée un faux fichier .deb dans le pool."""
    path = _POOL_DIR / f"{name}_{version}_{arch}.deb"
    path.write_bytes(b"fake-deb-content")
    return path


@pytest.fixture(autouse=True)
def clean_state(db_test_engine):
    """Recrée un état propre avant chaque test."""
    from sqlalchemy import text as _t

    def _wipe():
        for f in _MANIFEST_DIR.glob("*.json"):
            f.unlink(missing_ok=True)
        for f in _POOL_DIR.glob("*.deb"):
            f.unlink(missing_ok=True)
        with db_test_engine.begin() as conn:
            conn.execute(_t("DELETE FROM manifests"))
        manifest_mod.MANIFEST_DIR = _MANIFEST_DIR
        indexer_mod.INDEX_PATH    = Path(f"{_TMP}/manifests/index.json")
        snapshots_mod.POOL_DIR    = _POOL_DIR
        manifest_mod.invalidate_manifest_cache()

    _wipe()
    yield
    _wipe()


def _save_and_index(manifest: dict, with_deb: bool = True) -> None:
    """Helper : sauvegarde manifest + index + crée optionnellement le .deb."""
    manifest_mod.save_manifest(manifest)
    indexer_mod.add_to_index(manifest)
    if with_deb:
        _create_deb(manifest["name"], manifest["version"], manifest["arch"])


# ════════════════════════════════════════════════════════════════════════════════
# get_version_history
# ════════════════════════════════════════════════════════════════════════════════

class TestGetVersionHistory:

    def test_returns_all_versions(self):
        """get_version_history retourne toutes les versions enregistrées."""
        _save_and_index(_make_manifest("curl", "7.0.0"))
        _save_and_index(_make_manifest("curl", "8.0.0"))
        history = snapshots_mod.get_version_history("curl")
        versions = [h["version"] for h in history]
        assert "7.0.0" in versions
        assert "8.0.0" in versions
        assert len(history) == 2

    def test_sorted_newest_first(self):
        """Le tri est par date d'import descendante (plus récente en premier)."""
        old_ts = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        new_ts = datetime.now(timezone.utc).isoformat()
        _save_and_index(_make_manifest("nginx", "1.0.0", imported_at=old_ts))
        _save_and_index(_make_manifest("nginx", "2.0.0", imported_at=new_ts))
        history = snapshots_mod.get_version_history("nginx")
        assert history[0]["version"] == "2.0.0"
        assert history[1]["version"] == "1.0.0"

    def test_latest_version_flagged(self):
        """La version latest est marquée is_latest=True, les autres False."""
        _save_and_index(_make_manifest("vim", "1.0.0"))
        _save_and_index(_make_manifest("vim", "2.0.0"))
        history = snapshots_mod.get_version_history("vim")
        latest_entries = [h for h in history if h["is_latest"]]
        non_latest = [h for h in history if not h["is_latest"]]
        assert len(latest_entries) == 1
        assert latest_entries[0]["version"] == "2.0.0"
        assert len(non_latest) == 1

    def test_pool_available_true_when_deb_exists(self):
        """pool_available=True quand le .deb est dans le pool."""
        _save_and_index(_make_manifest("curl", "7.0.0"), with_deb=True)
        history = snapshots_mod.get_version_history("curl")
        assert history[0]["pool_available"] is True

    def test_pool_available_false_when_deb_absent(self):
        """pool_available=False quand le .deb est absent du pool."""
        _save_and_index(_make_manifest("curl", "7.0.0"), with_deb=False)
        history = snapshots_mod.get_version_history("curl")
        assert history[0]["pool_available"] is False

    def test_unknown_package_returns_empty(self):
        """Paquet inconnu → liste vide (pas d'exception)."""
        history = snapshots_mod.get_version_history("ghost-package-xyz")
        assert history == []

    def test_single_version(self):
        """Paquet avec une seule version → liste d'un élément, is_latest=True."""
        _save_and_index(_make_manifest("openssl", "3.0.0"))
        history = snapshots_mod.get_version_history("openssl")
        assert len(history) == 1
        assert history[0]["is_latest"] is True


# ════════════════════════════════════════════════════════════════════════════════
# get_snapshot
# ════════════════════════════════════════════════════════════════════════════════

class TestGetSnapshot:

    def test_returns_full_manifest(self):
        """get_snapshot retourne le manifest complet."""
        m = _make_manifest("curl", "7.0.0")
        _save_and_index(m)
        snap = snapshots_mod.get_snapshot("curl", "7.0.0", "amd64")
        assert snap is not None
        assert snap["name"] == "curl"
        assert snap["version"] == "7.0.0"
        assert "dependencies" in snap
        assert "integrity" in snap

    def test_returns_none_for_unknown(self):
        """get_snapshot retourne None pour une version inconnue."""
        result = snapshots_mod.get_snapshot("ghost", "9.9.9")
        assert result is None

    def test_arch_disambiguates(self):
        """Deux arches différentes retournent des snapshots différents."""
        _save_and_index(_make_manifest("multiarch", "1.0.0", arch="amd64"))
        _save_and_index(_make_manifest("multiarch", "1.0.0", arch="arm64"))
        snap_amd = snapshots_mod.get_snapshot("multiarch", "1.0.0", "amd64")
        snap_arm = snapshots_mod.get_snapshot("multiarch", "1.0.0", "arm64")
        assert snap_amd is not None and snap_amd["arch"] == "amd64"
        assert snap_arm is not None and snap_arm["arch"] == "arm64"


# ════════════════════════════════════════════════════════════════════════════════
# compare_versions
# ════════════════════════════════════════════════════════════════════════════════

class TestCompareVersions:

    def test_size_change_bytes(self):
        """size_change_bytes = size(v2) - size(v1)."""
        _save_and_index(_make_manifest("pkg", "1.0.0", file_size_bytes=1000))
        _save_and_index(_make_manifest("pkg", "2.0.0", file_size_bytes=1500))
        result = snapshots_mod.compare_versions("pkg", "1.0.0", "2.0.0")
        assert result["diff"]["size_change_bytes"] == 500

    def test_new_deps_detected(self):
        """new_deps contient les dépendances ajoutées dans v2."""
        _save_and_index(_make_manifest("pkg", "1.0.0", deps=[{"name": "libc6"}]))
        _save_and_index(_make_manifest("pkg", "2.0.0", deps=[{"name": "libc6"}, {"name": "openssl"}]))
        result = snapshots_mod.compare_versions("pkg", "1.0.0", "2.0.0")
        assert "openssl" in result["diff"]["new_deps"]
        assert result["diff"]["removed_deps"] == []

    def test_removed_deps_detected(self):
        """removed_deps contient les dépendances supprimées dans v2."""
        _save_and_index(_make_manifest("pkg", "1.0.0", deps=[{"name": "libc6"}, {"name": "libssl"}]))
        _save_and_index(_make_manifest("pkg", "2.0.0", deps=[{"name": "libc6"}]))
        result = snapshots_mod.compare_versions("pkg", "1.0.0", "2.0.0")
        assert "libssl" in result["diff"]["removed_deps"]

    def test_sha256_changed(self):
        """sha256_changed=True si les hashes d'intégrité diffèrent."""
        _save_and_index(_make_manifest("pkg", "1.0.0"))
        _save_and_index(_make_manifest("pkg", "2.0.0"))
        # Les hashes générés par _make_manifest sont {sha256-name-version} → différents
        result = snapshots_mod.compare_versions("pkg", "1.0.0", "2.0.0")
        assert result["diff"]["sha256_changed"] is True

    def test_description_changed(self):
        """description_changed=True si les descriptions diffèrent."""
        _save_and_index(_make_manifest("pkg", "1.0.0", description="Old desc"))
        _save_and_index(_make_manifest("pkg", "2.0.0", description="New desc"))
        result = snapshots_mod.compare_versions("pkg", "1.0.0", "2.0.0")
        assert result["diff"]["description_changed"] is True

    def test_no_changes_when_identical(self):
        """Si les deux versions ont les mêmes deps/hash/desc → pas de diff détecté."""
        m = _make_manifest("pkg", "1.0.0", deps=[{"name": "libc6"}], description="Same")
        m2 = _make_manifest("pkg", "2.0.0", deps=[{"name": "libc6"}], description="Same")
        # Forcer le même hash pour tester sha256_changed=False
        m2["integrity"]["sha256"] = m["integrity"]["sha256"]
        manifest_mod.save_manifest(m)
        indexer_mod.add_to_index(m)
        manifest_mod.save_manifest(m2)
        indexer_mod.add_to_index(m2)
        result = snapshots_mod.compare_versions("pkg", "1.0.0", "2.0.0")
        assert result["diff"]["description_changed"] is False
        assert result["diff"]["sha256_changed"] is False
        assert result["diff"]["new_deps"] == []
        assert result["diff"]["removed_deps"] == []

    def test_error_when_version_unknown(self):
        """compare_versions retourne error si l'une des versions est inconnue."""
        _save_and_index(_make_manifest("pkg", "1.0.0"))
        result = snapshots_mod.compare_versions("pkg", "1.0.0", "9.9.9")
        assert result["error"] is not None
        assert result["diff"] is None

    def test_returns_both_manifests(self):
        """Le résultat contient v1_manifest et v2_manifest complets."""
        _save_and_index(_make_manifest("pkg", "1.0.0"))
        _save_and_index(_make_manifest("pkg", "2.0.0"))
        result = snapshots_mod.compare_versions("pkg", "1.0.0", "2.0.0")
        assert result["v1_manifest"]["version"] == "1.0.0"
        assert result["v2_manifest"]["version"] == "2.0.0"


# ════════════════════════════════════════════════════════════════════════════════
# enforce_version_limit
# ════════════════════════════════════════════════════════════════════════════════

class TestEnforceVersionLimit:

    def test_does_nothing_when_at_limit(self):
        """Pas de suppression si count == max_versions."""
        for v in ["1.0.0", "2.0.0", "3.0.0"]:
            _save_and_index(_make_manifest("curl", v))
        deleted = snapshots_mod.enforce_version_limit("curl", max_versions=3)
        assert deleted == []

    def test_does_nothing_when_below_limit(self):
        """Pas de suppression si count < max_versions."""
        _save_and_index(_make_manifest("curl", "1.0.0"))
        deleted = snapshots_mod.enforce_version_limit("curl", max_versions=5)
        assert deleted == []

    def test_deletes_oldest_when_over_limit(self):
        """Supprime la version la plus ancienne quand count > max_versions."""
        old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        mid_ts = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        new_ts = datetime.now(timezone.utc).isoformat()

        _save_and_index(_make_manifest("curl", "1.0.0", imported_at=old_ts))
        _save_and_index(_make_manifest("curl", "2.0.0", imported_at=mid_ts))
        _save_and_index(_make_manifest("curl", "3.0.0", imported_at=new_ts))

        deleted = snapshots_mod.enforce_version_limit("curl", max_versions=2)
        assert len(deleted) == 1
        assert deleted[0]["version"] == "1.0.0"

    def test_never_deletes_latest(self):
        """La version marquée 'latest' n'est jamais supprimée."""
        old_ts = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        new_ts = datetime.now(timezone.utc).isoformat()

        _save_and_index(_make_manifest("vim", "1.0.0", imported_at=old_ts))
        _save_and_index(_make_manifest("vim", "9.0.0", imported_at=new_ts))

        # max_versions=1 → ne garde que la latest
        deleted = snapshots_mod.enforce_version_limit("vim", max_versions=1)
        assert len(deleted) == 1
        assert deleted[0]["version"] == "1.0.0"  # la plus ancienne supprimée

        # Vérifier que 9.0.0 est toujours dans l'index
        remaining = snapshots_mod.get_version_history("vim")
        assert len(remaining) == 1
        assert remaining[0]["version"] == "9.0.0"

    def test_disabled_when_max_is_zero(self):
        """max_versions=0 → désactivé, rien supprimé."""
        for v in ["1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0"]:
            _save_and_index(_make_manifest("pkg", v))
        deleted = snapshots_mod.enforce_version_limit("pkg", max_versions=0)
        assert deleted == []

    def test_unknown_package_returns_empty(self):
        """Paquet inconnu → [] (pas d'exception)."""
        deleted = snapshots_mod.enforce_version_limit("ghost-pkg", max_versions=3)
        assert deleted == []

    def test_deb_file_deleted_from_pool(self):
        """enforce_version_limit supprime le .deb du pool."""
        old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        _save_and_index(_make_manifest("curl", "1.0.0", imported_at=old_ts), with_deb=True)
        _save_and_index(_make_manifest("curl", "2.0.0"), with_deb=True)

        old_deb = _POOL_DIR / "curl_1.0.0_amd64.deb"
        assert old_deb.exists()

        snapshots_mod.enforce_version_limit("curl", max_versions=1)
        assert not old_deb.exists()

    def test_manifest_json_deleted(self):
        """enforce_version_limit supprime le manifest JSON."""
        old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        _save_and_index(_make_manifest("curl", "1.0.0", imported_at=old_ts))
        _save_and_index(_make_manifest("curl", "2.0.0"))

        old_json = _MANIFEST_DIR / "curl_1.0.0_amd64.manifest.json"
        assert old_json.exists()

        snapshots_mod.enforce_version_limit("curl", max_versions=1)
        assert not old_json.exists()

    def test_returns_deleted_list(self):
        """enforce_version_limit retourne la liste des versions supprimées."""
        old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        _save_and_index(_make_manifest("pkg", "1.0.0", imported_at=old_ts))
        _save_and_index(_make_manifest("pkg", "2.0.0"))
        _save_and_index(_make_manifest("pkg", "3.0.0"))

        deleted = snapshots_mod.enforce_version_limit("pkg", max_versions=2)
        assert len(deleted) == 1
        assert "version" in deleted[0]
        assert "name" in deleted[0]
        assert "filename" in deleted[0]


# ════════════════════════════════════════════════════════════════════════════════
# run_version_gc
# ════════════════════════════════════════════════════════════════════════════════

class TestRunVersionGc:

    def test_returns_summary(self):
        """run_version_gc retourne un dict de synthèse."""
        _save_and_index(_make_manifest("curl", "1.0.0"))
        result = snapshots_mod.run_version_gc(max_versions=5)
        assert "ran_at" in result
        assert "max_versions" in result
        assert "packages_checked" in result
        assert "versions_deleted" in result
        assert "details" in result

    def test_gc_deletes_excess_versions(self):
        """run_version_gc supprime les versions au-delà de max_versions sur tous les paquets."""
        old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        for name in ["curl", "nginx"]:
            _save_and_index(_make_manifest(name, "1.0.0", imported_at=old_ts))
            _save_and_index(_make_manifest(name, "2.0.0"))
            _save_and_index(_make_manifest(name, "3.0.0"))

        result = snapshots_mod.run_version_gc(max_versions=2)
        assert result["versions_deleted"] == 2  # 1 par paquet
        assert result["packages_checked"] == 2

    def test_gc_disabled_when_max_zero(self):
        """run_version_gc ne supprime rien si max_versions=0."""
        _save_and_index(_make_manifest("pkg", "1.0.0"))
        _save_and_index(_make_manifest("pkg", "2.0.0"))
        result = snapshots_mod.run_version_gc(max_versions=0)
        assert result["versions_deleted"] == 0
        assert "GC désactivé" in result.get("note", "")

    def test_gc_reads_from_settings(self):
        """run_version_gc lit max_versions depuis les settings si non fourni."""
        # Sauvegarder settings avec max_versions_per_package=2
        import services.settings as s
        s.SETTINGS_PATH = Path(f"{_TMP}/settings.json")
        s.update_settings({"versioning": {"max_versions_per_package": 2}})

        old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        _save_and_index(_make_manifest("vim", "1.0.0", imported_at=old_ts))
        _save_and_index(_make_manifest("vim", "2.0.0"))
        _save_and_index(_make_manifest("vim", "3.0.0"))

        result = snapshots_mod.run_version_gc()  # pas de max_versions → lit settings
        assert result["max_versions"] == 2
        assert result["versions_deleted"] == 1
