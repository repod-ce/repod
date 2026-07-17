"""
Module : test_manifest_sqlite.py
Rôle   : Tests de la couche DB dans services/manifest.py.
         Utilise db_test_engine (SQLite in-memory) — aucun PostgreSQL requis.

Scénarios couverts :
  save_manifest() :
    - Fichier JSON créé sur le disque
    - Manifest upsert dans la DB (count == 1)
    - Mise à jour d'un manifest existant (upsert → toujours 1 ligne)
    - Deux versions différentes coexistent
    - dependencies stockées et restituées fidèlement
    - validation_steps roundtrip
    - gpg_signed bool correct

  load_manifest() :
    - Lecture depuis la DB après save
    - Fallback JSON si absent de la DB
    - Retourne None si absent des deux

  search_manifests() :
    - Recherche par nom partiel
    - Filtre par distribution
    - Filtre par statut
    - Requête vide → tous
    - Aucun résultat → liste vide

  delete_manifest_from_db() :
    - Suppression par (name, version, arch)
    - Suppression par name seul (toutes versions)
    - Retourne 0 si absent
    - Seule la version ciblée est supprimée

  migrate_json_to_db() :
    - Importe les JSON existants
    - Idempotent (ON CONFLICT DO NOTHING)
    - Ne remplace pas les entrées DB existantes
    - Dir vide → 0

  count_manifests_in_db() :
    - Comptage correct

Dépend : pytest, db_test_engine (conftest.py)
"""

# ── Env avant tout import ─────────────────────────────────────────────────────
import json
import os
import tempfile
from pathlib import Path

import pytest

# MANIFEST_DIR doit être défini avant l'import du module
_TMP = tempfile.mkdtemp(prefix="repod_manifest_test_")
os.environ.setdefault("MANIFEST_DIR",    _TMP)
os.environ.setdefault("JWT_SECRET_KEY",  "test-key-manifest")
os.environ.setdefault("POOL_DIR",        _TMP)

# ── Import du module sous test ────────────────────────────────────────────────
import services.manifest as manifest_mod

manifest_mod.MANIFEST_DIR = Path(_TMP)


# ── Helper de construction ────────────────────────────────────────────────────

def _make_manifest(
    name: str = "testpkg",
    version: str = "1.0.0",
    arch: str = "amd64",
    distribution: str = "jammy",
    description: str = "Test package",
    status: str = "validated",
) -> dict:
    return {
        "name":        name,
        "version":     version,
        "arch":        arch,
        "distribution": distribution,
        "section":     "main",
        "description": description,
        "maintainer":  "test@test.local",
        "installed_size_kb": 100,
        "file_size_bytes":   1024,
        "filename":    f"{name}_{version}_{arch}.deb",
        "type":        "deb",
        "source": {
            "imported_by":    "ci",
            "imported_at":    "2026-01-01T00:00:00+00:00",
            "import_method":  "upload",
            "import_group":   None,
        },
        "integrity": {
            "sha256":     "abc123",
            "sha512":     "def456",
            "gpg_signed": False,
        },
        "dependencies":     [{"name": "libc6"}],
        "status":           status,
        "tags":             ["test"],
        "validation_steps": [{"step": "clamav", "ok": True}],
        "cve_results":      [],
    }


# ── Fixture : DB + filesystem propres avant chaque test ───────────────────────

@pytest.fixture(autouse=True)
def clean_db(db_test_engine):
    """
    Vide la table manifests et les fichiers JSON avant/après chaque test.
    Dépend de db_test_engine (SQLite in-memory) depuis conftest.py.
    """
    from sqlalchemy import text as _t

    manifest_mod.MANIFEST_DIR = Path(_TMP)

    def _wipe():
        with db_test_engine.begin() as conn:
            conn.execute(_t("DELETE FROM manifests"))
        for f in Path(_TMP).glob("*.manifest.json"):
            f.unlink(missing_ok=True)
        manifest_mod.invalidate_manifest_cache()

    _wipe()
    yield
    _wipe()


# ═════════════════════════════════════════════════════════════════════════════
# save_manifest — écriture DB + JSON
# ═════════════════════════════════════════════════════════════════════════════

class TestSaveManifest:

    def test_json_file_created(self):
        """save_manifest crée un fichier JSON sur le disque."""
        m = _make_manifest("curl", "7.88.0")
        path = manifest_mod.save_manifest(m)
        assert Path(path).exists()
        loaded = json.loads(Path(path).read_text())
        assert loaded["name"] == "curl"

    def test_db_row_inserted(self):
        """save_manifest insère une ligne dans la DB."""
        manifest_mod.save_manifest(_make_manifest("nginx", "1.24.0"))
        assert manifest_mod.count_manifests_in_db() == 1

    def test_upsert_updates_existing(self):
        """Sauvegarder deux fois le même paquet → upsert (pas de doublon)."""
        manifest_mod.save_manifest(_make_manifest("openssl", "3.0.2", description="original"))
        manifest_mod.save_manifest(_make_manifest("openssl", "3.0.2", description="updated"))
        assert manifest_mod.count_manifests_in_db() == 1
        results = manifest_mod.search_manifests("openssl")
        assert results[0]["description"] == "updated"

    def test_different_versions_coexist(self):
        """Deux versions différentes du même paquet → deux lignes."""
        manifest_mod.save_manifest(_make_manifest("curl", "7.88.0"))
        manifest_mod.save_manifest(_make_manifest("curl", "8.0.0"))
        assert manifest_mod.count_manifests_in_db() == 2

    def test_dependencies_stored_and_restored(self):
        """Les dépendances sont stockées et restituées fidèlement."""
        m = _make_manifest("myapp", "2.0.0")
        manifest_mod.save_manifest(m)
        loaded = manifest_mod.load_manifest("myapp", "2.0.0")
        assert loaded["dependencies"] == [{"name": "libc6"}]

    def test_validation_steps_roundtrip(self):
        """Les validation_steps sont préservés après save/load."""
        m = _make_manifest("scanme", "1.0.0")
        m["validation_steps"] = [{"step": "clamav", "ok": True, "detail": "clean"}]
        manifest_mod.save_manifest(m)
        loaded = manifest_mod.load_manifest("scanme", "1.0.0")
        assert loaded["validation_steps"] == [{"step": "clamav", "ok": True, "detail": "clean"}]

    def test_gpg_signed_stored_and_restored(self):
        """gpg_signed bool est correctement stocké et restauré."""
        m = _make_manifest("signed-pkg", "1.0.0")
        m["integrity"]["gpg_signed"] = True
        manifest_mod.save_manifest(m)
        loaded = manifest_mod.load_manifest("signed-pkg", "1.0.0")
        assert loaded["integrity"]["gpg_signed"] is True


# ═════════════════════════════════════════════════════════════════════════════
# load_manifest — DB en priorité, fallback JSON
# ═════════════════════════════════════════════════════════════════════════════

class TestLoadManifest:

    def test_loads_from_db_after_save(self):
        """load_manifest retourne le manifest depuis la DB après save."""
        m = _make_manifest("curl", "7.88.0")
        manifest_mod.save_manifest(m)
        loaded = manifest_mod.load_manifest("curl", "7.88.0", "amd64")
        assert loaded is not None
        assert loaded["name"] == "curl"
        assert loaded["version"] == "7.88.0"

    def test_falls_back_to_json_when_not_in_db(self):
        """Si la DB ne contient pas le manifest, load_manifest lit le JSON."""
        m = _make_manifest("legacy", "0.9.0")
        path = Path(_TMP) / "legacy_0.9.0_amd64.manifest.json"
        path.write_text(json.dumps(m))
        # DB vide → doit fallback sur JSON
        loaded = manifest_mod.load_manifest("legacy", "0.9.0", "amd64")
        assert loaded is not None
        assert loaded["name"] == "legacy"

    def test_returns_none_if_absent_everywhere(self):
        """load_manifest retourne None si absent de DB et JSON."""
        result = manifest_mod.load_manifest("nonexistent", "1.0.0", "amd64")
        assert result is None

    def test_source_fields_preserved(self):
        """Les champs source (imported_by, imported_at) sont préservés."""
        m = _make_manifest("srctest", "1.0.0")
        manifest_mod.save_manifest(m)
        loaded = manifest_mod.load_manifest("srctest", "1.0.0")
        assert loaded["source"]["imported_by"] == "ci"
        assert loaded["source"]["import_method"] == "upload"

    def test_arch_disambiguates(self):
        """Deux arches différentes du même nom/version sont des entrées distinctes."""
        manifest_mod.save_manifest(_make_manifest("multiarch", "1.0.0", arch="amd64"))
        manifest_mod.save_manifest(_make_manifest("multiarch", "1.0.0", arch="arm64"))
        amd = manifest_mod.load_manifest("multiarch", "1.0.0", "amd64")
        arm = manifest_mod.load_manifest("multiarch", "1.0.0", "arm64")
        assert amd is not None and amd["arch"] == "amd64"
        assert arm is not None and arm["arch"] == "arm64"


# ═════════════════════════════════════════════════════════════════════════════
# search_manifests
# ═════════════════════════════════════════════════════════════════════════════

class TestSearchManifests:

    def test_search_by_name_partial(self):
        """Recherche partielle sur le nom du paquet."""
        manifest_mod.save_manifest(_make_manifest("curl", "7.88.0"))
        manifest_mod.save_manifest(_make_manifest("libcurl", "7.88.0"))
        manifest_mod.save_manifest(_make_manifest("nginx", "1.24.0"))
        results = manifest_mod.search_manifests("curl")
        names = {r["name"] for r in results}
        assert "curl" in names
        assert "libcurl" in names
        assert "nginx" not in names

    def test_filter_by_distribution(self):
        """Filtre exact par distribution."""
        manifest_mod.save_manifest(_make_manifest("pkg1", "1.0.0", distribution="jammy"))
        manifest_mod.save_manifest(_make_manifest("pkg2", "1.0.0", distribution="noble"))
        results = manifest_mod.search_manifests(distribution="noble")
        assert len(results) == 1
        assert results[0]["name"] == "pkg2"

    def test_filter_by_status(self):
        """Filtre exact par statut."""
        manifest_mod.save_manifest(_make_manifest("ok-pkg",  "1.0.0", status="validated"))
        manifest_mod.save_manifest(_make_manifest("bad-pkg", "1.0.0", status="quarantined"))
        quarantined = manifest_mod.search_manifests(status="quarantined")
        assert len(quarantined) == 1
        assert quarantined[0]["name"] == "bad-pkg"

    def test_empty_query_returns_all(self):
        """Requête vide retourne tous les manifests."""
        for i in range(3):
            manifest_mod.save_manifest(_make_manifest(f"pkg{i}", "1.0.0"))
        assert len(manifest_mod.search_manifests()) == 3

    def test_no_match_returns_empty_list(self):
        """Aucun résultat → liste vide (pas d'exception)."""
        manifest_mod.save_manifest(_make_manifest("nginx", "1.0.0"))
        assert manifest_mod.search_manifests("zzz-nonexistent-zzz") == []


# ═════════════════════════════════════════════════════════════════════════════
# delete_manifest_from_db
# ═════════════════════════════════════════════════════════════════════════════

class TestDeleteManifestFromDb:

    def test_delete_exact_pk(self):
        """Suppression par (name, version, arch) exact."""
        manifest_mod.save_manifest(_make_manifest("curl", "7.88.0"))
        deleted = manifest_mod.delete_manifest_from_db("curl", "7.88.0", "amd64")
        assert deleted == 1
        assert manifest_mod.count_manifests_in_db() == 0

    def test_delete_all_versions_by_name(self):
        """delete_manifest_from_db sans version → toutes les versions supprimées."""
        manifest_mod.save_manifest(_make_manifest("curl", "7.88.0"))
        manifest_mod.save_manifest(_make_manifest("curl", "8.0.0"))
        deleted = manifest_mod.delete_manifest_from_db("curl")
        assert deleted == 2
        assert manifest_mod.count_manifests_in_db() == 0

    def test_delete_nonexistent_returns_zero(self):
        """Supprimer un manifest absent → 0 (pas d'exception)."""
        assert manifest_mod.delete_manifest_from_db("ghost", "1.0.0", "amd64") == 0

    def test_delete_only_target_version(self):
        """Seule la version ciblée est supprimée, l'autre reste."""
        manifest_mod.save_manifest(_make_manifest("curl", "7.88.0"))
        manifest_mod.save_manifest(_make_manifest("curl", "8.0.0"))
        manifest_mod.delete_manifest_from_db("curl", "7.88.0", "amd64")
        assert manifest_mod.count_manifests_in_db() == 1
        remaining = manifest_mod.search_manifests("curl")
        assert remaining[0]["version"] == "8.0.0"


# ═════════════════════════════════════════════════════════════════════════════
# migrate_json_to_db
# ═════════════════════════════════════════════════════════════════════════════

class TestMigrateJsonToDb:

    def test_imports_existing_json_files(self):
        """migrate_json_to_db importe les JSON présents dans MANIFEST_DIR."""
        for name in ["curl", "nginx", "openssl"]:
            m = _make_manifest(name, "1.0.0")
            (Path(_TMP) / f"{name}_1.0.0_amd64.manifest.json").write_text(json.dumps(m))

        count = manifest_mod.migrate_json_to_db()
        assert count == 3
        assert manifest_mod.count_manifests_in_db() == 3

    def test_migrate_is_idempotent(self):
        """Appeler migrate deux fois → ON CONFLICT DO NOTHING → pas de doublon."""
        m = _make_manifest("vim", "9.0.0")
        (Path(_TMP) / "vim_9.0.0_amd64.manifest.json").write_text(json.dumps(m))

        manifest_mod.migrate_json_to_db()
        manifest_mod.migrate_json_to_db()
        assert manifest_mod.count_manifests_in_db() == 1

    def test_migrate_does_not_overwrite_existing_db_entries(self):
        """Les entrées déjà en DB ne sont pas écrasées par la migration."""
        m_original = _make_manifest("curl", "7.88.0", description="original")
        manifest_mod.save_manifest(m_original)

        # JSON sur le disque diffère de la DB — migrate ne doit pas écraser
        m_modified = _make_manifest("curl", "7.88.0", description="modified-by-json")
        (Path(_TMP) / "curl_7.88.0_amd64.manifest.json").write_text(json.dumps(m_modified))

        manifest_mod.migrate_json_to_db()
        results = manifest_mod.search_manifests("curl")
        assert results[0]["description"] == "original"  # DB prioritaire

    def test_migrate_empty_dir_returns_zero(self):
        """Pas de fichiers JSON → 0 importé."""
        assert manifest_mod.migrate_json_to_db() == 0


# ═════════════════════════════════════════════════════════════════════════════
# count_manifests_in_db
# ═════════════════════════════════════════════════════════════════════════════

class TestCountManifestsInDb:

    def test_empty_db_returns_zero(self):
        """DB vide → 0."""
        assert manifest_mod.count_manifests_in_db() == 0

    def test_count_after_save(self):
        """Comptage correct après plusieurs saves."""
        for i in range(5):
            manifest_mod.save_manifest(_make_manifest(f"pkg{i}", "1.0.0"))
        assert manifest_mod.count_manifests_in_db() == 5

    def test_count_after_delete(self):
        """Comptage diminue après suppression."""
        manifest_mod.save_manifest(_make_manifest("a", "1.0.0"))
        manifest_mod.save_manifest(_make_manifest("b", "1.0.0"))
        manifest_mod.delete_manifest_from_db("a", "1.0.0", "amd64")
        assert manifest_mod.count_manifests_in_db() == 1
