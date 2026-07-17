# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_delete_pool_file_wrong_extension_bug.py
Rôle   : Bug réel observé en production (VM .20, REPO_FORMAT=all) — un admin
         supprime un paquet .deb depuis la page Paquets, reçoit une
         confirmation de succès (ligne PostgreSQL + index.json bien
         supprimés), mais le fichier reste physiquement dans /repos/pool.
         Une réimportation du même fichier échoue alors avec
         "déjà présent dans le dépôt (SHA256 identique)" — le fichier
         orphelin bloque silencieusement toute réimportation.

         Cause : delete_artifact()/delete_artifact_version() (et,
         séparément, decision_router.py/scan_router.py) reconstruisaient
         le nom de fichier du pool via
             _pkg_ext = next(iter(_ACCEPTED_EXTS))
         Or ACCEPTED_EXTENSIONS est un frozenset à 3 éléments
         ({.deb, .rpm, .apk}) dès que REPO_FORMAT=all/both (le mode par
         défaut du docker-compose.yaml livré, voir CLAUDE.md) —
         next(iter(frozenset)) renvoie un élément arbitraire (ordre de
         hachage), sans rapport avec le format réel du paquet traité.
         Confirmé en direct sur .20 : next(iter(_ACCEPTED_EXTS)) valait
         ".rpm" dans le process réel, donc glob("nom_*.rpm") ne trouvait
         jamais le vrai fichier .deb — unlink() itérait sur zéro résultat,
         aucune erreur, la suppression "réussissait" en apparence.

         Fix : utiliser le nom de fichier exact stocké dans l'index/le
         manifest (source fiable) au lieu de le reconstruire en devinant
         une extension. services/format_router.py:find_pool_file() sert
         de filet de secours (essaie chaque extension) pour les rares cas
         où le nom stocké est absent.

Dépend : pytest, db_test_engine (SQLite in-memory, conftest.py) — aucun
         PostgreSQL réel nécessaire. Simule REPO_FORMAT=all en patchant
         _ACCEPTED_EXTS à un frozenset multi-format où next(iter(...)) ne
         renvoie PAS ".deb", reproduisant exactement les conditions vues
         en prod.
"""
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_TMP = tempfile.mkdtemp(prefix="repod_delete_ext_bug_test_")
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR", _TMP)
os.environ.setdefault("JWT_SECRET_KEY", "test-key-delete-ext-bug")

import routers.artifacts as artifacts_mod  # noqa: E402
from auth.dependencies import get_maintainer_user  # noqa: E402
from services.indexer import add_to_index  # noqa: E402
from services.manifest import save_manifest  # noqa: E402

artifacts_mod.MANIFEST_DIR = Path(_TMP)
artifacts_mod.POOL_DIR = Path(_TMP)

# Un frozenset multi-format dont next(iter(...)) ne renvoie PAS ".deb" en
# premier — reproduit le REPO_FORMAT=all vu en prod, sans dépendre du hasard
# de l'ordre de hachage réel (on force explicitement le pire cas).
_MULTI_FORMAT_EXTS = frozenset({".rpm", ".apk", ".deb"})
assert next(iter(_MULTI_FORMAT_EXTS)) != ".deb", (
    "précondition du test : l'extension devinée doit être fausse pour reproduire le bug"
)


def _make_manifest(name="curl", version="7.35.0-1ubuntu2", arch="amd64"):
    filename = f"{name}_{version}_{arch}.deb"
    return {
        "name": name, "version": version, "arch": arch, "distribution": "jammy",
        "type": "deb", "section": "net", "description": "", "maintainer": "",
        "installed_size_kb": 0, "file_size_bytes": 0,
        "filename": filename, "status": "validated",
        "source": {"imported_by": "admin", "imported_at": datetime.now(timezone.utc).isoformat(),
                   "import_method": "upload", "import_group": None},
        "integrity": {"sha256": "", "sha512": "", "gpg_signed": False},
        "dependencies": [], "tags": [], "validation_steps": [], "cve_results": [],
    }


@pytest.fixture
def app_client(monkeypatch):
    monkeypatch.setattr(artifacts_mod, "_ACCEPTED_EXTS", _MULTI_FORMAT_EXTS)
    app = FastAPI()
    app.include_router(artifacts_mod.router)
    app.dependency_overrides[get_maintainer_user] = lambda: "admin"
    return TestClient(app, raise_server_exceptions=False)


def _touch_pool_file(filename: str) -> Path:
    p = Path(_TMP) / filename
    p.write_bytes(b"fake-deb-content")
    return p


class TestDeleteAllVersionsRemovesRealPoolFile:
    def test_delete_all_versions_removes_pool_file_even_with_multi_format_exts(self, app_client, db_test_engine):
        manifest = _make_manifest()
        save_manifest(manifest)
        add_to_index(manifest)
        pool_file = _touch_pool_file(manifest["filename"])
        assert pool_file.exists()

        resp = app_client.delete("/artifacts/curl")

        assert resp.status_code == 200, resp.text
        assert not pool_file.exists(), (
            "le fichier .deb reste orphelin dans le pool — reproduit le bug prod "
            "où next(iter(_ACCEPTED_EXTS)) devine une mauvaise extension et le "
            "glob de nettoyage ne trouve jamais le vrai fichier"
        )

    def test_reimport_after_delete_is_not_blocked_by_orphaned_file(self, app_client, db_test_engine):
        """Régression exacte rapportée en prod : supprimer puis réimporter le
        même fichier échouait avec 'déjà présent (SHA256 identique)' parce
        que le fichier orphelin du bug ci-dessus survivait à la suppression."""
        manifest = _make_manifest()
        save_manifest(manifest)
        add_to_index(manifest)
        pool_file = _touch_pool_file(manifest["filename"])

        resp = app_client.delete("/artifacts/curl")
        assert resp.status_code == 200, resp.text

        # Ce que routers/upload.py:_check_duplicate() vérifie avant tout
        # nouvel upload : le fichier ne doit plus exister dans le pool.
        assert not pool_file.exists(), (
            "une réimportation ultérieure serait bloquée à tort par "
            "_check_duplicate() (SHA256 identique sur un fichier orphelin)"
        )


class TestDeleteSingleVersionRemovesRealPoolFile:
    def test_delete_version_removes_pool_file_even_with_multi_format_exts(self, app_client, db_test_engine):
        manifest = _make_manifest()
        save_manifest(manifest)
        add_to_index(manifest)
        pool_file = _touch_pool_file(manifest["filename"])
        assert pool_file.exists()

        resp = app_client.delete("/artifacts/curl/7.35.0-1ubuntu2")

        assert resp.status_code == 200, resp.text
        assert not pool_file.exists()
