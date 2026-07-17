# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_delete_artifact_db_cleanup.py
Rôle   : Bug réel observé en production (VM .20) — un admin supprime un
         paquet depuis "Décisions CVE" (icône corbeille), reçoit une
         confirmation de succès, mais le paquet reste affiché
         indéfiniment. Confirmé en base réelle : la ligne PostgreSQL
         `manifests` n'était jamais supprimée.

         Cause : routers/artifacts.py:delete_artifact()/
         delete_artifact_version() ne nettoyaient que le fichier JSON
         legacy (glob + unlink manuel) et index.json — jamais la table
         PostgreSQL `manifests`, qui est pourtant la source de vérité
         lue par list_manifests()/GET /security/packages-posture (la
         liste affichée à l'écran). services/manifest.py expose déjà
         delete_manifest_from_db() qui fait les deux correctement
         (DB + fichier JSON) ; les routers ne l'appelaient simplement
         jamais.

Dépend : pytest, db_test_engine (SQLite in-memory, conftest.py) —
         aucun PostgreSQL réel nécessaire.
"""
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_TMP = tempfile.mkdtemp(prefix="repod_delete_artifact_test_")
os.environ.setdefault("MANIFEST_DIR", _TMP)
os.environ.setdefault("POOL_DIR", _TMP)
os.environ.setdefault("JWT_SECRET_KEY", "test-key-delete-artifact")

import routers.artifacts as artifacts_mod  # noqa: E402
from auth.dependencies import get_maintainer_user  # noqa: E402
from services.indexer import add_to_index  # noqa: E402
from services.manifest import count_manifests_in_db, save_manifest  # noqa: E402

artifacts_mod.MANIFEST_DIR = Path(_TMP)
artifacts_mod.POOL_DIR = Path(_TMP)


def _make_manifest(name="curl", version="7.35.0-1ubuntu2", arch="amd64", status="pending_review"):
    return {
        "name": name, "version": version, "arch": arch, "distribution": "jammy",
        "type": "deb", "section": "net", "description": "", "maintainer": "",
        "installed_size_kb": 0, "file_size_bytes": 0,
        "filename": f"{name}_{version}_{arch}.deb", "status": status,
        "source": {"imported_by": "admin", "imported_at": datetime.now(timezone.utc).isoformat(),
                   "import_method": "upload", "import_group": None},
        "integrity": {"sha256": "", "sha512": "", "gpg_signed": False},
        "dependencies": [], "tags": [], "validation_steps": [], "cve_results": [],
    }


@pytest.fixture
def app_client():
    app = FastAPI()
    app.include_router(artifacts_mod.router)
    app.dependency_overrides[get_maintainer_user] = lambda: "admin"
    return TestClient(app, raise_server_exceptions=False)


class TestDeleteArtifactVersionRemovesDbRow:
    def test_delete_version_removes_the_postgres_row(self, app_client, db_test_engine):
        manifest = _make_manifest()
        save_manifest(manifest)
        add_to_index(manifest)
        assert count_manifests_in_db() == 1

        resp = app_client.delete("/artifacts/curl/7.35.0-1ubuntu2")

        assert resp.status_code == 200, resp.text
        assert count_manifests_in_db() == 0, (
            "le paquet reste en base après suppression — c'est exactement le bug "
            "observé en prod : l'UI le réaffiche indéfiniment"
        )

    def test_delete_version_only_removes_the_targeted_version(self, app_client, db_test_engine):
        save_manifest(_make_manifest(version="7.35.0-1ubuntu2"))
        save_manifest(_make_manifest(version="7.68.0-1ubuntu2"))
        add_to_index(_make_manifest(version="7.35.0-1ubuntu2"))
        add_to_index(_make_manifest(version="7.68.0-1ubuntu2"))
        assert count_manifests_in_db() == 2

        resp = app_client.delete("/artifacts/curl/7.35.0-1ubuntu2")

        assert resp.status_code == 200, resp.text
        assert count_manifests_in_db() == 1


class TestDeleteArtifactAllVersionsRemovesDbRows:
    def test_delete_all_versions_removes_every_postgres_row(self, app_client, db_test_engine):
        save_manifest(_make_manifest(version="7.35.0-1ubuntu2"))
        save_manifest(_make_manifest(version="7.68.0-1ubuntu2"))
        add_to_index(_make_manifest(version="7.35.0-1ubuntu2"))
        add_to_index(_make_manifest(version="7.68.0-1ubuntu2"))
        assert count_manifests_in_db() == 2

        resp = app_client.delete("/artifacts/curl")

        assert resp.status_code == 200, resp.text
        assert count_manifests_in_db() == 0

    def test_delete_all_versions_does_not_touch_other_packages(self, app_client, db_test_engine):
        save_manifest(_make_manifest(name="curl"))
        save_manifest(_make_manifest(name="libf2c2-dev", version="20140711-1"))
        add_to_index(_make_manifest(name="curl"))
        add_to_index(_make_manifest(name="libf2c2-dev", version="20140711-1"))

        resp = app_client.delete("/artifacts/curl")

        assert resp.status_code == 200, resp.text
        assert count_manifests_in_db() == 1
