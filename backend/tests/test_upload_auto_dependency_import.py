# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_upload_auto_dependency_import.py
Rôle   : jusqu'ici, un dépôt manuel ("Déposer") ne faisait que RAPPORTER les
         dépendances manquantes (étape "dependencies", avertissement non
         bloquant) sans jamais les importer — seul l'onglet "Importer depuis
         internet" (resolve_deps_online() + import_package_stream()) le
         faisait, et uniquement sur demande explicite. Un paquet déposé
         manuellement dont les dépendances existent publiquement (ex. nmap
         et ses 10 dépendances Ubuntu) restait donc avec des dépendances
         manquantes tant que personne ne cliquait "Résoudre les dépendances"
         depuis la page Paquets.

         routers/upload.py:_auto_import_missing_deps() ferme cet écart :
         après la publication du paquet principal (POST /upload/ et
         /upload/stream), chaque dépendance signalée manquante par
         validate_dependencies() est importée automatiquement via
         services.importer.import_one() (même pipeline complet que l'import
         internet — validation format/antivirus/CVE/politique — dispatché
         par format selon la distribution cible).

Dépend : pytest, unittest.mock — aucun subprocess/réseau/DB réel.
"""
import asyncio
import importlib
import sys
from unittest.mock import MagicMock, patch

import pytest

# routers/__init__.py does `from .upload import router as upload`, which
# shadows the routers.upload SUBMODULE reference at the package level with
# the router object itself — patch("routers.upload.X", ...) (string form)
# resolves via that shadowed attribute and raises AttributeError. importlib
# bypasses it and returns the real registered submodule — see
# test_importer_pending_review_gate.py's twin issue with services.importer.
_upload_mod = importlib.import_module("routers.upload")


@pytest.fixture(autouse=True)
def _fresh_importer_module():
    """
    tests/test_rpm_format_services.py's _reload_module() sweeps sys.modules
    for anything containing "importer" (among other format-dependent
    modules) and deletes it, without re-importing it afterward — the
    `services` package keeps a now-orphaned `importer` attribute pointing
    at the deleted module object. unittest.mock.patch("services.importer.X")
    resolves its target via getattr(services_pkg, "importer") *before*
    falling back to sys.modules, so when this test runs after that reload
    helper, patch() ends up patching the orphaned object — never the one a
    native import (like import_one()'s own internal imports) would
    actually use, silently desyncing the mock from the code under test.
    Forcing a native reload/import here first keeps sys.modules and the
    parent package's attribute consistent — see the identical issue and
    fix in test_importer_pending_review_gate.py.
    """
    if "services.importer" in sys.modules:
        importlib.reload(sys.modules["services.importer"])
    else:
        import services.importer  # noqa: F401


class TestMissingDepNames:
    def test_extracts_only_unavailable_deps(self):
        from routers.upload import _missing_dep_names

        validation = MagicMock()
        validation.deps = [
            {"name": "libc6", "available_internally": False},
            {"name": "zlib1g", "available_internally": True},
            {"name": "libssl3", "available_internally": False},
        ]
        assert _missing_dep_names(validation) == ["libc6", "libssl3"]

    def test_no_deps_returns_empty_list(self):
        from routers.upload import _missing_dep_names

        validation = MagicMock()
        validation.deps = []
        assert _missing_dep_names(validation) == []

    def test_none_deps_returns_empty_list(self):
        from routers.upload import _missing_dep_names

        validation = MagicMock()
        validation.deps = None
        assert _missing_dep_names(validation) == []

    def test_missing_available_internally_key_treated_as_missing(self):
        """available_internally absent (données legacy) → considéré manquant,
        jamais silencieusement traité comme disponible."""
        from routers.upload import _missing_dep_names

        validation = MagicMock()
        validation.deps = [{"name": "foo"}]
        assert _missing_dep_names(validation) == ["foo"]


class TestAutoImportMissingDeps:
    def test_calls_import_one_per_dependency_with_correct_args(self):
        from routers.upload import _auto_import_missing_deps

        fake_results = {
            "libc6":  {"status": "added", "name": "libc6", "message": "ajouté au repo"},
            "zlib1g": {"status": "added", "name": "zlib1g", "message": "ajouté au repo"},
        }
        mock_import_one = MagicMock(side_effect=lambda pkg_row, distribution, user, group: fake_results[pkg_row["name"]])

        with patch("services.importer.import_one", mock_import_one):
            results = asyncio.run(_auto_import_missing_deps(
                ["libc6", "zlib1g"], "jammy", "admin", "nmap"
            ))

        assert results == [fake_results["libc6"], fake_results["zlib1g"]]
        assert mock_import_one.call_count == 2
        mock_import_one.assert_any_call({"name": "libc6"}, "jammy", "admin", "nmap")
        mock_import_one.assert_any_call({"name": "zlib1g"}, "jammy", "admin", "nmap")

    def test_pending_review_dependency_is_reported_not_raised(self):
        from routers.upload import _auto_import_missing_deps

        pending = {"status": "pending_review", "name": "libssl3", "message": "en attente révision RSSI (non publié)"}
        with patch("services.importer.import_one", return_value=pending):
            results = asyncio.run(_auto_import_missing_deps(["libssl3"], "jammy", "admin", "nmap"))
        assert results == [pending]

    def test_one_dependency_failing_does_not_block_the_others(self):
        """Une dépendance qui échoue (exception) ne doit ni interrompre la
        boucle ni faire planter le dépôt du paquet principal — juste être
        rapportée avec un statut error."""
        from routers.upload import _auto_import_missing_deps

        def side_effect(pkg_row, distribution, user, group):
            if pkg_row["name"] == "broken-dep":
                raise RuntimeError("réseau indisponible")
            return {"status": "added", "name": pkg_row["name"]}

        with patch("services.importer.import_one", side_effect=side_effect):
            results = asyncio.run(_auto_import_missing_deps(
                ["ok-dep-1", "broken-dep", "ok-dep-2"], "jammy", "admin", "pkg"
            ))

        assert len(results) == 3
        assert results[0]["status"] == "added"
        assert results[1]["status"] == "error"
        assert "réseau indisponible" in results[1]["message"]
        assert results[2]["status"] == "added"

    def test_empty_list_calls_nothing(self):
        from routers.upload import _auto_import_missing_deps

        with patch("services.importer.import_one") as mock_import_one:
            results = asyncio.run(_auto_import_missing_deps([], "jammy", "admin", "pkg"))
        mock_import_one.assert_not_called()
        assert results == []


class TestAutoImportMissingDepsTransitive:
    """validate_dependencies() ne peut lire le champ Depends que d'un .deb
    déjà présent localement — pour un paquet réellement manquant, ses PROPRES
    dépendances sont invisibles depuis le paquet parent. La seule façon de
    les découvrir est d'importer le paquet d'abord, puis de relire ses
    deps_missing (calculées à l'import, stockées dans l'index par
    add_to_index()). _auto_import_missing_deps() doit boucler jusqu'à
    épuisement (aucune nouvelle découverte), pas s'arrêter au premier
    niveau."""

    def test_discovers_and_imports_sub_dependencies(self):
        from routers.upload import _auto_import_missing_deps

        # libgcc-s1 manque → importé → révèle que libc6 lui manque à SON tour
        # → libc6 importé → ne révèle plus rien (point fixe atteint).
        import_results = {
            "libgcc-s1": {"status": "added", "name": "libgcc-s1"},
            "libc6":     {"status": "added", "name": "libc6"},
        }
        sub_deps = {"libgcc-s1": ["libc6"], "libc6": []}

        mock_import_one = MagicMock(side_effect=lambda pkg_row, distribution, user, group: import_results[pkg_row["name"]])

        with patch("services.importer.import_one", mock_import_one), \
             patch.object(_upload_mod, "_sub_missing_deps", side_effect=lambda name: sub_deps.get(name, [])):
            results = asyncio.run(_auto_import_missing_deps(["libgcc-s1"], "jammy", "admin", "webapp"))

        assert [r["name"] for r in results] == ["libgcc-s1", "libc6"]
        assert mock_import_one.call_count == 2
        mock_import_one.assert_any_call({"name": "libgcc-s1"}, "jammy", "admin", "webapp")
        mock_import_one.assert_any_call({"name": "libc6"}, "jammy", "admin", "webapp")

    def test_does_not_reimport_an_already_queued_or_processed_dependency(self):
        """Un graphe en losange (A et B dépendent tous deux de C) ne doit
        importer C qu'une seule fois, pas une fois par prédécesseur."""
        from routers.upload import _auto_import_missing_deps

        import_results = {
            "pkg-a": {"status": "added", "name": "pkg-a"},
            "pkg-b": {"status": "added", "name": "pkg-b"},
            "pkg-c": {"status": "added", "name": "pkg-c"},
        }
        sub_deps = {"pkg-a": ["pkg-c"], "pkg-b": ["pkg-c"], "pkg-c": []}

        mock_import_one = MagicMock(side_effect=lambda pkg_row, distribution, user, group: import_results[pkg_row["name"]])

        with patch("services.importer.import_one", mock_import_one), \
             patch.object(_upload_mod, "_sub_missing_deps", side_effect=lambda name: sub_deps.get(name, [])):
            results = asyncio.run(_auto_import_missing_deps(["pkg-a", "pkg-b"], "jammy", "admin", "webapp"))

        assert sorted(r["name"] for r in results) == ["pkg-a", "pkg-b", "pkg-c"]
        assert mock_import_one.call_count == 3, "pkg-c ne doit être importé qu'une seule fois malgré deux prédécesseurs"

    def test_circular_dependency_does_not_loop_forever(self):
        """A dépend de B, B dépend de A — sans garde-fou seen(), la file
        grossirait indéfiniment."""
        from routers.upload import _auto_import_missing_deps

        import_results = {
            "pkg-a": {"status": "added", "name": "pkg-a"},
            "pkg-b": {"status": "added", "name": "pkg-b"},
        }
        sub_deps = {"pkg-a": ["pkg-b"], "pkg-b": ["pkg-a"]}

        mock_import_one = MagicMock(side_effect=lambda pkg_row, distribution, user, group: import_results[pkg_row["name"]])

        with patch("services.importer.import_one", mock_import_one), \
             patch.object(_upload_mod, "_sub_missing_deps", side_effect=lambda name: sub_deps.get(name, [])):
            results = asyncio.run(_auto_import_missing_deps(["pkg-a"], "jammy", "admin", "webapp"))

        assert sorted(r["name"] for r in results) == ["pkg-a", "pkg-b"]
        assert mock_import_one.call_count == 2

    def test_max_total_caps_a_pathological_dependency_chain(self):
        """Une chaîne artificiellement longue (pkg-0 → pkg-1 → pkg-2 → …) ne
        doit jamais dépasser _MAX_AUTO_IMPORT_DEPS imports."""
        from routers.upload import _MAX_AUTO_IMPORT_DEPS, _auto_import_missing_deps

        def fake_import(pkg_row, distribution, user, group):
            return {"status": "added", "name": pkg_row["name"]}

        def fake_sub_deps(name):
            n = int(name.split("-")[1])
            return [f"pkg-{n + 1}"]

        with patch("services.importer.import_one", side_effect=fake_import) as mock_import_one, \
             patch.object(_upload_mod, "_sub_missing_deps", side_effect=fake_sub_deps):
            results = asyncio.run(_auto_import_missing_deps(["pkg-0"], "jammy", "admin", "webapp"))

        assert len(results) == _MAX_AUTO_IMPORT_DEPS
        assert mock_import_one.call_count == _MAX_AUTO_IMPORT_DEPS

    def test_failed_dependency_is_not_probed_for_sub_dependencies(self):
        """Une dépendance qui échoue n'a pas de manifest/index — inutile
        (et impossible) d'aller chercher ses deps_missing."""
        from routers.upload import _auto_import_missing_deps

        with patch("services.importer.import_one",
                   return_value={"status": "error", "name": "broken", "message": "boom"}), \
             patch.object(_upload_mod, "_sub_missing_deps") as mock_sub_deps:
            results = asyncio.run(_auto_import_missing_deps(["broken"], "jammy", "admin", "webapp"))

        assert len(results) == 1
        mock_sub_deps.assert_not_called()


# ─── Intégration : POST /upload/ appelle bien la résolution automatique ──────

import os
import tempfile
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_TMP = tempfile.mkdtemp(prefix="repod_upload_autodep_test_")
os.environ.setdefault("POOL_DIR", _TMP)
os.environ.setdefault("STAGING_INCOMING", os.path.join(_TMP, "incoming"))
os.environ.setdefault("STAGING_QUARANTINE", os.path.join(_TMP, "quarantine"))
os.environ.setdefault("JWT_SECRET_KEY", "test-key-upload-autodep")

import importlib  # noqa: E402

from auth.dependencies import get_uploader_user  # noqa: E402

# routers/__init__.py does `from .upload import router as upload`, which
# shadows the routers.upload SUBMODULE reference at the package level with
# the router object itself — `import routers.upload as upload_mod` would
# silently bind upload_mod to that router object, not the module, breaking
# every patch.object(upload_mod, ...) below. importlib bypasses the
# package's shadowed attribute and returns the real registered submodule.
upload_mod = importlib.import_module("routers.upload")

upload_mod.POOL_DIR = Path(_TMP)
upload_mod.STAGING_INCOMING = Path(_TMP) / "incoming"
upload_mod.STAGING_QUARANTINE = Path(_TMP) / "quarantine"
for _d in (upload_mod.POOL_DIR, upload_mod.STAGING_INCOMING, upload_mod.STAGING_QUARANTINE):
    _d.mkdir(parents=True, exist_ok=True)


def _fake_validation(deps_missing_names):
    v = MagicMock()
    v.passed = True
    v.cve_status = "approved"
    v.cve_results = []
    v.steps = [{"name": "dependencies", "passed": not deps_missing_names, "warning": bool(deps_missing_names),
                "message": f"{len(deps_missing_names)} manquante(s)" if deps_missing_names else "OK"}]
    v.deps = [{"name": n, "available_internally": False} for n in deps_missing_names]
    v.to_dict.return_value = {"passed": True, "steps": v.steps}
    return v


@pytest.fixture
def app_client():
    app = FastAPI()
    app.include_router(upload_mod.router)
    app.dependency_overrides[get_uploader_user] = lambda: "admin"
    return TestClient(app, raise_server_exceptions=False)


class TestUploadEndpointResolvesMissingDeps:
    def test_upload_triggers_auto_import_for_missing_deps(self, app_client):
        fake_manifest = {
            "name": "nmap", "version": "7.91", "arch": "amd64",
            "integrity": {"sha256": "deadbeef"},
        }
        fake_dep_result = {"status": "added", "name": "libc6", "message": "ajouté au repo"}

        with patch.object(upload_mod, "run_validation_pipeline", return_value=_fake_validation(["libc6"])), \
             patch.object(upload_mod, "_add_to_repo", return_value=True), \
             patch.object(upload_mod, "generate_manifest", return_value=fake_manifest), \
             patch.object(upload_mod, "save_manifest"), \
             patch.object(upload_mod, "add_to_index"), \
             patch("services.importer.import_one", return_value=fake_dep_result) as mock_import_one:

            resp = app_client.post(
                "/upload/",
                files={"file": ("nmap_7.91_amd64.deb", b"fake-deb-bytes", "application/octet-stream")},
                data={"distribution": "jammy"},
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "accepted"
        assert body["dependencies_resolved"] == [fake_dep_result]
        mock_import_one.assert_called_once_with({"name": "libc6"}, "jammy", "admin", "nmap")

    def test_upload_with_no_missing_deps_does_not_call_importer(self, app_client):
        fake_manifest = {
            "name": "curl", "version": "8.0", "arch": "amd64",
            "integrity": {"sha256": "cafebabe"},
        }
        with patch.object(upload_mod, "run_validation_pipeline", return_value=_fake_validation([])), \
             patch.object(upload_mod, "_add_to_repo", return_value=True), \
             patch.object(upload_mod, "generate_manifest", return_value=fake_manifest), \
             patch.object(upload_mod, "save_manifest"), \
             patch.object(upload_mod, "add_to_index"), \
             patch("services.importer.import_one") as mock_import_one:

            resp = app_client.post(
                "/upload/",
                files={"file": ("curl_8.0_amd64.deb", b"fake-deb-bytes", "application/octet-stream")},
                data={"distribution": "jammy"},
            )

        assert resp.status_code == 200, resp.text
        assert resp.json()["dependencies_resolved"] == []
        mock_import_one.assert_not_called()
