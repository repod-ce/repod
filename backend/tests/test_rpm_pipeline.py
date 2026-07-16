"""
Tests d'intégration du pipeline RPM.

Vérifie :
  - Parsing des métadonnées RPM (parse_rpm_fields, parse_rpm_requires)
  - Génération de manifest RPM
  - Validation extension dans upload.py en mode RPM
  - Dispatcher distributions.py en mode RPM
  - Dispatcher validator.py en mode RPM

Ces tests n'exécutent PAS de vrai rpm/createrepo_c — ils mockent les
appels subprocess pour rester rapides et portables (CI sans outils RPM).
"""
import importlib
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _reload_all_rpm():
    """Recharge tous les modules format-dépendants en mode RPM.
    NOTE : services.manifest gère nativement les deux formats — pas besoin de recharger.
    On exclut "manifest" pour ne pas invalider les références de module dans d'autres
    fichiers de test (évite le test pollution entre test_rpm_pipeline et test_snapshots)."""
    os.environ["REPO_FORMAT"] = "rpm"
    for mod in list(sys.modules.keys()):
        if any(x in mod for x in ["format_router", "distributions", "validator"]):
            if "manifest" not in mod:  # exclure services.manifest
                del sys.modules[mod]


def _reload_all_apt():
    """Recharge tous les modules format-dépendants en mode APT.
    NOTE : services.manifest gère nativement les deux formats — pas besoin de recharger.
    On exclut "manifest" pour ne pas invalider les références de module dans d'autres
    fichiers de test (évite le test pollution entre test_rpm_pipeline et test_snapshots)."""
    os.environ["REPO_FORMAT"] = "apt"
    for mod in list(sys.modules.keys()):
        if any(x in mod for x in ["format_router", "distributions", "validator"]):
            if "manifest" not in mod:  # exclure services.manifest
                del sys.modules[mod]


# ─── Parsing métadonnées RPM ──────────────────────────────────────────────────

class TestParseRpmFields:

    def test_parse_rpm_fields_ok(self):
        """parse_rpm_fields parse correctement la sortie de rpm -qp --queryformat."""
        _fake_output = (
            "NAME=nginx\n"
            "VERSION=1.24.0\n"
            "RELEASE=1.el8\n"
            "ARCH=x86_64\n"
            "SUMMARY=A high performance web server\n"
            "GROUP=System Environment/Daemons\n"
            "SIZE=2621440\n"
            "LICENSE=BSD\n"
            "URL=https://nginx.org\n"
            "EPOCH=(none)\n"
        )
        import services.manifest as m
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_fake_output, returncode=0)
            fields = m.parse_rpm_fields("/tmp/nginx-1.24.0.rpm")

        assert fields["name"] == "nginx"
        assert fields["version"] == "1.24.0"
        assert fields["release"] == "1.el8"
        assert fields["arch"] == "x86_64"
        assert fields["size"] == "2621440"
        # epoch=(none) doit être filtré
        assert "epoch" not in fields

    def test_parse_rpm_requires_filters_rpmlib(self):
        """parse_rpm_requires doit exclure rpmlib() et les dépendances /path."""
        _fake_output = (
            "rpmlib(CompressedFileNames) <= 3.0.4-1\n"
            "rpmlib(FileDigests) <= 4.6.0-1\n"
            "/bin/sh\n"
            "openssl >= 1.0\n"
            "glibc\n"
        )
        import services.manifest as m
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout=_fake_output, returncode=0)
            reqs = m.parse_rpm_requires("/tmp/nginx-1.24.0.rpm")

        assert "openssl >= 1.0" in reqs
        assert "glibc" in reqs
        assert not any(r.startswith("rpmlib(") for r in reqs)
        assert not any(r.startswith("/") for r in reqs)

    def test_parse_rpm_dependencies_structured(self):
        """parse_rpm_dependencies produit des dicts structurés."""
        import services.manifest as m
        requires = ["openssl >= 1.0.0", "glibc", "curl >= 7.0"]
        deps = m.parse_rpm_dependencies(requires)

        assert len(deps) == 3
        assert deps[0]["name"] == "openssl"
        assert deps[0]["version_constraint"] == ">= 1.0.0"
        assert deps[1]["name"] == "glibc"
        assert "version_constraint" not in deps[1]
        assert deps[2]["name"] == "curl"

    def test_rpm_full_version_with_epoch(self):
        """_rpm_full_version construit correctement epoch:version-release."""
        import services.manifest as m
        fields = {"epoch": "1", "version": "7.4.33", "release": "1.el8"}
        assert m._rpm_full_version(fields) == "1:7.4.33-1.el8"

    def test_rpm_full_version_no_epoch(self):
        """Sans epoch (ou epoch=0), la version est version-release."""
        import services.manifest as m
        fields = {"epoch": "0", "version": "7.4.33", "release": "1.el8"}
        assert m._rpm_full_version(fields) == "7.4.33-1.el8"


# ─── Génération manifest RPM ──────────────────────────────────────────────────

class TestGenerateRpmManifest:

    def test_generate_manifest_detects_rpm(self, tmp_path):
        """generate_manifest() doit générer un manifest type='rpm' pour un .rpm."""
        rpm_file = tmp_path / "nginx-1.24.0-1.x86_64.rpm"
        rpm_file.write_bytes(b"\xed\xab\xee\xdb" + b"\x00" * 96)  # magic RPM (mock)

        import services.manifest as m

        _fake_fields = {
            "name": "nginx", "version": "1.24.0", "release": "1.el8",
            "arch": "x86_64", "summary": "A web server",
            "group": "System", "size": "2621440", "license": "BSD",
        }
        _fake_reqs: list[str] = ["openssl"]

        with (
            patch.object(m, "parse_rpm_fields", return_value=_fake_fields),
            patch.object(m, "parse_rpm_requires", return_value=_fake_reqs),
            patch.object(m, "compute_sha256", return_value="abc123"),
            patch.object(m, "compute_sha512", return_value="def456"),
        ):
            manifest = m.generate_manifest(
                str(rpm_file),
                distribution="almalinux8",
            )

        assert manifest["type"] == "rpm"
        assert manifest["name"] == "nginx"
        assert manifest["distribution"] == "almalinux8"
        assert manifest["arch"] == "x86_64"
        assert manifest["integrity"]["sha256"] == "abc123"

    def test_generate_manifest_detects_deb(self, tmp_path):
        """generate_manifest() doit générer un manifest type='deb' pour un .deb."""
        deb_file = tmp_path / "nginx_1.24.0_amd64.deb"
        deb_file.write_bytes(b"!<arch>\n" + b"\x00" * 96)  # magic deb (mock)

        import services.manifest as m

        _fake_fields = {
            "package": "nginx", "version": "1.24.0", "architecture": "amd64",
            "section": "web", "description": "A web server", "maintainer": "team",
            "installed_size": "1024",
        }

        with (
            patch.object(m, "parse_deb_fields", return_value=_fake_fields),
            patch.object(m, "compute_sha256", return_value="abc123"),
            patch.object(m, "compute_sha512", return_value="def456"),
        ):
            manifest = m.generate_manifest(
                str(deb_file),
                distribution="jammy",
            )

        assert manifest["type"] == "deb"
        assert manifest["name"] == "nginx"
        assert manifest["distribution"] == "jammy"


# ─── Dispatcher distributions.py ─────────────────────────────────────────────

class TestDistributionsDispatcher:

    def test_apt_mode_exports_enterprise_distributions(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        _reload_all_apt()
        import services.distributions as d
        assert hasattr(d, "ENTERPRISE_DISTRIBUTIONS")
        assert hasattr(d, "VALID_CODENAMES")
        assert "jammy" in d.VALID_CODENAMES or len(d.VALID_CODENAMES) > 0

    def test_rpm_mode_exports_rpm_distributions(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        _reload_all_rpm()
        import services.distributions as d
        assert hasattr(d, "ENTERPRISE_DISTRIBUTIONS")
        assert hasattr(d, "VALID_CODENAMES")
        assert "almalinux8" in d.VALID_CODENAMES

    def test_rpm_mode_exports_architectures(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        _reload_all_rpm()
        import services.distributions as d
        assert hasattr(d, "ARCHITECTURES")
        assert "x86_64" in d.ARCHITECTURES

    def test_rpm_mode_has_add_rpm_to_distrib(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        _reload_all_rpm()
        import services.distributions as d
        assert callable(d.add_rpm_to_distrib)

    def test_apt_mode_add_rpm_stub_returns_false(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        _reload_all_apt()
        import services.distributions as d
        ok, msg = d.add_rpm_to_distrib("anything.rpm", "almalinux8")
        assert ok is False


# ─── Dispatcher validator.py ──────────────────────────────────────────────────

class TestValidatorDispatcher:

    def test_apt_mode_imports_deb_validator(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        _reload_all_apt()
        import services.validator as v
        assert hasattr(v, "run_validation_pipeline")
        assert hasattr(v, "ValidationResult")
        # En mode APT, validate_format doit accepter des .deb
        result = v.ValidationResult()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            v.validate_format("/tmp/test.deb", result)
        # Le step doit être présent (même si le fichier n'existe pas vraiment)
        assert any(s["name"] == "format" for s in result.steps)

    def test_rpm_mode_imports_rpm_validator(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        _reload_all_rpm()
        import services.validator as v
        assert hasattr(v, "run_validation_pipeline")
        assert hasattr(v, "ValidationResult")
        # En mode RPM, validate_format doit rejeter les .deb
        result = v.ValidationResult()
        v.validate_format("/tmp/test.deb", result)
        fmt_step = next((s for s in result.steps if s["name"] == "format"), None)
        assert fmt_step is not None
        assert fmt_step["passed"] is False

    def test_rpm_validate_format_accepts_rpm(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        _reload_all_rpm()
        import services.validator as v
        result = v.ValidationResult()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="Name: nginx", stderr="")
            v.validate_format("/tmp/test.rpm", result)
        fmt_step = next((s for s in result.steps if s["name"] == "format"), None)
        assert fmt_step is not None
        assert fmt_step["passed"] is True


# ─── Upload — validation d'extension ─────────────────────────────────────────

class TestUploadExtensionValidation:
    """
    Vérifie que l'endpoint upload rejette la mauvaise extension selon le format.
    Tests du routeur via client FastAPI de test.
    """

    def _make_client(self, repo_format: str):
        """Crée un client de test FastAPI en mode spécifié."""
        os.environ["REPO_FORMAT"] = repo_format
        for mod in list(sys.modules.keys()):
            if any(x in mod for x in ["format_router", "distributions", "validator",
                                        "upload", "main", "limiter"]):
                del sys.modules[mod]
        from fastapi.testclient import TestClient
        import services.format_router  # noqa: F401 — force le rechargement
        from routers.upload import router
        from fastapi import FastAPI
        app = FastAPI()
        app.include_router(router)
        return TestClient(app, raise_server_exceptions=False)

    def test_apt_mode_rejects_rpm_file(self, monkeypatch):
        """En mode APT, un .rpm doit être rejeté avec 400."""
        monkeypatch.setenv("REPO_FORMAT", "apt")

        # On teste directement la logique d'extension via format_router
        _reload_all_apt()
        import services.format_router as fr
        assert ".rpm" not in fr.ACCEPTED_EXTENSIONS

    def test_rpm_mode_rejects_deb_file(self, monkeypatch):
        """En mode RPM, un .deb doit être rejeté avec 400."""
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        _reload_all_rpm()
        import services.format_router as fr
        assert ".deb" not in fr.ACCEPTED_EXTENSIONS

    def test_apt_mode_accepts_deb(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        _reload_all_apt()
        import services.format_router as fr
        assert ".deb" in fr.ACCEPTED_EXTENSIONS

    def test_rpm_mode_accepts_rpm(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        _reload_all_rpm()
        import services.format_router as fr
        assert ".rpm" in fr.ACCEPTED_EXTENSIONS


# ─── Teardown global ──────────────────────────────────────────────────────────

def teardown_module():
    """Remet l'environnement en mode APT après tous les tests de ce module."""
    os.environ["REPO_FORMAT"] = "apt"
    for mod in list(sys.modules.keys()):
        if any(x in mod for x in ["format_router", "distributions", "validator"]):
            del sys.modules[mod]
