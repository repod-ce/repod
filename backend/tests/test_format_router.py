"""
Tests unitaires pour services/format_router.py

Ces tests vérifient la détection du format, la validation des valeurs,
et les constantes dérivées (ACCEPTED_EXTENSIONS, FORMAT_LABEL, etc.).
"""
import importlib
import os
import sys
import pytest


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _reload_format_router(repo_format: str):
    """
    Recharge format_router avec une valeur REPO_FORMAT différente.
    Nécessaire car le module est évalué à l'import.
    """
    os.environ["REPO_FORMAT"] = repo_format
    # Supprimer les modules qui dépendent de format_router pour forcer le rechargement
    for mod in list(sys.modules.keys()):
        if "format_router" in mod or "distributions" in mod or "validator" in mod:
            del sys.modules[mod]
    return importlib.import_module("services.format_router")


# ─── Tests de détection du format ─────────────────────────────────────────────

class TestFormatDetection:

    def test_default_is_apt(self, monkeypatch):
        monkeypatch.delenv("REPO_FORMAT", raising=False)
        fr = _reload_format_router("apt")
        assert fr.REPO_FORMAT == "apt"
        assert fr.is_apt() is True
        assert fr.is_rpm() is False

    def test_explicit_apt(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        fr = _reload_format_router("apt")
        assert fr.REPO_FORMAT == "apt"
        assert fr.is_apt() is True
        assert fr.is_rpm() is False

    def test_explicit_rpm(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        fr = _reload_format_router("rpm")
        assert fr.REPO_FORMAT == "rpm"
        assert fr.is_rpm() is True
        assert fr.is_apt() is False

    def test_case_insensitive(self, monkeypatch):
        """REPO_FORMAT=RPM doit être normalisé en minuscule."""
        monkeypatch.setenv("REPO_FORMAT", "RPM")
        fr = _reload_format_router("rpm")
        assert fr.REPO_FORMAT == "rpm"

    def test_invalid_value_falls_back_to_apt(self, monkeypatch):
        """Une valeur invalide doit être rejetée et remplacée par 'apt'."""
        monkeypatch.setenv("REPO_FORMAT", "yum")
        fr = _reload_format_router("yum")
        assert fr.REPO_FORMAT == "apt"
        assert fr.is_apt() is True

    def test_empty_value_falls_back_to_apt(self, monkeypatch):
        """Une valeur vide doit être rejetée et remplacée par 'apt'."""
        monkeypatch.setenv("REPO_FORMAT", "")
        fr = _reload_format_router("")
        assert fr.REPO_FORMAT == "apt"


# ─── Tests des constantes dérivées ────────────────────────────────────────────

class TestDerivedConstants:

    def test_apt_accepted_extensions(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        fr = _reload_format_router("apt")
        assert ".deb" in fr.ACCEPTED_EXTENSIONS
        assert ".rpm" not in fr.ACCEPTED_EXTENSIONS

    def test_rpm_accepted_extensions(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        fr = _reload_format_router("rpm")
        assert ".rpm" in fr.ACCEPTED_EXTENSIONS
        assert ".deb" not in fr.ACCEPTED_EXTENSIONS

    def test_apt_labels(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        fr = _reload_format_router("apt")
        assert "apt" in fr.FORMAT_LABEL.lower() or "deb" in fr.FORMAT_LABEL.lower()
        assert fr.REPO_TOOL_LABEL == "reprepro"
        assert fr.DEFAULT_DISTRIBUTION == "jammy"

    def test_rpm_labels(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        fr = _reload_format_router("rpm")
        assert "rpm" in fr.FORMAT_LABEL.lower()
        assert fr.REPO_TOOL_LABEL == "createrepo_c"
        assert fr.DEFAULT_DISTRIBUTION == "almalinux8"


# ─── Teardown ─────────────────────────────────────────────────────────────────

def teardown_module():
    """Remet l'environnement en mode APT après les tests."""
    os.environ["REPO_FORMAT"] = "apt"
    for mod in list(sys.modules.keys()):
        if "format_router" in mod:
            del sys.modules[mod]
