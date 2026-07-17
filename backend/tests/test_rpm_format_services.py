"""
Tests des services format-aware (dispatcher) — settings, package_index, importer, security_sync.

Couverture :
  TestSettingsSources         (8)  — sources APT/RPM dans settings.py
  TestPackageIndexDispatcher  (14) — dispatcher package_index selon REPO_FORMAT
  TestImporterDispatcher      (10) — dispatcher importer selon REPO_FORMAT
  TestSecuritySyncFormatAware (6)  — security_sync format-aware
  TestRpmPackageIndexCompat   (10) — fonctions de compatibilité RPM (get_sync_status, sync_all, is_indexed…)
"""
import importlib
import os
import sys
from unittest.mock import patch, MagicMock

import pytest


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _reload_module(dotted_name: str):
    """
    Force le rechargement des modules format-dépendants, sans toucher settings.
    services.settings est stable — ses fonctions (get_settings, update_settings)
    ne dépendent pas de REPO_FORMAT et ne doivent pas être réimportées.
    """
    for key in list(sys.modules.keys()):
        if any(x in key for x in ["format_router", "package_index", "importer",
                                    "security_sync"]):
            if "manifest" not in key and "settings" not in key:
                del sys.modules[key]
    return importlib.import_module(dotted_name)


# ═════════════════════════════════════════════════════════════════════════════
# 1. TestSettingsSources
# ═════════════════════════════════════════════════════════════════════════════

class TestSettingsSources:
    """Vérifie que settings.py expose les deux jeux de sources et que DEFAULT_SETTINGS
    utilise le bon jeu selon REPO_FORMAT."""

    def test_apt_sources_constant_exists(self):
        """_APT_SOURCES doit être défini et contenir les sources Ubuntu/Debian."""
        import services.settings as s
        assert hasattr(s, "_APT_SOURCES")
        assert isinstance(s._APT_SOURCES, dict)

    def test_rpm_sources_constant_exists(self):
        """_RPM_SOURCES doit être défini et contenir les sources RHEL/Fedora."""
        import services.settings as s
        assert hasattr(s, "_RPM_SOURCES")
        assert isinstance(s._RPM_SOURCES, dict)

    def test_apt_sources_contains_ubuntu_jammy(self):
        from services.settings import _APT_SOURCES
        assert "ubuntu-jammy" in _APT_SOURCES
        assert _APT_SOURCES["ubuntu-jammy"] is True

    def test_apt_sources_contains_debian_bookworm(self):
        from services.settings import _APT_SOURCES
        assert "debian-bookworm" in _APT_SOURCES

    def test_apt_sources_contains_security_sources(self):
        from services.settings import _APT_SOURCES
        assert "ubuntu-jammy-security" in _APT_SOURCES
        assert "debian-bookworm-security" in _APT_SOURCES

    def test_rpm_sources_contains_almalinux(self):
        from services.settings import _RPM_SOURCES
        assert "almalinux8-baseos" in _RPM_SOURCES
        assert "almalinux9-baseos" in _RPM_SOURCES
        assert _RPM_SOURCES["almalinux8-baseos"] is True

    def test_rpm_sources_contains_rocky_fedora_opensuse(self):
        from services.settings import _RPM_SOURCES
        assert "rocky8-baseos" in _RPM_SOURCES
        assert "fedora42" in _RPM_SOURCES
        assert "opensuse-leap-15.6-oss" in _RPM_SOURCES

    def test_no_cross_contamination(self):
        """Les sources APT ne doivent pas apparaître dans _RPM_SOURCES et vice-versa."""
        from services.settings import _APT_SOURCES, _RPM_SOURCES
        assert "ubuntu-jammy" not in _RPM_SOURCES
        assert "almalinux8-baseos" not in _APT_SOURCES

    def test_default_settings_apt_mode(self, monkeypatch):
        """
        En mode APT, _get_default_sources() doit retourner les sources Ubuntu.
        On teste via _get_default_sources() directement plutôt que de recharger
        le module (recharger settings polluerait les tests suivants).
        """
        monkeypatch.setenv("REPO_FORMAT", "apt")
        import services.settings as s
        sources = s._get_default_sources()
        assert "ubuntu-jammy" in sources
        assert "almalinux8-baseos" not in sources

    def test_default_settings_rpm_mode(self, monkeypatch):
        """
        En mode RPM, _get_default_sources() doit retourner les sources AlmaLinux.
        """
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        import services.settings as s
        sources = s._get_default_sources()
        assert "almalinux8-baseos" in sources
        assert "ubuntu-jammy" not in sources


# ═════════════════════════════════════════════════════════════════════════════
# 2. TestPackageIndexDispatcher
# ═════════════════════════════════════════════════════════════════════════════

class TestPackageIndexDispatcher:
    """Vérifie que package_index.py exporte l'implémentation correcte selon REPO_FORMAT."""

    def test_apt_mode_has_apt_sources(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        pi = _reload_module("services.package_index")
        # Les sources APT ont une clé "url" (Packages.gz)
        assert any("url" in s for s in pi.DEFAULT_SOURCES)
        # Les sources APT n'ont PAS de repomd_url
        assert not any("repomd_url" in s for s in pi.DEFAULT_SOURCES)

    def test_rpm_mode_has_rpm_sources(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        pi = _reload_module("services.package_index")
        # Les sources RPM ont une clé "repomd_url"
        assert any("repomd_url" in s for s in pi.DEFAULT_SOURCES)
        assert not any("url" in s and "repomd_url" not in s for s in pi.DEFAULT_SOURCES)

    def test_apt_mode_default_sources_are_ubuntu_debian(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        pi = _reload_module("services.package_index")
        ids = {s["id"] for s in pi.DEFAULT_SOURCES}
        assert "ubuntu-jammy" in ids
        assert "almalinux8-baseos" not in ids

    def test_rpm_mode_default_sources_are_almalinux(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        pi = _reload_module("services.package_index")
        ids = {s["id"] for s in pi.DEFAULT_SOURCES}
        assert "almalinux8-baseos" in ids
        assert "ubuntu-jammy" not in ids

    def test_both_modes_export_sync_source(self, monkeypatch):
        for fmt in ("apt", "rpm"):
            monkeypatch.setenv("REPO_FORMAT", fmt)
            pi = _reload_module("services.package_index")
            assert callable(pi.sync_source), f"sync_source manquant en mode {fmt}"

    def test_both_modes_export_sync_all(self, monkeypatch):
        for fmt in ("apt", "rpm"):
            monkeypatch.setenv("REPO_FORMAT", fmt)
            pi = _reload_module("services.package_index")
            assert callable(pi.sync_all), f"sync_all manquant en mode {fmt}"

    def test_both_modes_export_get_sync_status(self, monkeypatch):
        for fmt in ("apt", "rpm"):
            monkeypatch.setenv("REPO_FORMAT", fmt)
            pi = _reload_module("services.package_index")
            assert callable(pi.get_sync_status), f"get_sync_status manquant en mode {fmt}"

    def test_both_modes_export_search_packages(self, monkeypatch):
        for fmt in ("apt", "rpm"):
            monkeypatch.setenv("REPO_FORMAT", fmt)
            pi = _reload_module("services.package_index")
            assert callable(pi.search_packages), f"search_packages manquant en mode {fmt}"

    def test_both_modes_export_get_package_info(self, monkeypatch):
        for fmt in ("apt", "rpm"):
            monkeypatch.setenv("REPO_FORMAT", fmt)
            pi = _reload_module("services.package_index")
            assert callable(pi.get_package_info), f"get_package_info manquant en mode {fmt}"

    def test_both_modes_export_is_indexed(self, monkeypatch):
        for fmt in ("apt", "rpm"):
            monkeypatch.setenv("REPO_FORMAT", fmt)
            pi = _reload_module("services.package_index")
            assert callable(pi.is_indexed), f"is_indexed manquant en mode {fmt}"

    def test_both_modes_export_init_db(self, monkeypatch):
        for fmt in ("apt", "rpm"):
            monkeypatch.setenv("REPO_FORMAT", fmt)
            pi = _reload_module("services.package_index")
            assert callable(pi.init_db), f"init_db manquant en mode {fmt}"

    def test_both_modes_export_record_import_group(self, monkeypatch):
        """record_import_group doit être disponible dans les deux modes (stub en APT)."""
        for fmt in ("apt", "rpm"):
            monkeypatch.setenv("REPO_FORMAT", fmt)
            pi = _reload_module("services.package_index")
            assert callable(pi.record_import_group), f"record_import_group manquant en mode {fmt}"

    def test_apt_mode_record_import_group_is_noop(self, monkeypatch):
        """En mode APT, record_import_group est un no-op qui ne lève pas d'exception."""
        monkeypatch.setenv("REPO_FORMAT", "apt")
        pi = _reload_module("services.package_index")
        # Ne doit pas lever d'exception
        pi.record_import_group("test", [], "jammy", "user")

    def test_both_modes_export_get_sync_stats(self, monkeypatch):
        """get_sync_stats doit être disponible dans les deux modes."""
        for fmt in ("apt", "rpm"):
            monkeypatch.setenv("REPO_FORMAT", fmt)
            pi = _reload_module("services.package_index")
            assert callable(pi.get_sync_stats), f"get_sync_stats manquant en mode {fmt}"


# ═════════════════════════════════════════════════════════════════════════════
# 3. TestImporterDispatcher
# ═════════════════════════════════════════════════════════════════════════════

class TestImporterDispatcher:
    """Vérifie que importer.py exporte l'implémentation correcte selon REPO_FORMAT."""

    def test_apt_mode_exports_resolve_deps_online(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        imp = _reload_module("services.importer")
        assert callable(imp.resolve_deps_online)

    def test_rpm_mode_exports_resolve_deps_online(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        imp = _reload_module("services.importer")
        assert callable(imp.resolve_deps_online)

    def test_apt_mode_exports_import_package_stream(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        imp = _reload_module("services.importer")
        assert callable(imp.import_package_stream)

    def test_rpm_mode_exports_import_package_stream(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        imp = _reload_module("services.importer")
        assert callable(imp.import_package_stream)

    def test_rpm_importer_has_import_package(self, monkeypatch):
        """importer_rpm.py (implémentation) doit exposer import_package."""
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        import services.importer_rpm as imp_rpm
        assert callable(imp_rpm.import_package)

    def test_rpm_mode_resolve_deps_package_not_found(self, monkeypatch):
        """resolve_deps_online doit retourner success=False si le paquet est absent."""
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        imp = _reload_module("services.importer")
        # Mock services.indexer pour éviter l'import avec /repos inexistant
        mock_indexer = MagicMock()
        mock_indexer.get_package_info.return_value = None
        with patch.dict("sys.modules", {"services.indexer": mock_indexer}):
            with patch("services.package_index_rpm.get_package_info", return_value=None):
                with patch("services.package_index.get_package_info", return_value=None):
                    result = imp.resolve_deps_online("nginx-inexistant")
        assert result["success"] is False
        assert "introuvable" in result["error"]

    def test_apt_mode_resolve_deps_package_not_found(self, monkeypatch):
        """resolve_deps_online APT doit retourner success=False si le paquet est absent."""
        monkeypatch.setenv("REPO_FORMAT", "apt")
        imp = _reload_module("services.importer")
        # Mock services.indexer pour éviter l'import avec /repos inexistant
        mock_indexer = MagicMock()
        mock_indexer.get_package_info.return_value = None
        with patch.dict("sys.modules", {"services.indexer": mock_indexer}):
            with patch("services.package_index_apt.get_package_info", return_value=None):
                with patch("services.package_index.get_package_info", return_value=None):
                    result = imp.resolve_deps_online("nginx-inexistant")
        assert result["success"] is False

    def test_rpm_import_package_stream_is_generator(self, monkeypatch):
        """import_package_stream RPM doit retourner un générateur (itérable)."""
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        imp = _reload_module("services.importer")
        import types
        # On mock l'appel interne pour éviter tout effet de bord réseau
        with patch("services.importer_rpm.resolve_deps_online", return_value={
            "success": False,
            "error": "Mock — aucun index",
            "packages": [],
        }):
            gen = imp.import_package_stream("nginx", "tester")
            assert isinstance(gen, types.GeneratorType)
            # Premier message doit être un SSE data:
            first = next(gen)
            assert first.startswith("data:")

    def test_rpm_import_package_stream_emits_error_on_no_index(self, monkeypatch):
        """Si le paquet est absent de l'index, le stream émet une erreur."""
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        imp = _reload_module("services.importer")
        with patch("services.importer_rpm.resolve_deps_online", return_value={
            "success": False,
            "error": "Paquet introuvable",
            "packages": [],
        }):
            messages = list(imp.import_package_stream("nginx-inexistant", "ci"))
        error_msgs = [m for m in messages if "error|" in m]
        assert error_msgs, "Aucun message d'erreur émis"
        assert "introuvable" in " ".join(error_msgs)

    def test_apt_import_package_stream_emits_sse(self, monkeypatch):
        """import_package_stream APT doit émettre des SSE (data:...)."""
        monkeypatch.setenv("REPO_FORMAT", "apt")
        imp = _reload_module("services.importer")
        # Mock services.indexer + package_index pour éviter les appels réseau/disque
        mock_indexer = MagicMock()
        mock_indexer.get_package_info.return_value = None
        mock_indexer.add_to_index.return_value = None
        with patch.dict("sys.modules", {"services.indexer": mock_indexer}):
            # Le paquet est absent de l'index → le stream émet une erreur, pas d'exception
            with patch("services.package_index_apt.get_package_info", return_value=None):
                gen = imp.import_package_stream("curl-inexistant", "tester")
                import types
                assert isinstance(gen, types.GeneratorType)
                first = next(gen)
                assert first.startswith("data:")


# ═════════════════════════════════════════════════════════════════════════════
# 4. TestSecuritySyncFormatAware
# ═════════════════════════════════════════════════════════════════════════════

class TestSecuritySyncFormatAware:
    """Vérifie que security_sync utilise les bonnes sources selon REPO_FORMAT."""

    def test_apt_mode_security_sources_are_ubuntu(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        _reload_module("services.package_index")
        ss = _reload_module("services.security_sync")
        ids = {s["id"] for s in ss.ALL_SECURITY_SOURCES}
        assert any("ubuntu" in sid or "debian" in sid for sid in ids), (
            f"Sources de sécurité APT non trouvées : {ids}"
        )

    def test_rpm_mode_security_sources_are_rpm_distros(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        _reload_module("services.package_index")
        ss = _reload_module("services.security_sync")
        ids = {s["id"] for s in ss.ALL_SECURITY_SOURCES}
        # AlmaLinux, Rocky, Oracle ont des updateinfo.xml.gz
        rpm_security = {"almalinux8-baseos", "almalinux8-appstream", "rocky8-baseos"}
        assert rpm_security & ids, (
            f"Aucune source RPM avec security=True trouvée : {ids}"
        )

    def test_apt_mode_no_rpm_sources_in_security(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        _reload_module("services.package_index")
        ss = _reload_module("services.security_sync")
        ids = {s["id"] for s in ss.ALL_SECURITY_SOURCES}
        assert "almalinux8-baseos" not in ids

    def test_rpm_mode_no_apt_sources_in_security(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "rpm")
        _reload_module("services.package_index")
        ss = _reload_module("services.security_sync")
        ids = {s["id"] for s in ss.ALL_SECURITY_SOURCES}
        assert "ubuntu-jammy-security" not in ids

    def test_security_sync_exports_security_sources(self, monkeypatch):
        """SECURITY_SOURCES doit être exposé pour import_router."""
        monkeypatch.setenv("REPO_FORMAT", "apt")
        _reload_module("services.package_index")
        ss = _reload_module("services.security_sync")
        assert hasattr(ss, "SECURITY_SOURCES")
        assert isinstance(ss.SECURITY_SOURCES, list)

    def test_security_sync_exports_run_security_sync(self, monkeypatch):
        monkeypatch.setenv("REPO_FORMAT", "apt")
        _reload_module("services.package_index")
        ss = _reload_module("services.security_sync")
        assert callable(ss.run_security_sync)


# ═════════════════════════════════════════════════════════════════════════════
# 5. TestRpmPackageIndexCompat
# ═════════════════════════════════════════════════════════════════════════════

class TestRpmPackageIndexCompat:
    """
    Vérifie les fonctions de compatibilité dans package_index_rpm.py :
    get_sync_status, sync_all, is_indexed, search_packages, get_package_info,
    record_import_group / get_import_groups.
    Utilise db_test_engine (SQLite in-memory) depuis conftest — pas de DB_PATH.
    """

    @pytest.fixture(autouse=True)
    def clean_rpm_tables(self, db_test_engine):
        """Vide les tables RPM avant/après chaque test."""
        from sqlalchemy import text as _t

        def _wipe():
            with db_test_engine.begin() as conn:
                conn.execute(_t("DELETE FROM packages"))
                conn.execute(_t("DELETE FROM sync_status"))
                conn.execute(_t("DELETE FROM sync_log"))
                conn.execute(_t("DELETE FROM import_groups"))
                conn.execute(_t("DELETE FROM import_group_files"))

        _wipe()
        yield
        _wipe()

    def test_get_sync_status_returns_list(self):
        """get_sync_status() doit retourner une liste même sans synchronisation."""
        import services.package_index_rpm as rpm
        result = rpm.get_sync_status()
        assert isinstance(result, list)
        assert len(result) == len(rpm.DEFAULT_SOURCES)

    def test_get_sync_status_has_source_id(self):
        """get_sync_status() doit retourner source_id."""
        import services.package_index_rpm as rpm
        result = rpm.get_sync_status()
        for entry in result:
            assert "source_id" in entry, "Clé 'source_id' manquante"

    def test_get_sync_status_never_status_by_default(self):
        """Sans synchronisation, status doit être 'never'."""
        import services.package_index_rpm as rpm
        result = rpm.get_sync_status()
        assert all(e["status"] == "never" for e in result), (
            "Statut inattendu sans synchronisation"
        )

    def test_is_indexed_false_on_empty_db(self):
        """is_indexed() doit retourner False sur une table vide."""
        import services.package_index_rpm as rpm
        assert rpm.is_indexed() is False

    def test_is_indexed_true_after_insert(self, db_test_engine):
        """is_indexed() doit retourner True après insertion d'un paquet."""
        from sqlalchemy import text as _t
        with db_test_engine.begin() as conn:
            conn.execute(_t(
                "INSERT INTO packages (source_id, name, version, arch, synced_at) "
                "VALUES ('almalinux8-baseos', 'nginx', '1.24.0-1.el8', 'x86_64', '2026-01-01T00:00:00Z')"
            ))
        import services.package_index_rpm as rpm
        assert rpm.is_indexed() is True

    def test_sync_all_calls_sync_source(self):
        """sync_all() doit appeler sync_source() pour chaque source DEFAULT_SOURCES."""
        import services.package_index_rpm as rpm
        with patch.object(rpm, "sync_source") as mock_sync:
            mock_sync.return_value = {"source_id": "test", "status": "ok", "pkg_count": 0}
            results = rpm.sync_all()
        assert mock_sync.call_count == len(rpm.DEFAULT_SOURCES)
        assert len(results) == len(rpm.DEFAULT_SOURCES)

    def test_get_sync_stats_same_as_get_sync_status(self):
        """get_sync_stats() et get_sync_status() doivent retourner les mêmes données."""
        import services.package_index_rpm as rpm
        stats = rpm.get_sync_stats()
        status = rpm.get_sync_status()
        assert len(stats) == len(status)
        stats_ids = {e["source_id"] for e in stats}
        status_ids = {e["source_id"] for e in status}
        assert stats_ids == status_ids

    def test_search_packages_returns_empty_on_empty_db(self):
        """search_packages() doit retourner [] sur une table vide."""
        import services.package_index_rpm as rpm
        assert rpm.search_packages("nginx") == []

    def test_get_package_info_returns_none_on_empty_db(self):
        """get_package_info() doit retourner None si le paquet est absent."""
        import services.package_index_rpm as rpm
        assert rpm.get_package_info("nginx") is None

    def test_record_and_get_import_group(self):
        """record_import_group + get_import_groups doit fonctionner de bout en bout."""
        import services.package_index_rpm as rpm
        rpm.record_import_group(
            name="nginx-group",
            files=[{"filename": "nginx-1.24.rpm", "size_bytes": 1234567}],
            distribution="almalinux8",
            imported_by="ci",
        )
        groups = rpm.get_import_groups()
        assert len(groups) == 1
        assert groups[0]["name"] == "nginx-group"
        assert groups[0]["package_count"] == 1


# ═════════════════════════════════════════════════════════════════════════════
# Teardown global
# ═════════════════════════════════════════════════════════════════════════════

def teardown_module():
    """
    Remettre l'environnement en mode APT après tous les tests.

    NOTE : services.settings n'est PAS rechargé ici — c'est un module stable
    qui ne dépend pas de REPO_FORMAT au moment de l'exécution (ses fonctions
    get_settings/update_settings fonctionnent indépendamment du format).
    Le supprimer de sys.modules créerait une re-importation qui interfèrerait
    avec les tests suivants (test pollution via PermissionError sur /repos).
    """
    os.environ["REPO_FORMAT"] = "apt"
    for k in list(sys.modules.keys()):
        if any(x in k for x in ["format_router", "package_index", "importer",
                                  "security_sync"]):
            if "manifest" not in k and "settings" not in k:
                del sys.modules[k]
