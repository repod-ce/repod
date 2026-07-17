# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_importer_apk_transitive_deps.py
Rôle   : services/importer_apk.py:resolve_deps_online() — comme pour RPM
         (voir test_importer_rpm_transitive_deps.py), la résolution ne
         couvrait auparavant que les dépendances directes. De plus, Alpine
         exprime la quasi-totalité de ses dépendances de bibliothèques via
         des capabilities (so:/cmd:/pc:) plutôt que des noms de paquets —
         l'ancien code les filtrait purement et simplement, ce qui faisait
         disparaître la majorité des dépendances réelles avant même le
         niveau 1. Ces tests couvrent : la résolution transitive, la
         résolution so:/cmd:/pc: via la nouvelle
         package_index_apk.resolve_provide_to_package(), et le suivi des
         tokens non résolus.

Dépend : pytest, unittest.mock.patch — aucune base de données réelle.
"""
from unittest.mock import patch

# Graphe de paquets factice :
#   webapp   --depends-->  so:libssl.so.3, cmd:bash
#   libssl3  --depends-->  so:libc.musl-x86_64.so.1   --provides--> so:libssl.so.3=3
#   bash     --depends-->  (rien)                      --provides--> cmd:bash=5.2
#   musl     --depends-->  (rien)                      --provides--> so:libc.musl-x86_64.so.1=1
_FAKE_DB = {
    "webapp":  {"name": "webapp", "version": "1.0", "depends": "so:libssl.so.3 cmd:bash", "provides": None},
    "libssl3": {"name": "libssl3", "version": "3.0", "depends": "so:libc.musl-x86_64.so.1", "provides": "so:libssl.so.3=3"},
    "bash":    {"name": "bash", "version": "5.2", "depends": None, "provides": "cmd:bash=5.2"},
    "musl":    {"name": "musl", "version": "1.2", "depends": None, "provides": "so:libc.musl-x86_64.so.1=1"},
}


def _fake_get_package_info(name, source_id=None):
    row = _FAKE_DB.get(name)
    return dict(row) if row else None


def _fake_resolve_provide_to_package(token, source_id=None):
    """Reproduit le LIKE '%token%' de la vraie requête SQL (package_index_apk.py)
    — la colonne provides porte des suffixes de version (so:libssl.so.3=3),
    donc le matching doit être par sous-chaîne, pas par égalité exacte."""
    for row in _FAKE_DB.values():
        if row.get("provides") and token in row["provides"]:
            return dict(row)
    return None


def _fake_get_package_info_apk(pkg_name, distro=None):
    row = _FAKE_DB.get(pkg_name)
    return (dict(row), None) if row else (None, None)


def _patched():
    return (
        patch("services.importer_apk._get_package_info_apk", side_effect=_fake_get_package_info_apk),
        patch("services.package_index_apk.get_package_info", side_effect=_fake_get_package_info),
        patch("services.package_index_apk.resolve_provide_to_package", side_effect=_fake_resolve_provide_to_package),
    )


class TestResolveDepsTransitive:

    def test_soname_capability_resolved_to_real_package(self):
        """'so:libssl.so.3' n'est pas un nom de paquet — doit être résolu
        vers 'libssl3' via la colonne Provides, pas filtré/abandonné."""
        import services.importer_apk as imp

        p1, p2, p3 = _patched()
        with p1, p2, p3:
            result = imp.resolve_deps_online("webapp")

        names = {p["name"] for p in result["packages"]}
        assert "libssl3" in names, "capability so: non résolue vers son paquet fournisseur"
        assert "bash" in names, "capability cmd: non résolue vers son paquet fournisseur"

    def test_resolves_second_level_dependency(self):
        """musl est une dépendance de libssl3 (niveau 2, via une autre
        capability so:) — doit être incluse malgré deux résolutions
        Provides successives."""
        import services.importer_apk as imp

        p1, p2, p3 = _patched()
        with p1, p2, p3:
            result = imp.resolve_deps_online("webapp")

        names = {p["name"] for p in result["packages"]}
        assert "musl" in names, "dépendance de dépendance manquante — résolution non transitive"

    def test_unresolved_capability_tracked_not_silently_dropped(self):
        """Une capability qui ne correspond à aucun Provides connu doit
        apparaître dans 'unresolved' plutôt que de disparaître sans trace."""
        import services.importer_apk as imp

        db = dict(_FAKE_DB)
        db["webapp"] = {"name": "webapp", "version": "1.0",
                         "depends": "so:libssl.so.3 so:libghost.so.1", "provides": None}

        with patch("services.importer_apk._get_package_info_apk",
                   side_effect=lambda n, distro=None: (dict(db[n]), None) if n in db else (None, None)), \
             patch("services.package_index_apk.get_package_info",
                   side_effect=lambda n, source_id=None: dict(db[n]) if n in db else None), \
             patch("services.package_index_apk.resolve_provide_to_package",
                   side_effect=_fake_resolve_provide_to_package):
            result = imp.resolve_deps_online("webapp")

        assert "so:libghost.so.1" in result["unresolved"]
        assert "libghost" not in {p["name"] for p in result["packages"]}

    def test_absolute_path_dependency_is_not_resolved(self):
        """Un token de type chemin absolu (/bin/sh) reste non résolu — pas
        de tentative de le traiter comme un nom de paquet ou une capability."""
        import services.importer_apk as imp

        db = dict(_FAKE_DB)
        db["webapp"] = {"name": "webapp", "version": "1.0", "depends": "/bin/sh", "provides": None}

        with patch("services.importer_apk._get_package_info_apk",
                   side_effect=lambda n, distro=None: (dict(db[n]), None) if n in db else (None, None)), \
             patch("services.package_index_apk.get_package_info",
                   side_effect=lambda n, source_id=None: dict(db[n]) if n in db else None), \
             patch("services.package_index_apk.resolve_provide_to_package", return_value=None):
            result = imp.resolve_deps_online("webapp")

        assert result["packages"] == []

    def test_conflict_marker_excluded(self):
        """Un token préfixé '!' exprime un conflit, pas une dépendance —
        ne doit jamais être résolu ni compté."""
        import services.importer_apk as imp

        db = dict(_FAKE_DB)
        db["webapp"] = {"name": "webapp", "version": "1.0", "depends": "!conflicting-pkg", "provides": None}

        with patch("services.importer_apk._get_package_info_apk",
                   side_effect=lambda n, distro=None: (dict(db[n]), None) if n in db else (None, None)), \
             patch("services.package_index_apk.get_package_info", return_value=None), \
             patch("services.package_index_apk.resolve_provide_to_package", return_value=None):
            result = imp.resolve_deps_online("webapp")

        assert result["packages"] == []
        assert result["unresolved"] == []

    def test_package_not_in_index_returns_failure(self):
        import services.importer_apk as imp

        with patch("services.importer_apk._get_package_info_apk", return_value=(None, None)):
            result = imp.resolve_deps_online("nginx-inexistant")

        assert result["success"] is False
        assert "introuvable" in result["error"]

    def test_max_depth_bounds_the_walk(self):
        chain_db = {}
        for i in range(15):
            chain_db[f"pkg{i}"] = {"name": f"pkg{i}", "version": "1", "depends": f"pkg{i+1}", "provides": None}
        chain_db["pkg15"] = {"name": "pkg15", "version": "1", "depends": None, "provides": None}

        import services.importer_apk as imp

        with patch("services.importer_apk._get_package_info_apk",
                   side_effect=lambda n, distro=None: (dict(chain_db[n]), None) if n in chain_db else (None, None)), \
             patch("services.package_index_apk.get_package_info",
                   side_effect=lambda n, source_id=None: dict(chain_db[n]) if n in chain_db else None), \
             patch("services.package_index_apk.resolve_provide_to_package",
                   side_effect=lambda t, source_id=None: dict(chain_db[t]) if t in chain_db else None):
            result = imp.resolve_deps_online("pkg0", max_depth=3)

        names = {p["name"] for p in result["packages"]}
        assert "pkg1" in names and "pkg3" in names
        assert "pkg10" not in names


class TestResolveProvideToPackage:
    """package_index_apk.py:resolve_provide_to_package() — nouvelle fonction,
    absente auparavant (contrairement à son équivalent RPM déjà existant)."""

    def test_matches_provides_column(self, db_test_engine):
        from sqlalchemy import text

        from db.engine import db_conn

        with db_conn() as conn:
            conn.execute(text("""
                INSERT INTO apk_packages
                (source_id, name, version, arch, distro, synced_at, provides)
                VALUES (:sid, :name, :version, 'x86_64', 'alpine3.21', :now, :provides)
            """), {
                "sid": "alpine3.21-main", "name": "libssl3", "version": "3.0",
                "now": "2026-01-01T00:00:00+00:00", "provides": "so:libssl.so.3=3",
            })

        from services.package_index_apk import resolve_provide_to_package
        row = resolve_provide_to_package("so:libssl.so.3")
        assert row is not None
        assert row["name"] == "libssl3"

    def test_no_match_returns_none(self, db_test_engine):
        from services.package_index_apk import resolve_provide_to_package
        assert resolve_provide_to_package("so:does-not-exist.so.1") is None
