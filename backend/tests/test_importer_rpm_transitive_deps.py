# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_importer_rpm_transitive_deps.py
Rôle   : services/importer_rpm.py:resolve_deps_online() — la résolution ne se
         limitait auparavant qu'aux dépendances directes (Requires de niveau
         1), contrairement à importer_apt.py qui fait une vraie résolution
         transitive. Ces tests couvrent la réécriture qui aligne le
         comportement RPM sur celui de l'APT : parcours en largeur (BFS)
         jusqu'à plusieurs niveaux, résolution des Requires "virtuels" (noms
         de capability plutôt que noms de paquets réels) via Provides, et
         suivi explicite des tokens non résolus (au lieu d'être simplement
         abandonnés sans trace).

Dépend : pytest, unittest.mock.patch — aucune base de données réelle, tout
         est mocké au niveau de services.package_index_rpm/services.indexer
         (mêmes points d'entrée que le code de production).
"""
from unittest.mock import patch

# Graphe de paquets factice :
#   webapp  --requires-->  libfoo, webserver (virtuel), libc.so.6(...)(64bit) (capability, filtrée)
#   libfoo  --requires-->  libbar
#   libbar  --requires-->  (rien)
#   httpd   --provides-->  webserver  (fournisseur réel du Requires virtuel "webserver")
_FAKE_DB = {
    "webapp": {"name": "webapp", "requires": "libfoo, webserver, libc.so.6(GLIBC_2.34)(64bit)"},
    "libfoo": {"name": "libfoo", "requires": "libbar"},
    "libbar": {"name": "libbar", "requires": None},
    "httpd":  {"name": "httpd", "requires": None},
}
_PROVIDES = {"webserver": "httpd"}


def _fake_get_package_info(name, source_id=None, source_prefix=None):
    row = _FAKE_DB.get(name)
    return dict(row) if row else None


def _fake_resolve_provide_to_package(provide):
    if provide in _FAKE_DB:
        return dict(_FAKE_DB[provide])
    real = _PROVIDES.get(provide)
    return dict(_FAKE_DB[real]) if real else None


def _patched():
    """Contexte commun : index RPM mocké, rien n'est déjà dans le repo interne."""
    return (
        patch("services.package_index_rpm.get_package_info", side_effect=_fake_get_package_info),
        patch("services.package_index_rpm.resolve_provide_to_package", side_effect=_fake_resolve_provide_to_package),
        patch("services.indexer.get_package_info", return_value=None),
    )


class TestResolveDepsTransitive:

    def test_resolves_second_level_dependency(self):
        """libbar est une dépendance de libfoo (niveau 2) — doit être incluse,
        pas seulement les Requires directs de webapp (niveau 1)."""
        import services.importer_rpm as imp

        with _patched()[0], _patched()[1], _patched()[2]:
            result = imp.resolve_deps_online("webapp")

        names = {p["name"] for p in result["packages"]}
        assert "libfoo" in names
        assert "libbar" in names, "dépendance de dépendance manquante — résolution non transitive"

    def test_virtual_requires_resolved_via_provides(self):
        """'webserver' est un Requires virtuel — doit être résolu vers 'httpd'
        (le paquet réel qui le fournit), pas laissé tel quel ni abandonné."""
        import services.importer_rpm as imp

        with _patched()[0], _patched()[1], _patched()[2]:
            result = imp.resolve_deps_online("webapp")

        names = {p["name"] for p in result["packages"]}
        assert "httpd" in names
        assert "webserver" not in names  # le nom virtuel lui-même n'est jamais un nom de paquet à télécharger
        httpd_entry = next(p for p in result["packages"] if p["name"] == "httpd")
        assert httpd_entry.get("virtual") == "webserver"

    def test_capability_syntax_never_treated_as_package_name(self):
        """Un Requires du type 'libc.so.6(GLIBC_2.34)(64bit)' (parenthèses)
        ne doit jamais être traité comme un nom de paquet candidat — ni
        apparaître dans packages, ni dans unresolved (filtré en amont,
        comportement hérité intentionnellement conservé)."""
        import services.importer_rpm as imp

        with _patched()[0], _patched()[1], _patched()[2]:
            result = imp.resolve_deps_online("webapp")

        all_tokens = {p["name"] for p in result["packages"]} | set(result.get("unresolved", []))
        assert not any("(" in t for t in all_tokens)

    def test_unresolved_capability_tracked_not_silently_dropped(self):
        """Un Requires qui ne résout vers aucun paquet réel (ni nom direct,
        ni Provides) doit apparaître dans 'unresolved' plutôt que de
        disparaître sans trace du résultat final."""
        import services.importer_rpm as imp

        db = dict(_FAKE_DB)
        db["webapp"] = {"name": "webapp", "requires": "libfoo, ghost-package"}

        with patch("services.package_index_rpm.get_package_info",
                   side_effect=lambda n, **kw: dict(db[n]) if n in db else None), \
             patch("services.package_index_rpm.resolve_provide_to_package",
                   side_effect=lambda p: dict(db[p]) if p in db else None), \
             patch("services.indexer.get_package_info", return_value=None):
            result = imp.resolve_deps_online("webapp")

        assert "ghost-package" in result["unresolved"]
        assert "ghost-package" not in {p["name"] for p in result["packages"]}

    def test_package_not_in_index_returns_failure(self):
        import services.importer_rpm as imp

        with patch("services.package_index_rpm.get_package_info", return_value=None):
            result = imp.resolve_deps_online("nginx-inexistant")

        assert result["success"] is False
        assert "introuvable" in result["error"]

    def test_already_in_repo_is_reflected_per_package(self):
        """repo_get_info() (services.indexer) décide, paquet par paquet, ce
        qui est déjà présent — pas un simple booléen global."""
        import services.importer_rpm as imp

        def fake_repo_get_info(name):
            return {"name": name} if name == "libbar" else None

        with _patched()[0], _patched()[1], \
             patch("services.indexer.get_package_info", side_effect=fake_repo_get_info):
            result = imp.resolve_deps_online("webapp")

        by_name = {p["name"]: p for p in result["packages"]}
        assert by_name["libbar"]["already_in_repo"] is True
        assert by_name["libfoo"]["already_in_repo"] is False

    def test_max_depth_bounds_the_walk(self):
        """Une chaîne de dépendances plus longue que max_depth doit être
        tronquée plutôt que de boucler indéfiniment ou planter."""
        import services.importer_rpm as imp

        chain_db = {}
        for i in range(15):
            chain_db[f"pkg{i}"] = {"name": f"pkg{i}", "requires": f"pkg{i+1}"}
        chain_db["pkg15"] = {"name": "pkg15", "requires": None}

        with patch("services.package_index_rpm.get_package_info",
                   side_effect=lambda n, **kw: dict(chain_db[n]) if n in chain_db else None), \
             patch("services.package_index_rpm.resolve_provide_to_package",
                   side_effect=lambda p: dict(chain_db[p]) if p in chain_db else None), \
             patch("services.indexer.get_package_info", return_value=None):
            result = imp.resolve_deps_online("pkg0", max_depth=3)

        names = {p["name"] for p in result["packages"]}
        assert "pkg1" in names and "pkg3" in names
        assert "pkg10" not in names  # bien au-delà de max_depth=3


class TestImportPackageReusesDepsInfo:
    """import_package_stream() calcule deps_info une fois pour l'affichage
    puis le transmet à import_package() — la résolution transitive (plus
    coûteuse que l'ancienne résolution niveau-1) ne doit pas être refaite."""

    def test_import_package_accepts_precomputed_deps_info(self):
        import services.importer_rpm as imp

        deps_info = {
            "success": True, "package": "webapp",
            "total_deps": 0, "already_in_repo": 0, "to_download": 0,
            "packages": [], "unresolved": [],
        }

        with patch.object(imp, "resolve_deps_online") as mock_resolve:
            result = imp.import_package("webapp", "almalinux9", deps_info=deps_info)

        mock_resolve.assert_not_called()
        assert result["success"] is True
        assert result["message"] == "Tous les paquets sont déjà présents dans le repo"

    def test_import_package_computes_deps_info_when_not_provided(self):
        import services.importer_rpm as imp

        deps_info = {
            "success": True, "package": "webapp",
            "total_deps": 0, "already_in_repo": 0, "to_download": 0,
            "packages": [], "unresolved": [],
        }

        with patch.object(imp, "resolve_deps_online", return_value=deps_info) as mock_resolve:
            imp.import_package("webapp", "almalinux9")

        mock_resolve.assert_called_once_with("webapp", distro="almalinux9")


class TestDistroScopedResolution:
    """
    Régression : resolve_deps_online() acceptait un `distro` avalé par
    **_kwargs sans jamais s'en servir — ni pour le lookup racine
    (_rpm_get_info(package_name), sans source_prefix, contrairement à
    _download_rpm() dans le même fichier), ni pour la résolution des
    capabilities (resolve_provide_to_package(token), sans source_prefix
    non plus). Quand le même nom de paquet existe dans plusieurs distros
    indexées (ex. AlmaLinux 9 ET openSUSE Tumbleweed), la résolution
    transitive pouvait silencieusement partir de la mauvaise ligne — même
    bug que celui déjà corrigé côté APT ("prometheus" Fedora vs Ubuntu),
    un niveau plus profond (BFS + capabilities).

    Utilise la vraie base de test (db_test_engine, SQLite in-memory,
    autouse) plutôt que des mocks, pour exercer le SQL réel de
    get_package_info()/resolve_provide_to_package() avec `source_prefix`.
    """

    def _insert(self, conn, source_id, distro, name, version, requires="", provides="", synced_at=None):
        from datetime import datetime, timezone

        from sqlalchemy import text
        conn.execute(text("""
            INSERT INTO packages (source_id, name, version, arch, requires, provides, distro, synced_at)
            VALUES (:source_id, :name, :version, 'x86_64', :requires, :provides, :distro, :synced_at)
        """), {
            "source_id": source_id, "name": name, "version": version,
            "requires": requires, "provides": provides, "distro": distro,
            "synced_at": synced_at or datetime.now(timezone.utc).isoformat(),
        })

    def _seed_same_name_different_distros(self, conn):
        # Même nom "prometheus" publié dans deux distros RPM distinctes,
        # chacune requérant une dépendance directe différente. La ligne
        # openSUSE est délibérément insérée avec un synced_at PLUS RÉCENT
        # que la ligne AlmaLinux : get_package_info() trie par
        # "synced_at DESC" en dernier recours, donc un lookup non scopé
        # (le bug) retournerait systématiquement la ligne openSUSE quelle
        # que soit la distro demandée.
        from datetime import datetime, timedelta, timezone
        older = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        newer = datetime.now(timezone.utc).isoformat()

        self._insert(conn, "almalinux9-baseos", "almalinux9", "prometheus", "2.45-1.el9",
                      requires="glibc-almalinux", synced_at=older)
        self._insert(conn, "opensuse-tumbleweed-oss", "opensuse-tumbleweed", "prometheus", "3.0-1.suse",
                      requires="glibc-opensuse", synced_at=newer)
        self._insert(conn, "almalinux9-baseos", "almalinux9", "glibc-almalinux", "2.34-1.el9", synced_at=older)
        self._insert(conn, "opensuse-tumbleweed-oss", "opensuse-tumbleweed", "glibc-opensuse", "2.38-1.suse",
                      synced_at=newer)

    def test_root_resolved_from_requested_distro(self, db_test_engine):
        """
        La distro demandée (almalinux9) est la ligne la PLUS ANCIENNE — un
        lookup non scopé (tri synced_at DESC) retournerait à tort la ligne
        openSUSE. Seul un filtrage effectif par source_prefix fait passer ce test.
        """
        from db.engine import db_conn
        from services.importer_rpm import resolve_deps_online

        with db_conn() as conn:
            self._seed_same_name_different_distros(conn)

        result = resolve_deps_online("prometheus", distro="almalinux9")
        assert result["success"] is True
        names = {p["name"] for p in result["packages"]}
        assert names == {"glibc-almalinux"}

    def test_root_resolved_from_other_distro(self, db_test_engine):
        """Le même appel avec une distro différente doit résoudre l'AUTRE ligne, pas la même."""
        from db.engine import db_conn
        from services.importer_rpm import resolve_deps_online

        with db_conn() as conn:
            self._seed_same_name_different_distros(conn)

        result = resolve_deps_online("prometheus", distro="opensuse-tumbleweed")
        assert result["success"] is True
        names = {p["name"] for p in result["packages"]}
        assert names == {"glibc-opensuse"}

    def test_capability_resolved_within_requested_distro(self, db_test_engine):
        """
        Une capability virtuelle (Requires: un nom de paquet différent de
        celui qui la fournit réellement — même convention que "webserver"/
        "httpd" plus haut dans ce fichier) fournie par des paquets de deux
        distros différentes doit résoudre vers le paquet de la distro
        demandée (resolve_provide_to_package() doit aussi respecter
        source_prefix). Le fournisseur openSUSE (non demandé) est
        délibérément le plus récent — un lookup non scopé le retournerait à
        tort. Nom SANS parenthèses délibérément : _tokens() filtre déjà les
        tokens du type "libfoo.so.1(...)(64bit)" avant qu'ils n'atteignent
        _resolve_dep() (limitation préexistante de ce fichier, distincte du
        scoping par distro testé ici — voir importer_apt.py pour un import
        qui, lui, ne filtre pas ces tokens).
        """
        from datetime import datetime, timedelta, timezone

        from db.engine import db_conn
        from services.importer_rpm import resolve_deps_online

        older = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        newer = datetime.now(timezone.utc).isoformat()
        capability = "libfoo-provide"
        with db_conn() as conn:
            self._insert(conn, "almalinux9-baseos", "almalinux9", "prometheus", "2.45-1.el9",
                          requires=capability, synced_at=newer)
            self._insert(conn, "almalinux9-baseos", "almalinux9", "provider-almalinux", "1.0-1.el9",
                          provides=capability, synced_at=older)
            self._insert(conn, "opensuse-tumbleweed-oss", "opensuse-tumbleweed", "provider-opensuse", "1.0-1.suse",
                          provides=capability, synced_at=newer)

        result = resolve_deps_online("prometheus", distro="almalinux9")
        names = {p["name"] for p in result["packages"]}
        assert names == {"provider-almalinux"}
        assert "provider-opensuse" not in names

    def test_transitive_dependency_stays_within_requested_distro(self, db_test_engine):
        """
        Même bug, mais un niveau plus profond : le paquet direct requis
        ("libcurl") existe dans les deux distros avec des sous-dépendances
        DIFFÉRENTES ; un mauvais scoping au niveau BFS ferait dériver toute
        la fermeture transitive vers la mauvaise distro, pas seulement le nom
        immédiat.
        """
        from datetime import datetime, timedelta, timezone

        from db.engine import db_conn
        from services.importer_rpm import resolve_deps_online

        older = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        newer = datetime.now(timezone.utc).isoformat()
        with db_conn() as conn:
            self._insert(conn, "almalinux9-baseos", "almalinux9", "prometheus", "2.45-1.el9",
                          requires="libcurl", synced_at=older)
            self._insert(conn, "almalinux9-baseos", "almalinux9", "libcurl", "7.76-1.el9",
                          requires="openssl-almalinux", synced_at=older)
            self._insert(conn, "opensuse-tumbleweed-oss", "opensuse-tumbleweed", "libcurl", "8.0-1.suse",
                          requires="openssl-opensuse", synced_at=newer)
            self._insert(conn, "almalinux9-baseos", "almalinux9", "openssl-almalinux", "3.0-1.el9", synced_at=older)
            self._insert(conn, "opensuse-tumbleweed-oss", "opensuse-tumbleweed", "openssl-opensuse", "3.1-1.suse",
                          synced_at=newer)

        result = resolve_deps_online("prometheus", distro="almalinux9")
        names = {p["name"] for p in result["packages"]}
        assert names == {"libcurl", "openssl-almalinux"}
        assert "openssl-opensuse" not in names

    def test_no_distro_keeps_any_source_fallback(self, db_test_engine):
        """Sans distro fournie (comportement historique), la résolution reste toutes-sources."""
        from db.engine import db_conn
        from services.importer_rpm import resolve_deps_online

        with db_conn() as conn:
            self._insert(conn, "almalinux9-baseos", "almalinux9", "prometheus", "2.45-1.el9",
                          requires="glibc-almalinux")
            self._insert(conn, "almalinux9-baseos", "almalinux9", "glibc-almalinux", "2.34-1.el9")

        result = resolve_deps_online("prometheus")
        assert result["success"] is True
        names = {p["name"] for p in result["packages"]}
        assert names == {"glibc-almalinux"}
