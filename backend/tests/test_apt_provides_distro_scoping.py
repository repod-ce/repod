# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Module : test_apt_provides_distro_scoping.py
Rôle   : services/package_index_apt.py:get_package_info_for_distro() — bug
         réel trouvé en auditant ce fichier après les correctifs RPM/APK
         distro-scoping de ce soir (resolve_provide_to_package()/
         resolve_deps_online() ignorant le filtre distro pour la résolution
         des paquets virtuels via Provides — même bug côté APT, un niveau
         plus profond : "prometheus" résolu vers la mauvaise distro).

         get_package_info_for_distro(name, distro) scope correctement la
         recherche par NOM EXACT à la distro demandée, mais retombait
         directement sur get_package_info(name, arch=arch) — ENTIÈREMENT
         non scopé par distro — pour la résolution Provides (paquets
         virtuels, ex: "mail-transport-agent"). Un nom virtuel sans ligne
         exacte dans la distro demandée pouvait donc résoudre vers le
         fournisseur réel d'une AUTRE distro indexée.

Dépend : pytest, db_test_engine (fixture autouse, SQLite in-memory —
         tests/conftest.py).
"""
from datetime import datetime, timezone

from sqlalchemy import text

from db.engine import db_conn


def _insert(source_id, distro, name, arch="amd64", provides=None):
    with db_conn() as conn:
        conn.execute(text("""
            INSERT INTO packages (source_id, name, version, arch, distro, provides, synced_at)
            VALUES (:source_id, :name, '1.0', :arch, :distro, :provides, :now)
        """), {
            "source_id": source_id, "name": name, "arch": arch, "distro": distro,
            "provides": provides, "now": datetime.now(timezone.utc).isoformat(),
        })


class TestGetPackageInfoForDistroProvidesScoping:
    def test_virtual_package_resolved_within_requested_distro(self, db_test_engine):
        """
        'mail-transport-agent' est un paquet virtuel fourni par un
        fournisseur DIFFÉRENT selon la distro (postfix en jammy, exim4 en
        noble) — un lookup non scopé par distro pourrait résoudre vers
        n'importe lequel des deux, au hasard de l'ordre physique des
        lignes (aucun ORDER BY pertinent sans filtre distro/arch communs
        aux deux ici).
        """
        from services.package_index_apt import get_package_info_for_distro

        _insert("ubuntu-jammy", "jammy", "postfix", provides="mail-transport-agent")
        _insert("ubuntu-noble", "noble", "exim4", provides="mail-transport-agent")

        row = get_package_info_for_distro("mail-transport-agent", "jammy")
        assert row is not None
        assert row["name"] == "postfix"
        assert row["distro"] == "jammy"

        row2 = get_package_info_for_distro("mail-transport-agent", "noble")
        assert row2 is not None
        assert row2["name"] == "exim4"
        assert row2["distro"] == "noble"

    def test_virtual_package_arch_filter_still_applies(self, db_test_engine):
        """Le filtre `arch` doit continuer à s'appliquer en même temps que `distro`
        pour la résolution Provides."""
        from services.package_index_apt import get_package_info_for_distro

        _insert("ubuntu-jammy-arm64", "jammy", "postfix-arm", arch="arm64", provides="mail-transport-agent")
        _insert("ubuntu-jammy", "jammy", "postfix", arch="amd64", provides="mail-transport-agent")

        row = get_package_info_for_distro("mail-transport-agent", "jammy", arch="arm64")
        assert row["name"] == "postfix-arm"
        assert row["arch"] == "arm64"

    def test_no_distro_match_falls_back_to_unscoped_provides(self, db_test_engine):
        """Comportement historique préservé : sans correspondance dans la
        distro demandée, on retombe sur la résolution Provides toutes-distros
        (mieux qu'un échec sec, cohérent avec le fallback existant sur
        get_package_info(name))."""
        from services.package_index_apt import get_package_info_for_distro

        _insert("ubuntu-noble", "noble", "exim4", provides="mail-transport-agent")

        row = get_package_info_for_distro("mail-transport-agent", "jammy")
        assert row is not None
        assert row["name"] == "exim4"
