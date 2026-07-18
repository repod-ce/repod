"""
Dispatcher package_index — sélectionne l'implémentation selon REPO_FORMAT.

  REPO_FORMAT=apt   → package_index_apt.py  (Packages.gz, SQLite)
  REPO_FORMAT=rpm   → package_index_rpm.py  (repomd.xml → primary.xml.gz, SQLite)
  REPO_FORMAT=apk   → package_index_apk.py  (APKINDEX.tar.gz, SQLite)
  REPO_FORMAT=both  → APT + RPM simultanément (alias de "apt+rpm")
  REPO_FORMAT=all   → APT + RPM + APK simultanément

Interface publique commune :
  DEFAULT_SOURCES     — liste de dicts décrivant les sources upstream
  sync_source(source) — synchronise une source dans l'index SQLite
  sync_all()          — synchronise toutes les sources
  get_sync_status()   — statut de synchronisation de chaque source
  search_packages(q)  — recherche par nom/description/résumé
  get_package_info(n) — info complète d'un paquet par nom exact
  is_indexed()        — True si l'index contient au moins un paquet
  init_db()           — initialise le schéma SQLite
  list_packages_by_source(source_id) — tous les paquets indexés d'une source (paginé)

Fonctions RPM-uniquement (exposées en mode RPM et both/all, stub sinon) :
  record_import_group, get_import_groups, delete_import_group
  resolve_provide_to_package, get_sync_stats
"""
from services.format_router import is_rpm as _is_rpm, is_apk as _is_apk, REPO_FORMAT as _REPO_FORMAT

# ─── Mode ALL : APT + RPM + APK ───────────────────────────────────────────────
if _REPO_FORMAT == "all":
    from services.package_index_apt import (
        DEFAULT_SOURCES as _APT_SOURCES,
        sync_source as _apt_sync_source,
        sync_all as _apt_sync_all,
        get_sync_status as _apt_get_sync_status,
        search_packages as _apt_search,
        get_package_info as _apt_get_info,
        get_package_info_for_distro as _apt_get_info_for_distro,
        is_indexed as _apt_is_indexed,
        init_db as _apt_init_db,
        list_packages_by_source as _apt_list_by_source,
    )
    from services.package_index_rpm import (
        DEFAULT_SOURCES as _RPM_SOURCES,
        sync_source as _rpm_sync_source,
        sync_all as _rpm_sync_all,
        get_sync_status as _rpm_get_sync_status,
        get_sync_stats as _rpm_get_sync_stats,
        search_packages as _rpm_search,
        get_package_info as _rpm_get_info,
        is_indexed as _rpm_is_indexed,
        init_db as _rpm_init_db,
        record_import_group,
        get_import_groups,
        delete_import_group,
        resolve_provide_to_package,
        list_packages_by_source as _rpm_list_by_source,
    )
    from services.package_index_apk import (
        DEFAULT_SOURCES as _APK_SOURCES,
        sync_source as _apk_sync_source,
        sync_all as _apk_sync_all,
        get_sync_status as _apk_get_sync_status,
        search_packages as _apk_search,
        get_package_info as _apk_get_info,
        is_indexed as _apk_is_indexed,
        init_db as _apk_init_db,
        list_packages_by_source as _apk_list_by_source,
    )

    # Sources fusionnées : APT en premier, RPM en second, APK en troisième
    DEFAULT_SOURCES: list[dict] = list(_APT_SOURCES) + list(_RPM_SOURCES) + list(_APK_SOURCES)

    def sync_source(source: dict, stop_event=None) -> dict:           # noqa: E302
        """Route vers APT, RPM ou APK selon la clé discriminante."""
        if "apkindex_url" in source:
            return _apk_sync_source(source)
        if "repomd_url" in source:
            return _rpm_sync_source(source, stop_event=stop_event)
        return _apt_sync_source(source)

    def sync_all() -> list[dict]:                                     # noqa: E302
        """Synchronise toutes les sources APT puis RPM puis APK."""
        return _apt_sync_all() + _rpm_sync_all() + _apk_sync_all()

    def get_sync_status() -> list[dict]:                              # noqa: E302
        """Retourne le statut des sources APT + RPM + APK fusionnées."""
        apt = [dict(s, format="apt") for s in _apt_get_sync_status()]
        rpm = [dict(s, format="rpm") for s in _rpm_get_sync_status()]
        apk = _apk_get_sync_status()  # déjà tagué format=apk
        return apt + rpm + apk

    def get_sync_stats() -> list[dict]:                               # noqa: E302
        """Retourne les stats enrichies APT + RPM + APK."""
        return get_sync_status()

    def search_packages(q: str, **kwargs) -> list[dict]:              # noqa: E302
        """Recherche dans les trois index."""
        return _apt_search(q, **kwargs) + _rpm_search(q, **kwargs) + _apk_search(q, **kwargs)

    def get_package_info(name: str) -> dict | None:                   # noqa: E302
        """Cherche dans APT puis RPM puis APK."""
        return _apt_get_info(name) or _rpm_get_info(name) or _apk_get_info(name)

    def get_package_info_for_distro(name: str, distro: str | None) -> dict | None:  # noqa: E302
        """Cherche dans APT (avec filtre distro) puis RPM puis APK."""
        return _apt_get_info_for_distro(name, distro) or _rpm_get_info(name) or _apk_get_info(name)

    def is_indexed() -> bool:                                         # noqa: E302
        """Vrai si au moins un des trois index contient des paquets."""
        return _apt_is_indexed() or _rpm_is_indexed() or _apk_is_indexed()

    def init_db() -> None:                                            # noqa: E302
        """Initialise les schémas SQLite APT, RPM et APK."""
        _apt_init_db()
        _rpm_init_db()
        _apk_init_db()

    def list_packages_by_source(source_id: str, **kwargs) -> list[dict]:  # noqa: E302
        """Route vers APT, RPM ou APK selon la source."""
        if any(s["id"] == source_id for s in _APK_SOURCES):
            return _apk_list_by_source(source_id, **kwargs)
        if any(s["id"] == source_id for s in _RPM_SOURCES):
            return _rpm_list_by_source(source_id, **kwargs)
        return _apt_list_by_source(source_id, **kwargs)

# ─── Mode BOTH : APT + RPM ────────────────────────────────────────────────────
elif _REPO_FORMAT == "both":
    from services.package_index_apt import (
        DEFAULT_SOURCES as _APT_SOURCES,
        sync_source as _apt_sync_source,
        sync_all as _apt_sync_all,
        get_sync_status as _apt_get_sync_status,
        search_packages as _apt_search,
        get_package_info as _apt_get_info,
        get_package_info_for_distro as _apt_get_info_for_distro,
        is_indexed as _apt_is_indexed,
        init_db as _apt_init_db,
        list_packages_by_source as _apt_list_by_source,
    )
    from services.package_index_rpm import (
        DEFAULT_SOURCES as _RPM_SOURCES,
        sync_source as _rpm_sync_source,
        sync_all as _rpm_sync_all,
        get_sync_status as _rpm_get_sync_status,
        get_sync_stats as _rpm_get_sync_stats,
        search_packages as _rpm_search,
        get_package_info as _rpm_get_info,
        is_indexed as _rpm_is_indexed,
        init_db as _rpm_init_db,
        record_import_group,
        get_import_groups,
        delete_import_group,
        resolve_provide_to_package,
        list_packages_by_source as _rpm_list_by_source,
    )

    # Sources fusionnées — APT en premier, RPM en second
    DEFAULT_SOURCES: list[dict] = list(_APT_SOURCES) + list(_RPM_SOURCES)

    def sync_source(source: dict, stop_event=None) -> dict:           # noqa: E302
        """Route vers APT ou RPM selon la présence de 'repomd_url' (clé RPM)."""
        if "repomd_url" in source:
            return _rpm_sync_source(source, stop_event=stop_event)
        return _apt_sync_source(source)

    def sync_all() -> list[dict]:                                     # noqa: E302
        """Synchronise toutes les sources APT puis RPM."""
        return _apt_sync_all() + _rpm_sync_all()

    def get_sync_status() -> list[dict]:                              # noqa: E302
        """Retourne le statut des sources APT + RPM fusionnées."""
        apt = [dict(s, format="apt") for s in _apt_get_sync_status()]
        rpm = [dict(s, format="rpm") for s in _rpm_get_sync_status()]
        return apt + rpm

    def get_sync_stats() -> list[dict]:                               # noqa: E302
        """Retourne les stats enrichies APT + RPM."""
        return get_sync_status() + _rpm_get_sync_stats()

    def search_packages(q: str, **kwargs) -> list[dict]:              # noqa: E302
        """Recherche dans les deux index."""
        return _apt_search(q, **kwargs) + _rpm_search(q, **kwargs)

    def get_package_info(name: str) -> dict | None:                   # noqa: E302
        """Cherche dans APT puis RPM."""
        return _apt_get_info(name) or _rpm_get_info(name)

    def get_package_info_for_distro(name: str, distro: str | None) -> dict | None:  # noqa: E302
        """Cherche dans APT (avec filtre distro) puis RPM."""
        return _apt_get_info_for_distro(name, distro) or _rpm_get_info(name)

    def is_indexed() -> bool:                                         # noqa: E302
        """Vrai si au moins un des deux index contient des paquets."""
        return _apt_is_indexed() or _rpm_is_indexed()

    def init_db() -> None:                                            # noqa: E302
        """Initialise les schémas SQLite APT et RPM."""
        _apt_init_db()
        _rpm_init_db()

    def list_packages_by_source(source_id: str, **kwargs) -> list[dict]:  # noqa: E302
        """Route vers APT ou RPM selon la source."""
        if any(s["id"] == source_id for s in _RPM_SOURCES):
            return _rpm_list_by_source(source_id, **kwargs)
        return _apt_list_by_source(source_id, **kwargs)

# ─── Mode APK seul ────────────────────────────────────────────────────────────
elif _is_apk() and not _is_rpm():
    from services.package_index_apk import (
        DEFAULT_SOURCES,
        sync_source,
        sync_all,
        get_sync_status,
        search_packages,
        get_package_info,
        is_indexed,
        init_db,
        list_packages_by_source,
    )

    def get_package_info_for_distro(name: str, distro: str | None) -> dict | None:
        """En mode APK, alias de get_package_info()."""
        return get_package_info(name)

    def get_sync_stats() -> list[dict]:
        return get_sync_status()

    def record_import_group(name, files, distribution, imported_by):
        pass

    def get_import_groups():
        return []

    def delete_import_group(name):
        return False

    def resolve_provide_to_package(provide):
        return None

# ─── Mode RPM ─────────────────────────────────────────────────────────────────
elif _is_rpm():
    from services.package_index_rpm import (
        DEFAULT_SOURCES,
        sync_source,
        sync_all,
        get_sync_status,
        get_sync_stats,          # RPM-specific — statistiques enrichies
        search_packages,
        get_package_info,
        is_indexed,
        init_db,
        # Fonctions RPM-uniquement
        record_import_group,
        get_import_groups,
        delete_import_group,
        resolve_provide_to_package,
        list_packages_by_source,
    )

    def get_package_info_for_distro(name: str, distro: str | None) -> dict | None:
        """En mode RPM, alias de get_package_info() avec source_prefix."""
        return get_package_info(name, source_prefix=distro)

# ─── Mode APT (défaut) ────────────────────────────────────────────────────────
else:
    from services.package_index_apt import (
        DEFAULT_SOURCES,
        sync_source,
        sync_all,
        get_sync_status,
        search_packages,
        get_package_info,
        get_package_info_for_distro,
        is_indexed,
        init_db,
        list_packages_by_source,
    )

    # Stubs pour les fonctions RPM-uniquement en mode APT
    def get_sync_stats() -> list[dict]:
        """En mode APT, alias de get_sync_status()."""
        return get_sync_status()

    def record_import_group(name: str, files: list, distribution: str,
                            imported_by: str) -> None:
        """Non disponible en mode APT — no-op."""

    def get_import_groups() -> list[dict]:
        """Non disponible en mode APT."""
        return []

    def delete_import_group(name: str) -> bool:
        """Non disponible en mode APT."""
        return False

    def resolve_provide_to_package(provide: str) -> dict | None:
        """En mode APT, résolution via le champ Provides de l'index."""
        from services.package_index_apt import _find_by_provides
        from db.engine import db_conn
        with db_conn() as conn:
            row = _find_by_provides(conn, provide)
        return dict(row) if row else None
