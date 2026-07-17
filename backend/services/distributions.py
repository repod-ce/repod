"""
Façade format-agnostique pour la gestion des distributions.

Dispatche vers distributions_apt (reprepro / Debian-Ubuntu) ou distributions_rpm
(createrepo_c / RHEL-Fedora-SUSE) selon la variable d'environnement REPO_FORMAT.

Les modules spécifiques ne sont importés qu'à l'exécution pour éviter les erreurs
d'import si les outils système (reprepro, createrepo_c) ne sont pas installés
dans le container courant.

Tous les imports existants dans le code restent valides sans modification :
    from services.distributions import VALID_CODENAMES, get_distribution_stats, …
"""
from services.format_router import is_rpm as _is_rpm, is_apk as _is_apk, REPO_FORMAT as _REPO_FORMAT

if _REPO_FORMAT == "both":
    # ── Mode BOTH (APT + RPM simultanés) ─────────────────────────────────────
    from services.distributions_apt import (                          # noqa: F401
        ENTERPRISE_DISTRIBUTIONS as _APT_DISTS,
        ALPINE_DISTRIBUTIONS as _APK_DISTS_BOTH,
        SOURCE_TO_DISTRIB as _APT_SOURCE_TO_DISTRIB,
        get_distribution_stats as _apt_get_stats,
        list_packages_in_distrib as _apt_list_packages,
        promote_package as _apt_promote,
        migrate_all as _apt_migrate_all,
        detect_distribution_from_source as _apt_detect_from_source,
        _reprepro_env,                     # utilisé par tests (inspection interne)
    )
    from services.distributions_rpm import (                          # noqa: F401
        RPM_DISTRIBUTIONS as _RPM_DISTS,
        ARCHITECTURES,
        SOURCE_TO_DISTRIB as _RPM_SOURCE_TO_DISTRIB,
        get_distribution_stats as _rpm_get_stats,
        list_packages_in_distrib as _rpm_list_packages,
        promote_package as _rpm_promote,
        migrate_all as _rpm_migrate_all,
        detect_distribution_from_source as _rpm_detect_from_source,
        get_distrib_info as _rpm_get_distrib_info,
        add_rpm_to_distrib,
        init_distribution,
        remove_rpm_from_distrib,
    )

    # Chaque distribution reçoit un champ "format" pour que l'UI puisse les distinguer
    ENTERPRISE_DISTRIBUTIONS: list[dict] = (
        [{**d, "format": "deb"} for d in _APT_DISTS]
        + [{**d, "format": "rpm"} for d in _RPM_DISTS]
        + [{**d, "format": "apk"} for d in _APK_DISTS_BOTH]
    )

    # VALID_CODENAMES inclut les distributions Alpine (upload + inventaire)
    VALID_CODENAMES: set[str] = {d["codename"] for d in ENTERPRISE_DISTRIBUTIONS}

    SOURCE_TO_DISTRIB: dict[str, str] = {**_APT_SOURCE_TO_DISTRIB, **_RPM_SOURCE_TO_DISTRIB}

    def get_distribution_stats() -> list[dict]:                       # noqa: E302
        """Retourne les stats des distributions APT + RPM fusionnées (avec champ 'format')."""
        return (
            [{**d, "format": "deb"} for d in _apt_get_stats()]
            + [{**d, "format": "rpm"} for d in _rpm_get_stats()]
        )

    def list_packages_in_distrib(codename: str) -> list[dict]:        # noqa: E302
        """Route vers APT ou RPM selon le codename."""
        from services.distributions_apt import ENTERPRISE_DISTRIBUTIONS as _a
        if any(d["codename"] == codename for d in _a):
            return _apt_list_packages(codename)
        return _rpm_list_packages(codename)

    def promote_package(package: str, from_dist: str, to_dist: str) -> tuple[bool, str]:  # noqa: E302
        """
        Promotion inter-distributions.
        Garde : from_dist et to_dist doivent appartenir au même format (deb ou rpm).
        """
        from services.distributions_apt import ENTERPRISE_DISTRIBUTIONS as _a
        _apt_codenames = {d["codename"] for d in _a}
        from_is_apt = from_dist in _apt_codenames
        to_is_apt   = to_dist   in _apt_codenames
        if from_is_apt != to_is_apt:
            _from_fmt = "deb" if from_is_apt else "rpm"
            _to_fmt   = "deb" if to_is_apt   else "rpm"
            return False, (
                f"Promotion inter-format impossible : "
                f"'{from_dist}' ({_from_fmt}) → '{to_dist}' ({_to_fmt})"
            )
        if from_is_apt:
            return _apt_promote(package, from_dist, to_dist)
        return _rpm_promote(package, from_dist, to_dist)

    def migrate_all(from_dist: str, to_dist: str) -> dict:            # noqa: E302
        """Route vers APT ou RPM selon le codename source."""
        from services.distributions_apt import ENTERPRISE_DISTRIBUTIONS as _a
        if any(d["codename"] == from_dist for d in _a):
            return _apt_migrate_all(from_dist, to_dist)
        return _rpm_migrate_all(from_dist, to_dist)

    def detect_distribution_from_source(source_id: str) -> str | None:  # noqa: E302
        """Cherche dans les deux mappings source → codename."""
        return _apt_detect_from_source(source_id) or _rpm_detect_from_source(source_id)

    def get_distrib_info(codename: str) -> dict | None:               # noqa: E302
        """Cherche dans APT puis RPM."""
        from services.distributions_apt import ENTERPRISE_DISTRIBUTIONS as _a
        result = next((d for d in _a if d["codename"] == codename), None)
        if result:
            return {**result, "format": "deb"}
        return _rpm_get_distrib_info(codename)

    def remove_package(name: str) -> tuple[bool, str]:                # noqa: E302
        """Supprime un paquet des distributions APT et RPM (best-effort sur les deux)."""
        from services.reprepro import remove_package as _reprepro_remove
        apt_ok = True
        try:
            _reprepro_remove(name)
        except Exception as _e:
            apt_ok = False
        rpm_ok, rpm_msg = remove_rpm_from_distrib(name)
        if apt_ok and rpm_ok:
            return True, f"{name} supprimé (APT + RPM)"
        if apt_ok:
            return True, f"{name} supprimé (APT) — RPM : {rpm_msg}"
        if rpm_ok:
            return True, f"{name} supprimé (RPM) — APT : erreur reprepro"
        return False, f"{name} : suppression échouée (APT + RPM)"

elif _REPO_FORMAT == "all":
    # ── Mode ALL (APT + RPM + APK simultanés) ────────────────────────────────
    from services.distributions_apt import (                          # noqa: F401
        ENTERPRISE_DISTRIBUTIONS as _APT_DISTS,
        ALPINE_DISTRIBUTIONS as _APK_DISTS_IN_APT,
        SOURCE_TO_DISTRIB as _APT_SOURCE_TO_DISTRIB,
        get_distribution_stats as _apt_get_stats,
        list_packages_in_distrib as _apt_list_packages,
        promote_package as _apt_promote,
        migrate_all as _apt_migrate_all,
        detect_distribution_from_source as _apt_detect_from_source,
    )
    from services.distributions_rpm import (                          # noqa: F401
        RPM_DISTRIBUTIONS as _RPM_DISTS,
        SOURCE_TO_DISTRIB as _RPM_SOURCE_TO_DISTRIB,
        get_distribution_stats as _rpm_get_stats,
        list_packages_in_distrib as _rpm_list_packages,
        promote_package as _rpm_promote,
        migrate_all as _rpm_migrate_all,
        detect_distribution_from_source as _rpm_detect_from_source,
        add_rpm_to_distrib,
        init_distribution,
        remove_rpm_from_distrib,
        ARCHITECTURES,
    )
    from services.distributions_apk import (                          # noqa: F401
        APK_DISTRIBUTIONS as _APK_DISTS,
        get_distribution_stats as _apk_get_stats,
        list_packages_in_distrib as _apk_list_packages,
        add_package as add_apk_to_distrib,
        remove_package as remove_apk_from_distrib,
        init_distribution as init_apk_distribution,
    )

    ENTERPRISE_DISTRIBUTIONS: list[dict] = (
        [{**d, "format": "deb"} for d in _APT_DISTS]
        + [{**d, "format": "rpm"} for d in _RPM_DISTS]
        + [{**d, "format": "apk"} for d in _APK_DISTS]
    )
    VALID_CODENAMES: set[str] = {d["codename"] for d in ENTERPRISE_DISTRIBUTIONS}
    SOURCE_TO_DISTRIB: dict[str, str] = {**_APT_SOURCE_TO_DISTRIB, **_RPM_SOURCE_TO_DISTRIB}

    def get_distribution_stats() -> list[dict]:                       # noqa: E302
        return (
            [{**d, "format": "deb"} for d in _apt_get_stats()]
            + [{**d, "format": "rpm"} for d in _rpm_get_stats()]
            + [{**d, "format": "apk"} for d in _apk_get_stats()]
        )

    def list_packages_in_distrib(codename: str) -> list[dict]:        # noqa: E302
        from services.distributions_apt import ENTERPRISE_DISTRIBUTIONS as _a
        from services.distributions_apk import VALID_APK_CODENAMES
        if any(d["codename"] == codename for d in _a):
            return _apt_list_packages(codename)
        if codename in VALID_APK_CODENAMES:
            return _apk_list_packages(codename)
        return _rpm_list_packages(codename)

    def promote_package(package: str, from_dist: str, to_dist: str) -> tuple[bool, str]:  # noqa: E302
        from services.distributions_apt import ENTERPRISE_DISTRIBUTIONS as _a
        _apt_codenames = {d["codename"] for d in _a}
        from_is_apt = from_dist in _apt_codenames
        to_is_apt   = to_dist   in _apt_codenames
        if from_is_apt and to_is_apt:
            return _apt_promote(package, from_dist, to_dist)
        return _rpm_promote(package, from_dist, to_dist)

    def migrate_all(from_dist: str, to_dist: str) -> dict:            # noqa: E302
        from services.distributions_apt import ENTERPRISE_DISTRIBUTIONS as _a
        if any(d["codename"] == from_dist for d in _a):
            return _apt_migrate_all(from_dist, to_dist)
        return _rpm_migrate_all(from_dist, to_dist)

    def detect_distribution_from_source(source_id: str) -> str | None:  # noqa: E302
        return _apt_detect_from_source(source_id) or _rpm_detect_from_source(source_id)

    def remove_package(name: str) -> tuple[bool, str]:                # noqa: E302
        from services.reprepro import remove_package as _reprepro_remove
        try: _reprepro_remove(name)
        except Exception: pass
        return True, f"{name} supprimé (best-effort)"

elif _is_rpm():
    # ── Mode RPM (createrepo_c) ───────────────────────────────────────────────
    from services.distributions_rpm import (                          # noqa: F401
        RPM_DISTRIBUTIONS as ENTERPRISE_DISTRIBUTIONS,
        VALID_CODENAMES,
        ARCHITECTURES,
        SOURCE_TO_DISTRIB,
        get_distribution_stats,
        list_packages_in_distrib,
        promote_package,
        migrate_all,
        detect_distribution_from_source,
        get_distrib_info,
        add_rpm_to_distrib,
        init_distribution,
        remove_rpm_from_distrib,
    )

    def remove_package(name: str) -> tuple[bool, str]:                # noqa: E302
        """Supprime un paquet de toutes les distributions RPM (createrepo_c)."""
        return remove_rpm_from_distrib(name)

elif _is_apk():
    # ── Mode APK (APKINDEX Alpine) ────────────────────────────────────────────
    from services.distributions_apk import (                          # noqa: F401
        APK_DISTRIBUTIONS as ENTERPRISE_DISTRIBUTIONS,
        VALID_APK_CODENAMES as VALID_CODENAMES,
        get_distribution_stats,
        list_packages_in_distrib,
        add_package as add_apk_to_distrib,
        remove_package as remove_apk_from_distrib,
        init_distribution,
        init_all_distributions,
    )
    ARCHITECTURES: list[str] = ["x86_64"]
    SOURCE_TO_DISTRIB: dict[str, str] = {}

    def promote_package(package: str, from_dist: str, to_dist: str) -> tuple[bool, str]:  # noqa: E302
        return False, "Promotion non disponible en mode APK"

    def migrate_all(from_dist: str, to_dist: str) -> tuple[int, list, list]:  # noqa: E302
        return 0, [], ["Migration non disponible en mode APK"]

    def detect_distribution_from_source(source_id: str) -> str | None:  # noqa: E302
        return None

    def add_rpm_to_distrib(rpm_filename: str, codename: str) -> tuple[bool, str]:  # noqa: E302
        return False, "add_rpm_to_distrib non disponible en mode APK"

    def remove_package(name: str) -> tuple[bool, str]:                # noqa: E302
        """Supprime un paquet de toutes les distributions APK."""
        from services.distributions_apk import APK_DISTRIBUTIONS, remove_package as _rm
        errors = []
        for dist in APK_DISTRIBUTIONS:
            ok, msg = _rm(name, "", dist["codename"])
            if not ok:
                errors.append(msg)
        if errors:
            return False, " | ".join(errors)
        return True, f"{name} supprimé des distributions APK"

else:
    # ── Mode APT (reprepro) ───────────────────────────────────────────────────
    from services.distributions_apt import (                          # noqa: F401
        ENTERPRISE_DISTRIBUTIONS,
        VALID_CODENAMES,
        SOURCE_TO_DISTRIB,
        get_distribution_stats,
        list_packages_in_distrib,
        promote_package,
        migrate_all,
        detect_distribution_from_source,
        _reprepro_env,                     # utilisé par tests (inspection interne)
    )
    # Stub : fonctions RPM-only absentes en mode APT
    ARCHITECTURES: list[str] = ["amd64", "arm64", "i386"]

    def get_distrib_info(codename: str) -> dict | None:                # noqa: E302
        """Retourne les métadonnées d'une distribution APT (compatibility stub)."""
        from services.distributions_apt import ENTERPRISE_DISTRIBUTIONS as _DISTS
        return next((d for d in _DISTS if d["codename"] == codename), None)

    def add_rpm_to_distrib(rpm_filename: str, codename: str) -> tuple[bool, str]:  # noqa: E302
        """Non disponible en mode APT."""
        return False, "add_rpm_to_distrib non disponible en mode APT"

    def init_distribution(codename: str) -> tuple[bool, str]:         # noqa: E302
        """Non disponible en mode APT (utilise reprepro export à la place)."""
        return False, "init_distribution non disponible en mode APT"

    def remove_package(name: str) -> tuple[bool, str]:                # noqa: E302
        """Supprime un paquet de toutes les distributions APT (reprepro)."""
        from services.reprepro import remove_package as _reprepro_remove
        _reprepro_remove(name)
        return True, f"{name} supprimé via reprepro"
