"""
Dispatcher importer — sélectionne l'implémentation selon la distribution cible.

  distribution alpine* → importer_apk.py  (télécharge .apk depuis Alpine CDN)
  distribution alma/rocky/centos/… → importer_rpm.py  (télécharge .rpm)
  distribution jammy/bookworm/… → importer_apt.py  (télécharge .deb)

En mode REPO_FORMAT=all, le format est déterminé par la distribution passée,
et non par REPO_FORMAT global. Cela évite d'utiliser le mauvais pipeline.

Interface publique commune (attendue par import_router.py) :
  resolve_deps_online(package_name, distro=None) → dict
  import_package_stream(name, user, group, distribution) → Generator[str]
"""
from services.format_router import is_rpm as _is_rpm, is_apk as _is_apk, REPO_FORMAT as _REPO_FORMAT

# Préfixes de codenames pour déterminer le format depuis la distribution
_APK_PREFIXES = ("alpine",)
_RPM_PREFIXES = ("almalinux", "rocky", "centos", "oraclelinux", "fedora", "opensuse")


def _format_from_distribution(distribution: str | None) -> str:
    """
    Détermine le format paquet depuis le codename de distribution.
    Retourne 'apk', 'rpm' ou 'deb'.
    """
    if not distribution:
        # Fallback sur REPO_FORMAT global
        if _is_apk() and not _is_rpm():
            return "apk"
        if _is_rpm() and not _is_apk():
            return "rpm"
        return "deb"
    c = distribution.lower()
    if any(c.startswith(p) for p in _APK_PREFIXES):
        return "apk"
    if any(c.startswith(p) for p in _RPM_PREFIXES):
        return "rpm"
    return "deb"


def resolve_deps_online(package_name: str, distro: str | None = None) -> dict:
    """Résout les dépendances en ligne selon le format de la distribution."""
    fmt = _format_from_distribution(distro)
    if fmt == "apk":
        from services.importer_apk import resolve_deps_online as _fn
    elif fmt == "rpm":
        from services.importer_rpm import resolve_deps_online as _fn
    else:
        from services.importer_apt import resolve_deps_online as _fn
    return _fn(package_name)


def import_package_stream(
    package_name: str,
    user: str,
    group: str | None = None,
    distribution: str | None = None,
):
    """
    Importe un paquet en streaming SSE, en choisissant l'implémentation
    selon le format déduit de la distribution cible.
    """
    fmt = _format_from_distribution(distribution)
    if fmt == "apk":
        from services.importer_apk import import_package_stream as _stream
    elif fmt == "rpm":
        from services.importer_rpm import import_package_stream as _stream
    else:
        from services.importer_apt import import_package_stream as _stream
    yield from _stream(package_name, user, group, distribution)


def import_one(pkg_row: dict, distribution: str, user: str, group: str | None = None) -> dict:
    """
    Télécharge, valide et ajoute un seul paquet indexé, en choisissant
    l'implémentation selon le format déduit de la distribution cible.
    Utilisé par le mirroir planifié (services.mirror_manager).
    """
    fmt = _format_from_distribution(distribution)
    if fmt == "apk":
        from services.importer_apk import import_one as _fn
    elif fmt == "rpm":
        from services.importer_rpm import import_one as _fn
    else:
        from services.importer_apt import import_one as _fn
    return _fn(pkg_row, distribution, user, group)
