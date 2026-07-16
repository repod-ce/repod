"""
Détection du format de dépôt (APT ou RPM) via la variable d'environnement REPO_FORMAT.

Ce module est le point d'entrée unique pour tout code format-spécifique.
Il est importé au démarrage et ne change pas pendant la durée de vie du processus.

Usage :
    from services.format_router import REPO_FORMAT, is_apt, is_rpm, ACCEPTED_EXTENSIONS

Valeurs valides :
    REPO_FORMAT=apt   (défaut) → dépôt Debian/Ubuntu (.deb, reprepro)
    REPO_FORMAT=rpm            → dépôt RHEL/Fedora/SUSE (.rpm, createrepo_c)

Sécurité :
    Toute valeur non reconnue est rejetée (log warning + repli sur "apt").
    Aucun code extérieur ne peut modifier REPO_FORMAT à chaud — lecture seule.
"""
import os
import logging

logger = logging.getLogger("format_router")

_VALID_FORMATS: frozenset[str] = frozenset({"apt", "rpm", "apk", "both", "all"})
#  apt  → .deb / reprepro
#  rpm  → .rpm / createrepo_c
#  apk  → .apk / APKINDEX (Alpine Linux)
#  both → apt + rpm
#  all  → apt + rpm + apk

REPO_FORMAT: str = os.getenv("REPO_FORMAT", "apt").lower().strip()

if REPO_FORMAT not in _VALID_FORMATS:
    logger.warning(
        f"[format_router] REPO_FORMAT='{REPO_FORMAT}' invalide — "
        f"valeurs acceptées : {sorted(_VALID_FORMATS)}. Repli sur 'apt'."
    )
    REPO_FORMAT = "apt"

logger.debug(f"[format_router] Mode : {REPO_FORMAT.upper()}")


def is_apt() -> bool:
    """Retourne True si l'instance gère le format APT (.deb / reprepro).
    Vrai en mode 'apt', 'both' et 'all'."""
    return REPO_FORMAT in ("apt", "both", "all")


def is_rpm() -> bool:
    """Retourne True si l'instance gère le format RPM (.rpm / createrepo_c).
    Vrai en mode 'rpm', 'both' et 'all'."""
    return REPO_FORMAT in ("rpm", "both", "all")


def is_apk() -> bool:
    """Retourne True si l'instance gère le format APK (.apk / APKINDEX Alpine).
    Vrai en mode 'apk' et 'all'."""
    return REPO_FORMAT in ("apk", "all")


# Extensions acceptées pour l'upload selon le format
def _build_accepted_extensions() -> frozenset[str]:
    exts: set[str] = set()
    if is_apt(): exts.add(".deb")
    if is_rpm(): exts.add(".rpm")
    if is_apk(): exts.add(".apk")
    # Toujours accepter .apk pour le dépôt Alpine si le répertoire est configuré
    if os.getenv("APK_REPO_BASE"):
        exts.add(".apk")
    return frozenset(exts) or frozenset({".deb"})

ACCEPTED_EXTENSIONS: frozenset[str] = _build_accepted_extensions()

# Libellés humains utilisés dans les logs, messages d'erreur et SSE
_labels = []
if is_apt(): _labels.append("APT (.deb)")
if is_rpm(): _labels.append("RPM (.rpm)")
if is_apk(): _labels.append("APK (.apk)")
FORMAT_LABEL: str    = "+".join(_labels) if _labels else "APT (.deb)"
REPO_TOOL_LABEL: str = (
    "reprepro"          if REPO_FORMAT == "apt"
    else "createrepo_c" if REPO_FORMAT == "rpm"
    else "APKINDEX"     if REPO_FORMAT == "apk"
    else "reprepro+createrepo_c" if REPO_FORMAT == "both"
    else "reprepro+createrepo_c+APKINDEX"
)
DEFAULT_DISTRIBUTION: str = (
    "jammy"       if is_apt()
    else "alpine3.20" if is_apk()
    else "almalinux8"
)
