"""
Gestion des distributions reprepro (enterprise).
Distributions fixes : jammy, noble, focal, bookworm.
reprepro est exécuté directement dans le container backend (installé dans l'image).
Les volumes repos/conf, repos/dists, repos/db et repos/pool sont partagés.
"""
import os
import subprocess
from pathlib import Path

REPREPRO_BASE = Path(os.getenv("REPREPRO_BASE", "/repos"))
GNUPG_HOME    = os.getenv("GNUPG_HOME", "/repos/gnupg")

ENTERPRISE_DISTRIBUTIONS = [
    {
        "codename": "jammy",
        "name": "Ubuntu 22.04 LTS",
        "full_name": "Ubuntu 22.04 LTS — Jammy Jellyfish",
        "os": "ubuntu",
        "badge": "LTS",
        "color": "orange",
    },
    {
        "codename": "noble",
        "name": "Ubuntu 24.04 LTS",
        "full_name": "Ubuntu 24.04 LTS — Noble Numbat",
        "os": "ubuntu",
        "badge": "LTS",
        "color": "green",
    },
    {
        "codename": "focal",
        "name": "Ubuntu 20.04 LTS",
        "full_name": "Ubuntu 20.04 LTS — Focal Fossa",
        "os": "ubuntu",
        "badge": "ESM",
        "color": "gray",
    },
    {
        "codename": "bookworm",
        "name": "Debian 12",
        "full_name": "Debian 12 — Bookworm",
        "os": "debian",
        "badge": "Stable",
        "color": "red",
    },
]

# Distributions Alpine Linux — inventaire + CVE uniquement (APK, pas reprepro)
ALPINE_DISTRIBUTIONS = [
    {"codename": "alpine3.18", "name": "Alpine Linux 3.18", "os": "alpine", "pkg_type": "apk"},
    {"codename": "alpine3.19", "name": "Alpine Linux 3.19", "os": "alpine", "pkg_type": "apk"},
    {"codename": "alpine3.20", "name": "Alpine Linux 3.20", "os": "alpine", "pkg_type": "apk"},
    {"codename": "alpine3.21", "name": "Alpine Linux 3.21", "os": "alpine", "pkg_type": "apk"},
]

VALID_CODENAMES = (
    {d["codename"] for d in ENTERPRISE_DISTRIBUTIONS}
    | {d["codename"] for d in ALPINE_DISTRIBUTIONS}
)

SOURCE_TO_DISTRIB: dict[str, str] = {
    "ubuntu-jammy": "jammy",
    "ubuntu-jammy-updates": "jammy",
    "ubuntu-noble": "noble",
    "ubuntu-focal": "focal",
    "debian-bookworm": "bookworm",
    "ubuntu-jammy-security": "jammy",
    "ubuntu-noble-security": "noble",
    "ubuntu-focal-security": "focal",
    "debian-bookworm-security": "bookworm",
}


def _reprepro_env() -> dict:
    return {**os.environ, "GNUPGHOME": GNUPG_HOME}


def _reprepro(*args) -> tuple[int, str, str]:
    """Exécute reprepro directement (installé dans le container backend)."""
    cmd = ["reprepro", "-b", str(REPREPRO_BASE)] + list(args)
    result = subprocess.run(cmd, capture_output=True, text=True, env=_reprepro_env())
    return result.returncode, result.stdout, result.stderr


def list_packages_in_distrib(codename: str) -> list[dict]:
    """
    Liste les paquets dans une distribution via `reprepro list`.
    Format de sortie reprepro : "codename|component|arch: name version"
    """
    rc, stdout, _ = _reprepro("list", codename)
    if rc != 0:
        return []
    packages = []
    seen = set()
    for line in stdout.strip().splitlines():
        if ":" not in line:
            continue
        _, _, pkg_info = line.partition(": ")
        parts = pkg_info.strip().split(" ", 1)
        if len(parts) == 2:
            name, version = parts[0], parts[1]
            if name not in seen:
                seen.add(name)
                packages.append({"name": name, "version": version})
    return sorted(packages, key=lambda p: p["name"])


def get_distribution_stats() -> list[dict]:
    """Retourne la liste des distributions avec leur nombre de paquets."""
    result = []
    for distrib in ENTERPRISE_DISTRIBUTIONS:
        pkgs = list_packages_in_distrib(distrib["codename"])
        result.append({
            **distrib,
            "package_count": len(pkgs),
        })
    return result


def promote_package(name: str, from_dist: str, to_dist: str) -> tuple[bool, str]:
    """
    Promeut un paquet d'une distribution vers une autre via `reprepro copy`.
    """
    rc, stdout, stderr = _reprepro("copy", to_dist, from_dist, name)
    if rc == 0:
        return True, f"{name} promu de {from_dist} vers {to_dist}"
    combined = (stdout + stderr).lower()
    if "already" in combined or "up-to-date" in combined:
        return True, f"{name} est déjà présent dans {to_dist}"
    return False, (stderr.strip() or stdout.strip() or "Erreur reprepro inconnue")


def migrate_all(from_dist: str, to_dist: str) -> tuple[int, list[str], list[str]]:
    """
    Copie TOUS les paquets de from_dist vers to_dist.
    """
    packages = list_packages_in_distrib(from_dist)
    copied, errors = [], []
    for pkg in packages:
        ok, msg = promote_package(pkg["name"], from_dist, to_dist)
        if ok:
            copied.append(pkg["name"])
        else:
            errors.append(f"{pkg['name']}: {msg}")
    return len(copied), copied, errors


def detect_distribution_from_source(source_id: str) -> str:
    return SOURCE_TO_DISTRIB.get(source_id, "jammy")
