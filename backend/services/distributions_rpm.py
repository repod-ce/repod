"""
Gestion des distributions RPM (createrepo_c).
Distributions : AlmaLinux 8, Rocky Linux 8, CentOS Stream 9, Oracle Linux 8,
                Fedora, openSUSE Leap 15.5/15.6/Leap/Tumbleweed.
createrepo_c est exécuté directement dans le container backend.
"""
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_BASE = Path(os.getenv("REPO_BASE", "/repos"))
POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))
GNUPG_HOME = os.getenv("GNUPG_HOME", "/repos/gnupg")

RPM_DISTRIBUTIONS = [
    # ── Famille RHEL 8 ────────────────────────────────────────────────────────
    {
        "codename": "almalinux8",
        "name": "AlmaLinux 8",
        "full_name": "AlmaLinux 8 — Stone Smilodon",
        "os": "almalinux",
        "version": "8",
        "badge": "RHEL-compat",
        "color": "blue",
        "package_manager": "dnf",
        "grype_distro": "almalinux:8",
    },
    {
        "codename": "almalinux9",
        "name": "AlmaLinux 9",
        "full_name": "AlmaLinux 9 — Midnight Oncilla",
        "os": "almalinux",
        "version": "9",
        "badge": "RHEL-compat",
        "color": "blue",
        "package_manager": "dnf",
        "grype_distro": "almalinux:9",
    },
    {
        "codename": "rocky8",
        "name": "Rocky Linux 8",
        "full_name": "Rocky Linux 8 — Green Obsidian",
        "os": "rocky",
        "version": "8",
        "badge": "RHEL-compat",
        "color": "green",
        "package_manager": "dnf",
        "grype_distro": "rockylinux:8",
    },
    {
        "codename": "rocky9",
        "name": "Rocky Linux 9",
        "full_name": "Rocky Linux 9 — Blue Onyx",
        "os": "rocky",
        "version": "9",
        "badge": "RHEL-compat",
        "color": "green",
        "package_manager": "dnf",
        "grype_distro": "rockylinux:9",
    },
    {
        "codename": "centos-stream9",
        "name": "CentOS Stream 9",
        "full_name": "CentOS Stream 9",
        "os": "centos",
        "version": "9",
        "badge": "Upstream RHEL",
        "color": "purple",
        "package_manager": "dnf",
        "grype_distro": "centos:9",
    },
    {
        "codename": "oraclelinux8",
        "name": "Oracle Linux 8",
        "full_name": "Oracle Linux 8 — Slim Bullseye",
        "os": "oraclelinux",
        "version": "8",
        "badge": "RHEL-compat",
        "color": "red",
        "package_manager": "dnf",
        "grype_distro": "oraclelinux:8",
    },
    # ── Fedora ────────────────────────────────────────────────────────────────
    {
        "codename": "fedora",
        "name": "Fedora",
        "full_name": "Fedora 42",
        "os": "fedora",
        "version": "42",
        "badge": "Upstream",
        "color": "blue",
        "package_manager": "dnf",
        "grype_distro": "fedora:42",
    },
    # ── openSUSE ──────────────────────────────────────────────────────────────
    {
        "codename": "opensuse-leap-15.6",
        "name": "openSUSE Leap 15.6",
        "full_name": "openSUSE Leap 15.6",
        "os": "opensuse",
        "version": "15.6",
        "badge": "SUSE-stable",
        "color": "teal",
        "package_manager": "zypper",
        "grype_distro": "opensuse/leap:15.6",
    },
    {
        "codename": "opensuse-tumbleweed",
        "name": "openSUSE Tumbleweed",
        "full_name": "openSUSE Tumbleweed (rolling release)",
        "os": "opensuse",
        "version": "tumbleweed",
        "badge": "Rolling",
        "color": "orange",
        "package_manager": "zypper",
        "grype_distro": "opensuse/tumbleweed:latest",
    },
]

VALID_CODENAMES = {d["codename"] for d in RPM_DISTRIBUTIONS}

ARCHITECTURES = ["x86_64", "aarch64", "noarch", "i686"]

# Mapping source_id (package_index.py) → codename distribution interne
SOURCE_TO_DISTRIB: dict[str, str] = {
    # AlmaLinux
    "almalinux8-baseos":          "almalinux8",
    "almalinux8-appstream":       "almalinux8",
    "almalinux8-extras":          "almalinux8",
    "almalinux9-baseos":          "almalinux9",
    "almalinux9-appstream":       "almalinux9",
    # Rocky Linux
    "rocky8-baseos":              "rocky8",
    "rocky8-appstream":           "rocky8",
    "rocky9-baseos":              "rocky9",
    "rocky9-appstream":           "rocky9",
    # CentOS Stream
    "centos-stream9-baseos":      "centos-stream9",
    "centos-stream9-appstream":   "centos-stream9",
    # Oracle Linux
    "oraclelinux8-baseos":        "oraclelinux8",
    "oraclelinux8-appstream":     "oraclelinux8",
    "oraclelinux9-baseos":        "oraclelinux8",   # pas de distro oraclelinux9 encore
    # Fedora + EPEL
    "fedora42":                   "fedora",
    "fedora42-updates":           "fedora",
    "epel8":                      "almalinux8",
    "epel9":                      "rocky9",
    # openSUSE
    "opensuse-leap-15.6-oss":     "opensuse-leap-15.6",
    "opensuse-leap-15.6-updates": "opensuse-leap-15.6",
    "opensuse-tumbleweed-oss":    "opensuse-tumbleweed",
}


def _gpg_env() -> dict:
    return {**os.environ, "GNUPGHOME": GNUPG_HOME}


def _get_arch_from_rpm(rpm_path: str) -> str:
    """Lit l'architecture depuis les métadonnées d'un fichier .rpm."""
    result = subprocess.run(
        ["rpm", "-qp", "--queryformat", "%{ARCH}", "--nosignature", "--noplugins", rpm_path],
        capture_output=True, text=True,
    )
    arch = result.stdout.strip()
    return arch if arch in ARCHITECTURES else "x86_64"


def _distrib_dir(codename: str, arch: str) -> Path:
    return REPO_BASE / codename / arch


def _run_createrepo(distrib_dir: Path) -> tuple[int, str, str]:
    """Lance createrepo_c --update sur un répertoire distribution/arch."""
    cmd = ["createrepo_c", "--update", "--quiet", str(distrib_dir)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def _sign_repomd(distrib_dir: Path) -> bool:
    """Signe le repomd.xml avec GPG (détached signature ASCII)."""
    repomd = distrib_dir / "repodata" / "repomd.xml"
    repomd_asc = distrib_dir / "repodata" / "repomd.xml.asc"
    if not repomd.exists():
        return False
    result = subprocess.run(
        ["gpg", "--batch", "--yes", "--detach-sign", "--armor",
         "--output", str(repomd_asc), str(repomd)],
        capture_output=True, text=True, env=_gpg_env(),
    )
    return result.returncode == 0


def add_rpm_to_distrib(rpm_filename: str, codename: str) -> tuple[bool, str]:
    """
    Copie le .rpm depuis pool/ vers le répertoire distrib/arch/,
    puis relance createrepo_c et signe repomd.xml.

    Bug réel trouvé/corrigé en vérifiant le support arm64 en direct sur .20 :
    cherchait le fichier source sous REPO_BASE/pool (REPO_BASE vaut
    /repos/rpm en production — voir docker-compose.yaml, "répertoires
    createrepo_c" — donc /repos/rpm/pool/), alors que le pool RÉEL et
    partagé (utilisé par importer_rpm.py, routers/upload.py, et déjà
    correctement fourni comme variable d'env séparée POOL_DIR par
    docker-compose.yaml) est /repos/pool/. REPO_BASE sert UNIQUEMENT de
    base aux arborescences createrepo_c par distribution
    (REPO_BASE/{codename}/{arch}/) — jamais au pool lui-même, un concept
    distinct qui a toujours eu sa propre variable d'env, juste jamais lue
    ici. Confirmé en direct : le téléchargement/la validation d'un paquet
    RPM réussissaient, mais createrepo_c échouait ensuite avec "Fichier
    introuvable dans pool/" pour x86_64 ET aarch64 — pas spécifique à
    l'architecture.
    """
    rpm_pool_path = POOL_DIR / rpm_filename

    if not rpm_pool_path.exists():
        return False, f"Fichier introuvable dans pool/ : {rpm_filename}"

    # Déterminer l'architecture depuis le nom de fichier
    arch = "x86_64"
    for candidate in ARCHITECTURES:
        if f".{candidate}.rpm" in rpm_filename:
            arch = candidate
            break

    distrib_path = _distrib_dir(codename, arch)
    distrib_path.mkdir(parents=True, exist_ok=True)

    dest = distrib_path / rpm_filename
    import shutil
    shutil.copy2(str(rpm_pool_path), str(dest))

    rc, stdout, stderr = _run_createrepo(distrib_path)
    if rc != 0:
        return False, f"createrepo_c a échoué (code {rc}) : {stderr.strip()}"

    _sign_repomd(distrib_path)

    return True, f"{rpm_filename} ajouté dans {codename}/{arch}"


def _open_compressed(path: Path) -> bytes:
    """Ouvre un fichier compressé .gz, .zst ou non-compressé et retourne les bytes."""
    suffix = path.suffix.lower()
    if suffix == ".gz":
        import gzip
        with gzip.open(str(path), "rb") as f:
            return f.read()
    elif suffix == ".zst":
        import zstandard
        dctx = zstandard.ZstdDecompressor()
        with open(str(path), "rb") as f:
            return dctx.decompress(f.read(), max_output_size=256 * 1024 * 1024)
    else:
        return path.read_bytes()


def list_packages_in_distrib(codename: str, arch: str = "x86_64") -> list[dict]:
    """
    Liste les paquets dans une distribution en parsant primary.xml de createrepo_c.
    Supporte les compressions .gz et .zst (format moderne de createrepo_c).
    """
    distrib_path = _distrib_dir(codename, arch)
    repomd = distrib_path / "repodata" / "repomd.xml"

    if not repomd.exists():
        return []

    try:
        tree = ET.parse(str(repomd))
        root = tree.getroot()
        ns = {"r": "http://linux.duke.edu/metadata/repo"}

        primary_href = None
        for data in root.findall("r:data", ns):
            if data.get("type") == "primary":
                loc = data.find("r:location", ns)
                if loc is not None:
                    primary_href = loc.get("href")
                    break

        if not primary_href:
            return []

        primary_path = distrib_path / primary_href
        if not primary_path.exists():
            return []

        primary_xml = _open_compressed(primary_path)

        pkg_tree = ET.fromstring(primary_xml)
        pkg_ns = {"p": "http://linux.duke.edu/metadata/common"}
        packages = []
        seen = set()

        for pkg in pkg_tree.findall("p:package", pkg_ns):
            name_el = pkg.find("p:name", pkg_ns)
            version_el = pkg.find("p:version", pkg_ns)
            arch_el = pkg.find("p:arch", pkg_ns)

            if name_el is None:
                continue

            name = name_el.text or ""
            version = ""
            if version_el is not None:
                ver = version_el.get("ver", "")
                rel = version_el.get("rel", "")
                epoch = version_el.get("epoch", "0")
                version = f"{ver}-{rel}" if rel else ver
                if epoch and epoch != "0":
                    version = f"{epoch}:{version}"

            arch_val = arch_el.text if arch_el is not None else arch

            if name and name not in seen:
                seen.add(name)
                packages.append({"name": name, "version": version, "arch": arch_val})

        return sorted(packages, key=lambda p: p["name"])

    except Exception:
        return []


def get_distribution_stats() -> list[dict]:
    """Retourne la liste des distributions avec leur nombre de paquets."""
    result = []
    for distrib in RPM_DISTRIBUTIONS:
        codename = distrib["codename"]
        # Compter les paquets dans toutes les architectures
        total = 0
        for arch in ["x86_64", "aarch64", "noarch"]:
            pkgs = list_packages_in_distrib(codename, arch)
            total += len(pkgs)
        result.append({**distrib, "package_count": total})
    return result


def promote_package(name: str, from_dist: str, to_dist: str) -> tuple[bool, str]:
    """
    Copie un paquet d'une distribution vers une autre.
    Parcourt toutes les architectures.
    """
    import shutil
    copied = 0
    errors = []

    for arch in ["x86_64", "aarch64", "noarch", "i686"]:
        src_dir = _distrib_dir(from_dist, arch)
        dst_dir = _distrib_dir(to_dist, arch)

        rpms = list(src_dir.glob(f"{name}-*.rpm"))
        if not rpms:
            continue

        dst_dir.mkdir(parents=True, exist_ok=True)
        for rpm in rpms:
            shutil.copy2(str(rpm), str(dst_dir / rpm.name))
            copied += 1

        rc, _, stderr = _run_createrepo(dst_dir)
        if rc != 0:
            errors.append(f"{arch}: createrepo_c échoué — {stderr.strip()}")
        else:
            _sign_repomd(dst_dir)

    if copied == 0:
        return False, f"Paquet '{name}' introuvable dans {from_dist}"
    if errors:
        return False, "; ".join(errors)
    return True, f"{name} promu de {from_dist} vers {to_dist} ({copied} fichier(s))"


def migrate_all(from_dist: str, to_dist: str) -> tuple[int, list[str], list[str]]:
    """Copie TOUS les paquets de from_dist vers to_dist."""
    packages = list_packages_in_distrib(from_dist)
    copied, errors = [], []
    for pkg in packages:
        ok, msg = promote_package(pkg["name"], from_dist, to_dist)
        if ok:
            copied.append(pkg["name"])
        else:
            errors.append(f"{pkg['name']}: {msg}")
    return len(copied), copied, errors


def init_distribution(codename: str) -> tuple[bool, str]:
    """Initialise un dépôt vide pour une distribution donnée."""
    errors = []
    for arch in ["x86_64", "aarch64", "noarch"]:
        distrib_path = _distrib_dir(codename, arch)
        try:
            distrib_path.mkdir(parents=True, exist_ok=True)
        except PermissionError as exc:
            # Le dossier existe mais est owned par root (Docker bind-mount auto-créé).
            # L'entrypoint.sh corrige cela au prochain redémarrage via chown + mkdir.
            errors.append(f"{arch}: permission refusée — {exc}")
            continue

        repomd = distrib_path / "repodata" / "repomd.xml"
        if not repomd.exists():
            rc, _, stderr = _run_createrepo(distrib_path)
            if rc != 0:
                errors.append(f"{arch}: {stderr.strip()}")
            else:
                _sign_repomd(distrib_path)

    if errors:
        return False, "; ".join(errors)
    return True, f"{codename} initialisé"


def remove_rpm_from_distrib(name: str) -> tuple[bool, str]:
    """
    Supprime toutes les versions d'un paquet de toutes les distributions et architectures.
    Reconstruit repomd.xml via createrepo_c après suppression.
    """
    removed = 0
    errors: list[str] = []

    for distrib in RPM_DISTRIBUTIONS:
        codename = distrib["codename"]
        for arch in ["x86_64", "aarch64", "noarch", "i686"]:
            distrib_dir = _distrib_dir(codename, arch)
            if not distrib_dir.exists():
                continue
            # Cherche toutes les variantes du paquet : name-version-release.arch.rpm
            rpms = list(distrib_dir.glob(f"{name}-*.rpm"))
            if not rpms:
                continue
            for rpm in rpms:
                try:
                    rpm.unlink(missing_ok=True)
                    removed += 1
                except Exception as exc:
                    errors.append(f"{codename}/{arch}/{rpm.name}: {exc}")
            # Reconstruire les métadonnées après suppression
            rc, _, stderr = _run_createrepo(distrib_dir)
            if rc != 0:
                errors.append(f"{codename}/{arch}: createrepo_c — {stderr.strip()[:100]}")
            else:
                _sign_repomd(distrib_dir)

    if removed == 0:
        return False, f"Paquet '{name}' introuvable dans les distributions RPM"
    if errors:
        return False, f"{removed} fichier(s) supprimé(s), erreurs: {'; '.join(errors)}"
    return True, f"{name} supprimé de toutes les distributions ({removed} fichier(s))"


def detect_distribution_from_source(source_id: str) -> str:
    return SOURCE_TO_DISTRIB.get(source_id, "almalinux8")


def get_distrib_info(codename: str) -> dict | None:
    return next((d for d in RPM_DISTRIBUTIONS if d["codename"] == codename), None)
