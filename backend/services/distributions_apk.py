"""
Gestion du dépôt APK privé pour Alpine Linux.

Structure du dépôt :
    /repos/apk/
      {codename}/          ex: alpine3.20
        main/
          {arch}/          ex: x86_64
            APKINDEX.tar.gz
            {pkg}-{ver}-r{rel}.apk
            {pkg}-{ver}-r{rel}.apk.sig  (optionnel)

Clients Alpine configurent :
    https://repod.example.com/apk/alpine3.20/main

apk(8) cherche alors :
    https://repod.example.com/apk/alpine3.20/main/x86_64/APKINDEX.tar.gz
"""
import hashlib
import io
import logging
import os
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("distributions_apk")

APK_REPO_BASE = Path(os.getenv("APK_REPO_BASE", "/repos/apk"))
POOL_DIR      = Path(os.getenv("POOL_DIR",       "/repos/pool"))

# Versions Alpine supportées
APK_DISTRIBUTIONS = [
    {"codename": "alpine3.18", "name": "Alpine Linux 3.18", "arch": ["x86_64", "aarch64"]},
    {"codename": "alpine3.19", "name": "Alpine Linux 3.19", "arch": ["x86_64", "aarch64"]},
    {"codename": "alpine3.20", "name": "Alpine Linux 3.20", "arch": ["x86_64", "aarch64"]},
    {"codename": "alpine3.21", "name": "Alpine Linux 3.21", "arch": ["x86_64", "aarch64"]},
]

VALID_APK_CODENAMES: set[str] = {d["codename"] for d in APK_DISTRIBUTIONS}

# ── Utilitaires format APK ─────────────────────────────────────────────────────

def _sha1_checksum(path: Path) -> str:
    """Checksum SHA-1 d'un fichier encodé Base64 avec préfixe 'Q1' (format APKINDEX)."""
    import base64
    sha1 = hashlib.sha1(usedforsecurity=False)  # imposé par le format APKINDEX, pas un usage cryptographique
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha1.update(chunk)
    return "Q1" + base64.b64encode(sha1.digest()).decode("ascii")


def _parse_pkginfo_content(content: str) -> dict:
    """Parse le contenu d'un fichier .PKGINFO Alpine."""
    info: dict[str, list[str]] = {}
    for line in content.splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition(" = ")
        key = k.strip()
        val = v.strip()
        if key not in info:
            info[key] = []
        info[key].append(val)
    # Retourner les valeurs uniques (sauf depend/provides/install_if qui sont multi)
    return {k: (v[0] if len(v) == 1 else v) for k, v in info.items()}


def parse_apk_metadata(apk_path: Path) -> dict:
    """
    Extrait les métadonnées d'un fichier .apk Alpine.

    Un .apk est un ou plusieurs flux gzip concaténés :
      Stream 1  : signature RSA (optionnel) — contient .SIGN.RSA.*
      Stream 2  : section contrôle — contient .PKGINFO
      Stream N  : section données — fichiers du paquet

    Retourne un dict avec les clés de .PKGINFO.
    """
    with open(apk_path, "rb") as f:
        raw = f.read()

    # Cherche le .PKGINFO dans chaque flux gzip
    pos = 0
    while pos < len(raw) - 2:
        if raw[pos : pos + 2] != b"\x1f\x8b":
            pos += 1
            continue
        try:
            stream = io.BytesIO(raw[pos:])
            with tarfile.open(fileobj=stream, mode="r:gz") as tf:
                for member in tf.getmembers():
                    if member.name == ".PKGINFO":
                        content = tf.extractfile(member).read().decode("utf-8", errors="replace")
                        return _parse_pkginfo_content(content)
            # Flux gzip lu mais pas de .PKGINFO — avancer d'au moins 1 byte
            pos += max(1, stream.tell())
        except Exception:
            pos += 1

    logger.warning(f"[apk] Impossible d'extraire .PKGINFO de {apk_path.name}")
    return {}


def _apk_filename(meta: dict, apk_path: Path) -> str:
    """Construit le nom canonique du fichier .apk."""
    name = meta.get("pkgname", apk_path.stem)
    ver  = meta.get("pkgver", "0.0.0")
    return f"{name}-{ver}.apk"


# ── Gestion APKINDEX ──────────────────────────────────────────────────────────

def build_apkindex(repo_dir: Path) -> int:
    """
    Reconstruit le fichier APKINDEX.tar.gz dans le répertoire `repo_dir`.

    `repo_dir` doit être un répertoire arch (ex: .../alpine3.20/main/x86_64/).
    Scanne tous les .apk présents, extrait leur .PKGINFO, génère l'index.

    Retourne le nombre de paquets indexés.
    """
    entries: list[str] = []

    apk_files = sorted(repo_dir.glob("*.apk"))
    for apk_path in apk_files:
        try:
            meta    = parse_apk_metadata(apk_path)
            csum    = _sha1_checksum(apk_path)
            s_size  = apk_path.stat().st_size          # compressed size
            i_size  = meta.get("size", "0")            # installed size from .PKGINFO

            lines: list[str] = [
                f"C:{csum}",
                f"P:{meta.get('pkgname', apk_path.stem)}",
                f"V:{meta.get('pkgver', '0.0.0')}",
                f"A:{meta.get('arch', 'x86_64')}",
                f"S:{s_size}",
                f"I:{i_size}",
                f"T:{meta.get('pkgdesc', '')}",
            ]
            if meta.get("url"):
                lines.append(f"U:{meta['url']}")
            if meta.get("license"):
                lines.append(f"L:{meta['license']}")
            if meta.get("builddate"):
                lines.append(f"t:{meta['builddate']}")
            if meta.get("origin"):
                lines.append(f"o:{meta['origin']}")
            if meta.get("maintainer"):
                lines.append(f"m:{meta['maintainer']}")
            if meta.get("commit"):
                lines.append(f"c:{meta['commit']}")
            # Dépendances (peuvent être multiples → list)
            depends = meta.get("depend", [])
            if isinstance(depends, str):
                depends = [depends]
            if depends:
                lines.append(f"D:{' '.join(depends)}")
            # Provides (peuvent être multiples → list)
            provides = meta.get("provides", [])
            if isinstance(provides, str):
                provides = [provides]
            if provides:
                lines.append(f"p:{' '.join(provides)}")

            entries.append("\n".join(lines))
        except Exception as exc:
            logger.warning(f"[apk] Impossible d'indexer {apk_path.name}: {exc}")

    # Construire le contenu APKINDEX
    index_content = ("\n\n".join(entries) + "\n") if entries else ""
    index_bytes   = index_content.encode("utf-8")
    desc_bytes    = b"Repod Private Alpine Linux Repository\n"

    # Écrire APKINDEX.tar.gz (atomique via fichier temp)
    apkindex_path = repo_dir / "APKINDEX.tar.gz"
    tmp_path      = repo_dir / "APKINDEX.tar.gz.tmp"

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="APKINDEX")
        ti.size  = len(index_bytes)
        ti.mtime = int(datetime.now(timezone.utc).timestamp())
        tf.addfile(ti, io.BytesIO(index_bytes))

        ti2 = tarfile.TarInfo(name="DESCRIPTION")
        ti2.size  = len(desc_bytes)
        ti2.mtime = ti.mtime
        tf.addfile(ti2, io.BytesIO(desc_bytes))

    tmp_path.write_bytes(buf.getvalue())
    tmp_path.rename(apkindex_path)   # atomique

    logger.info(f"[apk] APKINDEX rebuild : {len(entries)} paquets dans {repo_dir}")
    return len(entries)


# ── Cycle de vie des distributions ────────────────────────────────────────────

def _repo_dir(codename: str, arch: str = "x86_64") -> Path:
    """Répertoire canonique d'une distribution/arch."""
    return APK_REPO_BASE / codename / "main" / arch


def init_distribution(codename: str) -> tuple[bool, str]:
    """
    Initialise la structure de répertoires pour une distribution Alpine.
    Crée APKINDEX.tar.gz vide si absent.
    """
    if codename not in VALID_APK_CODENAMES:
        return False, f"Distribution inconnue : {codename}"

    for dist in APK_DISTRIBUTIONS:
        if dist["codename"] == codename:
            for arch in dist["arch"]:
                d = _repo_dir(codename, arch)
                d.mkdir(parents=True, exist_ok=True)
                apkindex = d / "APKINDEX.tar.gz"
                if not apkindex.exists():
                    build_apkindex(d)
            return True, f"Distribution {codename} initialisée"

    return False, f"Distribution {codename} non trouvée"


def init_all_distributions() -> dict:
    """Initialise toutes les distributions Alpine."""
    results = []
    for dist in APK_DISTRIBUTIONS:
        ok, msg = init_distribution(dist["codename"])
        results.append({"codename": dist["codename"], "ok": ok, "message": msg})
    return results


# ── Ajout / suppression de paquets ────────────────────────────────────────────

def add_package(apk_path: Path, codename: str, arch: str | None = None) -> tuple[bool, str]:
    """
    Ajoute un paquet .apk au dépôt et reconstruit l'APKINDEX.

    1. Valide le codename
    2. Crée le répertoire si nécessaire
    3. Copie le .apk (le pool/ reste la source de vérité)
    4. Reconstruit APKINDEX.tar.gz

    Le fichier dans pool/ n'est PAS supprimé — il sert pour le manifest et les scans.

    arch : architecture cible. Si omis (None, le cas normal), dérivée
    automatiquement des métadonnées .PKGINFO du fichier lui-même
    (meta["arch"]) — jamais supposée x86_64 par défaut. Bug réel trouvé en
    ajoutant le support arm64 : ni routers/upload.py (upload manuel) ni
    services/importer_apk.py (import) ne passaient jamais ce paramètre, qui
    retombait donc toujours sur l'ancien défaut "x86_64" — un .apk aarch64
    uploadé ou importé atterrissait silencieusement dans le répertoire
    x86_64, corrompant son APKINDEX (fichiers du mauvais arch mélangés à
    l'index d'un autre) sans qu'aucune erreur ne soit jamais levée.
    """
    if codename not in VALID_APK_CODENAMES:
        return False, f"Distribution inconnue : {codename}"

    try:
        meta = parse_apk_metadata(apk_path)
    except Exception:
        meta = {}

    if arch is None:
        arch = meta.get("arch") or "x86_64"

    repo_d = _repo_dir(codename, arch)
    repo_d.mkdir(parents=True, exist_ok=True)

    dest_fn = _apk_filename(meta, apk_path) if meta else apk_path.name

    dest = repo_d / dest_fn
    shutil.copy2(apk_path, dest)
    logger.info(f"[apk] Paquet ajouté : {dest_fn} → {codename}/main/{arch}/")

    n = build_apkindex(repo_d)
    return True, f"Paquet {dest_fn} ajouté ({n} paquets dans l'index)"


def remove_package(
    name: str, version: str, codename: str, arch: str = "x86_64"
) -> tuple[bool, str]:
    """
    Supprime un paquet du dépôt et reconstruit l'APKINDEX.
    Ne supprime PAS le fichier dans pool/ (archivage).
    """
    if codename not in VALID_APK_CODENAMES:
        return False, f"Distribution inconnue : {codename}"

    repo_d = _repo_dir(codename, arch)
    pattern = f"{name}-{version}.apk"
    removed = []

    for f in repo_d.glob(f"{name}*.apk"):
        if f.name == pattern or f.name.startswith(f"{name}-{version}"):
            f.unlink()
            removed.append(f.name)
            logger.info(f"[apk] Supprimé : {f.name} de {codename}/main/{arch}/")

    if not removed:
        return False, f"Paquet {name}-{version}.apk introuvable dans {codename}"

    n = build_apkindex(repo_d)
    return True, f"{len(removed)} fichier(s) supprimé(s), index mis à jour ({n} paquets)"


# ── Statistiques ──────────────────────────────────────────────────────────────

def get_distribution_stats() -> list[dict]:
    """
    Retourne les statistiques par distribution Alpine :
    - Nombre de paquets dans chaque arch
    - Taille totale
    - Timestamp dernière mise à jour de l'APKINDEX
    """
    stats = []
    for dist in APK_DISTRIBUTIONS:
        codename = dist["codename"]
        pkg_count = 0
        total_size = 0
        last_updated = None

        for arch in dist["arch"]:
            d = _repo_dir(codename, arch)
            if d.exists():
                apk_files = list(d.glob("*.apk"))
                pkg_count += len(apk_files)
                total_size += sum(f.stat().st_size for f in apk_files)
                apkindex = d / "APKINDEX.tar.gz"
                if apkindex.exists():
                    ts = apkindex.stat().st_mtime
                    if last_updated is None or ts > last_updated:
                        last_updated = ts

        stats.append({
            "codename":     codename,
            "name":         dist["name"],
            "pkg_type":     "apk",
            "package_count": pkg_count,
            "total_size":   total_size,
            "last_updated": (
                datetime.fromtimestamp(last_updated, tz=timezone.utc).isoformat()
                if last_updated else None
            ),
            "repo_url_path": f"/apk/{codename}/main",
        })

    return stats


def list_packages_in_distrib(codename: str, arch: str = "x86_64") -> list[dict]:
    """Liste les paquets présents dans un dépôt Alpine."""
    repo_d = _repo_dir(codename, arch)
    if not repo_d.exists():
        return []

    packages = []
    for apk_path in sorted(repo_d.glob("*.apk")):
        try:
            meta = parse_apk_metadata(apk_path)
            packages.append({
                "filename": apk_path.name,
                "name":     meta.get("pkgname", apk_path.stem),
                "version":  meta.get("pkgver", "?"),
                "arch":     meta.get("arch", arch),
                "size":     apk_path.stat().st_size,
                "desc":     meta.get("pkgdesc", ""),
                "url":      meta.get("url", ""),
                "license":  meta.get("license", ""),
            })
        except Exception as exc:
            logger.warning(f"[apk] Erreur parsing {apk_path.name}: {exc}")

    return packages
