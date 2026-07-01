"""
Index local de métadonnées APT.
Télécharge et parse Packages.gz depuis les repos upstream → PostgreSQL.
Permet la recherche sans connexion internet permanente.
"""
import gzip
import lzma
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text

from db.engine import db_conn

# Sources APT configurées
# Ubuntu : main (system) + universe (community/tiers — contient la très grande majorité des paquets Perl, Python, etc.)
# Debian : main + contrib + non-free
DEFAULT_SOURCES = [
    # ── Ubuntu 22.04 Jammy ───────────────────────────────────────────────────
    {
        "id": "ubuntu-jammy",
        "label": "Ubuntu 22.04 (Jammy) main",
        "url": "https://archive.ubuntu.com/ubuntu/dists/jammy/main/binary-amd64/Packages.gz",
        "distro": "jammy",
        "component": "main",
        "arch": "amd64",
    },
    {
        "id": "ubuntu-jammy-universe",
        "label": "Ubuntu 22.04 (Jammy) universe",
        "url": "https://archive.ubuntu.com/ubuntu/dists/jammy/universe/binary-amd64/Packages.gz",
        "distro": "jammy",
        "component": "universe",
        "arch": "amd64",
    },
    {
        "id": "ubuntu-jammy-updates",
        "label": "Ubuntu 22.04 Updates (main)",
        "url": "https://archive.ubuntu.com/ubuntu/dists/jammy-updates/main/binary-amd64/Packages.gz",
        "distro": "jammy-updates",
        "component": "main",
        "arch": "amd64",
    },
    {
        "id": "ubuntu-jammy-updates-universe",
        "label": "Ubuntu 22.04 Updates (universe)",
        "url": "https://archive.ubuntu.com/ubuntu/dists/jammy-updates/universe/binary-amd64/Packages.gz",
        "distro": "jammy-updates",
        "component": "universe",
        "arch": "amd64",
    },
    # ── Ubuntu 24.04 Noble ───────────────────────────────────────────────────
    {
        "id": "ubuntu-noble",
        "label": "Ubuntu 24.04 (Noble) main",
        "url": "https://archive.ubuntu.com/ubuntu/dists/noble/main/binary-amd64/Packages.gz",
        "distro": "noble",
        "component": "main",
        "arch": "amd64",
    },
    {
        "id": "ubuntu-noble-universe",
        "label": "Ubuntu 24.04 (Noble) universe",
        "url": "https://archive.ubuntu.com/ubuntu/dists/noble/universe/binary-amd64/Packages.gz",
        "distro": "noble",
        "component": "universe",
        "arch": "amd64",
    },
    {
        "id": "ubuntu-noble-updates",
        "label": "Ubuntu 24.04 Updates (main)",
        "url": "https://archive.ubuntu.com/ubuntu/dists/noble-updates/main/binary-amd64/Packages.gz",
        "distro": "noble-updates",
        "component": "main",
        "arch": "amd64",
        "security": True,
    },
    {
        "id": "ubuntu-noble-updates-universe",
        "label": "Ubuntu 24.04 Updates (universe)",
        "url": "https://archive.ubuntu.com/ubuntu/dists/noble-updates/universe/binary-amd64/Packages.gz",
        "distro": "noble-updates",
        "component": "universe",
        "arch": "amd64",
        "security": True,
    },
    # ── Ubuntu 20.04 Focal ───────────────────────────────────────────────────
    {
        "id": "ubuntu-focal",
        "label": "Ubuntu 20.04 (Focal) main",
        "url": "https://archive.ubuntu.com/ubuntu/dists/focal/main/binary-amd64/Packages.gz",
        "distro": "focal",
        "component": "main",
        "arch": "amd64",
    },
    {
        "id": "ubuntu-focal-universe",
        "label": "Ubuntu 20.04 (Focal) universe",
        "url": "https://archive.ubuntu.com/ubuntu/dists/focal/universe/binary-amd64/Packages.gz",
        "distro": "focal",
        "component": "universe",
        "arch": "amd64",
    },
    {
        "id": "ubuntu-focal-updates",
        "label": "Ubuntu 20.04 Updates (main)",
        "url": "https://archive.ubuntu.com/ubuntu/dists/focal-updates/main/binary-amd64/Packages.gz",
        "distro": "focal-updates",
        "component": "main",
        "arch": "amd64",
        "security": True,
    },
    {
        "id": "ubuntu-focal-updates-universe",
        "label": "Ubuntu 20.04 Updates (universe)",
        "url": "https://archive.ubuntu.com/ubuntu/dists/focal-updates/universe/binary-amd64/Packages.gz",
        "distro": "focal-updates",
        "component": "universe",
        "arch": "amd64",
        "security": True,
    },
    # ── Debian 12 Bookworm ───────────────────────────────────────────────────
    {
        "id": "debian-bookworm",
        "label": "Debian 12 (Bookworm) main",
        "url": "https://deb.debian.org/debian/dists/bookworm/main/binary-amd64/Packages.gz",
        "distro": "bookworm",
        "component": "main",
        "arch": "amd64",
    },
    {
        "id": "debian-bookworm-contrib",
        "label": "Debian 12 (Bookworm) contrib",
        "url": "https://deb.debian.org/debian/dists/bookworm/contrib/binary-amd64/Packages.gz",
        "distro": "bookworm",
        "component": "contrib",
        "arch": "amd64",
    },
    {
        "id": "debian-bookworm-non-free",
        "label": "Debian 12 (Bookworm) non-free",
        "url": "https://deb.debian.org/debian/dists/bookworm/non-free/binary-amd64/Packages.gz",
        "distro": "bookworm",
        "component": "non-free",
        "arch": "amd64",
    },
    # ── Sources de sécurité ──────────────────────────────────────────────────
    {
        "id": "ubuntu-jammy-security",
        "label": "Ubuntu 22.04 Security",
        "url": "https://security.ubuntu.com/ubuntu/dists/jammy-security/main/binary-amd64/Packages.gz",
        "distro": "jammy",
        "component": "main",
        "arch": "amd64",
        "security": True,
    },
    {
        "id": "ubuntu-jammy-security-universe",
        "label": "Ubuntu 22.04 Security (universe)",
        "url": "https://security.ubuntu.com/ubuntu/dists/jammy-security/universe/binary-amd64/Packages.gz",
        "distro": "jammy",
        "component": "universe",
        "arch": "amd64",
        "security": True,
    },
    {
        "id": "ubuntu-noble-security",
        "label": "Ubuntu 24.04 Security",
        "url": "https://security.ubuntu.com/ubuntu/dists/noble-security/main/binary-amd64/Packages.gz",
        "distro": "noble",
        "component": "main",
        "arch": "amd64",
        "security": True,
    },
    {
        "id": "ubuntu-noble-security-universe",
        "label": "Ubuntu 24.04 Security (universe)",
        "url": "https://security.ubuntu.com/ubuntu/dists/noble-security/universe/binary-amd64/Packages.gz",
        "distro": "noble",
        "component": "universe",
        "arch": "amd64",
        "security": True,
    },
    {
        "id": "ubuntu-focal-security",
        "label": "Ubuntu 20.04 Security",
        "url": "https://security.ubuntu.com/ubuntu/dists/focal-security/main/binary-amd64/Packages.gz",
        "distro": "focal",
        "component": "main",
        "arch": "amd64",
        "security": True,
    },
    {
        "id": "ubuntu-focal-security-universe",
        "label": "Ubuntu 20.04 Security (universe)",
        "url": "https://security.ubuntu.com/ubuntu/dists/focal-security/universe/binary-amd64/Packages.gz",
        "distro": "focal",
        "component": "universe",
        "arch": "amd64",
        "security": True,
    },
    {
        "id": "debian-bookworm-security",
        "label": "Debian 12 Security",
        "url": "https://security.debian.org/debian-security/dists/bookworm-security/main/binary-amd64/Packages.xz",
        "distro": "bookworm",
        "component": "main",
        "arch": "amd64",
        "security": True,
    },
    {
        "id": "debian-bookworm-updates",
        "label": "Debian 12 Updates",
        "url": "https://deb.debian.org/debian/dists/bookworm-updates/main/binary-amd64/Packages.xz",
        "distro": "bookworm-updates",
        "component": "main",
        "arch": "amd64",
        "security": True,
    },
]


def init_db():
    """No-op — le schéma est géré par Alembic (db/tables.py)."""
    pass


def _decompress(data: bytes, url: str) -> str:
    """Décompresse selon l'extension de l'URL (.gz, .xz, ou pas de compression)."""
    if url.endswith(".xz"):
        return lzma.decompress(data).decode("utf-8", errors="replace")
    if url.endswith(".gz"):
        return gzip.decompress(data).decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


def _parse_packages_gz(gz_data: bytes, source: dict) -> list[dict]:
    """Parse le contenu d'un Packages(.gz/.xz) en liste de dicts."""
    try:
        content = _decompress(gz_data, source["url"])
    except Exception as e:
        raise ValueError(f"Impossible de décompresser le fichier Packages : {e}")

    packages = []
    current = {}

    for line in content.splitlines():
        if line == "":
            if current.get("name"):
                current["source_id"] = source["id"]
                current["distro"] = source["distro"]
                current["synced_at"] = datetime.now(timezone.utc).isoformat()
                current["security"] = bool(source.get("security", False))
                packages.append(current)
            current = {}
        elif line.startswith("Package: "):
            current["name"] = line[9:].strip()
        elif line.startswith("Version: "):
            current["version"] = line[9:].strip()
        elif line.startswith("Architecture: "):
            current["arch"] = line[14:].strip()
        elif line.startswith("Section: "):
            current["section"] = line[9:].strip()
        elif line.startswith("Description: "):
            current["description"] = line[13:].strip()
        elif line.startswith("Depends: "):
            current["depends"] = line[9:].strip()
        elif line.startswith("Pre-Depends: "):
            # Fusionner Pre-Depends avec Depends pour la résolution
            existing_dep = current.get("depends", "")
            predep = line[13:].strip()
            current["depends"] = f"{existing_dep}, {predep}" if existing_dep else predep
        elif line.startswith("Provides: "):
            current["provides"] = line[10:].strip()
        elif line.startswith("Filename: "):
            current["filename"] = line[10:].strip()
        elif line.startswith("Size: "):
            try:
                current["size"] = int(line[6:].strip())
            except ValueError:
                pass
        elif line.startswith("SHA256: "):
            current["sha256"] = line[8:].strip()
        elif line.startswith("Installed-Size: "):
            try:
                current["installed_size"] = int(line[16:].strip())
            except ValueError:
                pass
        elif line.startswith("Maintainer: "):
            current["maintainer"] = line[12:].strip()

    if current.get("name"):
        current["source_id"] = source["id"]
        current["distro"] = source["distro"]
        current["synced_at"] = datetime.now(timezone.utc).isoformat()
        current["security"] = bool(source.get("security", False))
        packages.append(current)

    return packages


def sync_source(source: dict) -> dict:
    """
    Télécharge et indexe Packages.gz pour une source donnée.
    Retourne un résumé du résultat.
    """
    source_id = source["id"]

    try:
        req = urllib.request.Request(
            source["url"],
            headers={"User-Agent": "APT-Repo-Manager/2.0"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            gz_data = resp.read()

        packages = _parse_packages_gz(gz_data, source)

        _defaults = {
            "arch": None, "section": None, "description": None,
            "depends": None, "provides": None, "filename": None, "size": None,
            "sha256": None, "installed_size": None, "maintainer": None,
            "security": False,
        }
        for pkg in packages:
            for k, v in _defaults.items():
                pkg.setdefault(k, v)

        with db_conn() as conn:
            conn.execute(text("DELETE FROM packages WHERE source_id = :source_id"), {"source_id": source_id})
            if packages:
                conn.execute(text("""
                    INSERT INTO packages
                    (source_id, name, version, arch, section, description,
                     depends, provides, filename, size, sha256, installed_size, maintainer, distro, synced_at, security)
                    VALUES
                    (:source_id, :name, :version, :arch, :section, :description,
                     :depends, :provides, :filename, :size, :sha256, :installed_size, :maintainer, :distro, :synced_at, :security)
                """), packages)
            conn.execute(text("""
                INSERT INTO sync_status (source_id, label, last_sync, pkg_count, status, error)
                VALUES (:source_id, :label, :last_sync, :pkg_count, 'ok', NULL)
                ON CONFLICT (source_id) DO UPDATE SET
                    label = EXCLUDED.label,
                    last_sync = EXCLUDED.last_sync,
                    pkg_count = EXCLUDED.pkg_count,
                    status = 'ok',
                    error = NULL
            """), {
                "source_id": source_id,
                "label": source["label"],
                "last_sync": datetime.now(timezone.utc).isoformat(),
                "pkg_count": len(packages),
            })

        return {
            "source_id": source_id,
            "label": source["label"],
            "status": "ok",
            "pkg_count": len(packages),
        }

    except urllib.error.URLError as e:
        error_msg = str(e)
        try:
            with db_conn() as conn:
                conn.execute(text("""
                    INSERT INTO sync_status (source_id, label, last_sync, pkg_count, status, error)
                    VALUES (:source_id, :label, :last_sync, 0, 'error', :error)
                    ON CONFLICT (source_id) DO UPDATE SET
                        label = EXCLUDED.label,
                        last_sync = EXCLUDED.last_sync,
                        pkg_count = 0,
                        status = 'error',
                        error = EXCLUDED.error
                """), {
                    "source_id": source_id,
                    "label": source["label"],
                    "last_sync": datetime.now(timezone.utc).isoformat(),
                    "error": error_msg,
                })
        except Exception:
            pass
        return {"source_id": source_id, "label": source["label"], "status": "error", "error": error_msg}

    except Exception as e:
        return {"source_id": source_id, "label": source["label"], "status": "error", "error": str(e)}


def sync_all() -> list[dict]:
    """Synchronise toutes les sources configurées."""
    results = []
    for source in DEFAULT_SOURCES:
        results.append(sync_source(source))
    return results


def get_sync_status() -> list[dict]:
    """Retourne le statut de synchronisation de chaque source."""
    with db_conn() as conn:
        rows = conn.execute(text("SELECT * FROM sync_status")).mappings().fetchall()
        synced = {r["source_id"]: dict(r) for r in rows}

    result = []
    for source in DEFAULT_SOURCES:
        sid = source["id"]
        is_security = source.get("security", False)
        if sid in synced:
            entry = dict(synced[sid])
            entry["security"] = is_security
            result.append(entry)
        else:
            result.append({
                "source_id": sid,
                "label": source["label"],
                "last_sync": None,
                "pkg_count": 0,
                "status": "never",
                "error": None,
                "security": is_security,
            })
    return result


def list_packages_by_source(source_id: str, limit: int = 1000, offset: int = 0) -> list[dict]:
    """
    Retourne tous les paquets indexés pour une source donnée, paginés.
    Utilisé par le mirroir planifié pour itérer sur l'ensemble du dépôt upstream.
    """
    with db_conn() as conn:
        rows = conn.execute(text("""
            SELECT name, version, arch, section, description, depends,
                   filename, size, sha256, distro, source_id, synced_at, security
            FROM packages
            WHERE source_id = :source_id
            ORDER BY name ASC
            LIMIT :limit OFFSET :offset
        """), {"source_id": source_id, "limit": limit, "offset": offset}).mappings().fetchall()
    return [{**dict(r), "format": "deb"} for r in rows]


def search_packages(query: str, limit: int = 30, source_id: str = None, distro: str = None) -> list[dict]:
    """
    Recherche des paquets dans l'index local par nom ou description.
    Prioritise les correspondances exactes sur le nom.
    distro : filtrer par codename (ex: "jammy" couvre jammy, jammy-updates, jammy-security).
    """
    query = query.strip()
    if not query:
        return []

    with db_conn() as conn:
        rows = conn.execute(text("""
            SELECT name, version, arch, section, description, depends,
                   size, sha256, distro, source_id, synced_at, security
            FROM packages
            WHERE (LOWER(name) LIKE LOWER(:q_wild) OR LOWER(description) LIKE LOWER(:q_wild))
            AND (:source_id IS NULL OR source_id = :source_id)
            AND (:distro IS NULL OR distro LIKE :distro_pattern)
            ORDER BY
                CASE
                    WHEN name = :q           THEN 0
                    WHEN LOWER(name) LIKE LOWER(:q_prefix) THEN 1
                    ELSE                          2
                END,
                name ASC
            LIMIT :limit
        """), {
            "q_wild": f"%{query}%",
            "q": query,
            "q_prefix": f"{query}%",
            "source_id": source_id,
            "limit": limit,
            "distro": distro,
            "distro_pattern": f"{distro}%" if distro else None,
        }).mappings().fetchall()

    return [{**dict(r), "format": "deb"} for r in rows]


def _find_by_provides(conn, name: str, source_id: str = None):
    """
    Cherche un paquet qui déclare `name` dans son champ Provides.
    Utilise quatre patterns pour éviter les faux positifs avec LIKE :
      - début de la liste     : "name,"  ou "name ("
      - milieu de la liste    : ", name," ou ", name ("
      - fin de la liste       : ", name"
      - seul élément          : exact match
    Les noms Provides sont séparés par ", " et peuvent avoir une version "(= x)".
    """
    patterns = [
        f"{name},%",
        f"{name} (%",
        f"%, {name},%",
        f"%, {name} (%",
        f"%, {name}",
        name,
    ]
    for pat in patterns:
        row = conn.execute(text("""
            SELECT * FROM packages
            WHERE LOWER(provides) LIKE LOWER(:pat)
            AND (:source_id IS NULL OR source_id = :source_id)
            LIMIT 1
        """), {"pat": pat, "source_id": source_id}).mappings().fetchone()
        if row:
            return row
    return None


def get_package_info(name: str, source_id: str = None) -> dict | None:
    """
    Retourne les infos complètes d'un paquet depuis l'index.
    Cherche d'abord par nom exact, puis dans le champ Provides
    pour les paquets virtuels (ex: perlapi-5.34.0, libssl).
    """
    with db_conn() as conn:
        row = conn.execute(text("""
            SELECT * FROM packages
            WHERE name = :name
            AND (:source_id IS NULL OR source_id = :source_id)
            LIMIT 1
        """), {"name": name, "source_id": source_id}).mappings().fetchone()
        if not row:
            row = _find_by_provides(conn, name, source_id)
    return {**dict(row), "format": "deb"} if row else None


def get_package_info_for_distro(name: str, distro: str | None) -> dict | None:
    """
    Comme get_package_info(), mais privilégie la distribution `distro`
    (ex: "jammy") : parmi toutes les sources indexées pour cette distro
    (main, universe, security, ...), retourne la première correspondance.
    Fallback sur get_package_info(name) si `distro` est absent/None ou si
    aucune ligne ne correspond à cette distro.
    """
    if distro:
        with db_conn() as conn:
            row = conn.execute(text("""
                SELECT * FROM packages
                WHERE name = :name AND distro = :distro
                LIMIT 1
            """), {"name": name, "distro": distro}).mappings().fetchone()
        if row:
            return {**dict(row), "format": "deb"}

    return get_package_info(name)


def is_indexed() -> bool:
    """Retourne True si l'index contient au moins un paquet."""
    with db_conn() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM packages WHERE source_id IS NOT NULL")).scalar()
    return (count or 0) > 0
