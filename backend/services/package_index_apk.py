"""
Index local de métadonnées APK (Alpine Linux).

Architecture Alpine :
  - Chaque dépôt Alpine est un répertoire avec un fichier APKINDEX.tar.gz
  - Ce fichier est un tar.gz contenant le fichier APKINDEX
  - Format APKINDEX : stanzas séparées par des lignes vides
    P:nom-du-paquet
    V:version
    A:arch (x86_64, aarch64…)
    S:taille-archive-octets
    I:taille-installée-octets
    T:description
    U:url-homepage
    L:licence
    o:paquet-source (origine)
    m:mainteneur
    t:timestamp-build
    c:commit-hash
    D:dépendances (espace séparées)
    p:provides (espace séparées)

Interface compatible avec package_index_apt.py :
  DEFAULT_SOURCES, sync_source, sync_all, get_sync_status, is_indexed,
  search_packages, get_package_info, init_db
"""
import io
import tarfile
import urllib.error
import urllib.request
from datetime import datetime, timezone

from sqlalchemy import text

from db.engine import db_conn

# ─── Sources APK configurées ─────────────────────────────────────────────────
#
# Alpine Linux utilise dl-cdn.alpinelinux.org (CDN Fastly mondial).
# Chaque version a : main (paquets stables officiels) et community (contributeurs).
# Le dossier security (edge) n'existe pas sur les branches stables — les patchs
# de sécurité sont intégrés directement dans main.
# ─────────────────────────────────────────────────────────────────────────────

_ALPINE_CDN = "https://dl-cdn.alpinelinux.org/alpine"

DEFAULT_SOURCES = [
    # ── Alpine 3.21 (LTS actuelle) ────────────────────────────────────────────
    {
        "id": "alpine3.21-main",
        "label": "Alpine 3.21 — main",
        "apkindex_url": f"{_ALPINE_CDN}/v3.21/main/x86_64/APKINDEX.tar.gz",
        "distro": "alpine3.21",
        "arch": "x86_64",
        "component": "main",
        "format": "apk",
        "security": False,
    },
    {
        "id": "alpine3.21-community",
        "label": "Alpine 3.21 — community",
        "apkindex_url": f"{_ALPINE_CDN}/v3.21/community/x86_64/APKINDEX.tar.gz",
        "distro": "alpine3.21",
        "arch": "x86_64",
        "component": "community",
        "format": "apk",
        "security": False,
    },
    # ── Alpine 3.20 ───────────────────────────────────────────────────────────
    {
        "id": "alpine3.20-main",
        "label": "Alpine 3.20 — main",
        "apkindex_url": f"{_ALPINE_CDN}/v3.20/main/x86_64/APKINDEX.tar.gz",
        "distro": "alpine3.20",
        "arch": "x86_64",
        "component": "main",
        "format": "apk",
        "security": False,
    },
    {
        "id": "alpine3.20-community",
        "label": "Alpine 3.20 — community",
        "apkindex_url": f"{_ALPINE_CDN}/v3.20/community/x86_64/APKINDEX.tar.gz",
        "distro": "alpine3.20",
        "arch": "x86_64",
        "component": "community",
        "format": "apk",
        "security": False,
    },
    # ── Alpine 3.19 ───────────────────────────────────────────────────────────
    {
        "id": "alpine3.19-main",
        "label": "Alpine 3.19 — main",
        "apkindex_url": f"{_ALPINE_CDN}/v3.19/main/x86_64/APKINDEX.tar.gz",
        "distro": "alpine3.19",
        "arch": "x86_64",
        "component": "main",
        "format": "apk",
        "security": False,
    },
    {
        "id": "alpine3.19-community",
        "label": "Alpine 3.19 — community",
        "apkindex_url": f"{_ALPINE_CDN}/v3.19/community/x86_64/APKINDEX.tar.gz",
        "distro": "alpine3.19",
        "arch": "x86_64",
        "component": "community",
        "format": "apk",
        "security": False,
    },
    # ── Alpine 3.18 ───────────────────────────────────────────────────────────
    {
        "id": "alpine3.18-main",
        "label": "Alpine 3.18 — main",
        "apkindex_url": f"{_ALPINE_CDN}/v3.18/main/x86_64/APKINDEX.tar.gz",
        "distro": "alpine3.18",
        "arch": "x86_64",
        "component": "main",
        "format": "apk",
        "security": False,
    },
    {
        "id": "alpine3.18-community",
        "label": "Alpine 3.18 — community",
        "apkindex_url": f"{_ALPINE_CDN}/v3.18/community/x86_64/APKINDEX.tar.gz",
        "distro": "alpine3.18",
        "arch": "x86_64",
        "component": "community",
        "format": "apk",
        "security": False,
    },
]


def init_db() -> None:
    """No-op — le schéma est géré par Alembic (db/tables.py)."""
    pass


def _parse_apkindex(raw_text: str, source: dict) -> list[dict]:
    """
    Parse le contenu d'un fichier APKINDEX en liste de dicts.
    Chaque stanza se termine par une ligne vide.
    """
    packages = []
    current: dict = {}
    now = datetime.now(timezone.utc).isoformat()

    for line in raw_text.splitlines():
        line = line.rstrip()
        if line == "":
            # Fin de stanza
            if current.get("name") and current.get("version"):
                current.setdefault("arch", source.get("arch", "x86_64"))
                current["source_id"] = source["id"]
                current["distro"] = source["distro"]
                current["synced_at"] = now
                packages.append(current)
            current = {}
            continue

        if ":" not in line:
            continue

        key, _, val = line.partition(":")
        val = val.strip()

        if key == "P":
            current["name"] = val
        elif key == "V":
            current["version"] = val
        elif key == "A":
            current["arch"] = val
        elif key == "S":
            try:
                current["size"] = int(val)
            except ValueError:
                pass
        elif key == "I":
            try:
                current["installed_size"] = int(val)
            except ValueError:
                pass
        elif key == "T":
            current["description"] = val
        elif key == "U":
            current["url"] = val
        elif key == "L":
            current["license"] = val
        elif key == "o":
            current["origin"] = val
        elif key == "D":
            # Dépendances : séparées par des espaces, peut avoir des versions "pkg>=1.0"
            deps = [d.split(">=")[0].split("<=")[0].split("=")[0].split("!")[0].strip()
                    for d in val.split() if d and not d.startswith("!")]
            current["depends"] = " ".join(deps) if deps else None
        elif key == "p":
            current["provides"] = val

    # Dernière stanza sans ligne vide finale
    if current.get("name") and current.get("version"):
        current.setdefault("arch", source.get("arch", "x86_64"))
        current["source_id"] = source["id"]
        current["distro"] = source["distro"]
        current["synced_at"] = now
        packages.append(current)

    return packages


def _download_and_parse(apkindex_url: str, source: dict) -> list[dict]:
    """
    Télécharge APKINDEX.tar.gz, extrait le fichier APKINDEX et le parse.
    Retourne la liste des paquets.
    """
    req = urllib.request.Request(
        apkindex_url,
        headers={"User-Agent": "APK-Repo-Manager/1.0"}
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        gz_data = resp.read()

    # Le fichier est un .tar.gz contenant "APKINDEX" et "DESCRIPTION"
    with tarfile.open(fileobj=io.BytesIO(gz_data), mode="r:gz") as tar:
        try:
            member = tar.getmember("APKINDEX")
            f = tar.extractfile(member)
            if f is None:
                raise ValueError("APKINDEX non extractible depuis l'archive")
            raw_text = f.read().decode("utf-8", errors="replace")
        except KeyError:
            raise ValueError("Fichier APKINDEX absent du tar.gz")

    return _parse_apkindex(raw_text, source)


def sync_source(source: dict) -> dict:
    """
    Télécharge et indexe APKINDEX.tar.gz pour une source Alpine donnée.
    """
    source_id = source["id"]

    try:
        packages = _download_and_parse(source["apkindex_url"], source)

        _defaults = {
            "arch": None, "description": None, "depends": None, "provides": None,
            "size": None, "installed_size": None, "url": None, "license": None,
            "origin": None,
        }
        for pkg in packages:
            for k, v in _defaults.items():
                pkg.setdefault(k, v)

        with db_conn() as conn:
            conn.execute(text("DELETE FROM apk_packages WHERE source_id = :source_id"), {"source_id": source_id})
            if packages:
                conn.execute(text("""
                    INSERT INTO apk_packages
                    (source_id, name, version, arch, description, depends, provides,
                     size, installed_size, url, license, origin, distro, synced_at)
                    VALUES
                    (:source_id, :name, :version, :arch, :description, :depends, :provides,
                     :size, :installed_size, :url, :license, :origin, :distro, :synced_at)
                """), packages)
            conn.execute(text("""
                INSERT INTO apk_sync_status (source_id, label, last_sync, pkg_count, status, error)
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

    except (urllib.error.URLError, Exception) as e:
        error_msg = str(e)
        _write_error(source_id, source["label"], error_msg)
        return {"source_id": source_id, "label": source["label"], "status": "error", "error": error_msg}


def _write_error(source_id: str, label: str, error: str) -> None:
    try:
        with db_conn() as conn:
            conn.execute(text("""
                INSERT INTO apk_sync_status (source_id, label, last_sync, pkg_count, status, error)
                VALUES (:source_id, :label, :last_sync, 0, 'error', :error)
                ON CONFLICT (source_id) DO UPDATE SET
                    label = EXCLUDED.label,
                    last_sync = EXCLUDED.last_sync,
                    pkg_count = 0,
                    status = 'error',
                    error = EXCLUDED.error
            """), {"source_id": source_id, "label": label, "last_sync": datetime.now(timezone.utc).isoformat(), "error": error})
    except Exception:
        pass


def sync_all() -> list[dict]:
    """Synchronise toutes les sources APK configurées."""
    return [sync_source(s) for s in DEFAULT_SOURCES]


def get_sync_status() -> list[dict]:
    """Retourne le statut de synchronisation de chaque source APK."""
    with db_conn() as conn:
        rows = conn.execute(text("SELECT * FROM apk_sync_status")).mappings().fetchall()
        synced = {r["source_id"]: dict(r) for r in rows}

    result = []
    for source in DEFAULT_SOURCES:
        sid = source["id"]
        if sid in synced:
            entry = dict(synced[sid])
            entry["format"] = "apk"
            result.append(entry)
        else:
            result.append({
                "source_id": sid,
                "label": source["label"],
                "last_sync": None,
                "pkg_count": 0,
                "status": "never",
                "error": None,
                "security": False,
                "format": "apk",
            })
    return result


def list_packages_by_source(source_id: str, limit: int = 1000, offset: int = 0) -> list[dict]:
    """
    Retourne tous les paquets indexés pour une source donnée, paginés.
    Utilisé par le mirroir planifié pour itérer sur l'ensemble du dépôt upstream.
    """
    with db_conn() as conn:
        rows = conn.execute(text("""
            SELECT name, version, arch, description, depends, provides, size,
                   distro, source_id, synced_at, license, url,
                   'apk' AS format
            FROM apk_packages
            WHERE source_id = :source_id
            ORDER BY name ASC
            LIMIT :limit OFFSET :offset
        """), {"source_id": source_id, "limit": limit, "offset": offset}).mappings().fetchall()
    return [dict(r) for r in rows]


def search_packages(query: str, limit: int = 30, source_id: str = None, distro: str = None) -> list[dict]:
    """Recherche des paquets APK dans l'index local."""
    query = query.strip()
    if not query:
        return []

    with db_conn() as conn:
        rows = conn.execute(text("""
            SELECT name, version, arch, description, depends, size,
                   distro, source_id, synced_at, license, url,
                   'apk' AS format
            FROM apk_packages
            WHERE (LOWER(name) LIKE LOWER(:q_wild) OR LOWER(description) LIKE LOWER(:q_wild))
            AND (:source_id IS NULL OR source_id = :source_id)
            AND (:distro IS NULL OR distro LIKE :distro_pattern)
            ORDER BY
                CASE
                    WHEN name = :q       THEN 0
                    WHEN LOWER(name) LIKE LOWER(:q_prefix) THEN 1
                    ELSE                      2
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

    return [dict(r) for r in rows]


def get_package_info(name: str, source_id: str = None) -> dict | None:
    """Retourne les infos d'un paquet APK par nom exact."""
    with db_conn() as conn:
        row = conn.execute(text("""
            SELECT *, 'apk' AS format FROM apk_packages
            WHERE name = :name
            AND (:source_id IS NULL OR source_id = :source_id)
            LIMIT 1
        """), {"name": name, "source_id": source_id}).mappings().fetchone()
    return dict(row) if row else None


def is_indexed() -> bool:
    """Retourne True si l'index APK contient au moins un paquet."""
    try:
        with db_conn() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM apk_packages")).scalar()
        return (count or 0) > 0
    except Exception:
        return False
