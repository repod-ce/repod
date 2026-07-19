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
import logging
import os
import subprocess
import tarfile
import tempfile
import urllib.error
import zlib
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import text

from db.engine import db_conn
from services.http_retry import fetch_url

logger = logging.getLogger("package_index_apk")

# Répertoire des clés RSA publiques Alpine — voir scripts/gen-apk-keys.sh.
# Chaque fichier est nommé exactement comme le nom de clé embarqué dans la
# signature (".SIGN.RSA.<nom>" -> fichier "<nom>"), pour une résolution
# directe sans deviner quelle clé utiliser.
_APK_KEYS_DIR = os.getenv(
    "APK_ARCHIVE_KEYS_DIR",
    str(Path(__file__).resolve().parent.parent / "security-keys" / "apk-keys"),
)

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
    # ── aarch64 ────────────────────────────────────────────────────────────────
    # Toutes les URLs ci-dessous ont été vérifiées en direct (HTTP 200). Alpine
    # signe aarch64 avec une clé RSA DIFFÉRENTE de x86_64 (confirmé en direct
    # sur les 8 sources : alpine-devel@...-616ae350.rsa.pub, pas -6165ee59) —
    # voir scripts/gen-apk-keys.sh, cette seconde clé y est déjà déclarée.
    {
        "id": "alpine3.21-main-aarch64",
        "label": "Alpine 3.21 — main [aarch64]",
        "apkindex_url": f"{_ALPINE_CDN}/v3.21/main/aarch64/APKINDEX.tar.gz",
        "distro": "alpine3.21", "arch": "aarch64", "component": "main", "format": "apk", "security": False,
    },
    {
        "id": "alpine3.21-community-aarch64",
        "label": "Alpine 3.21 — community [aarch64]",
        "apkindex_url": f"{_ALPINE_CDN}/v3.21/community/aarch64/APKINDEX.tar.gz",
        "distro": "alpine3.21", "arch": "aarch64", "component": "community", "format": "apk", "security": False,
    },
    {
        "id": "alpine3.20-main-aarch64",
        "label": "Alpine 3.20 — main [aarch64]",
        "apkindex_url": f"{_ALPINE_CDN}/v3.20/main/aarch64/APKINDEX.tar.gz",
        "distro": "alpine3.20", "arch": "aarch64", "component": "main", "format": "apk", "security": False,
    },
    {
        "id": "alpine3.20-community-aarch64",
        "label": "Alpine 3.20 — community [aarch64]",
        "apkindex_url": f"{_ALPINE_CDN}/v3.20/community/aarch64/APKINDEX.tar.gz",
        "distro": "alpine3.20", "arch": "aarch64", "component": "community", "format": "apk", "security": False,
    },
    {
        "id": "alpine3.19-main-aarch64",
        "label": "Alpine 3.19 — main [aarch64]",
        "apkindex_url": f"{_ALPINE_CDN}/v3.19/main/aarch64/APKINDEX.tar.gz",
        "distro": "alpine3.19", "arch": "aarch64", "component": "main", "format": "apk", "security": False,
    },
    {
        "id": "alpine3.19-community-aarch64",
        "label": "Alpine 3.19 — community [aarch64]",
        "apkindex_url": f"{_ALPINE_CDN}/v3.19/community/aarch64/APKINDEX.tar.gz",
        "distro": "alpine3.19", "arch": "aarch64", "component": "community", "format": "apk", "security": False,
    },
    {
        "id": "alpine3.18-main-aarch64",
        "label": "Alpine 3.18 — main [aarch64]",
        "apkindex_url": f"{_ALPINE_CDN}/v3.18/main/aarch64/APKINDEX.tar.gz",
        "distro": "alpine3.18", "arch": "aarch64", "component": "main", "format": "apk", "security": False,
    },
    {
        "id": "alpine3.18-community-aarch64",
        "label": "Alpine 3.18 — community [aarch64]",
        "apkindex_url": f"{_ALPINE_CDN}/v3.18/community/aarch64/APKINDEX.tar.gz",
        "distro": "alpine3.18", "arch": "aarch64", "component": "community", "format": "apk", "security": False,
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
        elif key == "C":
            current["apk_checksum"] = val

    # Dernière stanza sans ligne vide finale
    if current.get("name") and current.get("version"):
        current.setdefault("arch", source.get("arch", "x86_64"))
        current["source_id"] = source["id"]
        current["distro"] = source["distro"]
        current["synced_at"] = now
        packages.append(current)

    return packages


def _split_apk_signed_archive(gz_data: bytes) -> tuple[bytes, bytes]:
    """
    Sépare APKINDEX.tar.gz en (tar.gz de signature, tar.gz de contenu).

    Le fichier est la concaténation brute de deux flux gzip indépendants —
    pas un seul flux avec deux entrées : `abuild-sign` écrit d'abord une
    petite archive tar.gz contenant un fichier ".SIGN.RSA.<nom-clé>" (la
    signature RSA brute), puis colle directement à la suite l'archive
    tar.gz réelle (APKINDEX + DESCRIPTION). `zlib.decompressobj` avec
    `unused_data` donne la frontière exacte entre les deux flux sans
    deviner un déchargement de premier membre par recherche d'octets —
    confirmé en direct contre un APKINDEX.tar.gz réel (dl-cdn.alpinelinux.org).
    """
    d = zlib.decompressobj(zlib.MAX_WBITS | 16)
    d.decompress(gz_data)
    boundary = len(gz_data) - len(d.unused_data)
    return gz_data[:boundary], gz_data[boundary:]


def _verify_apkindex_signature(gz_data: bytes) -> tuple[bool, str]:
    """
    Authentifie APKINDEX.tar.gz via sa signature RSA embarquée.

    Contrairement à APT (GPG) et RPM (repomd.xml.asc détaché), Alpine ne
    signe pas avec GPG : la signature est calculée par `abuild-sign` avec
    `openssl dgst -sha1 -sign` sur les octets COMPRESSÉS du second flux
    gzip (jamais sur le tar décompressé) — confirmé en direct : la
    vérification échoue sur le tar décompressé et réussit sur le .tar.gz
    compressé, ce qui confirme exactement ce que signe abuild-sign.

    Politique : toujours fail-closed, contrairement à RPM. Les 8 sources
    APK configurées (DEFAULT_SOURCES) sont TOUTES signées par la même clé
    officielle Alpine (confirmé en direct) — un APKINDEX.tar.gz Alpine sans
    signature valide n'est jamais un cas légitime comme "Fedora sans
    repomd.xml.asc", c'est soit une corruption soit une falsification.
    """
    try:
        sig_gz, content_gz = _split_apk_signed_archive(gz_data)
    except Exception as exc:
        return False, f"Impossible de séparer signature et contenu : {exc}"

    if not content_gz:
        return False, "Aucun contenu après le flux de signature — fichier tronqué ou non signé."

    try:
        with tarfile.open(fileobj=io.BytesIO(sig_gz), mode="r:gz") as tar:
            sig_members = [m for m in tar.getmembers() if m.name.startswith(".SIGN.RSA.")]
            if not sig_members:
                return False, "Aucun fichier .SIGN.RSA.* trouvé — APKINDEX non signé."
            member = sig_members[0]
            key_name = member.name[len(".SIGN.RSA."):]
            sig_file = tar.extractfile(member)
            if sig_file is None:
                return False, "Fichier de signature non extractible."
            signature_bytes = sig_file.read()
    except Exception as exc:
        return False, f"Archive de signature illisible : {exc}"

    key_path = os.path.join(_APK_KEYS_DIR, key_name)
    if not os.path.exists(key_path):
        return False, (
            f"Clé publique inconnue du trousseau local : {key_name} "
            f"(voir scripts/gen-apk-keys.sh)"
        )

    try:
        with tempfile.TemporaryDirectory() as tmp:
            content_path = os.path.join(tmp, "content.tar.gz")
            sig_path = os.path.join(tmp, "signature")
            with open(content_path, "wb") as fh:
                fh.write(content_gz)
            with open(sig_path, "wb") as fh:
                fh.write(signature_bytes)

            proc = subprocess.run(
                ["openssl", "dgst", "-sha1", "-verify", key_path,
                 "-signature", sig_path, content_path],
                capture_output=True, timeout=30,
            )
    except Exception as exc:
        return False, f"Échec d'exécution d'openssl : {exc}"

    if proc.returncode != 0:
        return False, f"Signature RSA invalide (clé {key_name}) — contenu potentiellement altéré."
    return True, ""


def _download_and_parse(apkindex_url: str, source: dict) -> list[dict]:
    """
    Télécharge APKINDEX.tar.gz, authentifie sa signature RSA, extrait le
    fichier APKINDEX et le parse. Retourne la liste des paquets.

    Retente jusqu'à 2 fois (backoff 2s/5s) sur un aléa réseau transitoire —
    voir services/http_retry.py.
    """
    gz_data = fetch_url(
        apkindex_url,
        headers={"User-Agent": "APK-Repo-Manager/1.0"},
        timeout=60,
    )

    sig_ok, sig_msg = _verify_apkindex_signature(gz_data)
    if not sig_ok:
        raise ValueError(f"Vérification de signature APKINDEX échouée : {sig_msg}")

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
            "origin": None, "apk_checksum": None,
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
                     size, installed_size, url, license, origin, distro, synced_at, apk_checksum)
                    VALUES
                    (:source_id, :name, :version, :arch, :description, :depends, :provides,
                     :size, :installed_size, :url, :license, :origin, :distro, :synced_at, :apk_checksum)
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


def search_packages(query: str, limit: int = 30, source_id: str = None, distro: str = None, arch: str = None) -> list[dict]:
    """Recherche des paquets APK dans l'index local.

    arch : filtre optionnel sur l'architecture exacte (ex: "aarch64") — sans
    ce filtre, x86_64 et aarch64 apparaissent mélangés, x86_64 en premier
    (voir get_package_info() pour le raisonnement complet).
    """
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
            AND (:arch IS NULL OR arch = :arch)
            ORDER BY
                CASE
                    WHEN name = :q       THEN 0
                    WHEN LOWER(name) LIKE LOWER(:q_prefix) THEN 1
                    ELSE                      2
                END,
                CASE WHEN arch = 'x86_64' THEN 0 ELSE 1 END,
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
            "arch": arch,
        }).mappings().fetchall()

    return [dict(r) for r in rows]


def get_package_info(name: str, source_id: str = None, arch: str = None) -> dict | None:
    """Retourne les infos d'un paquet APK par nom exact.

    arch : filtre explicite sur l'architecture exacte (ex: "aarch64"). Depuis
    l'ajout des sources aarch64 (même `distro` que leur équivalent x86_64,
    par cohérence avec les autres formats), un même (name, distro) peut
    désormais correspondre à plusieurs lignes — sans filtre, x86_64 reste
    préféré par défaut (ORDER BY), pour ne rien changer au comportement des
    appelants existants.
    """
    with db_conn() as conn:
        row = conn.execute(text("""
            SELECT *, 'apk' AS format FROM apk_packages
            WHERE name = :name
            AND (:source_id IS NULL OR source_id = :source_id)
            AND (:arch IS NULL OR arch = :arch)
            ORDER BY CASE WHEN arch = 'x86_64' THEN 0 ELSE 1 END, synced_at DESC
            LIMIT 1
        """), {"name": name, "source_id": source_id, "arch": arch}).mappings().fetchone()
    return dict(row) if row else None


def resolve_provide_to_package(provide: str, source_id: str = None, arch: str = None) -> dict | None:
    """
    Résout une dépendance virtuelle APK (so:libssl.so.3, cmd:bash, pc:zlib…)
    vers le paquet qui la fournit, via la colonne `provides` (même convention
    que le champ Depends — la valeur brute avec le préfixe est stockée telle
    quelle au moment du parsing de APKINDEX).

    Alpine exprime la quasi-totalité de ses dépendances de bibliothèques via
    des capabilities `so:` plutôt que des noms de paquets — sans cette
    résolution, la grande majorité des dépendances directes d'un paquet APK
    seraient ignorées silencieusement (elles ne correspondent à aucun nom de
    paquet réel).

    arch : voir get_package_info() — même filtre optionnel avec préférence
    x86_64 par défaut.
    """
    with db_conn() as conn:
        row = conn.execute(text("""
            SELECT *, 'apk' AS format FROM apk_packages
            WHERE provides LIKE :pat
            AND (:source_id IS NULL OR source_id = :source_id)
            AND (:arch IS NULL OR arch = :arch)
            ORDER BY CASE WHEN arch = 'x86_64' THEN 0 ELSE 1 END, synced_at DESC
            LIMIT 1
        """), {"pat": f"%{provide}%", "source_id": source_id, "arch": arch}).mappings().fetchone()
    return dict(row) if row else None


def is_indexed() -> bool:
    """Retourne True si l'index APK contient au moins un paquet."""
    try:
        with db_conn() as conn:
            count = conn.execute(text("SELECT COUNT(*) FROM apk_packages")).scalar()
        return (count or 0) > 0
    except Exception:
        return False
