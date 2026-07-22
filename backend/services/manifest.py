# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Génération et lecture des manifests d'artefacts.

Stockage :
  • PostgreSQL (table manifests) — source de vérité principale ; JSONB pour
    tags, dependencies, validation_steps, cve_results
  • Fichiers JSON dans MANIFEST_DIR — backup.sh, outils tiers (lecture seule)

Stratégie de lecture/écriture :
  • save_manifest()    → écrit PostgreSQL + fichier JSON
  • load_manifest()    → PostgreSQL en priorité, fallback JSON
  • list_manifests()   → fichiers JSON + cache in-memory (TTL)
  • search_manifests() → PostgreSQL uniquement (recherche rapide)
  • delete_manifest_from_db() → PostgreSQL + fichiers JSON
  • migrate_json_to_db() → import one-time des JSON vers PostgreSQL

Cache in-memory
───────────────
TTL configurable via MANIFEST_CACHE_TTL (secondes, défaut : 30).
Invalidé automatiquement par save_manifest().
Thread-safe via RLock sur le cache uniquement.
"""
import hashlib
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock

from sqlalchemy import text

from db.engine import db_conn
from services.path_safety import PathTraversalError, safe_path_join

logger = logging.getLogger("manifest")

MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))
MANIFEST_DIR.mkdir(parents=True, exist_ok=True)


def _get_default_distribution() -> str:
    from services.format_router import DEFAULT_DISTRIBUTION
    return DEFAULT_DISTRIBUTION


def _get_pkg_type() -> str:
    from services.format_router import REPO_FORMAT, is_rpm
    if REPO_FORMAT == "apk":
        return "apk"
    return "rpm" if is_rpm() else "deb"


# ── Conversion manifest dict ↔ ligne DB ───────────────────────────────────────

def _json_field(val, default=None):
    """
    Retourne val sous forme de liste/dict Python.
    - PostgreSQL JSONB → SQLAlchemy/psycopg2 retourne déjà un objet Python : retourné tel quel.
    - SQLite TEXT (tests unitaires) → chaîne JSON : désérialisée avec json.loads().
    """
    if default is None:
        default = []
    if val is None:
        return default
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, ValueError):
            return default
    return val


def _manifest_to_row(m: dict) -> dict:
    """
    Convertit un manifest dict en paramètres pour INSERT/UPDATE.
    Les champs JSONB sont sérialisés en chaînes JSON — PostgreSQL les accepte
    via cast implicite TEXT→JSONB et SQLite les stocke comme TEXT.
    """
    src = m.get("source", {})
    intg = m.get("integrity", {})
    return {
        "name":              m.get("name", ""),
        "version":           m.get("version", ""),
        "arch":              m.get("arch", "amd64"),
        "distribution":      m.get("distribution") or _get_default_distribution(),
        "pkg_type":          m.get("type") or _get_pkg_type(),
        "section":           m.get("section", ""),
        "description":       m.get("description", ""),
        "maintainer":        m.get("maintainer", ""),
        "installed_size_kb": int(m.get("installed_size_kb", 0) or 0),
        "file_size_bytes":   int(m.get("file_size_bytes", 0) or 0),
        "filename":          m.get("filename", ""),
        "status":            m.get("status", "validated"),
        "imported_by":       src.get("imported_by", "system"),
        "imported_at":       src.get("imported_at", ""),
        "import_method":     src.get("import_method", "upload"),
        "import_group":      src.get("import_group"),
        "sha256":            intg.get("sha256", ""),
        "sha512":            intg.get("sha512", ""),
        "gpg_signed":        bool(intg.get("gpg_signed", False)),
        "tags":              json.dumps(m.get("tags", []), ensure_ascii=False),
        "dependencies":      json.dumps(m.get("dependencies", []), ensure_ascii=False),
        "validation_steps":  json.dumps(m.get("validation_steps", []), ensure_ascii=False),
        "cve_results":       json.dumps(m.get("cve_results", []), ensure_ascii=False),
        "updated_at":        datetime.now(timezone.utc).isoformat(),
    }


def _row_to_manifest(row) -> dict:
    """
    Reconstruit un manifest dict depuis une ligne DB (mappings).
    Gère les deux cas :
      - PostgreSQL JSONB  → Python list/dict retourné directement par psycopg2
      - SQLite TEXT (tests) → chaîne JSON que _json_field() désérialise
    """
    d = dict(row)
    return {
        "name":               d["name"],
        "version":            d["version"],
        "arch":               d["arch"],
        "distribution":       d["distribution"],
        "section":            d.get("section", ""),
        "description":        d.get("description", ""),
        "maintainer":         d.get("maintainer", ""),
        "installed_size_kb":  d.get("installed_size_kb", 0),
        "file_size_bytes":    d.get("file_size_bytes", 0),
        "filename":           d.get("filename", ""),
        "type":               d.get("pkg_type", "deb"),
        "status":             d.get("status", "validated"),
        "source": {
            "imported_by":   d.get("imported_by", "system"),
            "imported_at":   d.get("imported_at", ""),
            "import_method": d.get("import_method", "upload"),
            "import_group":  d.get("import_group"),
        },
        "integrity": {
            "sha256":     d.get("sha256", ""),
            "sha512":     d.get("sha512", ""),
            "gpg_signed": bool(d.get("gpg_signed", False)),
        },
        "tags":             _json_field(d.get("tags")),
        "dependencies":     _json_field(d.get("dependencies")),
        "validation_steps": _json_field(d.get("validation_steps")),
        "cve_results":      _json_field(d.get("cve_results")),
    }


# ── Cache in-memory ───────────────────────────────────────────────────────────

_CACHE_TTL: float = float(os.getenv("MANIFEST_CACHE_TTL", "30"))
_cache: list[dict] | None = None
_cache_at: float = 0.0
_cache_lock: RLock = RLock()


def invalidate_manifest_cache() -> None:
    """
    Invalide le cache de list_manifests().
    Appeler après toute opération qui crée, modifie ou supprime un manifest
    sans passer par save_manifest() (ex : import batch, quarantaine manuelle).
    """
    global _cache, _cache_at
    with _cache_lock:
        _cache = None
        _cache_at = 0.0


def compute_sha256(file_path: str) -> str:
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_sha512(file_path: str) -> str:
    h = hashlib.sha512()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Parseurs APT (.deb) ───────────────────────────────────────────────────────

def parse_deb_info(deb_path: str) -> dict:
    result = subprocess.run(["dpkg-deb", "--info", deb_path], capture_output=True, text=True)
    info = {}
    for line in result.stdout.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            info[key.strip().lower()] = value.strip()
    return info


def parse_deb_fields(deb_path: str) -> dict:
    fields = {}
    for field in ["Package", "Version", "Architecture", "Depends",
                  "Description", "Maintainer", "Installed-Size", "Section"]:
        result = subprocess.run(
            ["dpkg-deb", "-f", deb_path, field],
            capture_output=True, text=True,
        )
        val = result.stdout.strip()
        if val:
            fields[field.lower().replace("-", "_")] = val
    return fields


def parse_dependencies(depends_str: str) -> list[dict]:
    if not depends_str:
        return []
    deps = []
    for dep in depends_str.split(","):
        dep = dep.strip()
        if not dep:
            continue
        dep = dep.split("|")[0].strip()
        if "(" in dep:
            name = dep[:dep.index("(")].strip()
            version_constraint = dep[dep.index("(")+1:dep.index(")")].strip()
        else:
            name = dep.strip()
            version_constraint = None
        if ":" in name:
            name = name.split(":")[0]
        if name:
            entry = {"name": name}
            if version_constraint:
                entry["version_constraint"] = version_constraint
            deps.append(entry)
    return deps


# ── Parseurs RPM (.rpm) ───────────────────────────────────────────────────────

def parse_rpm_fields(rpm_path: str) -> dict:
    queryformat = (
        "NAME=%{NAME}\\n"
        "VERSION=%{VERSION}\\n"
        "RELEASE=%{RELEASE}\\n"
        "ARCH=%{ARCH}\\n"
        "SUMMARY=%{SUMMARY}\\n"
        "DESCRIPTION=%{DESCRIPTION}\\n"
        "GROUP=%{GROUP}\\n"
        "SIZE=%{SIZE}\\n"
        "LICENSE=%{LICENSE}\\n"
        "VENDOR=%{VENDOR}\\n"
        "URL=%{URL}\\n"
        "EPOCH=%{EPOCH}\\n"
        "BUILDHOST=%{BUILDHOST}\\n"
        "SOURCERPM=%{SOURCERPM}\\n"
        "PACKAGER=%{PACKAGER}\\n"
    )
    result = subprocess.run(
        ["rpm", "-qp", "--queryformat", queryformat,
         "--nosignature", "--noplugins", rpm_path],
        capture_output=True, text=True,
    )
    fields: dict = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            val = value.strip()
            if val and val != "(none)":
                fields[key.strip().lower()] = val
    return fields


def parse_rpm_requires(rpm_path: str) -> list[str]:
    result = subprocess.run(
        ["rpm", "-qp", "--requires", "--nosignature", "--noplugins", rpm_path],
        capture_output=True, text=True,
    )
    reqs = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("rpmlib(") and not line.startswith("/"):
            reqs.append(line)
    return reqs


def parse_rpm_dependencies(requires_list: list[str]) -> list[dict]:
    deps = []
    for req in requires_list:
        req = req.strip()
        if not req:
            continue
        parts = req.split()
        name = parts[0]
        version_constraint = None
        if len(parts) >= 3:
            version_constraint = f"{parts[1]} {parts[2]}"
        entry: dict = {"name": name}
        if version_constraint:
            entry["version_constraint"] = version_constraint
        deps.append(entry)
    return deps


def _rpm_full_version(fields: dict) -> str:
    epoch   = fields.get("epoch", "")
    version = fields.get("version", "unknown")
    release = fields.get("release", "")
    full    = f"{version}-{release}" if release else version
    if epoch and epoch not in ("0", "(none)"):
        full = f"{epoch}:{full}"
    return full


def parse_apk_fields(apk_path: str) -> dict:
    from services.distributions_apk import parse_apk_metadata
    return parse_apk_metadata(Path(apk_path))


# ── generate_manifest() — format-agnostique ──────────────────────────────────

def generate_manifest(
    pkg_path: str,
    imported_by: str = "system",
    import_method: str = "upload",
    validated_deps: list[dict] | None = None,
    import_group: str | None = None,
    validation_steps: list[dict] | None = None,
    cve_results: list[dict] | None = None,
    distribution: str | None = None,
) -> dict:
    from services.format_router import DEFAULT_DISTRIBUTION
    from services.format_router import is_rpm as _is_rpm

    dist = distribution if distribution is not None else DEFAULT_DISTRIBUTION

    if pkg_path.endswith(".apk"):
        return _generate_apk_manifest(
            pkg_path, imported_by, import_method,
            validated_deps, import_group, validation_steps, cve_results, dist,
        )
    if pkg_path.endswith(".deb"):
        return _generate_deb_manifest(
            pkg_path, imported_by, import_method,
            validated_deps, import_group, validation_steps, cve_results, dist,
        )
    if pkg_path.endswith(".rpm"):
        return _generate_rpm_manifest(
            pkg_path, imported_by, import_method,
            validated_deps, import_group, validation_steps, cve_results, dist,
        )
    # Extension inconnue : se rabattre sur le format singleton (REPO_FORMAT)
    if _is_rpm():
        return _generate_rpm_manifest(
            pkg_path, imported_by, import_method,
            validated_deps, import_group, validation_steps, cve_results, dist,
        )
    return _generate_deb_manifest(
        pkg_path, imported_by, import_method,
        validated_deps, import_group, validation_steps, cve_results, dist,
    )


def _generate_apk_manifest(apk_path, imported_by, import_method,
                            validated_deps, import_group, validation_steps,
                            cve_results, distribution):
    fields    = parse_apk_fields(apk_path)
    file_size = os.path.getsize(apk_path)
    raw_deps  = fields.get("depend", [])
    if isinstance(raw_deps, str):
        raw_deps = [raw_deps]
    deps: list[dict] = (
        validated_deps if validated_deps is not None
        else [{"name": d.split(">")[0].split("=")[0].split("<")[0].strip(),
               "raw": d, "available_internally": False, "depth": 1}
              for d in raw_deps if d and not d.startswith("so:") and not d.startswith("cmd:")]
    )
    installed_bytes = int(fields.get("size", 0) or 0)
    return {
        "name":              fields.get("pkgname", Path(apk_path).stem),
        "version":           fields.get("pkgver", "unknown"),
        "arch":              fields.get("arch", "x86_64"),
        "section":           fields.get("builddate", ""),
        "description":       fields.get("pkgdesc", ""),
        "maintainer":        fields.get("maintainer", ""),
        "license":           fields.get("license", ""),
        "url":               fields.get("url", ""),
        "installed_size_kb": installed_bytes // 1024,
        "file_size_bytes":   file_size,
        "filename":          Path(apk_path).name,
        "type":              "apk",
        "distribution":      distribution,
        "source":            {"imported_by": imported_by, "imported_at": datetime.now(timezone.utc).isoformat(),
                              "import_method": import_method, "import_group": import_group},
        "integrity":         {"sha256": compute_sha256(apk_path), "sha512": compute_sha512(apk_path), "gpg_signed": False},
        "dependencies":      deps,
        "status":            "validated",
        "tags":              [],
        "validation_steps":  validation_steps or [],
        "cve_results":       cve_results or [],
    }


def _generate_deb_manifest(deb_path, imported_by, import_method,
                            validated_deps, import_group, validation_steps,
                            cve_results, distribution):
    fields    = parse_deb_fields(deb_path)
    file_size = os.path.getsize(deb_path)
    deps = validated_deps if validated_deps is not None else parse_dependencies(fields.get("depends", ""))
    return {
        "name":              fields.get("package", Path(deb_path).stem),
        "version":           fields.get("version", "unknown"),
        "arch":              fields.get("architecture", "unknown"),
        "section":           fields.get("section", "main"),
        "description":       fields.get("description", ""),
        "maintainer":        fields.get("maintainer", ""),
        "installed_size_kb": int(fields.get("installed_size", 0) or 0),
        "file_size_bytes":   file_size,
        "filename":          Path(deb_path).name,
        "type":              "deb",
        "distribution":      distribution,
        "source":            {"imported_by": imported_by, "imported_at": datetime.now(timezone.utc).isoformat(),
                              "import_method": import_method, "import_group": import_group},
        "integrity":         {"sha256": compute_sha256(deb_path), "sha512": compute_sha512(deb_path), "gpg_signed": False},
        "dependencies":      deps,
        "status":            "validated",
        "tags":              [],
        "validation_steps":  validation_steps or [],
        "cve_results":       cve_results or [],
    }


def _generate_rpm_manifest(rpm_path, imported_by, import_method,
                            validated_deps, import_group, validation_steps,
                            cve_results, distribution):
    fields      = parse_rpm_fields(rpm_path)
    file_size   = os.path.getsize(rpm_path)
    full_version = _rpm_full_version(fields)
    if validated_deps is not None:
        deps = validated_deps
    else:
        deps = parse_rpm_dependencies(parse_rpm_requires(rpm_path))
    return {
        "name":              fields.get("name", Path(rpm_path).stem),
        "version":           full_version,
        "arch":              fields.get("arch", "x86_64"),
        "section":           fields.get("group", "Unspecified"),
        "description":       fields.get("summary", fields.get("description", "")),
        "maintainer":        fields.get("packager", fields.get("vendor", "")),
        "license":           fields.get("license", ""),
        "url":               fields.get("url", ""),
        "source_rpm":        fields.get("sourcerpm", ""),
        "installed_size_kb": int(fields.get("size", 0) or 0) // 1024,
        "file_size_bytes":   file_size,
        "filename":          Path(rpm_path).name,
        "type":              "rpm",
        "distribution":      distribution,
        "source":            {"imported_by": imported_by, "imported_at": datetime.now(timezone.utc).isoformat(),
                              "import_method": import_method, "import_group": import_group},
        "integrity":         {"sha256": compute_sha256(rpm_path), "sha512": compute_sha512(rpm_path), "gpg_signed": False},
        "dependencies":      deps,
        "status":            "validated",
        "tags":              [],
        "validation_steps":  validation_steps or [],
        "cve_results":       cve_results or [],
    }


# ── Persistance PostgreSQL ────────────────────────────────────────────────────

def save_manifest(manifest: dict) -> str:
    """
    Persiste un manifest dans PostgreSQL (JSONB) et écrit le fichier JSON
    (pour backup.sh et la rétrocompatibilité). Invalide le cache.
    Retourne le chemin du fichier JSON.
    """
    name    = manifest["name"]
    version = manifest["version"].replace(":", "_").replace("/", "_")
    arch    = manifest["arch"]
    filename = f"{name}_{version}_{arch}.manifest.json"
    try:
        path = safe_path_join(MANIFEST_DIR, filename)
    except PathTraversalError as exc:
        raise ValueError(f"Métadonnées de paquet invalides (name/version/arch) : {exc}") from exc

    # Fichier JSON — backup / outils tiers
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    # PostgreSQL upsert
    row = _manifest_to_row(manifest)
    cols     = ", ".join(row.keys())
    binds    = ", ".join(f":{k}" for k in row.keys())
    updates  = ", ".join(
        f"{k} = EXCLUDED.{k}"
        for k in row.keys()
        if k not in ("name", "version", "arch")
    )
    with db_conn() as conn:
        conn.execute(
            text(
                f"INSERT INTO manifests ({cols}) VALUES ({binds}) "
                f"ON CONFLICT (name, version, arch) DO UPDATE SET {updates}"
            ),
            row,
        )

    invalidate_manifest_cache()
    return str(path)


def load_manifest(name: str, version: str, arch: str = "amd64") -> dict | None:
    """
    Charge un manifest par (name, version, arch).
    PostgreSQL en priorité, fallback fichier JSON.
    """
    try:
        with db_conn() as conn:
            row = conn.execute(
                text("SELECT * FROM manifests WHERE name = :n AND version = :v AND arch = :a"),
                {"n": name, "v": version, "a": arch},
            ).mappings().fetchone()
        if row:
            return _row_to_manifest(row)
    except Exception:
        pass

    version_safe = version.replace(":", "_").replace("/", "_")
    try:
        path = safe_path_join(MANIFEST_DIR, f"{name}_{version_safe}_{arch}.manifest.json")
    except PathTraversalError:
        return None
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def list_manifests() -> list[dict]:
    """
    Retourne tous les manifests (cache TTL = MANIFEST_CACHE_TTL s).
    Lit les fichiers JSON pour la rétrocompatibilité avec backup.sh et les tests.
    Utiliser search_manifests() pour les requêtes filtrées sur PostgreSQL.
    """
    global _cache, _cache_at
    with _cache_lock:
        now = time.monotonic()
        if _cache is not None and (now - _cache_at) < _CACHE_TTL:
            return list(_cache)

        manifests: list[dict] = []
        for path in sorted(MANIFEST_DIR.glob("*.manifest.json")):
            try:
                with open(path) as f:
                    manifests.append(json.load(f))
            except Exception:
                continue

        _cache = manifests
        _cache_at = now
        return list(manifests)


def search_manifests(
    query: str = "",
    distribution: str | None = None,
    status: str | None = None,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    """Recherche dans PostgreSQL avec filtres optionnels."""
    conditions = []
    params: dict = {"limit": limit, "offset": offset}

    if query:
        conditions.append("(LOWER(name) LIKE LOWER(:q) OR LOWER(description) LIKE LOWER(:q))")
        params["q"] = f"%{query}%"
    if distribution:
        conditions.append("distribution = :dist")
        params["dist"] = distribution
    if status:
        conditions.append("status = :status")
        params["status"] = status

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    sql = f"SELECT * FROM manifests {where} ORDER BY name, version LIMIT :limit OFFSET :offset"

    with db_conn() as conn:
        rows = conn.execute(text(sql), params).mappings().fetchall()
    return [_row_to_manifest(r) for r in rows]


def delete_manifest_from_db(name: str, version: str | None = None, arch: str | None = None) -> int:
    """
    Supprime un ou plusieurs manifests de PostgreSQL et les fichiers JSON associés.
    Retourne le nombre de lignes supprimées.
    """
    with db_conn() as conn:
        if version and arch:
            result = conn.execute(
                text("DELETE FROM manifests WHERE name = :n AND version = :v AND arch = :a"),
                {"n": name, "v": version, "a": arch},
            )
        elif version:
            result = conn.execute(
                text("DELETE FROM manifests WHERE name = :n AND version = :v"),
                {"n": name, "v": version},
            )
        else:
            result = conn.execute(
                text("DELETE FROM manifests WHERE name = :n"),
                {"n": name},
            )

    # Supprimer aussi les fichiers JSON correspondants
    version_safe = version.replace(":", "_").replace("/", "_") if version else None
    if version_safe and arch:
        try:
            p = safe_path_join(MANIFEST_DIR, f"{name}_{version_safe}_{arch}.manifest.json")
            p.unlink(missing_ok=True)
        except PathTraversalError:
            pass
    elif version_safe:
        for p in MANIFEST_DIR.glob(f"{name}_{version_safe}_*.manifest.json"):
            p.unlink(missing_ok=True)
    else:
        for p in MANIFEST_DIR.glob(f"{name}_*.manifest.json"):
            p.unlink(missing_ok=True)

    invalidate_manifest_cache()
    return result.rowcount


def migrate_json_to_db() -> int:
    """
    Importe tous les fichiers *.manifest.json du MANIFEST_DIR dans PostgreSQL.
    INSERT ON CONFLICT DO NOTHING pour ne pas écraser les entrées existantes.
    Retourne le nombre de manifests importés.
    """
    imported = 0
    for path in sorted(MANIFEST_DIR.glob("*.manifest.json")):
        try:
            with open(path) as f:
                manifest = json.load(f)
            row  = _manifest_to_row(manifest)
            cols = ", ".join(row.keys())
            binds = ", ".join(f":{k}" for k in row.keys())
            with db_conn() as conn:
                conn.execute(
                    text(
                        f"INSERT INTO manifests ({cols}) VALUES ({binds}) "
                        f"ON CONFLICT (name, version, arch) DO NOTHING"
                    ),
                    row,
                )
            imported += 1
        except Exception:
            continue
    return imported


def count_manifests_in_db() -> int:
    """Retourne le nombre de manifests dans PostgreSQL."""
    try:
        with db_conn() as conn:
            return conn.execute(text("SELECT COUNT(*) FROM manifests")).scalar() or 0
    except Exception:
        return 0


def reenrich_manifest_cve() -> dict:
    """
    Ré-enrichit les cve_results de tous les manifests déjà scannés avec les
    scores EPSS/KEV/TruRisk actuels du cache local, sans jamais relancer un
    scan Grype — la liste des CVE elle-même et leur description ne
    changent pas, ces deux champs ne viennent que d'un scan Grype réel.

    Bug réel qui motive cette fonction : l'enrichissement EPSS/KEV est
    calculé UNE SEULE FOIS, au moment du scan, puis figé indéfiniment dans
    le manifest. Une CVE trop récente pour avoir un score EPSS à ce
    moment-là reste bloquée à 0 % pour toujours, même après que le cache
    EPSS (rafraîchi quotidiennement par security_sync_daily) obtient la
    vraie valeur.

    epss_map/kev_set sont récupérés UNE SEULE FOIS pour tous les manifests
    (pas par manifest) — la liste catalogue peut compter plusieurs
    centaines de paquets, et enrich_cve_list() relirait sinon le cache
    disque à chaque appel.

    Lit/écrit directement PostgreSQL (pas list_manifests(), qui lit les
    fichiers JSON — une seconde copie utilisée pour backup.sh/rétro-
    compatibilité, jamais celle que get_package_cve() consulte réellement
    via load_manifest(), lequel priorise PostgreSQL). save_manifest()
    réécrit quand même le fichier JSON en plus, gardant les deux copies
    synchronisées comme pour toute autre écriture de manifest.
    """
    from services.cve_enrichment import enrich_cve_list, get_epss_scores, get_kev_set

    with db_conn() as conn:
        rows = conn.execute(
            text("SELECT * FROM manifests WHERE cve_results IS NOT NULL")
        ).mappings().fetchall()
    manifests = [_row_to_manifest(r) for r in rows]
    manifests = [m for m in manifests if m.get("cve_results")]
    if not manifests:
        return {"updated": 0, "manifests_with_cve": 0, "cve_ids_checked": 0}

    all_cve_ids = {c["id"] for m in manifests for c in m["cve_results"] if c.get("id")}

    try:
        kev_set  = get_kev_set()
        epss_map = get_epss_scores(list(all_cve_ids))
    except Exception as exc:
        logger.warning("[reenrich] Récupération EPSS/KEV échouée : %s", exc)
        kev_set  = set()
        epss_map = {}

    updated = 0
    for m in manifests:
        enrich_cve_list(m["cve_results"], epss_map=epss_map, kev_set=kev_set)
        save_manifest(m)
        updated += 1

    invalidate_manifest_cache()
    return {"updated": updated, "manifests_with_cve": len(manifests), "cve_ids_checked": len(all_cve_ids)}
