"""
services/snapshots.py — Gestion des snapshots historiques de paquets.

Fonctionnalités :
  • get_version_history(name)        → toutes les versions triées par date d'import (plus récente en premier)
  • get_snapshot(name, version)      → manifest complet d'une version spécifique
  • compare_versions(name, v1, v2)   → diff entre deux versions d'un manifest
  • enforce_version_limit(name, max) → supprime les versions excédentaires (plus anciennes)
  • run_version_gc()                 → applique enforce_version_limit sur tous les paquets

Politique de rétention par compte (max_versions_per_package) :
  La rétention basée sur l'âge (_purge_old_packages dans retention.py) supprime
  les versions trop anciennes. La rétention par COMPTE garantit qu'on ne garde pas
  plus de N versions par paquet, indépendamment de leur âge.

  max_versions_per_package = 10  → configurable dans settings.json
  max_versions_per_package = 0   → illimité (désactive la suppression par compte)

  L'ancienne version est toujours supprimée en DERNIER — on ne supprime jamais
  la version la plus récente, même si max_versions = 1.
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from services.path_safety import safe_path_join, PathTraversalError

logger = logging.getLogger("snapshots")

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))


# ── Helpers de date ───────────────────────────────────────────────────────────

def _parse_imported_at(version_info: dict) -> datetime:
    """Parse la date d'import depuis un dict version (index ou manifest)."""
    raw = version_info.get("imported_at", "") or ""
    if not raw:
        return datetime.min.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


# ── Historique des versions ───────────────────────────────────────────────────

def get_version_history(name: str) -> list[dict]:
    """
    Retourne toutes les versions connues d'un paquet, triées par date d'import
    descendante (la plus récente en premier).

    Chaque entrée contient :
      version, arch, distribution, filename, sha256, size_bytes,
      imported_at, imported_by, status, cve_summary, is_latest
    """
    from services.indexer import get_package_info
    info = get_package_info(name)
    if not info:
        return []

    latest = info.get("latest")
    versions_raw = info.get("versions", {})

    history = []
    for ver, meta in versions_raw.items():
        entry = {
            "version":      ver,
            "arch":         meta.get("arch", "amd64"),
            "distribution": meta.get("distribution", "jammy"),
            "filename":     meta.get("filename", ""),
            "sha256":       meta.get("sha256", ""),
            "size_bytes":   meta.get("size_bytes", 0),
            "imported_at":  meta.get("imported_at", ""),
            "imported_by":  meta.get("imported_by", ""),
            "status":       meta.get("status", "validated"),
            "cve_summary":  meta.get("cve_summary"),
            "deps_missing": meta.get("deps_missing", []),
            "is_latest":    (ver == latest),
            "pool_available": _deb_exists_in_pool(meta.get("filename", "")),
        }
        history.append(entry)

    # Tri par date d'import descendant
    history.sort(key=lambda e: _parse_imported_at(e), reverse=True)
    return history


def _deb_exists_in_pool(filename: str) -> bool:
    """Vérifie si le fichier .deb est encore présent dans le pool."""
    if not filename:
        return False
    try:
        return safe_path_join(POOL_DIR, filename).exists()
    except PathTraversalError:
        logger.warning(f"[snapshots] Nom de fichier suspect ignoré : {filename!r}")
        return False


def get_snapshot(name: str, version: str, arch: str = "amd64") -> dict | None:
    """
    Retourne le manifest complet (snapshot) d'une version spécifique.
    Lit SQLite en priorité, fallback JSON.
    """
    from services.manifest import load_manifest
    return load_manifest(name, version, arch)


# ── Comparaison de versions ───────────────────────────────────────────────────

def compare_versions(name: str, v1: str, v2: str, arch: str = "amd64") -> dict:
    """
    Compare deux versions d'un paquet et retourne les différences clés.

    Retourne un dict :
      {
        "package": str,
        "v1": str, "v2": str,
        "v1_manifest": dict | None,
        "v2_manifest": dict | None,
        "diff": {
          "size_change_bytes": int,     # v2 - v1
          "description_changed": bool,
          "new_deps": list[str],        # dépendances ajoutées dans v2
          "removed_deps": list[str],    # dépendances supprimées dans v2
          "cve_change": dict | None,    # évolution du score CVE
          "status_change": str | None,  # ex: "validated → pending_review"
          "sha256_changed": bool,
        }
      }
    """
    m1 = get_snapshot(name, v1, arch)
    m2 = get_snapshot(name, v2, arch)

    diff: dict[str, Any] = {}

    if m1 and m2:
        # Taille
        diff["size_change_bytes"] = (
            m2.get("file_size_bytes", 0) - m1.get("file_size_bytes", 0)
        )

        # Description
        diff["description_changed"] = m1.get("description") != m2.get("description")

        # Dépendances
        deps1 = {d["name"] for d in m1.get("dependencies", [])}
        deps2 = {d["name"] for d in m2.get("dependencies", [])}
        diff["new_deps"]     = sorted(deps2 - deps1)
        diff["removed_deps"] = sorted(deps1 - deps2)

        # Intégrité
        diff["sha256_changed"] = (
            m1.get("integrity", {}).get("sha256") != m2.get("integrity", {}).get("sha256")
        )

        # Statut
        s1, s2 = m1.get("status"), m2.get("status")
        diff["status_change"] = f"{s1} → {s2}" if s1 != s2 else None

        # CVE (comparaison du résumé depuis l'index)
        from services.indexer import get_package_info
        info = get_package_info(name)
        if info:
            cve1 = info["versions"].get(v1, {}).get("cve_summary")
            cve2 = info["versions"].get(v2, {}).get("cve_summary")
            if cve1 and cve2:
                sev_keys = ["critical", "high", "medium", "low", "negligible"]
                diff["cve_change"] = {
                    sev: cve2.get(sev, 0) - cve1.get(sev, 0) for sev in sev_keys
                }
            else:
                diff["cve_change"] = None
        else:
            diff["cve_change"] = None

    return {
        "package":     name,
        "arch":        arch,
        "v1":          v1,
        "v2":          v2,
        "v1_manifest": m1,
        "v2_manifest": m2,
        "diff":        diff if (m1 and m2) else None,
        "error":       None if (m1 and m2) else (
            f"Version {'v1' if not m1 else 'v2'} introuvable"
        ),
    }


# ── Limite du nombre de versions ─────────────────────────────────────────────

def _version_age_days(version_info: dict) -> float:
    """
    Retourne l'âge en jours (fraction décimale) d'une version depuis son import.
    Retourne +inf si la date d'import est absente (considérée très ancienne).
    """
    dt = _parse_imported_at(version_info)
    if dt == datetime.min.replace(tzinfo=timezone.utc):
        return float("inf")
    delta = datetime.now(timezone.utc) - dt
    return delta.total_seconds() / 86400.0


def enforce_version_limit(
    name: str,
    max_versions: int,
    min_age_days: int = 0,
    dry_run: bool = False,
) -> list[dict]:
    """
    Si le paquet a plus de `max_versions` versions, supprime les plus anciennes
    jusqu'à atteindre la limite, en respectant l'âge minimum requis.

    Paramètres
    ----------
    name          : nom du paquet
    max_versions  : nombre maximum de versions à conserver (0 = désactivé)
    min_age_days  : une version n'est éligible à la suppression que si elle a
                    au moins `min_age_days` jours d'ancienneté.
                    0 = suppression immédiate (comportement historique).
    dry_run       : si True, retourne les versions qui seraient supprimées sans
                    effectuer aucune suppression réelle.

    Garanties :
      - La version marquée "latest" n'est JAMAIS supprimée.
      - max_versions = 0 → désactivé (retourne []).
      - Si max_versions >= nombre de versions existantes → rien supprimé.
      - Les versions plus récentes que `min_age_days` sont protégées.

    Retourne la liste des versions supprimées (ou à supprimer si dry_run=True) :
      [{
        "name": str, "version": str, "arch": str, "filename": str,
        "age_days": float,
        "deleted_deb": bool, "deleted_manifest": bool,  # False si dry_run
        "skipped_too_young": bool,   # True si protégée par min_age_days
      }]
    """
    if max_versions <= 0:
        return []

    from services.indexer import get_package_info, remove_from_index
    from services.manifest import MANIFEST_DIR, delete_manifest_from_db

    info = get_package_info(name)
    if not info:
        return []

    latest = info.get("latest")
    versions_raw = info.get("versions", {})

    if len(versions_raw) <= max_versions:
        return []

    # Trier par date d'import ascendante (les plus anciennes en premier),
    # en excluant toujours la version "latest"
    sorted_versions = sorted(
        [
            (ver, meta)
            for ver, meta in versions_raw.items()
            if ver != latest
        ],
        key=lambda kv: _parse_imported_at(kv[1]),
    )

    # Nombre de versions à supprimer pour revenir à max_versions
    n_to_delete = len(versions_raw) - max_versions
    candidates  = sorted_versions[:n_to_delete]
    result      = []

    for ver, meta in candidates:
        arch     = meta.get("arch", "amd64")
        filename = meta.get("filename", "")
        age      = _version_age_days(meta)

        # Vérification de l'âge minimum
        if min_age_days > 0 and age < min_age_days:
            result.append({
                "name":               name,
                "version":            ver,
                "arch":               arch,
                "filename":           filename,
                "age_days":           round(age, 2),
                "deleted_deb":        False,
                "deleted_manifest":   False,
                "skipped_too_young":  True,
            })
            logger.info(
                "[snapshots] %s@%s ignoré (âge=%.1fj < min=%dd)",
                name, ver, age, min_age_days,
            )
            continue

        if dry_run:
            result.append({
                "name":               name,
                "version":            ver,
                "arch":               arch,
                "filename":           filename,
                "age_days":           round(age, 2),
                "deleted_deb":        False,
                "deleted_manifest":   False,
                "skipped_too_young":  False,
            })
            continue

        deleted_deb      = False
        deleted_manifest = False

        # 1. Supprimer le .deb du pool
        if filename:
            try:
                deb_path = safe_path_join(POOL_DIR, filename)
            except PathTraversalError:
                logger.warning(f"[snapshots] Nom de fichier suspect ignoré : {filename!r}")
                deb_path = None
            if deb_path and deb_path.exists():
                try:
                    deb_path.unlink()
                    deleted_deb = True
                    logger.info("[snapshots] .deb supprimé : %s", filename)
                except Exception as exc:
                    logger.error("[snapshots] Erreur suppression .deb %s : %s", filename, exc)

        # 2. Supprimer le manifest JSON
        ver_safe = ver.replace(":", "_").replace("/", "_")
        try:
            manifest_path = safe_path_join(MANIFEST_DIR, f"{name}_{ver_safe}_{arch}.manifest.json")
        except PathTraversalError:
            logger.warning(f"[snapshots] Nom de manifest suspect ignoré : {name}_{ver_safe}_{arch}")
            manifest_path = None
        if manifest_path and manifest_path.exists():
            try:
                manifest_path.unlink()
                deleted_manifest = True
                logger.info("[snapshots] Manifest JSON supprimé : %s", manifest_path.name)
            except Exception as exc:
                logger.error("[snapshots] Erreur suppression manifest %s : %s",
                             manifest_path.name, exc)

        # 3. Supprimer de la DB SQLite
        try:
            delete_manifest_from_db(name, ver, arch)
        except Exception:
            pass

        # 4. Mettre à jour l'index
        try:
            remove_from_index(name, ver)
        except Exception as exc:
            logger.error("[snapshots] Erreur suppression index %s@%s : %s", name, ver, exc)

        result.append({
            "name":               name,
            "version":            ver,
            "arch":               arch,
            "filename":           filename,
            "age_days":           round(age, 2),
            "deleted_deb":        deleted_deb,
            "deleted_manifest":   deleted_manifest,
            "skipped_too_young":  False,
        })
        logger.info(
            "[snapshots] enforce_version_limit : %s@%s supprimé (deb=%s, manifest=%s)",
            name, ver, deleted_deb, deleted_manifest,
        )

    return result


def run_version_gc(
    max_versions: int | None = None,
    min_age_days: int | None = None,
    dry_run: bool = False,
) -> dict:
    """
    Applique enforce_version_limit sur tous les paquets connus dans l'index.

    Si max_versions est omis, lit la valeur dans settings.json
    (versioning.max_versions_per_package, défaut 10).
    Si min_age_days est omis, lit versioning.min_version_age_days (défaut 0).

    Paramètres
    ----------
    max_versions : limite du nombre de versions par paquet (0 = désactivé)
    min_age_days : âge minimum requis pour qu'une version soit éligible à la
                   suppression (0 = suppression immédiate)
    dry_run      : si True, simule le GC sans supprimer quoi que ce soit

    Retourne :
      {
        "ran_at":           str,
        "max_versions":     int,
        "min_age_days":     int,
        "dry_run":          bool,
        "packages_checked": int,
        "versions_deleted": int,   # 0 si dry_run
        "versions_skipped": int,   # protégées par min_age_days
        "details": [{"name": ..., "deleted": [...]}]
      }
    """
    from services.settings import get_settings
    from services.indexer import get_index

    settings = get_settings()
    versioning = settings.get("versioning", {})

    if max_versions is None:
        max_versions = int(versioning.get("max_versions_per_package", 10))

    if min_age_days is None:
        min_age_days = int(versioning.get("min_version_age_days", 0))

    if max_versions <= 0:
        return {
            "ran_at":           datetime.now(timezone.utc).isoformat(),
            "max_versions":     0,
            "min_age_days":     min_age_days,
            "dry_run":          dry_run,
            "packages_checked": 0,
            "versions_deleted": 0,
            "versions_skipped": 0,
            "details":          [],
            "note":             "max_versions_per_package=0 — GC désactivé",
        }

    index = get_index()
    packages = list(index.get("packages", {}).keys())

    details = []
    total_deleted = 0
    total_skipped = 0

    for name in packages:
        result = enforce_version_limit(
            name, max_versions,
            min_age_days=min_age_days,
            dry_run=dry_run,
        )
        if result:
            skipped = [r for r in result if r.get("skipped_too_young")]
            total_skipped += len(skipped)
            if not dry_run:
                # En mode réel, seules les versions non-protégées sont vraiment supprimées
                actually_deleted = [r for r in result if not r.get("skipped_too_young")]
                total_deleted += len(actually_deleted)
            details.append({"name": name, "deleted": result})

    return {
        "ran_at":           datetime.now(timezone.utc).isoformat(),
        "max_versions":     max_versions,
        "min_age_days":     min_age_days,
        "dry_run":          dry_run,
        "packages_checked": len(packages),
        "versions_deleted": total_deleted,
        "versions_skipped": total_skipped,
        "details":          details,
    }
