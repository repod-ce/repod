"""
Politique de rétention automatique.

Tâches planifiées chaque nuit (02:00) via APScheduler :
  1. Purge des logs d'audit  → supprime les fichiers JSONL plus vieux que audit_days
  2. Purge des vieux paquets → supprime les versions périmées (manifests + pool)
     - Pour chaque (nom, arch) → conserve la version la plus récente
     - Supprime les versions plus vieilles que import_cleanup_days SEULEMENT
       si une version plus récente existe (on ne supprime jamais la dernière version)

Peut aussi être déclenché manuellement via POST /settings/run-retention.
"""

import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path

from services.audit import log as audit_log, AUDIT_DIR
from services.manifest import list_manifests, MANIFEST_DIR
from services.settings import get_settings
from services.path_safety import safe_path_join, PathTraversalError

logger = logging.getLogger("retention")

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))


# ─── Audit logs ───────────────────────────────────────────────────────────────

def _purge_audit_logs(audit_days: int) -> dict:
    """
    Supprime les fichiers JSONL d'audit dont la date est antérieure à audit_days.
    Retourne {"deleted": N, "kept": M, "freed_bytes": B}.
    """
    if audit_days <= 0:
        return {"deleted": 0, "kept": 0, "freed_bytes": 0}

    cutoff = datetime.now(timezone.utc).date() - timedelta(days=audit_days)
    deleted = 0
    kept = 0
    freed_bytes = 0

    for log_file in sorted(AUDIT_DIR.glob("*.jsonl")):
        # Le nom du fichier est YYYY-MM-DD.jsonl
        stem = log_file.stem  # e.g. "2025-11-01"
        try:
            file_date = datetime.strptime(stem, "%Y-%m-%d").date()
        except ValueError:
            kept += 1
            continue

        if file_date < cutoff:
            size = log_file.stat().st_size
            try:
                log_file.unlink()
                freed_bytes += size
                deleted += 1
                logger.info(f"[retention] Audit log supprimé : {log_file.name}")
            except Exception as e:
                logger.error(f"[retention] Impossible de supprimer {log_file.name} : {e}")
                kept += 1
        else:
            kept += 1

    return {"deleted": deleted, "kept": kept, "freed_bytes": freed_bytes}


# ─── Vieux paquets ────────────────────────────────────────────────────────────

def _parse_imported_at(manifest: dict) -> datetime | None:
    """Extrait la date d'import depuis le manifest."""
    try:
        raw = manifest.get("source", {}).get("imported_at", "")
        if not raw:
            return None
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _purge_old_packages(import_cleanup_days: int) -> dict:
    """
    Pour chaque (nom, arch, distribution), conserve uniquement la version
    la plus récente. Supprime les versions plus anciennes si leur date
    d'import est antérieure à import_cleanup_days.

    Ne supprime jamais la seule version disponible d'un paquet.

    Retourne {"deleted": N, "freed_bytes": B, "packages": [...]}.
    """
    if import_cleanup_days <= 0:
        return {"deleted": 0, "freed_bytes": 0, "packages": []}

    cutoff = datetime.now(timezone.utc) - timedelta(days=import_cleanup_days)
    manifests = list_manifests()

    # Grouper par (nom, arch, distribution)
    groups: dict[tuple, list[dict]] = {}
    for m in manifests:
        key = (m.get("name", ""), m.get("arch", "amd64"), m.get("distribution", "jammy"))
        groups.setdefault(key, []).append(m)

    deleted = 0
    freed_bytes = 0
    deleted_packages = []

    for (name, arch, distrib), versions in groups.items():
        if len(versions) <= 1:
            # Une seule version — ne jamais supprimer
            continue

        # Trier par date d'import (la plus récente en dernier)
        def sort_key(m):
            dt = _parse_imported_at(m)
            return dt or datetime.min.replace(tzinfo=timezone.utc)

        versions_sorted = sorted(versions, key=sort_key)

        # Garder la plus récente (dernière après tri)
        latest = versions_sorted[-1]
        candidates = versions_sorted[:-1]

        for m in candidates:
            imported_at = _parse_imported_at(m)
            if imported_at is None:
                continue
            # S'assurer que la date est timezone-aware
            if imported_at.tzinfo is None:
                imported_at = imported_at.replace(tzinfo=timezone.utc)

            if imported_at >= cutoff:
                # Pas encore assez vieux → on garde
                continue

            version = m.get("version", "unknown")
            filename = m.get("filename", "")

            # Supprimer le manifest
            version_safe = version.replace(":", "_").replace("/", "_")
            try:
                manifest_path = safe_path_join(MANIFEST_DIR, f"{name}_{version_safe}_{arch}.manifest.json")
            except PathTraversalError:
                logger.warning(f"[retention] Nom de manifest suspect ignoré : {name}_{version_safe}_{arch}")
                manifest_path = None
            manifest_deleted = False
            if manifest_path and manifest_path.exists():
                try:
                    manifest_path.unlink()
                    manifest_deleted = True
                    logger.info(f"[retention] Manifest supprimé : {manifest_path.name}")
                except Exception as e:
                    logger.error(f"[retention] Erreur manifest {manifest_path.name} : {e}")

            # Supprimer le fichier .deb du pool
            pool_deleted = False
            pool_freed = 0
            if filename:
                try:
                    pool_path = safe_path_join(POOL_DIR, filename)
                except PathTraversalError:
                    logger.warning(f"[retention] Nom de fichier suspect ignoré : {filename!r}")
                    pool_path = None
                if pool_path and pool_path.exists():
                    try:
                        pool_freed = pool_path.stat().st_size
                        pool_path.unlink()
                        pool_deleted = True
                        logger.info(f"[retention] Pool supprimé : {pool_path.name}")
                    except Exception as e:
                        logger.error(f"[retention] Erreur pool {pool_path.name} : {e}")

            if manifest_deleted or pool_deleted:
                deleted += 1
                freed_bytes += pool_freed
                deleted_packages.append({
                    "name":        name,
                    "version":     version,
                    "arch":        arch,
                    "distribution": distrib,
                    "imported_at": imported_at.isoformat(),
                })

    return {
        "deleted":  deleted,
        "freed_bytes": freed_bytes,
        "packages": deleted_packages,
    }


# ─── Point d'entrée principal ─────────────────────────────────────────────────

def run_retention() -> dict:
    """
    Exécute la politique de rétention complète.
    Retourne un résumé des actions effectuées.
    Enregistre le résultat dans l'audit log.

    Sprint 6.1 : déclenche aussi le GC de versions (max_versions_per_package).
    Sprint 6.2 : notifie SLA_OVERDUE si des paquets dépassent le SLA, et
                 VERSION_GC si des versions ont été supprimées.
    """
    from services.notifications import notify
    from services.snapshots import run_version_gc
    from services.dashboard import get_sla_overdue

    settings = get_settings()
    retention_cfg = settings.get("retention", {})
    audit_days          = int(retention_cfg.get("audit_days", 90))
    import_cleanup_days = int(retention_cfg.get("import_cleanup_days", 30))

    logger.info(
        "[retention] Démarrage — audit_days=%d, import_cleanup_days=%d",
        audit_days, import_cleanup_days,
    )

    audit_result   = _purge_audit_logs(audit_days)
    package_result = _purge_old_packages(import_cleanup_days)

    # ── Purge des JWT révoqués expirés (table revoked_tokens) ─────────────────
    try:
        from auth.token_revocation import purge_expired as _purge_revoked_tokens
        revoked_purged = _purge_revoked_tokens()
        logger.info("[retention] Tokens révoqués purgés : %d", revoked_purged)
    except Exception as exc:
        logger.error("[retention] Purge revoked_tokens échouée : %s", exc)
        revoked_purged = 0

    # ── Sprint 6.1 : GC de versions par compte ────────────────────────────────
    try:
        gc_result = run_version_gc()
        logger.info(
            "[retention] GC versions : %d supprimée(s), %d ignorée(s)",
            gc_result["versions_deleted"], gc_result.get("versions_skipped", 0),
        )
    except Exception as exc:
        logger.error("[retention] GC versions échoué : %s", exc)
        gc_result = {}

    total_freed = audit_result["freed_bytes"] + package_result["freed_bytes"]

    summary = {
        "ran_at":            datetime.now(timezone.utc).isoformat(),
        "audit_logs":        audit_result,
        "packages":          package_result,
        "version_gc":        gc_result,
        "revoked_tokens_purged": revoked_purged,
        "total_freed_bytes": total_freed,
    }

    audit_log(
        "RETENTION", "scheduler", "SUCCESS",
        detail=(
            f"Audit logs supprimés : {audit_result['deleted']} fichiers, "
            f"Paquets supprimés : {package_result['deleted']}, "
            f"Versions GC : {gc_result.get('versions_deleted', 0)}, "
            f"Libéré : {total_freed / 1024 / 1024:.1f} Mo"
        ),
    )

    # ── Sprint 6.2 : notifications ────────────────────────────────────────────
    # SLA_OVERDUE — paquets pending_review depuis trop longtemps
    try:
        overdue = get_sla_overdue()
        if overdue:
            pkg_list = "\n".join(
                f"  • {e['name']}@{e['version']} — {e['age_days']:.0f} jours"
                for e in overdue
            )
            notify("SLA_OVERDUE", {
                "count":        len(overdue),
                "max_age_days": settings.get("sla", {}).get("review_max_age_days", 7),
                "package_list": pkg_list,
            })
    except Exception as exc:
        logger.warning("[retention] Notification SLA_OVERDUE échouée : %s", exc)

    # VERSION_GC — notification si des versions ont réellement été supprimées
    try:
        if gc_result.get("versions_deleted", 0) > 0:
            notify("VERSION_GC", {
                "versions_deleted": gc_result["versions_deleted"],
                "versions_skipped": gc_result.get("versions_skipped", 0),
                "packages_checked": gc_result.get("packages_checked", 0),
                "max_versions":     gc_result.get("max_versions", "?"),
                "min_age_days":     gc_result.get("min_age_days", 0),
            })
    except Exception as exc:
        logger.warning("[retention] Notification VERSION_GC échouée : %s", exc)

    # GC des demandes de promotion décidées anciennes (> 90 jours)
    pending_gc_deleted = 0
    try:
        from services.pending_promotions import purge_old_decided
        pending_gc_deleted = purge_old_decided(max_age_days=90)
        if pending_gc_deleted:
            logger.info("[retention] GC pending promotions : %d demandes supprimées", pending_gc_deleted)
    except Exception as exc:
        logger.warning("[retention] GC pending promotions échoué : %s", exc)

    summary["pending_promotions_gc"] = pending_gc_deleted

    logger.info(
        "[retention] Terminé — audit:%d logs, paquets:%d, gc:%d versions, libéré:%.1f Mo",
        audit_result["deleted"], package_result["deleted"],
        gc_result.get("versions_deleted", 0), total_freed / 1024 / 1024,
    )

    return summary
