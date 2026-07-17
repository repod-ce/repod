"""
Synchronisation automatique des sources de sécurité.

Planifié via APScheduler (main.py) → cron quotidien configurable.
Déclenché manuellement via POST /import/sync-security.

Format-aware : s'adapte automatiquement au mode APT ou RPM via REPO_FORMAT.
  - REPO_FORMAT=apt → synchronise les sources de sécurité Ubuntu/Debian
  - REPO_FORMAT=rpm → synchronise les sources de sécurité RHEL/Fedora/openSUSE

Respecte les paramètres :
  - settings.sources  : sources activées/désactivées

Rafraîchit aussi, chaque jour, les trois bases de sécurité affichées sur la
page Supervision : Grype (base CVE), KEV (CISA) et EPSS (FIRST.org) — même
logique que les boutons manuels "Mettre à jour"
(POST /security/grype/update, POST /security/feeds/refresh), pour que ces
bases ne dépendent plus uniquement d'un scan CVE explicite ou d'un clic
manuel pour sortir de l'état "Non disponible" sur une instance neuve.
"""

import logging
from datetime import datetime, timezone

from services.package_index import DEFAULT_SOURCES, sync_source
from services.audit import log as audit_log
from services.settings import get_settings
from services.grype_db import update_grype_db
from services.cve_enrichment import refresh_kev, refresh_epss_bulk

logger = logging.getLogger("security_sync")

# Toutes les sources marquées security=True (référence statique du module)
ALL_SECURITY_SOURCES = [s for s in DEFAULT_SOURCES if s.get("security")]


def _get_active_security_sources() -> list[dict]:
    """Retourne les sources sécurité activées dans les paramètres."""
    settings = get_settings()
    enabled = settings.get("sources", {})
    return [s for s in ALL_SECURITY_SOURCES if enabled.get(s["id"], True)]


def run_security_sync() -> dict:
    """
    Synchronise toutes les sources de sécurité activées.
    Appelé par le scheduler (cron) ET par l'endpoint manuel POST /import/sync-security.

    Retourne :
    {
        "started_at": "...",
        "finished_at": "...",
        "sources": [...],
        "total_ok": int,
        "total_error": int,
        "skipped": int,
    }
    """
    started_at = datetime.now(timezone.utc).isoformat()
    active_sources = _get_active_security_sources()
    skipped = len(ALL_SECURITY_SOURCES) - len(active_sources)

    logger.info(
        f"[security_sync] Démarrage — {len(active_sources)} source(s) active(s), "
        f"{skipped} désactivée(s)."
    )

    # Mise à jour de la base de vulnérabilités Grype (CVE) — pas de daemon
    # comme freshclam pour ClamAV, donc rafraîchie ici quotidiennement.
    logger.info("[security_sync] Mise à jour de la base Grype...")
    grype_result = update_grype_db()
    if grype_result["ok"]:
        logger.info("[security_sync] ✅ Base Grype à jour.")
        audit_log("GRYPE_DB_UPDATE", "scheduler", "SUCCESS")
    else:
        logger.error(f"[security_sync] ❌ Mise à jour Grype échouée : {grype_result['output']}")
        audit_log("GRYPE_DB_UPDATE", "scheduler", "ERROR", detail=grype_result["output"][:500])

    # Rafraîchissement KEV (CISA) — non bloquant : un échec réseau conserve
    # le dernier cache connu et n'interrompt jamais la synchro des sources.
    logger.info("[security_sync] Rafraîchissement KEV (CISA)...")
    if refresh_kev():
        logger.info("[security_sync] ✅ KEV à jour.")
        audit_log("KEV_UPDATE", "scheduler", "SUCCESS")
    else:
        logger.warning("[security_sync] ⚠️ Mise à jour KEV impossible (cache conservé).")
        audit_log("KEV_UPDATE", "scheduler", "WARNING", detail="Flux CISA injoignable, cache conservé")

    # Rafraîchissement EPSS (FIRST.org) — même logique non bloquante.
    logger.info("[security_sync] Rafraîchissement EPSS (FIRST.org)...")
    epss_ok, epss_count = refresh_epss_bulk()
    if epss_ok:
        logger.info(f"[security_sync] ✅ EPSS à jour — {epss_count} scores.")
        audit_log("EPSS_UPDATE", "scheduler", "SUCCESS", detail=f"{epss_count} scores")
    else:
        logger.warning("[security_sync] ⚠️ Mise à jour EPSS impossible (cache conservé).")
        audit_log("EPSS_UPDATE", "scheduler", "WARNING", detail="API FIRST.org injoignable, cache conservé")

    results = []
    total_ok = 0
    total_error = 0

    for source in active_sources:
        logger.info(f"[security_sync] Synchronisation : {source['label']}")
        result = sync_source(source)
        result["label"] = source["label"]
        results.append(result)

        if result["status"] == "ok":
            total_ok += 1
            logger.info(f"[security_sync] ✅ {source['label']} — {result['pkg_count']} paquets")
        else:
            total_error += 1
            logger.error(f"[security_sync] ❌ {source['label']} — {result.get('error')}")

    finished_at = datetime.now(timezone.utc).isoformat()
    status = "SUCCESS" if total_error == 0 else ("PARTIAL" if total_ok > 0 else "ERROR")

    audit_log(
        "SECURITY_SYNC", "scheduler", status,
        detail=(
            f"{total_ok} OK, {total_error} erreur(s), {skipped} source(s) désactivée(s)"
        ),
    )

    summary = {
        "started_at": started_at,
        "finished_at": finished_at,
        "sources": results,
        "total_ok": total_ok,
        "total_error": total_error,
        "skipped": skipped,
        "grype_db": grype_result,
    }

    logger.info(f"[security_sync] Terminé — {total_ok} OK / {total_error} erreur(s).")
    return summary


# Exposé pour import_router.py
SECURITY_SOURCES = ALL_SECURITY_SOURCES
