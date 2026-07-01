"""
Mirroir planifié sécurisé — point d'entrée cron.

Pour chaque source activée dans settings["mirror"]["sources"], lance un job
de mirroir (services.mirror_manager) qui télécharge, valide (ClamAV + Grype +
GPG + dépendances) et ajoute au repo interne tous les paquets indexés de la
source, dans la limite de settings["mirror"]["max_packages_per_run"] et
settings["mirror"]["max_runtime_minutes"].

Planifié via APScheduler (main.py, job "mirror_daily"), hot-reschedulable
via scheduler_state.py. Déclenchable manuellement via
POST /import/mirror/start/{source_id} (import_router.py).
"""

import logging
import time

from services.distributions import detect_distribution_from_source
from services.mirror_manager import mirror_manager
from services.package_index import DEFAULT_SOURCES
from services.settings import get_settings

logger = logging.getLogger("mirror")


def _distribution_for_source(source: dict) -> str:
    """
    Détermine la distribution cible (codename repod) pour une source upstream.

    Les sources APK n'ont pas de mapping dans SOURCE_TO_DISTRIB (réservé à
    APT/RPM, dont les fonctions detect_distribution_from_source() renvoient
    toujours une valeur par défaut non-vide même pour un source_id inconnu).
    On utilise donc directement le champ "distro" de la source pour l'APK
    (ex: "alpine3.21", correspondant aux codenames ALPINE_DISTRIBUTIONS), et
    detect_distribution_from_source() pour APT/RPM.
    """
    if source.get("format") == "apk":
        return source.get("distro", "")
    return detect_distribution_from_source(source["id"])


def run_scheduled_mirror() -> dict:
    """Point d'entrée du job APScheduler "mirror_daily"."""
    cfg = get_settings().get("mirror", {})
    if not cfg.get("enabled"):
        logger.info("[mirror] Mirroir planifié désactivé — aucun job lancé.")
        return {"skipped": True}

    sources_cfg = cfg.get("sources", {})
    enabled_ids = [sid for sid, on in sources_cfg.items() if on]

    if not enabled_ids:
        logger.info("[mirror] Aucune source activée pour le mirroir.")
        return {"skipped": True, "reason": "no sources enabled"}

    max_packages = cfg.get("max_packages_per_run", 300)
    max_runtime_minutes = cfg.get("max_runtime_minutes", 90)
    deadline = time.monotonic() + max_runtime_minutes * 60

    results = []
    total_pending = 0
    total_blocked = 0

    for source_id in enabled_ids:
        source = next((s for s in DEFAULT_SOURCES if s["id"] == source_id), None)
        if not source:
            logger.warning(f"[mirror] Source inconnue ignorée : {source_id}")
            continue

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            logger.info("[mirror] Budget de temps épuisé — arrêt du mirroir planifié.")
            break

        distribution = _distribution_for_source(source)
        if not distribution:
            logger.warning(f"[mirror] Distribution introuvable pour la source '{source_id}' — ignorée.")
            continue

        job = mirror_manager.start_job(source_id, distribution, user="scheduler", limit=max_packages)

        # Attendre la fin du job (ou le budget de temps restant)
        while job.status == "running" and (time.monotonic() < deadline):
            time.sleep(2)

        if job.status == "running" and time.monotonic() >= deadline:
            job.cancel()
            # Laisser le temps au job de s'arrêter proprement
            for _ in range(30):
                if job.status != "running":
                    break
                time.sleep(1)

        job_dict = job.to_dict()
        results.append(job_dict)
        total_pending += job_dict["pending_count"]
        total_blocked += job_dict["blocked_count"]

    summary = {
        "skipped": False,
        "sources": results,
        "total_pending": total_pending,
        "total_blocked": total_blocked,
    }

    logger.info(
        f"[mirror] Mirroir planifié terminé — {len(results)} source(s), "
        f"{total_pending} en revue, {total_blocked} bloqué(s)."
    )
    return summary
