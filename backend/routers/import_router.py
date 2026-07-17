"""
Routes pour l'import de paquets depuis internet.
- GET  /import/search?q=nginx        → recherche dans l'index local
- GET  /import/resolve/{name}        → résout les dépendances online
- POST /import/fetch                 → lance l'import (streaming SSE)
- POST /import/batch                 → importe une liste de paquets
- GET  /import/sync-status           → statut des sources indexées
- POST /import/sync                  → (re)synchronise l'index local
- POST /import/sync/{source_id}      → synchronise une source précise
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from auth.dependencies import (
    get_admin_user,
    get_current_user,
    get_maintainer_user,
    get_uploader_user,
)
from limiter import limiter
from services.audit import log as audit_log
from services.importer import import_package_stream, resolve_deps_online
from services.leader_election import require_leader
from services.mirror import _distribution_for_source
from services.mirror_manager import mirror_manager
from services.package_index import (
    DEFAULT_SOURCES,
    get_sync_status,
    is_indexed,
    search_packages,
    sync_all,
    sync_source,
)
from services.package_index import (
    get_package_info as index_get_info,
)
from services.rate_limits import make_role_limit
from services.security_sync import SECURITY_SOURCES, run_security_sync
from services.settings import get_settings, is_source_enabled, update_settings
from services.sync_manager import sync_manager

IMPORTS_DIR = Path(os.getenv("IMPORTS_DIR", "/repos/imports"))

logger = logging.getLogger("import_router")

router = APIRouter(prefix="/import", tags=["Import"])


# ─── Recherche ────────────────────────────────────────────────────────────────

@router.get("/search")
def search(
    q: str = Query(..., min_length=1, description="Terme de recherche"),
    limit: int = Query(20, ge=1, le=100),
    source_id: str = Query(None),
    format: str = Query(None, description="Filtre format : deb | rpm | apk"),
    distro: str = Query(None, description="Filtre distribution : jammy, almalinux9, alpine3.21…"),
    current_user: str = Depends(get_current_user),
):
    """
    Recherche dans l'index local (Packages.gz mis en cache).
    Ne nécessite pas de connexion internet au moment de la recherche.
    `format` filtre par type de paquet ; `distro` filtre par distribution cible.
    """
    if not is_indexed():
        raise HTTPException(
            status_code=424,
            detail="L'index local est vide. Lancez une synchronisation d'abord."
        )

    results = search_packages(q, limit=limit, source_id=source_id, distro=distro)

    # Filtre côté serveur par format si spécifié
    if format in ("deb", "rpm", "apk"):
        results = [r for r in results if r.get("format") == format]

    return {"query": q, "count": len(results), "results": results}


# ─── Résolution des dépendances ───────────────────────────────────────────────

@router.get("/resolve/{package_name}")
def resolve(
    package_name: str,
    current_user: str = Depends(get_current_user),
):
    """
    Résout les dépendances d'un paquet en temps réel via apt-cache.
    Indique pour chaque dépendance si elle est déjà dans le repo interne.
    """
    result = resolve_deps_online(package_name)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


# ─── Import ───────────────────────────────────────────────────────────────────

class ImportRequest(BaseModel):
    package: str
    group: str | None = None         # groupe d'import cible (défaut = nom du paquet)
    distribution: str | None = None  # distribution cible (défaut = auto-détection depuis source)


class BatchImportRequest(BaseModel):
    packages: list[str]
    group: str | None = None         # tous les paquets du batch vont dans ce groupe
    distribution: str | None = None  # distribution cible pour tous les paquets


@router.post("/fetch")
@limiter.limit(make_role_limit("upload"))
def fetch_package(
    request: Request,
    response: Response,
    body: ImportRequest,
    current_user: str = Depends(get_uploader_user),
):
    """
    Télécharge un paquet et ses dépendances depuis internet,
    les valide et les ajoute au repo.
    Retourne un stream Server-Sent Events pour les logs en temps réel.
    """
    audit_log("IMPORT", current_user, "START",
              package=body.package,
              detail="Import depuis internet lancé")

    def event_stream():
        for chunk in import_package_stream(
            body.package, current_user,
            group=body.group,
            distribution=body.distribution,
        ):
            yield chunk
        yield "data: done|DONE\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@router.post("/batch")
@limiter.limit(make_role_limit("upload"))
def batch_import(
    request: Request,
    response: Response,
    body: BatchImportRequest,
    current_user: str = Depends(get_uploader_user),
):
    """
    Import par lot : stream SSE pour une liste de paquets.
    """
    if not body.packages:
        raise HTTPException(status_code=400, detail="Liste de paquets vide")

    if len(body.packages) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 paquets par batch")

    def event_stream():
        for pkg in body.packages:
            yield f"data: info|=== Import de {pkg} ===\n\n"
            for chunk in import_package_stream(
                pkg, current_user,
                group=body.group,
                distribution=body.distribution,
            ):
                yield chunk
        yield "data: done|DONE\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── Sync de l'index ─────────────────────────────────────────────────────────

@router.get("/sync-status")
def get_status(current_user: str = Depends(get_current_user)):
    """Retourne le statut de synchronisation de chaque source (APT + RPM + APK)."""
    return {"sources": get_sync_status()}


# ─── Jobs de synchronisation en arrière-plan ─────────────────────────────────
#
# POST /import/sync/start          → toutes les sources
# POST /import/sync/start/{target} → apt | rpm | apk | <source_id>
# GET  /import/sync/jobs           → liste des jobs (actifs + historique 1h)
# GET  /import/sync/jobs/{id}      → état d'un job
# GET  /import/sync/jobs/{id}/stream → SSE reconnectable
# ─────────────────────────────────────────────────────────────────────────────

@router.post("/sync/start")
@limiter.limit(make_role_limit("write"))
def start_sync_all(
    request: Request,
    response: Response,
    current_user: str = Depends(get_maintainer_user),
    _leader: None = Depends(require_leader),
):
    """Démarre la synchronisation de toutes les sources en arrière-plan."""
    job = sync_manager.start_job(
        "all",
        user=current_user,
        enabled_filter=is_source_enabled,
    )
    return {
        "job_id": job.job_id,
        "label": job.label,
        "status": job.status,
        "total": job.total,
        "already_running": job.status == "running" and len(job.logs) > 0,
    }


@router.post("/sync/start/{target}")
@limiter.limit(make_role_limit("write"))
def start_sync_target(
    request: Request,
    response: Response,
    target: str,
    current_user: str = Depends(get_maintainer_user),
    _leader: None = Depends(require_leader),
):
    """
    Démarre la synchronisation d'un groupe ou d'une source spécifique.
    target : apt | rpm | apk | <source_id>
    """
    valid_groups = {"apt", "rpm", "apk"}
    source_ids = {s["id"] for s in DEFAULT_SOURCES}

    if target not in valid_groups and target not in source_ids:
        raise HTTPException(
            status_code=400,
            detail=f"Target '{target}' invalide. Groupes valides : apt, rpm, apk. "
                   f"Ou utilisez un source_id valide.",
        )

    job = sync_manager.start_job(
        target,
        user=current_user,
        enabled_filter=is_source_enabled if target in valid_groups else None,
    )
    return {
        "job_id": job.job_id,
        "label": job.label,
        "status": job.status,
        "total": job.total,
        "already_running": job.status == "running" and len(job.logs) > 0,
    }


@router.get("/sync/jobs")
def list_sync_jobs(current_user: str = Depends(get_current_user)):
    """Liste les jobs de sync actifs + terminés récemment (1h)."""
    return {"jobs": sync_manager.list_jobs(limit=20)}


@router.get("/sync/jobs/active")
def active_sync_jobs(current_user: str = Depends(get_current_user)):
    """Retourne uniquement les jobs de sync actuellement actifs."""
    return {"jobs": sync_manager.active_jobs()}


@router.get("/sync/jobs/{job_id}")
def get_sync_job(job_id: str, current_user: str = Depends(get_current_user)):
    """Retourne l'état d'un job de sync."""
    job = sync_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' introuvable")
    return job.to_dict()


@router.post("/sync/jobs/{job_id}/cancel")
def cancel_sync_job(
    job_id: str,
    current_user: str = Depends(get_maintainer_user),
):
    """
    Annule un job de synchronisation en cours.
    La source en cours de téléchargement sera terminée, les suivantes seront ignorées.
    """
    job = sync_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' introuvable")
    cancelled = sync_manager.cancel_job(job_id)
    return {
        "job_id": job_id,
        "cancelled": cancelled,
        "status": job.status,
        "message": "Arrêt demandé" if cancelled else "Job déjà terminé",
    }


@router.get("/sync/jobs/{job_id}/stream")
def stream_sync_job(
    job_id: str,
    from_index: int = Query(0, ge=0, description="Index du premier log à recevoir"),
    current_user: str = Depends(get_current_user),
):
    """
    Stream SSE reconnectable des logs d'un job de sync.
    Le paramètre from_index permet de reprendre depuis le dernier log reçu
    sans perdre les logs précédents (utile après navigation ou reconnexion).
    """
    job = sync_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' introuvable")

    return StreamingResponse(
        job.iter_stream(from_index=from_index),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "X-Job-Id": job_id,
            "X-Job-Total": str(job.total),
        },
    )


# ─── Mirroir planifié sécurisé ───────────────────────────────────────────────
#
# GET  /import/mirror/sources       → sources mirroirables + activation + dernier job
# POST /import/mirror/sources       → met à jour les flags d'activation par source
# GET  /import/mirror/schedule      → planification + limites de sécurité
# POST /import/mirror/schedule      → met à jour la planification (hot-reschedule)
# POST /import/mirror/start/{id}    → lance un job de mirroir maintenant
# GET  /import/mirror/jobs          → jobs actifs + historique (1h)
# GET  /import/mirror/jobs/{id}     → état d'un job
# GET  /import/mirror/jobs/{id}/stream → SSE reconnectable
# POST /import/mirror/jobs/{id}/cancel → annule un job en cours
# ─────────────────────────────────────────────────────────────────────────────

class MirrorSourcesPatch(BaseModel):
    sources: dict[str, bool]


class MirrorSchedulePatch(BaseModel):
    enabled:              bool | None = None
    hour:                 int | None = None
    minute:               int | None = None
    timezone:             str | None = None
    max_packages_per_run: int | None = None
    max_runtime_minutes:  int | None = None
    min_free_disk_gb:     int | None = None


@router.get("/mirror/sources")
def list_mirror_sources(current_user: str = Depends(get_current_user)):
    """Liste les sources mirroirables, leur activation et le dernier job associé."""
    cfg = get_settings().get("mirror", {})
    enabled_sources = cfg.get("sources", {})

    last_jobs: dict[str, dict] = {}
    for job in mirror_manager.list_jobs(limit=50):
        sid = job["source_id"]
        if sid not in last_jobs:
            last_jobs[sid] = job

    sources = []
    for s in DEFAULT_SOURCES:
        sources.append({
            "id":      s["id"],
            "label":   s["label"],
            "format":  s.get("format", "deb"),
            "enabled": enabled_sources.get(s["id"], False),
            "last_job": last_jobs.get(s["id"]),
        })
    return {"sources": sources}


@router.post("/mirror/sources")
@limiter.limit(make_role_limit("write"))
def update_mirror_sources(
    request: Request,
    response: Response,
    body: MirrorSourcesPatch,
    current_user: str = Depends(get_maintainer_user),
):
    """Met à jour les flags d'activation du mirroir par source (opt-in)."""
    valid_ids = {s["id"] for s in DEFAULT_SOURCES}
    unknown = set(body.sources) - valid_ids
    if unknown:
        raise HTTPException(status_code=400, detail=f"Source(s) inconnue(s) : {', '.join(sorted(unknown))}")

    current = get_settings().get("mirror", {}).get("sources", {})
    merged = {**current, **body.sources}
    updated = update_settings({"mirror": {"sources": merged}})
    audit_log("SETTINGS_CHANGE", current_user, "SUCCESS",
              detail=f"Mirroir — sources modifiées : {', '.join(body.sources.keys())}")
    return {"sources": updated["mirror"]["sources"]}


@router.get("/mirror/schedule")
def get_mirror_schedule(current_user: str = Depends(get_current_user)):
    """Retourne la planification du mirroir et les limites de sécurité."""
    cfg = get_settings().get("mirror", {})
    return {k: v for k, v in cfg.items() if k != "sources"}


@router.post("/mirror/schedule")
@limiter.limit(make_role_limit("write"))
def update_mirror_schedule(
    request: Request,
    response: Response,
    body: MirrorSchedulePatch,
    current_user: str = Depends(get_admin_user),
):
    """Met à jour la planification/limites du mirroir et replanifie à chaud."""
    from services import scheduler_state

    partial = {k: v for k, v in body.model_dump().items() if v is not None}
    if not partial:
        return {k: v for k, v in get_settings().get("mirror", {}).items() if k != "sources"}

    updated = update_settings({"mirror": partial})
    mirror_cfg = updated["mirror"]
    audit_log("SETTINGS_CHANGE", current_user, "SUCCESS",
              detail=f"Mirroir — planification modifiée : {', '.join(partial.keys())}")

    # La replanification à chaud est une optimisation (éviter un redémarrage
    # du backend) — un échec ici ne doit jamais faire perdre les paramètres
    # déjà persistés par update_settings() ci-dessus. Mais il ne doit pas non
    # plus être avalé silencieusement : sans ça, un appelant recevait un 200
    # "planification mise à jour" alors que le job APScheduler continuait de
    # tourner sur l'ancien horaire jusqu'au prochain redémarrage du backend,
    # sans aucun moyen de le savoir depuis la réponse de l'API.
    reschedule_warning = None
    if scheduler_state.scheduler is not None:
        try:
            if mirror_cfg.get("enabled", False):
                scheduler_state.scheduler.reschedule_job(
                    "mirror_daily",
                    trigger="cron",
                    hour=int(mirror_cfg.get("hour", 4)),
                    minute=int(mirror_cfg.get("minute", 30)),
                )
                scheduler_state.scheduler.resume_job("mirror_daily")
            else:
                scheduler_state.scheduler.pause_job("mirror_daily")
        except Exception as exc:
            logger.error("[import_router] Échec de la replanification à chaud du mirroir : %s", exc)
            reschedule_warning = (
                f"Paramètres enregistrés, mais la replanification à chaud a échoué ({exc}) — "
                "un redémarrage du backend est nécessaire pour appliquer le nouvel horaire."
            )
            audit_log("SETTINGS_CHANGE", current_user, "WARNING",
                      detail=f"Mirroir — replanification à chaud échouée : {exc}")

    result = {k: v for k, v in mirror_cfg.items() if k != "sources"}
    if reschedule_warning:
        result["reschedule_warning"] = reschedule_warning
    return result


@router.post("/mirror/start/{source_id}")
@limiter.limit(make_role_limit("write"))
def start_mirror_job(
    request: Request,
    response: Response,
    source_id: str,
    limit: int | None = Query(None, ge=1, description="Limite de paquets pour ce job"),
    current_user: str = Depends(get_maintainer_user),
    _leader: None = Depends(require_leader),
):
    """Démarre un job de mirroir pour une source donnée."""
    source = next((s for s in DEFAULT_SOURCES if s["id"] == source_id), None)
    if not source:
        raise HTTPException(status_code=404, detail=f"Source '{source_id}' introuvable")

    distribution = _distribution_for_source(source)
    if not distribution:
        raise HTTPException(status_code=400, detail=f"Distribution introuvable pour '{source_id}'")

    cfg = get_settings().get("mirror", {})
    job = mirror_manager.start_job(
        source_id, distribution, user=current_user,
        limit=limit or cfg.get("max_packages_per_run"),
    )
    return {
        "job_id": job.job_id,
        "label": job.label,
        "status": job.status,
        "total": job.total,
        "already_running": job.status == "running" and len(job.logs) > 0,
    }


@router.get("/mirror/jobs")
def list_mirror_jobs(current_user: str = Depends(get_current_user)):
    """Liste les jobs de mirroir actifs + terminés récemment (1h)."""
    return {"jobs": mirror_manager.list_jobs(limit=20)}


@router.get("/mirror/jobs/{job_id}")
def get_mirror_job(job_id: str, current_user: str = Depends(get_current_user)):
    """Retourne l'état d'un job de mirroir."""
    job = mirror_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' introuvable")
    return job.to_dict()


@router.post("/mirror/jobs/{job_id}/cancel")
def cancel_mirror_job(
    job_id: str,
    current_user: str = Depends(get_maintainer_user),
):
    """Annule un job de mirroir en cours."""
    job = mirror_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' introuvable")
    cancelled = mirror_manager.cancel_job(job_id)
    return {
        "job_id": job_id,
        "cancelled": cancelled,
        "status": job.status,
        "message": "Arrêt demandé" if cancelled else "Job déjà terminé",
    }


@router.get("/mirror/jobs/{job_id}/stream")
def stream_mirror_job(
    job_id: str,
    from_index: int = Query(0, ge=0, description="Index du premier log à recevoir"),
    current_user: str = Depends(get_current_user),
):
    """Stream SSE reconnectable des logs d'un job de mirroir."""
    job = mirror_manager.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' introuvable")

    return StreamingResponse(
        job.iter_stream(from_index=from_index),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "X-Job-Id": job_id,
            "X-Job-Total": str(job.total),
        },
    )


# ─── Compat : ancien endpoint POST /import/sync (redirige vers le système job) ─

@router.post("/sync")
@limiter.limit(make_role_limit("write"))
def sync_index_compat(request: Request, response: Response, current_user: str = Depends(get_maintainer_user)):
    """
    [Compatibilité] Lance une sync globale et stream les logs en SSE.
    Utilise le nouveau système de jobs en arrière-plan.
    """
    job = sync_manager.start_job(
        "all",
        user=current_user,
        enabled_filter=is_source_enabled,
    )
    return StreamingResponse(
        job.iter_stream(from_index=0),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── Analyseur Dockerfile ────────────────────────────────────────────────────

import re as _re

# ── Patterns APT ──────────────────────────────────────────────────────────────
_APT_CMDS = _re.compile(r'apt(?:-get)?\s+install\s+[^\n]*', _re.IGNORECASE)
_APT_FLAGS = _re.compile(r'^-{1,2}[a-zA-Z\-]+=?.*$')
_APT_ENV_PREFIXES = ("DEBIAN_FRONTEND=", "apt-get", "apt")

# ── Patterns RPM (dnf / yum / microdnf) ──────────────────────────────────────
_RPM_CMDS = _re.compile(r'(?:dnf|yum|microdnf)\s+install\s+[^\n]*', _re.IGNORECASE)
_RPM_FLAGS = _re.compile(r'^-{1,2}[a-zA-Z\-]+=?.*$')
_RPM_STOP = {"update", "upgrade", "remove", "erase", "autoremove", "clean",
             "check-update", "groupinstall", "&&", ";", "||", "echo", "rm", "mkdir"}

# ── Patterns APK (Alpine) ─────────────────────────────────────────────────────
_APK_CMDS = _re.compile(r'apk\s+add\s+[^\n]*', _re.IGNORECASE)
_APK_FLAGS = _re.compile(r'^-{1,2}[a-zA-Z\-]+=?.*$')
_APK_STOP = {"update", "upgrade", "del", "fix", "search", "info",
             "&&", ";", "||", "echo", "rm"}


def _parse_apt_packages(content: str) -> list[str]:
    """Extrait les noms de paquets des commandes apt-get install / apt install."""
    merged = content.replace("\\\n", " ")
    packages: set[str] = set()
    for match in _APT_CMDS.finditer(merged):
        capture = False
        for tok in match.group(0).split():
            tok = tok.strip().rstrip(";\\&")
            if not tok:
                continue
            if tok in ("apt-get", "apt", "install", "&&", ";", "\\"):
                if tok == "install":
                    capture = True
                continue
            if not capture:
                continue
            if tok in ("update", "upgrade", "remove", "purge", "autoremove",
                       "clean", "&&", ";", "||", "echo", "rm", "mkdir"):
                break
            if _APT_FLAGS.match(tok):
                continue
            if any(tok.startswith(p) for p in _APT_ENV_PREFIXES):
                continue
            if len(tok) < 2:
                continue
            pkg_name = tok.split("=")[0].split(":")[0].strip().lower()
            if pkg_name and _re.match(r'^[a-z0-9][a-z0-9+\-\.]+$', pkg_name):
                packages.add(pkg_name)
    return sorted(packages)


# Rétro-compatibilité — ancienne signature utilisée par des tests éventuels
_parse_dockerfile_packages = _parse_apt_packages


def _parse_rpm_packages(content: str) -> list[str]:
    """Extrait les noms de paquets des commandes dnf/yum/microdnf install."""
    merged = content.replace("\\\n", " ")
    packages: set[str] = set()
    for match in _RPM_CMDS.finditer(merged):
        capture = False
        for tok in match.group(0).split():
            tok = tok.strip().rstrip(";\\&")
            if not tok:
                continue
            if tok.lower() in ("dnf", "yum", "microdnf", "install", "&&", ";", "\\"):
                if tok.lower() == "install":
                    capture = True
                continue
            if not capture:
                continue
            if tok.lower() in _RPM_STOP:
                break
            if _RPM_FLAGS.match(tok):
                continue
            if len(tok) < 2:
                continue
            # Supprimer arch (.x86_64, .noarch…) et version (name-1.2.3)
            pkg_name = tok.split("=")[0]                    # name=version → name
            pkg_name = _re.sub(r'\.(x86_64|aarch64|i686|noarch|src)$', '', pkg_name)
            pkg_name = pkg_name.strip().lower()
            if pkg_name and _re.match(r'^[a-z0-9][a-z0-9+\-\.\_]+$', pkg_name):
                packages.add(pkg_name)
    return sorted(packages)


def _parse_apk_packages(content: str) -> list[str]:
    """Extrait les noms de paquets des commandes apk add (Alpine Linux)."""
    merged = content.replace("\\\n", " ")
    packages: set[str] = set()
    for match in _APK_CMDS.finditer(merged):
        capture = False
        skip_next = False  # pour --virtual <alias>
        for tok in match.group(0).split():
            tok = tok.strip().rstrip(";\\&")
            if not tok:
                continue
            if skip_next:
                skip_next = False
                continue
            if tok.lower() in ("apk", "&&", ";", "\\"):
                continue
            if tok.lower() == "add":
                capture = True
                continue
            if not capture:
                continue
            if tok.lower() in _APK_STOP:
                break
            if _APK_FLAGS.match(tok):
                # --virtual / -t prend un argument (l'alias) → ignorer le token suivant
                if tok in ("--virtual", "-t") or tok.startswith("--virtual="):
                    if "=" not in tok:
                        skip_next = True
                continue
            if len(tok) < 2:
                continue
            pkg_name = tok.split("=")[0].split("@")[0].strip().lower()
            if pkg_name and _re.match(r'^[a-z0-9][a-z0-9+\-\.]+$', pkg_name):
                packages.add(pkg_name)
    return sorted(packages)


def _detect_base_image(content: str) -> dict:
    """
    Détecte le gestionnaire de paquets et la distribution depuis un Dockerfile.

    Stratégie (ordre de priorité) :
    1. Commandes RUN : apk add / apt-get install / dnf install  → source de vérité absolue
       (peu importe le nom de l'image — "mycompany/app:v2" ne dit rien,
        mais "apk add nginx" est sans ambiguïté)
    2. Ligne FROM    : utile pour déduire la version/distribution → fallback
    """
    # ── 1. Commandes RUN ──────────────────────────────────────────────────────────
    has_apk = bool(_re.search(r'\bapk\s+add\b',                          content, _re.IGNORECASE))
    has_apt = bool(_re.search(r'\b(?:apt-get|apt)\s+(?:install|upgrade)\b', content, _re.IGNORECASE))
    has_rpm = bool(_re.search(r'\b(?:dnf|yum|microdnf)\s+install\b',     content, _re.IGNORECASE))
    pm_count = sum([has_apk, has_apt, has_rpm])
    # Un seul PM dans les commandes → certitude
    if pm_count == 1:
        pm_from_cmds = "apk" if has_apk else ("apt" if has_apt else "rpm")
    else:
        pm_from_cmds = None

    # ── 2. Ligne FROM ─────────────────────────────────────────────────────────────
    from_match = _re.search(r'^FROM\s+(\S+)', content, _re.MULTILINE | _re.IGNORECASE)
    pm_from_image = None
    distribution  = None

    if from_match:
        # "FROM image:tag AS alias" → garder seulement "image:tag"
        full_ref = _re.split(r'\s+as\s+', from_match.group(1), flags=_re.IGNORECASE)[0].lower()
        # Dernier segment (registry.io/org/image:tag → "image")
        image = full_ref.split(":")[0].split("/")[-1]

        if "alpine" in full_ref:
            pm_from_image = "apk"
            ver_m = _re.search(r'alpine[-:/]?(\d+\.\d+)', full_ref)
            distribution = f"alpine-{ver_m.group(1) if ver_m else '3.20'}"

        elif _re.search(r'\b(almalinux|rockylinux|rhel|ubi\d+|centos|oraclelinux)\b', full_ref):
            pm_from_image = "rpm"
            ubi_m = _re.search(r'\bubi(\d+)\b', full_ref)
            img_m = _re.search(r'(?:almalinux|rockylinux|rhel|centos|oraclelinux)[:/](\d+)', full_ref)
            ver   = (ubi_m or img_m)
            distribution = f"el{ver.group(1) if ver else '9'}"

        elif "fedora" in full_ref:
            pm_from_image = "rpm"
            ver_m = _re.search(r'[:/](\d+)', full_ref)
            distribution = f"fc{ver_m.group(1) if ver_m else '41'}"

        else:
            apt_map = {
                "noble": "noble", "24.04": "noble",
                "jammy": "jammy", "22.04": "jammy",
                "focal":  "focal",  "20.04": "focal",
                "bookworm": "bookworm", "bullseye": "bullseye", "buster": "buster",
            }
            for key, codename in apt_map.items():
                if key in full_ref:
                    pm_from_image = "apt"
                    distribution  = codename
                    break
            if not pm_from_image and _re.search(
                r'\b(ubuntu|debian|node|python|ruby|php|nginx|openjdk|golang|gradle|maven)\b', image
            ):
                pm_from_image = "apt"
                distribution  = "bookworm"

    # ── 3. Résolution finale ──────────────────────────────────────────────────────
    # Priorité : commandes RUN > nom d'image FROM
    pkg_manager = pm_from_cmds or pm_from_image
    if not pkg_manager:
        return {"pkg_manager": None, "distribution": None}

    # Si les commandes contredisent l'image FROM (ex: FROM node:22 + apk add),
    # la distribution déduite du FROM n'est plus cohérente → on la jette
    if pm_from_cmds and pm_from_cmds != pm_from_image:
        distribution = None

    # Distribution par défaut si FROM ne l'indique pas
    if not distribution:
        if pkg_manager == "apk":  distribution = "alpine-3.20"
        elif pkg_manager == "rpm": distribution = "el9"
        else:                      distribution = "bookworm"

    return {"pkg_manager": pkg_manager, "distribution": distribution}


class DockerfileAnalyzeRequest(BaseModel):
    content: str        # Contenu brut du Dockerfile
    distribution: str | None = None  # Distribution cible (jammy, el9, alpine-3.20…)


@router.post("/analyze-dockerfile")
def analyze_dockerfile(
    body: DockerfileAnalyzeRequest,
    current_user: str = Depends(get_uploader_user),
):
    """
    Analyse un Dockerfile et retourne :
    - La liste des paquets APT / RPM / APK référencés (toutes distributions)
    - Pour chaque paquet : présent dans repod (available), importable ou inconnu
    - La détection automatique de l'image de base (pkg_manager + distribution suggérée)

    Ne lance aucun import — analyse statique uniquement.
    """
    from services.indexer import list_packages_from_index
    from services.package_index import get_package_info as upstream_get_info

    if not body.content.strip():
        raise HTTPException(status_code=400, detail="Dockerfile vide")
    if len(body.content) > 500_000:
        raise HTTPException(status_code=400, detail="Dockerfile trop volumineux (max 500 Ko)")

    # Détecter l'image de base
    base_image = _detect_base_image(body.content)

    # Extraire les paquets par gestionnaire
    apt_pkgs = [(p, "apt") for p in _parse_apt_packages(body.content)]
    rpm_pkgs = [(p, "rpm") for p in _parse_rpm_packages(body.content)]
    apk_pkgs = [(p, "apk") for p in _parse_apk_packages(body.content)]
    all_pkgs = apt_pkgs + rpm_pkgs + apk_pkgs

    if not all_pkgs:
        return {
            "packages_found": [],
            "total": 0, "available": 0, "missing": 0, "importable": 0, "unknown": 0,
            "distribution": body.distribution,
            "base_image": base_image,
        }

    # Paquets déjà dans repod (index local)
    repod_names = {p["name"] for p in list_packages_from_index()}

    results = []
    for pkg, pm in all_pkgs:
        in_repod = pkg in repod_names
        if in_repod:
            status = "available"
            upstream_info = None
        else:
            row = upstream_get_info(pkg)
            if row:
                status = "importable"
                upstream_info = {
                    "version":   row.get("version"),
                    "section":   row.get("section"),
                    "size":      row.get("size"),
                    "source_id": row.get("source_id"),
                }
            else:
                status = "unknown"
                upstream_info = None

        results.append({
            "name":          pkg,
            "status":        status,       # "available" | "importable" | "unknown"
            "pkg_manager":   pm,           # "apt" | "rpm" | "apk"
            "upstream_info": upstream_info,
        })

    n_available  = sum(1 for r in results if r["status"] == "available")
    n_importable = sum(1 for r in results if r["status"] == "importable")
    n_unknown    = sum(1 for r in results if r["status"] == "unknown")

    audit_log("DOCKERFILE_ANALYZE", current_user, "SUCCESS",
              detail=f"{len(results)} paquets ({base_image.get('pkg_manager','?')}) — "
                     f"{n_available} OK / {n_importable} importables / {n_unknown} inconnus")

    return {
        "packages_found": results,
        "total":       len(results),
        "available":   n_available,
        "missing":     n_importable + n_unknown,
        "importable":  n_importable,
        "unknown":     n_unknown,
        "distribution": body.distribution,
        "base_image":  base_image,
    }


# ─── Groupes d'import ────────────────────────────────────────────────────────

@router.get("/groups")
def list_import_groups(current_user: str = Depends(get_current_user)):
    """Liste tous les groupes d'import (un répertoire par paquet importé)."""
    IMPORTS_DIR.mkdir(parents=True, exist_ok=True)
    groups = []
    for group_dir in sorted(IMPORTS_DIR.iterdir()):
        if not group_dir.is_dir():
            continue
        debs = sorted(group_dir.glob("*.deb"))
        if not debs:
            continue
        total_size = sum(f.stat().st_size for f in debs)
        # Date de création = date du fichier le plus ancien
        imported_at = min(f.stat().st_mtime for f in debs)
        groups.append({
            "name": group_dir.name,
            "package_count": len(debs),
            "total_size_bytes": total_size,
            "imported_at": datetime.fromtimestamp(imported_at, tz=timezone.utc).isoformat(),
            "packages": [
                {
                    "filename": f.name,
                    "size_bytes": f.stat().st_size,
                }
                for f in debs
            ],
        })
    return {"groups": groups}


@router.delete("/groups/{group_name}")
def delete_import_group(
    group_name: str,
    current_user: str = Depends(get_admin_user),
):
    """Supprime un groupe d'import (les fichiers dans /repos/imports/{name})."""
    import re
    import shutil
    if not re.match(r'^[\w.\-+]+$', group_name):
        raise HTTPException(status_code=400, detail="Nom de groupe invalide")
    group_dir = IMPORTS_DIR / group_name
    if not group_dir.exists():
        raise HTTPException(status_code=404, detail=f"Groupe '{group_name}' introuvable")
    shutil.rmtree(str(group_dir))
    audit_log("IMPORT_GROUP_DELETE", current_user, "SUCCESS", detail=f"Groupe '{group_name}' supprimé")
    return {"deleted": group_name}


@router.post("/sync/{source_id}")
def sync_one_source(
    source_id: str,
    current_user: str = Depends(get_maintainer_user),
):
    """
    Synchronise une source spécifique en arrière-plan.
    Retourne immédiatement un job_id pour suivre la progression.
    """
    if not any(s["id"] == source_id for s in DEFAULT_SOURCES):
        raise HTTPException(status_code=404, detail=f"Source '{source_id}' inconnue")

    job = sync_manager.start_job(source_id, user=current_user)
    return {
        "job_id": job.job_id,
        "source_id": source_id,
        "status": job.status,
    }


# ─── Sync sécurité ────────────────────────────────────────────────────────────

@router.post("/sync-security")
def sync_security(current_user: str = Depends(get_maintainer_user)):
    """
    Déclenche manuellement la synchronisation de toutes les sources de sécurité.
    Retourne un stream SSE avec la progression en temps réel.
    Equivalent à ce que fait le cron quotidien à 03:00.
    """
    def event_stream():
        yield f"data: info|🔒 Synchronisation des sources de sécurité ({len(SECURITY_SOURCES)} sources)...\n\n"
        for source in SECURITY_SOURCES:
            yield f"data: info|Synchronisation de {source['label']}...\n\n"
            result = sync_source(source)
            if result["status"] == "ok":
                yield f"data: success|✅ {source['label']} — {result['pkg_count']} paquets indexés\n\n"
            else:
                yield f"data: error|❌ {source['label']} — {result.get('error', 'Erreur inconnue')}\n\n"

        audit_log("SECURITY_SYNC", current_user, "SUCCESS",
                  detail="Sync sécurité déclenchée manuellement")
        yield "data: success|🔒 Synchronisation sécurité terminée\n\n"
        yield "data: done|DONE\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/sync-schedule")
def get_sync_schedule(current_user: str = Depends(get_current_user)):
    """
    Retourne les informations sur la planification du cron de sécurité.
    Lit depuis settings.json (source de vérité) pour être cohérent avec le scheduler.
    """
    from services.settings import get_settings
    sync_cfg = get_settings().get("sync", {})
    hour = int(sync_cfg.get("hour", 3))
    minute = int(sync_cfg.get("minute", 0))
    enabled = sync_cfg.get("enabled", True)
    return {
        "schedule": f"Chaque jour à {hour:02d}:{minute:02d} (Europe/Paris)",
        "cron": f"0 {minute} {hour} * * *",
        "enabled": enabled,
        "security_sources": [
            {"id": s["id"], "label": s["label"]}
            for s in SECURITY_SOURCES
        ],
    }
