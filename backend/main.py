# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
import logging
import os
from contextlib import asynccontextmanager

from apscheduler.events import EVENT_JOB_ERROR, JobExecutionEvent
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from auth.roles import seed_builtin_roles
from auth.router import router as auth_router
from middleware.metrics_middleware import MetricsMiddleware
from middleware.request_id import RequestIdMiddleware
from middleware.security_headers import SecurityHeadersMiddleware
from routers.artifacts import router as artifacts_router
from routers.dashboard_router import router as dashboard_router
from routers.distributions_router import auto_init_distributions
from routers.distributions_router import router as distributions_router
from routers.downloads_router import router as downloads_router
from routers.groups_router import router as groups_router
from routers.health_router import router as health_router
from routers.import_router import router as import_router
from routers.license_router import router as license_router
from routers.logs_router import router as logs_router
from routers.metrics_router import router as metrics_router
from routers.packages import router as packages_router
from routers.roles_router import router as roles_router
from routers.security_router import router as security_router
from routers.settings_router import export_public_key as _export_gpg_pubkey
from routers.settings_router import router as settings_router
from routers.setup_router import router as setup_router
from routers.templates_router import router as templates_router
from routers.upload import router as upload_router
from routers.webhook_router import router as webhook_router
from services import leader_election, scheduler_state
from services.cve_rematch import run_cve_rematch_daily
from services.logging_config import setup_logging
from services.mirror import run_scheduled_mirror
from services.notifications import notify
from services.retention import run_retention
from services.security_sync import run_security_sync
from services.settings import get_settings
from services.sla_alerts import run_sla_check

load_dotenv()

setup_logging()
logger = logging.getLogger("main")

# ── Validation des secrets obligatoires au démarrage ─────────────────────────
_IS_PRODUCTION = os.getenv("ENV", "development") == "production"

_JWT_SECRET = os.getenv("JWT_SECRET_KEY", "")
if not _JWT_SECRET or _JWT_SECRET == "change-me-in-production":
    if _IS_PRODUCTION:
        raise RuntimeError(
            "ERREUR CRITIQUE : JWT_SECRET_KEY n'est pas défini ou utilise la valeur par défaut. "
            "Définissez une valeur aléatoire sécurisée dans backend.env avant de démarrer en production.\n"
            "  Exemple : openssl rand -hex 32"
        )
    else:
        logger.warning(
            "[security] JWT_SECRET_KEY utilise la valeur par défaut. "
            "Définissez une vraie valeur avant de passer en production."
        )

_WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
if not _WEBHOOK_SECRET or _WEBHOOK_SECRET == "changeme-for-production":
    if _IS_PRODUCTION:
        raise RuntimeError(
            "ERREUR CRITIQUE : WEBHOOK_SECRET n'est pas défini ou utilise la valeur par défaut. "
            "Sans un secret unique, les endpoints /webhooks/github et /webhooks/kev "
            "acceptent des requêtes non authentifiées (injection de CVE/KEV possible).\n"
            "  Exemple : openssl rand -hex 32"
        )
    else:
        logger.warning(
            "[security] WEBHOOK_SECRET non défini ou utilise la valeur par défaut — "
            "vérification HMAC désactivée/faible. "
            "Définissez une valeur unique avant de passer en production."
        )

_LICENSE_VENDOR_KEY = os.getenv("REPOD_LICENSE_VENDOR_KEY", "")
if not _LICENSE_VENDOR_KEY or _LICENSE_VENDOR_KEY == "repod-vendor-license-key-dev-only-change-in-prod-00000000000000":
    if _IS_PRODUCTION:
        raise RuntimeError(
            "ERREUR CRITIQUE : REPOD_LICENSE_VENDOR_KEY n'est pas défini ou utilise la valeur "
            "par défaut publiée dans le code source. Sans une clé vendeur secrète, n'importe "
            "qui peut forger une licence Enterprise valide (bypass du modèle de licence).\n"
            "  Exemple : openssl rand -hex 32"
        )
    else:
        logger.warning(
            "[security] REPOD_LICENSE_VENDOR_KEY utilise la valeur par défaut. "
            "Définissez une vraie valeur avant de passer en production, sous peine "
            "de permettre la forge de licences Enterprise."
        )

_SETTINGS_ENCRYPTION_KEY = os.getenv("SETTINGS_ENCRYPTION_KEY", "")
if not _SETTINGS_ENCRYPTION_KEY:
    logger.warning(
        "[security] SETTINGS_ENCRYPTION_KEY n'est pas défini — les secrets de "
        "settings.json (mots de passe SMTP, etc.) sont chiffrés avec une "
        "clé dérivée de JWT_SECRET_KEY. Toute future rotation de JWT_SECRET_KEY "
        "rendra ces secrets indéchiffrables (ré-saisie requise).\n"
        "  Exemple : openssl rand -hex 32"
    )

from limiter import limiter
from services.rate_limits import rate_limit_exceeded_handler

# ── Configuration Swagger / OpenAPI ──────────────────────────────────────────
_docs_url    = None if _IS_PRODUCTION else "/docs"
_redoc_url   = None if _IS_PRODUCTION else "/redoc"
_openapi_url = None if _IS_PRODUCTION else "/openapi.json"

_DESCRIPTION = """\
**Repod** est un gestionnaire de dépôts APT privés avec contrôle de sécurité intégré.

## Fonctionnalités principales

- 📦 **Artifacts** — upload, versionning, téléchargement, comparaison de snapshots
- 🔐 **Sécurité** — évaluation CVE (NVD + CISA KEV), politique de blocage configurable
- 🚀 **Promotions** — workflow de promotion inter-distributions avec approbation RSSI
- 🔔 **Notifications** — Email, Slack, Teams ; routage par événement
- ⚙️ **Settings** — configuration GPG, rétention, scheduler de sync

## Authentification

Tous les endpoints `/api/v1/*` requièrent un **JWT Bearer token** obtenu via `POST /api/v1/auth/token`.

Les rôles sont : `viewer` < `maintainer` < `admin`.

## Workflow de promotion RSSI

```
POST /{name}/promote  →  202 pending_review
                              ↓
GET  /admin/pending-promotions   (file d'attente)
                              ↓
POST /{name}/promote/{id}/approve   ou   reject
```
"""

_OPENAPI_TAGS: list[dict] = [
    {
        "name": "Auth",
        "description": "Authentification JWT (login, refresh, logout, MFA TOTP).",
    },
    {
        "name": "Artifacts",
        "description": (
            "Gestion des paquets .deb : liste, détail, suppression, "
            "versionning, snapshots, promotion inter-distributions et "
            "**workflow d'approbation RSSI** (pending promotions)."
        ),
    },
    {
        "name": "Upload",
        "description": "Dépôt de fichiers .deb via multipart/form-data ou flux binaire.",
    },
    {
        "name": "Security",
        "description": (
            "Politique CVE, décisions manuelles (block/allow/review), "
            "synchronisation NVD et CISA KEV."
        ),
    },
    {
        "name": "Distributions",
        "description": "Gestion des distributions APT (jammy, noble…) et de leurs composants.",
    },
    {
        "name": "Dashboard",
        "description": "Statistiques globales, tendances CVE, alertes SLA, imports récents.",
    },
    {
        "name": "Settings",
        "description": (
            "Configuration de l'application : SMTP, GPG, rétention, "
            "canaux de notification (Email/Slack/Teams) et test de canal."
        ),
    },
    {
        "name": "Downloads",
        "description": "Téléchargement de fichiers .deb et des fichiers APT (Release, Packages…).",
    },
    {
        "name": "Inventory",
        "description": "Inventaire enrichi des paquets avec métadonnées EOL et licences.",
    },
    {
        "name": "Health",
        "description": "Sondes de santé Docker/Kubernetes et métriques Prometheus.",
    },
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Gestion du cycle de vie de l'application.
    Lit les paramètres de sync depuis settings.json au démarrage.
    Démarre le scheduler et l'arrête proprement à l'extinction.
    """
    # ── Élection de leader (HA actif-passif) ─────────────────────────────────
    is_leader = leader_election.acquire_leadership()
    if is_leader:
        logger.info(f"[ha] Cette instance est leader (instance={leader_election.INSTANCE_ID})")
    else:
        logger.info(
            f"[ha] Réplique passive (instance={leader_election.INSTANCE_ID}) — "
            "scheduler désactivé, jobs leader-only refusés (503)."
        )

    # ── Branchement _MemoryHandler sur les loggers uvicorn ───────────────────
    # Uvicorn configure ses loggers avec propagate=False (via dictConfig).
    # On doit donc les brancher directement pour que les access/error logs
    # apparaissent dans le ring buffer et le flux SSE.
    try:
        mem_handler = getattr(setup_logging, "_memory_handler", None)
        if mem_handler is not None:
            import logging as _std_logging
            for _lg_name in ("uvicorn.access", "uvicorn.error", "uvicorn"):
                _lg = _std_logging.getLogger(_lg_name)
                if mem_handler not in _lg.handlers:
                    _lg.addHandler(mem_handler)
            logger.info("[logs] _MemoryHandler branché sur les loggers uvicorn")
    except Exception as _me:
        logger.warning(f"[logs] Impossible de brancher _MemoryHandler sur uvicorn : {_me}")

    # ── Initialisation admin depuis ADMIN_PASSWORD_HASH (bootstrap) ─────────
    try:
        from auth.users import init_db as _init_users_db
        _init_users_db()
        logger.info("[auth] init_db() exécuté (admin seeded si table vide).")
    except Exception as _idb_exc:
        logger.warning(f"[auth] init_db() échoué : {_idb_exc}")

    # ── Seed des rôles built-in (idempotent) ──────────────────────────────
    try:
        seed_builtin_roles()
        logger.info("[roles] Rôles built-in seedés.")
    except Exception as _roles_exc:
        logger.warning(f"[roles] seed_builtin_roles() échoué : {_roles_exc}")

    # ── Vérification de l'état du wizard de setup ────────────────────────────
    try:
        from services.setup import is_setup_done
        if not is_setup_done():
            logger.warning(
                "[setup] ⚠ Application non configurée — "
                "accédez à /api/v1/setup/status pour démarrer le wizard de première installation."
            )
        else:
            logger.info("[setup] ✔ Application déjà configurée.")
    except Exception as _setup_exc:
        logger.warning(f"[setup] Impossible de vérifier l'état de setup : {_setup_exc}")

    # ── Watermark licence au démarrage ────────────────────────────────────────
    try:
        from services.license import get_license_status
        _lic = get_license_status()
        if _lic.get("edition") == "enterprise":
            _days = _lic.get("days_remaining")
            _days_str = f", {_days}j restants" if _days is not None else ", sans expiration"
            logger.info(
                f"[license] ✔ Licence Enterprise — {_lic.get('issued_to', '?')} "
                f"(id={_lic.get('license_id', '?')}{_days_str})"
            )
        else:
            logger.info("[license] Edition Community — aucune licence Enterprise activée")
    except Exception as _lic_exc:
        logger.warning(f"[license] Impossible de lire le statut de licence : {_lic_exc}")

    # ── Init automatique des distributions (première installation) ────────────
    auto_init_distributions()

    # ── Export de la clé publique GPG vers /repos/dists/depot.gpg ─────────────
    # Assure que nginx peut toujours servir la clé à jour même après un redémarrage
    try:
        _export_gpg_pubkey()
    except Exception as _gpg_exc:
        logger.warning(f"[gpg] Export clé publique au démarrage ignoré : {_gpg_exc}")

    # ── Scheduler APScheduler — uniquement sur l'instance leader ─────────────
    # En déploiement HA actif-passif, seule l'instance leader exécute les
    # tâches planifiées (sync, SLA, rétention, scan inventaire,
    # mirroir). Les répliques passives laissent scheduler_state.scheduler à
    # None — déjà géré sans erreur par settings_router (hot-reschedule).
    if is_leader:
        settings = get_settings()
        sync_cfg = settings.get("sync", {})

        hour = int(sync_cfg.get("hour", 3))
        minute = int(sync_cfg.get("minute", 0))
        enabled = sync_cfg.get("enabled", True)
        # Timezone lue depuis settings (défaut UTC) — configurable via settings["sync"]["timezone"]
        tz = sync_cfg.get("timezone", "UTC")

        sched = BackgroundScheduler(timezone=tz)
        sched.add_job(
            run_security_sync,
            trigger=CronTrigger(hour=hour, minute=minute),
            id="security_sync_daily",
            name="Sync quotidienne sécurité (sources + Grype + KEV + EPSS)",
            replace_existing=True,
            misfire_grace_time=3600,  # tolère 1h de décalage (container redémarré)
        )
        # ── Re-matching CVE rétroactif via SBOM stocké (Grype seul, APT/RPM/APK) ──
        # Job séparé de security_sync_daily : un balayage complet du catalogue
        # peut prendre plusieurs dizaines de minutes à grande échelle et
        # bloquerait sinon le reste de la sync (KEV, EPSS, sources).
        # Programmé juste après security_sync_daily (qui vient de rafraîchir la
        # base Grype) pour un séquencement naturel, base fraîche garantie.
        # Activé par défaut — voir services/cve_rematch.py.
        cve_rematch_cfg = settings.get("cve_rematch", {})
        cve_rematch_enabled = cve_rematch_cfg.get("enabled", True)
        sched.add_job(
            run_cve_rematch_daily,
            trigger=CronTrigger(
                hour=int(cve_rematch_cfg.get("hour", 3)),
                minute=int(cve_rematch_cfg.get("minute", 45)),
            ),
            id="cve_rematch_daily",
            name="Re-matching CVE rétroactif (Grype, via SBOM stocké)",
            replace_existing=True,
            misfire_grace_time=3600,
        )
        if not cve_rematch_enabled:
            sched.pause_job("cve_rematch_daily")

        # ── Vérification quotidienne des SLA CVE (08h00) ──────────────────────────
        sched.add_job(
            run_sla_check,
            trigger=CronTrigger(hour=8, minute=0),
            id="sla_check_daily",
            name="Vérification SLA décisions CVE",
            replace_existing=True,
            misfire_grace_time=3600,
        )
        # ── Nettoyage rétention (audit logs + vieux paquets) à 02h00 ──────────────
        sched.add_job(
            run_retention,
            trigger=CronTrigger(hour=2, minute=0),
            id="retention_daily",
            name="Politique de rétention (audit + paquets)",
            replace_existing=True,
            misfire_grace_time=3600,
        )
        # ── Mirroir planifié sécurisé, désactivé par défaut ───────────────────────
        mirror_cfg = settings.get("mirror", {})
        mirror_enabled = mirror_cfg.get("enabled", False)
        sched.add_job(
            run_scheduled_mirror,
            trigger=CronTrigger(
                hour=int(mirror_cfg.get("hour", 4)),
                minute=int(mirror_cfg.get("minute", 30)),
            ),
            id="mirror_daily",
            name="Mirroir planifié sécurisé",
            replace_existing=True,
            misfire_grace_time=3600,
        )
        if not mirror_enabled:
            sched.pause_job("mirror_daily")

        def _on_job_error(event: JobExecutionEvent) -> None:
            """Notifie (email/Slack) lorsqu'une tâche planifiée échoue."""
            job = sched.get_job(event.job_id)
            job_name = job.name if job else event.job_id
            logger.error(
                "[scheduler] Tâche '%s' (%s) a échoué : %s",
                job_name, event.job_id, event.exception,
            )
            notify("SCHEDULER_JOB_FAILED", {
                "job_id": event.job_id,
                "job_name": job_name,
                "scheduled_run_time": event.scheduled_run_time.isoformat() if event.scheduled_run_time else "?",
                "error": str(event.exception),
            })

        sched.add_listener(_on_job_error, EVENT_JOB_ERROR)

        sched.start()

        # Stocker la référence pour que settings_router puisse reschedule à chaud
        scheduler_state.scheduler = sched

        if enabled:
            logger.info(
                f"[scheduler] Sync sécurité APT planifiée chaque jour à "
                f"{hour:02d}:{minute:02d} (Europe/Paris)"
            )
        else:
            sched.pause_job("security_sync_daily")
            logger.info("[scheduler] Sync sécurité désactivée dans les paramètres.")

    yield  # ← l'application tourne ici

    if scheduler_state.scheduler is not None:
        scheduler_state.scheduler.shutdown(wait=False)
        scheduler_state.scheduler = None
        logger.info("[scheduler] Scheduler arrêté proprement.")

    leader_election.release()


app = FastAPI(
    title="Repod — APT Repository Manager",
    version="2.0.0",
    description=_DESCRIPTION,
    contact={
        "name": "Repod",
        "url":  "https://github.com/repod-apt/repod",
    },
    license_info={
        "name": "AGPL-3.0",
        "url":  "https://www.gnu.org/licenses/agpl-3.0.html",
    },
    openapi_tags=_OPENAPI_TAGS,
    lifespan=lifespan,
    docs_url=_docs_url,
    redoc_url=_redoc_url,
    openapi_url=_openapi_url,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Filet de sécurité : log la stack trace complète côté serveur, ne renvoie
    qu'un message générique au client (pas de détails internes — chemins,
    requêtes SQL, types d'exception, etc.)."""
    logger.exception(
        "[unhandled] %s %s -> %s", request.method, request.url.path, exc
    )
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

allowed_origins = os.getenv("CORS_ORIGINS", "http://localhost:3003").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    # SEC-04 : liste explicite plutôt que wildcard — réduit la surface d'attaque CORS
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "X-Requested-With",
        "X-Request-ID",
        # Headers techniques slowapi / uvicorn
        "X-Forwarded-For",
        "X-Forwarded-Proto",
        "X-Forwarded-Host",
    ],
)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(SecurityHeadersMiddleware)  # SEC-4

API_V1 = "/api/v1"

# Endpoints infra sans préfixe — consulté par Docker healthcheck, Prometheus, load balancers
app.include_router(health_router)
app.include_router(metrics_router)
# Webhooks entrants (GitHub Advisory, CISA KEV) — sans /api/v1, auth par signature HMAC
app.include_router(webhook_router)

# Tous les routers métier sous /api/v1
app.include_router(auth_router,          prefix=API_V1)
app.include_router(packages_router,      prefix=API_V1)
app.include_router(upload_router,        prefix=API_V1)
app.include_router(artifacts_router,     prefix=API_V1)
app.include_router(import_router,        prefix=API_V1)
app.include_router(security_router,      prefix=API_V1)
app.include_router(dashboard_router,     prefix=API_V1)
app.include_router(distributions_router, prefix=API_V1)
app.include_router(settings_router,      prefix=API_V1)
app.include_router(downloads_router,     prefix=API_V1)
app.include_router(license_router,       prefix=API_V1)
# Setup wizard — public endpoints, pas de préfixe d'auth, monté en dernier
app.include_router(setup_router,          prefix=API_V1)
app.include_router(logs_router,           prefix=API_V1)
app.include_router(groups_router,         prefix=API_V1)
app.include_router(roles_router,          prefix=API_V1)
app.include_router(templates_router,     prefix=API_V1)
