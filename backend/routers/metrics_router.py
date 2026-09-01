"""
routers/metrics_router.py — Endpoint GET /metrics (format Prometheus)

Exposé SANS préfixe /api/v1 (endpoint infra, comme GET /health).

Authentification, par ordre de créance acceptée :
  - METRICS_TOKEN défini : « Authorization: Bearer <METRICS_TOKEN> », ou à défaut
    un JWT de rôle admin, maintainer ou auditor. Toute autre créance est refusée.
  - METRICS_TOKEN vide (défaut livré) : accès sans authentification.

Aucun label de métrique ne porte de donnée nominative : MetricsMiddleware
n'étiquette que des gabarits de route (voir middleware/metrics_middleware.py).

Configuration Prometheus :
  scrape_configs:
    - job_name: repod
      bearer_token: <valeur de METRICS_TOKEN>
      static_configs:
        - targets: ['repod-backend:8000']

Content-Type : text/plain; version=0.0.4; charset=utf-8 (CONTENT_TYPE_LATEST)
"""

import logging
import os
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from auth.dependencies import get_user_role
from auth.jwt import decode_token
from services.metrics import REGISTRY

logger = logging.getLogger("metrics")

router = APIRouter(tags=["Metrics"])

# Jeton dédié au scrape Prometheus, lu une fois à l'import du module.
# Vide par défaut, auquel cas /metrics reste accessible sans authentification.
_METRICS_TOKEN: str = os.getenv("METRICS_TOKEN", "")


def _est_auditeur(token: str) -> bool:
    """
    Vrai si `token` est un JWT valide dont le porteur détient un rôle d'audit.

    decode_token() écarte déjà les signatures invalides, les tokens expirés, les
    tokens révoqués (table revoked_tokens) et les tokens MFA intermédiaires
    (scope=mfa_required). Le rôle est ensuite relu dans la table users par
    get_user_role(), jamais pris dans le claim « role » du JWT, qui n'est qu'un
    instantané figé à l'émission. get_user_role() retombe sur « reader » si le
    compte est absent ou désactivé : le refus est le défaut.
    """
    data = decode_token(token)
    return bool(data) and get_user_role(data["username"]) in ("admin", "maintainer", "auditor")


def _require_metrics_auth(request: Request) -> None:
    """
    Vérifie l'authentification pour GET /metrics.

    METRICS_TOKEN défini : « Authorization: Bearer <METRICS_TOKEN> » est accepté,
      et à défaut un JWT de rôle admin, maintainer ou auditor, ce qui évite de
      distribuer le jeton de scrape à un humain. Toute autre créance est refusée.
    METRICS_TOKEN vide (défaut livré) : aucune vérification, l'endpoint reste
      accessible sans authentification. C'est la raison pour laquelle
      MetricsMiddleware n'étiquette que des gabarits de route et jamais de chemin
      concret : aucune donnée nominative ne doit exister dans le registre.

    Volontairement synchrone : decode_token() et get_user_role() interrogent la
    base en SQLAlchemy synchrone, FastAPI exécute donc cette dépendance dans le
    threadpool au lieu de bloquer la boucle d'événements à chaque scrape.
    """
    if not _METRICS_TOKEN:
        return

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token requis pour /metrics",
            headers={"WWW-Authenticate": "Bearer"},
        )

    presentee = auth_header[len("Bearer "):]
    # Jeton de scrape d'abord : comparaison à temps constant et sans accès base,
    # c'est le chemin emprunté par chaque scrape Prometheus. Le JWT, plus coûteux
    # (décodage, revoked_tokens, users), n'est évalué qu'ensuite.
    if secrets.compare_digest(presentee, _METRICS_TOKEN) or _est_auditeur(presentee):
        return

    # Un seul point de refus, donc un seul statut : rien ne distingue un JWT
    # authentique de rôle insuffisant d'un token quelconque, /metrics ne peut pas
    # servir d'oracle pour tester un token volé.
    logger.warning("[metrics] Tentative d'accès avec une créance invalide depuis %s",
                   request.client.host if request.client else "?")
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Créance invalide pour /metrics",
    )


@router.get("/metrics", include_in_schema=False)
def get_metrics(
    request: Request,
    _auth: None = Depends(_require_metrics_auth),
) -> Response:
    """
    Retourne les métriques Prometheus au format text/plain.
    Scraped par Prometheus server ou compatible (VictoriaMetrics, Grafana Agent…).

    Protégé par METRICS_TOKEN (Bearer) ou par un JWT de rôle auditeur lorsque
    METRICS_TOKEN est défini ; sans authentification lorsqu'il ne l'est pas.
    """
    data = generate_latest(REGISTRY)
    return Response(
        content=data,
        media_type=CONTENT_TYPE_LATEST,
        headers={"Cache-Control": "no-store"},
    )
