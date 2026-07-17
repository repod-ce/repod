"""
routers/metrics_router.py — Endpoint GET /metrics (format Prometheus)

Exposé SANS préfixe /api/v1 (endpoint infra, comme GET /health).

Authentification : Bearer token via variable d'environnement METRICS_TOKEN.
  - Si METRICS_TOKEN est défini  : le header Authorization: Bearer <token> est requis.
  - Si METRICS_TOKEN est vide    : l'endpoint est protégé par get_auditor_user (JWT).

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

from auth.dependencies import get_auditor_user
from services.metrics import REGISTRY

logger = logging.getLogger("metrics")

router = APIRouter(tags=["Metrics"])

# Token dédié au scrape Prometheus — généré aléatoirement si non défini
# (dans ce cas, l'accès nécessite un JWT auditor via get_auditor_user)
_METRICS_TOKEN: str = os.getenv("METRICS_TOKEN", "")


def _require_metrics_auth(request: Request) -> None:
    """
    Vérifie l'authentification pour /metrics.

    Deux modes :
      1. METRICS_TOKEN défini → vérifie Authorization: Bearer <METRICS_TOKEN>
      2. METRICS_TOKEN vide   → délègue à get_auditor_user (JWT standard)
    """
    if _METRICS_TOKEN:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token requis pour /metrics",
                headers={"WWW-Authenticate": "Bearer"},
            )
        provided = auth_header[len("Bearer "):]
        if not secrets.compare_digest(provided, _METRICS_TOKEN):
            logger.warning("[metrics] Tentative d'accès avec un token invalide depuis %s",
                           request.client.host if request.client else "?")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Token Prometheus invalide",
            )


@router.get("/metrics", include_in_schema=False)
def get_metrics(
    request: Request,
    _auth: None = Depends(_require_metrics_auth),
) -> Response:
    """
    Retourne les métriques Prometheus au format text/plain.
    Scraped par Prometheus server ou compatible (VictoriaMetrics, Grafana Agent…).

    Protégé par METRICS_TOKEN (Bearer) ou JWT auditor si METRICS_TOKEN non défini.
    """
    data = generate_latest(REGISTRY)
    return Response(
        content=data,
        media_type=CONTENT_TYPE_LATEST,
        headers={"Cache-Control": "no-store"},
    )
