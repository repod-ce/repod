"""
middleware/metrics_middleware.py — P3-B : Instrumentation HTTP Prometheus

MetricsMiddleware enregistre pour chaque requête :
  • repod_http_requests_total     {method, path, status_code}  → Counter
  • repod_http_request_duration_seconds {method, path}         → Histogram

Note sur la cardinalité :
  Le label 'path' utilise le chemin brut (request.url.path), ce qui peut
  créer une cardinalité élevée si les segments de route contiennent des IDs
  arbitraires (ex. /api/v1/sbom/nginx/1.24.0).
  En production avec un volume important, envisager une normalisation des
  chemins via le template de route Starlette (request.scope["route"].path).
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from services.metrics import http_request_duration_seconds, http_requests_total


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware Starlette qui alimente les métriques Prometheus HTTP."""

    async def dispatch(self, request: Request, call_next) -> Response:
        method   = request.method
        path     = request.url.path
        start    = time.perf_counter()

        response = await call_next(request)

        duration    = time.perf_counter() - start
        status_code = str(response.status_code)

        http_requests_total.labels(
            method=method,
            path=path,
            status_code=status_code,
        ).inc()

        http_request_duration_seconds.labels(
            method=method,
            path=path,
        ).observe(duration)

        return response
