"""
middleware/metrics_middleware.py — P3-B : Instrumentation HTTP Prometheus

MetricsMiddleware enregistre pour chaque requête :
  • repod_http_requests_total     {method, path, status_code}  → Counter
  • repod_http_request_duration_seconds {method, path}         → Histogram

Le label 'path' porte le gabarit de la route (« /api/v1/auth/users/{username} »),
jamais le chemin concret. Le chemin brut plaçait dans le registre les noms
d'utilisateurs, les couples paquet/version et les identifiants de groupe, exposés
tels quels par GET /metrics (endpoint qui reste accessible sans authentification
tant que METRICS_TOKEN n'est pas défini). Il ouvrait de surcroît une cardinalité
non bornée, un client pouvant créer une série par chemin inventé.
"""

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from services.metrics import http_request_duration_seconds, http_requests_total

# Repli quand aucune route n'a traité la requête : 404, redirection de slash,
# application ASGI montée. Constante fixe, et surtout pas le chemin demandé, qui
# est choisi par le client : les 404 suffiraient sinon à réintroduire la fuite et
# la cardinalité non bornée. Aucune collision possible avec un gabarit réel, tous
# commencent par « / ».
_PATH_INCONNU = "__unmatched__"


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware Starlette qui alimente les métriques Prometheus HTTP."""

    async def dispatch(self, request: Request, call_next) -> Response:
        method = request.method
        start  = time.perf_counter()

        response = await call_next(request)

        duration    = time.perf_counter() - start
        status_code = str(response.status_code)

        # Lecture obligatoirement après call_next : scope["route"] est posé
        # pendant le dispatch par fastapi.routing.APIRoute.matches(), il est
        # absent avant, et il le reste quand aucune route ne correspond.
        # path_format est le gabarit normalisé (« /a/{p} » même pour
        # « /a/{p:path} ») ; path sert de repli, les deux étant absents d'un
        # objet route qui n'en exposerait pas (starlette.routing.Host).
        route   = request.scope.get("route")
        gabarit = getattr(route, "path_format", "") or getattr(route, "path", "")
        path    = gabarit or _PATH_INCONNU

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
