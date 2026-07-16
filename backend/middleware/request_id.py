"""
Middleware de corrélation des requêtes (P2-2).

RequestIdMiddleware :
  • Lit X-Request-ID depuis l'en-tête entrant (traçabilité end-to-end)
    ou génère un UUID v4 si absent.
  • Positionne request_id_var (ContextVar) pour que tous les logs
    émis pendant le traitement de la requête incluent l'ID.
  • Ajoute X-Request-ID dans les en-têtes de la réponse.
  • Réinitialise le ContextVar après la réponse (propreté entre requêtes).
"""
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from services.logging_config import request_id_var


class RequestIdMiddleware(BaseHTTPMiddleware):
    """
    Middleware Starlette/FastAPI : corrélation X-Request-ID ↔ logs JSON.

    Utilisation dans main.py :
        from middleware.request_id import RequestIdMiddleware
        app.add_middleware(RequestIdMiddleware)
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Réutiliser l'ID fourni par le client (ALB, Nginx, tracer amont)
        # ou en générer un nouveau.
        req_id = (
            request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )

        token = request_id_var.set(req_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = req_id
            return response
        finally:
            # Réinitialiser proprement même en cas d'exception dans le handler
            request_id_var.reset(token)
