"""
middleware/security_headers.py — Injection des headers HTTP de sécurité.

Headers appliqués sur toutes les réponses :

  X-Content-Type-Options: nosniff
      Empêche le MIME-sniffing dans les navigateurs.

  X-Frame-Options: DENY
      Bloque l'intégration de l'API dans une iframe (clickjacking).

  X-XSS-Protection: 1; mode=block
      Filtre XSS intégré des anciens navigateurs (rétrocompatibilité).

  Referrer-Policy: strict-origin-when-cross-origin
      Limite les informations de provenance transmises aux tiers.

  Permissions-Policy: ...
      Désactive les API navigateur non utilisées par l'API.

  Cross-Origin-Opener-Policy: same-origin
      Isole le contexte de navigation (atténuation Spectre).

  Content-Security-Policy (CSP)
      Défense en profondeur pour les accès directs au backend (sans passer
      par nginx, qui injecte déjà sa propre CSP pour le SPA React — voir
      frontend/nginx.conf). En production, /docs et /redoc sont désactivés
      (cf. main.py `_docs_url`), donc une politique stricte `default-src 'none'`
      est appliquée. En dev, /docs (Swagger UI) charge des assets depuis
      cdn.jsdelivr.net et exécute des scripts inline → politique assouplie.

Headers intentionnellement omis :
  - Strict-Transport-Security (HSTS) : géré par Nginx (TLS termination)
"""

import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injecte les headers de sécurité HTTP sur chaque réponse."""

    # En dev, on applique quand même les headers pour ne pas masquer
    # de régressions. On peut surcharger via la variable d'env
    # SECURITY_HEADERS_DISABLED=1 pour les tests d'intégration qui
    # vérifieraient l'absence de headers.
    _DISABLED = os.getenv("SECURITY_HEADERS_DISABLED", "").lower() in ("1", "true", "yes")

    # En production, /docs /redoc /openapi.json sont désactivés (main.py)
    # → CSP stricte. En dev, Swagger UI a besoin de cdn.jsdelivr.net + inline scripts.
    _IS_PRODUCTION = os.getenv("ENV", "development") == "production"

    if _IS_PRODUCTION:
        _CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    else:
        _CSP = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'"
        )

    _HEADERS = {
        "X-Content-Type-Options":   "nosniff",
        "X-Frame-Options":          "DENY",
        "X-XSS-Protection":         "1; mode=block",
        "Referrer-Policy":          "strict-origin-when-cross-origin",
        "Permissions-Policy":       "geolocation=(), microphone=(), camera=(), payment=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Content-Security-Policy":  _CSP,
    }

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        if not self._DISABLED:
            for header, value in self._HEADERS.items():
                response.headers.setdefault(header, value)
        return response
