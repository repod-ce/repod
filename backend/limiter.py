"""
limiter.py — Instance partagée du rate limiter slowapi.

Clé de rate limiting :
  - Requêtes authentifiées (JWT valide) → "user:{username}:{role}" (per-user)
  - Requêtes anonymes                   → adresse IP (per-IP fallback)

Headers X-RateLimit-* :
  headers_enabled=True active l'injection automatique des headers :
    X-RateLimit-Limit     : limite configurée pour l'endpoint
    X-RateLimit-Remaining : requêtes restantes dans la fenêtre courante
    X-RateLimit-Reset     : timestamp Unix de réinitialisation de la fenêtre

Utilisation :
  from limiter import limiter, auth_limit
  from services.rate_limits import make_role_limit

  @router.post("/upload")
  @limiter.limit(make_role_limit("upload"))   # limite dynamique par rôle
  async def upload(request: Request, ...):
      ...

  @router.post("/auth/token")
  @limiter.limit(auth_limit)                  # limite fixe pour les logins
  async def login(request: Request, ...):
      ...
"""

import os
from slowapi import Limiter

from services.rate_limits import get_user_key

_auth_rate = os.getenv("AUTH_RATELIMIT_PER_MINUTE", "10")
auth_limit = f"{_auth_rate}/minute"

limiter = Limiter(
    key_func=get_user_key,      # per-user (fallback IP pour anonymes)
    headers_enabled=True,       # injecte X-RateLimit-Limit/Remaining/Reset
    default_limits=[],          # pas de limite globale — défini par endpoint
)
