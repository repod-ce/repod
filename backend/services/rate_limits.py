"""
services/rate_limits.py — Rate limiting granulaire par rôle.

Limites par rôle et catégorie d'opération :
  upload  : dépôt de paquets, import, synchronisation (opérations coûteuses)
  read    : lecture, liste, téléchargement, recherche (opérations légères)
  write   : suppression, configuration, GC (opérations modifiantes non-upload)

Clé de rate limiting :
  Les requêtes authentifiées sont limitées par username (pas par IP), ce qui
  permet un comportement correct derrière un reverse-proxy partagé (plusieurs
  utilisateurs derrière la même IP).
  Les requêtes anonymes (sans JWT valide) sont limitées par IP.

Utilisation dans les routers :
  from services.rate_limits import make_role_limit
  from limiter import limiter

  @router.post("/upload")
  @limiter.limit(make_role_limit("upload"))
  async def upload_package(request: Request, ...):
      ...

Réponse 429 structurée :
  {
    "detail": {
      "error":       "rate_limit_exceeded",
      "message":     "Trop de requêtes ...",
      "limit":       "30/minute",
      "retry_after": "42"
    }
  }
"""

import logging
from fastapi import Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("rate_limits")

# ── Limites par rôle ──────────────────────────────────────────────────────────
# Format slowapi : "{count}/{period}" — period = second|minute|hour|day

ROLE_LIMITS: dict[str, dict[str, str]] = {
    # Administrateurs : limites très généreuses (usage rare, haute confiance)
    "admin":      {
        "upload": "200/minute",
        "read":   "2000/minute",
        "write":  "500/minute",
    },
    # Mainteneurs : cycle de vie complet des paquets
    "maintainer": {
        "upload": "100/minute",
        "read":   "1000/minute",
        "write":  "200/minute",
    },
    # Packagers / CI-CD : dépôt fréquent mais contrôlé
    "uploader":   {
        "upload": "30/minute",
        "read":   "300/minute",
        "write":  "30/minute",
    },
    # Auditeurs : lecture intensive des logs, pas d'upload
    "auditor":    {
        "upload": "5/minute",
        "read":   "500/minute",
        "write":  "5/minute",
    },
    # Lecteurs : consultation basique, pas d'upload
    "reader":     {
        "upload": "5/minute",
        "read":   "200/minute",
        "write":  "5/minute",
    },
    # Anonymes (pas de token valide) : protection maximale
    "anonymous":  {
        "upload": "5/minute",
        "read":   "60/minute",
        "write":  "5/minute",
    },
}

_VALID_CATEGORIES = frozenset({"upload", "read", "write"})
_DEFAULT_ROLE = "anonymous"


# ── Extraction du rôle depuis le JWT ─────────────────────────────────────────

def _extract_role(request: Request) -> str:
    """
    Extrait le rôle depuis le JWT Bearer.
    Retourne 'anonymous' si absent, invalide ou expiré.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return _DEFAULT_ROLE
    token = auth[len("Bearer "):]
    try:
        from auth.jwt import decode_token
        data = decode_token(token)
        if data:
            return data.get("role", _DEFAULT_ROLE)
    except (ValueError, KeyError):
        pass
    return _DEFAULT_ROLE


def _extract_username(request: Request) -> str | None:
    """Extrait le username depuis le JWT Bearer. Retourne None si absent/invalide."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):]
    try:
        from auth.jwt import decode_token
        data = decode_token(token)
        if data:
            return data.get("username")
    except (ValueError, KeyError):
        pass
    return None


# ── Clé de rate limiting per-utilisateur ─────────────────────────────────────

def get_user_key(request: Request) -> str:
    """
    Clé de rate limiting :
      - Requête authentifiée → "user:{username}:{role}" (per-user)
      - Requête anonyme      → adresse IP (per-IP fallback)

    Ce key_func doit remplacer get_remote_address dans Limiter() pour activer
    le rate limiting par utilisateur plutôt que par IP. Cela évite les faux
    positifs pour des utilisateurs derrière le même proxy (NAT, load-balancer).
    """
    username = _extract_username(request)
    if username:
        role = _extract_role(request)
        return f"user:{username}:{role}"
    # Fallback IP pour les anonymes
    if request.client:
        return f"ip:{request.client.host}"
    return "ip:unknown"


# ── Factory de limites dynamiques ────────────────────────────────────────────

def make_role_limit(category: str):
    """
    Fabrique un callable (Request) → str utilisable dans @limiter.limit().

    slowapi accepte un callable comme argument de limite. Le rôle est extrait
    du JWT à chaque requête ; si le token est absent ou invalide, le rôle
    'anonymous' (limite la plus stricte) est appliqué.

    Paramètre
    ---------
    category : "upload" | "read" | "write"

    Retourne
    --------
    Callable[[Request], str] — ex. "30/minute" pour un uploader

    Exemple
    -------
    @router.post("/packages/import")
    @limiter.limit(make_role_limit("upload"))
    async def import_package(request: Request, ...):
        ...
    """
    if category not in _VALID_CATEGORIES:
        raise ValueError(
            f"Catégorie inconnue : {category!r}. "
            f"Valeurs acceptées : {sorted(_VALID_CATEGORIES)}"
        )

    def _limit_fn(key: str) -> str:
        """
        slowapi appelle ce callable avec `key = key_function(request)` car le
        paramètre est nommé 'key' (voir LimitGroup.__iter__ dans wrappers.py).
        La clé a le format "user:{username}:{role}" ou "ip:{host}".
        On en extrait le rôle pour retourner la limite appropriée.
        """
        if key.startswith("user:"):
            # format : "user:<username>:<role>"
            parts = key.split(":", 2)
            role = parts[2] if len(parts) >= 3 else _DEFAULT_ROLE
        else:
            role = _DEFAULT_ROLE
        return ROLE_LIMITS.get(role, ROLE_LIMITS[_DEFAULT_ROLE])[category]

    # Nommer la fonction pour faciliter le débogage / les logs slowapi
    _limit_fn.__name__ = f"role_limit_{category}"
    _limit_fn.__qualname__ = f"make_role_limit.<locals>.role_limit_{category}"
    return _limit_fn


# ── API publique ──────────────────────────────────────────────────────────────

def get_limits_for_role(role: str) -> dict:
    """
    Retourne les limites complètes pour un rôle.
    Utilisé par GET /api/v1/rate-limits/{role} ou l'UI admin.
    """
    return dict(ROLE_LIMITS.get(role, ROLE_LIMITS[_DEFAULT_ROLE]))


def get_all_role_limits() -> dict:
    """Retourne toutes les limites (tous rôles) pour affichage dans l'UI."""
    return {role: dict(limits) for role, limits in ROLE_LIMITS.items()}


# ── Gestionnaire structuré 429 ────────────────────────────────────────────────

def rate_limit_exceeded_handler(request: Request, exc) -> JSONResponse:
    """
    Remplace le handler 429 par défaut de slowapi (texte brut) par une réponse
    JSON structurée avec le header Retry-After.

    À enregistrer dans main.py :
      from slowapi.errors import RateLimitExceeded
      from services.rate_limits import rate_limit_exceeded_handler
      app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)
    """
    retry_after = getattr(exc, "retry_after", None)
    limit_str   = str(getattr(exc, "limit", ""))

    headers = {}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)

    client_ip = request.client.host if request.client else "unknown"
    logger.warning(
        "[rate_limit] 429 %s %s — ip=%s limit=%s retry_after=%s",
        request.method, request.url.path, client_ip, limit_str, retry_after,
    )

    return JSONResponse(
        status_code=429,
        content={
            "detail": {
                "error":       "rate_limit_exceeded",
                "message":     "Trop de requêtes. Veuillez réessayer dans quelques instants.",
                "limit":       limit_str,
                "retry_after": str(retry_after) if retry_after is not None else None,
            }
        },
        headers=headers,
    )
