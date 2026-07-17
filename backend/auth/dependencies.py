"""
Dépendances FastAPI pour l'authentification et le contrôle d'accès par rôle.

Hiérarchie des rôles (du plus au moins permissif) :
  admin > maintainer > uploader > reader
                    > auditor   (accès transverse aux logs)

Matrice des permissions :
  get_current_user    → tout utilisateur authentifié (tous rôles)
  get_uploader_user   → admin, maintainer, uploader
  get_maintainer_user → admin, maintainer
  get_auditor_user    → admin, maintainer, auditor
  get_admin_user      → admin uniquement
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from .jwt import decode_token
from .users import get_user

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

_401 = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Token invalide ou expiré",
    headers={"WWW-Authenticate": "Bearer"},
)


def _parse_token(token: str) -> dict:
    data = decode_token(token)
    if not data:
        raise _401
    # Vérifie que le compte existe et est toujours actif
    user = get_user(data["username"])
    if not user:
        raise _401
    return data


def _require_role(data: dict, allowed: tuple, detail: str) -> str:
    if data["role"] not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)
    return data["username"]


# ── Dépendances publiques ─────────────────────────────────────────────────────

async def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """Tout utilisateur authentifié — retourne le username."""
    return _parse_token(token)["username"]


async def get_current_user_full(token: str = Depends(oauth2_scheme)) -> dict:
    """Tout utilisateur authentifié — retourne {username, role, full_name}."""
    return _parse_token(token)


async def get_uploader_user(token: str = Depends(oauth2_scheme)) -> str:
    """Admin, Mainteneur ou Packager — peut déposer et importer des paquets."""
    return _require_role(
        _parse_token(token),
        ("admin", "maintainer", "uploader"),
        "Rôle packager, mainteneur ou administrateur requis pour cette action.",
    )


async def get_maintainer_user(token: str = Depends(oauth2_scheme)) -> str:
    """Admin ou Mainteneur — peut supprimer, promouvoir et synchroniser."""
    return _require_role(
        _parse_token(token),
        ("admin", "maintainer"),
        "Rôle mainteneur ou administrateur requis pour cette action.",
    )


async def get_auditor_user(token: str = Depends(oauth2_scheme)) -> str:
    """Admin, Mainteneur ou Auditeur — peut lire les logs d'audit."""
    return _require_role(
        _parse_token(token),
        ("admin", "maintainer", "auditor"),
        "Rôle auditeur, mainteneur ou administrateur requis pour accéder aux logs d'audit.",
    )


async def get_admin_user(token: str = Depends(oauth2_scheme)) -> str:
    """Administrateur uniquement — gestion des utilisateurs et paramètres système."""
    return _require_role(
        _parse_token(token),
        ("admin",),
        "Accès réservé aux administrateurs.",
    )


def get_user_role(username: str) -> str:
    """Retourne le rôle d'un utilisateur (non-async, pour appels internes)."""
    user = get_user(username)
    return user.get("role", "reader") if user else "reader"


def require_permission(perm: str):
    """Factory de dépendance basée sur une permission granulaire."""
    async def _dep(token: str = Depends(oauth2_scheme)) -> str:
        from .roles import get_user_permissions
        data = _parse_token(token)
        perms = get_user_permissions(data["username"])
        if perm not in perms:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission requise : {perm}",
            )
        return data["username"]
    return _dep
