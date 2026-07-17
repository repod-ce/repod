"""
Routes de gestion des licences Repod.

Endpoints :
  GET    /license           → statut de la licence (admin)
  POST   /license/activate  → activer une clé de licence (admin)
  DELETE /license           → désactiver la licence / retour Community (admin)

Tous les endpoints nécessitent le rôle admin.
La clé brute n'est jamais exposée dans les réponses API.
"""

from fastapi import APIRouter, HTTPException
from fastapi.params import Depends
from pydantic import BaseModel

from auth.dependencies import get_admin_user
from services.license import (
    activate_license,
    deactivate_license,
    get_license_summary,
    LicenseError,
)

router = APIRouter(prefix="/license", tags=["License"])


class ActivateRequest(BaseModel):
    key: str


@router.get("/")
def license_status(current_user: str = Depends(get_admin_user)):
    """
    Retourne le statut complet de la licence.
    Community Edition si aucune clé valide n'est activée.
    La clé brute n'est jamais exposée dans la réponse.
    """
    return get_license_summary()


@router.post("/activate")
def activate(
    body: ActivateRequest,
    current_user: str = Depends(get_admin_user),
):
    """
    Active une clé de licence Enterprise.
    Valide la signature HMAC, vérifie l'expiration, puis stocke la clé.

    Erreurs :
      400 — clé invalide (format, signature corrompue, expirée)
    """
    try:
        decoded = activate_license(body.key)
    except LicenseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "status":    "activated",
        "edition":   decoded.get("edition"),
        "issued_to": decoded.get("issued_to"),
        "license_id": decoded.get("license_id"),
        "expires_at": decoded.get("expires_at"),
        "days_remaining": decoded.get("days_remaining"),
        "features":  decoded.get("features", []),
        "max_packages":      decoded.get("max_packages", 0),
        "max_users":         decoded.get("max_users", 0),
        "max_distributions": decoded.get("max_distributions", 0),
    }


@router.delete("/")
def deactivate(current_user: str = Depends(get_admin_user)):
    """
    Supprime la licence et revient en Community Edition.
    """
    deactivate_license()
    return {"status": "deactivated", "edition": "community"}
