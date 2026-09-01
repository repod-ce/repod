from fastapi import APIRouter, HTTPException, Depends, Query
from services.search import list_packages
from services.pagination import paginate
from auth.dependencies import get_current_user


router = APIRouter(prefix="/packages", tags=["Packages"])


@router.get("/")
def get_packages(
    page: int = Query(1, ge=1, description="Numéro de page (1-indexé)"),
    per_page: int = Query(50, ge=1, le=200, description="Éléments par page"),
    current_user: str = Depends(get_current_user),
):
    """Retourne la liste paginée des paquets disponibles."""
    try:
        raw = list_packages()
        # list_packages() peut retourner {"packages": [...]} ou une liste directe
        if isinstance(raw, dict):
            all_packages = raw.get("packages", [])
        else:
            all_packages = raw
        return paginate(all_packages, page=page, per_page=per_page)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur : {str(e)}")


# POST /install/ a été supprimé : doublon hérité de POST /artifacts/{name}/install
# (routers/artifacts.py), qui atteint le même sink SSH de services/download.py
# mais exige get_uploader_user, refuse en 409 quand des dépendances manquent et
# écrit une entrée d'audit. Ce doublon n'avait aucun des trois et n'était gardé
# que par get_current_user : le rôle reader, distribué aux machines clientes APT,
# pouvait donc déclencher une exécution SSH sur la machine gérée et faire entrer
# un paquet amont et sa fermeture de dépendances dans le pool servi, sans trace.
