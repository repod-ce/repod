from fastapi import APIRouter, HTTPException, Depends, Query
from services.download import download_package
from services.search import list_packages
from services.pagination import paginate
from auth.dependencies import get_current_user
from pydantic import BaseModel


router = APIRouter(prefix="/packages", tags=["Packages"])


class PackageRequest(BaseModel):
    name: str


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


@router.post("/install/")
def install_package(request: PackageRequest, current_user: str = Depends(get_current_user)):
    """Installe un paquet APT en exécutant download-package-dep.sh."""
    try:
        result = download_package(request.name)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur : {str(e)}")
