"""
GET /downloads/stats?days=30  → statistiques de téléchargements (admin)
"""
from fastapi import APIRouter, Depends, Query
from auth.dependencies import get_current_user
from services.download_stats import get_download_stats

router = APIRouter(prefix="/downloads", tags=["Downloads"])


@router.get("/stats")
def download_stats(
    days: int = Query(30, ge=1, le=365),
    _user: str = Depends(get_current_user),
):
    """Retourne les statistiques de téléchargements des N derniers jours."""
    return get_download_stats(days=days)
