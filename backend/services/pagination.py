"""
Utilitaire de pagination (P2-1).

Format de sortie standard :
    {
        "items":    [...],   # tranche de la liste pour la page demandée
        "total":    N,       # nombre total d'éléments (avant pagination)
        "page":     1,       # page courante (1-indexé)
        "per_page": 50,      # éléments par page
        "pages":    P,       # nombre total de pages (ceil(total/per_page))
    }

Utilisation :
    from services.pagination import paginate
    return paginate(my_list, page=page, per_page=per_page)
"""
import math
from typing import Any


def paginate(
    items: list[Any],
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """
    Découpe *items* selon la page et le nombre d'éléments par page.

    Paramètres
    ----------
    items    : liste complète à paginer
    page     : numéro de page demandé (1-indexé, défaut : 1)
    per_page : taille de page (défaut : 50)

    Retour
    ------
    dict avec les clés : items, total, page, per_page, pages
    """
    total = len(items)
    pages = math.ceil(total / per_page) if total > 0 else 0

    start = (page - 1) * per_page
    end = start + per_page
    slice_ = items[start:end]

    return {
        "items":    slice_,
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    pages,
    }
