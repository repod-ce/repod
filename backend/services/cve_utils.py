"""
Module : cve_utils.py
Rôle   : Utilitaires partagés pour l'agrégation des résultats CVE (Grype).
         Centralise la logique qui était dupliquée dans upload.py.
Expose : compute_cve_summary
Dépend : —
"""

# Ordre canonique de sévérité (Critical = plus grave)
_SEV_ORDER: list[str] = ["Critical", "High", "Medium", "Low", "Negligible"]


def compute_cve_summary(
    cve_results: list[dict],
) -> tuple[dict[str, int], int, str | None]:
    """
    Calcule le résumé CVE depuis une liste de résultats Grype enrichis.

    Paramètres
    ----------
    cve_results : liste de dicts, chaque dict ayant au minimum :
        - "severity"  : str  — sévérité Grype (Critical/High/Medium/Low/Negligible/Unknown)
        - "in_kev"    : bool — True si la CVE est dans le catalogue CISA KEV (optionnel)

    Retourne
    --------
    (cve_counts, kev_count, worst_severity)
        cve_counts      : dict sévérité → nombre de CVE
        kev_count       : nombre de CVE activement exploitées (in_kev=True)
        worst_severity  : sévérité la plus haute présente, ou None si aucune CVE
    """
    cve_counts: dict[str, int] = {}
    kev_count: int = 0

    for cve in cve_results:
        sev = cve.get("severity", "Unknown")
        cve_counts[sev] = cve_counts.get(sev, 0) + 1
        if cve.get("in_kev"):
            kev_count += 1

    worst: str | None = next(
        (s for s in _SEV_ORDER if cve_counts.get(s, 0) > 0), None
    )
    return cve_counts, kev_count, worst
