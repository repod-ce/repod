# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
routers/security_common.py
---------------------------
Constantes et helpers partagés entre les sous-routers de sécurité
(cve_router, decision_router, scan_router) — voir security_router.py
pour l'agrégation.
"""
import os
import re
from pathlib import Path

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))
STAGING_QUARANTINE = Path(os.getenv("STAGING_QUARANTINE", "/repos/staging/quarantine"))
MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))


# Sous-chaînes (en minuscules) des messages d'étape "cve" que
# validator_apt.py:validate_cve_grype() écrit quand le scan Grype n'a PAS
# pu produire de résultat exploitable (binaire absent, timeout, sortie
# JSON illisible, code retour inattendu) — par opposition à un scan qui a
# réellement tourné et n'a simplement rien trouvé ("Grype — aucune CVE
# connue", qui ne contient aucun de ces marqueurs).
_INCONCLUSIVE_CVE_MARKERS = ("non disponible", "ignoré", "timeout", "illisible", "incomplet")


def _cve_message_is_inconclusive(msg: str) -> bool:
    if not msg:
        return True
    lower = msg.lower()
    return any(marker in lower for marker in _INCONCLUSIVE_CVE_MARKERS)


def _parse_cve_message(msg: str) -> dict:
    """
    Parse un message CVE compact en comptages par sévérité.
    Ex: "Grype — 3 High | 18 Medium | 34 Low | 1 Negligible"
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
    if _cve_message_is_inconclusive(msg):
        return counts
    # Parse "N Severity" pairs wherever they appear
    for m in re.finditer(r"(\d+)\s+(critical|high|medium|low|negligible|unknown)", msg, re.IGNORECASE):
        sev = m.group(2).lower()
        counts[sev] = int(m.group(1))
    return counts


def has_conclusive_cve_scan(manifest: dict) -> bool:
    """
    True si ce manifest porte la preuve qu'un scan Grype a réellement
    tourné et produit un résultat exploitable — y compris "aucune CVE
    trouvée" (cve_results vide n'est alors pas une absence de donnée,
    c'est le résultat). False si le scan n'a jamais eu lieu, a expiré, ou
    n'a pas pu être interprété (binaire absent, JSON illisible, code
    retour inattendu) — dans ce cas seulement, l'UI doit inviter à
    ré-importer le paquet pour obtenir un vrai résultat.

    À ne pas confondre avec `len(cve_results) > 0` : un paquet
    effectivement scanné et sain a `cve_results == []` tout en étant
    parfaitement conclusif.
    """
    if manifest.get("cve_results"):
        return True
    for step in manifest.get("validation_steps", []):
        if step.get("name") == "cve":
            return not _cve_message_is_inconclusive(step.get("message", ""))
    return False
