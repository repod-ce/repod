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


def _parse_cve_message(msg: str) -> dict:
    """
    Parse un message CVE compact en comptages par sévérité.
    Ex: "Grype — 3 High | 18 Medium | 34 Low | 1 Negligible"
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "negligible": 0, "unknown": 0}
    if not msg:
        return counts
    lower = msg.lower()
    if "non disponible" in lower or "ignoré" in lower or "timeout" in lower:
        return counts
    # Parse "N Severity" pairs wherever they appear
    for m in re.finditer(r"(\d+)\s+(critical|high|medium|low|negligible|unknown)", msg, re.IGNORECASE):
        sev = m.group(2).lower()
        counts[sev] = int(m.group(1))
    return counts
