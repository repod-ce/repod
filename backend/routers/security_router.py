# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Agrégateur des routes /security.

Le module a été découpé (refactoring qualité, juin 2026) en trois
sous-routers thématiques, tous montés sous le préfixe /security :

- routers.cve_router      → visibilité CVE (vulnerabilities, posture, report, review-queue)
- routers.decision_router → décisions RSSI (decide, decision, quarantine)
- routers.scan_router      → rescan Grype + bases ClamAV/Grype/KEV/EPSS

Ce module ne définit plus de route directement : il agrège uniquement
les sous-routers ci-dessus pour conserver une unique inclusion dans
main.py (`from routers.security_router import router as security_router`).
"""
from fastapi import APIRouter

from routers.cve_router import router as cve_router
from routers.decision_router import router as decision_router
from routers.scan_router import router as scan_router

router = APIRouter()
router.include_router(cve_router)
router.include_router(decision_router)
router.include_router(scan_router)
