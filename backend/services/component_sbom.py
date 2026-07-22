# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Stockage du SBOM CycloneDX capturé lors du scan Grype (voir
services/validator_apt.py:_run_grype_and_capture_sbom()) — le graphe de
composants internes d'un artefact, PAS le catalogue de paquets publiés
(un export différent, à ne pas confondre).

Ce SBOM est ce qui permet à services/cve_rematch.py de refaire un matching
CVE (`grype sbom:<fichier>`) sans jamais rouvrir le fichier `.deb`/`.rpm`/
`.apk` d'origine dans pool/ — voir le docstring de cve_rematch.py pour le
raisonnement complet.

Chemin déterministe, calculé depuis (name, version, arch) — même convention
que MANIFEST_DIR (services/manifest.py), aucune colonne PostgreSQL dédiée :
le SBOM est un artefact secondaire, pas une donnée interrogée en base.
"""
import json
import logging
import os
from pathlib import Path

from services.path_safety import PathTraversalError, safe_path_join

logger = logging.getLogger("component_sbom")

SBOM_DIR = Path(os.getenv("SBOM_DIR", "/repos/sboms"))
SBOM_DIR.mkdir(parents=True, exist_ok=True)


def sbom_path_for(name: str, version: str, arch: str) -> Path:
    """Même sanitisation que services/manifest.py:save_manifest() (le nom
    n'a jamais besoin d'être sanitisé côté CE, pas de formats Maven/PyPI/
    npm/OCI dont les noms contiennent ':'/'/')."""
    version_safe = version.replace(":", "_").replace("/", "_")
    filename = f"{name}_{version_safe}_{arch}.cdx.json"
    return safe_path_join(SBOM_DIR, filename)


def save_component_sbom(name: str, version: str, arch: str, sbom: dict | None) -> None:
    """Écrit le SBOM CycloneDX sur disque. No-op silencieux si sbom est
    None/vide/pas un dict (capture échouée/ignorée à la source — voir
    _run_grype_and_capture_sbom(), best-effort par conception ; le check de
    type couvre aussi un objet inattendu passé par erreur par l'appelant)."""
    if not isinstance(sbom, dict) or not sbom:
        return
    try:
        path = sbom_path_for(name, version, arch)
        path.write_text(json.dumps(sbom, ensure_ascii=False), encoding="utf-8")
    except (OSError, PathTraversalError) as exc:
        logger.warning("[component_sbom] Écriture SBOM échouée pour %s %s %s : %s", name, version, arch, exc)


def load_component_sbom(name: str, version: str, arch: str) -> dict | None:
    """Retourne None si le SBOM n'existe pas ou est illisible — jamais
    d'exception, cve_rematch.py doit pouvoir passer au paquet suivant."""
    try:
        path = sbom_path_for(name, version, arch)
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, PathTraversalError):
        return None
