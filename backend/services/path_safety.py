# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
services/path_safety.py
------------------------
Garde-fou anti path-traversal pour la construction de chemins de fichiers
à partir de données potentiellement influencées par l'utilisateur
(nom de paquet, version, arch, nom de fichier issu d'un manifest).

Plusieurs endpoints construisent des chemins du type :

    pool_pkg = POOL_DIR / filename

où `filename` provient soit directement du manifest (généralement fiable),
soit d'un fallback construit à partir de `name`/`version`/`arch` (paramètres
de route ou de body — potentiellement `../../etc/passwd`).

Utilisation :

    from services.path_safety import safe_path_join, safe_path_join_http

    # Dans un service (pas de contexte HTTP) :
    try:
        pkg_path = safe_path_join(POOL_DIR, filename)
    except PathTraversalError:
        logger.warning(...)
        return None

    # Dans un router FastAPI :
    pkg_path = safe_path_join_http(POOL_DIR, filename)  # lève HTTPException(400)
"""

from pathlib import Path

from fastapi import HTTPException


class PathTraversalError(ValueError):
    """Levée quand le chemin construit sortirait du répertoire de base."""


def safe_path_join(base_dir: Path, filename: str) -> Path:
    """
    Construit `base_dir / filename` et vérifie que le résultat reste
    strictement à l'intérieur de `base_dir` (résolution des `..`, chemins
    absolus et liens symboliques incluse).

    Lève `PathTraversalError` si :
      - `filename` est vide / None
      - le chemin résolu n'est pas un descendant de `base_dir`
    """
    if not filename:
        raise PathTraversalError("Nom de fichier vide")

    base_resolved = base_dir.resolve()
    candidate = (base_dir / filename).resolve()

    if not candidate.is_relative_to(base_resolved):
        raise PathTraversalError(f"Chemin hors de {base_dir} : {filename!r}")

    return candidate


def safe_path_join_http(base_dir: Path, filename: str, status_code: int = 400) -> Path:
    """
    Variante pour les routers FastAPI : lève `HTTPException(status_code)`
    au lieu de `PathTraversalError`.
    """
    try:
        return safe_path_join(base_dir, filename)
    except PathTraversalError as exc:
        raise HTTPException(status_code=status_code, detail="Nom de fichier invalide") from exc
