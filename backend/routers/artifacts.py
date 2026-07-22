"""
Routes pour la gestion des artefacts :
- Liste enrichie depuis l'index
- Détail d'un paquet (toutes versions)
- Résolution de dépendances
- Suppression
- Historique d'audit
- Synchronisation de l'index
- Snapshots historiques (versioning)
- Promotion entre distributions
"""
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi import Path as FPath  # évite le conflit avec pathlib.Path
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from auth.dependencies import (
    get_admin_user,
    get_auditor_user,
    get_current_user,
    get_maintainer_user,
    get_uploader_user,
)
from limiter import limiter
from services.audit import get_package_history, get_recent_logs
from services.audit import log as audit_log
from services.audit_export import (
    build_audit_archive,
    check_audit_integrity,
    export_audit_logs,
    export_user_data,
    get_export_filename,
)
from services.distributions import remove_package as _repo_remove_package
from services.format_router import ACCEPTED_EXTENSIONS as _ACCEPTED_EXTS
from services.format_router import find_pool_file as _find_pool_file
from services.format_router import is_apt as _is_apt
from services.indexer import (
    get_index,
    get_package_info,
    list_packages_from_index,
    remove_from_index,
    sync_index_from_pool,
)
from services.manifest import (
    delete_manifest_from_db,
    list_manifests,
    load_manifest,
    reenrich_manifest_cve,
)
from services.pagination import paginate
from services.path_safety import safe_path_join_http
from services.pending_promotions import get_pending, list_pending
from services.promotion import (
    PromotionError,
    approve_pending,
    evaluate_cve_policy,
    get_promotable_targets,
    promote,
    reject_pending,
)
from services.snapshots import (
    compare_versions,
    enforce_version_limit,
    get_snapshot,
    get_version_history,
    run_version_gc,
)
from services.validator import (
    ValidationResult,
    _resolve_deps_recursive,
    validate_dependencies,
)

router = APIRouter(prefix="/artifacts", tags=["Artifacts"])
logger = logging.getLogger("artifacts")

POOL_DIR = Path(os.getenv("POOL_DIR", "/repos/pool"))
MANIFEST_DIR = Path(os.getenv("MANIFEST_DIR", "/repos/manifests"))


# ─── Liste & détail ──────────────────────────────────────────────────────────

@router.get("/")
def list_artifacts(
    page: int = Query(1, ge=1, description="Numéro de page (1-indexé)"),
    per_page: int = Query(50, ge=1, le=200, description="Éléments par page"),
    search: str = Query(None, description="Filtre texte sur nom / description"),
    distribution: str = Query(None, description="Filtrer par distribution (jammy, noble…)"),
    current_user: str = Depends(get_current_user),
):
    """Liste paginée des artefacts avec métadonnées enrichies depuis l'index."""
    try:
        pkgs = list_packages_from_index()
        if search:
            s = search.lower()
            pkgs = [p for p in pkgs if
                    s in (p.get("name") or "").lower() or
                    s in (p.get("description") or "").lower()]
        if distribution and distribution != "all":
            from services.format_router import DEFAULT_DISTRIBUTION as _DEF_DIST
            pkgs = [
                p for p in pkgs
                if (p.get("distribution") or _DEF_DIST) == distribution
                or distribution in (p.get("promoted_distributions") or [])
            ]
        return paginate(pkgs, page=page, per_page=per_page)
    except Exception as e:
        logger.exception("[artifacts] Échec de listing : %s", e)
        raise HTTPException(status_code=500, detail="Failed to list artifacts — see server logs for details")


@router.get("/{name}")
def get_artifact(name: str, current_user: str = Depends(get_current_user)):
    """Retourne le détail complet d'un paquet (toutes versions, historique, validation)."""
    info = get_package_info(name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' introuvable")
    history = get_package_history(name)

    # Charger les étapes de validation depuis le manifest
    latest = info.get("latest")
    version_info = info["versions"].get(latest, {}) if latest else {}
    arch = version_info.get("arch", "amd64")
    manifest = load_manifest(name, latest, arch) if latest else None
    validation_steps = manifest.get("validation_steps", []) if manifest else []

    return {"name": name, "info": info, "history": history, "validation_steps": validation_steps}


# ─── Résolution de dépendances ───────────────────────────────────────────────

@router.get("/{name}/dependencies")
def resolve_dependencies(name: str, current_user: str = Depends(get_current_user)):
    """
    Résout les dépendances d'un paquet et retourne leur disponibilité interne.
    Utilisé par le bouton 'Installer' pour valider avant de procéder.
    """
    info = get_package_info(name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' introuvable")

    latest = info.get("latest")
    if not latest:
        raise HTTPException(status_code=404, detail="Aucune version disponible")

    version_info = info["versions"][latest]
    arch = version_info.get("arch", "amd64")

    manifest = load_manifest(name, latest, arch)
    if not manifest:
        return {
            "package": name,
            "version": latest,
            "dependencies": [],
            "all_satisfied": True,
            "missing": [],
        }

    # Résolution récursive en temps réel depuis le paquet dans le pool
    # (couvre les dépendances transitives, pas seulement les directes du manifest)
    pkg_filename = manifest.get("filename")
    pkg_candidates = list(POOL_DIR.rglob(pkg_filename)) if pkg_filename else []
    if not pkg_candidates:
        _found = _find_pool_file(POOL_DIR, name, recursive=True)
        pkg_candidates = [_found] if _found else []
    if not pkg_candidates:
        # Fallback sur le manifest si le fichier n'est plus dans le pool.
        # On strip les qualificateurs d'architecture (perl:any → perl) pour
        # éviter les faux "Manquant" sur les paquets virtuels Debian.
        deps = []
        seen: set[str] = set()
        for dep in manifest.get("dependencies", []):
            raw_name = dep.get("name", "")
            clean_name = raw_name.split(":")[0] if ":" in raw_name else raw_name
            if not clean_name or clean_name in seen:
                continue
            seen.add(clean_name)
            # Essaie chaque extension acceptée plutôt que d'en deviner une
            # seule via next(iter(_ACCEPTED_EXTS)) — en REPO_FORMAT=all/both
            # cela pouvait faire rapporter à tort une dépendance comme
            # "manquante" alors qu'elle était présente sous un autre format.
            available = _find_pool_file(POOL_DIR, clean_name, recursive=True) is not None
            deps.append({**dep, "name": clean_name, "available_internally": available})
    elif _is_apt():
        deps = _resolve_deps_recursive(str(pkg_candidates[0]))
    else:
        # RPM : résolution via l'index RPM (requires/provides)
        from services.package_index import get_package_info as _rpm_pkg_info
        deps = []
        for dep_name in manifest.get("dependencies", []):
            name_str = dep_name.get("name", dep_name) if isinstance(dep_name, dict) else dep_name
            info = _rpm_pkg_info(name_str)
            deps.append({
                "name": name_str,
                "available_internally": info is not None,
                "version": info.get("version") if info else None,
            })

    missing = [d["name"] for d in deps if not d["available_internally"]]

    return {
        "package":        name,
        "version":        latest,
        "dependencies":   deps,
        "all_satisfied":  len(missing) == 0,
        "missing":        missing,
        "install_blocked": len(missing) > 0,
    }


# ─── Installation ─────────────────────────────────────────────────────────────

class InstallRequest(BaseModel):
    target: str = "localhost"


@router.post("/{name}/install")
def install_artifact(
    name: str,
    request: InstallRequest,
    current_user: str = Depends(get_uploader_user),
):
    """
    Installe un paquet sur une cible après vérification des dépendances.
    Bloque si des dépendances sont manquantes.
    """
    info = get_package_info(name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' introuvable")

    latest = info.get("latest")
    version_info = info["versions"].get(latest, {})
    missing_deps = version_info.get("deps_missing", [])

    if missing_deps:
        audit_log("INSTALL", current_user, "FAILURE", package=name, version=latest,
                  detail=f"Dépendances manquantes: {', '.join(missing_deps)}",
                  extra={"target": request.target})
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Installation bloquée — dépendances manquantes dans le repo interne",
                "missing_dependencies": missing_deps,
            }
        )

    # Lancer l'installation via SSH ou localement
    from services.download import download_package
    result = download_package(name)

    audit_log("INSTALL", current_user, "SUCCESS", package=name, version=latest,
              extra={"target": request.target})

    return {
        "status": "success",
        "package": name,
        "version": latest,
        "target": request.target,
        "result": result,
    }


# ─── Suppression ─────────────────────────────────────────────────────────────

@router.delete("/{name}")
def delete_artifact(name: str, current_user: str = Depends(get_maintainer_user)):
    """Supprime un paquet du dépôt (toutes versions)."""
    info = get_package_info(name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' introuvable")

    # Retirer du dépôt physique (reprepro en APT, createrepo_c en RPM)
    _repo_remove_package(name)

    # Supprimer les fichiers paquet du pool — un par version, via le nom de
    # fichier exact stocké dans l'index (comme delete_artifact_version()).
    # NE PAS reconstruire nom_*.ext en devinant l'extension via
    # next(iter(_ACCEPTED_EXTS)) : en REPO_FORMAT=all, _ACCEPTED_EXTS est un
    # frozenset à 3 éléments ({.deb, .rpm, .apk}) et next(iter(...)) renvoie
    # un élément arbitraire (ordre de hachage du frozenset), pas forcément
    # celui du paquet réellement traité — un paquet .deb pouvait ainsi être
    # "supprimé" (ligne PostgreSQL + index retirés, 200 OK) sans que son
    # fichier .deb ne quitte jamais /repos/pool, le rendant indétectable en
    # dehors du pool tout en bloquant silencieusement toute réimportation
    # ultérieure (SHA256 identique → "déjà importé").
    for _version_info in info.get("versions", {}).values():
        _filename = _version_info.get("filename")
        if _filename:
            safe_path_join_http(POOL_DIR, _filename).unlink(missing_ok=True)

    # Supprimer les manifests — PostgreSQL (source de vérité lue par
    # list_manifests()/packages-posture) ET les fichiers JSON legacy.
    # L'ancien code ne supprimait que les fichiers JSON via un glob
    # manuel, jamais la ligne PostgreSQL : le paquet "supprimé"
    # continuait donc d'apparaître dans l'UI indéfiniment.
    delete_manifest_from_db(name)

    # Mettre à jour l'index
    remove_from_index(name)

    audit_log("DELETE", current_user, "SUCCESS", package=name,
              detail="Toutes les versions supprimées")

    return {"status": "deleted", "package": name}


@router.delete("/{name}/{version}")
def delete_artifact_version(
    name: str, version: str,
    current_user: str = Depends(get_maintainer_user),
):
    """Supprime une version spécifique d'un paquet."""
    info = get_package_info(name)
    if not info or version not in info.get("versions", {}):
        raise HTTPException(status_code=404, detail=f"{name} {version} introuvable")

    arch = info["versions"][version].get("arch", "amd64")
    filename = info["versions"][version].get("filename")

    # Retirer du dépôt physique (reprepro en APT, createrepo_c en RPM)
    _repo_remove_package(name)

    # Supprimer le fichier paquet du pool. Le nom stocké dans l'index est la
    # source fiable ; en son absence (ancienne donnée), on recherche le
    # fichier réel plutôt que de reconstruire un nom en devinant une
    # extension via next(iter(_ACCEPTED_EXTS)) — voir delete_artifact()
    # ci-dessus pour l'explication complète de ce bug.
    pkg_path = safe_path_join_http(POOL_DIR, filename) if filename else _find_pool_file(POOL_DIR, name)
    if pkg_path:
        pkg_path.unlink(missing_ok=True)

    # Supprimer le manifest — PostgreSQL (source de vérité) ET le fichier
    # JSON legacy. Même bug que delete_artifact() ci-dessus : un unlink()
    # manuel du seul fichier JSON laissait la ligne PostgreSQL intacte,
    # donc le paquet réapparaissait toujours dans list_manifests()/
    # packages-posture après une suppression "réussie".
    delete_manifest_from_db(name, version, arch)

    remove_from_index(name, version)
    audit_log("DELETE", current_user, "SUCCESS", package=name, version=version)

    return {"status": "deleted", "package": name, "version": version}


# ─── Snapshots historiques ───────────────────────────────────────────────────

@router.get("/{name}/versions")
def list_versions(
    name: str,
    current_user: str = Depends(get_current_user),
):
    """
    Retourne l'historique complet des versions d'un paquet,
    trié par date d'import descendante (la plus récente en premier).

    Chaque entrée indique si le .deb est encore disponible dans le pool.
    """
    history = get_version_history(name)
    if not history:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' introuvable ou sans versions")
    return {
        "package":  name,
        "count":    len(history),
        "versions": history,
    }


@router.get("/{name}/versions/{version}/snapshot")
def get_version_snapshot(
    name: str,
    version: str,
    arch: str = Query("amd64", description="Architecture cible"),
    current_user: str = Depends(get_current_user),
):
    """Retourne le manifest complet (snapshot) d'une version spécifique."""
    snapshot = get_snapshot(name, version, arch)
    if not snapshot:
        raise HTTPException(
            status_code=404,
            detail=f"Snapshot introuvable : {name} {version} ({arch})"
        )
    return snapshot


@router.get("/{name}/versions/compare")
def compare_package_versions(
    name: str,
    v1: str = Query(..., description="Version de référence (ancienne)"),
    v2: str = Query(..., description="Version cible (nouvelle)"),
    arch: str = Query("amd64", description="Architecture cible"),
    current_user: str = Depends(get_current_user),
):
    """
    Compare deux versions d'un paquet.
    Retourne les différences de taille, dépendances, CVE et statut.
    """
    result = compare_versions(name, v1, v2, arch)
    if result.get("error"):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/{name}/versions/{version}/download")
def download_version(
    name: str,
    version: str,
    arch: str = Query("amd64", description="Architecture cible"),
    current_user: str = Depends(get_current_user),
):
    """
    Télécharge le fichier .deb d'une version spécifique depuis le pool.
    Retourne 404 si le fichier n'est plus dans le pool (purgé par rétention).
    """
    snapshot = get_snapshot(name, version, arch)
    if not snapshot:
        raise HTTPException(status_code=404, detail=f"{name} {version} ({arch}) introuvable")

    filename = snapshot.get("filename", "")
    if not filename:
        raise HTTPException(status_code=404, detail="Nom de fichier absent du manifest")

    pkg_path = safe_path_join_http(POOL_DIR, filename)
    if not pkg_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Fichier {filename} absent du pool — version peut-être purgée par la rétention"
        )

    audit_log("DOWNLOAD", current_user, "SUCCESS", package=name, version=version,
              detail=f"Téléchargement historique : {filename}")

    media_type = (
        "application/vnd.debian.binary-package" if _is_apt()
        else "application/x-rpm"
    )
    return FileResponse(
        path=str(pkg_path),
        filename=filename,
        media_type=media_type,
    )


@router.get("/admin/gc-preview")
def preview_version_gc(
    max_versions: int = Query(None, ge=1, description="Override max_versions (défaut : valeur settings)"),
    min_age_days: int = Query(None, ge=0, description="Âge minimum requis pour suppression (défaut : valeur settings)"),
    current_user: str = Depends(get_admin_user),
):
    """
    Simule le garbage collector de versions sans rien supprimer (dry-run).
    Retourne la liste des versions qui seraient supprimées ou ignorées
    selon la politique courante (max_versions + min_age_days).
    """
    result = run_version_gc(
        max_versions=max_versions,
        min_age_days=min_age_days,
        dry_run=True,
    )
    return result


@router.post("/admin/version-gc")
def trigger_version_gc(
    max_versions: int = Query(None, ge=1, description="Override max_versions (défaut : valeur settings)"),
    min_age_days: int = Query(None, ge=0, description="Âge minimum requis pour suppression (défaut : valeur settings)"),
    current_user: str = Depends(get_admin_user),
):
    """
    Déclenche manuellement le garbage collector de versions.
    Supprime les versions excédentaires (les plus anciennes) de chaque paquet
    selon max_versions_per_package et min_version_age_days définis dans les paramètres.
    """
    result = run_version_gc(max_versions=max_versions, min_age_days=min_age_days)
    audit_log(
        "VERSION_GC", current_user, "SUCCESS",
        detail=(
            f"GC versions : {result['versions_deleted']} version(s) supprimée(s), "
            f"{result['versions_skipped']} ignorée(s) (trop récentes), "
            f"sur {result['packages_checked']} paquet(s), "
            f"max_versions={result['max_versions']}, min_age_days={result['min_age_days']}"
        ),
    )
    return result


# ─── Promotion entre distributions ──────────────────────────────────────────

class PromoteRequest(BaseModel):
    from_dist: str      = Field(..., description="Distribution source (ex. jammy)", examples=["jammy"])
    to_dist: str        = Field(..., description="Distribution cible (ex. noble)",  examples=["noble"])
    version: str | None = Field(None, description="Version précise à promouvoir ; si omis, utilise la dernière")
    force: bool         = Field(False, description="Contourner le niveau 'review' (admin uniquement)")
    justification: str  = Field("", description="Justification métier (stockée dans l'audit log)")


@router.get("/{name}/promote/targets")
def get_promote_targets(
    name: str,
    from_dist: str = Query(..., description="Distribution source"),
    current_user: str = Depends(get_current_user),
):
    """
    Retourne les distributions cibles disponibles pour une promotion,
    avec l'évaluation de la politique CVE pour chaque cible.
    """
    info = get_package_info(name)
    if not info:
        raise HTTPException(status_code=404, detail=f"Paquet '{name}' introuvable")

    targets = get_promotable_targets(from_dist)
    latest = info.get("latest")
    cve_summary = info["versions"].get(latest, {}).get("cve_summary") if latest else None
    policy = evaluate_cve_policy(cve_summary)

    return {
        "package":        name,
        "from_dist":      from_dist,
        "targets":        targets,
        "policy_verdict": policy,
    }


@router.post(
    "/{name}/promote",
    summary="Promouvoir un paquet vers une autre distribution",
    responses={
        # SEC-3 : rate limiting documenté
        429: {"description": "Trop de requêtes — limite 20/minute par utilisateur"},
        200: {"description": "Promotion effectuée (`approved`) ou paquet déjà présent (`already_present`)"},
        202: {"description": "CVEs niveau *review* — demande créée, approbation RSSI requise"},
        400: {"description": "Erreur de promotion (paquet introuvable, version absente…)"},
        403: {"description": "Droits insuffisants (`force=True` requiert le rôle admin)"},
        409: {"description": "CVEs niveau *blocked* — promotion interdite"},
    },
)
@limiter.limit("20/minute")  # SEC-3 : rate limit promote
def promote_package(
    request: Request,
    response: Response,
    name: str,
    body: PromoteRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """
    Promeut un paquet d'une distribution vers une autre.

    **Résultats possibles :**

    | HTTP | `status`          | Signification |
    |------|-------------------|---------------|
    | 200  | `approved`        | Promotion effectuée immédiatement |
    | 200  | `already_present` | Version déjà présente dans la cible |
    | 202  | `pending_review`  | CVEs niveau *review* — en attente RSSI |
    | 409  | `blocked`         | CVEs niveau *block* — refusée |

    Le champ `force=True` (admin uniquement) contourne le niveau *review*.
    Le niveau *block* n'est jamais contournable.
    """
    # force=True réservé aux admins
    if body.force and not current_user:
        raise HTTPException(status_code=403, detail="force=True requiert le rôle admin")

    try:
        result = promote(
            name=name,
            from_dist=body.from_dist,
            to_dist=body.to_dist,
            promoted_by=current_user,
            version=body.version,
            force=body.force,
            justification=body.justification,
        )
    except PromotionError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    status = result["status"]
    if status == "blocked":
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Promotion bloquée — CVE(s) critiques détectées.",
                "policy_verdict": result["policy_verdict"],
            },
        )
    if status == "pending_review":
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=202, content=result)

    return result


# ─── Workflow d'approbation RSSI ──────────────────────────────────────────────

# Schémas de réponse (définis avant les endpoints qui les référencent)

class PolicyVerdictSchema(BaseModel):
    verdict:   str  = Field(
        ..., description="approved | blocked | pending_review | pending_admin",
        examples=["pending_review"],
    )
    reason:    str  = Field(..., examples=["CVE HIGH détectée (CVE-2024-1234)"])
    reviewing: list[str] = Field(
        default_factory=list, description="CVEs nécessitant une revue manuelle",
    )
    warnings:  list[str] = Field(default_factory=list)
    blocking:  list[str] = Field(
        default_factory=list, description="CVEs bloquantes (force=True requis)",
    )


class PendingPromotionSchema(BaseModel):
    """Représente une demande de promotion en attente d'approbation RSSI."""
    id:           str          = Field(..., examples=["550e8400-e29b-41d4-a716-446655440000"])
    name:         str          = Field(..., examples=["nginx"])
    version:      str          = Field(..., examples=["1.24.0"])
    from_dist:    str          = Field(..., examples=["jammy"])
    to_dist:      str          = Field(..., examples=["noble"])
    requested_by: str          = Field(..., examples=["alice"])
    requested_at: str          = Field(..., examples=["2026-01-15T10:00:00+00:00"])
    status:       str          = Field(
        ..., description="pending | approved | rejected", examples=["pending"],
    )
    policy_verdict: PolicyVerdictSchema
    decided_by:   str | None   = Field(None, examples=["rssi_admin"])
    decided_at:   str | None   = Field(None, examples=["2026-01-16T09:30:00+00:00"])
    decision_note: str         = Field("", examples=["Validé après revue des CVEs"])


class PaginatedPendingResponse(BaseModel):
    """Réponse paginée de la file d'approbation RSSI."""
    total:  int  = Field(..., description="Nombre total de demandes (avant pagination)")
    status: str  = Field(..., examples=["pending"])
    items:  Any  = Field(..., description="Objet paginé {items: [...], total: int, page: int, …}")

    model_config = {"json_schema_extra": {"example": {
        "total": 2,
        "status": "pending",
        "items": {
            "items": [
                {
                    "id": "550e8400-e29b-41d4-a716-446655440000",
                    "name": "nginx", "version": "1.24.0",
                    "from_dist": "jammy", "to_dist": "noble",
                    "requested_by": "alice",
                    "requested_at": "2026-01-15T10:00:00+00:00",
                    "status": "pending",
                    "policy_verdict": {
                        "verdict": "pending_review",
                        "reason": "CVE HIGH détectée",
                        "reviewing": ["CVE-2024-1234"],
                        "warnings": [], "blocking": [],
                    },
                    "decided_by": None, "decided_at": None, "decision_note": "",
                }
            ],
            "total": 2, "page": 1, "per_page": 50, "pages": 1,
        },
    }}}


class PendingDecisionRequest(BaseModel):
    """Corps des requêtes approve / reject."""
    justification: str = Field(
        ...,
        description="Justification métier obligatoire (pour l'approbation)",
        examples=["Revue CVEs effectuée — risque acceptable pour l'environnement de production."],
    )
    reason: str = Field(
        "",
        description="Motif de rejet (obligatoire pour reject, ignoré pour approve)",
        examples=["CVE-2024-1234 non corrigée — risque inacceptable."],
    )


@router.get(
    "/admin/pending-promotions",
    summary="File d'approbation RSSI — liste des demandes",
    response_model=PaginatedPendingResponse,
    responses={
        200: {"description": "Liste paginée des demandes de promotion"},
        403: {"description": "Droits insuffisants (rôle maintainer requis)"},
    },
)
def list_pending_promotions(
    status: str = Query(
        "pending",
        description="Filtre statut : `pending` | `approved` | `rejected` | `all`",
        openapi_examples={"pending": {"summary": "En attente", "value": "pending"}},
    ),
    page:     int = Query(1,  ge=1,       description="Numéro de page (1-indexé)"),
    per_page: int = Query(50, ge=1, le=200, description="Éléments par page"),
    current_user: str = Depends(get_maintainer_user),
):
    """
    Retourne la file d'approbation RSSI.

    - `status=pending` (défaut) — demandes en attente de décision
    - `status=approved` / `rejected` — historique filtré
    - `status=all` — historique complet (toutes décisions)

    Résultats triés du plus récent au plus ancien.
    Rôle minimum requis : **maintainer**.
    """
    filter_status = None if status == "all" else status
    records = list_pending(status=filter_status)
    return {
        "total":   len(records),
        "status":  status,
        "items":   paginate(records, page=page, per_page=per_page),
    }


@router.post(
    "/{name}/promote/{pending_id}/approve",
    summary="Approuver une demande de promotion (RSSI)",
    responses={
        200: {"description": "Promotion approuvée et effectuée"},
        400: {"description": "Justification manquante ou nom de paquet incohérent"},
        404: {"description": "Demande introuvable"},
        409: {
            "description": (
                "Approbation refusée — CVEs redevenues *blocked* depuis la demande, "
                "ou demande déjà traitée (concurrence)"
            )
        },
        429: {"description": "Trop de requêtes — limite 5/minute par utilisateur"},
    },
)
@limiter.limit("5/minute")  # SEC-3 : décisions RSSI — limite stricte
def approve_pending_promotion(
    request: Request,
    response: Response,
    name:       str = FPath(..., description="Nom du paquet"),
    pending_id: str = FPath(..., description="UUID de la demande"),
    body: PendingDecisionRequest = ...,
    current_user: str = Depends(get_admin_user),
):
    """
    Approuve formellement une demande de promotion (rôle **admin / RSSI**).

    **Comportement :**

    1. Vérifie que la demande existe et correspond au paquet `{name}`
    2. Valide que la justification n'est pas vide
    3. **Re-évalue la politique CVE** au moment de la décision :
       si le verdict est `blocked` (nouvelles CVEs découvertes), l'approbation est refusée
    4. Exécute la promotion dans reprepro
    5. Envoie une notification `PROMOTION_APPROVED`

    > ⚠️ Le niveau *blocked* ne peut jamais être contourné, même par un admin.
    """
    record = get_pending(pending_id)
    if record is None:
        raise HTTPException(status_code=404,
                            detail=f"Demande introuvable : {pending_id}")
    if record.get("name") != name:
        raise HTTPException(status_code=400,
                            detail=f"La demande {pending_id} ne concerne pas le paquet {name!r}")
    if not body.justification.strip():
        raise HTTPException(status_code=400,
                            detail="La justification est obligatoire pour l'approbation.")

    try:
        result = approve_pending(
            pending_id=pending_id,
            approved_by=current_user,
            justification=body.justification,
        )
    except PromotionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return result


@router.post(
    "/{name}/promote/{pending_id}/reject",
    summary="Rejeter une demande de promotion (RSSI)",
    responses={
        200: {"description": "Demande rejetée — paquet reste dans la distribution source"},
        400: {"description": "Motif de rejet manquant ou nom de paquet incohérent"},
        404: {"description": "Demande introuvable"},
        409: {"description": "Demande déjà traitée (concurrence)"},
        429: {"description": "Trop de requêtes — limite 5/minute par utilisateur"},
    },
)
@limiter.limit("5/minute")  # SEC-3 : décisions RSSI — limite stricte
def reject_pending_promotion(
    request: Request,
    response: Response,
    name:       str = FPath(..., description="Nom du paquet"),
    pending_id: str = FPath(..., description="UUID de la demande"),
    body: PendingDecisionRequest = ...,
    current_user: str = Depends(get_admin_user),
):
    """
    Rejette formellement une demande de promotion (rôle **admin / RSSI**).

    **Comportement :**

    1. Vérifie que la demande existe et correspond au paquet `{name}`
    2. Valide que le motif de rejet (`reason`) n'est pas vide
    3. Met à jour le statut en `rejected` (aucune action reprepro)
    4. Envoie une notification `PROMOTION_REJECTED` au demandeur

    Le paquet reste dans la distribution source sans modification.
    """
    record = get_pending(pending_id)
    if record is None:
        raise HTTPException(status_code=404,
                            detail=f"Demande introuvable : {pending_id}")
    if record.get("name") != name:
        raise HTTPException(status_code=400,
                            detail=f"La demande {pending_id} ne concerne pas le paquet {name!r}")
    if not body.reason.strip():
        raise HTTPException(status_code=400,
                            detail="Le motif de rejet est obligatoire.")

    try:
        result = reject_pending(
            pending_id=pending_id,
            rejected_by=current_user,
            reason=body.reason,
        )
    except PromotionError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return result


# ─── Audit & Sync ─────────────────────────────────────────────────────────────

@router.get(
    "/audit/logs",
    summary="Journal d'audit paginé",
    responses={200: {"description": "Entrées paginées"}, 403: {"description": "Droits insuffisants"}},
)
def get_audit_logs(
    page:     int = Query(1, ge=1, description="Numéro de page (1-indexé)"),
    per_page: int = Query(100, ge=1, le=500, description="Éléments par page"),
    package:  str = Query(None, description="Filtrer par nom de paquet"),
    action:   str = Query(None, description="Filtrer par action (UPLOAD, DELETE, PROMOTE…)"),
    result:   str = Query(None, description="Filtrer par résultat (SUCCESS, FAILURE, WARNING…)"),
    user:     str = Query(None, description="Filtrer par nom d'utilisateur"),
    start:    str = Query(None, description="Borne début ISO-8601 (incluse)"),
    end:      str = Query(None, description="Borne fin ISO-8601 (incluse)"),
    q:        str = Query(None, description="Recherche texte libre sur package, user, detail"),
    sort:     str = Query("desc", pattern="^(asc|desc)$",
                           description="Ordre de tri par horodatage : desc (plus récent d'abord, défaut) ou asc"),
    current_user: str = Depends(get_auditor_user),
):
    """
    Retourne les entrées paginées du journal d'audit avec filtres optionnels.

    Tous les filtres sont combinables (AND logique).
    Triés par horodatage selon `sort` (desc par défaut, plus récent d'abord).
    """
    from services.audit_export import _filter_entries

    if package:
        logs = get_package_history(package)
    else:
        logs = get_recent_logs(limit=10_000)

    # Déléguer le filtrage structuré au service d'export (réutilisation)
    logs = _filter_entries(logs, start=start, end=end, action=action,
                           result=result, user=user)

    # Filtre texte libre (package déjà géré au-dessus)
    if q:
        q_low = q.lower()
        logs = [
            l for l in logs
            if q_low in (l.get("package") or "").lower()
            or q_low in (l.get("user") or "").lower()
            or q_low in (l.get("detail") or "").lower()
        ]

    # Tri explicite par horodatage — get_recent_logs() et get_package_history()
    # ne renvoient pas le même ordre de base (respectivement desc et asc), donc
    # on ne peut pas se reposer sur l'ordre implicite de la source pour honorer
    # le paramètre `sort` de façon fiable dans les deux cas.
    logs = sorted(logs, key=lambda entry: entry.get("timestamp") or "", reverse=(sort == "desc"))

    return paginate(logs, page=page, per_page=per_page)


@router.get("/audit/export")
def export_audit(
    fmt: str = Query("json", alias="format", description="Format : 'csv' ou 'json'"),
    start: str = Query(None, description="Borne début ISO-8601 (incluse)"),
    end: str   = Query(None, description="Borne fin ISO-8601 (incluse)"),
    package: str = Query(None, description="Filtrer par paquet"),
    action: str  = Query(None, description="Filtrer par action"),
    result: str  = Query(None, description="Filtrer par résultat"),
    user: str    = Query(None, description="Filtrer par utilisateur"),
    compress: bool = Query(False, description="Compression gzip"),
    sign: bool     = Query(False, description="Signature GPG détachée (header X-GPG-Signature)"),
    current_user: str = Depends(get_auditor_user),
):
    """
    Exporte le journal d'audit en CSV ou JSON, avec filtres optionnels.

    Paramètres
    ----------
    format   : 'csv' ou 'json' (défaut 'json')
    start    : borne temporelle début (ISO-8601)
    end      : borne temporelle fin   (ISO-8601)
    compress : si True, retourne le fichier compressé en gzip
    sign     : si True, ajoute la signature GPG dans le header X-GPG-Signature

    Le nom du fichier est suggéré via Content-Disposition.
    """
    if fmt not in ("csv", "json"):
        raise HTTPException(status_code=400, detail="format invalide : 'csv' ou 'json' attendu")

    export = export_audit_logs(
        fmt=fmt,
        start=start,
        end=end,
        package=package,
        action=action,
        result=result,
        user=user,
        compress=compress,
        sign=sign,
    )

    filename = get_export_filename(fmt=fmt, compress=compress)

    if fmt == "csv":
        media_type = "text/csv; charset=utf-8"
    else:
        media_type = "application/json"
    if compress:
        media_type = "application/gzip"

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Export-Count": str(export["count"]),
    }
    if export.get("signature"):
        headers["X-GPG-Signature"] = export["signature"]

    audit_log(
        "AUDIT_EXPORT", current_user, "SUCCESS",
        detail=f"format={fmt}, count={export['count']}, compress={compress}, sign={sign}",
    )

    return Response(
        content=export["data"],
        media_type=media_type,
        headers=headers,
    )


@router.get(
    "/audit/export/archive",
    summary="Archive ZIP de tous les journaux d'audit (admin)",
    responses={
        200: {"description": "Fichier ZIP contenant tous les JSONL d'audit"},
        403: {"description": "Droits insuffisants (rôle admin requis)"},
    },
)
def export_audit_archive(
    current_user: str = Depends(get_admin_user),
):
    """
    Télécharge un fichier ZIP contenant tous les fichiers JSONL d'audit.

    Chaque fichier JSONL correspond à une journée (ex. `2026-06-03.jsonl`).
    Rôle **admin** requis.
    """
    data = build_audit_archive()
    today = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"audit_archive_{today}.zip"

    audit_log(
        "AUDIT_EXPORT_ARCHIVE", current_user, "SUCCESS",
        detail=f"Archive ZIP téléchargée, taille={len(data)}",
    )

    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Archive-Size": str(len(data)),
        },
    )


@router.get(
    "/audit/export/user/{username}",
    summary="Export RGPD des entrées d'audit d'un utilisateur (admin)",
    responses={
        200: {"description": "JSON structuré des entrées d'audit de l'utilisateur"},
        403: {"description": "Droits insuffisants (rôle admin requis)"},
    },
)
def export_audit_user(
    username: str = FPath(..., description="Nom d'utilisateur (RGPD)"),
    compress: bool = Query(False, description="Compression gzip"),
    current_user: str = Depends(get_admin_user),
):
    """
    Exporte toutes les entrées d'audit concernant l'utilisateur `username`.

    Conforme RGPD — retourne un JSON structuré avec le nombre d'entrées
    et leur contenu complet, triées par ordre chronologique.
    Rôle **admin** requis.
    """
    data = export_user_data(username)

    today = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if compress:
        from services.audit_export import _gzip_compress
        data = _gzip_compress(data)
        filename   = f"audit_user_{username}_{today}.json.gz"
        media_type = "application/gzip"
    else:
        filename   = f"audit_user_{username}_{today}.json"
        media_type = "application/json"

    audit_log(
        "AUDIT_EXPORT_USER", current_user, "SUCCESS",
        detail=f"Export RGPD user={username}, compress={compress}",
    )

    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get(
    "/audit/integrity",
    summary="Vérification d'intégrité des journaux d'audit (admin)",
    responses={
        200: {"description": "SHA-256 et métadonnées de chaque fichier JSONL"},
        403: {"description": "Droits insuffisants (rôle admin requis)"},
    },
)
def get_audit_integrity(
    current_user: str = Depends(get_admin_user),
):
    """
    Calcule le condensat SHA-256 de chaque fichier JSONL d'audit.

    Permet de détecter toute altération a posteriori des journaux.
    Retourne pour chaque fichier : nom, SHA-256, taille en octets, nombre de lignes.
    Rôle **admin** requis.
    """
    results = check_audit_integrity()
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "files":      results,
        "total":      len(results),
    }


@router.post("/admin/sync-index")
def sync_index(current_user: str = Depends(get_maintainer_user)):
    """Resynchronise l'index depuis les fichiers manifests existants."""
    count = sync_index_from_pool()
    audit_log("SYNC", current_user, "SUCCESS", detail=f"{count} paquets indexés")
    return {"status": "ok", "packages_indexed": count}


@router.post("/admin/reenrich-cve", status_code=202)
def reenrich_cve(current_user: str = Depends(get_maintainer_user)):
    """
    Ré-enrichit les CVE déjà scannées de tous les paquets avec les scores
    EPSS/KEV actuels, sans relancer Grype — voir
    services/manifest.py:reenrich_manifest_cve() pour le raisonnement complet.
    """
    import threading

    def _run():
        try:
            result = reenrich_manifest_cve()
            audit_log("REENRICH_CVE", current_user, "SUCCESS", detail=str(result))
            logger.info(f"[reenrich-cve] Terminé : {result}")
        except Exception as e:
            logger.error(f"[reenrich-cve] Erreur : {e}")

    threading.Thread(target=_run, daemon=True).start()
    return {"message": "Ré-enrichissement des CVE lancé en arrière-plan"}


@router.get("/admin/index")
def get_full_index(current_user: str = Depends(get_admin_user)):
    """Retourne l'index complet (pour debug/inspection)."""
    return get_index()
