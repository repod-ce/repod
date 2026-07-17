# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Routes de décision RSSI :
- GET  /security/packages/{name}/{version}/decision   → manifest + décision + SLA
- POST /security/packages/{name}/{version}/decide     → enregistre une décision RSSI
- POST /security/packages/{name}/{version}/quarantine → mise en quarantaine immédiate
"""
import os
import shutil
import subprocess
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from auth.dependencies import get_current_user, get_maintainer_user
from routers.security_common import POOL_DIR, STAGING_QUARANTINE
from services.audit import log as audit_log
from services.distributions import remove_package as _repo_remove_package
from services.email_notifications import notify_decision_email
from services.format_router import (
    ACCEPTED_EXTENSIONS as _ACCEPTED_EXTS,
)
from services.format_router import (
    DEFAULT_DISTRIBUTION as _DEFAULT_DISTRIBUTION,
)
from services.format_router import (
    FORMAT_LABEL as _FORMAT_LABEL,
)
from services.format_router import (
    is_apt as _is_apt,
)
from services.format_router import (
    find_pool_file as _find_pool_file,
)
from services.manifest import list_manifests, load_manifest, save_manifest
from services.notifications import notify_decision
from services.path_safety import PathTraversalError, safe_path_join, safe_path_join_http
from services.security_decisions import (
    ACTION_TO_STATUS,
    assign_decision,
    delete_decision,
    get_decision_by_id,
    get_sla_status,
    list_all_decisions,
    list_decisions_for_user,
    load_decision,
    resolve_decision,
    save_decision,
    update_decision,
)

router = APIRouter(prefix="/security", tags=["Security"])


def _pool_filename_fallback(name: str) -> str:
    """
    Nom de fichier de secours quand manifest["filename"] est absent — cherche
    le fichier réel dans le pool plutôt que de deviner une extension via
    next(iter(_ACCEPTED_EXTS)) (arbitraire en REPO_FORMAT=all/both). Renvoie
    "" si introuvable — safe_path_join_http() rejette alors proprement au
    lieu d'un unlink()/subprocess silencieux sur un chemin inventé.
    """
    found = _find_pool_file(POOL_DIR, name)
    return found.name if found else ""


class DecisionRequest(BaseModel):
    action:           str           # accept_risk | exception | reject | upgrade_required
    justification:    str           # obligatoire
    expires_in_days:  int | None = None   # pour accept_risk et exception
    target_version:   str | None = None   # pour upgrade_required
    cve_ids:          list[str] = []      # CVE IDs couverts (vide = tous)
    arch:             str = "amd64"
    assigned_to:      str | None = None   # username ou group id
    assigned_to_type: str | None = None   # "user" | "group"


@router.get("/decisions")
def list_decisions(current_user: str = Depends(get_current_user)):
    """
    Retourne toutes les décisions RSSI enregistrées, pour le suivi/audit.

    Chaque décision est enrichie avec :
    - `sla` : statut d'expiration (accept_risk / exception)
    """
    decisions = []
    for decision in list_all_decisions():
        entry = dict(decision)
        entry["sla"] = get_sla_status(decision)

        if decision.get("action") == "upgrade_required" and decision.get("target_version"):
            # CE : pas de compliance_engine ni inventory
            entry["patch_status"] = {"available": False}
            entry["index_status"] = {"available": False, "indexed_version": None}
            manifest = load_manifest(decision["package"], decision["version"], decision.get("arch", "amd64"))
            entry["distribution"] = manifest.get("distribution") if manifest else None

        # CE : pas d'inventaire machine
        entry["install_count"] = 0
        entry["install_clients"] = []

        decisions.append(entry)

    decisions.sort(key=lambda d: d.get("decided_at") or "", reverse=True)
    return {"decisions": decisions, "count": len(decisions)}


@router.get("/decisions/unassigned")
def list_unassigned_decisions(current_user: str = Depends(get_current_user)):
    """Décisions sans assignation — nécessitent une attribution manuelle."""
    decisions = []
    for decision in list_all_decisions():
        if decision.get("assigned_to"):
            continue
        entry = dict(decision)
        entry["sla"] = get_sla_status(decision)
        entry["install_count"] = 0
        entry["install_clients"] = []
        decisions.append(entry)

    decisions.sort(key=lambda d: d.get("decided_at") or "", reverse=True)
    return {"decisions": decisions, "count": len(decisions)}


class AssignRequest(BaseModel):
    assigned_to:      str | None = None  # username ou group id ; None = retirer l'assignation
    assigned_to_type: str | None = None  # "user" | "group"


@router.patch("/decisions/{decision_id}/assign")
def assign_decision_endpoint(
    decision_id: str,
    body: AssignRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """Assigner ou réassigner une décision existante (sans changer la décision elle-même)."""
    if body.assigned_to and body.assigned_to_type not in ("user", "group"):
        raise HTTPException(status_code=400, detail="assigned_to_type doit être 'user' ou 'group'")

    decision = assign_decision(decision_id, body.assigned_to, body.assigned_to_type)
    if decision is None:
        raise HTTPException(status_code=404, detail=f"Décision {decision_id} introuvable")

    if body.assigned_to:
        try:
            from services.cve_assignment import notify_assignment
            notify_assignment(
                decision["package"], decision["version"],
                body.assigned_to, body.assigned_to_type or "user",
                decision.get("cve_ids") or [],
            )
        except Exception:
            pass

    return {"decision": decision}


class UpdateDecisionRequest(BaseModel):
    action:          str
    justification:   str
    expires_in_days: int | None = None
    target_version:  str | None = None


@router.put("/decisions/{decision_id}")
def update_decision_endpoint(
    decision_id: str,
    body: UpdateDecisionRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """Modifier une décision existante. Admin = toutes; maintainer = ses propres."""
    from auth.dependencies import get_user_role
    existing = get_decision_by_id(decision_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Décision {decision_id} introuvable")

    role = get_user_role(current_user)
    if role != "admin" and existing.get("decided_by") != current_user:
        raise HTTPException(status_code=403, detail="Vous ne pouvez modifier que vos propres décisions")

    if body.action not in ("accept_risk", "exception", "reject", "upgrade_required"):
        raise HTTPException(status_code=400, detail=f"Action invalide : {body.action}")
    if not body.justification.strip():
        raise HTTPException(status_code=400, detail="La justification est obligatoire")

    updated = update_decision(
        decision_id=decision_id,
        action=body.action,
        justification=body.justification,
        expires_in_days=body.expires_in_days,
        target_version=body.target_version,
        updated_by=current_user,
    )
    audit_log(
        "SECURITY_DECISION_UPDATE", current_user, "SUCCESS",
        detail=f"Décision {decision_id} mise à jour → {body.action}",
    )
    return {"decision": updated}


@router.delete("/decisions/{decision_id}")
def delete_decision_endpoint(
    decision_id: str,
    current_user: str = Depends(get_maintainer_user),
):
    """Supprimer une décision. Admin = toutes; maintainer = ses propres."""
    from auth.dependencies import get_user_role
    existing = get_decision_by_id(decision_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Décision {decision_id} introuvable")

    role = get_user_role(current_user)
    if role != "admin" and existing.get("decided_by") != current_user:
        raise HTTPException(status_code=403, detail="Vous ne pouvez supprimer que vos propres décisions")

    delete_decision(existing["package"], existing["version"], existing.get("arch", "amd64"))
    audit_log(
        "SECURITY_DECISION_DELETE", current_user, "SUCCESS",
        detail=f"Décision supprimée : {existing['package']} {existing['version']}",
    )
    return {"status": "deleted", "id": decision_id}


@router.get("/decisions/mine")
def list_my_decisions(current_user: str = Depends(get_current_user)):
    """Retourne les décisions assignées à l'utilisateur courant ou à ses groupes."""
    from services.groups import get_user_group_ids

    group_ids = get_user_group_ids(current_user)

    decisions = []
    for decision in list_decisions_for_user(current_user, group_ids):
        entry = dict(decision)
        entry["sla"] = get_sla_status(decision)
        # CE : pas de compliance_engine ni inventory
        entry["install_count"] = 0
        entry["install_clients"] = []
        decisions.append(entry)

    decisions.sort(key=lambda d: d.get("decided_at") or "", reverse=True)
    return {"decisions": decisions, "count": len(decisions)}


@router.get("/packages/{name}/{version}/decision")
def get_package_decision(
    name: str,
    version: str,
    arch: str = "amd64",
    current_user: str = Depends(get_current_user),
):
    """Retourne le manifest + la décision RSSI + le statut SLA pour un paquet."""
    manifest = load_manifest(name, version, arch)
    if not manifest:
        raise HTTPException(status_code=404, detail=f"{name} {version} introuvable")
    decision = load_decision(name, version, arch)
    sla = get_sla_status(decision) if decision else None
    return {
        "manifest": manifest,
        "decision": decision,
        "sla": sla,
        "status": manifest.get("status", "unknown"),
    }


@router.post("/packages/{name}/{version}/decide")
def decide_package(
    name: str,
    version: str,
    body: DecisionRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """
    Enregistre la décision RSSI pour un paquet en attente.

    Actions :
      accept_risk      → accepte les CVE existantes, paquet promu dans APT
      exception        → exception temporaire (même effet + date d'expiration)
      reject           → quarantaine définitive
      upgrade_required → paquet bloqué jusqu'à la version cible
    """
    VALID_ACTIONS = {"accept_risk", "exception", "reject", "upgrade_required"}
    if body.action not in VALID_ACTIONS:
        raise HTTPException(status_code=400,
                            detail=f"Action invalide. Valeurs : {sorted(VALID_ACTIONS)}")

    if not body.justification.strip():
        raise HTTPException(status_code=400, detail="La justification est obligatoire")

    # Charger le manifest
    manifest = load_manifest(name, version, body.arch)
    if not manifest:
        for m in list_manifests():
            if m["name"] == name and m.get("version") == version:
                manifest = m
                body.arch = m.get("arch", body.arch)
                break
    if not manifest:
        raise HTTPException(status_code=404,
                            detail=f"Manifest introuvable pour {name} {version}")

    current_status = manifest.get("status", "validated")
    if current_status not in ("pending_review", "blocked", "accepted_risk",
                               "exception", "upgrade_required", "validated", "accepted"):
        raise HTTPException(status_code=409,
                            detail=f"Ce paquet n'est pas en révision (statut: {current_status})")

    # Auto-assignation si non spécifiée et règles configurées
    assigned_to      = body.assigned_to
    assigned_to_type = body.assigned_to_type
    if not assigned_to:
        try:
            from services.cve_assignment import auto_assign
            from services.settings import get_settings
            _settings = get_settings()
            _rules = _settings.get("cve_assignment_rules", [])
            if _rules:
                _severities = [c.get("severity", "") for c in manifest.get("cve_results", [])]
                assigned_to, assigned_to_type = auto_assign(_severities, _rules)
        except Exception:
            pass

    # Persister la décision
    cve_ids = body.cve_ids or [c["id"] for c in manifest.get("cve_results", []) if c.get("id")]
    decision = save_decision(
        name=name, version=version, arch=body.arch,
        action=body.action,
        justification=body.justification,
        decided_by=current_user,
        expires_in_days=body.expires_in_days,
        target_version=body.target_version,
        cve_ids=cve_ids,
        assigned_to=assigned_to,
        assigned_to_type=assigned_to_type,
    )

    # Notification d'assignation
    if assigned_to:
        try:
            from services.cve_assignment import notify_assignment
            notify_assignment(name, version, assigned_to, assigned_to_type or "user", cve_ids)
        except Exception:
            pass

    # Mettre à jour le manifest
    new_status = ACTION_TO_STATUS[body.action]
    manifest["status"]        = new_status
    manifest["decision"]      = decision
    save_manifest(manifest)

    # Actions système selon la décision. Le nom de fichier stocké dans le
    # manifest est la source fiable ; en son absence, on recherche le
    # fichier réel (find_pool_file essaie chaque extension acceptée) plutôt
    # que de reconstruire un nom en devinant une extension via
    # next(iter(_ACCEPTED_EXTS)) — en REPO_FORMAT=all/both, cet appel
    # renvoie un élément arbitraire du frozenset, pas forcément celui du
    # paquet réellement traité (voir routers/artifacts.py:delete_artifact()
    # pour un cas confirmé de ce bug faisant échouer silencieusement une
    # opération sur le pool).

    if body.action in ("accept_risk", "exception"):
        # Promouvoir dans le dépôt physique
        distrib  = manifest.get("distribution", _DEFAULT_DISTRIBUTION)
        filename = manifest.get("filename") or _pool_filename_fallback(name)
        pool_pkg = safe_path_join_http(POOL_DIR, filename)
        if pool_pkg.exists():
            if _is_apt():
                ADD_DEB_SCRIPT = os.getenv("ADD_DEB_SCRIPT", "/scripts/add-deb.sh")
                subprocess.run(
                    ["sh", ADD_DEB_SCRIPT, distrib, filename],
                    capture_output=True, text=True,
                )
            else:
                from services.distributions_rpm import add_rpm_to_distrib
                add_rpm_to_distrib(filename, distrib)

    elif body.action == "reject":
        # Déplacer vers quarantaine
        STAGING_QUARANTINE.mkdir(parents=True, exist_ok=True)
        filename = manifest.get("filename") or _pool_filename_fallback(name)
        pool_pkg = safe_path_join_http(POOL_DIR, filename)
        if pool_pkg.exists():
            shutil.move(str(pool_pkg), str(STAGING_QUARANTINE / pool_pkg.name))
        # Retirer du dépôt physique (reprepro en APT, createrepo_c en RPM)
        _repo_remove_package(name)

    audit_log(
        "SECURITY_DECISION", current_user, "SUCCESS",
        package=name, version=version,
        detail=(
            f"Action : {body.action} | "
            f"Justification : {body.justification[:100]} | "
            f"Expire : {decision.get('expires_at') or 'jamais'}"
        ),
    )

    # ── Notifications (webhook + email) ──────────────────────────────────────
    try:
        notify_decision(
            package=name,
            version=version,
            action=body.action,
            decided_by=current_user,
            justification=body.justification,
            expires_in_days=body.expires_in_days,
        )
        notify_decision_email(
            package=name,
            version=version,
            action=body.action,
            decided_by=current_user,
            justification=body.justification,
            expires_in_days=body.expires_in_days,
        )
    except Exception:
        pass  # notifications non bloquantes

    return {
        "status":   "ok",
        "package":  name,
        "version":  version,
        "action":   body.action,
        "new_status": new_status,
        "decision": decision,
        "message": {
            "accept_risk":      f"{name} accepté avec risque — publié dans {_FORMAT_LABEL}",
            "exception":        f"{name} exception accordée — publié dans {_FORMAT_LABEL}",
            "reject":           f"{name} rejeté — déplacé en quarantaine",
            "upgrade_required": f"{name} en attente de mise à jour vers {body.target_version}",
        }.get(body.action, "Décision enregistrée"),
    }


# ─── Décisions machines clientes (flux Conformité Patch) ─────────────────────

class ClientDecisionRequest(BaseModel):
    package:         str
    version:         str
    arch:            str = "x86_64"
    distro_family:   str = ""
    action:          str
    justification:   str
    expires_in_days: int | None = None
    target_version:  str | None = None
    cve_ids:         list[str] = []
    client_ids:      list[str] = []
    hostnames:       list[str] = []


@router.post("/client-decisions")
def create_client_decision(
    body: ClientDecisionRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """Enregistre une décision RSSI sur un paquet vulnérable installé sur une machine cliente."""
    from services.client_decisions import (
        VALID_ACTIONS as _VALID,
    )
    from services.client_decisions import (
        save_client_decision,
    )
    if body.action not in _VALID:
        raise HTTPException(status_code=400,
                            detail=f"Action invalide. Valeurs : {sorted(_VALID)}")
    if not body.justification.strip():
        raise HTTPException(status_code=400, detail="La justification est obligatoire")

    decision = save_client_decision(
        package=body.package, version=body.version, arch=body.arch,
        distro_family=body.distro_family, action=body.action,
        justification=body.justification, decided_by=current_user,
        client_ids=body.client_ids, hostnames=body.hostnames,
        cve_ids=body.cve_ids, expires_in_days=body.expires_in_days,
        target_version=body.target_version,
    )

    audit_log(
        "CLIENT_DECISION", current_user, "SUCCESS",
        package=body.package, version=body.version,
        detail=(
            f"Action : {body.action} | "
            f"Machines : {', '.join(body.hostnames or body.client_ids or ['?'])} | "
            f"{body.justification[:80]}"
        ),
    )

    try:
        notify_decision(
            package=body.package, version=body.version, action=body.action,
            decided_by=current_user, justification=body.justification,
            expires_in_days=body.expires_in_days,
        )
        notify_decision_email(
            package=body.package, version=body.version, action=body.action,
            decided_by=current_user, justification=body.justification,
            expires_in_days=body.expires_in_days,
        )
    except Exception:
        pass

    return {"status": "ok", "decision": decision}


@router.get("/client-decisions")
def list_client_decisions_endpoint(current_user: str = Depends(get_current_user)):
    """
    Retourne toutes les décisions RSSI sur machines clientes,
    enrichies du statut SLA et du statut de résolution.
    """
    from services.client_decisions import get_sla_status as _sla
    from services.client_decisions import list_client_decisions
    decisions = list_client_decisions()
    result = []
    for d in decisions:
        entry = dict(d)
        entry["sla"] = _sla(d)
        result.append(entry)
    return {"decisions": result, "count": len(result)}


@router.post("/client-decisions/{decision_id}/resolve")
def resolve_client_decision_endpoint(
    decision_id: str,
    current_user: str = Depends(get_maintainer_user),
):
    """Marque manuellement une décision client comme résolue (CVE patchée ou risque éliminé)."""
    from services.client_decisions import load_client_decision, resolve_client_decision
    d = load_client_decision(decision_id)
    if not d:
        raise HTTPException(status_code=404, detail="Décision introuvable")
    if d.get("resolved_at"):
        raise HTTPException(status_code=409, detail="Cette décision est déjà résolue")

    updated = resolve_client_decision(decision_id, current_user)
    audit_log(
        "CLIENT_DECISION_RESOLVED", current_user, "SUCCESS",
        package=d.get("package"), version=d.get("version"),
        detail=f"Décision {decision_id[:8]}… résolue manuellement",
    )
    return {"status": "ok", "decision": updated}


class ResolveDecisionRequest(BaseModel):
    arch: str = "amd64"
    note:  str = ""


@router.post("/packages/{name}/{version}/decision/resolve")
def resolve_decision_endpoint(
    name: str,
    version: str,
    body: ResolveDecisionRequest,
    current_user: str = Depends(get_maintainer_user),
):
    """
    Clôture manuellement une décision 'upgrade_required' une fois le correctif
    déployé sur le parc, pour audit (sort la décision de la file d'action tout
    en conservant son historique dans "Suivi des décisions").
    """
    decision = load_decision(name, version, body.arch)
    if not decision:
        raise HTTPException(status_code=404, detail=f"Décision introuvable pour {name} {version}")

    if decision.get("action") != "upgrade_required":
        raise HTTPException(status_code=409, detail="Seules les décisions 'upgrade_required' peuvent être résolues")

    if decision.get("resolved_at"):
        raise HTTPException(status_code=409, detail="Cette décision est déjà résolue")

    updated = resolve_decision(name, version, body.arch, current_user, body.note)

    audit_log(
        "DECISION_RESOLVED", current_user, "SUCCESS",
        package=name, version=version,
        detail=f"Décision 'upgrade_required' -> {decision.get('target_version')} marquée résolue. {body.note[:100]}".strip(),
    )

    return {"status": "ok", "decision": updated}


@router.post("/packages/{name}/{version}/quarantine")
def quarantine_package(
    name: str,
    version: str,
    arch: str = Query("amd64"),
    current_user: str = Depends(get_maintainer_user),
):
    """
    Met un paquet en quarantaine immédiatement :
    1. Déplace le .deb du pool vers staging/quarantine/
    2. Retire de reprepro (toutes distributions)
    3. Met à jour le manifest (status = quarantined)
    4. Audit log
    """
    STAGING_QUARANTINE.mkdir(parents=True, exist_ok=True)

    # Trouver le fichier paquet dans le pool — le manifest est la source
    # fiable pour le nom de fichier exact ; en son absence, find_pool_file()
    # cherche à travers toutes les extensions acceptées plutôt que d'en
    # deviner une seule via next(iter(_ACCEPTED_EXTS)) (arbitraire en
    # REPO_FORMAT=all/both — voir routers/artifacts.py:delete_artifact()
    # pour un cas confirmé où ce pattern laissait un fichier orphelin dans
    # le pool tout en rapportant un succès).
    _manifest_for_path = load_manifest(name, version, arch)
    _manifest_filename = _manifest_for_path.get("filename") if _manifest_for_path else None
    if _manifest_filename:
        try:
            pkg_path = safe_path_join(POOL_DIR, _manifest_filename)
            if not pkg_path.exists():
                pkg_path = None
        except PathTraversalError:
            pkg_path = None
    else:
        pkg_path = None
    if pkg_path is None:
        pkg_path = _find_pool_file(POOL_DIR, name)

    # Retirer du dépôt physique (reprepro APT ou createrepo_c RPM)
    _repo_remove_package(name)

    # Déplacer le paquet si trouvé
    moved_deb = None
    if pkg_path and pkg_path.exists():
        dest = STAGING_QUARANTINE / pkg_path.name
        shutil.move(str(pkg_path), str(dest))
        moved_deb = pkg_path.name

    # Mettre à jour le manifest
    manifest = load_manifest(name, version, arch)
    if not manifest:
        for m in list_manifests():
            if m["name"] == name and m.get("version") == version:
                manifest = m
                arch = m.get("arch", arch)
                break

    if manifest:
        manifest["status"] = "quarantined"
        manifest["quarantined_at"] = datetime.now(timezone.utc).isoformat()
        manifest["quarantined_by"] = current_user
        save_manifest(manifest)

    audit_log(
        "QUARANTINE", current_user, "SUCCESS",
        package=name, version=version,
        detail=f"Mis en quarantaine manuellement — .deb: {moved_deb or 'non trouvé dans pool'}",
    )

    return {
        "status": "quarantined",
        "package": name,
        "version": version,
        "deb_moved": moved_deb,
        "message": f"{name} {version} déplacé en quarantaine",
    }
