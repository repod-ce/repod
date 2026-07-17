"""
Routes de gestion des rôles personnalisables.

  GET    /roles                    → liste tous les rôles
  POST   /roles                    → créer un rôle (admin)
  GET    /roles/{id}               → détail d'un rôle
  PUT    /roles/{id}               → mettre à jour label/description/color (admin)
  DELETE /roles/{id}               → supprimer (admin, interdit sur built-in)
  GET    /roles/{id}/permissions   → liste les permissions du rôle
  PUT    /roles/{id}/permissions   → remplace les permissions (admin)
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth.dependencies import get_admin_user, get_current_user
from auth.permissions import ALL_PERMISSIONS, PERMISSION_CATEGORIES, PERMISSION_LABELS
from auth.roles import (
    create_role,
    delete_role,
    get_role,
    get_role_permissions,
    list_roles,
    set_role_permissions,
    update_role,
)

router = APIRouter(prefix="/roles", tags=["Roles"])

VALID_COLORS = {"blue", "green", "red", "purple", "yellow", "orange", "pink", "gray", "indigo", "teal"}


class RoleCreate(BaseModel):
    name:        str
    label:       str
    description: str = ""
    color:       str = "gray"
    permissions: list[str] = []


class RoleUpdate(BaseModel):
    label:       str | None = None
    description: str | None = None
    color:       str | None = None


class PermissionsUpdate(BaseModel):
    permissions: list[str]


@router.get("")
def list_all_roles(current_user: str = Depends(get_current_user)):
    return {
        "roles": list_roles(),
        "all_permissions": sorted(ALL_PERMISSIONS),
        "permission_labels": PERMISSION_LABELS,
        "permission_categories": PERMISSION_CATEGORIES,
    }


@router.post("", status_code=201)
def create_new_role(body: RoleCreate, current_user: str = Depends(get_admin_user)):
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="Le nom du rôle est obligatoire")
    if body.color not in VALID_COLORS:
        raise HTTPException(status_code=400, detail=f"Couleur invalide. Valeurs : {sorted(VALID_COLORS)}")
    invalid = set(body.permissions) - ALL_PERMISSIONS
    if invalid:
        raise HTTPException(status_code=400, detail=f"Permissions invalides : {sorted(invalid)}")
    try:
        role = create_role(
            name=body.name.strip(),
            label=body.label.strip() or body.name.strip(),
            description=body.description,
            color=body.color,
            permissions=set(body.permissions),
            created_by=current_user,
        )
    except Exception as exc:
        if "uq_custom_roles_name" in str(exc) or "unique" in str(exc).lower():
            raise HTTPException(status_code=409, detail=f"Un rôle '{body.name}' existe déjà")
        raise HTTPException(status_code=500, detail=str(exc))
    return {"role": role}


@router.get("/{role_id}")
def get_one_role(role_id: str, current_user: str = Depends(get_current_user)):
    role = get_role(role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Rôle introuvable")
    return {"role": role}


@router.put("/{role_id}")
def update_one_role(role_id: str, body: RoleUpdate, current_user: str = Depends(get_admin_user)):
    role = get_role(role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Rôle introuvable")
    if body.color is not None and body.color not in VALID_COLORS:
        raise HTTPException(status_code=400, detail=f"Couleur invalide. Valeurs : {sorted(VALID_COLORS)}")
    updated = update_role(role_id, label=body.label, description=body.description, color=body.color)
    return {"role": updated}


@router.delete("/{role_id}", status_code=204)
def delete_one_role(role_id: str, current_user: str = Depends(get_admin_user)):
    role = get_role(role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Rôle introuvable")
    try:
        deleted = delete_role(role_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if not deleted:
        raise HTTPException(status_code=500, detail="Suppression échouée")


@router.get("/{role_id}/permissions")
def get_permissions(role_id: str, current_user: str = Depends(get_current_user)):
    if not get_role(role_id):
        raise HTTPException(status_code=404, detail="Rôle introuvable")
    return {"permissions": sorted(get_role_permissions(role_id))}


@router.put("/{role_id}/permissions")
def set_permissions(role_id: str, body: PermissionsUpdate, current_user: str = Depends(get_admin_user)):
    role = get_role(role_id)
    if not role:
        raise HTTPException(status_code=404, detail="Rôle introuvable")
    invalid = set(body.permissions) - ALL_PERMISSIONS
    if invalid:
        raise HTTPException(status_code=400, detail=f"Permissions invalides : {sorted(invalid)}")
    try:
        set_role_permissions(role_id, set(body.permissions))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"permissions": sorted(body.permissions)}
