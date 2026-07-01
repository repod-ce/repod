"""
Routes de gestion des groupes d'utilisateurs.

  GET    /groups                    → liste tous les groupes
  POST   /groups                    → créer un groupe (admin)
  GET    /groups/{id}               → détail d'un groupe
  PUT    /groups/{id}               → mettre à jour (admin)
  DELETE /groups/{id}               → supprimer (admin)
  GET    /groups/{id}/members       → liste des membres
  POST   /groups/{id}/members       → ajouter un membre (admin)
  DELETE /groups/{id}/members/{u}   → retirer un membre (admin)
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth.dependencies import get_admin_user, get_current_user
from services.groups import (
    add_member,
    create_group,
    delete_group,
    get_group,
    get_group_members,
    get_user_groups,
    list_groups,
    remove_member,
    update_group,
)

router = APIRouter(prefix="/groups", tags=["Groups"])

VALID_COLORS = {"blue", "green", "red", "purple", "yellow", "orange", "pink", "gray", "indigo", "teal"}


VALID_ROLES = {"admin", "maintainer", "uploader", "auditor", "reader"}


class GroupCreate(BaseModel):
    name:         str
    description:  str = ""
    color:        str = "blue"
    default_role: str | None = None


_UNSET = "__unset__"


class GroupUpdate(BaseModel):
    name:         str | None = None
    description:  str | None = None
    color:        str | None = None
    default_role: str | None = _UNSET


class MemberAdd(BaseModel):
    username: str


@router.get("")
def list_all_groups(current_user: str = Depends(get_current_user)):
    return {"groups": list_groups()}


@router.post("", status_code=201)
def create_new_group(body: GroupCreate, current_user: str = Depends(get_admin_user)):
    if body.color not in VALID_COLORS:
        raise HTTPException(status_code=400, detail=f"Couleur invalide. Valeurs : {sorted(VALID_COLORS)}")
    if not body.name.strip():
        raise HTTPException(status_code=400, detail="Le nom du groupe est obligatoire")
    if body.default_role and body.default_role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Role invalide. Valeurs : {sorted(VALID_ROLES)}")
    try:
        group = create_group(body.name.strip(), body.description, body.color, current_user,
                             default_role=body.default_role)
    except Exception as exc:
        if "uq_groups_name" in str(exc) or "unique" in str(exc).lower():
            raise HTTPException(status_code=409, detail=f"Un groupe '{body.name}' existe déjà")
        raise HTTPException(status_code=500, detail=str(exc))
    return {"group": group}


@router.get("/me")
def my_groups(current_user: str = Depends(get_current_user)):
    """Retourne les groupes de l'utilisateur courant."""
    return {"groups": get_user_groups(current_user)}


@router.get("/{group_id}")
def get_one_group(group_id: str, current_user: str = Depends(get_current_user)):
    group = get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Groupe introuvable")
    return {"group": group}


@router.put("/{group_id}")
def update_one_group(group_id: str, body: GroupUpdate, current_user: str = Depends(get_admin_user)):
    if not get_group(group_id):
        raise HTTPException(status_code=404, detail="Groupe introuvable")
    if body.color is not None and body.color not in VALID_COLORS:
        raise HTTPException(status_code=400, detail=f"Couleur invalide. Valeurs : {sorted(VALID_COLORS)}")
    if body.default_role not in (_UNSET, None) and body.default_role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Role invalide. Valeurs : {sorted(VALID_ROLES)}")
    role_arg = ... if body.default_role == _UNSET else body.default_role
    try:
        group = update_group(group_id, name=body.name, description=body.description,
                             color=body.color, default_role=role_arg)
    except Exception as exc:
        if "uq_groups_name" in str(exc) or "unique" in str(exc).lower():
            raise HTTPException(status_code=409, detail=f"Un groupe '{body.name}' existe déjà")
        raise HTTPException(status_code=500, detail=str(exc))
    return {"group": group}


@router.delete("/{group_id}", status_code=204)
def delete_one_group(group_id: str, current_user: str = Depends(get_admin_user)):
    if not get_group(group_id):
        raise HTTPException(status_code=404, detail="Groupe introuvable")
    delete_group(group_id)


@router.get("/{group_id}/members")
def list_members(group_id: str, current_user: str = Depends(get_current_user)):
    if not get_group(group_id):
        raise HTTPException(status_code=404, detail="Groupe introuvable")
    return {"members": get_group_members(group_id)}


@router.post("/{group_id}/members", status_code=201)
def add_group_member(group_id: str, body: MemberAdd, current_user: str = Depends(get_admin_user)):
    if not get_group(group_id):
        raise HTTPException(status_code=404, detail="Groupe introuvable")
    added = add_member(group_id, body.username, current_user)
    if not added:
        raise HTTPException(status_code=409, detail=f"'{body.username}' est déjà membre du groupe")
    return {"status": "ok", "username": body.username}


@router.delete("/{group_id}/members/{username}", status_code=204)
def remove_group_member(group_id: str, username: str, current_user: str = Depends(get_admin_user)):
    if not get_group(group_id):
        raise HTTPException(status_code=404, detail="Groupe introuvable")
    removed = remove_member(group_id, username)
    if not removed:
        raise HTTPException(status_code=404, detail=f"'{username}' n'est pas membre du groupe")
