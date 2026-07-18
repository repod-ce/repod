"""
Routes de gestion des templates email.

  GET    /templates              → liste tous les templates
  GET    /templates/{name}       → contenu d'un template
  PUT    /templates/{name}       → sauvegarder un template custom
  POST   /templates/{name}/reset → restaurer le défaut
  POST   /templates/{name}/preview → preview HTML avec données fictives
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth.dependencies import get_admin_user

router = APIRouter(prefix="/templates", tags=["Templates"])


class TemplateUpdate(BaseModel):
    body: str
    subject: str | None = None


class TemplatePreview(BaseModel):
    body: str | None = None


@router.get("")
def list_all_templates(current_user: str = Depends(get_admin_user)):
    from services.email_templates import list_templates
    return {"templates": list_templates()}


@router.get("/{name}")
def get_one_template(name: str, current_user: str = Depends(get_admin_user)):
    from services.email_templates import get_template
    tpl = get_template(name)
    if not tpl:
        raise HTTPException(status_code=404, detail=f"Template '{name}' introuvable")
    return {"template": tpl}


@router.put("/{name}")
def update_template(name: str, body: TemplateUpdate, current_user: str = Depends(get_admin_user)):
    from services.email_templates import save_template
    tpl = save_template(name, body.body, subject=body.subject)
    return {"template": tpl}


@router.post("/{name}/reset")
def reset_one_template(name: str, current_user: str = Depends(get_admin_user)):
    from services.email_templates import reset_template
    tpl = reset_template(name)
    if not tpl:
        raise HTTPException(status_code=404, detail=f"Pas de défaut pour '{name}'")
    return {"template": tpl}


@router.post("/{name}/preview")
def preview_one_template(name: str, body: TemplatePreview = TemplatePreview(),
                         current_user: str = Depends(get_admin_user)):
    from services.email_templates import preview_template
    html = preview_template(name, body=body.body)
    return {"html": html}
