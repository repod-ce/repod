"""
Routes du wizard de première installation.

Ces endpoints sont SANS AUTHENTIFICATION — nécessaire pour le bootstrap initial.
Une fois l'application configurée (admin créé), POST /setup renvoie 409.

Endpoints :
  GET  /setup/status     → statut du wizard (setup_done, needs_setup)
  GET  /setup/preflight  → pré-diagnostic système (DB, disque, ClamAV, Grype, secrets, TLS)
  POST /setup            → exécute la configuration initiale et retourne un JWT

Sécurité (SETUP_TOKEN) :
  Entre le démarrage du conteneur et la création du premier admin, POST /setup
  est accessible à quiconque atteint le réseau du backend (course possible).
  Si la variable d'environnement SETUP_TOKEN est définie, POST /setup exige
  un header `X-Setup-Token` correspondant — sinon 403. Si SETUP_TOKEN n'est
  pas défini, le comportement historique (aucune vérification) est conservé,
  pour ne pas casser les déploiements existants.
"""

import hmac
import os
import shutil
import subprocess

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from services.setup import (
    SetupAlreadyDoneError,
    SetupError,
    get_setup_status,
    run_setup,
)

router = APIRouter(prefix="/setup", tags=["Setup"])


class SetupRequest(BaseModel):
    admin_username: str = Field(..., min_length=3, description="Nom du premier compte administrateur")
    admin_password: str = Field(..., min_length=8, description="Mot de passe (≥ 8 caractères)")
    admin_email: str = Field("", description="Adresse e-mail de l'administrateur (optionnel)")
    admin_full_name: str = Field("", description="Nom complet affiché (optionnel)")
    app_url: str = Field("", description="URL publique de l'application (optionnel)")


@router.get("/status")
def setup_status():
    """
    Retourne l'état du wizard de première installation.
    Endpoint public — aucune authentification requise.

    Réponse :
      {
        "setup_done":  bool,
        "needs_setup": bool,
        "checked_at":  str
      }
    """
    return get_setup_status()


@router.get("/preflight")
def preflight_check():
    """
    Pré-diagnostic avant installation. Pas d'authentification requise.

    Vérifie la connectivité base de données, l'espace disque, la disponibilité
    de ClamAV et Grype, la configuration des secrets et la présence d'un
    certificat TLS.

    Réponse :
      {
        "checks": { "<name>": {"ok": bool, "detail": str, ...}, ... },
        "ready":  bool   // true si tous les checks passent
      }
    """
    checks = {}

    # 1. Database connectivity
    try:
        from db.engine import db_conn
        from sqlalchemy import text
        with db_conn() as conn:
            conn.execute(text("SELECT 1"))
        checks["database"] = {"ok": True, "detail": "PostgreSQL connecté"}
    except Exception as e:
        checks["database"] = {"ok": False, "detail": str(e)[:100]}

    # 2. Disk space
    try:
        usage = shutil.disk_usage("/repos")
        free_gb = round(usage.free / (1024**3), 1)
        checks["disk_space"] = {
            "ok": free_gb > 1,
            "detail": f"{free_gb} Go libres",
            "free_gb": free_gb,
        }
    except Exception:
        checks["disk_space"] = {"ok": False, "detail": "Impossible de vérifier"}

    # 3. ClamAV
    try:
        result = subprocess.run(
            ["clamscan", "--version"],
            capture_output=True, text=True, timeout=5,
        )
        checks["clamav"] = {
            "ok": result.returncode == 0,
            "detail": result.stdout.strip()[:80],
        }
    except Exception:
        checks["clamav"] = {"ok": False, "detail": "ClamAV non disponible"}

    # 4. Grype
    try:
        result = subprocess.run(
            ["grype", "version"],
            capture_output=True, text=True, timeout=5,
        )
        version = result.stdout.strip().split("\n")[0] if result.stdout else "?"
        checks["grype"] = {
            "ok": result.returncode == 0,
            "detail": version[:80],
        }
    except Exception:
        checks["grype"] = {"ok": False, "detail": "Grype non disponible"}

    # 5. Secrets
    jwt_key = os.getenv("JWT_SECRET_KEY", "")
    is_default = not jwt_key or jwt_key == "change-me-in-production"
    checks["secrets"] = {
        "ok": not is_default,
        "detail": "Auto-générés" if not is_default else "Non configurés (valeur par défaut)",
    }

    # 6. TLS certificate
    cert_path = "/repos/certs/server.crt"
    checks["tls"] = {
        "ok": os.path.isfile(cert_path),
        "detail": "Certificat présent" if os.path.isfile(cert_path) else "Certificat absent",
    }

    return {
        "checks": checks,
        "ready": all(c["ok"] for c in checks.values()),
    }


@router.post("/")
def setup(
    body: SetupRequest,
    x_setup_token: str = Header(default="", alias="X-Setup-Token"),
):
    """
    Effectue la configuration initiale de l'application.

    - Crée le premier compte administrateur.
    - Configure l'URL publique si fournie.
    - Retourne un JWT valide pour connexion immédiate.

    Endpoint public — aucune authentification requise (sauf si SETUP_TOKEN
    est défini, auquel cas le header X-Setup-Token est requis).
    Retourne 409 si l'application est déjà configurée.

    Réponse :
      {
        "admin_username": str,
        "access_token":   str,
        "token_type":     "bearer",
        "message":        str
      }
    """
    expected_token = os.getenv("SETUP_TOKEN", "")
    if expected_token and not hmac.compare_digest(x_setup_token, expected_token):
        raise HTTPException(status_code=403, detail="X-Setup-Token invalide ou manquant.")

    try:
        result = run_setup(
            admin_username=body.admin_username,
            admin_password=body.admin_password,
            admin_email=body.admin_email,
            admin_full_name=body.admin_full_name,
            app_url=body.app_url,
        )
    except SetupAlreadyDoneError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except SetupError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return result
