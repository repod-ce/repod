"""
Routes pour les paramètres de l'application (admin uniquement).
- GET  /settings/           → lire tous les paramètres (mots de passe masqués)
- PATCH /settings/          → mettre à jour (partiel, deep-merge)
- POST /settings/test-webhook → tester le webhook configuré
- GET  /settings/next-sync  → prochaine exécution du cron sécurité
"""

import copy
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth.dependencies import get_admin_user
from services import scheduler_state
from services.settings import get_settings, update_settings
from services.audit import log as audit_log

logger = logging.getLogger("settings_router")

# Répertoire du trousseau GPG partagé entre depot-apt et backend
GNUPG_HOME = os.getenv("GNUPG_HOME", "/repos/gnupg")


# Champs sensibles à masquer dans les réponses GET /settings
# Ajouter ici tout nouveau champ secret pour qu'il soit automatiquement masqué.
_SENSITIVE_KEYS = {"smtp_password", "bind_password", "client_secret"}
_MASK = "••••••••"


def _mask_secrets(obj: Any) -> Any:
    """Masque récursivement les champs sensibles dans un dict/list."""
    if isinstance(obj, dict):
        return {
            k: _MASK if k in _SENSITIVE_KEYS and obj[k] else _mask_secrets(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_mask_secrets(i) for i in obj]
    return obj


def _strip_masked_secrets(obj: Any) -> Any:
    """Supprime les placeholders masqués pour ne pas écraser les vrais mots de passe."""
    if isinstance(obj, dict):
        return {
            k: _strip_masked_secrets(v)
            for k, v in obj.items()
            if not (k in _SENSITIVE_KEYS and v == _MASK)
        }
    if isinstance(obj, list):
        return [_strip_masked_secrets(i) for i in obj]
    return obj

router = APIRouter(prefix="/settings", tags=["Settings"])


# ─── Lecture ──────────────────────────────────────────────────────────────────

@router.get("/")
def read_settings(current_user: str = Depends(get_admin_user)):
    """Retourne tous les paramètres courants (mots de passe masqués)."""
    return _mask_secrets(get_settings())


# ─── Mise à jour ──────────────────────────────────────────────────────────────

class SettingsPatch(BaseModel):
    app_url:       str | None = None
    repo_url:      str | None = None
    sync:          dict[str, Any] | None = None
    sources:       dict[str, Any] | None = None
    email:         dict[str, Any] | None = None
    retention:     dict[str, Any] | None = None
    validation:    dict[str, Any] | None = None
    mirror:        dict[str, Any] | None = None


@router.patch("/")
def patch_settings(
    body: SettingsPatch,
    current_user: str = Depends(get_admin_user),
):
    """
    Met à jour les paramètres par fusion profonde.
    Si les paramètres sync changent, le scheduler est mis à jour immédiatement.
    """
    partial = {k: v for k, v in body.model_dump().items() if v is not None}
    partial = _strip_masked_secrets(partial)
    updated = update_settings(partial)
    audit_log("SETTINGS_CHANGE", current_user, "SUCCESS",
              detail=f"Sections modifiées : {', '.join(partial.keys())}")

    # ── Reschedule à chaud si le cron APT a changé ─────────────────────────
    if "sync" in partial and scheduler_state.scheduler is not None:
        sync = updated["sync"]
        try:
            if sync.get("enabled", True):
                scheduler_state.scheduler.reschedule_job(
                    "security_sync_daily",
                    trigger="cron",
                    hour=int(sync["hour"]),
                    minute=int(sync["minute"]),
                )
                logger.info(
                    f"[settings] Cron sécurité replanifié → {sync['hour']:02d}:{sync['minute']:02d}"
                )
            else:
                scheduler_state.scheduler.pause_job("security_sync_daily")
                logger.info("[settings] Cron sécurité mis en pause.")
        except Exception as e:
            logger.warning(f"[settings] Impossible de mettre à jour le scheduler sécurité : {e}")

    # ── Reschedule à chaud du mirroir planifié si la config a changé ─────────
    if "mirror" in partial and scheduler_state.scheduler is not None:
        mirror_cfg = updated.get("mirror", {})
        try:
            if mirror_cfg.get("enabled", False):
                scheduler_state.scheduler.reschedule_job(
                    "mirror_daily",
                    trigger="cron",
                    hour=int(mirror_cfg.get("hour", 4)),
                    minute=int(mirror_cfg.get("minute", 30)),
                )
                scheduler_state.scheduler.resume_job("mirror_daily")
                logger.info(
                    f"[settings] Mirroir planifié replanifié → "
                    f"{mirror_cfg['hour']:02d}:{mirror_cfg['minute']:02d}"
                )
            else:
                scheduler_state.scheduler.pause_job("mirror_daily")
                logger.info("[settings] Mirroir planifié mis en pause.")
        except Exception as e:
            logger.warning(f"[settings] Impossible de mettre à jour le scheduler de mirroir : {e}")

    return _mask_secrets(updated)


# ─── GPG ──────────────────────────────────────────────────────────────────────

def _gpg_cmd(args: list[str]) -> list[str]:
    """Préfixe une commande GPG avec --homedir et options batch-safe."""
    return [
        "gpg",
        "--homedir", GNUPG_HOME,
        "--no-default-keyring",
        "--keyring", f"{GNUPG_HOME}/pubring.kbx",
        "--pinentry-mode", "loopback",   # évite le besoin d'un terminal/agent PIN
    ] + args


def _ensure_gnupg_permissions() -> None:
    """S'assure que le homedir GPG a les bons droits (700) pour éviter le warning unsafe ownership."""
    import stat
    path = Path(GNUPG_HOME)
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(stat.S_IRWXU)   # 700 — owner only


# Répertoire dists — monté en lecture-écriture dans le backend ET dans nginx
DISTS_DIR = os.getenv("DISTS_DIR", "/repos/dists")


def export_public_key() -> None:
    """
    Exporte la clé publique GPG courante en ASCII armored vers {DISTS_DIR}/depot.gpg.

    Ce fichier est accessible via nginx au chemin /repos/dists/depot.gpg car le
    répertoire ./repos/dists est monté dans les deux conteneurs.

    Appelée automatiquement :
      - au démarrage du backend (lifespan)
      - après generate_gpg_key()
    """
    dists_dir = Path(DISTS_DIR)
    out_path = dists_dir / "depot.gpg"

    try:
        _ensure_gnupg_permissions()
        result = subprocess.run(
            _gpg_cmd(["--armor", "--export"]),
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0 or not result.stdout.strip():
            logger.warning("[gpg] export_public_key : aucune clé à exporter (keyring vide ?)")
            return

        dists_dir.mkdir(parents=True, exist_ok=True)
        out_path.write_text(result.stdout, encoding="utf-8")
        out_path.chmod(0o644)   # lisible par nginx
        logger.info(f"[gpg] Clé publique exportée → {out_path}")
    except Exception as exc:
        logger.warning(f"[gpg] export_public_key échoué : {exc}")


@router.get("/gpg")
def get_gpg_info(current_user: str = Depends(get_admin_user)):
    """Retourne les infos de la clé GPG du dépôt (fingerprint, UID, expiration)."""
    try:
        result = subprocess.run(
            _gpg_cmd(["--list-keys", "--with-colons", "--fingerprint"]),
            capture_output=True, text=True, timeout=10,
        )
        keys = []
        current_key: dict = {}
        for line in result.stdout.splitlines():
            parts = line.split(":")
            if parts[0] == "pub":
                if current_key:
                    keys.append(current_key)
                current_key = {
                    "type":        "pub",
                    "algo":        parts[3] if len(parts) > 3 else "",
                    "key_id":      parts[4] if len(parts) > 4 else "",
                    "created":     parts[5] if len(parts) > 5 else "",
                    "expires":     parts[6] if len(parts) > 6 else "",
                    "uids":        [],
                    "fingerprint": "",
                }
            elif parts[0] == "fpr" and current_key:
                current_key["fingerprint"] = parts[9] if len(parts) > 9 else ""
            elif parts[0] == "uid" and current_key:
                uid_str = parts[9] if len(parts) > 9 else ""
                if uid_str:
                    current_key["uids"].append(uid_str)
        if current_key:
            keys.append(current_key)

        export = subprocess.run(
            _gpg_cmd(["--armor", "--export"]),
            capture_output=True, text=True, timeout=10,
        )
        return {
            "keys": keys,
            "public_key_armored": export.stdout.strip() if export.returncode == 0 else None,
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="GPG timeout")
    except Exception as e:
        logger.exception("[gpg] Échec opération GPG : %s", e)
        raise HTTPException(status_code=500, detail="GPG operation failed — see server logs for details")


@router.post("/gpg/generate")
def generate_gpg_key(current_user: str = Depends(get_admin_user)):
    """Génère une nouvelle paire de clés GPG dans le trousseau partagé."""
    _ensure_gnupg_permissions()
    batch = (
        "%no-protection\n"
        "Key-Type: RSA\n"
        "Key-Length: 4096\n"
        "Subkey-Type: RSA\n"
        "Subkey-Length: 4096\n"
        "Name-Real: Repod APT Repository\n"
        "Name-Email: repod@localhost\n"
        "Expire-Date: 2y\n"
        "%commit\n"
    )
    try:
        env = {**os.environ, "GNUPGHOME": GNUPG_HOME}
        result = subprocess.run(
            _gpg_cmd(["--batch", "--gen-key"]),
            input=batch, capture_output=True, text=True, timeout=120, env=env,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Erreur GPG inconnue"
            raise HTTPException(status_code=500, detail=detail)

        # Exporter immédiatement la clé publique vers /repos/dists/depot.gpg
        export_public_key()

        # Ré-initialise les distributions pour que la nouvelle clé soit prise en
        # compte immédiatement — sans ça, conf/distributions (écrit une seule
        # fois, automatiquement, au démarrage du backend, avant qu'aucune clé
        # n'existe) resterait sans SignWith: et les Release APT continueraient
        # à être publiés non signés malgré l'existence d'une clé. RPM/APK ne
        # sont pas concernés par ce problème (ils re-signent à chaque
        # publication avec la clé courante) mais les ré-initialiser aussi ici
        # est sans risque (opération idempotente, déjà utilisée par le bouton
        # "Init dists"). Un échec de cette étape ne doit pas faire échouer la
        # génération de la clé elle-même — la clé existe déjà à ce stade.
        reinit_result = None
        try:
            from routers.distributions_router import init_distributions
            reinit_result = init_distributions(current_user)
        except Exception as exc:
            logger.warning(
                "[gpg] Clé générée mais ré-initialisation des distributions échouée : %s", exc
            )

        audit_log("GPG_GENERATE", current_user, "SUCCESS", detail="Nouvelle clé GPG générée")
        return {
            "status": "ok",
            "message": "Clé GPG générée avec succès. La clé publique a été exportée vers /repos/dists/depot.gpg.",
            "distributions_reinit": reinit_result,
        }
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Génération GPG timeout (>120s) — le système manque peut-être d'entropie")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("[gpg] Échec génération de clé : %s", e)
        raise HTTPException(status_code=500, detail="GPG key generation failed — see server logs for details")


@router.post("/gpg/export")
def export_gpg_key(current_user: str = Depends(get_admin_user)):
    """
    (Re)exporte manuellement la clé publique GPG vers /repos/dists/depot.gpg.
    Utile si le fichier a été supprimé ou si la clé a été regénérée manuellement.
    """
    try:
        export_public_key()
        dists_dir = Path(DISTS_DIR)
        out_path = dists_dir / "depot.gpg"
        if not out_path.exists():
            raise HTTPException(status_code=500, detail="Export réussi mais le fichier est introuvable.")
        return {
            "status": "ok",
            "path": str(out_path),
            "url_path": "/repos/dists/depot.gpg",
            "message": "Clé publique exportée avec succès.",
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("[gpg] Échec export de clé : %s", e)
        raise HTTPException(status_code=500, detail="GPG key export failed — see server logs for details")


# ─── Infos scheduler ──────────────────────────────────────────────────────────

@router.get("/next-sync")
def get_next_sync(current_user: str = Depends(get_admin_user)):
    """Retourne la date/heure de la prochaine sync sécurité planifiée."""
    if scheduler_state.scheduler is None:
        return {"next_run": None, "status": "scheduler_not_started"}

    try:
        job = scheduler_state.scheduler.get_job("security_sync_daily")
        if job is None:
            return {"next_run": None, "status": "job_not_found"}
        if job.next_run_time is None:
            return {"next_run": None, "status": "paused"}
        return {
            "next_run": job.next_run_time.isoformat(),
            "status": "scheduled",
        }
    except Exception as e:
        return {"next_run": None, "status": f"error: {e}"}


# ─── Rétention manuelle ───────────────────────────────────────────────────────

@router.post("/run-retention")
def run_retention_now(current_user: str = Depends(get_admin_user)):
    """Déclenche immédiatement la politique de rétention (audit logs + vieux paquets)."""
    from services.retention import run_retention
    try:
        result = run_retention()
        return {"status": "ok", "result": result}
    except Exception as e:
        logger.error(f"[retention] Erreur déclenchement manuel : {e}")
        raise HTTPException(status_code=500, detail="Retention job failed — see server logs for details")


# ─── Test email ───────────────────────────────────────────────────────────────

class TestEmailPayload(BaseModel):
    to_override: str | None = None

@router.post("/test-email")
def test_email(payload: TestEmailPayload = TestEmailPayload(), current_user: str = Depends(get_admin_user)):
    """Envoie un email de test pour vérifier la configuration SMTP."""
    from services.email_notifications import send_test_email
    result = send_test_email(to_override=payload.to_override)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("error", "Échec envoi"))
    return {"status": "ok", "message": "Email de test envoyé"}

