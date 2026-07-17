"""
services/setup.py — Wizard de première installation Repod.

Le wizard est disponible seulement si aucun compte admin local n'existe encore
dans la base de données (table `users`, PostgreSQL). Une fois le premier admin
créé (via le wizard ou via les variables d'environnement ADMIN_USERNAME /
ADMIN_PASSWORD_HASH), le wizard est désactivé (toute tentative de
re-configuration retourne 409).

Flux :
  1. GET  /api/v1/setup/status  → {"setup_done": bool, "needs_setup": bool}
  2. POST /api/v1/setup          → crée l'admin, configure app_url, retourne le JWT

Données persistées :
  - Premier compte admin dans la table `users` (via auth.users.create_user)
  - app_url dans settings.json si fourni

Sécurité :
  - Les deux endpoints sont SANS AUTHENTIFICATION (nécessaire pour le bootstrap).
  - Dès que setup_done=True, POST /setup renvoie 409 — impossible de ré-écraser
    les credentials admin via ce endpoint.
  - Le mot de passe est hashé via bcrypt avant stockage (auth.users.hash_password).
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import text
from db.engine import db_conn

logger = logging.getLogger("setup")

# Contraintes minimales sur les credentials initiaux
_MIN_USERNAME_LEN = 3
_MIN_PASSWORD_LEN = 8


class SetupError(Exception):
    """Erreur de validation pendant le wizard de setup."""


class SetupAlreadyDoneError(SetupError):
    """L'application est déjà configurée — le wizard est désactivé."""


# ── Détection de l'état de setup ─────────────────────────────────────────────

def is_setup_done() -> bool:
    """
    Retourne True si au moins un compte admin actif existe dans PostgreSQL.
    Retourne False si la DB est inaccessible ou la table absente.
    """
    try:
        with db_conn() as conn:
            count = conn.execute(text(
                "SELECT COUNT(*) FROM users WHERE role = 'admin' AND active = true"
            )).scalar()
        return (count or 0) > 0
    except Exception:
        return False


def get_setup_status() -> dict:
    """
    Retourne le statut complet du wizard.

    {
      "setup_done":   bool,
      "needs_setup":  bool,   # = not setup_done
      "checked_at":   str,    # ISO-8601 UTC
    }
    """
    done = is_setup_done()
    return {
        "setup_done":  done,
        "needs_setup": not done,
        "checked_at":  datetime.now(timezone.utc).isoformat(),
    }


# ── Exécution du wizard ───────────────────────────────────────────────────────

def run_setup(
    admin_username: str,
    admin_password: str,
    admin_email: str = "",
    admin_full_name: str = "",
    app_url: str = "",
) -> dict:
    """
    Effectue la configuration initiale.

    Paramètres
    ----------
    admin_username  : nom du premier compte administrateur (≥ 3 caractères)
    admin_password  : mot de passe en clair (≥ 8 caractères, hashé avant stockage)
    admin_email     : adresse e-mail (optionnel)
    admin_full_name : nom complet affiché (optionnel)
    app_url         : URL publique de l'application (ex. https://repod.example.com)

    Retourne
    --------
    {
      "admin_username": str,
      "access_token":   str,   # JWT valide immédiatement
      "token_type":     "bearer",
      "message":        str,
    }

    Lève
    ----
    SetupAlreadyDoneError  : si un admin existe déjà
    SetupError             : si les données fournies sont invalides
    """
    # ── Garde : setup déjà effectué ──────────────────────────────────────────
    if is_setup_done():
        raise SetupAlreadyDoneError(
            "L'application est déjà configurée. "
            "Connectez-vous avec vos identifiants admin existants."
        )

    # ── Validation des credentials ────────────────────────────────────────────
    admin_username = (admin_username or "").strip()
    if len(admin_username) < _MIN_USERNAME_LEN:
        raise SetupError(
            f"Nom d'utilisateur trop court (minimum {_MIN_USERNAME_LEN} caractères)."
        )

    if not admin_password or len(admin_password) < _MIN_PASSWORD_LEN:
        raise SetupError(
            f"Mot de passe trop court (minimum {_MIN_PASSWORD_LEN} caractères)."
        )

    # ── Création du premier admin ─────────────────────────────────────────────
    from auth.users import create_user
    try:
        create_user(
            username=admin_username,
            password=admin_password,
            role="admin",
            full_name=admin_full_name or "",
            email=admin_email or "",
        )
    except Exception as exc:
        raise SetupError(f"Impossible de créer le compte admin : {exc}") from exc

    logger.info(f"[setup] Premier compte admin créé : {admin_username!r}")

    # ── Configuration app_url ─────────────────────────────────────────────────
    if app_url:
        try:
            from services.settings import update_settings
            update_settings({"app_url": app_url.rstrip("/")})
            logger.info(f"[setup] app_url configurée : {app_url}")
        except Exception as exc:
            logger.warning(f"[setup] Impossible de mettre à jour app_url : {exc}")

    # ── Émission du JWT ───────────────────────────────────────────────────────
    from auth.jwt import create_access_token
    token = create_access_token({"sub": admin_username, "role": "admin"})

    logger.info("[setup] Configuration initiale terminée — wizard désactivé.")

    return {
        "admin_username": admin_username,
        "access_token":   token,
        "token_type":     "bearer",
        "message":        "Configuration initiale réussie. Bienvenue dans Repod !",
    }
