"""
Routes d'authentification et de gestion des utilisateurs.

Publique :
  POST /auth/token           → connexion, retourne JWT

Authentifié (tout rôle) :
  GET  /auth/me              → info du compte courant
  POST /auth/logout          → révoque le JWT courant (jti → revoked_tokens)
  POST /auth/change-password → changer son propre mot de passe

Admin uniquement :
  GET    /auth/users                        → liste tous les utilisateurs
  POST   /auth/users                        → créer un utilisateur
  PATCH  /auth/users/{username}             → modifier rôle/infos
  DELETE /auth/users/{username}             → supprimer un utilisateur
  POST   /auth/users/{username}/reset-password → réinitialiser le mdp
"""
import re
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, Response, status, Depends
from pydantic import BaseModel

from .models import (
    Token, UserLogin, UserCreate, UserUpdate, PasswordChange, PasswordReset,
    MfaSetupResponse, MfaConfirmRequest, MfaAuthenticateRequest, MfaDisableRequest,
)
from .users import (
    get_user, get_user_any, list_users, create_user,
    update_user, delete_user, change_password, verify_password, update_last_login,
    VALID_ROLES, ROLE_DESCRIPTIONS,
    get_mfa_info, set_mfa_pending_secret, enable_mfa, disable_mfa,
    get_lockout_status, record_failed_login, reset_failed_logins,
    MAX_FAILED_ATTEMPTS, LOCKOUT_MINUTES,
)
from .jwt import create_access_token, create_mfa_token, get_token_claims
from .dependencies import get_current_user, get_current_user_full, get_admin_user, oauth2_scheme
from .token_revocation import revoke_jti
from .reset_tokens import create_reset_token, consume_reset_token
from .mfa import generate_totp_secret, get_totp_uri, generate_qr_code_base64, verify_totp
from limiter import limiter, auth_limit
from services.audit import log as audit_log

router = APIRouter(prefix="/auth", tags=["Auth"])

# SEC-07 : Défense contre les attaques par timing (username enumeration).
# Si le compte n'existe pas, on exécute quand même un verify_password() sur ce
# hash factice pour normaliser le temps de réponse avec le cas "mauvais mdp"
# (bcrypt ~150ms). Le résultat est toujours False — c'est volontaire.
# Hash bcrypt valide calculé une seule fois à l'avance (rounds=12, ~150ms).
# Permet d'appeler verify_password() pour les utilisateurs inconnus sans
# court-circuiter le calcul bcrypt — la protection timing reste effective.
_TIMING_DUMMY_HASH = "$2b$12$30/iok1yej398SkjMohpnOqk49OXkQYLwUihng5bvB6wz7dRPL96a"


# ─── Validation de la politique mot de passe ─────────────────────────────────

def _validate_password(password: str, field: str = "Le mot de passe") -> None:
    """
    Vérifie que le mot de passe respecte la politique de sécurité :
    - 8 caractères minimum, 128 maximum
    - Au moins une majuscule
    - Au moins un chiffre ou un caractère spécial

    La limite de 128 caractères protège contre le bug de troncature bcrypt
    (bcrypt tronque à 72 octets — deux mots de passe partageant les 72 premiers
    caractères seraient identiques du point de vue de l'authentification).

    Lève HTTPException 400 si la politique n'est pas respectée.
    """
    if len(password) < 8:
        raise HTTPException(
            status_code=400,
            detail=f"{field} doit contenir au moins 8 caractères.",
        )
    if len(password) > 128:
        raise HTTPException(
            status_code=400,
            detail=f"{field} ne peut pas dépasser 128 caractères.",
        )
    if not re.search(r"[A-Z]", password):
        raise HTTPException(
            status_code=400,
            detail=f"{field} doit contenir au moins une lettre majuscule.",
        )
    if not re.search(r"[0-9!@#$%^&*()_+\-=\[\]{{}}|;':\",./<>?]", password):
        raise HTTPException(
            status_code=400,
            detail=f"{field} doit contenir au moins un chiffre ou un caractère spécial.",
        )


# ─── Connexion ────────────────────────────────────────────────────────────────

@router.post("/token", response_model=Token)
@limiter.limit(auth_limit)
def login(request: Request, response: Response, credentials: UserLogin):
    """
    Authentifie un utilisateur.
    """
    # ── 1. Vérification du verrouillage par username ──────────────────────────
    client_ip = request.client.host if request.client else "unknown"

    lockout = get_lockout_status(credentials.username)
    if lockout["locked"]:
        remaining_min = max(1, lockout["remaining_seconds"] // 60)
        audit_log("LOGIN", credentials.username, "FAILURE",
                  detail=f"Compte verrouillé ({lockout['remaining_seconds']}s restantes)",
                  extra={"ip": client_ip})
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Compte temporairement verrouillé suite à trop de tentatives échouées. "
                f"Réessayez dans {remaining_min} minute(s)."
            ),
        )

    # ── 2. Auth locale ────────────────────────────────────────────────────────
    local_user = get_user(credentials.username)

    # SEC-07 : normalisation du temps de réponse.
    # Si le compte est introuvable, on effectue quand même un verify_password()
    # sur un hash factice pour égaliser le temps de réponse avec le cas
    # "mauvais mot de passe" (bcrypt ≈ 150 ms). Sans ceci, un attaquant peut
    # distinguer "utilisateur inconnu" de "mauvais mdp" par le temps de réponse.
    if not local_user:
        verify_password(credentials.password, _TIMING_DUMMY_HASH)  # résultat ignoré
        audit_log("LOGIN", credentials.username, "FAILURE",
                  detail="Utilisateur inconnu", extra={"ip": client_ip})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Identifiants incorrects")

    # Compte local
    if not verify_password(credentials.password, local_user["hashed_password"]):
        lockout_status = record_failed_login(credentials.username)
        detail_extra = ""
        if lockout_status["locked"]:
            detail_extra = (
                f" Compte verrouillé pour {LOCKOUT_MINUTES} min "
                f"(trop de tentatives)."
            )
        elif lockout_status["attempts_left"] <= 3:
            detail_extra = (
                f" {lockout_status['attempts_left']} tentative(s) restante(s) "
                f"avant verrouillage."
            )
        audit_log("LOGIN", credentials.username, "FAILURE",
                  detail="Mot de passe incorrect", extra={"ip": client_ip})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Identifiants incorrects.{detail_extra}",
        )
    if not local_user.get("active", True):
        audit_log("LOGIN", credentials.username, "FAILURE",
                  detail="Compte désactivé", extra={"ip": client_ip})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Compte désactivé")
    # Connexion réussie : réinitialiser le compteur d'échecs
    reset_failed_logins(credentials.username)
    user = local_user

    # ── Vérification MFA ──────────────────────────────────────────────────────
    mfa = get_mfa_info(user["username"])
    if mfa["mfa_enabled"]:
        # Step 1 du login MFA : retourner un token temporaire (5 min)
        mfa_token = create_mfa_token(user["username"], user["role"])
        audit_log("LOGIN", user["username"], "SUCCESS",
                  extra={"ip": client_ip, "role": user["role"], "mfa": "step1"})
        return {
            "mfa_required": True,
            "mfa_token":    mfa_token,
            "token_type":   "bearer",
        }

    update_last_login(user["username"])
    audit_log("LOGIN", user["username"], "SUCCESS",
              extra={"ip": client_ip, "role": user["role"]})
    token = create_access_token({
        "sub":       user["username"],
        "role":      user["role"],
        "full_name": user.get("full_name", ""),
    })
    return {"access_token": token, "token_type": "bearer"}


# ─── Déconnexion ──────────────────────────────────────────────────────────────

@router.post("/logout")
def logout(
    token: str = Depends(oauth2_scheme),
    current_user: dict = Depends(get_current_user_full),
):
    """
    Révoque immédiatement le JWT courant (insertion du `jti` dans
    `revoked_tokens`).

    Idempotent : si le token est déjà révoqué ou ne porte pas de `jti`,
    la requête réussit quand même.
    """
    claims = get_token_claims(token)
    if claims and claims.get("jti"):
        exp_ts = claims.get("exp")
        expires_at = (
            datetime.fromtimestamp(exp_ts, tz=timezone.utc)
            if exp_ts else datetime.now(timezone.utc)
        )
        revoke_jti(claims["jti"], current_user["username"], expires_at)
        audit_log("LOGOUT", current_user["username"], "SUCCESS")
    return {"status": "logged_out"}


# ─── Rafraîchissement silencieux du token ─────────────────────────────────────

@router.post("/refresh")
def refresh_token(
    current_user: dict = Depends(get_current_user_full),
):
    """
    Émet un nouveau JWT avec une expiration fraîche.
    Appelé automatiquement par le frontend pour prolonger la session
    tant que l'utilisateur est actif.
    """
    token = create_access_token({
        "sub":       current_user["username"],
        "role":      current_user["role"],
        "full_name": current_user.get("full_name", ""),
    })
    return {"access_token": token, "token_type": "bearer"}


# ─── Compte courant ───────────────────────────────────────────────────────────

@router.get("/me")
def me(current_user: dict = Depends(get_current_user_full)):
    """Retourne les informations du compte connecté."""
    user = get_user_any(current_user["username"])
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    mfa_info = get_mfa_info(user["username"])
    return {
        "username": user["username"],
        "role": user["role"],
        "full_name": user.get("full_name", ""),
        "email": user.get("email", ""),
        "active": bool(user["active"]),
        "last_login": user.get("last_login"),
        "mfa_enabled": mfa_info.get("mfa_enabled", False),
    }


@router.post("/change-password")
def change_own_password(
    payload: PasswordChange,
    current_user: dict = Depends(get_current_user_full),
):
    """Permet à l'utilisateur connecté de changer son propre mot de passe."""
    username = current_user["username"]
    user = get_user_any(username)
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")

    if not verify_password(payload.current_password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect")

    _validate_password(payload.new_password, "Le nouveau mot de passe")
    change_password(username, payload.new_password)
    audit_log("PASSWORD_CHANGE", username, "SUCCESS", detail="Changement de mot de passe par l'utilisateur")
    return {"status": "ok", "message": "Mot de passe modifié avec succès"}


# ─── Gestion des utilisateurs (admin) ────────────────────────────────────────

@router.get("/roles")
def list_roles():
    """Retourne la liste des rôles disponibles avec leur description (public)."""
    return {"roles": ROLE_DESCRIPTIONS}


@router.get("/users")
def list_all_users(admin: str = Depends(get_admin_user)):
    """Liste tous les utilisateurs (admin uniquement)."""
    users = list_users()
    # Ne jamais exposer les hashes
    return {"users": [
        {k: v for k, v in u.items() if k != "hashed_password"}
        for u in users
    ]}


@router.post("/users", status_code=201)
def create_new_user(payload: UserCreate, admin: str = Depends(get_admin_user)):
    """Crée un nouvel utilisateur (admin uniquement)."""
    if payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Rôle invalide. Valeurs acceptées : {', '.join(VALID_ROLES)}")

    _validate_password(payload.password)

    existing = get_user_any(payload.username)
    if existing:
        raise HTTPException(status_code=409, detail=f"L'utilisateur '{payload.username}' existe déjà")

    user = create_user(
        username=payload.username,
        password=payload.password,
        role=payload.role,
        full_name=payload.full_name,
        email=payload.email,
    )
    audit_log("USER_CREATE", admin, "SUCCESS",
              detail=f"Utilisateur créé : {payload.username} (rôle={payload.role})")
    return {k: v for k, v in user.items() if k != "hashed_password"}


@router.patch("/users/{username}")
def update_existing_user(
    username: str,
    payload: UserUpdate,
    admin: str = Depends(get_admin_user),
):
    """Met à jour le rôle et/ou les infos d'un utilisateur (admin uniquement)."""
    # L'admin ne peut pas changer son propre rôle (sécurité)
    if username == admin and payload.role is not None and payload.role != "admin":
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas changer votre propre rôle")

    if payload.role is not None and payload.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Rôle invalide. Valeurs acceptées : {', '.join(VALID_ROLES)}")

    before = get_user_any(username)
    user = update_user(
        username=username,
        role=payload.role,
        full_name=payload.full_name,
        email=payload.email,
        active=payload.active,
    )
    if not user:
        raise HTTPException(status_code=404, detail=f"Utilisateur '{username}' introuvable")

    # Tracer les changements significatifs dans l'audit trail
    changes = []
    if payload.role is not None and before and before.get("role") != payload.role:
        changes.append(f"rôle : {before.get('role')} → {payload.role}")
    if payload.active is not None and before and bool(before.get("active")) != payload.active:
        changes.append(f"actif : {bool(before.get('active'))} → {payload.active}")
    if changes:
        audit_log("USER_UPDATE", admin, "SUCCESS",
                  detail=f"{username} — {', '.join(changes)}")

    return {k: v for k, v in user.items() if k != "hashed_password"}


@router.delete("/users/{username}")
def delete_existing_user(username: str, admin: str = Depends(get_admin_user)):
    """Supprime un utilisateur (admin uniquement, ne peut pas se supprimer soi-même)."""
    if username == admin:
        raise HTTPException(status_code=400, detail="Vous ne pouvez pas supprimer votre propre compte")

    ok = delete_user(username)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Utilisateur '{username}' introuvable")

    audit_log("USER_DELETE", admin, "SUCCESS", detail=f"Utilisateur supprimé : {username}")
    return {"status": "deleted", "username": username}


@router.post("/users/{username}/reset-password")
def reset_user_password(
    username: str,
    payload: PasswordReset,
    admin: str = Depends(get_admin_user),
):
    """Réinitialise le mot de passe d'un utilisateur (admin uniquement)."""
    _validate_password(payload.new_password)

    user = get_user_any(username)
    if not user:
        raise HTTPException(status_code=404, detail=f"Utilisateur '{username}' introuvable")

    change_password(username, payload.new_password)
    audit_log("PASSWORD_RESET", admin, "SUCCESS",
              detail=f"Réinitialisation mot de passe de '{username}' par l'admin")
    return {"status": "ok", "message": f"Mot de passe de '{username}' réinitialisé"}


# ─── Réinitialisation de mot de passe (publique) ─────────────────────────────

import logging as _logging
_logger = _logging.getLogger("auth.reset")

class ForgotPasswordPayload(BaseModel):
    username: str

class ResetPasswordPayload(BaseModel):
    token: str
    new_password: str


@router.post("/forgot-password")
@limiter.limit(auth_limit)
def forgot_password(request: Request, response: Response, payload: ForgotPasswordPayload):
    """
    Envoie un email de réinitialisation si l'utilisateur existe et a un email.
    Toujours 200 pour ne pas divulguer l'existence du compte.
    """
    user = get_user_any(payload.username)
    if not user or not user.get("email"):
        # Réponse générique — on ne révèle pas si l'utilisateur existe
        return {"status": "ok", "message": "Si ce compte existe et a un email, un lien a été envoyé."}

    token = create_reset_token(payload.username)

    try:
        from services.email_notifications import _send_email
        from services.settings import get_settings
        settings = get_settings()
        base_url = settings.get("app_url", "http://localhost:3003")

        reset_url = f"{base_url}/reset-password?token={token}"
        subject = "Réinitialisation de mot de passe — APT Repo Manager"
        body_html = f"""
<p>Bonjour <strong>{user.get('full_name') or payload.username}</strong>,</p>
<p>Une demande de réinitialisation de mot de passe a été effectuée pour votre compte.</p>
<p>
  <a href="{reset_url}" style="
    background:#2563eb;color:#fff;padding:10px 20px;
    border-radius:6px;text-decoration:none;font-weight:600
  ">Réinitialiser mon mot de passe</a>
</p>
<p>Ce lien est valable <strong>30 minutes</strong>. Si vous n'avez pas fait cette demande, ignorez cet email.</p>
<hr/>
<p style="color:#888;font-size:12px">APT Repo Manager</p>
"""
        body_text = (
            f"Réinitialisez votre mot de passe via ce lien (valable 30 min) :\n{reset_url}\n"
            "Si vous n'avez pas fait cette demande, ignorez cet email."
        )
        _send_email(subject, body_html, body_text, to_override=user["email"])
        _logger.info(f"[reset] Email de reset envoyé à {user['email']} pour {payload.username}")
    except Exception as e:
        _logger.error(f"[reset] Erreur envoi email reset : {e}")
        # On continue — le token est créé, l'admin peut le lire en CLI si besoin

    return {"status": "ok", "message": "Si ce compte existe et a un email, un lien a été envoyé."}


@router.post("/reset-password")
@limiter.limit(auth_limit)
def reset_password_with_token(request: Request, response: Response, payload: ResetPasswordPayload):
    """Réinitialise le mot de passe via un token one-time envoyé par email."""
    _validate_password(payload.new_password)

    username = consume_reset_token(payload.token)
    if not username:
        raise HTTPException(status_code=400, detail="Lien invalide ou expiré. Faites une nouvelle demande.")

    change_password(username, payload.new_password)
    audit_log("PASSWORD_RESET", username, "SUCCESS", detail="Reset via token email")
    _logger.info(f"[reset] Mot de passe réinitialisé pour {username}")
    return {"status": "ok", "message": "Mot de passe modifié. Vous pouvez vous connecter."}


# ─── MFA TOTP ─────────────────────────────────────────────────────────────────

@router.post("/mfa/setup", response_model=MfaSetupResponse)
def mfa_setup(current_user: dict = Depends(get_current_user_full)):
    """
    Génère un secret TOTP et un QR code pour l'activation du MFA.
    Le secret est stocké temporairement (pending) jusqu'à confirmation.
    """
    username = current_user["username"]
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, username)
    qr = generate_qr_code_base64(uri)
    set_mfa_pending_secret(username, secret)
    return {"secret": secret, "uri": uri, "qr_code_base64": qr}


@router.post("/mfa/confirm")
def mfa_confirm(
    body: MfaConfirmRequest,
    current_user: dict = Depends(get_current_user_full),
):
    """
    Confirme l'activation du MFA en vérifiant le premier code TOTP.
    Active le MFA si le code est valide.
    """
    username = current_user["username"]
    mfa = get_mfa_info(username)
    pending = mfa.get("totp_pending_secret")
    if not pending:
        raise HTTPException(status_code=400, detail="Aucun secret MFA en attente. Lancez d'abord /mfa/setup.")
    if not verify_totp(pending, body.totp_code):
        raise HTTPException(status_code=400, detail="Code TOTP invalide.")
    if not enable_mfa(username):
        raise HTTPException(status_code=500, detail="Impossible d'activer le MFA.")
    audit_log("MFA_ENABLE", username, "SUCCESS")
    return {"message": "MFA activé avec succès."}


@router.post("/mfa/authenticate")
def mfa_authenticate(body: MfaAuthenticateRequest):
    """
    Step 2 du login MFA : valide le code TOTP contre le mfa_token temporaire.
    Retourne un access_token complet si le code est correct.
    """
    import jwt as _jwt
    from jwt.exceptions import PyJWTError
    from .config import SECRET_KEY, ALGORITHM

    try:
        payload = _jwt.decode(body.mfa_token, SECRET_KEY, algorithms=[ALGORITHM])
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Token MFA invalide ou expiré.")

    if payload.get("scope") != "mfa_required":
        raise HTTPException(status_code=401, detail="Token MFA invalide.")

    username = payload.get("sub")
    role = payload.get("role", "reader")
    if not username:
        raise HTTPException(status_code=401, detail="Token MFA invalide.")

    mfa = get_mfa_info(username)
    if not mfa["mfa_enabled"] or not mfa["totp_secret"]:
        raise HTTPException(status_code=400, detail="MFA non activé pour cet utilisateur.")

    if not verify_totp(mfa["totp_secret"], body.totp_code):
        audit_log("LOGIN", username, "FAILURE", detail="Code TOTP MFA invalide")
        raise HTTPException(status_code=401, detail="Code TOTP invalide.")

    user = get_user_any(username)
    update_last_login(username)
    audit_log("LOGIN", username, "SUCCESS", extra={"role": role, "mfa": "step2"})
    token = create_access_token({
        "sub":       username,
        "role":      role,
        "full_name": user.get("full_name", "") if user else "",
    })
    return {"access_token": token, "token_type": "bearer"}


@router.post("/mfa/disable")
def mfa_disable(
    body: MfaDisableRequest,
    current_user: dict = Depends(get_current_user_full),
):
    """
    Désactive le MFA après vérification du mot de passe.
    """
    username = current_user["username"]
    user = get_user_any(username)
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable.")
    if not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Mot de passe incorrect.")
    disable_mfa(username)
    audit_log("MFA_DISABLE", username, "SUCCESS")
    return {"message": "MFA désactivé."}
