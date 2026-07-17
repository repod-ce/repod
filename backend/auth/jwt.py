import secrets
from datetime import datetime, timedelta, timezone
import jwt
from jwt.exceptions import PyJWTError
from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

# Durée de validité du token MFA temporaire (step 1 du login à 2 facteurs)
MFA_TOKEN_EXPIRE_MINUTES = 5


def create_access_token(data: dict) -> str:
    """
    Crée un JWT avec sub, role, expiration et un `jti` (JWT ID) unique.

    Le `jti` permet la révocation immédiate du token via
    `auth.token_revocation.revoke_jti()` (POST /auth/logout) — sans `jti`,
    un JWT volé resterait valide jusqu'à expiration même après déconnexion.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "jti": secrets.token_hex(16)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_token_claims(token: str) -> dict | None:
    """
    Décode un JWT et retourne le payload brut (sub, role, exp, jti, ...)
    SANS vérifier la révocation — utilisé par POST /auth/logout pour
    extraire `jti`/`exp` même si le token est déjà révoqué (idempotence).

    Retourne None si la signature est invalide ou le token expiré.
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except PyJWTError:
        return None


def create_mfa_token(username: str, role: str) -> str:
    """
    Crée un JWT temporaire utilisé lors du step 1 du login MFA.
    Ce token a une durée de vie courte (5 min) et contient scope='mfa_required'
    pour être distingué d'un vrai access_token.
    Il ne doit être accepté que par POST /auth/mfa/authenticate.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=MFA_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub":   username,
        "role":  role,
        "scope": "mfa_required",
        "exp":   expire,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    """
    Décode un JWT et retourne {username, role, jti} ou None si invalide.

    Rejette explicitement les tokens MFA intermédiaires (scope='mfa_required') :
    ces tokens sont à usage unique pour le step 2 du login MFA, ils ne doivent
    jamais être acceptés comme tokens d'accès complet.

    Rejette aussi les tokens dont le `jti` figure dans `revoked_tokens`
    (POST /auth/logout) — voir auth.token_revocation.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
        # SEC-1 : bloquer les tokens MFA intermédiaires (scope=mfa_required)
        if payload.get("scope") == "mfa_required":
            return None

        jti = payload.get("jti")
        if jti:
            from .token_revocation import is_revoked
            if is_revoked(jti):
                return None

        return {
            "username": username,
            "role": payload.get("role", "reader"),
            "full_name": payload.get("full_name", ""),
            "jti": jti,
        }
    except PyJWTError:
        return None
