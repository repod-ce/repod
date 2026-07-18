"""
Tokens de réinitialisation de mot de passe (one-time, 30 min).
Stockage dans /repos/auth/reset_tokens.json — tokens stockés HASHÉS (HMAC-SHA256).
Nettoyage automatique à chaque accès.
"""

import hashlib
import hmac as _hmac_mod
import json
import os
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import Lock

STORE_PATH = Path(os.getenv("AUTH_DIR", "/repos/auth")) / "reset_tokens.json"
TOKEN_TTL_MINUTES = 30
_lock = Lock()


def _hash(token: str) -> str:
    """
    Hash HMAC-SHA256 du token keyed sur JWT_SECRET_KEY — résistant aux
    rainbow tables même si le fichier reset_tokens.json est exfiltré.
    """
    key = os.getenv("JWT_SECRET_KEY", "change-me-in-production").encode("utf-8")
    return _hmac_mod.new(key, token.encode("utf-8"), digestmod=hashlib.sha256).hexdigest()


def _load() -> dict:
    try:
        with open(STORE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data: dict):
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(STORE_PATH, "w") as f:
        json.dump(data, f)


def _purge_expired(data: dict) -> dict:
    now = datetime.now(timezone.utc)
    return {
        k: v for k, v in data.items()
        if datetime.fromisoformat(v["expires_at"]) > now
    }


def create_reset_token(username: str) -> str:
    """
    Génère un token de reset valide 30 min.
    Stocke son hash SHA-256 (jamais le token en clair).
    Retourne le token en clair (envoyé par email, usage unique).
    """
    token = secrets.token_urlsafe(32)
    token_hash = _hash(token)
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MINUTES)).isoformat()
    with _lock:
        data = _purge_expired(_load())
        # Un seul token actif par utilisateur (révoque l'ancien)
        data = {k: v for k, v in data.items() if v["username"] != username}
        data[token_hash] = {"username": username, "expires_at": expires_at}
        _save(data)
    return token  # retourné UNE SEULE FOIS, jamais persisté en clair


def consume_reset_token(token: str) -> str | None:
    """
    Valide et consomme un token (usage unique).
    Recherche par hash — retourne le username associé ou None si invalide/expiré.
    """
    token_hash = _hash(token)
    with _lock:
        data = _purge_expired(_load())
        entry = data.pop(token_hash, None)
        _save(data)
    if not entry:
        return None
    return entry["username"]
