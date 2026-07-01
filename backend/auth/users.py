# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2024-present repod contributors
# See LICENSE for terms. Commercial use: LICENSE-COMMERCIAL.md
"""
Gestion des utilisateurs — PostgreSQL via SQLAlchemy Core.
"""
import os
import secrets
import bcrypt
from datetime import datetime, timezone, timedelta

from sqlalchemy import text

from db.engine import db_conn

MAX_FAILED_ATTEMPTS: int = int(os.getenv("LOGIN_MAX_ATTEMPTS", "5"))
LOCKOUT_MINUTES:     int = int(os.getenv("LOGIN_LOCKOUT_MINUTES", "15"))

_BUILTIN_ROLES = {"admin", "maintainer", "uploader", "auditor", "reader"}


def _get_valid_roles() -> set[str]:
    """Retourne les rôles valides (built-in + custom). Utilisé pour valider les assignations."""
    try:
        with db_conn() as conn:
            rows = conn.execute(text("SELECT name FROM custom_roles")).fetchall()
            return {r[0] for r in rows} | _BUILTIN_ROLES
    except Exception:
        return _BUILTIN_ROLES


# Alias statique pour rétrocompatibilité des imports existants
VALID_ROLES = _BUILTIN_ROLES

ROLE_DESCRIPTIONS = {
    "admin": {
        "label": "Administrateur",
        "description": "Accès total : gestion des utilisateurs, paramètres système, toutes opérations.",
        "color": "red",
    },
    "maintainer": {
        "label": "Mainteneur",
        "description": "Cycle de vie des paquets : upload, import, promotion entre distributions, suppression, synchronisation et lecture des logs d'audit.",
        "color": "purple",
    },
    "uploader": {
        "label": "Packager / CI-CD",
        "description": "Dépôt de paquets uniquement : upload et import. Ne peut pas supprimer, promouvoir ou accéder aux logs d'audit.",
        "color": "blue",
    },
    "auditor": {
        "label": "Auditeur",
        "description": "Lecture de l'ensemble du dépôt + accès aux logs d'audit. Aucune modification autorisée. Idéal pour les équipes conformité / RSSI.",
        "color": "yellow",
    },
    "reader": {
        "label": "Lecteur",
        "description": "Lecture seule : recherche et liste des paquets. Compte de service pour les machines clientes APT.",
        "color": "gray",
    },
}


def init_db() -> None:
    """Insère l'admin depuis l'environnement si la table users est vide.

    Si ADMIN_PASSWORD_HASH est absent, vide, ou n'a pas la forme d'un hash
    bcrypt valide, aucun compte n'est créé : le wizard de première
    installation (/api/v1/setup) reste disponible. Insérer un compte admin
    avec un hash invalide bloquerait le wizard (un admin "actif" existerait
    déjà) tout en rendant la connexion impossible.
    """
    with db_conn() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM users")).scalar()
        if count == 0:
            admin_username = os.getenv("ADMIN_USERNAME", "admin")
            admin_hash = os.getenv("ADMIN_PASSWORD_HASH", "")
            admin_hash = admin_hash.replace("$$", "$")
            if not admin_hash.startswith(("$2a$", "$2b$", "$2y$")):
                return
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                text(
                    "INSERT INTO users (username, hashed_password, role, created_at) "
                    "VALUES (:u, :h, 'admin', :ts)"
                ),
                {"u": admin_username, "h": admin_hash, "ts": now},
            )


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def get_user(username: str) -> dict | None:
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT * FROM users WHERE username = :u AND active = true"),
            {"u": username},
        ).mappings().fetchone()
    return dict(row) if row else None


def get_user_any(username: str) -> dict | None:
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT * FROM users WHERE username = :u"),
            {"u": username},
        ).mappings().fetchone()
    return dict(row) if row else None


def list_users() -> list[dict]:
    with db_conn() as conn:
        rows = conn.execute(
            text(
                "SELECT id, username, role, full_name, email, active, created_at, "
                "last_login, auth_source FROM users ORDER BY role DESC, username ASC"
            )
        ).mappings().fetchall()
    return [dict(r) for r in rows]


def create_user(username: str, password: str, role: str = "reader",
                full_name: str = "", email: str = "",
                auth_source: str = "local") -> dict:
    if role not in _get_valid_roles():
        raise ValueError(f"Rôle invalide : {role}")
    hashed = hash_password(password)
    now = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        conn.execute(
            text(
                "INSERT INTO users "
                "(username, hashed_password, role, full_name, email, created_at, auth_source) "
                "VALUES (:u, :h, :r, :fn, :em, :ts, :src)"
            ),
            {"u": username, "h": hashed, "r": role,
             "fn": full_name, "em": email, "ts": now, "src": auth_source},
        )
    return get_user_any(username)


def update_user(username: str, role: str | None = None, full_name: str | None = None,
                email: str | None = None, active: bool | None = None,
                auth_source: str | None = None) -> dict | None:
    user = get_user_any(username)
    if not user:
        return None
    if role is not None and role not in _get_valid_roles():
        raise ValueError(f"Rôle invalide : {role}")
    with db_conn() as conn:
        if role is not None:
            conn.execute(text("UPDATE users SET role = :v WHERE username = :u"), {"v": role, "u": username})
        if full_name is not None:
            conn.execute(text("UPDATE users SET full_name = :v WHERE username = :u"), {"v": full_name, "u": username})
        if email is not None:
            conn.execute(text("UPDATE users SET email = :v WHERE username = :u"), {"v": email, "u": username})
        if active is not None:
            conn.execute(text("UPDATE users SET active = :v WHERE username = :u"), {"v": active, "u": username})
        if auth_source is not None:
            conn.execute(text("UPDATE users SET auth_source = :v WHERE username = :u"), {"v": auth_source, "u": username})
    return get_user_any(username)


def delete_user(username: str) -> bool:
    with db_conn() as conn:
        result = conn.execute(
            text("DELETE FROM users WHERE username = :u"), {"u": username}
        )
    return result.rowcount > 0


def change_password(username: str, new_password: str) -> bool:
    hashed = hash_password(new_password)
    with db_conn() as conn:
        result = conn.execute(
            text("UPDATE users SET hashed_password = :h WHERE username = :u"),
            {"h": hashed, "u": username},
        )
    return result.rowcount > 0


def update_last_login(username: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        conn.execute(
            text("UPDATE users SET last_login = :ts WHERE username = :u"),
            {"ts": now, "u": username},
        )


# ── Brute-force protection ─────────────────────────────────────────────────────

def get_lockout_status(username: str) -> dict:
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT failed_login_count, locked_until FROM users WHERE username = :u"),
            {"u": username},
        ).mappings().fetchone()

    if not row:
        return {"locked": False, "locked_until": None, "remaining_seconds": 0,
                "failed_count": 0, "attempts_left": MAX_FAILED_ATTEMPTS}

    failed_count = row["failed_login_count"] or 0
    locked_until_str = row["locked_until"]
    now = datetime.now(timezone.utc)

    if locked_until_str:
        try:
            locked_until = datetime.fromisoformat(locked_until_str)
            if locked_until.tzinfo is None:
                locked_until = locked_until.replace(tzinfo=timezone.utc)
            if now < locked_until:
                remaining = int((locked_until - now).total_seconds())
                return {
                    "locked": True,
                    "locked_until": locked_until_str,
                    "remaining_seconds": remaining,
                    "failed_count": failed_count,
                    "attempts_left": 0,
                }
        except ValueError:
            pass

    return {
        "locked": False,
        "locked_until": None,
        "remaining_seconds": 0,
        "failed_count": failed_count,
        "attempts_left": max(0, MAX_FAILED_ATTEMPTS - failed_count),
    }


def record_failed_login(username: str) -> dict:
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT failed_login_count FROM users WHERE username = :u"),
            {"u": username},
        ).mappings().fetchone()
        if not row:
            return {"locked": False, "failed_count": 0, "attempts_left": MAX_FAILED_ATTEMPTS}

        new_count = (row["failed_login_count"] or 0) + 1
        locked_until_str = None
        if new_count >= MAX_FAILED_ATTEMPTS:
            locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
            locked_until_str = locked_until.isoformat()

        conn.execute(
            text("UPDATE users SET failed_login_count = :c, locked_until = :lu WHERE username = :u"),
            {"c": new_count, "lu": locked_until_str, "u": username},
        )

    return get_lockout_status(username)


def reset_failed_logins(username: str) -> None:
    with db_conn() as conn:
        conn.execute(
            text("UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE username = :u"),
            {"u": username},
        )


# ── MFA TOTP ──────────────────────────────────────────────────────────────────

def get_mfa_info(username: str) -> dict:
    from auth.totp_crypto import decrypt_totp_secret
    with db_conn() as conn:
        row = conn.execute(
            text(
                "SELECT mfa_enabled, totp_secret, totp_pending_secret "
                "FROM users WHERE username = :u"
            ),
            {"u": username},
        ).mappings().fetchone()
    if not row:
        return {"mfa_enabled": False, "totp_secret": None, "totp_pending_secret": None}
    return {
        "mfa_enabled":         bool(row["mfa_enabled"]),
        "totp_secret":         decrypt_totp_secret(row["totp_secret"]) if row["totp_secret"] else None,
        "totp_pending_secret": decrypt_totp_secret(row["totp_pending_secret"]) if row["totp_pending_secret"] else None,
    }


def set_mfa_pending_secret(username: str, secret: str) -> bool:
    from auth.totp_crypto import encrypt_totp_secret
    encrypted = encrypt_totp_secret(secret) if secret else secret
    with db_conn() as conn:
        result = conn.execute(
            text("UPDATE users SET totp_pending_secret = :s WHERE username = :u"),
            {"s": encrypted, "u": username},
        )
    return result.rowcount > 0


def enable_mfa(username: str) -> bool:
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT totp_pending_secret FROM users WHERE username = :u"),
            {"u": username},
        ).mappings().fetchone()
        if not row or not row["totp_pending_secret"]:
            return False
        conn.execute(
            text(
                "UPDATE users SET mfa_enabled = true, totp_secret = totp_pending_secret, "
                "totp_pending_secret = NULL WHERE username = :u"
            ),
            {"u": username},
        )
    return True


def disable_mfa(username: str) -> bool:
    with db_conn() as conn:
        result = conn.execute(
            text(
                "UPDATE users SET mfa_enabled = false, totp_secret = NULL, "
                "totp_pending_secret = NULL WHERE username = :u"
            ),
            {"u": username},
        )
    return result.rowcount > 0
