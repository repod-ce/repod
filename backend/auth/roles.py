"""
Gestion des rôles personnalisables — PostgreSQL (tables custom_roles, role_permissions).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import text

from db.engine import db_conn
from auth.permissions import ALL_PERMISSIONS, BUILTIN_ROLE_PERMISSIONS

_BUILTIN_IDS = {"admin", "maintainer", "uploader", "auditor", "reader"}


def seed_builtin_roles() -> None:
    """Insère les rôles built-in si absents (idempotent). Appelé au démarrage."""
    from auth.permissions import BUILTIN_ROLE_PERMISSIONS
    now = datetime.now(timezone.utc).isoformat()
    labels = {
        "admin":      ("Administrateur", "red"),
        "maintainer": ("Mainteneur",     "purple"),
        "uploader":   ("Packager / CI-CD", "blue"),
        "auditor":    ("Auditeur",       "yellow"),
        "reader":     ("Lecteur",        "gray"),
    }
    with db_conn() as conn:
        for role_id, perms in BUILTIN_ROLE_PERMISSIONS.items():
            label, color = labels[role_id]
            conn.execute(
                text(
                    "INSERT INTO custom_roles (id, name, label, color, is_builtin, created_at, created_by) "
                    "VALUES (:id, :name, :label, :color, true, :ts, 'system') "
                    "ON CONFLICT (name) DO NOTHING"
                ),
                {"id": role_id, "name": role_id, "label": label, "color": color, "ts": now},
            )
            for perm in perms:
                conn.execute(
                    text(
                        "INSERT INTO role_permissions (role_id, permission) VALUES (:rid, :perm) "
                        "ON CONFLICT DO NOTHING"
                    ),
                    {"rid": role_id, "perm": perm},
                )


def list_roles() -> list[dict]:
    with db_conn() as conn:
        rows = conn.execute(
            text(
                "SELECT r.id, r.name, r.label, r.description, r.color, r.is_builtin, "
                "       r.created_at, r.created_by, "
                "       array_agg(rp.permission) FILTER (WHERE rp.permission IS NOT NULL) AS permissions "
                "FROM custom_roles r "
                "LEFT JOIN role_permissions rp ON rp.role_id = r.id "
                "GROUP BY r.id "
                "ORDER BY r.is_builtin DESC, r.name ASC"
            )
        ).mappings().fetchall()
    return [_row_to_dict(r) for r in rows]


def get_role(role_id: str) -> dict | None:
    with db_conn() as conn:
        row = conn.execute(
            text(
                "SELECT r.id, r.name, r.label, r.description, r.color, r.is_builtin, "
                "       r.created_at, r.created_by, "
                "       array_agg(rp.permission) FILTER (WHERE rp.permission IS NOT NULL) AS permissions "
                "FROM custom_roles r "
                "LEFT JOIN role_permissions rp ON rp.role_id = r.id "
                "WHERE r.id = :id "
                "GROUP BY r.id"
            ),
            {"id": role_id},
        ).mappings().fetchone()
    return _row_to_dict(row) if row else None


def _row_to_dict(row) -> dict:
    d = dict(row)
    perms = d.get("permissions")
    if perms is None:
        d["permissions"] = []
    elif not isinstance(perms, list):
        d["permissions"] = list(perms)
    return d


def create_role(name: str, label: str, description: str, color: str,
                permissions: set[str], created_by: str) -> dict:
    invalid = permissions - ALL_PERMISSIONS
    if invalid:
        raise ValueError(f"Permissions invalides : {invalid}")
    rid = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    with db_conn() as conn:
        conn.execute(
            text(
                "INSERT INTO custom_roles (id, name, label, description, color, is_builtin, created_at, created_by) "
                "VALUES (:id, :name, :label, :desc, :color, false, :ts, :by)"
            ),
            {"id": rid, "name": name, "label": label, "desc": description,
             "color": color, "ts": now, "by": created_by},
        )
        for perm in permissions:
            conn.execute(
                text("INSERT INTO role_permissions (role_id, permission) VALUES (:rid, :perm) ON CONFLICT DO NOTHING"),
                {"rid": rid, "perm": perm},
            )
    return get_role(rid)


def update_role(role_id: str, label: str | None = None, description: str | None = None,
                color: str | None = None) -> dict | None:
    with db_conn() as conn:
        if label is not None:
            conn.execute(text("UPDATE custom_roles SET label = :v WHERE id = :id"), {"v": label, "id": role_id})
        if description is not None:
            conn.execute(text("UPDATE custom_roles SET description = :v WHERE id = :id"), {"v": description, "id": role_id})
        if color is not None:
            conn.execute(text("UPDATE custom_roles SET color = :v WHERE id = :id"), {"v": color, "id": role_id})
    return get_role(role_id)


def delete_role(role_id: str) -> bool:
    role = get_role(role_id)
    if not role:
        return False
    if role.get("is_builtin"):
        raise ValueError("Impossible de supprimer un rôle built-in")
    with db_conn() as conn:
        result = conn.execute(text("DELETE FROM custom_roles WHERE id = :id"), {"id": role_id})
    return result.rowcount > 0


def get_role_permissions(role_id: str) -> set[str]:
    with db_conn() as conn:
        rows = conn.execute(
            text("SELECT permission FROM role_permissions WHERE role_id = :id"),
            {"id": role_id},
        ).fetchall()
    return {r[0] for r in rows}


def set_role_permissions(role_id: str, permissions: set[str]) -> bool:
    invalid = permissions - ALL_PERMISSIONS
    if invalid:
        raise ValueError(f"Permissions invalides : {invalid}")
    with db_conn() as conn:
        conn.execute(text("DELETE FROM role_permissions WHERE role_id = :id"), {"id": role_id})
        for perm in permissions:
            conn.execute(
                text("INSERT INTO role_permissions (role_id, permission) VALUES (:rid, :perm) ON CONFLICT DO NOTHING"),
                {"rid": role_id, "perm": perm},
            )
    return True


def get_user_permissions(username: str) -> set[str]:
    """Retourne l'ensemble des permissions effectives de l'utilisateur via son rôle."""
    with db_conn() as conn:
        row = conn.execute(
            text("SELECT role FROM users WHERE username = :u AND active = true"),
            {"u": username},
        ).fetchone()
    if not row:
        return set()
    role_id = row[0]
    # Chercher d'abord dans custom_roles (supporte les rôles custom)
    perms = get_role_permissions(role_id)
    if not perms:
        # Fallback sur BUILTIN_ROLE_PERMISSIONS si la table n'est pas encore seedée
        perms = BUILTIN_ROLE_PERMISSIONS.get(role_id, set())
    return perms
