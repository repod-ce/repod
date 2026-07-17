"""custom_roles — rôles personnalisables et permissions

Revision ID: 0007
Revises: 0006
Create Date: 2026-06-18

Crée les tables custom_roles et role_permissions.
Insère les 5 rôles built-in avec leur jeu de permissions initial.
"""

from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

_NOW = datetime.now(timezone.utc).isoformat()

_ALL_PERMISSIONS = {
    "cve.view", "cve.decide",
    "pkg.upload", "pkg.import", "pkg.delete", "pkg.promote",
    "user.manage", "group.manage", "role.manage",
    "audit.read", "settings.admin", "system.backup",
    "inventory.read", "inventory.scan", "deploy.run",
}

_BUILTIN = {
    "admin": {
        "label": "Administrateur",
        "description": "Accès total : gestion des utilisateurs, paramètres système, toutes opérations.",
        "color": "red",
        "perms": _ALL_PERMISSIONS,
    },
    "maintainer": {
        "label": "Mainteneur",
        "description": "Cycle de vie des paquets : upload, import, promotion, suppression, CVE, audit.",
        "color": "purple",
        "perms": {
            "cve.view", "cve.decide",
            "pkg.upload", "pkg.import", "pkg.delete", "pkg.promote",
            "audit.read",
            "inventory.read", "inventory.scan", "deploy.run",
        },
    },
    "uploader": {
        "label": "Packager / CI-CD",
        "description": "Dépôt de paquets uniquement : upload et import.",
        "color": "blue",
        "perms": {"pkg.upload", "pkg.import"},
    },
    "auditor": {
        "label": "Auditeur",
        "description": "Lecture du dépôt + logs d'audit. Aucune modification.",
        "color": "yellow",
        "perms": {"cve.view", "audit.read", "inventory.read"},
    },
    "reader": {
        "label": "Lecteur",
        "description": "Lecture seule : recherche et liste des paquets.",
        "color": "gray",
        "perms": {"cve.view"},
    },
}


def upgrade() -> None:
    op.create_table(
        "custom_roles",
        sa.Column("id",          sa.Text(),    primary_key=True),
        sa.Column("name",        sa.Text(),    nullable=False),
        sa.Column("label",       sa.Text(),    nullable=False),
        sa.Column("description", sa.Text(),    nullable=False, server_default=""),
        sa.Column("color",       sa.Text(),    nullable=False, server_default="gray"),
        sa.Column("is_builtin",  sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at",  sa.Text(),    nullable=False),
        sa.Column("created_by",  sa.Text(),    nullable=False, server_default="system"),
        sa.UniqueConstraint("name", name="uq_custom_roles_name"),
    )

    op.create_table(
        "role_permissions",
        sa.Column("role_id",    sa.Text(), sa.ForeignKey("custom_roles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("permission", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("role_id", "permission", name="pk_role_permissions"),
    )
    op.create_index("idx_role_permissions_role", "role_permissions", ["role_id"])

    conn = op.get_bind()
    for role_id, meta in _BUILTIN.items():
        conn.execute(
            sa.text(
                "INSERT INTO custom_roles (id, name, label, description, color, is_builtin, created_at, created_by) "
                "VALUES (:id, :name, :label, :desc, :color, true, :ts, 'system') "
                "ON CONFLICT (name) DO NOTHING"
            ),
            {"id": role_id, "name": role_id, "label": meta["label"],
             "desc": meta["description"], "color": meta["color"], "ts": _NOW},
        )
        for perm in meta["perms"]:
            conn.execute(
                sa.text(
                    "INSERT INTO role_permissions (role_id, permission) VALUES (:rid, :perm) "
                    "ON CONFLICT DO NOTHING"
                ),
                {"rid": role_id, "perm": perm},
            )


def downgrade() -> None:
    op.drop_index("idx_role_permissions_role", "role_permissions")
    op.drop_table("role_permissions")
    op.drop_table("custom_roles")
