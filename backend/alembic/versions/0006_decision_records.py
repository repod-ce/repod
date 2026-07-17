"""decision_records — décisions CVE migrées de JSON vers PostgreSQL

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-18

Remplace le stockage JSON fichier (security/decisions/*.json et
security/client_decisions/*.json) par deux tables PostgreSQL.
Les fichiers existants sont importés automatiquement lors de l'upgrade.
"""

import json
import os
import uuid
from pathlib import Path

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

_SECURITY_DIR = Path(os.getenv("SECURITY_CACHE_DIR", "/repos/security"))
_DECISIONS_DIR = _SECURITY_DIR / "decisions"
_CLIENT_DECISIONS_DIR = _SECURITY_DIR / "client_decisions"


def upgrade() -> None:
    op.create_table(
        "decision_records",
        sa.Column("id",                       sa.Text(),    primary_key=True),
        sa.Column("package",                  sa.Text(),    nullable=False),
        sa.Column("version",                  sa.Text(),    nullable=False),
        sa.Column("arch",                     sa.Text(),    nullable=False, server_default="amd64"),
        sa.Column("action",                   sa.Text(),    nullable=False),
        sa.Column("status",                   sa.Text(),    nullable=False),
        sa.Column("justification",            sa.Text(),    nullable=False, server_default=""),
        sa.Column("decided_by",               sa.Text(),    nullable=False),
        sa.Column("decided_at",               sa.Text(),    nullable=False),
        sa.Column("expires_at",               sa.Text()),
        sa.Column("expires_in_days",          sa.Integer()),
        sa.Column("target_version",           sa.Text()),
        sa.Column("cve_ids",                  JSONB,        nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("assigned_to",              sa.Text()),
        sa.Column("assigned_to_type",         sa.Text()),
        sa.Column("assigned_at",              sa.Text()),
        sa.Column("patch_available_notified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("resolved_at",              sa.Text()),
        sa.Column("resolved_by",              sa.Text()),
        sa.Column("resolution_note",          sa.Text()),
    )
    op.create_index("idx_dr_package",     "decision_records", ["package"])
    op.create_index("idx_dr_assigned_to", "decision_records", ["assigned_to"])
    # Contrainte : un seul enregistrement actif par (package, version, arch)
    op.create_unique_constraint("uq_dr_pkg_ver_arch", "decision_records", ["package", "version", "arch"])

    op.create_table(
        "client_decision_records",
        sa.Column("id",              sa.Text(), primary_key=True),
        sa.Column("source",          sa.Text(), nullable=False, server_default="compliance"),
        sa.Column("package",         sa.Text(), nullable=False),
        sa.Column("version",         sa.Text(), nullable=False),
        sa.Column("arch",            sa.Text(), nullable=False, server_default="x86_64"),
        sa.Column("distro_family",   sa.Text(), nullable=False, server_default=""),
        sa.Column("action",          sa.Text(), nullable=False),
        sa.Column("justification",   sa.Text(), nullable=False, server_default=""),
        sa.Column("decided_by",      sa.Text(), nullable=False),
        sa.Column("decided_at",      sa.Text(), nullable=False),
        sa.Column("expires_at",      sa.Text()),
        sa.Column("expires_in_days", sa.Integer()),
        sa.Column("target_version",  sa.Text()),
        sa.Column("cve_ids",         JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("client_ids",      JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("hostnames",       JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("assigned_to",     sa.Text()),
        sa.Column("assigned_to_type",sa.Text()),
        sa.Column("assigned_at",     sa.Text()),
        sa.Column("resolved_at",     sa.Text()),
        sa.Column("resolved_by",     sa.Text()),
        sa.Column("resolve_note",    sa.Text()),
    )
    op.create_index("idx_cdr_package",     "client_decision_records", ["package"])
    op.create_index("idx_cdr_assigned_to", "client_decision_records", ["assigned_to"])

    # ── Importer les JSON existants ───────────────────────────────────────────
    # SAVEPOINTs pour isoler chaque INSERT : une erreur SQL n'avorte pas la
    # transaction principale.

    conn = op.get_bind()

    ACTION_TO_STATUS = {
        "accept_risk":      "accepted_risk",
        "exception":        "exception",
        "reject":           "quarantined",
        "upgrade_required": "upgrade_required",
    }

    if _DECISIONS_DIR.exists():
        for path in sorted(_DECISIONS_DIR.glob("*.json")):
            try:
                d = json.loads(path.read_text(encoding="utf-8"))
                sp = conn.begin_nested()
                try:
                    conn.execute(
                        sa.text(
                            "INSERT INTO decision_records "
                            "(id, package, version, arch, action, status, justification, "
                            " decided_by, decided_at, expires_at, expires_in_days, target_version, "
                            " cve_ids, patch_available_notified, resolved_at, resolved_by, resolution_note) "
                            "VALUES (:id, :pkg, :ver, :arch, :action, :status, :just, "
                            " :by, :at, :exp_at, :exp_days, :tgt_ver, "
                            " CAST(:cve_ids AS jsonb), :notified, :res_at, :res_by, :res_note) "
                            "ON CONFLICT ON CONSTRAINT uq_dr_pkg_ver_arch DO NOTHING"
                        ),
                        {
                            "id":       d.get("id", str(uuid.uuid4())),
                            "pkg":      d.get("package", ""),
                            "ver":      d.get("version", ""),
                            "arch":     d.get("arch", "amd64"),
                            "action":   d.get("action", ""),
                            "status":   d.get("status") or ACTION_TO_STATUS.get(d.get("action", ""), ""),
                            "just":     d.get("justification", ""),
                            "by":       d.get("decided_by", "system"),
                            "at":       d.get("decided_at", ""),
                            "exp_at":   d.get("expires_at"),
                            "exp_days": d.get("expires_in_days"),
                            "tgt_ver":  d.get("target_version"),
                            "cve_ids":  json.dumps(d.get("cve_ids", [])),
                            "notified": bool(d.get("patch_available_notified", False)),
                            "res_at":   d.get("resolved_at"),
                            "res_by":   d.get("resolved_by"),
                            "res_note": d.get("resolution_note"),
                        },
                    )
                    sp.commit()
                except Exception:
                    sp.rollback()
            except Exception:
                pass

    if _CLIENT_DECISIONS_DIR.exists():
        for path in sorted(_CLIENT_DECISIONS_DIR.glob("*.json")):
            try:
                d = json.loads(path.read_text(encoding="utf-8"))
                sp = conn.begin_nested()
                try:
                    conn.execute(
                        sa.text(
                            "INSERT INTO client_decision_records "
                            "(id, source, package, version, arch, distro_family, action, justification, "
                            " decided_by, decided_at, expires_at, expires_in_days, target_version, "
                            " cve_ids, client_ids, hostnames, resolved_at, resolved_by, resolve_note) "
                            "VALUES (:id, :src, :pkg, :ver, :arch, :distro, :action, :just, "
                            " :by, :at, :exp_at, :exp_days, :tgt_ver, "
                            " CAST(:cve_ids AS jsonb), CAST(:cli_ids AS jsonb), CAST(:hosts AS jsonb),"
                            " :res_at, :res_by, :res_note) "
                            "ON CONFLICT (id) DO NOTHING"
                        ),
                        {
                            "id":       d.get("id", str(uuid.uuid4())),
                            "src":      d.get("source", "compliance"),
                            "pkg":      d.get("package", ""),
                            "ver":      d.get("version", ""),
                            "arch":     d.get("arch", "x86_64"),
                            "distro":   d.get("distro_family", ""),
                            "action":   d.get("action", ""),
                            "just":     d.get("justification", ""),
                            "by":       d.get("decided_by", "system"),
                            "at":       d.get("decided_at", ""),
                            "exp_at":   d.get("expires_at"),
                            "exp_days": d.get("expires_in_days"),
                            "tgt_ver":  d.get("target_version"),
                            "cve_ids":  json.dumps(d.get("cve_ids", [])),
                            "cli_ids":  json.dumps(d.get("client_ids", [])),
                            "hosts":    json.dumps(d.get("hostnames", [])),
                            "res_at":   d.get("resolved_at"),
                            "res_by":   d.get("resolved_by"),
                            "res_note": d.get("resolve_note"),
                        },
                    )
                    sp.commit()
                except Exception:
                    sp.rollback()
            except Exception:
                pass


def downgrade() -> None:
    op.drop_table("client_decision_records")
    op.drop_index("idx_dr_assigned_to", "decision_records")
    op.drop_index("idx_dr_package",     "decision_records")
    op.drop_table("decision_records")
