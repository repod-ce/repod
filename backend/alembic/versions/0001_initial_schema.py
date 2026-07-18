"""initial_schema

Revision ID: 0001
Revises:
Create Date: 2026-06-09 00:00:00.000000

Crée l'intégralité du schéma PostgreSQL repod.
Remplace les 5 bases SQLite distinctes (users.db, manifests.db,
inventory.db, install_jobs.db, packages.db) par une base PostgreSQL unique.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Authentification ──────────────────────────────────────────────────────

    op.create_table(
        "users",
        sa.Column("id",                    sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("username",              sa.Text(),    nullable=False),
        sa.Column("hashed_password",       sa.Text(),    nullable=False),
        sa.Column("role",                  sa.Text(),    nullable=False, server_default="reader"),
        sa.Column("full_name",             sa.Text(),    nullable=False, server_default=""),
        sa.Column("email",                 sa.Text(),    nullable=False, server_default=""),
        sa.Column("active",                sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at",            sa.Text(),    nullable=False),
        sa.Column("last_login",            sa.Text()),
        sa.Column("auth_source",           sa.Text(),    nullable=False, server_default="local"),
        sa.Column("mfa_enabled",           sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("totp_secret",           sa.Text()),
        sa.Column("totp_pending_secret",   sa.Text()),
        sa.Column("failed_login_count",    sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until",          sa.Text()),
        sa.UniqueConstraint("username", name="uq_users_username"),
    )

    op.create_table(
        "api_tokens",
        sa.Column("id",          sa.Text(), primary_key=True),
        sa.Column("hash",        sa.Text(), nullable=False),
        sa.Column("name",        sa.Text(), nullable=False),
        sa.Column("role",        sa.Text(), nullable=False, server_default="reader"),
        sa.Column("created_by",  sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at",  sa.Text(), nullable=False),
        sa.Column("expires_at",  sa.Text()),
        sa.Column("last_used",   sa.Text()),
        sa.UniqueConstraint("hash", name="uq_api_tokens_hash"),
    )
    op.create_index("idx_api_token_hash", "api_tokens", ["hash"])

    # ── Manifests ─────────────────────────────────────────────────────────────

    op.create_table(
        "manifests",
        sa.Column("name",               sa.Text(),    nullable=False),
        sa.Column("version",            sa.Text(),    nullable=False),
        sa.Column("arch",               sa.Text(),    nullable=False, server_default="amd64"),
        sa.Column("distribution",       sa.Text(),    nullable=False, server_default="unknown"),
        sa.Column("pkg_type",           sa.Text(),    nullable=False, server_default="unknown"),
        sa.Column("section",            sa.Text(),    server_default=""),
        sa.Column("description",        sa.Text(),    server_default=""),
        sa.Column("maintainer",         sa.Text(),    server_default=""),
        sa.Column("installed_size_kb",  sa.Integer(), server_default="0"),
        sa.Column("file_size_bytes",    sa.Integer(), server_default="0"),
        sa.Column("filename",           sa.Text(),    server_default=""),
        sa.Column("status",             sa.Text(),    server_default="validated"),
        sa.Column("imported_by",        sa.Text(),    server_default="system"),
        sa.Column("imported_at",        sa.Text(),    server_default=""),
        sa.Column("import_method",      sa.Text(),    server_default="upload"),
        sa.Column("import_group",       sa.Text()),
        sa.Column("sha256",             sa.Text(),    server_default=""),
        sa.Column("sha512",             sa.Text(),    server_default=""),
        sa.Column("gpg_signed",         sa.Boolean(), server_default="false"),
        sa.Column("tags",               JSONB,        server_default=sa.text("'[]'::jsonb")),
        sa.Column("dependencies",       JSONB,        server_default=sa.text("'[]'::jsonb")),
        sa.Column("validation_steps",   JSONB,        server_default=sa.text("'[]'::jsonb")),
        sa.Column("cve_results",        JSONB,        server_default=sa.text("'[]'::jsonb")),
        sa.Column("updated_at",         sa.Text()),
        sa.PrimaryKeyConstraint("name", "version", "arch", name="pk_manifests"),
    )
    op.create_index("idx_manifest_name", "manifests", ["name"])
    op.create_index("idx_manifest_dist", "manifests", ["distribution"])

    # ── Inventaire clients ────────────────────────────────────────────────────

    op.create_table(
        "inventory_clients",
        sa.Column("id",               sa.Text(),    primary_key=True),
        sa.Column("hostname",         sa.Text(),    nullable=False),
        sa.Column("ip",               sa.Text(),    nullable=False),
        sa.Column("ssh_user",         sa.Text(),    nullable=False, server_default="root"),
        sa.Column("ssh_port",         sa.Integer(), nullable=False, server_default="22"),
        sa.Column("pkg_type",         sa.Text(),    nullable=False, server_default="auto"),
        sa.Column("distro_pretty",    sa.Text()),
        sa.Column("distro_codename",  sa.Text()),
        sa.Column("grype_distro",     sa.Text()),
        sa.Column("label",            sa.Text()),
        sa.Column("enabled",          sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_scan",        sa.Text()),
        sa.Column("last_scan_status", sa.Text()),
        sa.Column("last_error",       sa.Text()),
        sa.Column("last_error_code",  sa.Text()),
        sa.Column("connection_type",  sa.Text(),    nullable=False, server_default="ssh"),
        sa.Column("agent_token",      sa.Text()),
        sa.Column("agent_version",    sa.Text()),
        sa.Column("agent_last_seen",  sa.Text()),
        sa.Column("sudo_user",        sa.Text(),    nullable=False, server_default="root"),
        sa.Column("sudo_password",    sa.Text()),
        sa.Column("cis_score",        sa.Float()),
        sa.Column("created_at",       sa.Text(),    nullable=False),
        sa.Column("updated_at",       sa.Text(),    nullable=False),
    )
    op.create_index("idx_invclients_agent_token", "inventory_clients", ["agent_token"])

    op.create_table(
        "inventory_packages",
        sa.Column("id",         sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("client_id",  sa.Text(),    sa.ForeignKey("inventory_clients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name",       sa.Text(),    nullable=False),
        sa.Column("version",    sa.Text(),    nullable=False),
        sa.Column("arch",       sa.Text()),
        sa.Column("scanned_at", sa.Text(),    nullable=False),
    )
    op.create_index("idx_invpkg_client", "inventory_packages", ["client_id"])
    op.create_index("idx_invpkg_name",   "inventory_packages", ["name"])

    op.create_table(
        "inventory_cve",
        sa.Column("id",              sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("client_id",       sa.Text(),    sa.ForeignKey("inventory_clients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pkg_name",        sa.Text(),    nullable=False),
        sa.Column("pkg_version",     sa.Text(),    nullable=False),
        sa.Column("cve_id",          sa.Text(),    nullable=False),
        sa.Column("severity",        sa.Text(),    nullable=False),
        sa.Column("cvss",            sa.Float()),
        sa.Column("description",     sa.Text()),
        sa.Column("fix_state",       sa.Text()),
        sa.Column("fix_version",     sa.Text()),
        sa.Column("in_kev",          sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("epss",            sa.Float()),
        sa.Column("epss_percent",    sa.Float()),
        sa.Column("epss_percentile", sa.Float()),
        sa.Column("trurisk",         sa.Float()),
        sa.Column("urls",            JSONB),
        sa.Column("scanned_at",      sa.Text(),    nullable=False),
    )
    op.create_index("idx_invcve_client", "inventory_cve", ["client_id"])
    op.create_index("idx_invcve_id",     "inventory_cve", ["cve_id"])

    op.create_table(
        "inventory_compliance",
        sa.Column("id",          sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("client_id",   sa.Text(),    sa.ForeignKey("inventory_clients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("check_id",    sa.Text(),    nullable=False),
        sa.Column("category",    sa.Text(),    nullable=False),
        sa.Column("level",       sa.Integer(), nullable=False, server_default="1"),
        sa.Column("title",       sa.Text(),    nullable=False),
        sa.Column("status",      sa.Text(),    nullable=False),
        sa.Column("detail",      sa.Text()),
        sa.Column("remediation", sa.Text()),
        sa.Column("scanned_at",  sa.Text(),    nullable=False),
    )
    op.create_index("idx_compliance_client", "inventory_compliance", ["client_id"])

    op.create_table(
        "ssh_known_hosts",
        sa.Column("client_id",   sa.Text(), nullable=False),
        sa.Column("hostname",    sa.Text(), nullable=False),
        sa.Column("key_type",    sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("trusted_at",  sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("client_id", "hostname", name="pk_ssh_known_hosts"),
    )

    # ── Jobs d'installation ───────────────────────────────────────────────────

    op.create_table(
        "install_jobs",
        sa.Column("job_id",          sa.Text(), primary_key=True),
        sa.Column("package_name",    sa.Text(), nullable=False),
        sa.Column("package_version", sa.Text()),
        sa.Column("target_ids",      JSONB,     nullable=False),
        sa.Column("requested_by",    sa.Text(), nullable=False),
        sa.Column("step",            sa.Text(), nullable=False),
        sa.Column("error",           sa.Text()),
        sa.Column("started_at",      sa.Text(), nullable=False),
        sa.Column("finished_at",     sa.Text()),
        sa.Column("machines",        JSONB,     nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("archived_at",     sa.Text(), nullable=False),
    )
    op.create_index("idx_install_jobs_finished", "install_jobs", ["finished_at"])

    # ── Index de paquets — APT/RPM ────────────────────────────────────────────

    op.create_table(
        "packages",
        sa.Column("id",             sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("source_id",      sa.Text(),    nullable=False),
        sa.Column("name",           sa.Text(),    nullable=False),
        sa.Column("version",        sa.Text(),    nullable=False),
        sa.Column("arch",           sa.Text()),
        sa.Column("section",        sa.Text()),
        sa.Column("description",    sa.Text()),
        sa.Column("depends",        sa.Text()),
        sa.Column("provides",       sa.Text()),
        sa.Column("filename",       sa.Text()),
        sa.Column("size",           sa.Integer()),
        sa.Column("sha256",         sa.Text()),
        sa.Column("installed_size", sa.Integer()),
        sa.Column("maintainer",     sa.Text()),
        sa.Column("distro",         sa.Text()),
        sa.Column("security",       sa.Boolean(), server_default="false"),
        sa.Column("summary",        sa.Text()),
        sa.Column("group_name",     sa.Text()),
        sa.Column("license",        sa.Text()),
        sa.Column("url",            sa.Text()),
        sa.Column("rpm_url",        sa.Text()),
        sa.Column("requires",       sa.Text()),
        sa.Column("synced_at",      sa.Text()),
        sa.UniqueConstraint("source_id", "name", "version", "arch",
                            name="uq_pkg_source_name_ver_arch"),
    )
    op.create_index("idx_pkg_name",   "packages", ["name"])
    op.create_index("idx_pkg_source", "packages", ["source_id"])

    op.create_table(
        "sync_status",
        sa.Column("source_id",  sa.Text(),    primary_key=True),
        sa.Column("label",      sa.Text()),
        sa.Column("last_sync",  sa.Text()),
        sa.Column("pkg_count",  sa.Integer()),
        sa.Column("status",     sa.Text()),
        sa.Column("error",      sa.Text()),
    )

    op.create_table(
        "sync_log",
        sa.Column("id",        sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("source_id", sa.Text(),    nullable=False),
        sa.Column("status",    sa.Text(),    nullable=False),
        sa.Column("pkg_count", sa.Integer()),
        sa.Column("error",     sa.Text()),
        sa.Column("synced_at", sa.Text(),    nullable=False),
    )

    op.create_table(
        "import_groups",
        sa.Column("id",               sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("name",             sa.Text(),    nullable=False),
        sa.Column("package_count",    sa.Integer(), server_default="0"),
        sa.Column("total_size_bytes", sa.Integer(), server_default="0"),
        sa.Column("distribution",     sa.Text()),
        sa.Column("imported_by",      sa.Text()),
        sa.Column("imported_at",      sa.Text(),    nullable=False),
        sa.UniqueConstraint("name", name="uq_import_groups_name"),
    )

    op.create_table(
        "import_group_files",
        sa.Column("id",         sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("group_name", sa.Text(),    sa.ForeignKey("import_groups.name", ondelete="CASCADE"), nullable=False),
        sa.Column("filename",   sa.Text(),    nullable=False),
        sa.Column("size_bytes", sa.Integer(), server_default="0"),
    )

    # ── Index de paquets — APK ────────────────────────────────────────────────

    op.create_table(
        "apk_packages",
        sa.Column("id",             sa.Integer(), sa.Identity(), primary_key=True),
        sa.Column("source_id",      sa.Text(),    nullable=False),
        sa.Column("name",           sa.Text(),    nullable=False),
        sa.Column("version",        sa.Text(),    nullable=False),
        sa.Column("arch",           sa.Text()),
        sa.Column("description",    sa.Text()),
        sa.Column("depends",        sa.Text()),
        sa.Column("provides",       sa.Text()),
        sa.Column("size",           sa.Integer()),
        sa.Column("installed_size", sa.Integer()),
        sa.Column("url",            sa.Text()),
        sa.Column("license",        sa.Text()),
        sa.Column("origin",         sa.Text()),
        sa.Column("distro",         sa.Text()),
        sa.Column("synced_at",      sa.Text(),    nullable=False),
    )
    op.create_index("idx_apk_name",   "apk_packages", ["name"])
    op.create_index("idx_apk_source", "apk_packages", ["source_id"])

    op.create_table(
        "apk_sync_status",
        sa.Column("source_id",  sa.Text(),    primary_key=True),
        sa.Column("label",      sa.Text()),
        sa.Column("last_sync",  sa.Text()),
        sa.Column("pkg_count",  sa.Integer(), server_default="0"),
        sa.Column("status",     sa.Text(),    server_default="never"),
        sa.Column("error",      sa.Text()),
    )


def downgrade() -> None:
    op.drop_table("apk_sync_status")
    op.drop_table("apk_packages")
    op.drop_table("import_group_files")
    op.drop_table("import_groups")
    op.drop_table("sync_log")
    op.drop_table("sync_status")
    op.drop_table("packages")
    op.drop_table("install_jobs")
    op.drop_table("ssh_known_hosts")
    op.drop_table("inventory_compliance")
    op.drop_table("inventory_cve")
    op.drop_table("inventory_packages")
    op.drop_table("inventory_clients")
    op.drop_table("manifests")
    op.drop_table("api_tokens")
    op.drop_table("users")
