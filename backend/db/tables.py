"""
db/tables.py — Définitions SQLAlchemy Core de toutes les tables PostgreSQL.

Remplace tous les CREATE TABLE dispersés dans les services.
Alembic lit ce module pour générer les migrations versionnées.

Usage :
    from db.tables import metadata, users, api_tokens, manifests, ...
    from db.engine import get_engine
    metadata.create_all(get_engine())   # utilisé par Alembic seulement
"""

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    Sequence,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB

metadata = MetaData()


# ── Authentification ──────────────────────────────────────────────────────────

users = Table(
    "users",
    metadata,
    Column("id",                    Integer, Sequence("users_id_seq"), primary_key=True),
    Column("username",              Text,    nullable=False, unique=True),
    Column("hashed_password",       Text,    nullable=False),
    Column("role",                  Text,    nullable=False, server_default="reader"),
    Column("full_name",             Text,    nullable=False, server_default=""),
    Column("email",                 Text,    nullable=False, server_default=""),
    Column("active",                Boolean, nullable=False, server_default="true"),
    Column("created_at",            Text,    nullable=False),
    Column("last_login",            Text),
    Column("auth_source",           Text,    nullable=False, server_default="local"),
    Column("mfa_enabled",           Boolean, nullable=False, server_default="false"),
    Column("totp_secret",           Text),
    Column("totp_pending_secret",   Text),
    Column("failed_login_count",    Integer, nullable=False, server_default="0"),
    Column("locked_until",          Text),
)

api_tokens = Table(
    "api_tokens",
    metadata,
    Column("id",          Text,    primary_key=True),
    Column("hash",        Text,    nullable=False, unique=True),
    Column("name",        Text,    nullable=False),
    Column("role",        Text,    nullable=False, server_default="reader"),
    Column("created_by",  Text,    nullable=False, server_default=""),
    Column("created_at",  Text,    nullable=False),
    Column("expires_at",  Text),
    Column("last_used",   Text),
    Index("idx_api_token_hash", "hash"),
)

revoked_tokens = Table(
    "revoked_tokens",
    metadata,
    Column("jti",         Text, primary_key=True),
    Column("username",    Text, nullable=False),
    Column("revoked_at",  Text, nullable=False),
    Column("expires_at",  Text, nullable=False),
    Index("idx_revoked_expires", "expires_at"),
)


# ── Manifests ─────────────────────────────────────────────────────────────────

manifests = Table(
    "manifests",
    metadata,
    Column("name",               Text,    nullable=False),
    Column("version",            Text,    nullable=False),
    Column("arch",               Text,    nullable=False, server_default="amd64"),
    Column("distribution",       Text,    nullable=False, server_default="unknown"),
    Column("pkg_type",           Text,    nullable=False, server_default="unknown"),
    Column("section",            Text,    server_default=""),
    Column("description",        Text,    server_default=""),
    Column("maintainer",         Text,    server_default=""),
    Column("installed_size_kb",  Integer, server_default="0"),
    Column("file_size_bytes",    Integer, server_default="0"),
    Column("filename",           Text,    server_default=""),
    Column("status",             Text,    server_default="validated"),
    Column("imported_by",        Text,    server_default="system"),
    Column("imported_at",        Text,    server_default=""),
    Column("import_method",      Text,    server_default="upload"),
    Column("import_group",       Text),
    Column("sha256",             Text,    server_default=""),
    Column("sha512",             Text,    server_default=""),
    Column("gpg_signed",         Boolean, server_default="false"),
    Column("tags",               JSONB,   server_default="'[]'::jsonb"),
    Column("dependencies",       JSONB,   server_default="'[]'::jsonb"),
    Column("validation_steps",   JSONB,   server_default="'[]'::jsonb"),
    Column("cve_results",        JSONB,   server_default="'[]'::jsonb"),
    Column("last_rematch_at",    Text),
    Column("updated_at",         Text),
    PrimaryKeyConstraint("name", "version", "arch", name="pk_manifests"),
    Index("idx_manifest_name", "name"),
    Index("idx_manifest_dist", "distribution"),
)


# ── Inventaire clients ────────────────────────────────────────────────────────

inventory_clients = Table(
    "inventory_clients",
    metadata,
    Column("id",               Text,    primary_key=True),
    Column("hostname",         Text,    nullable=False),
    Column("ip",               Text,    nullable=False),
    Column("ssh_user",         Text,    nullable=False, server_default="root"),
    Column("ssh_port",         Integer, nullable=False, server_default="22"),
    Column("pkg_type",         Text,    nullable=False, server_default="auto"),
    Column("distro_pretty",    Text),
    Column("distro_codename",  Text),
    Column("grype_distro",     Text),
    Column("label",            Text),
    Column("enabled",          Boolean, nullable=False, server_default="true"),
    Column("last_scan",        Text),
    Column("last_scan_status", Text),
    Column("last_error",       Text),
    Column("last_error_code",  Text),
    Column("connection_type",  Text,    nullable=False, server_default="ssh"),
    Column("agent_token",      Text),
    Column("agent_version",    Text),
    Column("agent_last_seen",  Text),
    Column("sudo_user",        Text,    nullable=False, server_default="root"),
    Column("sudo_password",    Text),
    Column("cis_score",        Float),
    Column("created_at",       Text,    nullable=False),
    Column("updated_at",       Text,    nullable=False),
    Index("idx_invclients_agent_token", "agent_token"),
)

inventory_packages = Table(
    "inventory_packages",
    metadata,
    Column("id",         Integer, Sequence("inventory_packages_id_seq"), primary_key=True),
    Column("client_id",  Text,    ForeignKey("inventory_clients.id", ondelete="CASCADE"), nullable=False),
    Column("name",       Text,    nullable=False),
    Column("version",    Text,    nullable=False),
    Column("arch",       Text),
    Column("scanned_at", Text,    nullable=False),
    Index("idx_invpkg_client", "client_id"),
    Index("idx_invpkg_name",   "name"),
)

inventory_cve = Table(
    "inventory_cve",
    metadata,
    Column("id",              Integer, Sequence("inventory_cve_id_seq"), primary_key=True),
    Column("client_id",       Text,    ForeignKey("inventory_clients.id", ondelete="CASCADE"), nullable=False),
    Column("pkg_name",        Text,    nullable=False),
    Column("pkg_version",     Text,    nullable=False),
    Column("cve_id",          Text,    nullable=False),
    Column("severity",        Text,    nullable=False),
    Column("cvss",            Float),
    Column("description",     Text),
    Column("fix_state",       Text),
    Column("fix_version",     Text),
    Column("in_kev",          Boolean, nullable=False, server_default="false"),
    Column("epss",            Float),
    Column("epss_percent",    Float),
    Column("epss_percentile", Float),
    Column("trurisk",         Float),
    Column("urls",            JSONB),
    Column("scanned_at",      Text,    nullable=False),
    Index("idx_invcve_client", "client_id"),
    Index("idx_invcve_id",     "cve_id"),
)

inventory_compliance = Table(
    "inventory_compliance",
    metadata,
    Column("id",          Integer, Sequence("inventory_compliance_id_seq"), primary_key=True),
    Column("client_id",   Text,    ForeignKey("inventory_clients.id", ondelete="CASCADE"), nullable=False),
    Column("check_id",    Text,    nullable=False),
    Column("category",    Text,    nullable=False),
    Column("level",       Integer, nullable=False, server_default="1"),
    Column("title",       Text,    nullable=False),
    Column("status",      Text,    nullable=False),
    Column("detail",      Text),
    Column("remediation", Text),
    Column("scanned_at",  Text,    nullable=False),
    Index("idx_compliance_client", "client_id"),
)

ssh_known_hosts = Table(
    "ssh_known_hosts",
    metadata,
    Column("client_id",   Text, nullable=False),
    Column("hostname",    Text, nullable=False),
    Column("key_type",    Text, nullable=False),
    Column("fingerprint", Text, nullable=False),
    Column("trusted_at",  Text, nullable=False),
    PrimaryKeyConstraint("client_id", "hostname", name="pk_ssh_known_hosts"),
)


# ── Jobs d'installation ───────────────────────────────────────────────────────

install_jobs = Table(
    "install_jobs",
    metadata,
    Column("job_id",          Text,    primary_key=True),
    Column("package_name",    Text,    nullable=False),
    Column("package_version", Text),
    Column("target_ids",      JSONB,   nullable=False),
    Column("requested_by",    Text,    nullable=False),
    Column("step",            Text,    nullable=False),
    Column("error",           Text),
    Column("started_at",      Text,    nullable=False),
    Column("finished_at",     Text),
    Column("machines",        JSONB,   nullable=False, server_default="'{}'::jsonb"),
    Column("archived_at",     Text,    nullable=False),
    Index("idx_install_jobs_finished", "finished_at"),
)


# ── Index de paquets — APT/RPM (table partagée) ───────────────────────────────

packages = Table(
    "packages",
    metadata,
    Column("id",             Integer, Sequence("packages_id_seq"), primary_key=True),
    Column("source_id",      Text,    nullable=False),
    Column("name",           Text,    nullable=False),
    Column("version",        Text,    nullable=False),
    Column("arch",           Text),
    # APT
    Column("section",        Text),
    Column("description",    Text),
    Column("depends",        Text),
    Column("provides",       Text),
    Column("filename",       Text),
    Column("size",           BigInteger),
    Column("sha256",         Text),
    Column("installed_size", BigInteger),
    Column("maintainer",     Text),
    Column("distro",         Text),
    Column("security",       Boolean, server_default="false"),
    # RPM
    Column("summary",        Text),
    Column("group_name",     Text),
    Column("license",        Text),
    Column("url",            Text),
    Column("rpm_url",        Text),
    Column("requires",       Text),
    Column("synced_at",      Text),
    UniqueConstraint("source_id", "name", "version", "arch", name="uq_pkg_source_name_ver_arch"),
    Index("idx_pkg_name",   "name"),
    Index("idx_pkg_source", "source_id"),
)

sync_status = Table(
    "sync_status",
    metadata,
    Column("source_id",  Text,    primary_key=True),
    Column("label",      Text),
    Column("last_sync",  Text),
    Column("pkg_count",  Integer),
    Column("status",     Text),
    Column("error",      Text),
)

sync_log = Table(
    "sync_log",
    metadata,
    Column("id",        Integer, Sequence("sync_log_id_seq"), primary_key=True),
    Column("source_id", Text,    nullable=False),
    Column("status",    Text,    nullable=False),
    Column("pkg_count", Integer),
    Column("error",     Text),
    Column("synced_at", Text,    nullable=False),
)

import_groups = Table(
    "import_groups",
    metadata,
    Column("id",                Integer, Sequence("import_groups_id_seq"), primary_key=True),
    Column("name",              Text,    nullable=False, unique=True),
    Column("package_count",     Integer, server_default="0"),
    Column("total_size_bytes",  BigInteger, server_default="0"),
    Column("distribution",      Text),
    Column("imported_by",       Text),
    Column("imported_at",       Text,    nullable=False),
)

import_group_files = Table(
    "import_group_files",
    metadata,
    Column("id",         Integer, Sequence("import_group_files_id_seq"), primary_key=True),
    Column("group_name", Text,    ForeignKey("import_groups.name", ondelete="CASCADE"), nullable=False),
    Column("filename",   Text,    nullable=False),
    Column("size_bytes", BigInteger, server_default="0"),
)


# ── Index de paquets — APK (tables séparées) ──────────────────────────────────

apk_packages = Table(
    "apk_packages",
    metadata,
    Column("id",             Integer, Sequence("apk_packages_id_seq"), primary_key=True),
    Column("source_id",      Text,    nullable=False),
    Column("name",           Text,    nullable=False),
    Column("version",        Text,    nullable=False),
    Column("arch",           Text),
    Column("description",    Text),
    Column("depends",        Text),
    Column("provides",       Text),
    Column("size",           BigInteger),
    Column("installed_size", BigInteger),
    Column("url",            Text),
    Column("license",        Text),
    Column("origin",         Text),
    Column("distro",         Text),
    Column("synced_at",      Text,    nullable=False),
    Column("apk_checksum",   Text),
    Index("idx_apk_name",   "name"),
    Index("idx_apk_source", "source_id"),
)

apk_sync_status = Table(
    "apk_sync_status",
    metadata,
    Column("source_id",  Text,    primary_key=True),
    Column("label",      Text),
    Column("last_sync",  Text),
    Column("pkg_count",  Integer, server_default="0"),
    Column("status",     Text,    server_default="never"),
    Column("error",      Text),
)
