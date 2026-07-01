"""bigint_package_sizes

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-14 00:00:00.000000

Certains paquets APT/APK dépassent la limite de PostgreSQL INTEGER
(2 147 483 647) pour leurs champs Size/Installed-Size (octets ou Ko),
ce qui fait échouer la synchronisation de l'index avec
`psycopg2.errors.NumericValueOutOfRange: integer out of range`.

Passe ces colonnes en BIGINT dans `packages`, `apk_packages`,
`import_groups` et `import_group_files`.
"""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("packages", "size", type_=sa.BigInteger())
    op.alter_column("packages", "installed_size", type_=sa.BigInteger())
    op.alter_column("apk_packages", "size", type_=sa.BigInteger())
    op.alter_column("apk_packages", "installed_size", type_=sa.BigInteger())
    op.alter_column("import_groups", "total_size_bytes", type_=sa.BigInteger())
    op.alter_column("import_group_files", "size_bytes", type_=sa.BigInteger())


def downgrade() -> None:
    op.alter_column("packages", "size", type_=sa.Integer())
    op.alter_column("packages", "installed_size", type_=sa.Integer())
    op.alter_column("apk_packages", "size", type_=sa.Integer())
    op.alter_column("apk_packages", "installed_size", type_=sa.Integer())
    op.alter_column("import_groups", "total_size_bytes", type_=sa.Integer())
    op.alter_column("import_group_files", "size_bytes", type_=sa.Integer())
