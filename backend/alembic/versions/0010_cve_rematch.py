"""manifests.last_rematch_at — re-matching CVE rétroactif via SBOM stocké

Ajoute manifests.last_rematch_at (Text, nullable) : horodatage ISO du
dernier re-matching Grype réussi via SBOM stocké (services/cve_rematch.py).
NULL sur un paquet jamais re-matché (créé avant cette fonctionnalité, ou
SBOM jamais capturé).

Revision ID: 0010
Revises: 0009
"""
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"


def upgrade():
    op.add_column("manifests", sa.Column("last_rematch_at", sa.Text, nullable=True))


def downgrade():
    op.drop_column("manifests", "last_rematch_at")
