"""apk_checksum — Ajoute la colonne apk_checksum à apk_packages

Stocke le champ C: de l'APKINDEX (Q1<base64(SHA1(control_section))>)
pour permettre la vérification d'intégrité lors de l'import depuis internet.

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"


def upgrade():
    op.add_column("apk_packages", sa.Column("apk_checksum", sa.Text, nullable=True))


def downgrade():
    op.drop_column("apk_packages", "apk_checksum")
