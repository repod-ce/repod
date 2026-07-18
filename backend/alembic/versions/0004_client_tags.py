"""client_tags

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-15 00:00:00.000000

Ajoute une colonne `tags` (JSONB, liste de chaînes) sur `inventory_clients`
pour permettre d'étiqueter les machines (ex: "prod", "staging") et de
filtrer les vues de conformité par environnement.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "inventory_clients",
        sa.Column("tags", JSONB, server_default=sa.text("'[]'::jsonb")),
    )


def downgrade() -> None:
    op.drop_column("inventory_clients", "tags")
