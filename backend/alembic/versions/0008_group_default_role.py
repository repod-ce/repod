"""group_default_role — ajoute default_role aux groupes

Revision ID: 0008
Revises: 0007
"""
import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"


def upgrade():
    op.add_column(
        "groups",
        sa.Column("default_role", sa.Text(), nullable=True),
    )


def downgrade():
    op.drop_column("groups", "default_role")
