"""groups — tables groupes et membres

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-18
"""

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "groups",
        sa.Column("id",          sa.Text(), primary_key=True),
        sa.Column("name",        sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("color",       sa.Text(), nullable=False, server_default="blue"),
        sa.Column("created_at",  sa.Text(), nullable=False),
        sa.Column("created_by",  sa.Text(), nullable=False, server_default="system"),
        sa.UniqueConstraint("name", name="uq_groups_name"),
    )

    op.create_table(
        "group_members",
        sa.Column("group_id",  sa.Text(), sa.ForeignKey("groups.id", ondelete="CASCADE"), nullable=False),
        sa.Column("username",  sa.Text(), nullable=False),
        sa.Column("added_at",  sa.Text(), nullable=False),
        sa.Column("added_by",  sa.Text(), nullable=False, server_default="system"),
        sa.PrimaryKeyConstraint("group_id", "username", name="pk_group_members"),
    )
    op.create_index("idx_group_members_group",    "group_members", ["group_id"])
    op.create_index("idx_group_members_username", "group_members", ["username"])


def downgrade() -> None:
    op.drop_table("group_members")
    op.drop_table("groups")
