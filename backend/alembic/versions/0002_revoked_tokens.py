"""revoked_tokens

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-10 00:00:00.000000

Ajoute la table revoked_tokens utilisée pour la révocation des JWT
(logout, compromission de compte) — voir auth/token_revocation.py.

Chaque JWT créé par create_access_token() embarque désormais un claim
`jti` (JWT ID) unique. Le logout insère le jti dans cette table jusqu'à
sa date d'expiration naturelle (`expires_at` = claim `exp` du token),
après quoi l'entrée est purgée par la tâche de rétention quotidienne
(le token serait de toute façon rejeté par decode_token() pour expiration).
"""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "revoked_tokens",
        sa.Column("jti",        sa.Text(), primary_key=True),
        sa.Column("username",   sa.Text(), nullable=False),
        sa.Column("revoked_at", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
    )
    op.create_index("idx_revoked_expires", "revoked_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_table("revoked_tokens")
