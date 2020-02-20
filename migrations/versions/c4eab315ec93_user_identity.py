"""user_identity

Revision ID: c4eab315ec93
Revises:
Create Date: 2020-02-19 10:42:28.699843

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "c4eab315ec93"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(), nullable=False),
        sa.Column("profile", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "identities",
        sa.Column("id", sa.BigInteger(), nullable=False),
        sa.Column("sub", sa.Unicode(), nullable=False),
        sa.Column("idp", sa.Unicode(), nullable=False),
        sa.Column("user_id", postgresql.UUID(), nullable=False),
        sa.Column("profile", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("identities_idp_sub_idx", "identities", ["sub", "idp"], unique=True)


def downgrade():
    op.drop_index("identities_idp_sub_idx", table_name="identities")
    op.drop_table("identities")
    op.drop_table("users")
