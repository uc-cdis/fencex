"""oidc provider

Revision ID: 01eb65cb5f40
Revises: c4eab315ec93
Create Date: 2020-03-03 10:19:21.214895

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "01eb65cb5f40"
down_revision = "c4eab315ec93"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "clients",
        sa.Column("client_id", postgresql.UUID(), nullable=False),
        sa.Column("client_secret", sa.Unicode(), nullable=True),
        sa.Column("user_id", postgresql.UUID(), nullable=False),
        sa.Column("grant_types", postgresql.ARRAY(sa.Unicode()), nullable=False),
        sa.Column("response_types", postgresql.ARRAY(sa.Unicode()), nullable=False),
        sa.Column("token_endpoint_auth_method", sa.Unicode(), nullable=False),
        sa.Column("scope", sa.Unicode(), nullable=False),
        sa.Column("redirect_uris", postgresql.ARRAY(sa.Unicode()), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("client_id"),
    )
    op.create_table(
        "authorization_codes",
        sa.Column("code", sa.Unicode(), nullable=False),
        sa.Column("client_id", postgresql.UUID(), nullable=False),
        sa.Column("user_id", postgresql.UUID(), nullable=False),
        sa.Column("scope", sa.Unicode(), nullable=False),
        sa.Column("redirect_uri", sa.Unicode(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("nonce", sa.Unicode(), nullable=True),
        sa.ForeignKeyConstraint(["client_id"], ["clients.client_id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("code"),
    )
    op.create_index(
        op.f("ix_authorization_codes_nonce"),
        "authorization_codes",
        ["nonce"],
        unique=False,
    )
    op.create_table(
        "bearer_tokens",
        sa.Column("id", postgresql.UUID(), nullable=False),
        sa.Column("client_id", postgresql.UUID(), nullable=False),
        sa.Column("user_id", postgresql.UUID(), nullable=False),
        sa.Column("scope", sa.Unicode(), nullable=False),
        sa.Column("access_token", sa.Unicode(), nullable=False),
        sa.Column("refresh_token", sa.Unicode(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["clients.client_id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_bearer_tokens_access_token"),
        "bearer_tokens",
        ["access_token"],
        unique=True,
    )
    op.create_index(
        op.f("ix_bearer_tokens_refresh_token"),
        "bearer_tokens",
        ["refresh_token"],
        unique=True,
    )
    op.create_table(
        "client_users",
        sa.Column("id", postgresql.UUID(), nullable=False),
        sa.Column("user_id", postgresql.UUID(), nullable=False),
        sa.Column("client_id", postgresql.UUID(), nullable=False),
        sa.ForeignKeyConstraint(["client_id"], ["clients.client_id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "client_id"),
    )


def downgrade():
    op.drop_table("client_users")
    op.drop_index(op.f("ix_bearer_tokens_refresh_token"), table_name="bearer_tokens")
    op.drop_index(op.f("ix_bearer_tokens_access_token"), table_name="bearer_tokens")
    op.drop_table("bearer_tokens")
    op.drop_index(
        op.f("ix_authorization_codes_nonce"), table_name="authorization_codes"
    )
    op.drop_table("authorization_codes")
    op.drop_table("clients")
