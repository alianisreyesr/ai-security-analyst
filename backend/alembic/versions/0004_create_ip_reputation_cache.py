"""Create IP reputation cache table.

Revision ID: 0004
Revises: 0003
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | Sequence[str] | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ip_reputation_cache",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cache_key", sa.String(length=512), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("verdict", sa.String(length=100), nullable=False),
        sa.Column("score", sa.Integer(), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cache_key"),
    )
    op.create_index(
        "ix_ip_reputation_cache_cache_key",
        "ip_reputation_cache",
        ["cache_key"],
        unique=True,
    )
    op.create_index(
        "ix_ip_reputation_cache_ip_address",
        "ip_reputation_cache",
        ["ip_address"],
    )
    op.create_index(
        "ix_ip_reputation_cache_provider",
        "ip_reputation_cache",
        ["provider"],
    )
    op.create_index(
        "ix_ip_reputation_cache_expires_at",
        "ip_reputation_cache",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_ip_reputation_cache_expires_at",
        table_name="ip_reputation_cache",
    )
    op.drop_index(
        "ix_ip_reputation_cache_provider",
        table_name="ip_reputation_cache",
    )
    op.drop_index(
        "ix_ip_reputation_cache_ip_address",
        table_name="ip_reputation_cache",
    )
    op.drop_index(
        "ix_ip_reputation_cache_cache_key",
        table_name="ip_reputation_cache",
    )
    op.drop_table("ip_reputation_cache")
