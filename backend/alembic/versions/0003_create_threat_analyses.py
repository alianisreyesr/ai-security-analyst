"""Create threat analyses table.

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "threat_analyses",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("threat_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("model", sa.String(length=255), nullable=False),
        sa.Column("template_version", sa.String(length=50), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("observed_evidence", sa.JSON(), nullable=False),
        sa.Column("interpretation", sa.Text(), nullable=False),
        sa.Column("investigation_steps", sa.JSON(), nullable=False),
        sa.Column("caveats", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["threat_id"],
            ["threats.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_threat_analyses_threat_id",
        "threat_analyses",
        ["threat_id"],
    )
    op.create_index(
        "ix_threat_analyses_status",
        "threat_analyses",
        ["status"],
    )


def downgrade() -> None:
    op.drop_index("ix_threat_analyses_status", table_name="threat_analyses")
    op.drop_index("ix_threat_analyses_threat_id", table_name="threat_analyses")
    op.drop_table("threat_analyses")
