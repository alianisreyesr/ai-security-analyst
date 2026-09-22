"""Create threats table.

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "threats",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_ids", sa.JSON(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint"),
    )
    op.create_index("ix_threats_fingerprint", "threats", ["fingerprint"], unique=True)
    op.create_index("ix_threats_rule_id", "threats", ["rule_id"])
    op.create_index("ix_threats_source_ip", "threats", ["source_ip"])
    op.create_index("ix_threats_risk_score", "threats", ["risk_score"])
    op.create_index("ix_threats_severity", "threats", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_threats_severity", table_name="threats")
    op.drop_index("ix_threats_risk_score", table_name="threats")
    op.drop_index("ix_threats_source_ip", table_name="threats")
    op.drop_index("ix_threats_rule_id", table_name="threats")
    op.drop_index("ix_threats_fingerprint", table_name="threats")
    op.drop_table("threats")
