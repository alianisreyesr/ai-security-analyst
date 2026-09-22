"""Create analytics snapshots, security cases and threat reviews.

Revision ID: 0005
Revises: 0004
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | Sequence[str] | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "analytics_snapshots",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("bucket_key", sa.String(length=100), nullable=False),
        sa.Column("granularity", sa.String(length=16), nullable=False),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("total_threats", sa.Integer(), nullable=False),
        sa.Column("severity_counts", sa.JSON(), nullable=False),
        sa.Column("rule_counts", sa.JSON(), nullable=False),
        sa.Column("source_counts", sa.JSON(), nullable=False),
        sa.Column(
            "rebuilt_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("bucket_key"),
    )
    op.create_index(
        "ix_analytics_snapshots_bucket_key",
        "analytics_snapshots",
        ["bucket_key"],
        unique=True,
    )
    op.create_index(
        "ix_analytics_snapshots_granularity",
        "analytics_snapshots",
        ["granularity"],
    )
    op.create_index(
        "ix_analytics_snapshots_bucket_start",
        "analytics_snapshots",
        ["bucket_start"],
    )

    op.create_table(
        "security_cases",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("threat_ids", sa.JSON(), nullable=False),
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
    op.create_index(
        "ix_security_cases_fingerprint",
        "security_cases",
        ["fingerprint"],
        unique=True,
    )
    op.create_index(
        "ix_security_cases_source_ip",
        "security_cases",
        ["source_ip"],
    )
    op.create_index(
        "ix_security_cases_status",
        "security_cases",
        ["status"],
    )
    op.create_index(
        "ix_security_cases_first_seen",
        "security_cases",
        ["first_seen"],
    )
    op.create_index(
        "ix_security_cases_last_seen",
        "security_cases",
        ["last_seen"],
    )

    op.create_table(
        "threat_reviews",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("threat_id", sa.Integer(), nullable=False),
        sa.Column("disposition", sa.String(length=32), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("reviewer", sa.String(length=255), nullable=False),
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
        "ix_threat_reviews_threat_id",
        "threat_reviews",
        ["threat_id"],
    )
    op.create_index(
        "ix_threat_reviews_disposition",
        "threat_reviews",
        ["disposition"],
    )


def downgrade() -> None:
    op.drop_index("ix_threat_reviews_disposition", table_name="threat_reviews")
    op.drop_index("ix_threat_reviews_threat_id", table_name="threat_reviews")
    op.drop_table("threat_reviews")

    op.drop_index("ix_security_cases_last_seen", table_name="security_cases")
    op.drop_index("ix_security_cases_first_seen", table_name="security_cases")
    op.drop_index("ix_security_cases_status", table_name="security_cases")
    op.drop_index("ix_security_cases_source_ip", table_name="security_cases")
    op.drop_index("ix_security_cases_fingerprint", table_name="security_cases")
    op.drop_table("security_cases")

    op.drop_index(
        "ix_analytics_snapshots_bucket_start",
        table_name="analytics_snapshots",
    )
    op.drop_index(
        "ix_analytics_snapshots_granularity",
        table_name="analytics_snapshots",
    )
    op.drop_index(
        "ix_analytics_snapshots_bucket_key",
        table_name="analytics_snapshots",
    )
    op.drop_table("analytics_snapshots")
