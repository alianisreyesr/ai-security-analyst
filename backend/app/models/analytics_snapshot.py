from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AnalyticsSnapshot(Base):
    __tablename__ = "analytics_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    bucket_key: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    granularity: Mapped[str] = mapped_column(String(16), index=True)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    total_threats: Mapped[int] = mapped_column(Integer)
    severity_counts: Mapped[dict] = mapped_column(JSON)
    rule_counts: Mapped[dict] = mapped_column(JSON)
    source_counts: Mapped[dict] = mapped_column(JSON)
    rebuilt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
