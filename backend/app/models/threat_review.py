from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ThreatReview(Base):
    __tablename__ = "threat_reviews"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    threat_id: Mapped[int] = mapped_column(
        ForeignKey("threats.id", ondelete="CASCADE"),
        index=True,
    )
    disposition: Mapped[str] = mapped_column(String(32), index=True)
    rationale: Mapped[str] = mapped_column(Text)
    reviewer: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
