from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ThreatAnalysis(Base):
    __tablename__ = "threat_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    threat_id: Mapped[int] = mapped_column(
        ForeignKey("threats.id", ondelete="CASCADE"),
        index=True,
    )
    status: Mapped[str] = mapped_column(String(16), index=True)
    provider: Mapped[str] = mapped_column(String(100))
    model: Mapped[str] = mapped_column(String(255))
    template_version: Mapped[str] = mapped_column(String(50))
    summary: Mapped[str] = mapped_column(Text)
    observed_evidence: Mapped[list[str]] = mapped_column(JSON)
    interpretation: Mapped[str] = mapped_column(Text)
    investigation_steps: Mapped[list[str]] = mapped_column(JSON)
    caveats: Mapped[list[str]] = mapped_column(JSON)
    confidence: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
