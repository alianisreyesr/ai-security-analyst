from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class MitreTechniqueResponse(BaseModel):
    technique_id: str
    name: str
    tactic: str


class ReputationResponse(BaseModel):
    ip_address: str
    status: Literal["ok", "not_applicable", "unsupported", "unavailable"]
    scope: Literal["global", "non_global"]
    provider: str
    cached: bool
    verdict: str | None = None
    score: int | None = Field(default=None, ge=0, le=100)
    details: dict[str, Any] = Field(default_factory=dict)
    retrieved_at: datetime | None = None
