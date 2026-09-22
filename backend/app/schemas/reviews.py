from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

ThreatDisposition = Literal[
    "likely_false_positive",
    "confirmed_suspicious",
    "needs_review",
]


class ThreatReviewCreate(BaseModel):
    disposition: ThreatDisposition
    rationale: str = Field(min_length=3, max_length=4000)
    reviewer: str = Field(min_length=1, max_length=255)


class ThreatReviewResponse(BaseModel):
    id: int
    threat_id: int
    disposition: ThreatDisposition
    rationale: str
    reviewer: str
    created_at: datetime


class ThreatReviewListResponse(BaseModel):
    items: list[ThreatReviewResponse]
