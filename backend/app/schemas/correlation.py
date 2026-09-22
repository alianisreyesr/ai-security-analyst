from datetime import datetime

from pydantic import BaseModel, Field


class CorrelationRunRequest(BaseModel):
    limit: int = Field(default=5000, ge=1, le=10000)


class SecurityCaseResponse(BaseModel):
    id: int
    source_ip: str
    title: str
    status: str
    first_seen: datetime
    last_seen: datetime
    threat_ids: list[int]
    event_ids: list[int]
    evidence: dict


class CorrelationRunResponse(BaseModel):
    cases: list[SecurityCaseResponse]
