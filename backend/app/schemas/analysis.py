from pydantic import BaseModel, Field


class AnalysisRunRequest(BaseModel):
    limit: int = Field(default=5000, ge=1, le=10000)


class ThreatSummary(BaseModel):
    id: int
    rule_id: str
    title: str
    source_ip: str | None
    risk_score: int
    severity: str
    event_ids: list[int]
    evidence: dict


class AnalysisRunResponse(BaseModel):
    analyzed_event_limit: int
    threats: list[ThreatSummary]
