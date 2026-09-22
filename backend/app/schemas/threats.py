from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.threat_intel import MitreTechniqueResponse


class ThreatListItem(BaseModel):
    id: int
    rule_id: str
    title: str
    source_ip: str | None
    risk_score: int
    severity: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    mitre: list[MitreTechniqueResponse]


class ThreatListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[ThreatListItem]


class TimelineEvent(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    source: str
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    username: str | None


class ThreatTimelineResponse(BaseModel):
    threat_id: int
    rule_id: str
    total: int
    limit: int
    offset: int
    events: list[TimelineEvent]


class SourceStatistic(BaseModel):
    source_ip: str
    threat_count: int
    max_risk_score: int = Field(ge=0, le=100)
    last_seen: datetime


class SourceStatisticsResponse(BaseModel):
    items: list[SourceStatistic]
