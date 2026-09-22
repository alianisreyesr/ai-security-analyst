from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class AnalyticsRebuildRequest(BaseModel):
    granularity: Literal["hour", "day"]
    start: datetime
    end: datetime


class AnalyticsSnapshotResponse(BaseModel):
    bucket_start: datetime
    granularity: str
    total_threats: int
    severity_counts: dict[str, int]
    rule_counts: dict[str, int]
    source_counts: dict[str, int]


class AnalyticsRebuildResponse(BaseModel):
    rebuilt: int
    snapshots: list[AnalyticsSnapshotResponse]


class BaselineResponse(BaseModel):
    status: Literal["cold_start", "ready"]
    sample_count: int
    mean: float
    stddev: float
    minimum_samples: int


class SourceAnomalyResponse(BaseModel):
    source_ip: str
    granularity: Literal["hour", "day"]
    current_value: float
    baseline: BaselineResponse
    z_score: float
    anomaly_score: int = Field(ge=0, le=100)
    threshold: int = Field(ge=0, le=100)
    anomalous: bool
    explanation: str
