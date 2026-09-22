from typing import Literal

from pydantic import BaseModel, Field


class AnalystOutput(BaseModel):
    summary: str = Field(min_length=1, max_length=2000)
    observed_evidence: list[str] = Field(max_length=20)
    interpretation: str = Field(min_length=1, max_length=3000)
    investigation_steps: list[str] = Field(max_length=20)
    caveats: list[str] = Field(max_length=20)
    confidence: Literal["low", "medium", "high"]


class ThreatAnalysisResponse(BaseModel):
    id: int
    threat_id: int
    status: Literal["success", "fallback"]
    provider: str
    model: str
    template_version: str
    output: AnalystOutput
