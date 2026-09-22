from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

AnalystText = Annotated[str, Field(min_length=1, max_length=1000)]
AnalysisStatus = Literal["success", "fallback"]
ConfidenceLevel = Literal["low", "medium", "high"]


class AnalystOutput(BaseModel):
    summary: str = Field(min_length=1, max_length=2000)
    observed_evidence: list[AnalystText] = Field(max_length=20)
    interpretation: str = Field(min_length=1, max_length=3000)
    investigation_steps: list[AnalystText] = Field(max_length=20)
    caveats: list[AnalystText] = Field(max_length=20)
    confidence: ConfidenceLevel

    model_config = ConfigDict(extra="forbid")


class ThreatAnalysisResponse(BaseModel):
    id: int
    threat_id: int
    status: AnalysisStatus
    provider: str
    model: str
    template_version: str
    output: AnalystOutput
