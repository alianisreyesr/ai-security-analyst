from typing import Literal

from pydantic import BaseModel, Field


class BatchIngestRequest(BaseModel):
    format: Literal["json", "csv", "log", "txt"]
    content: str = Field(min_length=1, max_length=1_000_000)


class BatchIngestResponse(BaseModel):
    accepted: int
    rejected: int
    event_ids: list[int]
    errors: list[str]
