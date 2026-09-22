from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class SecurityEventCreate(BaseModel):
    timestamp: datetime
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=16)
    event_type: str = Field(min_length=1, max_length=100)
    username: str | None = Field(default=None, max_length=255)
    source: str = Field(min_length=1, max_length=100)
    raw_payload: dict[str, Any] | None = None

    model_config = ConfigDict(extra="forbid")


class SecurityEventAccepted(BaseModel):
    id: int
    status: Literal["accepted"] = "accepted"
    normalized: bool = True


class SecurityEventListItem(BaseModel):
    id: int
    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    event_type: str
    username: str | None
    source: str
    created_at: datetime


class SecurityEventListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[SecurityEventListItem]
