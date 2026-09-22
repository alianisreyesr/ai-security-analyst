from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class DetectionFinding:
    rule_id: str
    title: str
    source_ip: str | None
    score: int
    first_seen: datetime
    last_seen: datetime
    event_ids: list[int] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
