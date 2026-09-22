from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]


def clamp_score(score: int) -> int:
    return max(0, min(100, score))


def severity_from_score(score: int) -> Severity:
    bounded = clamp_score(score)
    if bounded >= 80:
        return "critical"
    if bounded >= 60:
        return "high"
    if bounded >= 30:
        return "medium"
    return "low"
