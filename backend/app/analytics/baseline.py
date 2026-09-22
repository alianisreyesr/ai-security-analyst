from dataclasses import dataclass
from statistics import mean, pstdev

from app.core.config import settings


@dataclass(frozen=True, slots=True)
class BaselineResult:
    status: str
    sample_count: int
    mean: float
    stddev: float
    minimum_samples: int


@dataclass(frozen=True, slots=True)
class AnomalyResult:
    baseline: BaselineResult
    current_value: float
    z_score: float
    anomaly_score: int
    threshold: int
    anomalous: bool
    explanation: str


def compute_baseline(
    values: list[float],
    minimum_samples: int | None = None,
) -> BaselineResult:
    required = minimum_samples or settings.baseline_min_samples
    if len(values) < required:
        return BaselineResult(
            status="cold_start",
            sample_count=len(values),
            mean=mean(values) if values else 0.0,
            stddev=pstdev(values) if len(values) > 1 else 0.0,
            minimum_samples=required,
        )

    return BaselineResult(
        status="ready",
        sample_count=len(values),
        mean=mean(values),
        stddev=pstdev(values),
        minimum_samples=required,
    )


def score_anomaly(
    current_value: float,
    baseline: BaselineResult,
    threshold: int | None = None,
) -> AnomalyResult:
    configured_threshold = threshold or settings.anomaly_score_threshold

    if baseline.status != "ready":
        return AnomalyResult(
            baseline=baseline,
            current_value=current_value,
            z_score=0.0,
            anomaly_score=0,
            threshold=configured_threshold,
            anomalous=False,
            explanation=(
                "Insufficient historical samples; anomaly scoring is disabled "
                "until the baseline is ready."
            ),
        )

    if baseline.stddev > 0:
        z_score = max(0.0, (current_value - baseline.mean) / baseline.stddev)
    elif current_value > baseline.mean:
        z_score = 3.0
    else:
        z_score = 0.0

    anomaly_score = min(100, round(z_score * 20))
    anomalous = anomaly_score >= configured_threshold

    return AnomalyResult(
        baseline=baseline,
        current_value=current_value,
        z_score=round(z_score, 4),
        anomaly_score=anomaly_score,
        threshold=configured_threshold,
        anomalous=anomalous,
        explanation=(
            "Score is derived from deviation above the historical mean. "
            "It is separate from deterministic threat risk scoring."
        ),
    )
