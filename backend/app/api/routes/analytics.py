from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.schemas.analytics import (
    AnalyticsRebuildRequest,
    AnalyticsRebuildResponse,
    AnalyticsSnapshotResponse,
    BaselineResponse,
    SourceAnomalyResponse,
)
from app.security.auth import require_admin
from app.services.analytics import rebuild_threat_snapshots, source_anomaly

router = APIRouter(prefix="/api/v1/analytics", tags=["analytics"])


@router.post(
    "/rebuild",
    response_model=AnalyticsRebuildResponse,
    dependencies=[Depends(require_admin)],
)
def rebuild_analytics(
    payload: AnalyticsRebuildRequest,
    db: Session = Depends(get_db),
) -> AnalyticsRebuildResponse:
    try:
        snapshots = rebuild_threat_snapshots(
            db,
            start=payload.start,
            end=payload.end,
            granularity=payload.granularity,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    return AnalyticsRebuildResponse(
        rebuilt=len(snapshots),
        snapshots=[
            AnalyticsSnapshotResponse(
                bucket_start=snapshot.bucket_start,
                granularity=snapshot.granularity,
                total_threats=snapshot.total_threats,
                severity_counts=snapshot.severity_counts,
                rule_counts=snapshot.rule_counts,
                source_counts=snapshot.source_counts,
            )
            for snapshot in snapshots
        ],
    )


@router.get(
    "/sources/{source_ip}/anomaly",
    response_model=SourceAnomalyResponse,
)
def get_source_anomaly(
    source_ip: str,
    granularity: Literal["hour", "day"] = "hour",
    lookback: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
) -> SourceAnomalyResponse:
    result = source_anomaly(
        db,
        source_ip=source_ip,
        granularity=granularity,
        lookback=lookback,
    )
    baseline = result.baseline

    return SourceAnomalyResponse(
        source_ip=source_ip,
        granularity=granularity,
        current_value=result.current_value,
        baseline=BaselineResponse(
            status=baseline.status,
            sample_count=baseline.sample_count,
            mean=baseline.mean,
            stddev=baseline.stddev,
            minimum_samples=baseline.minimum_samples,
        ),
        z_score=result.z_score,
        anomaly_score=result.anomaly_score,
        threshold=result.threshold,
        anomalous=result.anomalous,
        explanation=result.explanation,
    )
