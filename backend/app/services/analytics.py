from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import TypedDict

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.analytics.baseline import AnomalyResult, compute_baseline, score_anomaly
from app.core.config import settings
from app.models.analytics_snapshot import AnalyticsSnapshot
from app.models.threat import Threat

_GRANULARITY_STEPS = {
    "hour": timedelta(hours=1),
    "day": timedelta(days=1),
}


class BucketData(TypedDict):
    total: int
    severity: Counter[str]
    rules: Counter[str]
    sources: Counter[str]


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def bucket_start(value: datetime, granularity: str) -> datetime:
    utc_value = ensure_utc(value)
    if granularity == "hour":
        return utc_value.replace(minute=0, second=0, microsecond=0)
    if granularity == "day":
        return utc_value.replace(hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"Unsupported granularity: {granularity}")


def validate_range(start: datetime, end: datetime) -> tuple[datetime, datetime]:
    start_utc = ensure_utc(start)
    end_utc = ensure_utc(end)
    if end_utc <= start_utc:
        raise ValueError("end must be after start")
    if end_utc - start_utc > timedelta(days=settings.analytics_max_days):
        raise ValueError(
            f"analytics range exceeds maximum of {settings.analytics_max_days} days"
        )
    return start_utc, end_utc


def _bucket_sequence(
    start: datetime,
    end: datetime,
    granularity: str,
) -> list[datetime]:
    step = _GRANULARITY_STEPS.get(granularity)
    if step is None:
        raise ValueError(f"Unsupported granularity: {granularity}")

    current = bucket_start(start, granularity)
    buckets: list[datetime] = []
    while current < end:
        buckets.append(current)
        current += step
    return buckets


def rebuild_threat_snapshots(
    db: Session,
    *,
    start: datetime,
    end: datetime,
    granularity: str,
) -> list[AnalyticsSnapshot]:
    start_utc, end_utc = validate_range(start, end)
    bucket_starts = _bucket_sequence(start_utc, end_utc, granularity)

    bucket_data: dict[datetime, BucketData] = {
        value: {
            "total": 0,
            "severity": Counter[str](),
            "rules": Counter[str](),
            "sources": Counter[str](),
        }
        for value in bucket_starts
    }

    threats = list(
        db.scalars(
            select(Threat)
            .where(Threat.last_seen >= start_utc)
            .where(Threat.last_seen < end_utc)
            .order_by(Threat.last_seen.asc())
        )
    )

    for threat in threats:
        key = bucket_start(threat.last_seen, granularity)
        if key not in bucket_data:
            continue
        bucket_data[key]["total"] += 1
        bucket_data[key]["severity"][threat.severity] += 1
        bucket_data[key]["rules"][threat.rule_id] += 1
        if threat.source_ip:
            bucket_data[key]["sources"][threat.source_ip] += 1

    db.execute(
        delete(AnalyticsSnapshot)
        .where(AnalyticsSnapshot.granularity == granularity)
        .where(AnalyticsSnapshot.bucket_start >= bucket_start(start_utc, granularity))
        .where(AnalyticsSnapshot.bucket_start < end_utc)
        .execution_options(synchronize_session=False)
    )
    db.expire_all()

    snapshots: list[AnalyticsSnapshot] = []
    for value in bucket_starts:
        data = bucket_data[value]
        snapshot = AnalyticsSnapshot(
            bucket_key=f"{granularity}:{value.isoformat()}",
            granularity=granularity,
            bucket_start=value,
            total_threats=data["total"],
            severity_counts=dict(data["severity"]),
            rule_counts=dict(data["rules"]),
            source_counts=dict(data["sources"]),
        )
        db.add(snapshot)
        snapshots.append(snapshot)

    db.commit()
    for snapshot in snapshots:
        db.refresh(snapshot)

    return snapshots


def load_snapshots(
    db: Session,
    *,
    granularity: str,
    limit: int = 168,
) -> list[AnalyticsSnapshot]:
    items = list(
        db.scalars(
            select(AnalyticsSnapshot)
            .where(AnalyticsSnapshot.granularity == granularity)
            .order_by(AnalyticsSnapshot.bucket_start.desc())
            .limit(limit)
        )
    )
    items.reverse()
    return items


def source_anomaly(
    db: Session,
    *,
    source_ip: str,
    granularity: str,
    lookback: int,
) -> AnomalyResult:
    snapshots = load_snapshots(
        db,
        granularity=granularity,
        limit=lookback + 1,
    )

    if not snapshots:
        baseline = compute_baseline([])
        return score_anomaly(0.0, baseline)

    current_snapshot = snapshots[-1]
    history = snapshots[:-1]
    historical_values = [
        float(snapshot.source_counts.get(source_ip, 0))
        for snapshot in history
    ]
    current_value = float(current_snapshot.source_counts.get(source_ip, 0))
    baseline = compute_baseline(historical_values)
    return score_anomaly(current_value, baseline)
