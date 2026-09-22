import hashlib
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.security_case import SecurityCase
from app.models.threat import Threat


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _fingerprint(
    source_ip: str,
    first_seen: datetime,
    last_seen: datetime,
    threat_ids: list[int],
) -> str:
    raw = "|".join(
        [
            source_ip,
            _utc(first_seen).isoformat(),
            _utc(last_seen).isoformat(),
            ",".join(str(value) for value in sorted(threat_ids)),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_case(
    db: Session,
    source_ip: str,
    threats: list[Threat],
) -> SecurityCase | None:
    if len(threats) < settings.correlation_min_threats:
        return None

    threat_ids = sorted(threat.id for threat in threats)
    event_ids = sorted(
        {
            event_id
            for threat in threats
            for event_id in threat.event_ids
        }
    )
    first_seen = min(threat.first_seen for threat in threats)
    last_seen = max(threat.last_seen for threat in threats)
    rule_ids = sorted({threat.rule_id for threat in threats})
    fingerprint = _fingerprint(
        source_ip,
        first_seen,
        last_seen,
        threat_ids,
    )

    existing = db.scalar(
        select(SecurityCase).where(SecurityCase.fingerprint == fingerprint)
    )
    if existing is not None:
        return existing

    case = SecurityCase(
        fingerprint=fingerprint,
        source_ip=source_ip,
        title="Correlated security activity",
        status="open",
        first_seen=first_seen,
        last_seen=last_seen,
        threat_ids=threat_ids,
        event_ids=event_ids,
        evidence={
            "threat_count": len(threat_ids),
            "distinct_rule_ids": rule_ids,
            "window_seconds": settings.correlation_window_seconds,
        },
    )
    db.add(case)
    return case


def correlate_threats(
    db: Session,
    threats: list[Threat],
) -> list[SecurityCase]:
    grouped: dict[str, list[Threat]] = defaultdict(list)
    for threat in threats:
        if threat.source_ip:
            grouped[threat.source_ip].append(threat)

    created_or_existing: list[SecurityCase] = []
    window = timedelta(seconds=settings.correlation_window_seconds)

    for source_ip, source_threats in grouped.items():
        ordered = sorted(
            source_threats,
            key=lambda item: _utc(item.first_seen),
        )
        cluster: list[Threat] = []

        for threat in ordered:
            if not cluster:
                cluster = [threat]
                continue

            cluster_start = _utc(cluster[0].first_seen)
            if _utc(threat.first_seen) - cluster_start <= window:
                cluster.append(threat)
                continue

            case = _build_case(db, source_ip, cluster)
            if case is not None:
                created_or_existing.append(case)
            cluster = [threat]

        case = _build_case(db, source_ip, cluster)
        if case is not None:
            created_or_existing.append(case)

    db.commit()
    for case in created_or_existing:
        db.refresh(case)

    return created_or_existing


def run_correlation(
    db: Session,
    *,
    limit: int = 5000,
) -> list[SecurityCase]:
    threats = list(
        db.scalars(
            select(Threat)
            .order_by(Threat.last_seen.desc())
            .limit(limit)
        )
    )
    return correlate_threats(db, threats)
