from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.security_event import SecurityEvent
from app.models.threat import Threat
from app.schemas.threat_intel import MitreTechniqueResponse
from app.schemas.threats import (
    SourceStatistic,
    SourceStatisticsResponse,
    ThreatListItem,
    ThreatListResponse,
    ThreatTimelineResponse,
    TimelineEvent,
)
from app.threat_intel.mitre import techniques_for_rule

router = APIRouter(prefix="/api/v1/threats", tags=["threats"])


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _mitre(rule_id: str) -> list[MitreTechniqueResponse]:
    return [
        MitreTechniqueResponse(
            technique_id=item.technique_id,
            name=item.name,
            tactic=item.tactic,
        )
        for item in techniques_for_rule(rule_id)
    ]


@router.get("", response_model=ThreatListResponse)
def list_threats(
    severity: str | None = None,
    source_ip: str | None = None,
    rule_id: str | None = None,
    q: str | None = None,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> ThreatListResponse:
    filters = []
    if severity:
        filters.append(Threat.severity == severity)
    if source_ip:
        filters.append(Threat.source_ip == source_ip)
    if rule_id:
        filters.append(Threat.rule_id.ilike(f"%{rule_id}%"))
    if q:
        filters.append(
            or_(
                Threat.rule_id.ilike(f"%{q}%"),
                Threat.title.ilike(f"%{q}%"),
                Threat.source_ip.ilike(f"%{q}%"),
            )
        )
    if start:
        filters.append(Threat.last_seen >= start)
    if end:
        filters.append(Threat.first_seen <= end)

    total = db.scalar(
        select(func.count()).select_from(Threat).where(*filters)
    ) or 0
    threats = list(
        db.scalars(
            select(Threat)
            .where(*filters)
            .order_by(desc(Threat.last_seen))
            .offset(offset)
            .limit(limit)
        )
    )

    return ThreatListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[
            ThreatListItem(
                id=threat.id,
                rule_id=threat.rule_id,
                title=threat.title,
                source_ip=threat.source_ip,
                risk_score=threat.risk_score,
                severity=threat.severity,
                first_seen=_utc(threat.first_seen),
                last_seen=_utc(threat.last_seen),
                event_count=len(threat.event_ids),
                mitre=_mitre(threat.rule_id),
            )
            for threat in threats
        ],
    )


@router.get("/{threat_id}/timeline", response_model=ThreatTimelineResponse)
def threat_timeline(
    threat_id: int,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> ThreatTimelineResponse:
    threat = db.scalar(select(Threat).where(Threat.id == threat_id))
    if threat is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat not found.",
        )

    event_ids = threat.event_ids
    if not event_ids:
        events: list[SecurityEvent] = []
    else:
        events = list(
            db.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.id.in_(event_ids))
                .order_by(SecurityEvent.timestamp.asc())
                .offset(offset)
                .limit(limit)
            )
        )

    return ThreatTimelineResponse(
        threat_id=threat.id,
        rule_id=threat.rule_id,
        total=len(event_ids),
        limit=limit,
        offset=offset,
        events=[
            TimelineEvent(
                id=event.id,
                timestamp=_utc(event.timestamp),
                event_type=event.event_type,
                source=event.source,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                source_port=event.source_port,
                destination_port=event.destination_port,
                username=event.username,
            )
            for event in events
        ],
    )


@router.get("/sources/statistics", response_model=SourceStatisticsResponse)
def source_statistics(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> SourceStatisticsResponse:
    rows = db.execute(
        select(
            Threat.source_ip,
            func.count(Threat.id),
            func.max(Threat.risk_score),
            func.max(Threat.last_seen),
        )
        .where(Threat.source_ip.is_not(None))
        .group_by(Threat.source_ip)
        .order_by(desc(func.count(Threat.id)))
        .limit(limit)
    ).all()

    return SourceStatisticsResponse(
        items=[
            SourceStatistic(
                source_ip=row[0],
                threat_count=row[1],
                max_risk_score=row[2],
                last_seen=_utc(row[3]),
            )
            for row in rows
            if row[0] is not None
        ]
    )
