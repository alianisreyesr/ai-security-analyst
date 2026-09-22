from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.security_event import SecurityEvent
from app.schemas.security_event import (
    SecurityEventAccepted,
    SecurityEventCreate,
    SecurityEventListItem,
    SecurityEventListResponse,
)

router = APIRouter(prefix="/api/v1/events", tags=["events"])


@router.get("", response_model=SecurityEventListResponse)
def list_events(
    event_type: str | None = None,
    source_ip: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> SecurityEventListResponse:
    filters = []
    if event_type:
        filters.append(SecurityEvent.event_type == event_type)
    if source_ip:
        filters.append(SecurityEvent.source_ip == source_ip)

    total = db.scalar(
        select(func.count()).select_from(SecurityEvent).where(*filters)
    ) or 0

    events = list(
        db.scalars(
            select(SecurityEvent)
            .where(*filters)
            .order_by(desc(SecurityEvent.timestamp))
            .offset(offset)
            .limit(limit)
        )
    )

    return SecurityEventListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[
            SecurityEventListItem(
                id=event.id,
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                source_port=event.source_port,
                destination_port=event.destination_port,
                protocol=event.protocol,
                event_type=event.event_type,
                username=event.username,
                source=event.source,
                created_at=event.created_at,
            )
            for event in events
        ],
    )


@router.post(
    "",
    response_model=SecurityEventAccepted,
    status_code=status.HTTP_201_CREATED,
)
def create_event(
    payload: SecurityEventCreate,
    db: Session = Depends(get_db),
) -> SecurityEventAccepted:
    data = payload.model_dump()
    for field in ("source_ip", "destination_ip"):
        if data[field] is not None:
            data[field] = str(data[field])

    event = SecurityEvent(**data)

    try:
        db.add(event)
        db.commit()
        db.refresh(event)
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to persist security event.",
        ) from exc

    return SecurityEventAccepted(id=event.id)
